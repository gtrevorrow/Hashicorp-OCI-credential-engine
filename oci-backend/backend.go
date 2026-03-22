package ocibackend

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	// defaultHTTPClientTimeout is the maximum time allowed for an outbound HTTP
	// request (e.g., OCI token exchange) to complete before being cancelled.
	defaultHTTPClientTimeout = 30 * time.Second

	backendHelp = `
The OCI secrets engine dynamically generates OCI session tokens
by exchanging 3rd party OIDC/OAuth JWT subject tokens.

After mounting this secrets engine, configure it using the "config" endpoint
to provide OCI federated identity configuration. Then, use the "exchange" 
endpoint to submit a JWT subject token and receive an OCI session token.
`
)

// backend implements the Vault secrets engine backend
type backend struct {
	*framework.Backend
	lock                 sync.RWMutex
	logger               hclog.Logger
	httpClient           *http.Client
	subjectTokenCallback SubjectTokenCallback
	tokenExchanger       func(ctx context.Context, subjectToken, requestedTokenType, resType, publicKey string, config *federatedConfig) (*tokenExchangeResult, error)
}

// SubjectTokenCallback mints a JWT subject token for fallback flows when callers
// do not provide subject_token and plugin identity token generation is unavailable.
type SubjectTokenCallback func(ctx context.Context, req *logical.Request, config *federatedConfig) (string, error)

// RegisterSubjectTokenCallback registers a callback used to self-mint fallback
// subject tokens. Intended for feature-gated enterprise/non-enterprise behavior.
func (b *backend) RegisterSubjectTokenCallback(callback SubjectTokenCallback) {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.subjectTokenCallback = callback
}

func (b *backend) getSubjectTokenCallback() SubjectTokenCallback {
	b.lock.RLock()
	defer b.lock.RUnlock()
	return b.subjectTokenCallback
}

func (b *backend) setTokenExchanger(exchanger func(ctx context.Context, subjectToken, requestedTokenType, resType, publicKey string, config *federatedConfig) (*tokenExchangeResult, error)) {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.tokenExchanger = exchanger
}

func (b *backend) getTokenExchanger() func(ctx context.Context, subjectToken, requestedTokenType, resType, publicKey string, config *federatedConfig) (*tokenExchangeResult, error) {
	b.lock.RLock()
	defer b.lock.RUnlock()
	return b.tokenExchanger
}

// Factory returns a configured logical.Factory
func Factory(version string) logical.Factory {
	return func(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
		if conf == nil {
			return nil, errors.New("configuration passed into backend is nil")
		}

		b := backend{
			logger: conf.Logger,
			httpClient: &http.Client{
				Timeout: defaultHTTPClientTimeout,
			},
		}
		b.Backend = &framework.Backend{
			Help: backendHelp,
			PathsSpecial: &logical.Paths{ //seal wrap data stored in the config path will be encrypted with the master key ( Enterprise Vault only)
				SealWrapStorage: []string{
					"config",
				},
			},
			Paths: framework.PathAppend(
				b.pathConfig(),
				b.pathExchange(),
				b.pathRoles(),
				b.pathJWKS(),
			),
			Secrets: []*framework.Secret{
				b.ociTokenSecret(),
			},
			BackendType:    logical.TypeLogical,
			RunningVersion: version,
		}

		if err := b.Setup(ctx, conf); err != nil {
			return nil, err
		}
		b.RegisterSubjectTokenCallback(b.defaultSubjectTokenCallback)
		b.setTokenExchanger(b.exchangeTokenForOCI)

		return &b, nil
	}
}

// TLSProvider provides TLS configuration for the plugin
func TLSProvider() (*tls.Config, error) {
	return nil, nil
}

// federatedConfig holds OCI federated identity configuration
type federatedConfig struct {
	// OCI Identity Domain URL (e.g., https://idcs-xxxx.identity.oraclecloud.com)
	DomainUrl string `json:"domain_url" mapstructure:"domain_url"`

	// Client credentials for the OAuth Confidential Application inside the Identity Domain
	ClientID     string `json:"client_id" mapstructure:"client_id"`
	ClientSecret string `json:"client_secret" mapstructure:"client_secret"`

	// Default TTL for issued OCI session tokens
	DefaultTTL int `json:"default_ttl" mapstructure:"default_ttl"`

	// Maximum TTL for issued OCI session tokens
	MaxTTL int `json:"max_ttl" mapstructure:"max_ttl"`

	// Ordered rules used to derive a Vault role from a caller-supplied subject token.
	SubjectTokenRoleMappings []subjectTokenRoleMapping `json:"subject_token_role_mappings,omitempty" mapstructure:"subject_token_role_mappings"`

	// Allow plugin identity token fallback when subject_token is omitted.
	// Pointer is used to preserve default behavior for legacy configs with missing field.
	EnablePluginIssuedSubjectToken *bool `json:"enable_plugin_issued_subject_token,omitempty" mapstructure:"enable_plugin_issued_subject_token"`

	// Enforce strict role-name format for role creation and exchange requests.
	StrictRoleNameMatch bool `json:"strict_role_name_match" mapstructure:"strict_role_name_match"`

	// Built-in callback fallback controls for self-minting subject_token.
	SubjectTokenSelfMintEnabled           bool     `json:"subject_token_self_mint_enabled" mapstructure:"subject_token_self_mint_enabled"`
	SubjectTokenSelfMintIssuer            string   `json:"subject_token_self_mint_issuer" mapstructure:"subject_token_self_mint_issuer"`
	SubjectTokenSelfMintAudience          string   `json:"subject_token_self_mint_audience" mapstructure:"subject_token_self_mint_audience"`
	SubjectTokenAllowedAudiences          []string `json:"subject_token_allowed_audiences" mapstructure:"subject_token_allowed_audiences"`
	SubjectTokenSelfMintTTLSeconds        int      `json:"subject_token_self_mint_ttl_seconds" mapstructure:"subject_token_self_mint_ttl_seconds"`
	SubjectTokenSelfMintPrivateKey        string   `json:"subject_token_self_mint_private_key" mapstructure:"subject_token_self_mint_private_key"`
	DebugReturnResolvedSubjectTokenClaims bool     `json:"debug_return_resolved_subject_token_claims" mapstructure:"debug_return_resolved_subject_token_claims"`
}

type subjectTokenRoleMapping struct {
	Claim string `json:"claim" mapstructure:"claim"`
	Op    string `json:"op" mapstructure:"op"`
	Value string `json:"value" mapstructure:"value"`
	Role  string `json:"role" mapstructure:"role"`
}

// getConfig retrieves the backend configuration from storage
func (b *backend) getConfig(ctx context.Context, s logical.Storage) (*federatedConfig, error) {
	entry, err := s.Get(ctx, "config")
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var config federatedConfig
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

// saveConfig stores the backend configuration
func (b *backend) saveConfig(ctx context.Context, s logical.Storage, config *federatedConfig) error {
	entry, err := logical.StorageEntryJSON("config", config)
	if err != nil {
		return err
	}

	return s.Put(ctx, entry)
}
