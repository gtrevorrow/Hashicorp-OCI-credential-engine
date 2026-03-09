package ocibackend

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
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
	lock   sync.RWMutex
	logger hclog.Logger
}

// Factory returns a configured logical.Factory
func Factory(version string) logical.Factory {
	return func(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
		if conf == nil {
			return nil, errors.New("configuration passed into backend is nil")
		}

		b := backend{
			logger: conf.Logger,
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

		return &b, nil
	}
}

// TLSProvider provides TLS configuration for the plugin
func TLSProvider() (*tls.Config, error) {
	return nil, nil
}

// federatedConfig holds OCI federated identity configuration
type federatedConfig struct {
	// OCI tenancy and identity domain
	TenancyOCID string `json:"tenancy_ocid" mapstructure:"tenancy_ocid"`

	// OCI Identity Domain URL (e.g., https://idcs-xxxx.identity.oraclecloud.com)
	DomainUrl string `json:"domain_url" mapstructure:"domain_url"`

	// OCI Region
	Region string `json:"region" mapstructure:"region"`

	// Client credentials for the OAuth Confidential Application inside the Identity Domain
	ClientID     string `json:"client_id" mapstructure:"client_id"`
	ClientSecret string `json:"client_secret" mapstructure:"client_secret"`

	// Default TTL for issued OCI session tokens
	DefaultTTL int `json:"default_ttl" mapstructure:"default_ttl"`

	// Maximum TTL for issued OCI session tokens
	MaxTTL int `json:"max_ttl" mapstructure:"max_ttl"`

	// Enforce that a claim in caller-provided subject_token matches request role.
	EnforceRoleClaimMatch bool `json:"enforce_role_claim_match" mapstructure:"enforce_role_claim_match"`

	// Claim key used when EnforceRoleClaimMatch is enabled.
	RoleClaimKey string `json:"role_claim_key" mapstructure:"role_claim_key"`

	// Allow plugin identity token fallback when subject_token is omitted.
	// Pointer is used to preserve default behavior for legacy configs with missing field.
	AllowPluginIdentityFallback *bool `json:"allow_plugin_identity_fallback,omitempty" mapstructure:"allow_plugin_identity_fallback"`

	// Enforce strict role-name format for role creation and exchange requests.
	StrictRoleNameMatch bool `json:"strict_role_name_match" mapstructure:"strict_role_name_match"`
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
