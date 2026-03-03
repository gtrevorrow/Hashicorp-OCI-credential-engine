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

		if conf == nil {
			return nil, errors.New("configuration passed into backend is nil")
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

	// OCI Identity Domain OCID (for federated identity)
	DomainOCID string `json:"domain_ocid" mapstructure:"domain_ocid"`

	// Identity Provider ID for the 3rd party IdP configured in OCI
	IdentityProviderID string `json:"identity_provider_id" mapstructure:"identity_provider_id"`

	// OCI Region
	Region string `json:"region" mapstructure:"region"`

	// Optional: Client credentials for OCI IAM (if not using instance/auth principal)
	ClientID     string `json:"client_id,omitempty" mapstructure:"client_id"`
	ClientSecret string `json:"client_secret,omitempty" mapstructure:"client_secret"`

	// Default TTL for issued OCI session tokens
	DefaultTTL int `json:"default_ttl" mapstructure:"default_ttl"`

	// Maximum TTL for issued OCI session tokens
	MaxTTL int `json:"max_ttl" mapstructure:"max_ttl"`
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
