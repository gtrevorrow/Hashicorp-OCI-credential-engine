package ocibackend

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/helper/base62"
)

const (
	backendHelp = `
The OCI secrets engine dynamically generates OCI session tokens.

After mounting this secrets engine, configure it using the "config" endpoint
to provide OCI credentials (tenancy OCID, user OCID, API key fingerprint, 
private key, and region). Then, use the "creds" endpoint to generate 
temporary session tokens.
`
)

// Factory returns a new backend as logical.Backend
type backend struct {
	*framework.Backend
	lock   sync.RWMutex
	logger hclog.Logger
}

// Factory configures and returns a new backend
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend{
		logger: conf.Logger,
	}
	b.Backend = &framework.Backend{
		Help: backendHelp,
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"config",
			},
		},
		Paths: framework.PathAppend(
			b.pathConfig(),
			b.pathCreds(),
		),
		Secrets: []*framework.Secret{
			b.ociToken(),
		},
		BackendType: logical.TypeLogical,
	}

	if conf == nil {
		return nil, errors.New("configuration passed into backend is nil")
	}

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	return &b, nil
}

// TLSProvider provides TLS configuration for the plugin
func TLSProvider() (*tls.Config, error) {
	return nil, nil
}

// genUsername generates a unique username for the OCI token
func genUsername(displayName string) (string, error) {
	randomStr, err := base62.Random(8)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("vault-%s-%s", displayName, randomStr), nil
}

// backendConfig contains the actual OCI configuration
type backendConfig struct {
	TenancyOCID    string `json:"tenancy_ocid" mapstructure:"tenancy_ocid"`
	UserOCID       string `json:"user_ocid" mapstructure:"user_ocid"`
	Fingerprint    string `json:"fingerprint" mapstructure:"fingerprint"`
	PrivateKey     string `json:"private_key" mapstructure:"private_key"`
	PrivateKeyPath string `json:"private_key_path" mapstructure:"private_key_path"`
	Region         string `json:"region" mapstructure:"region"`
	Passphrase     string `json:"passphrase,omitempty" mapstructure:"passphrase"`
}

// getConfig retrieves the backend configuration from storage
func (b *backend) getConfig(ctx context.Context, s logical.Storage) (*backendConfig, error) {
	entry, err := s.Get(ctx, "config")
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var config backendConfig
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

// saveConfig stores the backend configuration
func (b *backend) saveConfig(ctx context.Context, s logical.Storage, config *backendConfig) error {
	entry, err := logical.StorageEntryJSON("config", config)
	if err != nil {
		return err
	}

	return s.Put(ctx, entry)
}
