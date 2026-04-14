package ocibackend

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/hashicorp/vault/sdk/helper/pluginutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSystemView is used to inject custom mock data for WIF testing
type mockSystemView struct {
	logical.StaticSystemView
	mockIdentity     string
	lastAudienceSeen string
}

func (m *mockSystemView) GenerateIdentityToken(ctx context.Context, req *pluginutil.IdentityTokenRequest) (*pluginutil.IdentityTokenResponse, error) {
	m.lastAudienceSeen = req.Audience
	if m.mockIdentity != "" {
		return &pluginutil.IdentityTokenResponse{
			Token: pluginutil.IdentityToken(m.mockIdentity),
		}, nil
	}
	return nil, logical.ErrUnsupportedOperation
}

func installFailingTokenExchanger(b *backend) {
	b.setTokenExchanger(func(ctx context.Context, subjectToken, requestedTokenType, resType, publicKey string, ttl time.Duration, config *federatedConfig) (*tokenExchangeResult, error) {
		return nil, fmt.Errorf("stub exchange failure")
	})
}

func TestPathExchange_TokenExchanges(t *testing.T) {
	// Standard Setup
	b, err := Factory("v0.0.0-test")(context.Background(), &logical.BackendConfig{
		System: &mockSystemView{
			mockIdentity: "",
			StaticSystemView: logical.StaticSystemView{
				DefaultLeaseTTLVal: time.Hour,
				MaxLeaseTTLVal:     24 * time.Hour,
			},
		},
	})
	require.NoError(t, err)
	backend := b.(*backend)
	installFailingTokenExchanger(backend)
	storage := &logical.InmemStorage{}

	// Baseline sanity check for exchange path prerequisites; not tied to a named plan ID.
	t.Run("Missing Config", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "exchange/dev",
			Storage:   storage,
			Data: map[string]interface{}{
				"subject_token": "token123",
			},
		}

		resp, err := backend.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.True(t, resp.IsError())
		require.Contains(t, resp.Error().Error(), "backend not configured")
	})

	// Pre-populate Config and Role
	reqConfig := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"domain_url":    "https://idcs-test.identity.oraclecloud.com",
			"client_id":     "test-client-id",
			"client_secret": "test-client-secret",
		},
	}
	_, err = backend.HandleRequest(context.Background(), reqConfig)
	require.NoError(t, err)

	reqRole := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/dev",
		Storage:   storage,
		Data: map[string]interface{}{
			"description": "dev role",
		},
	}
	_, err = backend.HandleRequest(context.Background(), reqRole)
	require.NoError(t, err)

	// Covers EXC-04 when fallback is enabled but neither Vault identity nor self-mint is available.
	t.Run("Missing Subject Token Unconfigured Identity", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "exchange/dev",
			Storage:   storage,
		}

		resp, err := backend.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.True(t, resp.IsError())
		require.Contains(t, resp.Error().Error(), "failed to mint subject_token via callback")
	})

	// Baseline role lookup validation; not tied to a named plan ID.
	t.Run("Missing Role Path", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "exchange/nonexistent",
			Storage:   storage,
			Data: map[string]interface{}{
				"subject_token": "token123",
			},
		}

		resp, err := backend.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.True(t, resp.IsError())
		require.Contains(t, resp.Error().Error(), "role 'nonexistent' not found")
	})
}

func TestPathExchange_WIFEnterprise(t *testing.T) {
	// Covers the Vault identity-token branch of EXC-04.
	b, err := Factory("v0.0.0-test")(context.Background(), &logical.BackendConfig{
		System: &mockSystemView{
			mockIdentity: "mocked-wif-identity-token",
			StaticSystemView: logical.StaticSystemView{
				DefaultLeaseTTLVal: time.Hour,
				MaxLeaseTTLVal:     24 * time.Hour,
			},
		},
	})
	require.NoError(t, err)
	backend := b.(*backend)
	installFailingTokenExchanger(backend)
	storage := &logical.InmemStorage{}

	// Pre-populate Config and Role
	reqConfig := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"domain_url":    "https://idcs-test.identity.oraclecloud.com",
			"client_id":     "test-client-id",
			"client_secret": "test-client-secret",
		},
	}
	_, _ = backend.HandleRequest(context.Background(), reqConfig)

	reqRole := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/dev",
		Storage:   storage,
		Data: map[string]interface{}{
			"description": "dev role",
		},
	}
	_, _ = backend.HandleRequest(context.Background(), reqRole)

	t.Run("Enterprise Token Generation Bypass", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "exchange/dev",
			Storage:   storage,
		}

		// Because we're mocking Enterprise but OCI calls will fail (no real endpoint),
		// we expect it to fail at token exchange rather than "missing subject_token" validation.
		// If it errors over missing subject_token, our Enterprise WIF bypass logic failed!
		resp, err := backend.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.True(t, resp.IsError())

		errStr := resp.Error().Error()
		assert.NotContains(t, errStr, "missing 'subject_token'", "Enterprise WIF bypass failed; it demanded a subject_token")
		assert.Contains(t, errStr, "token exchange failed", "It successfully bypassed subject_token and attempted token exchange")
	})
}

func TestPathExchange_RequestedTokenTypeValidation(t *testing.T) {
	// Covers requested-token-type validation adjacent to EXC-02 and EXC-03.
	b, err := Factory("v0.0.0-test")(context.Background(), &logical.BackendConfig{
		System: &mockSystemView{
			mockIdentity: "",
			StaticSystemView: logical.StaticSystemView{
				DefaultLeaseTTLVal: time.Hour,
				MaxLeaseTTLVal:     24 * time.Hour,
			},
		},
	})
	require.NoError(t, err)
	backend := b.(*backend)
	installFailingTokenExchanger(backend)
	storage := &logical.InmemStorage{}

	// Pre-populate minimal config.
	reqConfig := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"domain_url":    "https://idcs-test.identity.oraclecloud.com",
			"client_id":     "test-client-id",
			"client_secret": "test-client-secret",
		},
	}
	_, err = backend.HandleRequest(context.Background(), reqConfig)
	require.NoError(t, err)

	// Covers unsupported requested token type validation.
	t.Run("Unsupported Requested Token Type", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "exchange",
			Storage:   storage,
			Data: map[string]interface{}{
				"subject_token":        "token123",
				"requested_token_type": "urn:oci:token-type:not-valid",
			},
		}

		resp, err := backend.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.True(t, resp.IsError())
		require.Contains(t, resp.Error().Error(), "unsupported requested_token_type")
	})

	// Covers the RPST-specific res_type requirement for EXC-02.
	t.Run("RPST Missing Resource Type", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "exchange",
			Storage:   storage,
			Data: map[string]interface{}{
				"subject_token":        "token123",
				"requested_token_type": ociRequestedTokenTypeRPST,
			},
		}

		resp, err := backend.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.True(t, resp.IsError())
		require.Contains(t, resp.Error().Error(), "missing 'res_type'")
	})
}

func TestPathExchange_SubjectTokenRoleMappings(t *testing.T) {
	b, storage := getTestBackend(t)
	installFailingTokenExchanger(b)

	reqConfig := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"domain_url":                  "https://idcs-test.identity.oraclecloud.com",
			"client_id":                   "test-client-id",
			"client_secret":               "test-client-secret",
			"subject_token_role_mappings": `[{"claim":"vault_role","op":"eq","value":"dev","role":"dev"},{"claim":"groups","op":"co","value":"ops","role":"ops"}]`,
		},
	}
	_, err := b.HandleRequest(context.Background(), reqConfig)
	require.NoError(t, err)

	reqRole := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/dev",
		Storage:   storage,
		Data: map[string]interface{}{
			"description": "dev role",
		},
	}
	_, err = b.HandleRequest(context.Background(), reqRole)
	require.NoError(t, err)

	reqOpsRole := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/ops",
		Storage:   storage,
		Data: map[string]interface{}{
			"description": "ops role",
		},
	}
	_, err = b.HandleRequest(context.Background(), reqOpsRole)
	require.NoError(t, err)

	t.Run("Derives Role From First Matching Rule", func(t *testing.T) {
		subjectToken := makeTestJWT(t, map[string]interface{}{"vault_role": "dev"})
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "exchange",
			Storage:   storage,
			Data: map[string]interface{}{
				"subject_token": subjectToken,
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.True(t, resp.IsError())
		require.NotContains(t, resp.Error().Error(), "unable to derive role from subject_token")
		require.Contains(t, resp.Error().Error(), "token exchange failed")
	})

	t.Run("Rejects Role Path When Mappings Configured", func(t *testing.T) {
		subjectToken := makeTestJWT(t, map[string]interface{}{"vault_role": "dev"})
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "exchange/dev",
			Storage:   storage,
			Data: map[string]interface{}{
				"subject_token": subjectToken,
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.True(t, resp.IsError())
		require.Contains(t, resp.Error().Error(), "role-specific exchange paths cannot be used when subject_token_role_mappings are configured")
	})

	t.Run("Rejects No Match", func(t *testing.T) {
		subjectToken := makeTestJWT(t, map[string]interface{}{"vault_role": "prod"})
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "exchange",
			Storage:   storage,
			Data: map[string]interface{}{
				"subject_token": subjectToken,
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.True(t, resp.IsError())
		require.Contains(t, resp.Error().Error(), "no subject_token_role_mappings matched")
	})

	t.Run("Array Claim Match Uses Contains Operator", func(t *testing.T) {
		subjectToken := makeTestJWT(t, map[string]interface{}{"groups": []string{"team-ops", "team-dev"}})
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "exchange",
			Storage:   storage,
			Data: map[string]interface{}{
				"subject_token": subjectToken,
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.True(t, resp.IsError())
		require.NotContains(t, resp.Error().Error(), "unable to derive role from subject_token")
		require.Contains(t, resp.Error().Error(), "token exchange failed")
	})
}

func TestPathExchange_PluginIdentityFallbackDisabled(t *testing.T) {
	// Covers EXC-07.
	b, storage := getTestBackend(t)
	installFailingTokenExchanger(b)

	reqConfig := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"domain_url":                         "https://idcs-test.identity.oraclecloud.com",
			"client_id":                          "test-client-id",
			"client_secret":                      "test-client-secret",
			"enable_plugin_issued_subject_token": false,
		},
	}
	_, err := b.HandleRequest(context.Background(), reqConfig)
	require.NoError(t, err)

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "exchange/dev",
		Storage:   storage,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "missing 'subject_token' and plugin-issued subject token mode is disabled")
}

func TestPathExchange_EmptySubjectTokenIsRejected(t *testing.T) {
	b, storage := getTestBackend(t)
	installFailingTokenExchanger(b)

	reqConfig := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"domain_url":    "https://idcs-test.identity.oraclecloud.com",
			"client_id":     "test-client-id",
			"client_secret": "test-client-secret",
		},
	}
	_, err := b.HandleRequest(context.Background(), reqConfig)
	require.NoError(t, err)

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "exchange",
		Storage:   storage,
		Data: map[string]interface{}{
			"subject_token": "",
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "subject_token was provided but is empty")
}

func TestPathExchange_RequestBodyRoleIsIgnored(t *testing.T) {
	b, storage := getTestBackend(t)
	installFailingTokenExchanger(b)

	reqConfig := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"domain_url":    "https://idcs-test.identity.oraclecloud.com",
			"client_id":     "test-client-id",
			"client_secret": "test-client-secret",
		},
	}
	_, err := b.HandleRequest(context.Background(), reqConfig)
	require.NoError(t, err)

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "exchange",
		Storage:   storage,
		Data: map[string]interface{}{
			"subject_token": "token123",
			"role":          "dev",
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "token exchange failed")
}

func TestPathExchange_StrictRoleNameMatch(t *testing.T) {
	b, storage := getTestBackend(t)
	installFailingTokenExchanger(b)

	reqConfig := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"domain_url":                  "https://idcs-test.identity.oraclecloud.com",
			"client_id":                   "test-client-id",
			"client_secret":               "test-client-secret",
			"strict_role_name_match":      true,
			"subject_token_role_mappings": `[{"claim":"vault_role","op":"eq","value":"dev@team","role":"dev@team"}]`,
		},
	}
	resp, err := b.HandleRequest(context.Background(), reqConfig)
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "invalid mapped role")
}

func TestPathExchange_SubjectTokenCallbackFallback(t *testing.T) {
	// Covers EXC-04 using a custom registered callback implementation.
	b, err := Factory("v0.0.0-test")(context.Background(), &logical.BackendConfig{
		System: &mockSystemView{
			mockIdentity: "",
			StaticSystemView: logical.StaticSystemView{
				DefaultLeaseTTLVal: time.Hour,
				MaxLeaseTTLVal:     24 * time.Hour,
			},
		},
	})
	require.NoError(t, err)
	backend := b.(*backend)
	installFailingTokenExchanger(backend)
	storage := &logical.InmemStorage{}

	reqConfig := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"domain_url":    "https://idcs-test.identity.oraclecloud.com",
			"client_id":     "test-client-id",
			"client_secret": "test-client-secret",
		},
	}
	_, err = backend.HandleRequest(context.Background(), reqConfig)
	require.NoError(t, err)

	reqRole := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/dev",
		Storage:   storage,
		Data: map[string]interface{}{
			"description": "dev role",
		},
	}
	_, err = backend.HandleRequest(context.Background(), reqRole)
	require.NoError(t, err)

	backend.RegisterSubjectTokenCallback(func(ctx context.Context, req *logical.Request, config *federatedConfig) (string, error) {
		return "callback-subject-token", nil
	})

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "exchange/dev",
		Storage:   storage,
	}

	resp, err := backend.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.NotContains(t, resp.Error().Error(), "failed to generate plugin identity token")
	require.Contains(t, resp.Error().Error(), "token exchange failed")
}

func TestPathExchange_SubjectTokenCallbackError(t *testing.T) {
	// Covers callback error handling adjacent to EXC-04 and EXC-09.
	b, err := Factory("v0.0.0-test")(context.Background(), &logical.BackendConfig{
		System: &mockSystemView{
			mockIdentity: "",
			StaticSystemView: logical.StaticSystemView{
				DefaultLeaseTTLVal: time.Hour,
				MaxLeaseTTLVal:     24 * time.Hour,
			},
		},
	})
	require.NoError(t, err)
	backend := b.(*backend)
	installFailingTokenExchanger(backend)
	storage := &logical.InmemStorage{}

	reqConfig := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"domain_url":    "https://idcs-test.identity.oraclecloud.com",
			"client_id":     "test-client-id",
			"client_secret": "test-client-secret",
		},
	}
	_, err = backend.HandleRequest(context.Background(), reqConfig)
	require.NoError(t, err)

	backend.RegisterSubjectTokenCallback(func(ctx context.Context, req *logical.Request, config *federatedConfig) (string, error) {
		return "", logical.ErrPermissionDenied
	})

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "exchange",
		Storage:   storage,
		Data:      map[string]interface{}{},
	}

	resp, err := backend.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "failed to mint subject_token via callback")
}

func TestPathExchange_DefaultCallbackSelfMintEnabled(t *testing.T) {
	testKey := generateTestRSAPrivateKeyPEM(t)
	// Covers EXC-09 using the default callback self-mint path.

	b, err := Factory("v0.0.0-test")(context.Background(), &logical.BackendConfig{
		System: &mockSystemView{
			mockIdentity: "",
			StaticSystemView: logical.StaticSystemView{
				DefaultLeaseTTLVal: time.Hour,
				MaxLeaseTTLVal:     24 * time.Hour,
			},
		},
	})
	require.NoError(t, err)
	backend := b.(*backend)
	installFailingTokenExchanger(backend)
	storage := &logical.InmemStorage{}

	reqConfig := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"domain_url":                          "https://idcs-test.identity.oraclecloud.com",
			"client_id":                           "test-client-id",
			"client_secret":                       "test-client-secret",
			"subject_token_self_mint_enabled":     true,
			"subject_token_self_mint_issuer":      "https://vault.example.com",
			"subject_token_self_mint_private_key": testKey,
		},
	}
	_, err = backend.HandleRequest(context.Background(), reqConfig)
	require.NoError(t, err)

	reqRole := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/dev",
		Storage:   storage,
		Data: map[string]interface{}{
			"description": "dev role",
		},
	}
	_, err = backend.HandleRequest(context.Background(), reqRole)
	require.NoError(t, err)

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "exchange/dev",
		Storage:   storage,
	}

	resp, err := backend.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.NotContains(t, resp.Error().Error(), "failed to mint subject_token via callback")
	require.Contains(t, resp.Error().Error(), "token exchange failed")
}

func TestPathExchange_DefaultCallbackSelfMintUsesCallerPublicKey(t *testing.T) {
	testKey := generateTestRSAPrivateKeyPEM(t)
	suppliedPublicKey := deriveTestPublicKeyPEM(t, testKey)

	b, err := Factory("v0.0.0-test")(context.Background(), &logical.BackendConfig{
		System: &mockSystemView{
			mockIdentity: "",
			StaticSystemView: logical.StaticSystemView{
				DefaultLeaseTTLVal: time.Hour,
				MaxLeaseTTLVal:     24 * time.Hour,
			},
		},
	})
	require.NoError(t, err)
	backend := b.(*backend)
	storage := &logical.InmemStorage{}

	backend.setTokenExchanger(func(ctx context.Context, subjectToken, requestedTokenType, resType, publicKey string, ttl time.Duration, config *federatedConfig) (*tokenExchangeResult, error) {
		require.NotEmpty(t, subjectToken)
		require.Equal(t, suppliedPublicKey, publicKey)
		return &tokenExchangeResult{
			AccessToken:        "access-token",
			SessionToken:       "session-token",
			TokenType:          "Bearer",
			RequestedTokenType: ociRequestedTokenTypeUPST,
			PrivateKey:         "should-not-be-returned",
			PublicKey:          "should-not-be-returned",
		}, nil
	})

	reqConfig := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"domain_url":                          "https://idcs-test.identity.oraclecloud.com",
			"client_id":                           "test-client-id",
			"client_secret":                       "test-client-secret",
			"subject_token_self_mint_enabled":     true,
			"subject_token_self_mint_issuer":      "https://vault.example.com",
			"subject_token_self_mint_private_key": testKey,
		},
	}
	_, err = backend.HandleRequest(context.Background(), reqConfig)
	require.NoError(t, err)

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "exchange",
		Storage:   storage,
		Data: map[string]interface{}{
			"public_key": suppliedPublicKey,
		},
	}

	resp, err := backend.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError())
	require.Equal(t, "access-token", resp.Data["access_token"])
	require.Equal(t, "session-token", resp.Data["session_token"])
	require.Nil(t, resp.Data["private_key"])
	require.Nil(t, resp.Data["public_key"])
}

func TestPathExchange_CallerSuppliedSubjectTokenUsesCallerPublicKey(t *testing.T) {
	suppliedPrivateKey := generateTestRSAPrivateKeyPEM(t)
	suppliedPublicKey := deriveTestPublicKeyPEM(t, suppliedPrivateKey)

	b, storage := getTestBackend(t)

	b.setTokenExchanger(func(ctx context.Context, subjectToken, requestedTokenType, resType, publicKey string, ttl time.Duration, config *federatedConfig) (*tokenExchangeResult, error) {
		require.Equal(t, "caller-jwt-token", subjectToken)
		require.Equal(t, suppliedPublicKey, publicKey)
		return &tokenExchangeResult{
			AccessToken:        "access-token",
			SessionToken:       "session-token",
			TokenType:          "Bearer",
			RequestedTokenType: ociRequestedTokenTypeUPST,
			PrivateKey:         "should-not-be-returned",
			PublicKey:          "should-not-be-returned",
		}, nil
	})

	reqConfig := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"domain_url":    "https://idcs-test.identity.oraclecloud.com",
			"client_id":     "test-client-id",
			"client_secret": "test-client-secret",
		},
	}
	_, err := b.HandleRequest(context.Background(), reqConfig)
	require.NoError(t, err)

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "exchange",
		Storage:   storage,
		Data: map[string]interface{}{
			"subject_token": "caller-jwt-token",
			"public_key":    suppliedPublicKey,
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError())
	require.Equal(t, "access-token", resp.Data["access_token"])
	require.Equal(t, "session-token", resp.Data["session_token"])
	require.Nil(t, resp.Data["private_key"])
	require.Nil(t, resp.Data["public_key"])
}

func TestPathExchange_GeneratedKeyResponseOmitsPublicKey(t *testing.T) {
	b, storage := getTestBackend(t)

	b.setTokenExchanger(func(ctx context.Context, subjectToken, requestedTokenType, resType, publicKey string, ttl time.Duration, config *federatedConfig) (*tokenExchangeResult, error) {
		require.Equal(t, "caller-jwt-token", subjectToken)
		require.Empty(t, publicKey)
		return &tokenExchangeResult{
			AccessToken:        "access-token",
			SessionToken:       "session-token",
			TokenType:          "Bearer",
			RequestedTokenType: ociRequestedTokenTypeUPST,
			PrivateKey:         "generated-private-key",
			PublicKey:          "generated-public-key",
		}, nil
	})

	reqConfig := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"domain_url":    "https://idcs-test.identity.oraclecloud.com",
			"client_id":     "test-client-id",
			"client_secret": "test-client-secret",
		},
	}
	_, err := b.HandleRequest(context.Background(), reqConfig)
	require.NoError(t, err)

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "exchange",
		Storage:   storage,
		Data: map[string]interface{}{
			"subject_token": "caller-jwt-token",
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError())
	require.Equal(t, "access-token", resp.Data["access_token"])
	require.Equal(t, "session-token", resp.Data["session_token"])
	require.Equal(t, "generated-private-key", resp.Data["private_key"])
	require.Nil(t, resp.Data["public_key"])
}

func TestPathExchange_DebugClaimsDoNotSuppressErrorResponse(t *testing.T) {
	b, storage := getTestBackend(t)

	b.setTokenExchanger(func(ctx context.Context, subjectToken, requestedTokenType, resType, publicKey string, ttl time.Duration, config *federatedConfig) (*tokenExchangeResult, error) {
		return nil, fmt.Errorf("upstream exchange failure")
	})

	reqConfig := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"domain_url":    "https://idcs-test.identity.oraclecloud.com",
			"client_id":     "test-client-id",
			"client_secret": "test-client-secret",
			"debug_return_resolved_subject_token_claims": true,
		},
	}
	_, err := b.HandleRequest(context.Background(), reqConfig)
	require.NoError(t, err)

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "exchange",
		Storage:   storage,
		Data: map[string]interface{}{
			"subject_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiaXNzIjoiaHR0cHM6Ly92YXVsdC5leGFtcGxlLmNvbSIsImF1ZCI6InVybjptYWNlOm9jaTppZGNzIiwiZXhwIjo0MTAyNDQ0ODAwfQ.signature",
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "token exchange failed")
	require.NotNil(t, resp.Data)
	debugData, ok := resp.Data["data"].(map[string]interface{})
	require.True(t, ok)
	require.Contains(t, debugData, "resolved_subject_token_claims")
}

func TestPathExchange_SelfMintRolePathAddsCustomClaimsToResolvedToken(t *testing.T) {
	testKey := generateTestRSAPrivateKeyPEM(t)

	b, storage := getTestBackend(t)
	b.setTokenExchanger(func(ctx context.Context, subjectToken, requestedTokenType, resType, publicKey string, ttl time.Duration, config *federatedConfig) (*tokenExchangeResult, error) {
		return &tokenExchangeResult{
			AccessToken:        "access-token",
			SessionToken:       "session-token",
			TokenType:          "Bearer",
			RequestedTokenType: ociRequestedTokenTypeUPST,
		}, nil
	})

	reqConfig := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"domain_url":                                 "https://idcs-test.identity.oraclecloud.com",
			"client_id":                                  "test-client-id",
			"client_secret":                              "test-client-secret",
			"subject_token_self_mint_enabled":            true,
			"subject_token_self_mint_issuer":             "https://vault.example.com",
			"subject_token_self_mint_private_key":        testKey,
			"debug_return_resolved_subject_token_claims": true,
		},
	}
	_, err := b.HandleRequest(context.Background(), reqConfig)
	require.NoError(t, err)

	reqRole := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/developer",
		Storage:   storage,
		Data: map[string]interface{}{
			"self_mint_custom_claims": `{"oci_role":"developer","principal":"developer-static"}`,
		},
	}
	_, err = b.HandleRequest(context.Background(), reqRole)
	require.NoError(t, err)

	for _, tc := range []struct {
		name string
		op   logical.Operation
	}{
		{name: "create", op: logical.CreateOperation},
		{name: "update", op: logical.UpdateOperation},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := &logical.Request{
				Operation: tc.op,
				Path:      "exchange/developer",
				Storage:   storage,
			}

			resp, err := b.HandleRequest(context.Background(), req)
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.False(t, resp.IsError())

			claims, ok := resp.Data["resolved_subject_token_claims"].(map[string]interface{})
			require.True(t, ok)
			require.Equal(t, "developer", claims["oci_role"])
			require.Equal(t, "developer-static", claims["principal"])
		})
	}
}

func TestPathExchange_SelfMintWithoutRolePathDoesNotAddRoleCustomClaims(t *testing.T) {
	testKey := generateTestRSAPrivateKeyPEM(t)

	b, storage := getTestBackend(t)
	b.setTokenExchanger(func(ctx context.Context, subjectToken, requestedTokenType, resType, publicKey string, ttl time.Duration, config *federatedConfig) (*tokenExchangeResult, error) {
		return &tokenExchangeResult{
			AccessToken:        "access-token",
			SessionToken:       "session-token",
			TokenType:          "Bearer",
			RequestedTokenType: ociRequestedTokenTypeUPST,
		}, nil
	})

	reqConfig := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"domain_url":                                 "https://idcs-test.identity.oraclecloud.com",
			"client_id":                                  "test-client-id",
			"client_secret":                              "test-client-secret",
			"subject_token_self_mint_enabled":            true,
			"subject_token_self_mint_issuer":             "https://vault.example.com",
			"subject_token_self_mint_private_key":        testKey,
			"debug_return_resolved_subject_token_claims": true,
		},
	}
	_, err := b.HandleRequest(context.Background(), reqConfig)
	require.NoError(t, err)

	reqRole := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/developer",
		Storage:   storage,
		Data: map[string]interface{}{
			"self_mint_custom_claims": `{"oci_role":"developer"}`,
		},
	}
	_, err = b.HandleRequest(context.Background(), reqRole)
	require.NoError(t, err)

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "exchange",
		Storage:   storage,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError())

	claims, ok := resp.Data["resolved_subject_token_claims"].(map[string]interface{})
	require.True(t, ok)
	require.NotContains(t, claims, "oci_role")
}

func TestPathExchange_BrokeredModeUsesReissuedToken(t *testing.T) {
	b, storage := getTestBackend(t)
	incomingKey := generateTestRSAPrivateKey(t)
	selfMintKey := generateTestRSAPrivateKeyPEM(t)
	var exchangedSubjectToken string

	b.setTokenExchanger(func(ctx context.Context, subjectToken, requestedTokenType, resType, publicKey string, ttl time.Duration, config *federatedConfig) (*tokenExchangeResult, error) {
		exchangedSubjectToken = subjectToken
		return &tokenExchangeResult{
			AccessToken:        "access-token",
			SessionToken:       "session-token",
			TokenType:          "Bearer",
			RequestedTokenType: ociRequestedTokenTypeUPST,
		}, nil
	})

	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"domain_url":                                 "https://idcs-test.identity.oraclecloud.com",
			"client_id":                                  "test-client-id",
			"client_secret":                              "test-client-secret",
			"subject_token_self_mint_issuer":             "https://vault.example.com",
			"subject_token_self_mint_private_key":        selfMintKey,
			"debug_return_resolved_subject_token_claims": true,
			"brokered_subject_token_enabled":             true,
			"brokered_subject_token_trust_type":          "public_keys",
			"brokered_subject_token_issuer":              "https://issuer.example.com",
			"brokered_subject_token_allowed_audiences":   []string{"urn:test"},
			"brokered_subject_token_allowed_algs":        []string{"RS256"},
			"brokered_subject_token_public_keys":         encodeTestPublicKeyPEM(t, &incomingKey.PublicKey),
			"brokered_subject_token_claim_mappings":      `{"external_sub":"{{ claims.sub }}","principal":"svc/{{ claims.org }}/{{ claims.user.id }}"}`,
		},
	})
	require.NoError(t, err)

	incomingToken := makeSignedTestJWT(t, incomingKey, jose.RS256, map[string]interface{}{
		"iss":  "https://issuer.example.com",
		"sub":  "user-123",
		"aud":  "urn:test",
		"org":  "acme",
		"user": map[string]interface{}{"id": "42"},
		"iat":  time.Now().Add(-time.Minute).Unix(),
		"nbf":  time.Now().Add(-time.Minute).Unix(),
		"exp":  time.Now().Add(time.Hour).Unix(),
	})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "exchange",
		Storage:   storage,
		Data: map[string]interface{}{
			"subject_token": incomingToken,
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError())
	require.NotEqual(t, incomingToken, exchangedSubjectToken)

	claims, ok := resp.Data["resolved_subject_token_claims"].(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, "https://vault.example.com", claims["iss"])
	require.Equal(t, "user-123", claims["external_sub"])
	require.Equal(t, "svc/acme/42", claims["principal"])
}

func TestPathExchange_BrokeredRolePathAddsExistingSelfMintCustomClaims(t *testing.T) {
	b, storage := getTestBackend(t)
	incomingKey := generateTestRSAPrivateKey(t)
	selfMintKey := generateTestRSAPrivateKeyPEM(t)

	b.setTokenExchanger(func(ctx context.Context, subjectToken, requestedTokenType, resType, publicKey string, ttl time.Duration, config *federatedConfig) (*tokenExchangeResult, error) {
		return &tokenExchangeResult{
			AccessToken:        "access-token",
			SessionToken:       "session-token",
			TokenType:          "Bearer",
			RequestedTokenType: ociRequestedTokenTypeUPST,
		}, nil
	})

	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"domain_url":                                 "https://idcs-test.identity.oraclecloud.com",
			"client_id":                                  "test-client-id",
			"client_secret":                              "test-client-secret",
			"subject_token_self_mint_issuer":             "https://vault.example.com",
			"subject_token_self_mint_private_key":        selfMintKey,
			"debug_return_resolved_subject_token_claims": true,
			"brokered_subject_token_enabled":             true,
			"brokered_subject_token_trust_type":          "public_keys",
			"brokered_subject_token_issuer":              "https://issuer.example.com",
			"brokered_subject_token_allowed_audiences":   []string{"urn:test"},
			"brokered_subject_token_allowed_algs":        []string{"RS256"},
			"brokered_subject_token_public_keys":         encodeTestPublicKeyPEM(t, &incomingKey.PublicKey),
			"brokered_subject_token_claim_mappings":      `{"external_sub":"{{ claims.sub }}"}`,
		},
	})
	require.NoError(t, err)

	_, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/developer",
		Storage:   storage,
		Data: map[string]interface{}{
			"self_mint_custom_claims": `{"oci_role":"developer","external_subject":"{{ brokered.claims.sub }}"}`,
		},
	})
	require.NoError(t, err)

	incomingToken := makeSignedTestJWT(t, incomingKey, jose.RS256, map[string]interface{}{
		"iss": "https://issuer.example.com",
		"sub": "user-123",
		"aud": "urn:test",
		"iat": time.Now().Add(-time.Minute).Unix(),
		"nbf": time.Now().Add(-time.Minute).Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	for _, tc := range []struct {
		name string
		op   logical.Operation
	}{
		{name: "create", op: logical.CreateOperation},
		{name: "update", op: logical.UpdateOperation},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: tc.op,
				Path:      "exchange/developer",
				Storage:   storage,
				Data: map[string]interface{}{
					"subject_token": incomingToken,
				},
			})
			require.NoError(t, err)
			require.False(t, resp.IsError())

			claims, ok := resp.Data["resolved_subject_token_claims"].(map[string]interface{})
			require.True(t, ok)
			require.Equal(t, "developer", claims["oci_role"])
			require.Equal(t, "user-123", claims["external_sub"])
			require.Equal(t, "user-123", claims["external_subject"])
		})
	}
}

func TestPathExchange_BrokeredBareExchangeDoesNotAddRoleScopedClaims(t *testing.T) {
	b, storage := getTestBackend(t)
	incomingKey := generateTestRSAPrivateKey(t)
	selfMintKey := generateTestRSAPrivateKeyPEM(t)

	b.setTokenExchanger(func(ctx context.Context, subjectToken, requestedTokenType, resType, publicKey string, ttl time.Duration, config *federatedConfig) (*tokenExchangeResult, error) {
		return &tokenExchangeResult{
			AccessToken:        "access-token",
			SessionToken:       "session-token",
			TokenType:          "Bearer",
			RequestedTokenType: ociRequestedTokenTypeUPST,
		}, nil
	})

	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"domain_url":                                 "https://idcs-test.identity.oraclecloud.com",
			"client_id":                                  "test-client-id",
			"client_secret":                              "test-client-secret",
			"subject_token_self_mint_issuer":             "https://vault.example.com",
			"subject_token_self_mint_private_key":        selfMintKey,
			"debug_return_resolved_subject_token_claims": true,
			"brokered_subject_token_enabled":             true,
			"brokered_subject_token_trust_type":          "public_keys",
			"brokered_subject_token_issuer":              "https://issuer.example.com",
			"brokered_subject_token_allowed_audiences":   []string{"urn:test"},
			"brokered_subject_token_allowed_algs":        []string{"RS256"},
			"brokered_subject_token_public_keys":         encodeTestPublicKeyPEM(t, &incomingKey.PublicKey),
			"brokered_subject_token_claim_mappings":      `{"external_sub":"{{ claims.sub }}"}`,
		},
	})
	require.NoError(t, err)

	_, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/developer",
		Storage:   storage,
		Data: map[string]interface{}{
			"self_mint_custom_claims": `{"oci_role":"developer"}`,
		},
	})
	require.NoError(t, err)

	incomingToken := makeSignedTestJWT(t, incomingKey, jose.RS256, map[string]interface{}{
		"iss": "https://issuer.example.com",
		"sub": "user-123",
		"aud": "urn:test",
		"iat": time.Now().Add(-time.Minute).Unix(),
		"nbf": time.Now().Add(-time.Minute).Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "exchange",
		Storage:   storage,
		Data: map[string]interface{}{
			"subject_token": incomingToken,
		},
	})
	require.NoError(t, err)
	require.False(t, resp.IsError())

	claims, ok := resp.Data["resolved_subject_token_claims"].(map[string]interface{})
	require.True(t, ok)
	require.NotContains(t, claims, "oci_role")
}

func TestPathExchange_BrokeredModeOffPreservesDirectPassThrough(t *testing.T) {
	b, storage := getTestBackend(t)
	b.setTokenExchanger(func(ctx context.Context, subjectToken, requestedTokenType, resType, publicKey string, ttl time.Duration, config *federatedConfig) (*tokenExchangeResult, error) {
		require.Equal(t, "caller-jwt-token", subjectToken)
		return &tokenExchangeResult{
			AccessToken:        "access-token",
			SessionToken:       "session-token",
			TokenType:          "Bearer",
			RequestedTokenType: ociRequestedTokenTypeUPST,
		}, nil
	})

	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"domain_url":                     "https://idcs-test.identity.oraclecloud.com",
			"client_id":                      "test-client-id",
			"client_secret":                  "test-client-secret",
			"brokered_subject_token_enabled": false,
		},
	})
	require.NoError(t, err)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "exchange",
		Storage:   storage,
		Data: map[string]interface{}{
			"subject_token": "caller-jwt-token",
		},
	})
	require.NoError(t, err)
	require.False(t, resp.IsError())
}

func TestPathExchange_SubjectTokenAudienceOverrideRejectedForCallerProvidedToken(t *testing.T) {
	b, storage := getTestBackend(t)
	installFailingTokenExchanger(b)

	reqConfig := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"domain_url":    "https://idcs-test.identity.oraclecloud.com",
			"client_id":     "test-client-id",
			"client_secret": "test-client-secret",
		},
	}
	_, err := b.HandleRequest(context.Background(), reqConfig)
	require.NoError(t, err)

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "exchange",
		Storage:   storage,
		Data: map[string]interface{}{
			"subject_token":          "token123",
			"subject_token_audience": "urn:oci:test",
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "subject_token_audience is only supported when subject_token is omitted")
}

func TestPathExchange_SubjectTokenAudienceOverrideRejectedWhenNotAllowlisted(t *testing.T) {
	b, storage := getTestBackend(t)
	installFailingTokenExchanger(b)

	reqConfig := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"domain_url":                      "https://idcs-test.identity.oraclecloud.com",
			"client_id":                       "test-client-id",
			"client_secret":                   "test-client-secret",
			"subject_token_self_mint_enabled": true,
			"subject_token_self_mint_issuer":  "https://vault.example.com",
		},
	}
	_, err := b.HandleRequest(context.Background(), reqConfig)
	require.NoError(t, err)

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "exchange",
		Storage:   storage,
		Data: map[string]interface{}{
			"subject_token_audience": "urn:oci:test",
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "subject_token_audience override is not enabled for this backend")
}

func TestPathExchange_DefaultCallbackSelfMintUsesAudienceOverride(t *testing.T) {
	testKey := generateTestRSAPrivateKeyPEM(t)

	b, err := Factory("v0.0.0-test")(context.Background(), &logical.BackendConfig{
		System: &mockSystemView{
			mockIdentity: "",
			StaticSystemView: logical.StaticSystemView{
				DefaultLeaseTTLVal: time.Hour,
				MaxLeaseTTLVal:     24 * time.Hour,
			},
		},
	})
	require.NoError(t, err)
	backend := b.(*backend)
	installFailingTokenExchanger(backend)
	storage := &logical.InmemStorage{}

	reqConfig := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"domain_url":                          "https://idcs-test.identity.oraclecloud.com",
			"client_id":                           "test-client-id",
			"client_secret":                       "test-client-secret",
			"subject_token_self_mint_enabled":     true,
			"subject_token_self_mint_issuer":      "https://vault.example.com",
			"subject_token_self_mint_private_key": testKey,
			"subject_token_allowed_audiences":     []string{"urn:oci:test"},
		},
	}
	_, err = backend.HandleRequest(context.Background(), reqConfig)
	require.NoError(t, err)

	token, err := backend.defaultSubjectTokenCallback(context.Background(), &logical.Request{
		Data: map[string]interface{}{
			"subject_token_audience": "urn:oci:test",
		},
	}, mustGetConfig(t, backend, storage))
	require.NoError(t, err)

	claims := decodeJWTClaims(t, token)
	require.Equal(t, "urn:oci:test", claims["aud"])
}

func TestPathExchange_DefaultCallbackGenerateIdentityTokenUsesAudienceOverride(t *testing.T) {
	systemView := &mockSystemView{
		mockIdentity: "mocked-wif-identity-token",
		StaticSystemView: logical.StaticSystemView{
			DefaultLeaseTTLVal: time.Hour,
			MaxLeaseTTLVal:     24 * time.Hour,
		},
	}
	b, err := Factory("v0.0.0-test")(context.Background(), &logical.BackendConfig{
		System: systemView,
	})
	require.NoError(t, err)
	backend := b.(*backend)
	installFailingTokenExchanger(backend)
	storage := &logical.InmemStorage{}

	reqConfig := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"domain_url":                       "https://idcs-test.identity.oraclecloud.com",
			"client_id":                        "test-client-id",
			"client_secret":                    "test-client-secret",
			"subject_token_self_mint_audience": "urn:mace:oci:idcs",
			"subject_token_allowed_audiences":  []string{"urn:oci:test"},
		},
	}
	_, err = backend.HandleRequest(context.Background(), reqConfig)
	require.NoError(t, err)

	_, err = backend.defaultSubjectTokenCallback(context.Background(), &logical.Request{
		Data: map[string]interface{}{
			"subject_token_audience": "urn:oci:test",
		},
	}, mustGetConfig(t, backend, storage))
	require.NoError(t, err)
	require.Equal(t, "urn:oci:test", systemView.lastAudienceSeen)
}

func mustGetConfig(t *testing.T, b *backend, storage logical.Storage) *federatedConfig {
	t.Helper()
	config, err := b.getConfig(context.Background(), storage)
	require.NoError(t, err)
	require.NotNil(t, config)
	return config
}

func deriveTestPublicKeyPEM(t *testing.T, privateKeyPEM string) string {
	t.Helper()

	block, _ := pem.Decode([]byte(privateKeyPEM))
	require.NotNil(t, block)

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err)

	publicKeyPEM, err := marshalPublicKeyToPEM(privateKey.Public())
	require.NoError(t, err)
	return publicKeyPEM
}

func TestDefaultCallbackSelfMintUsesTrustedVaultIdentityClaims(t *testing.T) {
	testKey := generateTestRSAPrivateKeyPEM(t)

	b, err := Factory("v0.0.0-test")(context.Background(), &logical.BackendConfig{
		System: &mockSystemView{
			mockIdentity: "",
			StaticSystemView: logical.StaticSystemView{
				DefaultLeaseTTLVal: time.Hour,
				MaxLeaseTTLVal:     24 * time.Hour,
				EntityVal: &logical.Entity{
					ID:          "entity-123",
					Name:        "deployer",
					NamespaceID: "root",
					Metadata: map[string]string{
						"team": "platform",
					},
					Aliases: []*logical.Alias{
						{
							Name:          "sa:default:app",
							MountAccessor: "auth_kubernetes_123",
							MountType:     "kubernetes",
							Metadata: map[string]string{
								"service_account_name": "app",
							},
							CustomMetadata: map[string]string{
								"cluster": "dev",
							},
						},
					},
				},
				GroupsVal: []*logical.Group{
					{Name: "deployers"},
					{Name: "platform"},
				},
			},
		},
	})
	require.NoError(t, err)
	backend := b.(*backend)

	config := &federatedConfig{
		SubjectTokenSelfMintEnabled:    true,
		SubjectTokenSelfMintIssuer:     "https://vault.example.com",
		SubjectTokenSelfMintAudience:   "urn:mace:oci:idcs",
		SubjectTokenSelfMintTTLSeconds: 600,
		SubjectTokenSelfMintPrivateKey: testKey,
	}

	req := &logical.Request{
		EntityID:            "entity-123",
		DisplayName:         "kubernetes-app",
		MountAccessor:       "auth_kubernetes_123",
		MountType:           "kubernetes",
		ClientTokenAccessor: "hmac-token-accessor",
	}

	token, err := backend.defaultSubjectTokenCallback(context.Background(), req, config)
	require.NoError(t, err)

	claims := decodeJWTClaims(t, token)
	require.Equal(t, "vault:entity:entity-123", claims["sub"])
	require.Equal(t, "entity-123", claims["vault_entity_id"])
	require.Equal(t, "deployer", claims["vault_entity_name"])
	require.Equal(t, "root", claims["vault_namespace_id"])
	require.Equal(t, "kubernetes-app", claims["vault_display_name"])
	require.Equal(t, "auth_kubernetes_123", claims["vault_mount_accessor"])
	require.Equal(t, "kubernetes", claims["vault_mount_type"])
	require.Equal(t, "sa:default:app", claims["vault_alias_name"])
	require.Equal(t, "auth_kubernetes_123", claims["vault_alias_mount_accessor"])
	require.Equal(t, "kubernetes", claims["vault_alias_mount_type"])
	require.Equal(t, "hmac-token-accessor", claims["vault_client_token_accessor"])
	require.NotContains(t, claims, "vault_role")
	require.NotContains(t, claims, "role")

	entityMetadata, ok := claims["vault_entity_metadata"].(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, "platform", entityMetadata["team"])

	aliasMetadata, ok := claims["vault_alias_metadata"].(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, "app", aliasMetadata["service_account_name"])

	aliasCustomMetadata, ok := claims["vault_alias_custom_metadata"].(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, "dev", aliasCustomMetadata["cluster"])

	groupNames, ok := claims["vault_group_names"].([]interface{})
	require.True(t, ok)
	require.Len(t, groupNames, 2)
	require.Equal(t, "deployers", groupNames[0])
	require.Equal(t, "platform", groupNames[1])
}

func TestDefaultCallbackSelfMintWithoutEntityUsesTokenContextClaims(t *testing.T) {
	testKey := generateTestRSAPrivateKeyPEM(t)

	b, err := Factory("v0.0.0-test")(context.Background(), &logical.BackendConfig{
		System: &mockSystemView{
			mockIdentity: "",
			StaticSystemView: logical.StaticSystemView{
				DefaultLeaseTTLVal: time.Hour,
				MaxLeaseTTLVal:     24 * time.Hour,
			},
		},
	})
	require.NoError(t, err)
	backend := b.(*backend)

	config := &federatedConfig{
		SubjectTokenSelfMintEnabled:    true,
		SubjectTokenSelfMintIssuer:     "https://vault.example.com",
		SubjectTokenSelfMintAudience:   "urn:mace:oci:idcs",
		SubjectTokenSelfMintTTLSeconds: 600,
		SubjectTokenSelfMintPrivateKey: testKey,
	}

	req := &logical.Request{
		DisplayName:         "token",
		MountAccessor:       "oci_automation_123",
		MountType:           "token",
		ClientTokenAccessor: "hmac-token-accessor",
	}

	token, err := backend.defaultSubjectTokenCallback(context.Background(), req, config)
	require.NoError(t, err)

	claims := decodeJWTClaims(t, token)
	require.Equal(t, "vault:display:token", claims["sub"])
	require.Equal(t, "token", claims["vault_display_name"])
	require.Equal(t, "oci_automation_123", claims["vault_mount_accessor"])
	require.Equal(t, "token", claims["vault_mount_type"])
	require.Equal(t, "hmac-token-accessor", claims["vault_client_token_accessor"])
	require.NotContains(t, claims, "vault_entity_id")
	require.NotContains(t, claims, "vault_entity_name")
	require.NotContains(t, claims, "vault_alias_name")
	require.NotContains(t, claims, "vault_group_names")
}

func TestDefaultCallbackSelfMintAddsRoleCustomClaims(t *testing.T) {
	testKey := generateTestRSAPrivateKeyPEM(t)

	b, storage := getTestBackend(t)

	reqRole := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/developer",
		Storage:   storage,
		Data: map[string]interface{}{
			"self_mint_custom_claims": `{"oci_role":"developer","principal":"{{ vault.entity.id }}"}`,
		},
	}
	_, err := b.HandleRequest(context.Background(), reqRole)
	require.NoError(t, err)

	config := &federatedConfig{
		SubjectTokenSelfMintEnabled:    true,
		SubjectTokenSelfMintIssuer:     "https://vault.example.com",
		SubjectTokenSelfMintAudience:   "urn:mace:oci:idcs",
		SubjectTokenSelfMintTTLSeconds: 600,
		SubjectTokenSelfMintPrivateKey: testKey,
	}

	req := &logical.Request{
		Storage:             storage,
		EntityID:            "entity-123",
		DisplayName:         "kubernetes-app",
		MountAccessor:       "auth_kubernetes_123",
		MountType:           "kubernetes",
		ClientTokenAccessor: "hmac-token-accessor",
		Data: map[string]interface{}{
			"role": "developer",
		},
	}

	token, err := b.defaultSubjectTokenCallback(context.Background(), req, config)
	require.NoError(t, err)

	claims := decodeJWTClaims(t, token)
	require.Equal(t, "developer", claims["oci_role"])
	require.Equal(t, "entity-123", claims["principal"])

	require.Equal(t, "entity-123", claims["vault_entity_id"])
	require.Equal(t, "kubernetes-app", claims["vault_display_name"])
}

func decodeJWTClaims(t *testing.T, token string) map[string]interface{} {
	t.Helper()

	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	var claims map[string]interface{}
	require.NoError(t, json.Unmarshal(payload, &claims))
	return claims
}
