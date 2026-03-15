package ocibackend

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

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
	b.tokenExchanger = func(ctx context.Context, subjectToken, requestedTokenType, resType, publicKey string, config *federatedConfig) (*tokenExchangeResult, error) {
		return nil, fmt.Errorf("stub exchange failure")
	}
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
			Path:      "exchange",
			Storage:   storage,
			Data: map[string]interface{}{
				"role":          "dev",
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
			"tenancy_ocid":  "ocid1.tenancy.oc1..test",
			"domain_url":    "https://idcs-test.identity.oraclecloud.com",
			"client_id":     "test-client-id",
			"client_secret": "test-client-secret",
			"region":        "us-ashburn-1",
		},
	}
	_, err = backend.HandleRequest(context.Background(), reqConfig)
	require.NoError(t, err)

	reqRole := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/dev",
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
			Path:      "exchange",
			Storage:   storage,
			Data: map[string]interface{}{
				"role": "dev",
			},
		}

		resp, err := backend.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.True(t, resp.IsError())
		require.Contains(t, resp.Error().Error(), "failed to mint subject_token via callback")
	})

	// Baseline role lookup validation; not tied to a named plan ID.
	t.Run("Missing Role", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "exchange",
			Storage:   storage,
			Data: map[string]interface{}{
				"role":          "nonexistent",
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
			"tenancy_ocid":  "ocid1.tenancy.oc1..test",
			"domain_url":    "https://idcs-test.identity.oraclecloud.com",
			"client_id":     "test-client-id",
			"client_secret": "test-client-secret",
			"region":        "us-ashburn-1",
		},
	}
	_, _ = backend.HandleRequest(context.Background(), reqConfig)

	reqRole := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/dev",
		Storage:   storage,
		Data: map[string]interface{}{
			"description": "dev role",
		},
	}
	_, _ = backend.HandleRequest(context.Background(), reqRole)

	t.Run("Enterprise Token Generation Bypass", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "exchange",
			Storage:   storage,
			Data: map[string]interface{}{
				"role": "dev",
				// subject_token intentionally omitted!
			},
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
			"tenancy_ocid":  "ocid1.tenancy.oc1..test",
			"domain_url":    "https://idcs-test.identity.oraclecloud.com",
			"client_id":     "test-client-id",
			"client_secret": "test-client-secret",
			"region":        "us-ashburn-1",
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

func TestPathExchange_RoleClaimMatchGuardrail(t *testing.T) {
	// Covers EXC-08, RCM-01, RCM-02, and RCM-05.
	b, storage := getTestBackend(t)
	installFailingTokenExchanger(b)

	reqConfig := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"tenancy_ocid":             "ocid1.tenancy.oc1..test",
			"domain_url":               "https://idcs-test.identity.oraclecloud.com",
			"client_id":                "test-client-id",
			"client_secret":            "test-client-secret",
			"region":                   "us-ashburn-1",
			"enforce_role_claim_match": true,
			"role_claim_key":           "vault_role",
		},
	}
	_, err := b.HandleRequest(context.Background(), reqConfig)
	require.NoError(t, err)

	reqRole := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/dev",
		Storage:   storage,
		Data: map[string]interface{}{
			"description": "dev role",
		},
	}
	_, err = b.HandleRequest(context.Background(), reqRole)
	require.NoError(t, err)

	// Covers EXC-08.
	t.Run("Missing Role When Enforced", func(t *testing.T) {
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
		require.Contains(t, resp.Error().Error(), "missing 'role'")
	})

	// Covers the failure mode of EXC-09 when fallback token resolution is unavailable.
	t.Run("Missing Subject Token When Enforced", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "exchange",
			Storage:   storage,
			Data: map[string]interface{}{
				"role": "dev",
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.True(t, resp.IsError())
		require.Contains(t, resp.Error().Error(), "failed to mint subject_token via callback")
	})

	// Covers RCM-02.
	t.Run("Claim Mismatch", func(t *testing.T) {
		subjectToken := makeTestJWT(t, map[string]interface{}{"vault_role": "prod"})
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "exchange",
			Storage:   storage,
			Data: map[string]interface{}{
				"subject_token": subjectToken,
				"role":          "dev",
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.True(t, resp.IsError())
		require.Contains(t, resp.Error().Error(), "role claim mismatch")
	})

	// Covers RCM-01.
	t.Run("Claim Match Proceeds Past Guardrail", func(t *testing.T) {
		subjectToken := makeTestJWT(t, map[string]interface{}{"vault_role": "dev"})
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "exchange",
			Storage:   storage,
			Data: map[string]interface{}{
				"subject_token": subjectToken,
				"role":          "dev",
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.True(t, resp.IsError())
		require.NotContains(t, resp.Error().Error(), "role claim mismatch")
		require.Contains(t, resp.Error().Error(), "token exchange failed")
	})

	// Covers RCM-05.
	t.Run("Array Claim Match Proceeds Past Guardrail", func(t *testing.T) {
		subjectToken := makeTestJWT(t, map[string]interface{}{"vault_role": []string{"prod", "dev"}})
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "exchange",
			Storage:   storage,
			Data: map[string]interface{}{
				"subject_token": subjectToken,
				"role":          "dev",
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.True(t, resp.IsError())
		require.NotContains(t, resp.Error().Error(), "role claim mismatch")
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
			"tenancy_ocid":                   "ocid1.tenancy.oc1..test",
			"domain_url":                     "https://idcs-test.identity.oraclecloud.com",
			"client_id":                      "test-client-id",
			"client_secret":                  "test-client-secret",
			"region":                         "us-ashburn-1",
			"allow_plugin_identity_fallback": false,
		},
	}
	_, err := b.HandleRequest(context.Background(), reqConfig)
	require.NoError(t, err)

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "exchange",
		Storage:   storage,
		Data: map[string]interface{}{
			"role": "dev",
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "missing 'subject_token' and plugin identity fallback is disabled")
}

func TestPathExchange_CustomRoleClaimKey(t *testing.T) {
	// Covers RCM-01 and RCM-02 with a non-default claim key.
	b, storage := getTestBackend(t)
	installFailingTokenExchanger(b)

	reqConfig := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"tenancy_ocid":             "ocid1.tenancy.oc1..test",
			"domain_url":               "https://idcs-test.identity.oraclecloud.com",
			"client_id":                "test-client-id",
			"client_secret":            "test-client-secret",
			"region":                   "us-ashburn-1",
			"enforce_role_claim_match": true,
			"role_claim_key":           "oci_target",
		},
	}
	_, err := b.HandleRequest(context.Background(), reqConfig)
	require.NoError(t, err)

	reqRole := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/svc-dev-automation",
		Storage:   storage,
		Data: map[string]interface{}{
			"description": "service-user role",
		},
	}
	_, err = b.HandleRequest(context.Background(), reqRole)
	require.NoError(t, err)

	t.Run("Custom Claim Match", func(t *testing.T) {
		subjectToken := makeTestJWT(t, map[string]interface{}{"oci_target": "svc-dev-automation"})
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "exchange",
			Storage:   storage,
			Data: map[string]interface{}{
				"subject_token": subjectToken,
				"role":          "svc-dev-automation",
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.True(t, resp.IsError())
		require.NotContains(t, resp.Error().Error(), "role claim mismatch")
		require.Contains(t, resp.Error().Error(), "token exchange failed")
	})

	t.Run("Custom Claim Mismatch", func(t *testing.T) {
		subjectToken := makeTestJWT(t, map[string]interface{}{"oci_target": "svc-prod-automation"})
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "exchange",
			Storage:   storage,
			Data: map[string]interface{}{
				"subject_token": subjectToken,
				"role":          "svc-dev-automation",
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.True(t, resp.IsError())
		require.Contains(t, resp.Error().Error(), "role claim mismatch")
	})
}

func TestPathExchange_StrictRoleNameMatch(t *testing.T) {
	// Covers RCM-07.
	b, storage := getTestBackend(t)
	installFailingTokenExchanger(b)

	reqConfig := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"tenancy_ocid":             "ocid1.tenancy.oc1..test",
			"domain_url":               "https://idcs-test.identity.oraclecloud.com",
			"client_id":                "test-client-id",
			"client_secret":            "test-client-secret",
			"region":                   "us-ashburn-1",
			"strict_role_name_match":   true,
			"enforce_role_claim_match": true,
			"role_claim_key":           "vault_role",
		},
	}
	_, err := b.HandleRequest(context.Background(), reqConfig)
	require.NoError(t, err)

	subjectToken := makeTestJWT(t, map[string]interface{}{"vault_role": "dev@team"})
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "exchange",
		Storage:   storage,
		Data: map[string]interface{}{
			"subject_token": subjectToken,
			"role":          "dev@team",
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "invalid role")
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
			"tenancy_ocid":  "ocid1.tenancy.oc1..test",
			"domain_url":    "https://idcs-test.identity.oraclecloud.com",
			"client_id":     "test-client-id",
			"client_secret": "test-client-secret",
			"region":        "us-ashburn-1",
		},
	}
	_, err = backend.HandleRequest(context.Background(), reqConfig)
	require.NoError(t, err)

	reqRole := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/dev",
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
		Path:      "exchange",
		Storage:   storage,
		Data: map[string]interface{}{
			"role": "dev",
		},
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
			"tenancy_ocid":  "ocid1.tenancy.oc1..test",
			"domain_url":    "https://idcs-test.identity.oraclecloud.com",
			"client_id":     "test-client-id",
			"client_secret": "test-client-secret",
			"region":        "us-ashburn-1",
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
			"tenancy_ocid":                        "ocid1.tenancy.oc1..test",
			"domain_url":                          "https://idcs-test.identity.oraclecloud.com",
			"client_id":                           "test-client-id",
			"client_secret":                       "test-client-secret",
			"region":                              "us-ashburn-1",
			"subject_token_self_mint_enabled":     true,
			"subject_token_self_mint_issuer":      "https://vault.example.com",
			"subject_token_self_mint_private_key": testKey,
			"enforce_role_claim_match":            true,
			"role_claim_key":                      "vault_role",
		},
	}
	_, err = backend.HandleRequest(context.Background(), reqConfig)
	require.NoError(t, err)

	reqRole := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/dev",
		Storage:   storage,
		Data: map[string]interface{}{
			"description": "dev role",
		},
	}
	_, err = backend.HandleRequest(context.Background(), reqRole)
	require.NoError(t, err)

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "exchange",
		Storage:   storage,
		Data: map[string]interface{}{
			"role": "dev",
		},
	}

	resp, err := backend.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.NotContains(t, resp.Error().Error(), "failed to mint subject_token via callback")
	require.NotContains(t, resp.Error().Error(), "role claim mismatch")
	require.Contains(t, resp.Error().Error(), "token exchange failed")
}

func TestPathExchange_SubjectTokenAudienceOverrideRejectedForCallerProvidedToken(t *testing.T) {
	b, storage := getTestBackend(t)
	installFailingTokenExchanger(b)

	reqConfig := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"tenancy_ocid":  "ocid1.tenancy.oc1..test",
			"domain_url":    "https://idcs-test.identity.oraclecloud.com",
			"client_id":     "test-client-id",
			"client_secret": "test-client-secret",
			"region":        "us-ashburn-1",
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
			"tenancy_ocid":                    "ocid1.tenancy.oc1..test",
			"domain_url":                      "https://idcs-test.identity.oraclecloud.com",
			"client_id":                       "test-client-id",
			"client_secret":                   "test-client-secret",
			"region":                          "us-ashburn-1",
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
			"tenancy_ocid":                        "ocid1.tenancy.oc1..test",
			"domain_url":                          "https://idcs-test.identity.oraclecloud.com",
			"client_id":                           "test-client-id",
			"client_secret":                       "test-client-secret",
			"region":                              "us-ashburn-1",
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
			"tenancy_ocid":                     "ocid1.tenancy.oc1..test",
			"domain_url":                       "https://idcs-test.identity.oraclecloud.com",
			"client_id":                        "test-client-id",
			"client_secret":                    "test-client-secret",
			"region":                           "us-ashburn-1",
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
		Data: map[string]interface{}{
			"role": "dev",
		},
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
