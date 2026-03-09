package ocibackend

import (
	"context"
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
	mockIdentity string
}

func (m *mockSystemView) GenerateIdentityToken(ctx context.Context, req *pluginutil.IdentityTokenRequest) (*pluginutil.IdentityTokenResponse, error) {
	if m.mockIdentity != "" {
		return &pluginutil.IdentityTokenResponse{
			Token: pluginutil.IdentityToken(m.mockIdentity),
		}, nil
	}
	return nil, logical.ErrUnsupportedOperation
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
	storage := &logical.InmemStorage{}

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
		require.Contains(t, resp.Error().Error(), "failed to generate plugin identity token")
	})

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
		assert.Contains(t, errStr, "unable to exchange JWT for security token", "It successfully bypassed subject_token and attempted the API call utilizing the SDK")
	})
}

func TestPathExchange_RequestedTokenTypeValidation(t *testing.T) {
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
	b, storage := getTestBackend(t)

	reqConfig := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"tenancy_ocid":              "ocid1.tenancy.oc1..test",
			"domain_url":                "https://idcs-test.identity.oraclecloud.com",
			"client_id":                 "test-client-id",
			"client_secret":             "test-client-secret",
			"region":                    "us-ashburn-1",
			"enforce_role_claim_match":  true,
			"role_claim_key":            "vault_role",
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
		require.Contains(t, resp.Error().Error(), "missing 'subject_token' while enforce_role_claim_match is enabled")
	})

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
}

func TestPathExchange_PluginIdentityFallbackDisabled(t *testing.T) {
	b, storage := getTestBackend(t)

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
