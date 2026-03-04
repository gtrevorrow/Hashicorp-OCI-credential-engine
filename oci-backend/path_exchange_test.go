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

// mockSystemView is used to inject an Enterprise Vault version for WIF testing
type mockSystemView struct {
	logical.StaticSystemView
	isEnterprise bool
	mockIdentity string
}

func (m *mockSystemView) VaultVersion(ctx context.Context) (string, error) {
	if m.isEnterprise {
		return "1.16.0+ent", nil
	}
	return "1.16.0", nil
}

func (m *mockSystemView) GenerateIdentityToken(ctx context.Context, req *pluginutil.IdentityTokenRequest) (*pluginutil.IdentityTokenResponse, error) {
	if m.isEnterprise && m.mockIdentity != "" {
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
			isEnterprise: false,
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

	t.Run("Missing Subject Token (Non-Enterprise)", func(t *testing.T) {
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
		require.Contains(t, resp.Error().Error(), "missing 'subject_token'")
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

// Separate test function specifically for mocking Enterprise WIF
func TestPathExchange_WIFEnterprise(t *testing.T) {
	b, err := Factory("v0.0.0-test")(context.Background(), &logical.BackendConfig{
		System: &mockSystemView{
			isEnterprise: true,
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
