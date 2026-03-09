package ocibackend

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPathConfig_Updates(t *testing.T) {
	b, storage := getTestBackend(t)

	t.Run("Create Config Success", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config",
			Storage:   storage,
			Data: map[string]interface{}{
				"tenancy_ocid":  "ocid1.tenancy.oc1..test",
				"domain_url":    "https://idcs-test.identity.oraclecloud.com",
				"client_id":     "test-client-id",
				"client_secret": "test-client-secret",
				"region":        "us-ashburn-1",
				"jwks_url":      "https://example.com/jwks",
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		assert.False(t, resp != nil && resp.IsError(), "expected no error, got: %v", resp)
	})

	t.Run("Create Config Missing Variables", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config",
			Storage:   storage,
			Data: map[string]interface{}{
				"region": "us-ashburn-1",
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		assert.NoError(t, err) // Validation errors are returned in resp.Error, not err
		assert.True(t, resp.IsError())
	})
}

func TestPathConfig_ReadDelete(t *testing.T) {
	b, storage := getTestBackend(t)

	// Pre-populate storage
	reqCreate := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"tenancy_ocid":  "ocid1.tenancy.oc1..test",
			"domain_url":    "https://idcs-test.identity.oraclecloud.com",
			"client_id":     "test-client-id",
			"client_secret": "test-client-secret",
			"region":        "us-ashburn-1",
			"jwks_url":      "https://example.com/jwks",
		},
	}
	_, err := b.HandleRequest(context.Background(), reqCreate)
	require.NoError(t, err)

	t.Run("Read Config", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "config",
			Storage:   storage,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, resp)

		assert.Equal(t, "ocid1.tenancy.oc1..test", resp.Data["tenancy_ocid"])
		assert.Equal(t, "https://idcs-test.identity.oraclecloud.com", resp.Data["domain_url"])
		assert.Equal(t, "test-client-id", resp.Data["client_id"])
		assert.Nil(t, resp.Data["client_secret"])
		assert.Equal(t, "us-ashburn-1", resp.Data["region"])
		assert.Equal(t, false, resp.Data["enforce_role_claim_match"])
		assert.Equal(t, "vault_role", resp.Data["role_claim_key"])
		assert.Equal(t, true, resp.Data["allow_plugin_identity_fallback"])
		assert.Equal(t, false, resp.Data["strict_role_name_match"])
	})

	t.Run("Delete Config", func(t *testing.T) {
		reqDelete := &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      "config",
			Storage:   storage,
		}

		resp, err := b.HandleRequest(context.Background(), reqDelete)
		require.NoError(t, err)
		assert.False(t, resp != nil && resp.IsError())

		// Verify deletion
		reqRead := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "config",
			Storage:   storage,
		}
		respRead, errRead := b.HandleRequest(context.Background(), reqRead)
		require.NoError(t, errRead)
		assert.Nil(t, respRead) // Read should return nil response if config is empty
	})
}

func TestPathConfig_RoleClaimMatchSettings(t *testing.T) {
	b, storage := getTestBackend(t)

	reqCreate := &logical.Request{
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
			"allow_plugin_identity_fallback": false,
			"strict_role_name_match":    true,
		},
	}
	_, err := b.HandleRequest(context.Background(), reqCreate)
	require.NoError(t, err)

	reqRead := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(context.Background(), reqRead)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, true, resp.Data["enforce_role_claim_match"])
	assert.Equal(t, "vault_role", resp.Data["role_claim_key"])
	assert.Equal(t, false, resp.Data["allow_plugin_identity_fallback"])
	assert.Equal(t, true, resp.Data["strict_role_name_match"])
}

func TestPathConfig_RoleClaimKeyRequiresEnforcement(t *testing.T) {
	b, storage := getTestBackend(t)

	t.Run("Rejects role_claim_key without enforcement", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config",
			Storage:   storage,
			Data: map[string]interface{}{
				"tenancy_ocid":  "ocid1.tenancy.oc1..test",
				"domain_url":    "https://idcs-test.identity.oraclecloud.com",
				"client_id":     "test-client-id",
				"client_secret": "test-client-secret",
				"region":        "us-ashburn-1",
				"role_claim_key": "vault_role",
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.True(t, resp.IsError())
		require.Contains(t, resp.Error().Error(), "role_claim_key requires enforce_role_claim_match=true")
	})

	t.Run("Accepts role_claim_key with enforcement", func(t *testing.T) {
		req := &logical.Request{
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

		resp, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		assert.False(t, resp != nil && resp.IsError())
	})
}
