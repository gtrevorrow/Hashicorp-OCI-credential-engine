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
				"tenancy_ocid":         "ocid1.tenancy.oc1..test",
				"domain_ocid":          "ocid1.identitydomain.oc1..test",
				"identity_provider_id": "ocid1.idp.oc1..test",
				"region":               "us-ashburn-1",
				"jwks_url":             "https://example.com/jwks",
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
			"tenancy_ocid":         "ocid1.tenancy.oc1..test",
			"domain_ocid":          "ocid1.identitydomain.oc1..test",
			"identity_provider_id": "ocid1.idp.oc1..test",
			"region":               "us-ashburn-1",
			"jwks_url":             "https://example.com/jwks",
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
		assert.Equal(t, "us-ashburn-1", resp.Data["region"])
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
