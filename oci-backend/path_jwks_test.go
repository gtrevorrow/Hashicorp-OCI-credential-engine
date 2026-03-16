package ocibackend

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestPathJWKSRead(t *testing.T) {
	b, storage := getTestBackend(t)

	// Covers JWK-01.
	t.Run("Requires config", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "jwks",
			Storage:   storage,
		}
		resp, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.True(t, resp.IsError())
		require.Contains(t, resp.Error().Error(), "backend not configured")
	})

	// Covers JWK-02.
	t.Run("Requires self mint enabled", func(t *testing.T) {
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
		resp, err := b.HandleRequest(context.Background(), reqConfig)
		require.NoError(t, err)
		require.False(t, resp != nil && resp.IsError())

		reqJWKS := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "jwks",
			Storage:   storage,
		}
		resp, err = b.HandleRequest(context.Background(), reqJWKS)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.True(t, resp.IsError())
		require.Contains(t, resp.Error().Error(), "subject_token_self_mint_enabled is false")
	})

	// Covers JWK-03.
	t.Run("Returns JWKS when enabled", func(t *testing.T) {
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
		resp, err := b.HandleRequest(context.Background(), reqConfig)
		require.NoError(t, err)
		require.False(t, resp != nil && resp.IsError())

		reqJWKS := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "jwks",
			Storage:   storage,
		}
		resp, err = b.HandleRequest(context.Background(), reqJWKS)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.False(t, resp.IsError())

		rawKeys, ok := resp.Data["keys"].([]map[string]interface{})
		if !ok {
			// Framework can decode as []interface{} depending on map handling.
			rawInterfaces, ok2 := resp.Data["keys"].([]interface{})
			require.True(t, ok2)
			require.Len(t, rawInterfaces, 1)
			first, ok3 := rawInterfaces[0].(map[string]interface{})
			require.True(t, ok3)
			require.Equal(t, "RSA", first["kty"])
			require.Equal(t, "sig", first["use"])
			require.Equal(t, "RS256", first["alg"])
			require.NotEmpty(t, first["kid"])
			require.NotEmpty(t, first["n"])
			require.NotEmpty(t, first["e"])
			require.NotEmpty(t, first["x5c"])
			return
		}

		require.Len(t, rawKeys, 1)
		first := rawKeys[0]
		require.Equal(t, "RSA", first["kty"])
		require.Equal(t, "sig", first["use"])
		require.Equal(t, "RS256", first["alg"])
		require.NotEmpty(t, first["kid"])
		require.NotEmpty(t, first["n"])
		require.NotEmpty(t, first["e"])
		require.NotEmpty(t, first["x5c"])
	})
}
