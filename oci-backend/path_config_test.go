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

	// Covers CFG-01.
	t.Run("Create Config Success", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config",
			Storage:   storage,
			Data: map[string]interface{}{
				"domain_url":    "https://idcs-test.identity.oraclecloud.com",
				"client_id":     "test-client-id",
				"client_secret": "test-client-secret",
				"jwks_url":      "https://example.com/jwks",
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		assert.False(t, resp != nil && resp.IsError(), "expected no error, got: %v", resp)
	})

	// Covers CFG-03.
	t.Run("Create Config Missing Variables", func(t *testing.T) {
		b, storage := getTestBackend(t)

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config",
			Storage:   storage,
			Data: map[string]interface{}{
				"client_id": "test-client-id",
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		assert.NoError(t, err) // Validation errors are returned in resp.Error, not err
		assert.True(t, resp.IsError())
	})

	t.Run("Create Config", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config",
			Storage:   storage,
			Data: map[string]interface{}{
				"domain_url":    "https://idcs-test.identity.oraclecloud.com",
				"client_id":     "test-client-id",
				"client_secret": "test-client-secret",
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		assert.False(t, resp != nil && resp.IsError(), "expected no error, got: %v", resp)
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
			"domain_url":    "https://idcs-test.identity.oraclecloud.com",
			"client_id":     "test-client-id",
			"client_secret": "test-client-secret",
			"jwks_url":      "https://example.com/jwks",
		},
	}
	_, err := b.HandleRequest(context.Background(), reqCreate)
	require.NoError(t, err)

	// Covers CFG-05.
	t.Run("Read Config", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "config",
			Storage:   storage,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, resp)

		assert.Equal(t, "https://idcs-test.identity.oraclecloud.com", resp.Data["domain_url"])
		assert.Equal(t, "test-client-id", resp.Data["client_id"])
		assert.Nil(t, resp.Data["client_secret"])
		assert.Nil(t, resp.Data["subject_token_role_mappings"])
		assert.Equal(t, true, resp.Data["enable_plugin_issued_subject_token"])
		assert.Equal(t, false, resp.Data["strict_role_name_match"])
		assert.Equal(t, false, resp.Data["subject_token_self_mint_enabled"])
		assert.Equal(t, "urn:mace:oci:idcs", resp.Data["subject_token_self_mint_audience"])
		assert.Nil(t, resp.Data["subject_token_allowed_audiences"])
		assert.Equal(t, 600, resp.Data["subject_token_self_mint_ttl_seconds"])
	})

	// Covers CFG-07.
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

func TestPathConfig_SubjectTokenRoleMappings(t *testing.T) {
	b, storage := getTestBackend(t)
	testKey := generateTestRSAPrivateKeyPEM(t)
	// Covers CFG-02 and exercises CFG-09/CFG-10 with non-default settings.

	reqCreate := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"subject_token_role_mappings":         `[{"claim":"vault_role","op":"eq","value":"dev","role":"dev"}]`,
			"domain_url":                          "https://idcs-test.identity.oraclecloud.com",
			"client_id":                           "test-client-id",
			"client_secret":                       "test-client-secret",
			"enable_plugin_issued_subject_token":  false,
			"strict_role_name_match":              true,
			"subject_token_self_mint_enabled":     true,
			"subject_token_self_mint_issuer":      "https://vault.example.com",
			"subject_token_self_mint_audience":    "urn:mace:oci:idcs",
			"subject_token_allowed_audiences":     []string{"urn:oci:test", "urn:oci:prod"},
			"subject_token_self_mint_ttl_seconds": 900,
			"subject_token_self_mint_private_key": testKey,
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

	require.Equal(t, []subjectTokenRoleMapping{
		{Claim: "vault_role", Op: "eq", Value: "dev", Role: "dev"},
	}, resp.Data["subject_token_role_mappings"])
	assert.Equal(t, false, resp.Data["enable_plugin_issued_subject_token"])
	assert.Equal(t, true, resp.Data["strict_role_name_match"])
	assert.Equal(t, true, resp.Data["subject_token_self_mint_enabled"])
	assert.Equal(t, "https://vault.example.com", resp.Data["subject_token_self_mint_issuer"])
	assert.Equal(t, "urn:mace:oci:idcs", resp.Data["subject_token_self_mint_audience"])
	assert.Equal(t, []string{"urn:oci:test", "urn:oci:prod"}, resp.Data["subject_token_allowed_audiences"])
	assert.Equal(t, 900, resp.Data["subject_token_self_mint_ttl_seconds"])
}

func TestPathConfig_SubjectTokenRoleMappingsValidation(t *testing.T) {
	b, storage := getTestBackend(t)

	t.Run("Rejects invalid JSON", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config",
			Storage:   storage,
			Data: map[string]interface{}{
				"domain_url":                  "https://idcs-test.identity.oraclecloud.com",
				"client_id":                   "test-client-id",
				"client_secret":               "test-client-secret",
				"subject_token_role_mappings": `{not-json}`,
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.True(t, resp.IsError())
		require.Contains(t, resp.Error().Error(), "invalid subject_token_role_mappings")
	})

	t.Run("Rejects unsupported operator", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config",
			Storage:   storage,
			Data: map[string]interface{}{
				"domain_url":                  "https://idcs-test.identity.oraclecloud.com",
				"client_id":                   "test-client-id",
				"client_secret":               "test-client-secret",
				"subject_token_role_mappings": `[{"claim":"vault_role","op":"ne","value":"dev","role":"dev"}]`,
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.True(t, resp.IsError())
		require.Contains(t, resp.Error().Error(), "unsupported op")
	})

	t.Run("Rejects invalid mapped role in strict mode", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config",
			Storage:   storage,
			Data: map[string]interface{}{
				"domain_url":                  "https://idcs-test.identity.oraclecloud.com",
				"client_id":                   "test-client-id",
				"client_secret":               "test-client-secret",
				"strict_role_name_match":      true,
				"subject_token_role_mappings": `[{"claim":"groups","op":"co","value":"team","role":"dev@team"}]`,
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.True(t, resp.IsError())
		require.Contains(t, resp.Error().Error(), "invalid mapped role")
	})
}

func TestPathConfig_SelfMintValidation(t *testing.T) {
	b, storage := getTestBackend(t)
	testKey := generateTestRSAPrivateKeyPEM(t)

	// Covers the negative half of CFG-11: self-mint still requires an issuer.
	reqMissingIssuer := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"domain_url":                          "https://idcs-test.identity.oraclecloud.com",
			"client_id":                           "test-client-id",
			"client_secret":                       "test-client-secret",
			"subject_token_self_mint_enabled":     true,
			"subject_token_self_mint_private_key": testKey,
		},
	}
	resp, err := b.HandleRequest(context.Background(), reqMissingIssuer)
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "subject_token_self_mint_issuer is required")

	// Covers CFG-11.
	reqMissingKey := &logical.Request{
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
	resp, err = b.HandleRequest(context.Background(), reqMissingKey)
	require.NoError(t, err)
	assert.False(t, resp != nil && resp.IsError(), "expected no error, got: %v", resp)

	config, err := b.getConfig(context.Background(), storage)
	require.NoError(t, err)
	require.NotNil(t, config)
	require.NotEmpty(t, config.SubjectTokenSelfMintPrivateKey)
	require.Contains(t, config.SubjectTokenSelfMintPrivateKey, "BEGIN RSA PRIVATE KEY")
}

func TestPathConfig_PartialUpdates(t *testing.T) {
	b, storage := getTestBackend(t)

	reqCreate := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"domain_url":    "https://idcs-test.identity.oraclecloud.com",
			"client_id":     "test-client-id",
			"client_secret": "test-client-secret",
		},
	}

	resp, err := b.HandleRequest(context.Background(), reqCreate)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError())

	t.Run("Toggle debug flag without rewriting base config", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config",
			Storage:   storage,
			Data: map[string]interface{}{
				"debug_return_resolved_subject_token_claims": true,
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.False(t, resp != nil && resp.IsError())

		readReq := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "config",
			Storage:   storage,
		}
		readResp, err := b.HandleRequest(context.Background(), readReq)
		require.NoError(t, err)
		require.NotNil(t, readResp)

		assert.Equal(t, "https://idcs-test.identity.oraclecloud.com", readResp.Data["domain_url"])
		assert.Equal(t, "test-client-id", readResp.Data["client_id"])
		assert.Equal(t, true, readResp.Data["debug_return_resolved_subject_token_claims"])
	})

	t.Run("Enable self-mint incrementally with issuer", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config",
			Storage:   storage,
			Data: map[string]interface{}{
				"subject_token_self_mint_enabled": true,
				"subject_token_self_mint_issuer":  "https://vault.example.com",
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.False(t, resp != nil && resp.IsError())

		readReq := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "config",
			Storage:   storage,
		}
		readResp, err := b.HandleRequest(context.Background(), readReq)
		require.NoError(t, err)
		require.NotNil(t, readResp)

		assert.Equal(t, true, readResp.Data["subject_token_self_mint_enabled"])
		assert.Equal(t, "https://vault.example.com", readResp.Data["subject_token_self_mint_issuer"])
	})

	t.Run("Reject enabling self-mint without issuer on partial update", func(t *testing.T) {
		b, storage := getTestBackend(t)
		reqCreate := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config",
			Storage:   storage,
			Data: map[string]interface{}{
				"domain_url":    "https://idcs-test.identity.oraclecloud.com",
				"client_id":     "test-client-id",
				"client_secret": "test-client-secret",
			},
		}

		resp, err := b.HandleRequest(context.Background(), reqCreate)
		require.NoError(t, err)
		require.False(t, resp != nil && resp.IsError())

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config",
			Storage:   storage,
			Data: map[string]interface{}{
				"subject_token_self_mint_enabled": true,
			},
		}

		resp, err = b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.True(t, resp.IsError())
		require.Contains(t, resp.Error().Error(), "subject_token_self_mint_issuer is required")
	})
}

func TestPathConfig_SelfMintGeneratedKeyIsReused(t *testing.T) {
	b, storage := getTestBackend(t)
	// Covers the persistence aspect of CFG-11 across config updates.

	reqGenerate := &logical.Request{
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
	resp, err := b.HandleRequest(context.Background(), reqGenerate)
	require.NoError(t, err)
	assert.False(t, resp != nil && resp.IsError(), "expected no error, got: %v", resp)

	firstConfig, err := b.getConfig(context.Background(), storage)
	require.NoError(t, err)
	require.NotNil(t, firstConfig)
	firstKey := firstConfig.SubjectTokenSelfMintPrivateKey
	require.NotEmpty(t, firstKey)

	reqUpdateWithoutKey := &logical.Request{
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
	resp, err = b.HandleRequest(context.Background(), reqUpdateWithoutKey)
	require.NoError(t, err)
	assert.False(t, resp != nil && resp.IsError(), "expected no error, got: %v", resp)

	updatedConfig, err := b.getConfig(context.Background(), storage)
	require.NoError(t, err)
	require.NotNil(t, updatedConfig)
	assert.Equal(t, firstKey, updatedConfig.SubjectTokenSelfMintPrivateKey)
}
