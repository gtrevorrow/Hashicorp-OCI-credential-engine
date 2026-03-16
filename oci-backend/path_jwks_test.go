package ocibackend

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
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

func TestSelfMintedTokenValidatesAgainstJWKS(t *testing.T) {
	b, storage := getTestBackend(t)
	testKey := generateTestRSAPrivateKeyPEM(t)

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
			"subject_token_self_mint_audience":           "urn:mace:oci:idcs",
			"subject_token_self_mint_private_key":        testKey,
			"debug_return_resolved_subject_token_claims": false,
		},
	}
	resp, err := b.HandleRequest(context.Background(), reqConfig)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError())

	config, err := b.getConfig(context.Background(), storage)
	require.NoError(t, err)
	require.NotNil(t, config)

	token, err := b.selfMintSubjectToken(&logical.Request{
		DisplayName: "token",
	}, config, "urn:mace:oci:idcs")
	require.NoError(t, err)

	reqJWKS := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "jwks",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(context.Background(), reqJWKS)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError())

	keys := mustExtractJWKSKeys(t, resp.Data["keys"])
	require.Len(t, keys, 1)
	jwk := keys[0]

	x5cValues := mustExtractStringSlice(t, jwk["x5c"])
	require.Len(t, x5cValues, 1)

	certDER, err := base64.StdEncoding.DecodeString(x5cValues[0])
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	certPublicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	require.True(t, ok)
	require.Equal(t, jwk["n"], base64.RawURLEncoding.EncodeToString(certPublicKey.N.Bytes()))
	require.Equal(t, jwk["e"], base64.RawURLEncoding.EncodeToString(big.NewInt(int64(certPublicKey.E)).Bytes()))

	verifyJWTSignatureWithRSAKey(t, token, certPublicKey)
}

func mustExtractStringSlice(t *testing.T, raw interface{}) []string {
	t.Helper()

	if values, ok := raw.([]string); ok {
		return values
	}

	rawInterfaces, ok := raw.([]interface{})
	require.True(t, ok)
	out := make([]string, 0, len(rawInterfaces))
	for _, item := range rawInterfaces {
		value, ok := item.(string)
		require.True(t, ok)
		out = append(out, value)
	}
	return out
}

func mustExtractJWKSKeys(t *testing.T, raw interface{}) []map[string]interface{} {
	t.Helper()

	if keys, ok := raw.([]map[string]interface{}); ok {
		return keys
	}

	rawInterfaces, ok := raw.([]interface{})
	require.True(t, ok)
	out := make([]map[string]interface{}, 0, len(rawInterfaces))
	for _, item := range rawInterfaces {
		entry, ok := item.(map[string]interface{})
		require.True(t, ok)
		out = append(out, entry)
	}
	return out
}

func verifyJWTSignatureWithRSAKey(t *testing.T, token string, publicKey *rsa.PublicKey) {
	t.Helper()

	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)

	signingInput := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	var header map[string]interface{}
	require.NoError(t, json.Unmarshal(headerBytes, &header))
	require.Equal(t, "RS256", header["alg"])

	sum := sha256.Sum256([]byte(signingInput))
	require.NoError(t, rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, sum[:], signature))
}
