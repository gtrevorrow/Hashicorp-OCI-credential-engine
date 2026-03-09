package ocibackend

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtractStringJWTClaim(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		token := makeTestJWT(t, map[string]interface{}{"vault_role": "dev"})
		value, err := extractStringJWTClaim(token, "vault_role")
		require.NoError(t, err)
		require.Equal(t, "dev", value)
	})

	t.Run("Missing Claim", func(t *testing.T) {
		token := makeTestJWT(t, map[string]interface{}{"other": "dev"})
		_, err := extractStringJWTClaim(token, "vault_role")
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing claim")
	})

	t.Run("Invalid Format", func(t *testing.T) {
		_, err := extractStringJWTClaim("not-a-jwt", "vault_role")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid JWT format")
	})
}

func makeTestJWT(t *testing.T, claims map[string]interface{}) string {
	t.Helper()

	headerJSON, err := json.Marshal(map[string]string{"alg": "none", "typ": "JWT"})
	require.NoError(t, err)
	payloadJSON, err := json.Marshal(claims)
	require.NoError(t, err)

	header := base64.RawURLEncoding.EncodeToString(headerJSON)
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	return fmt.Sprintf("%s.%s.signature", header, payload)
}
