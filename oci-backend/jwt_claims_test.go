package ocibackend

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJWTClaimContainsRole(t *testing.T) {
	t.Run("String Claim Success", func(t *testing.T) {
		token := makeTestJWT(t, map[string]interface{}{"vault_role": "dev"})
		matched, value, err := jwtClaimContainsRole(token, "vault_role", "dev")
		require.NoError(t, err)
		require.True(t, matched)
		require.Equal(t, "dev", value)
	})

	t.Run("String Array Claim Success", func(t *testing.T) {
		token := makeTestJWT(t, map[string]interface{}{"vault_role": []string{"prod", "dev"}})
		matched, value, err := jwtClaimContainsRole(token, "vault_role", "dev")
		require.NoError(t, err)
		require.True(t, matched)
		require.Equal(t, "prod,dev", value)
	})

	t.Run("String Array Claim Mismatch", func(t *testing.T) {
		token := makeTestJWT(t, map[string]interface{}{"vault_role": []string{"prod", "stage"}})
		matched, value, err := jwtClaimContainsRole(token, "vault_role", "dev")
		require.NoError(t, err)
		require.False(t, matched)
		require.Equal(t, "prod,stage", value)
	})

	t.Run("Invalid Array Element", func(t *testing.T) {
		token := makeTestJWT(t, map[string]interface{}{"vault_role": []interface{}{"dev", 2}})
		_, _, err := jwtClaimContainsRole(token, "vault_role", "dev")
		require.Error(t, err)
		require.Contains(t, err.Error(), "array must contain only non-empty strings")
	})

	t.Run("Missing Claim", func(t *testing.T) {
		token := makeTestJWT(t, map[string]interface{}{"other": "dev"})
		_, _, err := jwtClaimContainsRole(token, "vault_role", "dev")
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing claim")
	})

	t.Run("Invalid Format", func(t *testing.T) {
		_, _, err := jwtClaimContainsRole("not-a-jwt", "vault_role", "dev")
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
