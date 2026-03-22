package ocibackend

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecodeSubjectTokenRoleMappings(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		mappings, err := decodeSubjectTokenRoleMappings("")
		require.NoError(t, err)
		require.Nil(t, mappings)
	})

	t.Run("Valid", func(t *testing.T) {
		mappings, err := decodeSubjectTokenRoleMappings(`[{"claim":"groups","op":"co","value":"dev","role":"developer"}]`)
		require.NoError(t, err)
		require.Equal(t, []subjectTokenRoleMapping{
			{Claim: "groups", Op: "co", Value: "dev", Role: "developer"},
		}, mappings)
	})

	t.Run("Rejects Unsupported Operator", func(t *testing.T) {
		_, err := decodeSubjectTokenRoleMappings(`[{"claim":"groups","op":"ne","value":"dev","role":"developer"}]`)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported op")
	})
}

func TestResolveRoleFromSubjectToken(t *testing.T) {
	t.Run("First Match Wins", func(t *testing.T) {
		token := makeTestJWT(t, map[string]interface{}{"groups": []string{"dev-team", "prod-team"}})
		role, err := resolveRoleFromSubjectToken(token, []subjectTokenRoleMapping{
			{Claim: "groups", Op: "co", Value: "dev", Role: "developer"},
			{Claim: "groups", Op: "co", Value: "team", Role: "team-member"},
		})
		require.NoError(t, err)
		require.Equal(t, "developer", role)
	})

	t.Run("Exact Match", func(t *testing.T) {
		token := makeTestJWT(t, map[string]interface{}{"vault_role": "dev"})
		role, err := resolveRoleFromSubjectToken(token, []subjectTokenRoleMapping{
			{Claim: "vault_role", Op: "eq", Value: "dev", Role: "developer"},
		})
		require.NoError(t, err)
		require.Equal(t, "developer", role)
	})

	t.Run("Starts With Match", func(t *testing.T) {
		token := makeTestJWT(t, map[string]interface{}{"sub": "svc:deploy"})
		role, err := resolveRoleFromSubjectToken(token, []subjectTokenRoleMapping{
			{Claim: "sub", Op: "sw", Value: "svc:", Role: "service"},
		})
		require.NoError(t, err)
		require.Equal(t, "service", role)
	})

	t.Run("No Match", func(t *testing.T) {
		token := makeTestJWT(t, map[string]interface{}{"vault_role": "prod"})
		_, err := resolveRoleFromSubjectToken(token, []subjectTokenRoleMapping{
			{Claim: "vault_role", Op: "eq", Value: "dev", Role: "developer"},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "no subject_token_role_mappings matched")
	})

	t.Run("Array Match Returns On First Valid Match", func(t *testing.T) {
		token := makeTestJWT(t, map[string]interface{}{"groups": []interface{}{"dev-team", 7}})
		role, err := resolveRoleFromSubjectToken(token, []subjectTokenRoleMapping{
			{Claim: "groups", Op: "co", Value: "dev", Role: "developer"},
		})
		require.NoError(t, err)
		require.Equal(t, "developer", role)
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
