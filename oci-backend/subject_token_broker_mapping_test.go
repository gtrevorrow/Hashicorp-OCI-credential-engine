package ocibackend

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRenderBrokeredClaimMappings(t *testing.T) {
	claims := map[string]interface{}{
		"sub": "user-123",
		"org": "acme",
		"user": map[string]interface{}{
			"id": "42",
		},
	}

	t.Run("Simple One To One Template", func(t *testing.T) {
		mapped, err := renderBrokeredClaimMappings(claims, map[string]string{
			"external_sub": "{{ claims.sub }}",
		})
		require.NoError(t, err)
		require.Equal(t, map[string]interface{}{"external_sub": "user-123"}, mapped)
	})

	t.Run("Concat From Multiple Claims", func(t *testing.T) {
		mapped, err := renderBrokeredClaimMappings(claims, map[string]string{
			"principal": "{{ claims.org }}:{{ claims.sub }}",
		})
		require.NoError(t, err)
		require.Equal(t, map[string]interface{}{"principal": "acme:user-123"}, mapped)
	})

	t.Run("Nested Claim Reference", func(t *testing.T) {
		mapped, err := renderBrokeredClaimMappings(claims, map[string]string{
			"employee_id": "{{ claims.user.id }}",
		})
		require.NoError(t, err)
		require.Equal(t, map[string]interface{}{"employee_id": "42"}, mapped)
	})

	t.Run("Missing Claim Failure", func(t *testing.T) {
		_, err := renderBrokeredClaimMappings(claims, map[string]string{
			"missing": "{{ claims.user.email }}",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "not found")
	})

	t.Run("Reserved Output Claim Failure", func(t *testing.T) {
		_, err := renderBrokeredClaimMappings(claims, map[string]string{
			"sub": "{{ claims.sub }}",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "reserved")
	})

	t.Run("Vault Namespace Output Claim Failure", func(t *testing.T) {
		_, err := renderBrokeredClaimMappings(claims, map[string]string{
			"vault_external": "{{ claims.sub }}",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "vault_")
	})
}
