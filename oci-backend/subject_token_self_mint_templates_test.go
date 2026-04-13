package ocibackend

import (
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestRenderSelfMintCustomClaimMappings(t *testing.T) {
	req := &logical.Request{
		DisplayName:         "token",
		MountAccessor:       "auth_aws_123",
		MountType:           "aws",
		ClientTokenAccessor: "accessor-123",
	}
	claims := map[string]interface{}{
		"vault_entity_id":       "entity-123",
		"vault_entity_name":     "deployer",
		"vault_namespace_id":    "root",
		"vault_entity_metadata": map[string]string{"team": "platform"},
		"vault_alias_name":      "aws-role",
		"vault_alias_metadata":  map[string]string{"arn": "arn:aws:iam::123456789012:role/app"},
		"vault_group_names":     []string{"deployers", "platform"},
	}
	templateContext := buildSelfMintTemplateContext(req, claims)

	t.Run("Simple Scalar Lookup", func(t *testing.T) {
		rendered, err := renderSelfMintCustomClaimMappings(templateContext, map[string]string{
			"entity_ref": "{{ vault.entity.id }}",
		}, nil)
		require.NoError(t, err)
		require.Equal(t, map[string]interface{}{"entity_ref": "entity-123"}, rendered)
	})

	t.Run("Nested Metadata Lookup", func(t *testing.T) {
		rendered, err := renderSelfMintCustomClaimMappings(templateContext, map[string]string{
			"aws_arn": "{{ vault.alias.metadata.arn }}",
		}, nil)
		require.NoError(t, err)
		require.Equal(t, map[string]interface{}{"aws_arn": "arn:aws:iam::123456789012:role/app"}, rendered)
	})

	t.Run("Literal And Interpolation", func(t *testing.T) {
		rendered, err := renderSelfMintCustomClaimMappings(templateContext, map[string]string{
			"principal": "aws/{{ vault.alias.metadata.arn }}",
		}, nil)
		require.NoError(t, err)
		require.Equal(t, map[string]interface{}{"principal": "aws/arn:aws:iam::123456789012:role/app"}, rendered)
	})

	t.Run("Join Groups", func(t *testing.T) {
		rendered, err := renderSelfMintCustomClaimMappings(templateContext, map[string]string{
			"groups_csv": `{{ join(vault.groups, ",") }}`,
		}, nil)
		require.NoError(t, err)
		require.Equal(t, map[string]interface{}{"groups_csv": "deployers,platform"}, rendered)
	})

	t.Run("Missing Value Failure", func(t *testing.T) {
		_, err := renderSelfMintCustomClaimMappings(templateContext, map[string]string{
			"missing": "{{ vault.entity.metadata.owner }}",
		}, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not found")
	})

	t.Run("Non Scalar Interpolation Failure", func(t *testing.T) {
		_, err := renderSelfMintCustomClaimMappings(templateContext, map[string]string{
			"groups": "{{ vault.groups }}",
		}, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "cannot be interpolated as a string")
	})

	t.Run("Join Type Mismatch Failure", func(t *testing.T) {
		_, err := renderSelfMintCustomClaimMappings(templateContext, map[string]string{
			"bad_join": `{{ join(vault.entity.id, ",") }}`,
		}, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "requires a list value")
	})

	t.Run("Brokered Claims Namespace", func(t *testing.T) {
		rendered, err := renderSelfMintCustomClaimMappings(templateContext, map[string]string{
			"brokered_sub": "{{ brokered.claims.sub }}",
		}, map[string]interface{}{"sub": "user-123"})
		require.NoError(t, err)
		require.Equal(t, map[string]interface{}{"brokered_sub": "user-123"}, rendered)
	})
}
