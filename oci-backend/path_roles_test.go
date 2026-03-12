package ocibackend

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPathRoles_CreateUpdate(t *testing.T) {
	b, storage := getTestBackend(t)

	// Covers ROL-01 and ROL-02.
	t.Run("Create Role Success", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "roles/test-role",
			Storage:   storage,
			Data: map[string]interface{}{
				"description":      "A test role",
				"default_ttl":      3600,
				"max_ttl":          86400,
				"allowed_subjects": []string{"systemA", "systemB"},
				"allowed_groups":   []string{"dev-team"},
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		assert.False(t, resp != nil && resp.IsError(), "expected no error, got: %v", resp)

		// Verify role was written
		role, err := b.getRole(context.Background(), storage, "test-role")
		require.NoError(t, err)
		require.NotNil(t, role)
		assert.Equal(t, "A test role", role.Description)
		assert.Contains(t, role.AllowedSubjects, "systemA")
	})

	// Covers ROL-08.
	t.Run("Create Role Missing Name", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "roles/", // No name appended
			Storage:   storage,
			Data: map[string]interface{}{
				"description": "missing name",
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.True(t, resp.IsError())
		require.Contains(t, resp.Error().Error(), "missing role name")
	})
}

func TestPathRoles_ReadListDelete(t *testing.T) {
	b, storage := getTestBackend(t)

	// Pre-populate role
	reqCreate := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/test-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"description": "Pre-created role",
			"default_ttl": 1800,
		},
	}
	_, err := b.HandleRequest(context.Background(), reqCreate)
	require.NoError(t, err)

	// Covers ROL-03.
	t.Run("Read Role", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "roles/test-role",
			Storage:   storage,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, resp)

		assert.Equal(t, "test-role", resp.Data["name"])
		assert.Equal(t, "Pre-created role", resp.Data["description"])
		assert.Equal(t, 1800, resp.Data["default_ttl"])
		assert.Equal(t, 86400, resp.Data["max_ttl"]) // Because of the default logic
	})

	// Covers ROL-04.
	t.Run("List Roles", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.ListOperation,
			Path:      "roles",
			Storage:   storage,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, resp)

		keys, ok := resp.Data["keys"].([]string)
		require.True(t, ok)
		assert.Contains(t, keys, "test-role")
	})

	// Covers ROL-06.
	t.Run("Delete Role", func(t *testing.T) {
		reqDelete := &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      "roles/test-role",
			Storage:   storage,
		}

		resp, err := b.HandleRequest(context.Background(), reqDelete)
		require.NoError(t, err)
		assert.False(t, resp != nil && resp.IsError())

		// Verify deletion
		reqRead := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "roles/test-role",
			Storage:   storage,
		}
		respRead, errRead := b.HandleRequest(context.Background(), reqRead)
		require.NoError(t, errRead)
		assert.Nil(t, respRead) // Read should return nil response if role is missing
	})
}

func TestPathRoles_StrictRoleNameMatch(t *testing.T) {
	b, storage := getTestBackend(t)

	reqConfig := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"tenancy_ocid":           "ocid1.tenancy.oc1..test",
			"domain_url":             "https://idcs-test.identity.oraclecloud.com",
			"client_id":              "test-client-id",
			"client_secret":          "test-client-secret",
			"region":                 "us-ashburn-1",
			"strict_role_name_match": true,
		},
	}
	_, err := b.HandleRequest(context.Background(), reqConfig)
	require.NoError(t, err)

	// Covers ROL-10.
	t.Run("Reject Invalid Role Name", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "roles/dev@team",
			Storage:   storage,
			Data: map[string]interface{}{
				"description": "invalid role name",
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.True(t, resp.IsError())
		require.Contains(t, resp.Error().Error(), "invalid role name")
	})

	// Covers the valid branch of strict role-name handling adjacent to ROL-10.
	t.Run("Accept Valid Role Name", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "roles/dev-team_1",
			Storage:   storage,
			Data: map[string]interface{}{
				"description": "valid role name",
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		assert.False(t, resp != nil && resp.IsError())
	})
}
