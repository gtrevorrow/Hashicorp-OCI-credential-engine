package ocibackend

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestSignedAliasClaimsRequireExplicitUniqueMount(t *testing.T) {
	key := generateTestRSAPrivateKeyPEM(t)
	trusted := &logical.Alias{Name: "approved", MountAccessor: "auth_approved", MountType: "userpass", Metadata: map[string]string{"principal": "approved-principal"}}
	other := &logical.Alias{Name: "other", MountAccessor: "oci_mount", MountType: "oci", Metadata: map[string]string{"principal": "other-principal"}}
	for _, flow := range []string{"self-mint", "brokered"} {
		for _, tc := range []struct {
			name, accessor, entityID string
			aliases                  []*logical.Alias
			wantErr                  bool
			wantAlias                bool
		}{
			{"disabled", "", "entity", []*logical.Alias{other, trusted}, false, false},
			{"selected second", "auth_approved", "entity", []*logical.Alias{other, nil, trusted}, false, true},
			{"selected first", "auth_approved", "entity", []*logical.Alias{trusted, other}, false, true},
			{"missing", "auth_missing", "entity", []*logical.Alias{other, trusted}, true, false},
			{"duplicate", "auth_approved", "entity", []*logical.Alias{trusted, trusted}, true, false},
			{"no aliases", "auth_approved", "entity", nil, true, false},
			{"no entity", "auth_approved", "", nil, true, false},
		} {
			t.Run(flow+"/"+tc.name, func(t *testing.T) {
				raw, err := Factory("test")(context.Background(), &logical.BackendConfig{System: &mockSystemView{StaticSystemView: logical.StaticSystemView{EntityVal: &logical.Entity{ID: "entity", Aliases: tc.aliases}}}})
				require.NoError(t, err)
				b := raw.(*backend)
				cfg := &federatedConfig{SubjectTokenSelfMintPrivateKey: key, SubjectTokenSelfMintIssuer: "https://vault.example", SubjectTokenIdentityAliasMountAccessor: tc.accessor}
				req := &logical.Request{EntityID: tc.entityID, MountAccessor: "oci_mount", MountType: "oci", Data: map[string]interface{}{"subject_token_identity_alias_mount_accessor": "oci_mount"}}
				var token string
				if flow == "self-mint" {
					token, err = b.selfMintSubjectToken(req, cfg, "aud")
				} else {
					token, err = b.selfMintBrokeredSubjectToken(context.Background(), req, cfg, nil, nil)
				}
				if tc.wantErr {
					require.Error(t, err)
					require.Empty(t, token)
					return
				}
				require.NoError(t, err)
				claims := decodeJWTClaims(t, token)
				require.Equal(t, "oci_mount", claims["vault_mount_accessor"])
				if tc.wantAlias {
					require.Equal(t, "approved", claims["vault_alias_name"])
					require.Equal(t, "auth_approved", claims["vault_alias_mount_accessor"])
					require.Equal(t, "approved-principal", claims["vault_alias_metadata"].(map[string]interface{})["principal"])
				} else {
					for _, field := range []string{"vault_alias_name", "vault_alias_mount_accessor", "vault_alias_mount_type", "vault_alias_metadata", "vault_alias_custom_metadata"} {
						require.NotContains(t, claims, field)
					}
				}
			})
		}
	}
}

func TestAliasConfigurationPersistsPreservesAndClears(t *testing.T) {
	b, s := getTestBackend(t)
	for _, data := range []map[string]interface{}{
		{"domain_url": "https://example.com", "client_id": "test", "client_secret": "test", "subject_token_identity_alias_mount_accessor": "auth_approved"},
		{"client_id": "updated"},
		{"subject_token_identity_alias_mount_accessor": ""},
	} {
		resp, err := b.HandleRequest(context.Background(), &logical.Request{Operation: logical.UpdateOperation, Path: "config", Storage: s, Data: data})
		require.NoError(t, err)
		require.False(t, resp != nil && resp.IsError(), "%v", resp)
		resp, err = b.HandleRequest(context.Background(), &logical.Request{Operation: logical.ReadOperation, Path: "config", Storage: s})
		require.NoError(t, err)
		expected := "auth_approved"
		if value, ok := data["subject_token_identity_alias_mount_accessor"]; ok {
			expected = value.(string)
		}
		require.Equal(t, expected, resp.Data["subject_token_identity_alias_mount_accessor"])
	}
}

func TestAliasTemplatesFailWithoutSelectedAlias(t *testing.T) {
	_, err := renderSelfMintCustomClaimMappings(buildSelfMintTemplateContext(&logical.Request{}, map[string]interface{}{}), map[string]string{"principal": "aws/{{ vault.alias.metadata.arn }}"}, nil)
	require.Error(t, err)
	alias, err := selectEntityAlias(nil, "auth_approved")
	require.Error(t, err)
	require.Nil(t, alias)
}
