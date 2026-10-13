package ocibackend

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestRoleWritesRejectRemovedAndUnknownFields(t *testing.T) {
	for _, op := range []logical.Operation{logical.CreateOperation, logical.UpdateOperation} {
		for _, field := range []string{"allowed_subjects", "allowed_groups", "unexpected"} {
			for _, value := range []interface{}{nil, []string{}, []string{"admin"}} {
				t.Run(fmt.Sprint(op, field, value), func(t *testing.T) {
					b, s := getTestBackend(t)
					resp, err := b.HandleRequest(context.Background(), &logical.Request{Operation: op, Path: "role/dev", Storage: s, Data: map[string]interface{}{field: value}})
					require.NoError(t, err)
					require.True(t, resp.IsError())
					require.Contains(t, resp.Error().Error(), "unknown field")
					require.Contains(t, resp.Error().Error(), field)
					entry, err := s.Get(context.Background(), "role/dev")
					require.NoError(t, err)
					require.Nil(t, entry)
				})
			}
		}
	}
}

func storeRoleWithRemovedField(t *testing.T, s logical.Storage, field string, value interface{}) {
	t.Helper()
	entry, err := logical.StorageEntryJSON("role/dev", map[string]interface{}{"name": "dev", "description": "preserve me", "default_ttl": time.Minute, "max_ttl": time.Hour, "self_mint_custom_claims": map[string]string{"team": "dev"}, field: value})
	require.NoError(t, err)
	require.NoError(t, s.Put(context.Background(), entry))
}

func TestRoleWithRemovedFiltersRequiresExplicitCleanup(t *testing.T) {
	for _, field := range []string{"allowed_subjects", "allowed_groups"} {
		for _, value := range []interface{}{[]string{"admin"}, "malformed", map[string]string{"bad": "shape"}} {
			t.Run(fmt.Sprint(field, value), func(t *testing.T) {
				b, s := getTestBackend(t)
				ctx := context.Background()
				storeRoleWithRemovedField(t, s, field, value)
				before, err := s.Get(ctx, "role/dev")
				require.NoError(t, err)
				resp, err := b.HandleRequest(ctx, &logical.Request{Operation: logical.ReadOperation, Path: "role/dev", Storage: s})
				require.NoError(t, err)
				require.Equal(t, "preserve me", resp.Data["description"])
				require.Len(t, resp.Warnings, 1)
				require.Contains(t, resp.Warnings[0], field)
				require.NotContains(t, resp.Data, "allowed_subjects")
				require.NotContains(t, resp.Data, "allowed_groups")
				_, err = b.getRole(ctx, s, "dev")
				require.ErrorContains(t, err, "delete and recreate")
				resp, err = b.HandleRequest(ctx, &logical.Request{Operation: logical.UpdateOperation, Path: "role/dev", Storage: s, Data: map[string]interface{}{"description": "overwrite"}})
				require.NoError(t, err)
				require.True(t, resp.IsError())
				require.Contains(t, resp.Error().Error(), "delete and recreate")
				after, err := s.Get(ctx, "role/dev")
				require.NoError(t, err)
				require.Equal(t, before.Value, after.Value)
				resp, err = b.HandleRequest(ctx, &logical.Request{Operation: logical.DeleteOperation, Path: "role/dev", Storage: s})
				require.NoError(t, err)
				require.False(t, resp != nil && resp.IsError())
				resp, err = b.HandleRequest(ctx, &logical.Request{Operation: logical.UpdateOperation, Path: "role/dev", Storage: s, Data: map[string]interface{}{"description": "reviewed", "default_ttl": 60, "max_ttl": 3600, "self_mint_custom_claims": `{"team":"dev"}`}})
				require.NoError(t, err)
				require.False(t, resp != nil && resp.IsError())
				role, err := b.getRole(ctx, s, "dev")
				require.NoError(t, err)
				require.Equal(t, "dev", role.SelfMintCustomClaims["team"])
				stored, err := s.Get(ctx, "role/dev")
				require.NoError(t, err)
				var raw map[string]interface{}
				require.NoError(t, json.Unmarshal(stored.Value, &raw))
				require.NotContains(t, raw, "allowed_subjects")
				require.NotContains(t, raw, "allowed_groups")
			})
		}
	}
}

func TestEmptyRemovedRoleFieldsRemainReadable(t *testing.T) {
	for _, value := range []interface{}{nil, []string{}} {
		b, s := getTestBackend(t)
		storeRoleWithRemovedField(t, s, "allowed_groups", value)
		role, err := b.getRole(context.Background(), s, "dev")
		require.NoError(t, err)
		require.NotNil(t, role)
		resp, err := b.HandleRequest(context.Background(), &logical.Request{Operation: logical.ReadOperation, Path: "role/dev", Storage: s})
		require.NoError(t, err)
		require.Empty(t, resp.Warnings)
		require.NotContains(t, resp.Data, "allowed_groups")
	}
}

func TestExchangeRejectsRolesWithRemovedFilters(t *testing.T) {
	for _, mode := range []string{"direct", "mapped", "self-mint", "brokered"} {
		t.Run(mode, func(t *testing.T) {
			b, s := getTestBackend(t)
			ctx := context.Background()
			enabled := true
			cfg := &federatedConfig{DefaultTTL: 60, MaxTTL: 3600, EnablePluginIssuedSubjectToken: &enabled, SubjectTokenSelfMintEnabled: true, SubjectTokenSelfMintIssuer: "https://vault.example", SubjectTokenSelfMintPrivateKey: generateTestRSAPrivateKeyPEM(t)}
			payload := map[string]interface{}{"subject_token": makeTestJWT(t, map[string]interface{}{"group": "dev"})}
			path := "exchange/dev"
			if mode == "mapped" {
				var err error
				cfg.SubjectTokenRoleMappings, err = decodeSubjectTokenRoleMappings(`[{"claim":"group","op":"eq","value":"dev","role":"dev"}]`)
				require.NoError(t, err)
				path = "exchange"
			}
			if mode == "self-mint" {
				delete(payload, "subject_token")
			}
			if mode == "brokered" {
				key := generateTestRSAPrivateKey(t)
				cfg.BrokeredSubjectTokenEnabled = true
				cfg.BrokeredSubjectTokenTrustType = brokeredTrustTypePublicKeys
				cfg.BrokeredSubjectTokenIssuer = "https://issuer.example"
				cfg.BrokeredSubjectTokenAllowedAudiences = []string{"test"}
				cfg.BrokeredSubjectTokenAllowedAlgs = []string{"RS256"}
				cfg.BrokeredSubjectTokenPublicKeys = []string{encodeTestPublicKeyPEM(t, &key.PublicKey)}
				payload["subject_token"] = makeSignedTestJWT(t, key, jose.RS256, map[string]interface{}{"iss": "https://issuer.example", "aud": "test", "sub": "alice", "exp": time.Now().Add(time.Hour).Unix()})
			}
			require.NoError(t, b.saveConfig(ctx, s, cfg))
			storeRoleWithRemovedField(t, s, "allowed_subjects", []string{"alice"})
			b.setTokenExchanger(func(context.Context, string, string, string, string, time.Duration, *federatedConfig) (*tokenExchangeResult, error) {
				t.Fatal("role requiring cleanup must not exchange credentials")
				return nil, nil
			})
			resp, err := b.HandleRequest(ctx, &logical.Request{Operation: logical.UpdateOperation, Path: path, Storage: s, Data: payload})
			if err != nil {
				require.ErrorContains(t, err, "delete and recreate")
			} else {
				require.NotNil(t, resp)
				require.True(t, resp.IsError())
				require.Contains(t, resp.Error().Error(), "delete and recreate")
			}
		})
	}
}
