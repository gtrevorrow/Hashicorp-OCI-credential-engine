package ocibackend

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestExchangeTTLPolicy(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		request                    interface{}
		backendDefault, backendMax int
		roleDefault, roleMax       time.Duration
		vaultMax                   time.Duration
		named, mapped              bool
		want, wantMax              time.Duration
	}{
		{name: "backend default", backendDefault: 120, backendMax: 600, want: 120 * time.Second, wantMax: 600 * time.Second},
		{name: "role default", backendDefault: 120, backendMax: 600, named: true, roleDefault: 180 * time.Second, roleMax: 300 * time.Second, want: 180 * time.Second, wantMax: 300 * time.Second},
		{name: "request overrides default", request: "30s", backendDefault: 120, backendMax: 600, named: true, roleDefault: 180 * time.Second, roleMax: 300 * time.Second, want: 30 * time.Second, wantMax: 300 * time.Second},
		{name: "zero request uses default", request: 0, backendDefault: 120, backendMax: 600, want: 120 * time.Second, wantMax: 600 * time.Second},
		{name: "backend caps role default", backendDefault: 30, backendMax: 60, named: true, roleDefault: time.Hour, roleMax: time.Hour, want: time.Minute, wantMax: time.Minute},
		{name: "backend caps request", request: 3600, backendDefault: 30, backendMax: 60, named: true, roleDefault: time.Hour, roleMax: time.Hour, want: time.Minute, wantMax: time.Minute},
		{name: "role caps request", request: 3600, backendDefault: 120, backendMax: 600, named: true, roleDefault: time.Minute, roleMax: 2 * time.Minute, want: 2 * time.Minute, wantMax: 2 * time.Minute},
		{name: "Vault caps request", request: 3600, backendDefault: 120, backendMax: 600, named: true, roleDefault: time.Minute, roleMax: 2 * time.Minute, vaultMax: 30 * time.Second, want: 30 * time.Second, wantMax: 30 * time.Second},
		{name: "Vault caps bare default", backendDefault: 120, backendMax: 600, vaultMax: 45 * time.Second, want: 45 * time.Second, wantMax: 45 * time.Second},
		{name: "fractional Vault ceiling rounds down", backendDefault: 120, backendMax: 600, vaultMax: 1500 * time.Millisecond, want: time.Second, wantMax: time.Second},
		{name: "zero role inherits backend", backendDefault: 120, backendMax: 600, named: true, want: 120 * time.Second, wantMax: 600 * time.Second},
		{name: "mapped role respects backend", backendDefault: 30, backendMax: 60, mapped: true, roleDefault: time.Hour, roleMax: time.Hour, want: time.Minute, wantMax: time.Minute},
	} {
		for _, tokenType := range []string{ociRequestedTokenTypeUPST, ociRequestedTokenTypeRPST} {
			t.Run(tc.name+"/"+tokenType, func(t *testing.T) {
				b, storage := getTestBackend(t)
				b.System().(*logical.StaticSystemView).MaxLeaseTTLVal = tc.vaultMax
				cfg := &federatedConfig{DomainUrl: "https://oci.example", ClientID: "test", ClientSecret: "test", DefaultTTL: tc.backendDefault, MaxTTL: tc.backendMax}
				if tc.mapped {
					var err error
					cfg.SubjectTokenRoleMappings, err = decodeSubjectTokenRoleMappings(`[{"claim":"group","op":"eq","value":"dev","role":"dev"}]`)
					require.NoError(t, err)
				}
				require.NoError(t, b.saveConfig(context.Background(), storage, cfg))
				path := "exchange"
				if tc.named || tc.mapped {
					require.NoError(t, b.saveRole(context.Background(), storage, &roleEntry{Name: "dev", DefaultTTL: tc.roleDefault, MaxTTL: tc.roleMax}))
					if tc.named {
						path += "/dev"
					}
				}
				calls := 0
				b.setTokenExchanger(func(_ context.Context, _ string, actualType string, _ string, _ string, ttl time.Duration, _ *federatedConfig) (*tokenExchangeResult, error) {
					calls++
					require.Equal(t, tokenType, actualType)
					require.Equal(t, tc.want, ttl)
					return &tokenExchangeResult{AccessToken: "synthetic", RequestedTokenType: tokenType}, nil
				})
				payload := map[string]interface{}{"subject_token": makeTestJWT(t, map[string]interface{}{"group": "dev"}), "requested_token_type": tokenType, "res_type": "resource_principal"}
				if tc.request != nil {
					payload["ttl"] = tc.request
				}
				resp, err := b.HandleRequest(context.Background(), &logical.Request{Operation: logical.UpdateOperation, Path: path, Storage: storage, Data: payload})
				require.NoError(t, err)
				require.NotNil(t, resp)
				require.False(t, resp.IsError(), "%v", resp)
				require.Equal(t, 1, calls)
				require.Equal(t, tc.want, resp.Secret.TTL)
				require.Equal(t, tc.wantMax, resp.Secret.MaxTTL)
			})
		}
	}
}

func TestTTLWritesRejectInvalidPolicyWithoutChangingStorage(t *testing.T) {
	for _, path := range []string{"config", "role/dev"} {
		for _, invalid := range []map[string]interface{}{
			{"default_ttl": "-0.5s"}, {"max_ttl": 0.5}, {"default_ttl": "1500ms"}, {"default_ttl": 0}, {"max_ttl": 0}, {"default_ttl": -1}, {"max_ttl": -1},
			{"default_ttl": "9223372037"}, {"max_ttl": "9223372037"},
			{"default_ttl": 601, "max_ttl": 600}, {"max_ttl": 30},
		} {
			t.Run(path+fmt.Sprint(invalid), func(t *testing.T) {
				b, storage := getTestBackend(t)
				initial := map[string]interface{}{"default_ttl": 60, "max_ttl": 600}
				if path == "config" {
					initial["domain_url"] = "https://oci.example"
					initial["client_id"] = "test"
					initial["client_secret"] = "test"
				}
				resp, err := b.HandleRequest(context.Background(), &logical.Request{Operation: logical.UpdateOperation, Path: path, Storage: storage, Data: initial})
				require.NoError(t, err)
				require.False(t, resp != nil && resp.IsError(), "%v", resp)
				storageKey := path
				before, err := storage.Get(context.Background(), storageKey)
				require.NoError(t, err)
				require.NotNil(t, before)
				resp, err = b.HandleRequest(context.Background(), &logical.Request{Operation: logical.UpdateOperation, Path: path, Storage: storage, Data: invalid})
				require.True(t, err != nil || (resp != nil && resp.IsError()), "invalid policy accepted: %v", invalid)
				after, err := storage.Get(context.Background(), storageKey)
				require.NoError(t, err)
				require.Equal(t, before.Value, after.Value)
			})
		}
	}
}

func TestExchangeRejectsInvalidTTLBeforeOCI(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		request                    interface{}
		backendDefault, backendMax int
		role                       *roleEntry
		vaultMax                   time.Duration
	}{
		{name: "negative fractional request", request: "-0.5s", backendDefault: 60, backendMax: 600},
		{name: "fractional numeric request", request: 0.5, backendDefault: 60, backendMax: 600},
		{name: "negative request", request: -1, backendDefault: 60, backendMax: 600},
		{name: "overflow request", request: "9223372037", backendDefault: 60, backendMax: 600},
		{name: "zero backend maximum", backendDefault: 60},
		{name: "negative stored backend", backendDefault: 60, backendMax: -1},
		{name: "inverted stored backend", backendDefault: 600, backendMax: 60},
		{name: "negative stored role", backendDefault: 60, backendMax: 600, role: &roleEntry{Name: "dev", MaxTTL: -time.Second}},
		{name: "inverted stored role", backendDefault: 60, backendMax: 600, role: &roleEntry{Name: "dev", DefaultTTL: time.Hour, MaxTTL: time.Minute}},
		{name: "subsecond Vault ceiling", backendDefault: 60, backendMax: 600, vaultMax: time.Millisecond},
		{name: "negative Vault ceiling", backendDefault: 60, backendMax: 600, vaultMax: -time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, storage := getTestBackend(t)
			b.System().(*logical.StaticSystemView).MaxLeaseTTLVal = tc.vaultMax
			require.NoError(t, b.saveConfig(context.Background(), storage, &federatedConfig{DefaultTTL: tc.backendDefault, MaxTTL: tc.backendMax}))
			path := "exchange"
			if tc.role != nil {
				require.NoError(t, b.saveRole(context.Background(), storage, tc.role))
				path += "/dev"
			}
			b.setTokenExchanger(func(context.Context, string, string, string, string, time.Duration, *federatedConfig) (*tokenExchangeResult, error) {
				t.Fatal("invalid TTL must not contact OCI")
				return nil, nil
			})
			payload := map[string]interface{}{"subject_token": "synthetic"}
			if tc.request != nil {
				payload["ttl"] = tc.request
			}
			resp, err := b.HandleRequest(context.Background(), &logical.Request{Operation: logical.UpdateOperation, Path: path, Storage: storage, Data: payload})
			require.True(t, err != nil || (resp != nil && resp.IsError()))
		})
	}
}

func TestTokenTTLConversionBounds(t *testing.T) {
	// Stored seconds use int; avoid overflowing the test itself on 32-bit builds.
	boundary := int64(maxTokenTTLSeconds)
	if int64(int(boundary)) != boundary {
		t.Skip("duration boundary exceeds platform int")
	}
	got, err := tokenTTLDuration(int(boundary), "ttl")
	require.NoError(t, err)
	require.Equal(t, time.Duration(maxTokenTTLSeconds)*time.Second, got)
	_, err = tokenTTLDuration(int(boundary+1), "ttl")
	require.Error(t, err)
}
