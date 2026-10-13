package ocibackend

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestCredentialExpiryBoundsLease(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name                            string
		deadline                        time.Time
		wantTTL, wantMax, wantRemaining time.Duration
		invalid                         bool
	}{
		{name: "shorter upstream lifetime", deadline: now.Add(10 * time.Second), wantTTL: 10 * time.Second, wantMax: 10 * time.Second, wantRemaining: 10 * time.Second},
		{name: "longer upstream lifetime", deadline: now.Add(time.Hour), wantTTL: time.Minute, wantMax: 2 * time.Minute, wantRemaining: time.Hour},
		{name: "processing consumes lifetime", deadline: now.Add(9500 * time.Millisecond), wantTTL: 9 * time.Second, wantMax: 9 * time.Second, wantRemaining: 9 * time.Second},
		{name: "unknown expiry retains policy", wantTTL: time.Minute, wantMax: 2 * time.Minute},
		{name: "expired", deadline: now.Add(-time.Second), invalid: true},
		{name: "expires now", deadline: now, invalid: true},
		{name: "less than one second", deadline: now.Add(time.Millisecond), invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ttl, max, remaining, err := reconcileCredentialExpiry(time.Minute, 2*time.Minute, tc.deadline, now)
			if tc.invalid {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.wantTTL, ttl)
			require.Equal(t, tc.wantMax, max)
			require.Equal(t, tc.wantRemaining, remaining)
		})
	}
}

func TestExchangeReportsCredentialExpirySeparatelyFromLease(t *testing.T) {
	for _, tokenType := range []string{ociRequestedTokenTypeUPST, ociRequestedTokenTypeRPST} {
		for _, state := range []string{"short", "long", "unknown", "expired"} {
			t.Run(tokenType+"/"+state, func(t *testing.T) {
				b, storage := getTestBackend(t)
				require.NoError(t, b.saveConfig(context.Background(), storage, &federatedConfig{DefaultTTL: 60, MaxTTL: 120}))
				var deadline time.Time
				switch state {
				case "short":
					deadline = time.Now().Add(10 * time.Second)
				case "long":
					deadline = time.Now().Add(time.Hour)
				case "expired":
					deadline = time.Now().Add(-time.Second)
				}
				b.setTokenExchanger(func(_ context.Context, _ string, _ string, _ string, _ string, ttl time.Duration, _ *federatedConfig) (*tokenExchangeResult, error) {
					require.Equal(t, time.Minute, ttl)
					return &tokenExchangeResult{AccessToken: "synthetic", PrivateKey: "synthetic-private", CredentialExpiresAt: deadline}, nil
				})
				resp, err := b.HandleRequest(context.Background(), &logical.Request{Operation: logical.UpdateOperation, Path: "exchange", Storage: storage, Data: map[string]interface{}{"subject_token": "synthetic", "requested_token_type": tokenType, "res_type": "resource_principal"}})
				require.NoError(t, err)
				require.NotNil(t, resp)
				if state == "expired" {
					require.True(t, resp.IsError())
					require.NotContains(t, resp.Data, "access_token")
					require.NotContains(t, resp.Data, "private_key")
					require.Nil(t, resp.Secret)
					return
				}
				require.False(t, resp.IsError(), "%v", resp)
				require.False(t, resp.Secret.Renewable)
				require.Equal(t, state != "unknown", resp.Data["credential_expiry_known"])
				if state == "unknown" {
					require.NotContains(t, resp.Data, "expires_in")
					require.NotContains(t, resp.Data, "expires_at")
					require.Equal(t, time.Minute, resp.Secret.TTL)
					require.Equal(t, 2*time.Minute, resp.Secret.MaxTTL)
					return
				}
				parsed, err := time.Parse(time.RFC3339Nano, resp.Data["expires_at"].(string))
				require.NoError(t, err)
				require.True(t, parsed.Equal(deadline))
				remaining := time.Duration(resp.Data["expires_in"].(int64)) * time.Second
				require.Positive(t, remaining)
				if state == "short" {
					require.LessOrEqual(t, remaining, 10*time.Second)
					require.Equal(t, remaining, resp.Secret.TTL)
					require.Equal(t, remaining, resp.Secret.MaxTTL)
				} else {
					require.Greater(t, remaining, 2*time.Minute)
					require.Equal(t, time.Minute, resp.Secret.TTL)
					require.Equal(t, 2*time.Minute, resp.Secret.MaxTTL)
				}
			})
		}
	}
}

func TestOCICredentialRevocationDoesNotCallOCI(t *testing.T) {
	b, _ := getTestBackend(t)
	b.httpClient = &http.Client{Transport: brokeredTestTransport(func(*http.Request) (*http.Response, error) {
		t.Fatal("revocation must not claim an OCI operation")
		return nil, nil
	})}
	secret := b.ociTokenSecret()
	require.Nil(t, secret.Renew)
	resp, err := secret.Revoke(context.Background(), &logical.Request{}, nil)
	require.NoError(t, err)
	require.Nil(t, resp)
}

func TestOCIExpiryStartsBeforeTransport(t *testing.T) {
	b, _ := getTestBackend(t)
	var dispatched time.Time
	b.httpClient = &http.Client{Transport: brokeredTestTransport(func(*http.Request) (*http.Response, error) {
		dispatched = time.Now()
		return brokeredTestResponse(200, `{"access_token":"synthetic","expires_in":10}`), nil
	})}
	key := generateTestRSAPrivateKey(t)
	before := time.Now()
	result, err := b.exchangeTokenForOCI(context.Background(), "synthetic", ociRequestedTokenTypeUPST, "", encodeTestPublicKeyPEM(t, &key.PublicKey), time.Hour, &federatedConfig{DomainUrl: "https://oci.example"})
	require.NoError(t, err)
	require.False(t, result.CredentialExpiresAt.Before(before.Add(10*time.Second)))
	require.False(t, result.CredentialExpiresAt.After(dispatched.Add(10*time.Second)))
}
