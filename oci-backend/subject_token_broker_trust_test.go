package ocibackend

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

type brokeredTestTransport func(*http.Request) (*http.Response, error)

func (f brokeredTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func brokeredTestResponse(code int, body string) *http.Response {
	return &http.Response{StatusCode: code, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}
func brokeredTestJWKS(t *testing.T, keys ...jose.JSONWebKey) string {
	t.Helper()
	data, err := json.Marshal(jose.JSONWebKeySet{Keys: keys})
	require.NoError(t, err)
	return string(data)
}
func brokeredRemoteTestConfig() *federatedConfig {
	return &federatedConfig{BrokeredSubjectTokenEnabled: true, BrokeredSubjectTokenTrustType: brokeredTrustTypeJWKSURL,
		BrokeredSubjectTokenIssuer: "https://issuer.example", BrokeredSubjectTokenJWKSURL: "https://issuer.example/keys",
		BrokeredSubjectTokenAllowedAudiences: []string{"test"}, BrokeredSubjectTokenAllowedAlgs: []string{"RS256"}}
}

func TestBrokeredTrustURLPolicy(t *testing.T) {
	for _, tc := range []struct {
		url          string
		debug, valid bool
	}{
		{"https://issuer.example/keys", false, true}, {"http://issuer.example/keys", false, false},
		{"http://issuer.example/keys", true, false}, {"http://127.0.0.1:8000/keys", false, false},
		{"http://127.0.0.1:8000/keys", true, true}, {"http://[::1]:8000/keys", true, true},
		{"http://localhost:8000/keys", true, true}, {"http://10.0.0.1/keys", true, false},
		{"https://user:pass@issuer.example/keys", false, false}, {"https://issuer.example/keys?secret=1", false, false},
		{"https://issuer.example/keys#fragment", false, false}, {"file:///keys", true, false},
	} {
		t.Run(fmt.Sprintf("%s/debug=%v", tc.url, tc.debug), func(t *testing.T) { _, err := brokeredURL(tc.url, tc.debug); require.Equal(t, tc.valid, err == nil) })
	}
}

func TestBrokeredTrustConfigPersistsDebugAndOrigins(t *testing.T) {
	b, s := getTestBackend(t)
	payload := map[string]interface{}{"domain_url": "https://oci.example", "client_id": "test", "client_secret": "test",
		"brokered_subject_token_enabled": true, "brokered_subject_token_trust_type": "jwks_url",
		"brokered_subject_token_issuer": "https://issuer.example", "brokered_subject_token_allowed_audiences": []string{"test"},
		"brokered_subject_token_allowed_algs": []string{"RS256"},
		"brokered_subject_token_jwks_url":     "http://localhost:8000/keys", "subject_token_self_mint_issuer": "https://vault.example"}
	resp, err := b.HandleRequest(context.Background(), &logical.Request{Operation: logical.UpdateOperation, Path: "config", Storage: s, Data: payload})
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "HTTPS")
	payload["debug_allow_brokered_http"] = true
	payload["brokered_subject_token_allowed_jwks_origins"] = []string{"https://keys.example"}
	resp, err = b.HandleRequest(context.Background(), &logical.Request{Operation: logical.UpdateOperation, Path: "config", Storage: s, Data: payload})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError())
	resp, err = b.HandleRequest(context.Background(), &logical.Request{Operation: logical.ReadOperation, Path: "config", Storage: s})
	require.NoError(t, err)
	require.Equal(t, true, resp.Data["debug_allow_brokered_http"])
	require.Equal(t, []string{"https://keys.example"}, resp.Data["brokered_subject_token_allowed_jwks_origins"])
	resp, err = b.HandleRequest(context.Background(), &logical.Request{Operation: logical.UpdateOperation, Path: "config", Storage: s, Data: map[string]interface{}{"debug_allow_brokered_http": false}})
	require.NoError(t, err)
	require.True(t, resp.IsError())
	cfg, err := b.getConfig(context.Background(), s)
	require.NoError(t, err)
	require.True(t, cfg.DebugAllowBrokeredHTTP)
}

func TestBrokeredDiscoveryIssuerAndOrigin(t *testing.T) {
	key := generateTestRSAPrivateKey(t)
	for _, tc := range []struct {
		name, issuer, url string
		allow             []string
		valid             bool
	}{
		{"same origin", "https://issuer.example", "https://issuer.example/keys", nil, true},
		{"missing issuer", "", "https://issuer.example/keys", nil, false},
		{"wrong issuer", "https://other.example", "https://issuer.example/keys", nil, false},
		{"trailing slash issuer", "https://issuer.example/", "https://issuer.example/keys", nil, false},
		{"unapproved origin", "https://issuer.example", "https://keys.example/keys", nil, false},
		{"approved origin", "https://issuer.example", "https://keys.example/keys", []string{"https://keys.example"}, true},
		{"downgrade", "https://issuer.example", "http://issuer.example/keys", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := getTestBackend(t)
			c := brokeredRemoteTestConfig()
			c.BrokeredSubjectTokenTrustType = brokeredTrustTypeOIDCDiscovery
			c.BrokeredSubjectTokenAllowedJWKSOrigins = tc.allow
			calls := 0
			b.brokeredTransport = brokeredTestTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					d, _ := json.Marshal(map[string]string{"issuer": tc.issuer, "jwks_uri": tc.url})
					return brokeredTestResponse(200, string(d)), nil
				}
				return brokeredTestResponse(200, brokeredTestJWKS(t, jose.JSONWebKey{Key: &key.PublicKey})), nil
			})
			_, err := b.resolveBrokeredVerificationKeys(context.Background(), c)
			require.Equal(t, tc.valid, err == nil)
			if !tc.valid {
				require.Equal(t, 1, calls)
			}
		})
	}
}

func TestBrokeredTrustRejectsRedirectsAndOversizedDocuments(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
		body string
	}{
		{"redirect", 302, ""}, {"temporary redirect", 307, ""}, {"oversize", 200, strings.Repeat(" ", maxBrokeredDocumentBytes+1)},
		{"trailing JSON", 200, `{} {}`}, {"error body", 500, "sensitive upstream diagnostic"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := getTestBackend(t)
			calls := 0
			b.brokeredTransport = brokeredTestTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				resp := brokeredTestResponse(tc.code, tc.body)
				resp.Header.Set("Location", "https://other.example/keys")
				return resp, nil
			})
			var out interface{}
			err := b.fetchBrokeredJSON(context.Background(), "https://issuer.example/keys", &out, brokeredRemoteTestConfig())
			require.Error(t, err)
			require.Equal(t, 1, calls)
			require.NotContains(t, err.Error(), "sensitive upstream diagnostic")
		})
	}
}

func TestBrokeredSigningKeySuitability(t *testing.T) {
	rsaKey := generateTestRSAPrivateKey(t)
	ecKey := generateTestECDSAPrivateKey(t)
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	for _, tc := range []struct {
		name  string
		key   jose.JSONWebKey
		alg   string
		valid bool
	}{
		{"RSA", jose.JSONWebKey{Key: &rsaKey.PublicKey}, "RS256", true},
		{"weak RSA", jose.JSONWebKey{Key: &weak.PublicKey}, "RS256", false},
		{"private key", jose.JSONWebKey{Key: rsaKey}, "RS256", false},
		{"encryption key", jose.JSONWebKey{Key: &rsaKey.PublicKey, Use: "enc"}, "RS256", false},
		{"algorithm mismatch", jose.JSONWebKey{Key: &rsaKey.PublicKey, Algorithm: "RS512"}, "RS256", false},
		{"EC", jose.JSONWebKey{Key: &ecKey.PublicKey}, "ES256", true},
		{"EC wrong curve", jose.JSONWebKey{Key: &ecKey.PublicKey}, "ES512", false},
	} {
		t.Run(tc.name, func(t *testing.T) { require.Equal(t, tc.valid, isBrokeredKeyCompatibleWithAlg(tc.key, tc.alg)) })
	}
	raw := brokeredTestJWKS(t, jose.JSONWebKey{Key: &rsaKey.PublicKey})
	var doc map[string][]map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(raw), &doc))
	doc["keys"][0]["key_ops"] = []string{"sign"}
	encoded, _ := json.Marshal(doc)
	_, err = parseBrokeredJWKS(string(encoded))
	require.Error(t, err)
	doc["keys"][0]["key_ops"] = []string{"verify"}
	encoded, _ = json.Marshal(doc)
	_, err = parseBrokeredJWKS(string(encoded))
	require.NoError(t, err)
	keys := make([]jose.JSONWebKey, maxBrokeredKeys+1)
	for i := range keys {
		keys[i] = jose.JSONWebKey{Key: &rsaKey.PublicKey}
	}
	_, err = parseBrokeredJWKS(brokeredTestJWKS(t, keys...))
	require.Error(t, err)
	_, err = resolveBrokeredInlinePublicKeys([]string{encodeTestPublicKeyPEM(t, &weak.PublicKey)})
	require.Error(t, err)
}

func TestBrokeredTrustCacheCoordinatesRefreshAndFailsClosed(t *testing.T) {
	b, _ := getTestBackend(t)
	c := brokeredRemoteTestConfig()
	key := generateTestRSAPrivateKey(t)
	var calls atomic.Int32
	var fail atomic.Bool
	b.brokeredTransport = brokeredTestTransport(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		if fail.Load() {
			return brokeredTestResponse(500, ""), nil
		}
		return brokeredTestResponse(200, brokeredTestJWKS(t, jose.JSONWebKey{Key: &key.PublicKey})), nil
	})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := b.cachedBrokeredVerificationKeys(context.Background(), c, false)
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	require.Equal(t, int32(1), calls.Load())
	_, err := b.cachedBrokeredVerificationKeys(context.Background(), c, true)
	require.NoError(t, err)
	require.Equal(t, int32(1), calls.Load())
	b.brokeredTrustCache.fetched = time.Now().Add(-brokeredRefreshInterval - time.Second)
	_, err = b.cachedBrokeredVerificationKeys(context.Background(), c, true)
	require.NoError(t, err)
	require.Equal(t, int32(2), calls.Load())
	fail.Store(true)
	b.brokeredTrustCache.fetched = time.Now().Add(-brokeredCacheTTL - time.Second)
	_, err = b.cachedBrokeredVerificationKeys(context.Background(), c, false)
	require.Error(t, err)
	_, err = b.cachedBrokeredVerificationKeys(context.Background(), c, false)
	require.Error(t, err)
	require.Equal(t, int32(3), calls.Load())
	fail.Store(false)
	c.BrokeredSubjectTokenJWKSURL = "https://other.example/keys"
	_, err = b.cachedBrokeredVerificationKeys(context.Background(), c, false)
	require.NoError(t, err)
	require.Equal(t, int32(4), calls.Load())
}

func TestBrokeredTrustRefreshWaitIsCancelable(t *testing.T) {
	b, _ := getTestBackend(t)
	b.brokeredTrustCache.flight = make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := b.cachedBrokeredVerificationKeys(ctx, brokeredRemoteTestConfig(), false)
	require.ErrorIs(t, err, context.Canceled)
}

func TestBrokeredUnknownKeyRefreshSupportsRotation(t *testing.T) {
	b, _ := getTestBackend(t)
	c := brokeredRemoteTestConfig()
	old := generateTestRSAPrivateKey(t)
	next := generateTestRSAPrivateKey(t)
	calls := 0
	b.brokeredTransport = brokeredTestTransport(func(*http.Request) (*http.Response, error) {
		calls++
		keys := []jose.JSONWebKey{{Key: &old.PublicKey, KeyID: "old"}}
		if calls > 1 {
			keys = append(keys, jose.JSONWebKey{Key: &next.PublicKey, KeyID: "new"})
		}
		return brokeredTestResponse(200, brokeredTestJWKS(t, keys...)), nil
	})
	_, err := b.cachedBrokeredVerificationKeys(context.Background(), c, false)
	require.NoError(t, err)
	b.brokeredTrustCache.fetched = time.Now().Add(-brokeredRefreshInterval - time.Second)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: next}, (&jose.SignerOptions{}).WithHeader("kid", "new"))
	require.NoError(t, err)
	token, err := jwt.Signed(signer).Claims(map[string]interface{}{"iss": c.BrokeredSubjectTokenIssuer, "aud": "test", "exp": time.Now().Add(time.Minute).Unix()}).Serialize()
	require.NoError(t, err)
	_, err = b.validateBrokeredSubjectToken(context.Background(), token, c)
	require.NoError(t, err)
	require.Equal(t, 2, calls)
	// A kid that names a different key must not fall back to trying every key.
	signer, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: next}, (&jose.SignerOptions{}).WithHeader("kid", "old"))
	require.NoError(t, err)
	token, err = jwt.Signed(signer).Claims(map[string]interface{}{"iss": c.BrokeredSubjectTokenIssuer, "aud": "test", "exp": time.Now().Add(time.Minute).Unix()}).Serialize()
	require.NoError(t, err)
	_, err = b.validateBrokeredSubjectToken(context.Background(), token, c)
	require.Error(t, err)
	require.Equal(t, 2, calls)
}

func TestBrokeredEgressAddressPolicy(t *testing.T) {
	for _, tc := range []struct {
		host, ip     string
		debug, valid bool
	}{
		{"issuer.example", "8.8.8.8", false, true},
		{"issuer.example", "127.0.0.1", false, false},
		{"issuer.example", "127.0.0.1", true, false},
		{"issuer.example", "10.0.0.1", false, false},
		{"issuer.example", "169.254.169.254", true, false},
		{"issuer.example", "::1", false, false},
		{"issuer.example", "fc00::1", false, false},
		{"localhost", "127.0.0.1", true, true},
		{"localhost", "8.8.8.8", true, false},
		{"127.0.0.1", "127.0.0.1", true, true},
	} {
		t.Run(tc.host+"/"+tc.ip+fmt.Sprint(tc.debug), func(t *testing.T) {
			require.Equal(t, tc.valid, validateBrokeredAddress(tc.host, net.ParseIP(tc.ip), tc.debug) == nil)
		})
	}
}

func TestBrokeredInlinePublicKeysAcceptJWTKeyID(t *testing.T) {
	b, _ := getTestBackend(t)
	c := brokeredRemoteTestConfig()
	key := generateTestRSAPrivateKey(t)
	c.BrokeredSubjectTokenTrustType = brokeredTrustTypePublicKeys
	c.BrokeredSubjectTokenPublicKeys = []string{encodeTestPublicKeyPEM(t, &key.PublicKey)}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "issuer-key-id"))
	require.NoError(t, err)
	token, err := jwt.Signed(signer).Claims(map[string]interface{}{"iss": c.BrokeredSubjectTokenIssuer, "aud": "test", "exp": time.Now().Add(time.Minute).Unix()}).Serialize()
	require.NoError(t, err)
	_, err = b.validateBrokeredSubjectToken(context.Background(), token, c)
	require.NoError(t, err)
}

func TestOCITokenExchangeDoesNotFollowRedirect(t *testing.T) {
	b, _ := getTestBackend(t)
	calls := 0
	b.httpClient = &http.Client{Transport: brokeredTestTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		resp := brokeredTestResponse(307, "")
		resp.Header.Set("Location", "https://other.example/steal")
		return resp, nil
	})}
	key := generateTestRSAPrivateKey(t)
	_, err := b.exchangeTokenForOCI(context.Background(), "synthetic-subject", ociRequestedTokenTypeUPST, "", encodeTestPublicKeyPEM(t, &key.PublicKey), time.Minute, &federatedConfig{DomainUrl: "https://oci.example", ClientID: "test", ClientSecret: "test"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "307")
	require.Equal(t, 1, calls)
}

func TestBrokeredCanceledRefreshDoesNotPoisonCache(t *testing.T) {
	b, _ := getTestBackend(t)
	c := brokeredRemoteTestConfig()
	key := generateTestRSAPrivateKey(t)
	calls := 0
	b.brokeredTransport = brokeredTestTransport(func(*http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return nil, context.Canceled
		}
		return brokeredTestResponse(200, brokeredTestJWKS(t, jose.JSONWebKey{Key: &key.PublicKey})), nil
	})
	_, err := b.cachedBrokeredVerificationKeys(context.Background(), c, false)
	require.ErrorIs(t, err, context.Canceled)
	_, err = b.cachedBrokeredVerificationKeys(context.Background(), c, false)
	require.NoError(t, err)
	require.Equal(t, 2, calls)
}
