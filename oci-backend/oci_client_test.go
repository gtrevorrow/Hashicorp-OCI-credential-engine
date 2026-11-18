package ocibackend

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type ociClientTestTransport func(*http.Request) (*http.Response, error)

func (f ociClientTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOCIExchangeRequestsRPSTLifetimeInWholeMinutes(t *testing.T) {
	key := generateTestRSAPrivateKey(t)
	publicKey := encodeTestPublicKeyPEM(t, &key.PublicKey)
	for _, tc := range []struct {
		name, tokenType, minutes string
		ttl                      time.Duration
		rejected                 bool
	}{
		{name: "zero cannot select upstream default", ttl: 0, rejected: true},
		{name: "negative lifetime", ttl: -time.Minute, rejected: true},
		{name: "subminute lifetime", ttl: 59 * time.Second, rejected: true},
		{name: "fraction below minute", ttl: time.Minute - time.Nanosecond, rejected: true},
		{name: "one minute", ttl: time.Minute, minutes: "1"},
		{name: "round down seconds", ttl: 90 * time.Second, minutes: "1"},
		{name: "just below two minutes", ttl: 119 * time.Second, minutes: "1"},
		{name: "two minutes", ttl: 2 * time.Minute, minutes: "2"},
		{name: "one hour", ttl: time.Hour, minutes: "60"},
		{name: "OCI maximum", ttl: 12 * time.Hour, minutes: "720"},
		{name: "cap above OCI maximum", ttl: 24 * time.Hour, minutes: "720"},
		{name: "large duration cannot overflow", ttl: time.Duration(1<<63 - 1), minutes: "720"},
		{name: "UPST omits RPST lifetime", tokenType: ociRequestedTokenTypeUPST, ttl: 30 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			b := &backend{httpClient: &http.Client{Transport: ociClientTestTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				require.NoError(t, r.ParseForm())
				require.Equal(t, tc.minutes, r.PostForm.Get("rpst_exp"))
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"access_token":"synthetic"}`))}, nil
			})}}
			tokenType := tc.tokenType
			if tokenType == "" {
				tokenType = ociRequestedTokenTypeRPST
			}
			result, err := b.exchangeTokenForOCI(context.Background(), "subject", tokenType, "resource", publicKey, tc.ttl,
				&federatedConfig{DomainUrl: "https://oci.example", ClientID: "client", ClientSecret: "secret"})
			if tc.rejected {
				require.ErrorContains(t, err, "ttl_invalid")
				require.Nil(t, result)
				require.Zero(t, calls, "invalid TTL must fail before contacting OCI")
				return
			}
			require.NoError(t, err)
			require.NotNil(t, result)
			require.Equal(t, 1, calls)
		})
	}
}

func TestKeyPairPEMMarshalling(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	privateKeyPEM, err := marshalPrivateKeyToPEM(privateKey)
	require.NoError(t, err)
	require.Contains(t, privateKeyPEM, "BEGIN PRIVATE KEY")

	publicKeyPEM, err := marshalPublicKeyToPEM(privateKey.Public())
	require.NoError(t, err)
	require.Contains(t, publicKeyPEM, "BEGIN PUBLIC KEY")

	privateBlock, _ := pem.Decode([]byte(privateKeyPEM))
	require.NotNil(t, privateBlock)
	require.Equal(t, "PRIVATE KEY", privateBlock.Type)

	parsedPrivateKey, err := x509.ParsePKCS8PrivateKey(privateBlock.Bytes)
	require.NoError(t, err)
	require.IsType(t, &rsa.PrivateKey{}, parsedPrivateKey)

	publicBlock, _ := pem.Decode([]byte(publicKeyPEM))
	require.NotNil(t, publicBlock)
	require.Equal(t, "PUBLIC KEY", publicBlock.Type)

	parsedPublicKey, err := x509.ParsePKIXPublicKey(publicBlock.Bytes)
	require.NoError(t, err)
	require.IsType(t, &rsa.PublicKey{}, parsedPublicKey)
}

func TestIsSupportedRequestedTokenType(t *testing.T) {
	require.True(t, isSupportedRequestedTokenType(ociRequestedTokenTypeUPST))
	require.True(t, isSupportedRequestedTokenType(ociRequestedTokenTypeRPST))
	require.False(t, isSupportedRequestedTokenType("urn:oci:token-type:unknown"))
}

func TestShouldReturnGeneratedKeyPair(t *testing.T) {
	require.True(t, shouldReturnGeneratedKeyPair(""))
	require.False(t, shouldReturnGeneratedKeyPair("-----BEGIN PUBLIC KEY-----..."))
}
