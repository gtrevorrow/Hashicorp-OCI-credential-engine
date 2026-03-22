//go:build integration

package ocibackend

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	mockSubjectToken   = "header.payload.signature"
	mockSubjectTypeJWT = "jwt"
)

func TestIntegrationExchangeTokenForOCI_UPST(t *testing.T) {
	// Covers OCI-01 and partially covers EXC-01/EXC-03 at the client integration layer.
	mockToken := makeMockSecurityJWT(t)
	var requestBody string

	server := newIntegrationServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)

		authHeader := r.Header.Get("Authorization")
		expectedAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("test-client:test-secret"))
		require.Equal(t, expectedAuth, authHeader)

		require.NoError(t, r.ParseForm())
		requestBody = r.PostForm.Encode()
		require.Equal(t, "urn:ietf:params:oauth:grant-type:token-exchange", r.PostForm.Get("grant_type"))
		require.Equal(t, ociRequestedTokenTypeUPST, r.PostForm.Get("requested_token_type"))
		require.Equal(t, mockSubjectToken, r.PostForm.Get("subject_token"))
		require.Equal(t, mockSubjectTypeJWT, r.PostForm.Get("subject_token_type"))
		require.NotEmpty(t, r.PostForm.Get("public_key"))

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fmt.Sprintf(`{"access_token":"%s","token_type":"Bearer"}`, mockToken)))
	}))
	defer server.Close()

	b := &backend{}
	config := &federatedConfig{
		DomainUrl:    server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		DefaultTTL:   3600,
	}

	result, err := b.exchangeTokenForOCI(
		context.Background(),
		mockSubjectToken,
		ociRequestedTokenTypeUPST,
		"",
		"",
		config,
	)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, mockToken, result.AccessToken)
	require.Equal(t, result.AccessToken, result.SessionToken)
	require.Equal(t, "", result.RPSTToken)
	require.Equal(t, ociRequestedTokenTypeUPST, result.RequestedTokenType)
	require.NotEmpty(t, result.PrivateKey)
	require.NotEmpty(t, result.PublicKey)
	require.Contains(t, requestBody, "public_key=")
}

func TestIntegrationExchangeTokenForOCI_RPSTWithPublicKey(t *testing.T) {
	// Covers OCI-01 for RPST and partially covers EXC-02 and EXC-06.
	mockToken := makeMockSecurityJWT(t)
	var requestBody string

	server := newIntegrationServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		requestBody = r.PostForm.Encode()
		require.Equal(t, ociRequestedTokenTypeRPST, r.PostForm.Get("requested_token_type"))
		require.Equal(t, "resource_principal", r.PostForm.Get("res_type"))
		require.NotEmpty(t, r.PostForm.Get("public_key"))

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fmt.Sprintf(`{"access_token":"%s","token_type":"Bearer"}`, mockToken)))
	}))
	defer server.Close()

	b := &backend{}
	config := &federatedConfig{
		DomainUrl:    server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		DefaultTTL:   3600,
	}

	privateKeyPEM := generateTestRSAPrivateKeyPEM(t)
	block, _ := pem.Decode([]byte(privateKeyPEM))
	require.NotNil(t, block)
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err)
	publicKeyPEM, err := marshalPublicKeyToPEM(privateKey.Public())
	require.NoError(t, err)

	result, err := b.exchangeTokenForOCI(
		context.Background(),
		mockSubjectToken,
		ociRequestedTokenTypeRPST,
		"resource_principal",
		publicKeyPEM,
		config,
	)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, mockToken, result.AccessToken)
	require.Equal(t, result.AccessToken, result.RPSTToken)
	require.Equal(t, "", result.SessionToken)
	require.Equal(t, ociRequestedTokenTypeRPST, result.RequestedTokenType)
	require.Equal(t, "", result.PrivateKey)
	require.Equal(t, "", result.PublicKey)
	require.Contains(t, requestBody, "res_type=resource_principal")
}

func TestIntegrationExchangeTokenForOCI_AuthFailure(t *testing.T) {
	// Covers OCI-03.
	server := newIntegrationServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
	}))
	defer server.Close()

	b := &backend{}
	config := &federatedConfig{
		DomainUrl:    server.URL,
		ClientID:     "bad-client",
		ClientSecret: "bad-secret",
		DefaultTTL:   3600,
	}

	_, err := b.exchangeTokenForOCI(
		context.Background(),
		mockSubjectToken,
		ociRequestedTokenTypeUPST,
		"",
		"",
		config,
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unable to exchange JWT for security token")
	require.Contains(t, err.Error(), "401")
}

func TestIntegrationExchangeTokenForOCI_Timeout(t *testing.T) {
	server := newIntegrationServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"late-token","token_type":"Bearer"}`))
	}))
	defer server.Close()

	b := &backend{
		httpClient: &http.Client{
			Timeout: 50 * time.Millisecond,
		},
	}
	config := &federatedConfig{
		DomainUrl:    server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		DefaultTTL:   3600,
	}

	_, err := b.exchangeTokenForOCI(
		context.Background(),
		mockSubjectToken,
		ociRequestedTokenTypeUPST,
		"",
		"",
		config,
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unable to exchange JWT for security token")
	require.Contains(t, err.Error(), "Client.Timeout")
}

func makeMockSecurityJWT(t *testing.T) string {
	t.Helper()

	headerJSON := `{"alg":"RS256","typ":"JWT"}`
	payloadJSON := fmt.Sprintf(
		`{"sub":"ocid1.user.oc1..test","tenant":"ocid1.tenancy.oc1..test","exp":%d,"iat":%d}`,
		time.Now().Add(2*time.Hour).Unix(),
		time.Now().Unix(),
	)

	header := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))
	payload := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))
	signature := base64.RawURLEncoding.EncodeToString([]byte("sig"))

	token := strings.Join([]string{header, payload, signature}, ".")
	// Sanity check token JSON decodes as expected.
	var claims map[string]interface{}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payload)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(payloadBytes, &claims))
	require.Contains(t, claims, "tenant")
	return token
}

func newIntegrationServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("integration test requires local TCP bind support: %v", err)
	}

	server := httptest.NewUnstartedServer(handler)
	server.Listener = listener
	server.Start()
	return server
}
