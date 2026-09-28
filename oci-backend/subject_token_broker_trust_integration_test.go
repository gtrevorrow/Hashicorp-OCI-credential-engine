//go:build integration

package ocibackend

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
)

func TestIntegrationBrokeredLocalHTTPRequiresDebug(t *testing.T) {
	key := generateTestRSAPrivateKey(t)
	server := newIntegrationServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey}}}))
	}))
	defer server.Close()
	b, _ := getTestBackend(t)
	c := brokeredRemoteTestConfig()
	c.BrokeredSubjectTokenJWKSURL = server.URL
	_, err := b.resolveBrokeredVerificationKeys(context.Background(), c)
	require.Error(t, err)
	c.DebugAllowBrokeredHTTP = true
	keys, err := b.resolveBrokeredVerificationKeys(context.Background(), c)
	require.NoError(t, err)
	require.Len(t, keys, 1)
}

func TestIntegrationBrokeredHTTPRedirectIsRejected(t *testing.T) {
	server := newIntegrationServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://127.0.0.1:1/unreachable")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	b, _ := getTestBackend(t)
	c := brokeredRemoteTestConfig()
	c.BrokeredSubjectTokenJWKSURL = server.URL
	c.DebugAllowBrokeredHTTP = true
	_, err := b.resolveBrokeredVerificationKeys(context.Background(), c)
	require.Error(t, err)
	require.Contains(t, err.Error(), "307")
}
