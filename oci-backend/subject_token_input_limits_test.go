package ocibackend

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
)

func oversizedRSATestJWK() map[string]string {
	// A 4097-bit public modulus exercises the parser limit without generating
	// an expensive RSA key or needing a valid signature.
	modulus := make([]byte, 513)
	modulus[0] = 1
	return map[string]string{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(modulus),
		"e":   "AQAB",
	}
}

func TestBrokeredSubjectTokenRejectsUnsafeHeaders(t *testing.T) {
	b, _ := getTestBackend(t)
	config := &federatedConfig{
		BrokeredSubjectTokenEnabled:     true,
		BrokeredSubjectTokenAllowedAlgs: []string{"RS256"},
	}
	oversizedHeader, err := json.Marshal(map[string]interface{}{
		"alg": "RS256",
		"jwk": oversizedRSATestJWK(),
	})
	require.NoError(t, err)

	for _, tc := range []struct {
		name   string
		header string
		err    string
	}{
		{
			name:   "excessive JSON nesting",
			header: `{"alg":"RS256","extra":` + strings.Repeat("[", 10001) + "0" + strings.Repeat("]", 10001) + "}",
			err:    "exceeded max depth",
		},
		{
			name:   "oversized embedded RSA key",
			header: string(oversizedHeader),
			err:    "modulus too large",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := base64.RawURLEncoding.EncodeToString([]byte(tc.header)) + ".e30.AA"
			claims, err := b.validateBrokeredSubjectToken(context.Background(), token, config)
			require.Nil(t, claims)
			require.ErrorContains(t, err, "failed to parse signed JWT")
			// Verify the parser's resource limit and the backend's non-disclosing public error independently.
			_, parserErr := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
			require.ErrorContains(t, parserErr, tc.err)
			require.Equal(t, "brokered_token_invalid", failureReason(err, ""))
		})
	}
}

func TestBrokeredJWKSRejectsOversizedRSAKeys(t *testing.T) {
	document, err := json.Marshal(map[string]interface{}{
		"keys": []map[string]string{oversizedRSATestJWK()},
	})
	require.NoError(t, err)

	keys, err := parseBrokeredJWKS(string(document))
	require.Nil(t, keys)
	require.ErrorContains(t, err, "modulus too large")
}
