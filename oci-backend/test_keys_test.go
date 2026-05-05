package ocibackend

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
)

func generateTestRSAPrivateKeyPEM(t *testing.T) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	der := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
	return string(pem.EncodeToMemory(block))
}

func generateTestRSAPrivateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

func generateTestECDSAPrivateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func encodeTestPublicKeyPEM(t *testing.T, publicKey interface{}) string {
	t.Helper()

	der, err := x509.MarshalPKIXPublicKey(publicKey)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func makeSignedTestJWT(t *testing.T, signingKey interface{}, alg jose.SignatureAlgorithm, claims map[string]interface{}) string {
	t.Helper()

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: alg,
		Key:       signingKey,
	}, (&jose.SignerOptions{}).WithType("JWT"))
	require.NoError(t, err)

	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return token
}

func makeTestJWKS(t *testing.T, publicKey interface{}, alg jose.SignatureAlgorithm, kid string) string {
	t.Helper()

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{
			Key:       publicKey,
			KeyID:     kid,
			Use:       "sig",
			Algorithm: string(alg),
		}},
	}

	raw, err := json.Marshal(jwks)
	require.NoError(t, err)
	return string(raw)
}
