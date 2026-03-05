package ocibackend

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"
)

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
