package ocibackend

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"

	"github.com/go-jose/go-jose/v4"
)

func buildSelfMintSigningJWK(privateKey *rsa.PrivateKey) (jose.JSONWebKey, error) {
	jwk := jose.JSONWebKey{
		Key:       privateKey,
		Use:       "sig",
		Algorithm: string(jose.RS256),
	}

	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return jose.JSONWebKey{}, err
	}
	jwk.KeyID = joseBase64URL(thumbprint)

	return jwk, nil
}

func jsonWebKeyMap(jwk jose.JSONWebKey) (map[string]interface{}, error) {
	raw, err := json.Marshal(jwk)
	if err != nil {
		return nil, err
	}

	var out map[string]interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}

	return out, nil
}

func joseBase64URL(raw []byte) string {
	return base64.RawURLEncoding.EncodeToString(raw)
}

func parseSingleCertificate(der []byte) ([]*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return []*x509.Certificate{cert}, nil
}
