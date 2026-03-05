package ocibackend

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/oracle/oci-go-sdk/v65/common/auth"
)

const (
	ociRequestedTokenTypeUPST = "urn:oci:token-type:oci-upst"
	ociRequestedTokenTypeRPST = "urn:oci:token-type:oci-rpst"
)

// tokenExchangeResult holds the result of token exchange
type tokenExchangeResult struct {
	AccessToken        string
	SessionToken       string
	RPSTToken          string
	TokenType          string
	RequestedTokenType string
	ExpiresIn          int
	PrivateKey         string
	PublicKey          string
}

func isSupportedRequestedTokenType(requestedTokenType string) bool {
	return requestedTokenType == ociRequestedTokenTypeUPST || requestedTokenType == ociRequestedTokenTypeRPST
}

func shouldReturnGeneratedKeyPair(publicKey string) bool {
	return publicKey == ""
}

// exchangeTokenForOCI exchanges the subject token for an OCI token (UPST or RPST).
func (b *backend) exchangeTokenForOCI(ctx context.Context, subjectToken, subjectTokenType, requestedTokenType, resType, publicKey string, config *federatedConfig) (*tokenExchangeResult, error) {
	_ = ctx // placeholder for future context-aware SDK calls

	if requestedTokenType == "" {
		requestedTokenType = ociRequestedTokenTypeUPST
	}

	builder := auth.TokenExchangeBuilder{
		DomainUrl:          config.DomainUrl,
		ClientId:           config.ClientID,
		ClientSecret:       config.ClientSecret,
		Region:             config.Region,
		RequestedTokenType: requestedTokenType,
		SubjectTokenType:   subjectTokenType,
		ResType:            resType,
		PublicKey:          publicKey,
	}

	provider, err := auth.TokenExchangeConfigurationProviderFromToken(subjectToken, builder)
	if err != nil {
		return nil, fmt.Errorf("failed to create token exchange provider: %w", err)
	}

	// The SDK exposes exchanged token value via KeyID/SecurityToken.
	exchangedToken, err := provider.KeyID()
	if err != nil {
		return nil, fmt.Errorf("failed to extract token from provider: %w", err)
	}

	privateKeyPEM := ""
	publicKeyPEM := ""
	if shouldReturnGeneratedKeyPair(publicKey) {
		privateKey, err := provider.PrivateRSAKey()
		if err != nil {
			return nil, fmt.Errorf("failed to extract private key from provider: %w", err)
		}

		privateKeyPEM, err = marshalPrivateKeyToPEM(privateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal private key: %w", err)
		}

		publicKeyPEM, err = marshalPublicKeyToPEM(privateKey.Public())
		if err != nil {
			return nil, fmt.Errorf("failed to marshal public key: %w", err)
		}
	}

	return &tokenExchangeResult{
		// OCI token from exchange can be UPST or RPST depending on requested token type.
		AccessToken:        exchangedToken,
		SessionToken:       tokenByType(requestedTokenType, ociRequestedTokenTypeUPST, exchangedToken),
		RPSTToken:          tokenByType(requestedTokenType, ociRequestedTokenTypeRPST, exchangedToken),
		TokenType:          "Bearer",
		RequestedTokenType: requestedTokenType,
		ExpiresIn:          config.DefaultTTL, // Handled implicitly by Vault unless OCI gives an exact TTL internally.
		PrivateKey:         privateKeyPEM,
		PublicKey:          publicKeyPEM,
	}, nil
}

func tokenByType(requestedTokenType, wantedType, token string) string {
	if requestedTokenType == wantedType {
		return token
	}
	return ""
}

// marshalPrivateKeyToPEM converts an RSA private key into PKCS#8 PEM format.
func marshalPrivateKeyToPEM(privateKey *rsa.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", err
	}

	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	return string(pem.EncodeToMemory(block)), nil
}

// marshalPublicKeyToPEM converts a public key into SubjectPublicKeyInfo PEM format.
func marshalPublicKeyToPEM(publicKey interface{}) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}

	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	return string(pem.EncodeToMemory(block)), nil
}
