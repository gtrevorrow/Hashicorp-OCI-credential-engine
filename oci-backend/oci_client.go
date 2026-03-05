package ocibackend

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/oracle/oci-go-sdk/v65/common/auth"
)

// tokenExchangeResult holds the result of token exchange
type tokenExchangeResult struct {
	AccessToken  string
	SessionToken string
	TokenType    string
	ExpiresIn    int
	PrivateKey   string
	PublicKey    string
}

// exchangeTokenForOCI exchanges the subject token for an OCI UPST token
func (b *backend) exchangeTokenForOCI(ctx context.Context, subjectToken, subjectTokenType string, config *federatedConfig) (*tokenExchangeResult, error) {
	builder := auth.TokenExchangeBuilder{
		DomainUrl:          config.DomainUrl,
		ClientId:           config.ClientID,
		ClientSecret:       config.ClientSecret,
		Region:             config.Region,
		RequestedTokenType: "urn:oci:token-type:oci-upst",
		SubjectTokenType:   subjectTokenType,
	}

	provider, err := auth.TokenExchangeConfigurationProviderFromToken(subjectToken, builder)
	if err != nil {
		return nil, fmt.Errorf("failed to create token exchange provider: %w", err)
	}

	// For User Principal Session Tokens (UPST), the SDK stores the raw token string
	// inside the SecurityToken/KeyID. We retrieve it to return directly as our session_token.
	sessionToken, err := provider.KeyID()
	if err != nil {
		return nil, fmt.Errorf("failed to extract underlying UPST from provider: %w", err)
	}

	privateKey, err := provider.PrivateRSAKey()
	if err != nil {
		return nil, fmt.Errorf("failed to extract private key from provider: %w", err)
	}

	privateKeyPEM, err := marshalPrivateKeyToPEM(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	publicKeyPEM, err := marshalPublicKeyToPEM(privateKey.Public())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	return &tokenExchangeResult{
		// OCI UPST is typically treated as the access or session token directly.
		AccessToken:  sessionToken,
		SessionToken: sessionToken,
		TokenType:    "Bearer",
		ExpiresIn:    config.DefaultTTL, // Handled implicitly by Vault unless OCI gives an exact TTL internally.
		PrivateKey:   privateKeyPEM,
		PublicKey:    publicKeyPEM,
	}, nil
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
