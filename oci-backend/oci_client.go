package ocibackend

import (
	"context"
	"fmt"

	"github.com/oracle/oci-go-sdk/v65/common/auth"
)

// tokenExchangeResult holds the result of token exchange
type tokenExchangeResult struct {
	AccessToken  string
	SessionToken string
	TokenType    string
	ExpiresIn    int
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

	return &tokenExchangeResult{
		// OCI UPST is typically treated as the access or session token directly.
		AccessToken:  sessionToken,
		SessionToken: sessionToken,
		TokenType:    "Bearer",
		ExpiresIn:    config.DefaultTTL, // Handled implicitly by Vault unless OCI gives an exact TTL internally.
	}, nil
}
