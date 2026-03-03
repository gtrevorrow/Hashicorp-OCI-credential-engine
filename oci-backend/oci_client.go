package ocibackend

import (
	"context"
	"errors"
)

// OCI Token Exchange API types

type ociTokenRequest struct {
	GrantType          string `json:"grant_type"`
	SubjectToken       string `json:"subject_token"`
	SubjectTokenType   string `json:"subject_token_type"`
	RequestedTokenType string `json:"requested_token_type,omitempty"`
	Scope              string `json:"scope,omitempty"`
}

type ociTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

// exchangeTokenWithOCI calls the OCI Identity Domain token endpoint
func (b *backend) exchangeTokenWithOCI(ctx context.Context, req *ociTokenRequest, config *federatedConfig) (*ociTokenResponse, error) {
	// TODO: Implement actual OCI API call
	// Endpoint: POST /oauth2/v1/token
	// Base URL: https://{domain}.identity.{region}.oci.oraclecloud.com
	// or: https://idcs-{domain}.identity.oraclecloud.com

	// The request body should be form-encoded or JSON depending on OCI's requirements
	// grant_type=urn:ietf:params:oauth:grant-type:token-exchange
	// subject_token={jwt}
	// subject_token_type=urn:ietf:params:oauth:token-type:jwt

	return nil, errors.New("OCI token exchange API not yet implemented")
}
