package ocibackend

import (
	"context"
	"fmt"
	"path"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathExchange returns the token exchange path
func (b *backend) pathExchange() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: path.Join("exchange"),
			Fields: map[string]*framework.FieldSchema{
				"subject_token": {
					Type:        framework.TypeString,
					Description: "The 3rd party OIDC/OAuth JWT subject token to exchange",
					Required:    true,
					DisplayAttrs: &framework.DisplayAttributes{
						Name:      "Subject Token",
						Sensitive: true,
					},
				},
				"subject_token_type": {
					Type:        framework.TypeString,
					Description: "Type of the subject token (urn:ietf:params:oauth:token-type:jwt)",
					Default:     "urn:ietf:params:oauth:token-type:jwt",
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "Subject Token Type",
					},
				},
				"role": {
					Type:        framework.TypeString,
					Description: "Role to use for token exchange constraints",
					Required:    false,
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "Role",
					},
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Requested TTL for the OCI session token",
					Required:    false,
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "TTL",
					},
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathExchangeWrite,
					Summary:  "Exchange a 3rd party JWT for an OCI session token",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathExchangeWrite,
					Summary:  "Exchange a 3rd party JWT for an OCI session token",
				},
			},

			HelpSynopsis:    pathExchangeHelpSyn,
			HelpDescription: pathExchangeHelpDesc,
		},
	}
}

// pathExchangeWrite handles the token exchange
func (b *backend) pathExchangeWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	subjectToken := data.Get("subject_token").(string)
	if subjectToken == "" {
		return logical.ErrorResponse("missing 'subject_token'"), nil
	}

	subjectTokenType := data.Get("subject_token_type").(string)
	if subjectTokenType == "" {
		subjectTokenType = "urn:ietf:params:oauth:token-type:jwt"
	}

	// Get backend configuration
	config, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return logical.ErrorResponse("backend not configured"), nil
	}

	// Get role if specified
	roleName := data.Get("role").(string)
	var role *roleEntry
	if roleName != "" {
		role, err = b.getRole(ctx, req.Storage, roleName)
		if err != nil {
			return nil, err
		}
		if role == nil {
			return logical.ErrorResponse("role '%s' not found", roleName), nil
		}
	}

	// Determine TTL
	ttl := time.Duration(data.Get("ttl").(int)) * time.Second
	if ttl == 0 {
		if role != nil && role.DefaultTTL > 0 {
			ttl = role.DefaultTTL
		} else {
			ttl = time.Duration(config.DefaultTTL) * time.Second
		}
	}

	maxTTL := time.Duration(config.MaxTTL) * time.Second
	if role != nil && role.MaxTTL > 0 {
		maxTTL = role.MaxTTL
	}

	if ttl > maxTTL {
		ttl = maxTTL
	}

	// Validate the subject token
	validatedClaims, err := b.validateSubjectToken(subjectToken, config)
	if err != nil {
		return logical.ErrorResponse("failed to validate subject token: %v", err), nil
	}

	// Perform the token exchange
	exchangeResult, err := b.exchangeTokenForOCI(ctx, subjectToken, subjectTokenType, config, validatedClaims)
	if err != nil {
		return logical.ErrorResponse("token exchange failed: %v", err), nil
	}

	// Prepare the response with OCI session token
	respData := map[string]interface{}{
		"access_token":  exchangeResult.AccessToken,
		"token_type":    exchangeResult.TokenType,
		"expires_in":    int(ttl.Seconds()),
		"expires_at":    time.Now().Add(ttl).Format(time.RFC3339),
		"region":        config.Region,
		"tenancy_ocid":  config.TenancyOCID,
	}

	// If OCI returns a session token specifically
	if exchangeResult.SessionToken != "" {
		respData["session_token"] = exchangeResult.SessionToken
	}

	resp := b.Secret("oci_token").Response(respData, map[string]interface{}{
		"role":            roleName,
		"subject_issuer":  validatedClaims.Issuer,
		"subject_subject": validatedClaims.Subject,
	})

	resp.Secret.TTL = ttl
	resp.Secret.MaxTTL = maxTTL

	return resp, nil
}

// ociTokenSecret returns the secret type for OCI tokens
func (b *backend) ociTokenSecret() *framework.Secret {
	return &framework.Secret{
		Type: "oci_token",
		Fields: map[string]*framework.FieldSchema{
			"access_token": {
				Type:        framework.TypeString,
				Description: "OCI access token",
			},
			"session_token": {
				Type:        framework.TypeString,
				Description: "OCI session token (for CLI/SDK)",
			},
			"token_type": {
				Type:        framework.TypeString,
				Description: "Token type (e.g., Bearer)",
			},
			"region": {
				Type:        framework.TypeString,
				Description: "OCI region",
			},
			"tenancy_ocid": {
				Type:        framework.TypeString,
				Description: "OCI tenancy OCID",
			},
		},
		Revoke: b.tokenRevoke,
	}
}

// tokenRevoke handles revocation of OCI tokens
func (b *backend) tokenRevoke(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// TODO: Implement token revocation via OCI API
	// This would call the OCI Identity service to invalidate the session token
	return nil, nil
}

// tokenValidationResult holds validated JWT claims
type tokenValidationResult struct {
	Issuer  string
	Subject string
	Email   string
	Groups  []string
	Raw     map[string]interface{}
}

// tokenExchangeResult holds the result of token exchange
type tokenExchangeResult struct {
	AccessToken  string
	SessionToken string
	TokenType    string
	ExpiresIn    int
}

// validateSubjectToken validates the incoming JWT subject token
func (b *backend) validateSubjectToken(token string, config *federatedConfig) (*tokenValidationResult, error) {
	// TODO: Implement JWT validation
	// This should:
	// 1. Parse the JWT without verification first to get the header
	// 2. Fetch the JWKS from config.JWKSURL if provided
	// 3. Verify the signature using the appropriate key
	// 4. Validate claims (iss, aud, exp, nbf)
	// 5. Check issuer against config.AllowedIssuers

	return &tokenValidationResult{
		Issuer:  "https://example.com",
		Subject: "user@example.com",
		Email:   "user@example.com",
		Groups:  []string{},
		Raw:     map[string]interface{}{},
	}, nil
}

// exchangeTokenForOCI exchanges the validated subject token for an OCI token
func (b *backend) exchangeTokenForOCI(ctx context.Context, subjectToken, subjectTokenType string, config *federatedConfig, claims *tokenValidationResult) (*tokenExchangeResult, error) {
	// TODO: Implement actual OCI token exchange
	// This should call the OCI Security Token Service or Identity API
	// to exchange the 3rd party JWT for an OCI session token

	// OCI API call would look something like:
	// POST /20200430/domains/{domainId}/token
	// with the subject token and configuration

	return &tokenExchangeResult{
		AccessToken:  "PLACEHOLDER_OCI_ACCESS_TOKEN",
		SessionToken: "PLACEHOLDER_OCI_SESSION_TOKEN",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	}, fmt.Errorf("OCI token exchange not yet implemented - this is a placeholder")
}

const pathExchangeHelpSyn = `
Exchange a 3rd party OIDC/OAuth JWT for an OCI session token.
`

const pathExchangeHelpDesc = `
This endpoint accepts a JWT subject token from a configured external Identity Provider
and exchanges it for an OCI session token via the OCI IAM token exchange API.

Required parameters:
  - subject_token: The JWT from your external IdP

Optional parameters:
  - subject_token_type: Token type (default: urn:ietf:params:oauth:token-type:jwt)
  - role: Role defining TTL constraints
  - ttl: Requested TTL for the OCI session token

Example:
  $ vault write oci/exchange \\
      subject_token="eyJhbGciOiJSUzI1NiIs..." \\
      role="developer"

The response includes:
  - access_token: The OCI access token
  - session_token: The OCI session token (for CLI/SDK use)
  - token_type: Bearer
  - expires_in: Token lifetime in seconds
  - region: The configured OCI region
  - tenancy_ocid: The OCI tenancy OCID
`
