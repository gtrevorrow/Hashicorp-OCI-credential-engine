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
					Description: "The 3rd party OIDC/OAuth JWT subject token to exchange (optional when callback fallback is enabled)",
					Required:    false,
					DisplayAttrs: &framework.DisplayAttributes{
						Name:      "Subject Token",
						Sensitive: true,
					},
				},
				"requested_token_type": {
					Type:        framework.TypeString,
					Description: "OCI token type to request (urn:oci:token-type:oci-upst or urn:oci:token-type:oci-rpst)",
					Default:     ociRequestedTokenTypeUPST,
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "Requested Token Type",
					},
				},
				"subject_token_audience": {
					Type:        framework.TypeString,
					Description: "Optional audience override for callback-resolved subject tokens; must be allowed by backend config",
					Required:    false,
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "Subject Token Audience",
					},
				},
				"res_type": {
					Type:        framework.TypeString,
					Description: "OCI resource type. Required when requested_token_type is urn:oci:token-type:oci-rpst",
					Required:    false,
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "Resource Type",
					},
				},
				"public_key": {
					Type:        framework.TypeString,
					Description: "Optional PEM-encoded public key to include in OCI token exchange",
					Required:    false,
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "Public Key",
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

			ExistenceCheck: func(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
				return false, nil // Always false, exchange paths overwrite/create
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
	// Get backend configuration
	config, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return logical.ErrorResponse("backend not configured"), nil
	}

	subjectToken := ""
	subjectTokenProvided := false
	if raw, ok := data.GetOk("subject_token"); ok {
		subjectToken = raw.(string)
		subjectTokenProvided = subjectToken != ""
	}

	requestedTokenType := ociRequestedTokenTypeUPST
	if raw, ok := data.GetOk("requested_token_type"); ok && raw.(string) != "" {
		requestedTokenType = raw.(string)
	}

	requestedSubjectTokenAudience := ""
	if raw, ok := data.GetOk("subject_token_audience"); ok && raw.(string) != "" {
		requestedSubjectTokenAudience = raw.(string)
	}

	if !isSupportedRequestedTokenType(requestedTokenType) {
		return logical.ErrorResponse("unsupported requested_token_type '%s'; supported values are '%s' and '%s'", requestedTokenType, ociRequestedTokenTypeUPST, ociRequestedTokenTypeRPST), nil
	}

	resType := ""
	if raw, ok := data.GetOk("res_type"); ok {
		resType = raw.(string)
	}

	if requestedTokenType == ociRequestedTokenTypeRPST && resType == "" {
		return logical.ErrorResponse("missing 'res_type' for requested_token_type '%s'", ociRequestedTokenTypeRPST), nil
	}

	publicKey := ""
	if raw, ok := data.GetOk("public_key"); ok {
		publicKey = raw.(string)
	}

	// Resolve missing subject token through registered callback flow.
	if subjectToken == "" {
		if !configAllowPluginIdentityFallback(config) {
			return logical.ErrorResponse("missing 'subject_token' and plugin identity fallback is disabled"), nil
		}
		if _, audienceErr := resolveSubjectTokenAudience(data, config); audienceErr != nil {
			return logical.ErrorResponse("%v", audienceErr), nil
		}
		callback := b.getSubjectTokenCallback()
		if callback == nil {
			return logical.ErrorResponse("missing 'subject_token' and unable to self-mint identity token"), nil
		}
		fallbackToken, callbackErr := callback(ctx, req, config)
		if callbackErr != nil {
			return logical.ErrorResponse("failed to mint subject_token via callback: %v", callbackErr), nil
		}
		if fallbackToken == "" {
			return logical.ErrorResponse("missing 'subject_token' and callback returned empty token"), nil
		}
		subjectToken = fallbackToken
	} else if requestedSubjectTokenAudience != "" {
		return logical.ErrorResponse("subject_token_audience is only supported when subject_token is omitted"), nil
	}

	// Get role if specified
	roleName := ""
	if raw, ok := data.GetOk("role"); ok {
		roleName = raw.(string)
	}
	if roleName != "" && config.StrictRoleNameMatch && !isStrictRoleNameValid(roleName) {
		return logical.ErrorResponse("invalid role '%s': strict_role_name_match requires pattern [A-Za-z0-9._:-]+", roleName), nil
	}
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

	// Role-claim enforcement is only meaningful for caller-supplied subject
	// tokens. Callback-resolved tokens are treated as plugin-trusted inputs and
	// use Vault-derived claims instead of caller-selected role values.
	if config.EnforceRoleClaimMatch && subjectTokenProvided {
		if roleName == "" {
			return logical.ErrorResponse("missing 'role' while enforce_role_claim_match is enabled"), nil
		}

		claimKey := configRoleClaimKey(config)
		roleMatched, claimValue, claimErr := jwtClaimContainsRole(subjectToken, claimKey, roleName)
		if claimErr != nil {
			return logical.ErrorResponse("unable to enforce role claim match: %v", claimErr), nil
		}

		if !roleMatched {
			return logical.ErrorResponse("role claim mismatch: claim '%s' value '%s' does not match requested role '%s'", claimKey, claimValue, roleName), nil
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

	// Perform the token exchange
	exchanger := b.tokenExchanger
	if exchanger == nil {
		exchanger = b.exchangeTokenForOCI
	}
	exchangeResult, err := exchanger(ctx, subjectToken, requestedTokenType, resType, publicKey, config)
	if err != nil {
		return logical.ErrorResponse("token exchange failed: %v", err), nil
	}

	// Prepare the response with OCI session token
	respData := map[string]interface{}{
		"access_token":         exchangeResult.AccessToken,
		"token_type":           exchangeResult.TokenType,
		"requested_token_type": exchangeResult.RequestedTokenType,
		"expires_in":           int(ttl.Seconds()),
		"expires_at":           time.Now().Add(ttl).Format(time.RFC3339),
	}
	if config.Region != "" {
		respData["region"] = config.Region
	}
	if config.TenancyOCID != "" {
		respData["tenancy_ocid"] = config.TenancyOCID
	}

	// If OCI returns a session token specifically
	if exchangeResult.SessionToken != "" {
		respData["session_token"] = exchangeResult.SessionToken
	}
	if exchangeResult.RPSTToken != "" {
		respData["rpst_token"] = exchangeResult.RPSTToken
	}
	if publicKey == "" && exchangeResult.PrivateKey != "" {
		respData["private_key"] = exchangeResult.PrivateKey
	}
	if publicKey == "" && exchangeResult.PublicKey != "" {
		respData["public_key"] = exchangeResult.PublicKey
	}

	resp := b.Secret("oci_token").Response(respData, map[string]interface{}{
		"role": roleName,
	})

	resp.Secret.TTL = ttl
	resp.Secret.MaxTTL = maxTTL

	return resp, nil
}

type fieldDataGetter interface {
	GetOk(string) (interface{}, bool)
}

func resolveSubjectTokenAudience(data fieldDataGetter, config *federatedConfig) (string, error) {
	audience := configSubjectTokenSelfMintAudience(config)
	if data == nil {
		return audience, nil
	}

	raw, ok := data.GetOk("subject_token_audience")
	if !ok || raw.(string) == "" {
		return audience, nil
	}
	requestedAudience := raw.(string)
	allowed := configSubjectTokenAllowedAudiences(config)
	for _, allowedAudience := range allowed {
		if requestedAudience == allowedAudience {
			return requestedAudience, nil
		}
	}
	if len(allowed) == 0 {
		return "", fmt.Errorf("subject_token_audience override is not enabled for this backend")
	}
	return "", fmt.Errorf("subject_token_audience '%s' is not in subject_token_allowed_audiences", requestedAudience)
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
			"rpst_token": {
				Type:        framework.TypeString,
				Description: "OCI Resource Principal Session Token",
			},
			"private_key": {
				Type:        framework.TypeString,
				Description: "PEM-encoded private key associated with the OCI session token",
			},
			"public_key": {
				Type:        framework.TypeString,
				Description: "PEM-encoded public key associated with the OCI session token",
			},
			"token_type": {
				Type:        framework.TypeString,
				Description: "Token type (e.g., Bearer)",
			},
			"requested_token_type": {
				Type:        framework.TypeString,
				Description: "OCI token type returned by token exchange",
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

const pathExchangeHelpSyn = `
Exchange a 3rd party OIDC/OAuth JWT for an OCI session token.
`

const pathExchangeHelpDesc = `
This endpoint accepts a JWT subject token from a configured external Identity Provider
and exchanges it for an OCI session token via the OCI IAM token exchange API.

Subject token behavior:
  - subject_token is required when allow_plugin_identity_fallback=false
  - subject_token is optional when allow_plugin_identity_fallback=true and callback fallback is configured

Optional parameters:
	- requested_token_type: OCI token type (default: urn:oci:token-type:oci-upst)
	- res_type: OCI resource type (required for urn:oci:token-type:oci-rpst)
	- public_key: Optional PEM public key included in the exchange request; if omitted, the plugin generates a fresh RSA key pair for the exchange
  - role: Role defining TTL constraints
  - ttl: Requested TTL for the OCI session token

Example:
  $ vault write oci/exchange \\
      subject_token="eyJhbGciOiJSUzI1NiIs..." \\
      role="developer"

The response includes:
  - access_token: The OCI access token
  - session_token: The OCI session token (for CLI/SDK use)
	- rpst_token: OCI RPST token when requested_token_type is urn:oci:token-type:oci-rpst
	- private_key: PEM-encoded private key for OCI request signing (omitted when public_key is provided)
	- public_key: PEM-encoded public key for OCI request signing (omitted when public_key is provided)
	- requested_token_type: The OCI token type requested/returned
  - token_type: Bearer
  - expires_in: Token lifetime in seconds
  - region: The configured OCI region
  - tenancy_ocid: The OCI tenancy OCID
`
