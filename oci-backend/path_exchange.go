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
		b.buildExchangePath(path.Join("exchange"), false),
		b.buildExchangePath(path.Join("exchange", framework.GenericNameRegex("role")), true),
	}
}

func (b *backend) buildExchangePath(pattern string, includeRole bool) *framework.Path {
	fields := map[string]*framework.FieldSchema{
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
		"ttl": {
			Type:        framework.TypeDurationSecond,
			Description: "Requested TTL for the OCI session token",
			Required:    false,
			DisplayAttrs: &framework.DisplayAttributes{
				Name: "TTL",
			},
		},
	}
	if includeRole {
		fields["role"] = &framework.FieldSchema{
			Type:        framework.TypeString,
			Description: "Role name selected from the exchange path",
			Required:    true,
			DisplayAttrs: &framework.DisplayAttributes{
				Name: "Role",
			},
		}
	}

	return &framework.Path{
		Pattern: pattern,
		Fields:  fields,

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
	}
}

// pathExchangeWrite handles the token exchange
func (b *backend) pathExchangeWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (resp *logical.Response, err error) {
	observed := &exchangeObservation{started: b.securityNow(), request: req, mode: "undetermined", source: "unavailable"}
	ctx = context.WithValue(ctx, exchangeObservationKey{}, observed)
	defer func() { b.finishExchange(req, observed, resp, err) }()

	// Reject undeclared input before raw request data can reach token resolution or signing.
	if err := data.ValidateStrict(); err != nil {
		return exchangeFailure(observed, "request_invalid", "invalid exchange request: unknown field or invalid field type")
	}

	if err := validateTokenTTLInputs(data, true, "ttl"); err != nil {
		return exchangeFailure(observed, "ttl_invalid", "invalid token TTL policy: ttl must use whole seconds within the supported range")
	}

	// Get backend configuration
	config, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		observed.reason = "storage_error"
		return nil, fmt.Errorf("unable to read backend configuration")
	}
	if config == nil {
		return exchangeFailure(observed, "not_configured", "backend not configured")
	}

	subjectToken := ""
	subjectTokenProvided := false
	if raw, ok := data.GetOk("subject_token"); ok {
		subjectToken = raw.(string)
		if subjectToken == "" {
			return exchangeFailure(observed, "subject_token_empty", "subject_token was provided but is empty")
		}
		subjectTokenProvided = true
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
		return exchangeFailure(observed, "token_type_invalid", "unsupported requested_token_type; supported values are urn:oci:token-type:oci-upst and urn:oci:token-type:oci-rpst")
	}

	resType := ""
	if raw, ok := data.GetOk("res_type"); ok {
		resType = raw.(string)
	}

	if requestedTokenType == ociRequestedTokenTypeRPST && resType == "" {
		return exchangeFailure(observed, "resource_type_missing", "missing 'res_type' for requested_token_type urn:oci:token-type:oci-rpst")
	}

	publicKey := ""
	if raw, ok := data.GetOk("public_key"); ok {
		publicKey = raw.(string)
	}

	roleName := ""
	if raw, ok := data.GetOk("role"); ok {
		roleName = raw.(string)
	}
	brokeredMode := subjectTokenProvided && config.BrokeredSubjectTokenEnabled
	observed.tokenType = requestedTokenType
	if subjectTokenProvided {
		observed.mode, observed.source = "direct", "caller"
	} else {
		observed.mode = "plugin_issued"
	}
	if brokeredMode {
		observed.mode, observed.source = "brokered", "brokered_reissue"
	}
	if subjectTokenProvided && !brokeredMode && len(config.SubjectTokenRoleMappings) > 0 {
		if roleName != "" {
			return exchangeFailure(observed, "role_path_disallowed", "role-specific exchange paths cannot be used when subject_token_role_mappings are configured")
		}
	}
	if roleName != "" {
		if req.Data == nil {
			req.Data = map[string]interface{}{}
		}
		req.Data["role"] = roleName
	}

	// Resolve missing subject token through registered callback flow.
	if subjectToken == "" {
		if !configEnablePluginIssuedSubjectToken(config) {
			return exchangeFailure(observed, "subject_token_required", "missing 'subject_token' and plugin-issued subject token mode is disabled")
		}
		if _, audienceErr := resolveSubjectTokenAudience(data, config); audienceErr != nil {
			return exchangeFailure(observed, "audience_invalid", "invalid subject_token_audience override; it must be explicitly allowed by backend configuration")
		}
		callback := b.getSubjectTokenCallback()
		if callback == nil {
			return exchangeFailure(observed, "subject_source_unavailable", "missing 'subject_token' and unable to self-mint identity token")
		}
		observed.source = "custom_callback"
		fallbackToken, callbackErr := callback(ctx, req, config)
		if callbackErr != nil {
			return exchangeFailure(observed, failureReason(callbackErr, "subject_resolution_failed"), "failed to mint subject_token via callback: "+publicFailureMessage(callbackErr, "subject token processing failed"))
		}
		if fallbackToken == "" {
			return exchangeFailure(observed, "subject_source_empty", "missing 'subject_token' and callback returned empty token")
		}
		subjectToken = fallbackToken
	} else if requestedSubjectTokenAudience != "" {
		return exchangeFailure(observed, "audience_disallowed", "subject_token_audience is only supported when subject_token is omitted")
	}

	if brokeredMode {
		validatedClaims, validateErr := b.validateBrokeredSubjectToken(ctx, subjectToken, config)
		if validateErr != nil {
			return exchangeFailure(observed, failureReason(validateErr, "brokered_validation_failed"), "failed to validate brokered subject_token: "+publicFailureMessage(validateErr, "verification or trust resolution failed"))
		}

		mappedClaims, mappingErr := renderBrokeredClaimMappings(validatedClaims, config.BrokeredSubjectTokenClaimMappings)
		if mappingErr != nil {
			return exchangeFailure(observed, "claim_mapping_failed", "failed to map brokered subject_token claims")
		}

		brokeredToken, mintErr := b.selfMintBrokeredSubjectToken(ctx, req, config, validatedClaims, mappedClaims)
		if mintErr != nil {
			return exchangeFailure(observed, failureReason(mintErr, "brokered_signing_failed"), "failed to self-mint brokered subject_token: "+publicFailureMessage(mintErr, "subject token signing failed"))
		}
		subjectToken = brokeredToken
	}

	var resolvedSubjectTokenClaims map[string]interface{}
	if config.DebugReturnResolvedSubjectTokenClaims && !debugClaimsActive(config, b.securityNow()) {
		b.securityEvent(req, "diagnostic_claims_inactive", true, true, "expired_or_unarmed")
	}
	if debugClaimsActive(config, b.securityNow()) {
		claims, claimsErr := decodeJWTClaimsMap(subjectToken)
		if claimsErr != nil {
			resolvedSubjectTokenClaims = map[string]interface{}{
				"_decode_error": "subject token is not a decodable JWT",
			}
		} else {
			resolvedSubjectTokenClaims = claims
		}
	}

	if subjectTokenProvided && !brokeredMode && len(config.SubjectTokenRoleMappings) > 0 {
		derivedRoleName, derivedRoleErr := resolveRoleFromSubjectToken(subjectToken, config.SubjectTokenRoleMappings)
		if derivedRoleErr != nil {
			return exchangeFailure(observed, "role_mapping_failed", "unable to derive role from subject_token: no subject_token_role_mappings matched or claims are invalid")
		}
		roleName = derivedRoleName
	}
	if roleName != "" && config.StrictRoleNameMatch && !isStrictRoleNameValid(roleName) {
		return exchangeFailure(observed, "role_invalid", "invalid mapped role: strict_role_name_match requires pattern [A-Za-z0-9._:-]+")
	}
	var role *roleEntry
	if roleName != "" {
		role, err = b.getRole(ctx, req.Storage, roleName)
		if err != nil {
			observed.reason = failureReason(err, "role_unavailable")
			return nil, fmt.Errorf("unable to load role: %s", publicFailureMessage(err, "role policy unavailable"))
		}
		if role == nil {
			return exchangeFailure(observed, "role_missing", "requested role not found")
		}
	}

	if role != nil {
		observed.role = roleName
	}
	var vaultMax time.Duration
	if system := b.System(); system != nil {
		vaultMax = system.MaxLeaseTTL()
	}
	ttl, maxTTL, ttlErr := resolveTokenTTL(data.Get("ttl").(int), config, role, vaultMax)
	if ttlErr != nil {
		return exchangeFailure(observed, "ttl_invalid", "invalid token TTL policy: unable to resolve bounded credential TTL")
	}

	// Perform the token exchange
	exchanger := b.getTokenExchanger()
	if exchanger == nil {
		exchanger = b.exchangeTokenForOCI
	}
	exchangeResult, err := exchanger(ctx, subjectToken, requestedTokenType, resType, publicKey, ttl, config)
	if err != nil {
		safe := safeExchangeError(err)
		observed.reason, observed.status, observed.upstreamID = safe.reason, safe.status, safe.requestID
		if resolvedSubjectTokenClaims != nil && debugClaimsActive(config, b.securityNow()) {
			b.securityEvent(req, "diagnostic_claims_returned", true, true, "enabled")
			return logical.ErrorResponseWithData(map[string]interface{}{"resolved_subject_token_claims": resolvedSubjectTokenClaims}, "token exchange failed: %s", safe.Error()), nil
		}
		return logical.ErrorResponse("token exchange failed: %s", safe.Error()), nil
	}
	if exchangeResult == nil {
		return exchangeFailure(observed, "oci_response_invalid", "token exchange failed: OCI response is unavailable")
	}
	observed.status, observed.upstreamID = exchangeResult.HTTPStatus, exchangeResult.RequestID

	now := time.Now()
	leaseTTL, leaseMaxTTL, remaining, expiryErr := reconcileCredentialExpiry(ttl, maxTTL, exchangeResult.CredentialExpiresAt, now)
	if expiryErr != nil {
		return exchangeFailure(observed, "oci_expiry_invalid", "invalid OCI credential expiry")
	}

	// Prepare the response with OCI session token
	respData := map[string]interface{}{
		"access_token":            exchangeResult.AccessToken,
		"token_type":              exchangeResult.TokenType,
		"requested_token_type":    exchangeResult.RequestedTokenType,
		"credential_expiry_known": !exchangeResult.CredentialExpiresAt.IsZero(),
	}
	if !exchangeResult.CredentialExpiresAt.IsZero() {
		respData["expires_in"] = int64(remaining / time.Second)
		respData["expires_at"] = exchangeResult.CredentialExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	if resolvedSubjectTokenClaims != nil && debugClaimsActive(config, b.securityNow()) {
		b.securityEvent(req, "diagnostic_claims_returned", true, true, "enabled")
		respData["resolved_subject_token_claims"] = resolvedSubjectTokenClaims
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
	resp = b.Secret("oci_token").Response(respData, map[string]interface{}{
		"role": roleName,
	})

	resp.Secret.TTL = leaseTTL
	resp.Secret.MaxTTL = leaseMaxTTL
	resp.Secret.Renewable = false

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
	requestedAudience, err := normalizeSubjectTokenAudience(raw.(string))
	if err != nil {
		return "", fmt.Errorf("invalid subject_token_audience: %w", err)
	}
	allowed := configSubjectTokenAllowedAudiences(config)
	for _, allowedAudience := range allowed {
		if requestedAudience == allowedAudience {
			return requestedAudience, nil
		}
	}
	if len(allowed) == 0 {
		return "", fmt.Errorf("subject_token_audience override is not enabled for this backend")
	}
	return "", fmt.Errorf("subject_token_audience is not in subject_token_allowed_audiences")
}

// ociTokenSecret returns the secret type for OCI tokens
func (b *backend) ociTokenSecret() *framework.Secret {
	return &framework.Secret{
		Type: "oci_token",
		Fields: map[string]*framework.FieldSchema{
			"credential_expiry_known": {Type: framework.TypeBool, Description: "Whether OCI supplied a usable expires_in"},
			"expires_in":              {Type: framework.TypeInt64, Description: "Remaining OCI credential lifetime in whole seconds; omitted if unknown"},
			"expires_at":              {Type: framework.TypeString, Description: "Conservative OCI expiry deadline; omitted if unknown"},
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
		},
		Revoke: b.tokenRevoke,
	}
}

// tokenRevoke completes Vault lease cleanup; it does not invalidate OCI credentials.
func (b *backend) tokenRevoke(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// No OCI revocation request is implemented. Credential validity at OCI is
	// independent of this local lease; callers must not treat revocation as logout.
	return nil, nil
}

const pathExchangeHelpSyn = `
Exchange a 3rd party OIDC/OAuth JWT for an OCI session token.
`

const pathExchangeHelpDesc = `
This endpoint accepts a JWT subject token from a configured external Identity Provider
and exchanges it for an OCI session token via the OCI IAM token exchange API.

Requests reject fields outside the endpoint schema before token processing.
The bare exchange endpoint does not accept a role field in the request body.

Subject token behavior:
  - subject_token is required when enable_plugin_issued_subject_token=false
  - subject_token is optional when enable_plugin_issued_subject_token=true and callback fallback is configured

Optional parameters:
	- requested_token_type: OCI token type (default: urn:oci:token-type:oci-upst)
	- res_type: OCI resource type (required for urn:oci:token-type:oci-rpst)
	- public_key: Optional PEM public key included in the exchange request; if omitted, the plugin generates a fresh RSA key pair for the exchange
  - ttl: Requested TTL for the OCI session token

Example:
  $ vault write oci/exchange/developer \\
      subject_token="eyJhbGciOiJSUzI1NiIs..." \\
      ttl=3600

The response includes:
  - access_token: The OCI access token
  - session_token: The OCI session token (for CLI/SDK use)
	- rpst_token: OCI RPST token when requested_token_type is urn:oci:token-type:oci-rpst
	- private_key: PEM-encoded private key for OCI request signing (omitted when public_key is provided)
	- requested_token_type: The OCI token type requested/returned
  - token_type: Bearer
  - credential_expiry_known: Whether OCI supplied expires_in
  - expires_in: Conservative remaining OCI lifetime in whole seconds (omitted if unknown)
  - expires_at: Conservative deadline derived from OCI expires_in (omitted if unknown)

Vault lease duration is bounded by local policy and known remaining OCI lifetime.
Leases are nonrenewable. Revoking a lease does not invalidate the OCI credential.
`
