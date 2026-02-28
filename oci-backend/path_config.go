package ocibackend

import (
	"context"
	"path"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathConfig returns the configuration path for the backend
func (b *backend) pathConfig() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: path.Join("config"),
			Fields: map[string]*framework.FieldSchema{
				"tenancy_ocid": {
					Type:        framework.TypeString,
					Description: "OCID of the OCI tenancy",
					Required:    true,
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "Tenancy OCID",
					},
				},
				"domain_ocid": {
					Type:        framework.TypeString,
					Description: "OCID of the OCI Identity Domain",
					Required:    true,
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "Identity Domain OCID",
					},
				},
				"identity_provider_id": {
					Type:        framework.TypeString,
					Description: "ID of the external Identity Provider configured in OCI IAM",
					Required:    true,
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "Identity Provider ID",
					},
				},
				"region": {
					Type:        framework.TypeString,
					Description: "OCI region identifier (e.g., us-ashburn-1)",
					Required:    true,
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "OCI Region",
					},
				},
				"jwks_url": {
					Type:        framework.TypeString,
					Description: "JWKS endpoint URL for validating incoming subject tokens",
					Required:    false,
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "JWKS URL",
					},
				},
				"allowed_issuers": {
					Type:        framework.TypeCommaStringSlice,
					Description: "List of allowed issuers for incoming subject tokens",
					Required:    false,
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "Allowed Issuers",
					},
				},
				"default_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Default TTL for OCI session tokens (seconds)",
					Default:     3600,
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "Default TTL",
					},
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Maximum TTL for OCI session tokens (seconds)",
					Default:     86400,
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "Maximum TTL",
					},
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathConfigRead,
					Summary:  "Read the OCI federated identity configuration",
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathConfigWrite,
					Summary:  "Configure the OCI federated identity backend",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathConfigWrite,
					Summary:  "Update the OCI federated identity configuration",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathConfigDelete,
					Summary:  "Delete the OCI federated identity configuration",
				},
			},

			ExistenceCheck: b.pathConfigExistenceCheck,

			HelpSynopsis:    pathConfigHelpSyn,
			HelpDescription: pathConfigHelpDesc,
		},
	}
}

// pathConfigRead reads the configuration
func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"tenancy_ocid":         config.TenancyOCID,
			"domain_ocid":          config.DomainOCID,
			"identity_provider_id": config.IdentityProviderID,
			"region":               config.Region,
			"jwks_url":             config.JWKSURL,
			"allowed_issuers":      config.AllowedIssuers,
			"default_ttl":          config.DefaultTTL,
			"max_ttl":              config.MaxTTL,
		},
	}, nil
}

// pathConfigWrite creates or updates the configuration
func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	tenancyOCID := data.Get("tenancy_ocid").(string)
	if tenancyOCID == "" {
		return logical.ErrorResponse("missing 'tenancy_ocid'"), nil
	}

	domainOCID := data.Get("domain_ocid").(string)
	if domainOCID == "" {
		return logical.ErrorResponse("missing 'domain_ocid'"), nil
	}

	identityProviderID := data.Get("identity_provider_id").(string)
	if identityProviderID == "" {
		return logical.ErrorResponse("missing 'identity_provider_id'"), nil
	}

	region := data.Get("region").(string)
	if region == "" {
		return logical.ErrorResponse("missing 'region'"), nil
	}

	config := &federatedConfig{
		TenancyOCID:        tenancyOCID,
		DomainOCID:         domainOCID,
		IdentityProviderID: identityProviderID,
		Region:             region,
		JWKSURL:            data.Get("jwks_url").(string),
		AllowedIssuers:     data.Get("allowed_issuers").([]string),
		DefaultTTL:         data.Get("default_ttl").(int),
		MaxTTL:             data.Get("max_ttl").(int),
	}

	// Validate basic OCI OCID formats
	if !strings.HasPrefix(tenancyOCID, "ocid1.tenancy.") {
		return logical.ErrorResponse("invalid tenancy_ocid format"), nil
	}
	if !strings.HasPrefix(domainOCID, "ocid1.identitydomain.") {
		return logical.ErrorResponse("invalid domain_ocid format"), nil
	}

	if err := b.saveConfig(ctx, req.Storage, config); err != nil {
		return nil, err
	}

	return nil, nil
}

// pathConfigDelete deletes the configuration
func (b *backend) pathConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, "config"); err != nil {
		return nil, err
	}
	return nil, nil
}

// pathConfigExistenceCheck checks if the configuration exists
func (b *backend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	config, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return false, err
	}
	return config != nil, nil
}

const pathConfigHelpSyn = `
Configure the OCI federated identity backend.
`

const pathConfigHelpDesc = `
The OCI secrets engine exchanges 3rd party OIDC/OAuth JWT tokens for OCI session tokens.

You must configure:
  - tenancy_ocid: The OCID of your OCI tenancy
  - domain_ocid: The OCID of your OCI Identity Domain
  - identity_provider_id: The ID of the external IdP configured in OCI IAM
  - region: The OCI region (e.g., us-ashburn-1)

Optional:
  - jwks_url: JWKS endpoint for validating subject tokens
  - allowed_issuers: List of allowed token issuers
  - default_ttl: Default session token TTL (default: 3600s)
  - max_ttl: Maximum session token TTL (default: 86400s)

Example:
  $ vault write oci/config \\
      tenancy_ocid="ocid1.tenancy.oc1..xxxxx" \\
      domain_ocid="ocid1.identitydomain.oc1..xxxxx" \\
      identity_provider_id="ocid1.idp.oc1..xxxxx" \\
      region="us-ashburn-1" \\
      jwks_url="https://auth.example.com/.well-known/jwks.json" \\
      allowed_issuers="https://auth.example.com"
`
