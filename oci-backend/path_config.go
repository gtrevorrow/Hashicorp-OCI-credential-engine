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
				"domain_url": {
					Type:        framework.TypeString,
					Description: "URL of the OCI Identity Domain (e.g. https://idcs-xxxx.identity.oraclecloud.com)",
					Required:    true,
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "Identity Domain URL",
					},
				},
				"client_id": {
					Type:        framework.TypeString,
					Description: "Client ID of the OAuth Confidential Application",
					Required:    true,
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "Client ID",
					},
				},
				"client_secret": {
					Type:        framework.TypeString,
					Description: "Client Secret of the OAuth Confidential Application",
					Required:    true,
					DisplayAttrs: &framework.DisplayAttributes{
						Name:      "Client Secret",
						Sensitive: true,
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
				"enforce_role_claim_match": {
					Type:        framework.TypeBool,
					Description: "When true, require caller-provided subject_token claim to match request role",
					Default:     false,
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "Enforce Role Claim Match",
					},
				},
				"role_claim_key": {
					Type:        framework.TypeString,
					Description: "JWT claim key used for role matching when enforce_role_claim_match is true",
					Default:     "vault_role",
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "Role Claim Key",
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
			"tenancy_ocid": config.TenancyOCID,
			"domain_url":   config.DomainUrl,
			"client_id":    config.ClientID,
			"region":       config.Region,
			// Client Secret is intentionally omitted from read

			"default_ttl": config.DefaultTTL,
			"max_ttl":     config.MaxTTL,
			"enforce_role_claim_match": config.EnforceRoleClaimMatch,
			"role_claim_key":          configRoleClaimKey(config),
		},
	}, nil
}

// pathConfigWrite creates or updates the configuration
func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	tenancyOCID := data.Get("tenancy_ocid").(string)
	if tenancyOCID == "" {
		return logical.ErrorResponse("missing 'tenancy_ocid'"), nil
	}

	domainUrl := data.Get("domain_url").(string)
	if domainUrl == "" {
		return logical.ErrorResponse("missing 'domain_url'"), nil
	}

	clientID := data.Get("client_id").(string)
	if clientID == "" {
		return logical.ErrorResponse("missing 'client_id'"), nil
	}

	clientSecret := data.Get("client_secret").(string)
	if clientSecret == "" {
		return logical.ErrorResponse("missing 'client_secret'"), nil
	}

	region := data.Get("region").(string)
	if region == "" {
		return logical.ErrorResponse("missing 'region'"), nil
	}

	config := &federatedConfig{
		TenancyOCID:  tenancyOCID,
		DomainUrl:    domainUrl,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Region:       region,

		DefaultTTL: data.Get("default_ttl").(int),
		MaxTTL:     data.Get("max_ttl").(int),

		EnforceRoleClaimMatch: data.Get("enforce_role_claim_match").(bool),
		RoleClaimKey:          data.Get("role_claim_key").(string),
	}

	// Validate basic OCI OCID formats
	if !strings.HasPrefix(tenancyOCID, "ocid1.tenancy.") {
		return logical.ErrorResponse("invalid tenancy_ocid format"), nil
	}
	if !strings.HasPrefix(domainUrl, "https://") {
		return logical.ErrorResponse("invalid domain_url format, must start with https://"), nil
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

func configRoleClaimKey(config *federatedConfig) string {
	if config != nil && config.RoleClaimKey != "" {
		return config.RoleClaimKey
	}
	return "vault_role"
}

const pathConfigHelpDesc = `
The OCI secrets engine exchanges 3rd party OIDC/OAuth JWT tokens for OCI session tokens.

You must configure:
  - tenancy_ocid: The OCID of your OCI tenancy
  - domain_url: The URL of your OCI Identity Domain
  - client_id: The Client ID of the OAuth Confidential Application
  - client_secret: The Client Secret of the OAuth Confidential Application
  - region: The OCI region (e.g., us-ashburn-1)

Optional:
  - default_ttl: Default session token TTL (default: 3600s)
  - max_ttl: Maximum session token TTL (default: 86400s)
  - enforce_role_claim_match: Require subject_token claim to match request role (default: false)
  - role_claim_key: Claim key used for role matching (default: vault_role)

Example:
  $ vault write oci/config \
      tenancy_ocid="ocid1.tenancy.oc1..xxxxx" \
      domain_url="https://idcs-xxxxx.identity.oraclecloud.com" \
      client_id="my-client-id" \
      client_secret="my-client-secret" \
      region="us-ashburn-1"
`
