package ocibackend

import (
	"context"
	"path"

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
				"user_ocid": {
					Type:        framework.TypeString,
					Description: "OCID of the OCI user",
					Required:    true,
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "User OCID",
					},
				},
				"fingerprint": {
					Type:        framework.TypeString,
					Description: "Fingerprint of the API key",
					Required:    true,
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "API Key Fingerprint",
					},
				},
				"private_key": {
					Type:        framework.TypeString,
					Description: "Private key content for API authentication (PEM format)",
					Required:    false,
					DisplayAttrs: &framework.DisplayAttributes{
						Name:      "Private Key",
						Sensitive: true,
					},
				},
				"private_key_path": {
					Type:        framework.TypeString,
					Description: "Path to the private key file (alternative to private_key)",
					Required:    false,
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "Private Key Path",
					},
				},
				"passphrase": {
					Type:        framework.TypeString,
					Description: "Passphrase for the private key (if encrypted)",
					Required:    false,
					DisplayAttrs: &framework.DisplayAttributes{
						Name:      "Private Key Passphrase",
						Sensitive: true,
					},
				},
				"region": {
					Type:        framework.TypeString,
					Description: "OCI region identifier (e.g., us-ashburn-1)",
					Required:    true,
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "Region",
					},
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathConfigRead,
					Summary:  "Read the OCI backend configuration",
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathConfigWrite,
					Summary:  "Configure the OCI backend",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathConfigWrite,
					Summary:  "Update the OCI backend configuration",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathConfigDelete,
					Summary:  "Delete the OCI backend configuration",
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
			"tenancy_ocid":     config.TenancyOCID,
			"user_ocid":        config.UserOCID,
			"fingerprint":      config.Fingerprint,
			"region":           config.Region,
			"private_key_path": config.PrivateKeyPath,
			// Note: private_key and passphrase are not returned for security
		},
	}, nil
}

// pathConfigWrite creates or updates the configuration
func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	tenancyOCID := data.Get("tenancy_ocid").(string)
	if tenancyOCID == "" {
		return logical.ErrorResponse("missing 'tenancy_ocid'"), nil
	}

	userOCID := data.Get("user_ocid").(string)
	if userOCID == "" {
		return logical.ErrorResponse("missing 'user_ocid'"), nil
	}

	fingerprint := data.Get("fingerprint").(string)
	if fingerprint == "" {
		return logical.ErrorResponse("missing 'fingerprint'"), nil
	}

	region := data.Get("region").(string)
	if region == "" {
		return logical.ErrorResponse("missing 'region'"), nil
	}

	privateKey := data.Get("private_key").(string)
	privateKeyPath := data.Get("private_key_path").(string)

	if privateKey == "" && privateKeyPath == "" {
		return logical.ErrorResponse("either 'private_key' or 'private_key_path' must be provided"), nil
	}

	config := &backendConfig{
		TenancyOCID:    tenancyOCID,
		UserOCID:       userOCID,
		Fingerprint:    fingerprint,
		PrivateKey:     privateKey,
		PrivateKeyPath: privateKeyPath,
		Region:         region,
		Passphrase:     data.Get("passphrase").(string),
	}

	// TODO: Validate OCI credentials by attempting a connection
	// This would involve creating an OCI provider and making a test API call

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
Configure the OCI secrets engine with API credentials.
`

const pathConfigHelpDesc = `
The OCI secrets engine requires API credentials to authenticate with Oracle Cloud Infrastructure.

You must provide:
  - tenancy_ocid: The OCID of your OCI tenancy
  - user_ocid: The OCID of the user for authentication
  - fingerprint: The fingerprint of the API key
  - region: The OCI region (e.g., us-ashburn-1)
  - private_key OR private_key_path: The API private key

Example:
  $ vault write oci/config \\
      tenancy_ocid="ocid1.tenancy.oc1..xxxxx" \\
      user_ocid="ocid1.user.oc1..xxxxx" \\
      fingerprint="aa:bb:cc:dd:ee:ff" \\
      region="us-ashburn-1" \\
      private_key=@/path/to/oci_api_key.pem
`
