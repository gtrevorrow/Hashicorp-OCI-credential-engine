package ocibackend

import (
	"context"
	"path"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathCreds returns the credential generation paths
func (b *backend) pathCreds() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: path.Join("creds", framework.MatchAllRegex("name")),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the role",
					Required:    true,
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "TTL for the session token",
					Default:     3600, // 1 hour default
				},
			},

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation:   b.pathCredsRead,
				logical.UpdateOperation: b.pathCredsRead,
			},

			HelpSynopsis:    pathCredsHelpSyn,
			HelpDescription: pathCredsHelpDesc,
		},
		{
			Pattern: path.Join("roles", framework.MatchAllRegex("name")),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the role",
					Required:    true,
				},
				"description": {
					Type:        framework.TypeString,
					Description: "Description of the role",
					Required:    false,
				},
				"default_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Default TTL for tokens generated under this role",
					Default:     3600,
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Maximum TTL for tokens generated under this role",
					Default:     86400, // 24 hours
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathRoleRead,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathRoleWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRoleWrite,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathRoleDelete,
				},
			},

			ExistenceCheck: b.pathRoleExistenceCheck,

			HelpSynopsis:    pathRoleHelpSyn,
			HelpDescription: pathRoleHelpDesc,
		},
	}
}

// pathCredsRead generates a new OCI session token
type ociTokenData struct {
	SessionToken string        `json:"session_token"`
	AccessToken  string        `json:"access_token"`
	ExpiresAt    time.Time     `json:"expires_at"`
	Region       string        `json:"region"`
	TenancyOCID  string        `json:"tenancy_ocid"`
}

func (b *backend) pathCredsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	// Get backend configuration
	config, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return logical.ErrorResponse("backend not configured"), nil
	}

	// Get role configuration
	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("role '%s' not found", roleName), nil
	}

	// Determine TTL
	ttl := time.Duration(data.Get("ttl").(int)) * time.Second
	if ttl == 0 {
		ttl = role.DefaultTTL
	}
	if ttl > role.MaxTTL {
		ttl = role.MaxTTL
	}

	// Generate the OCI session token
	// TODO: Implement actual OCI SDK integration here
	// This would call the OCI Identity service to generate a session token
	/*
	provider, err := b.getOCIProvider(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create OCI provider: %w", err)
	}

	identityClient, err := identity.NewIdentityClientWithConfigurationProvider(provider)
	if err != nil {
		return nil, fmt.Errorf("failed to create identity client: %w", err)
	}

	token, err := generateSessionToken(identityClient, config.UserOCID, ttl)
	if err != nil {
		return nil, fmt.Errorf("failed to generate session token: %w", err)
	}
	*/

	// For now, return placeholder data
	// In production, this would be the actual token from OCI
	resp := b.Secret("oci_token").Response(map[string]interface{}{
		"session_token": "PLACEHOLDER_TOKEN",
		"access_token":  "PLACEHOLDER_ACCESS_TOKEN",
		"region":        config.Region,
		"tenancy_ocid":  config.TenancyOCID,
		"user_ocid":     config.UserOCID,
	}, map[string]interface{}{
		"role": roleName,
	})

	resp.Secret.TTL = ttl
	resp.Secret.MaxTTL = role.MaxTTL

	return resp, nil
}

// ociToken returns the secret type for OCI tokens
func (b *backend) ociToken() *framework.Secret {
	return &framework.Secret{
		Type: "oci_token",
		Fields: map[string]*framework.FieldSchema{
			"session_token": {
				Type:        framework.TypeString,
				Description: "OCI session token",
			},
			"access_token": {
				Type:        framework.TypeString,
				Description: "OCI access token",
			},
			"region": {
				Type:        framework.TypeString,
				Description: "OCI region",
			},
			"tenancy_ocid": {
				Type:        framework.TypeString,
				Description: "OCI tenancy OCID",
			},
			"user_ocid": {
				Type:        framework.TypeString,
				Description: "OCI user OCID",
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

// Role management
type roleEntry struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	DefaultTTL  time.Duration `json:"default_ttl"`
	MaxTTL      time.Duration `json:"max_ttl"`
}

func (b *backend) getRole(ctx context.Context, s logical.Storage, name string) (*roleEntry, error) {
	entry, err := s.Get(ctx, "role/"+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var role roleEntry
	if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}

	return &role, nil
}

func (b *backend) saveRole(ctx context.Context, s logical.Storage, role *roleEntry) error {
	entry, err := logical.StorageEntryJSON("role/"+role.Name, role)
	if err != nil {
		return err
	}

	return s.Put(ctx, entry)
}

func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	role, err := b.getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"name":         role.Name,
			"description":  role.Description,
			"default_ttl":  role.DefaultTTL.Seconds(),
			"max_ttl":      role.MaxTTL.Seconds(),
		},
	}, nil
}

func (b *backend) pathRoleWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	role := &roleEntry{
		Name:        name,
		Description: data.Get("description").(string),
		DefaultTTL:  time.Duration(data.Get("default_ttl").(int)) * time.Second,
		MaxTTL:      time.Duration(data.Get("max_ttl").(int)) * time.Second,
	}

	if role.DefaultTTL == 0 {
		role.DefaultTTL = 3600 * time.Second
	}
	if role.MaxTTL == 0 {
		role.MaxTTL = 86400 * time.Second
	}

	if err := b.saveRole(ctx, req.Storage, role); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	if err := req.Storage.Delete(ctx, "role/"+name); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	name := data.Get("name").(string)

	role, err := b.getRole(ctx, req.Storage, name)
	if err != nil {
		return false, err
	}
	return role != nil, nil
}

const pathCredsHelpSyn = `
Generate an OCI session token for a specific role.
`

const pathCredsHelpDesc = `
This endpoint generates a new OCI session token for the specified role.
The token will be valid for the configured TTL (default: 1 hour, max: 24 hours).

Example:
  $ vault read oci/creds/my-role

The response includes:
  - session_token: The OCI session token for CLI/SDK authentication
  - access_token: The OAuth access token
  - region: The configured OCI region
  - tenancy_ocid: The tenancy OCID
  - user_ocid: The user OCID
`

const pathRoleHelpSyn = `
Manage OCI credential roles.
`

const pathRoleHelpDesc = `
Roles allow you to define different token configurations with varying TTLs.

Example:
  $ vault write oci/roles/my-role \\
      description="Production access" \\
      default_ttl=3600 \\
      max_ttl=14400
`
