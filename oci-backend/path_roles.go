package ocibackend

import (
	"context"
	"path"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathRoles returns the role management paths
func (b *backend) pathRoles() []*framework.Path {
	return []*framework.Path{
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
					Default:     86400,
				},
				"allowed_subjects": {
					Type:        framework.TypeCommaStringSlice,
					Description: "List of allowed subject claims (wildcards supported)",
					Required:    false,
				},
				"allowed_groups": {
					Type:        framework.TypeCommaStringSlice,
					Description: "List of allowed groups from the subject token",
					Required:    false,
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathRoleRead,
					Summary:  "Read a role",
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathRoleWrite,
					Summary:  "Create a role",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRoleWrite,
					Summary:  "Update a role",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathRoleDelete,
					Summary:  "Delete a role",
				},
			},

			ExistenceCheck: b.pathRoleExistenceCheck,

			HelpSynopsis:    pathRoleHelpSyn,
			HelpDescription: pathRoleHelpDesc,
		},
		{
			Pattern: path.Join("roles"),
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathRoleList,
			},
			HelpSynopsis:    pathRoleListHelpSyn,
			HelpDescription: pathRoleListHelpDesc,
		},
	}
}

// Role management
type roleEntry struct {
	Name            string        `json:"name"`
	Description     string        `json:"description"`
	DefaultTTL      time.Duration `json:"default_ttl"`
	MaxTTL          time.Duration `json:"max_ttl"`
	AllowedSubjects []string      `json:"allowed_subjects,omitempty"`
	AllowedGroups   []string      `json:"allowed_groups,omitempty"`
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
			"name":             role.Name,
			"description":      role.Description,
			"default_ttl":      int(role.DefaultTTL.Seconds()),
			"max_ttl":          int(role.MaxTTL.Seconds()),
			"allowed_subjects": role.AllowedSubjects,
			"allowed_groups":   role.AllowedGroups,
		},
	}, nil
}

func (b *backend) pathRoleWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	role := &roleEntry{
		Name:            name,
		Description:     data.Get("description").(string),
		DefaultTTL:      time.Duration(data.Get("default_ttl").(int)) * time.Second,
		MaxTTL:          time.Duration(data.Get("max_ttl").(int)) * time.Second,
		AllowedSubjects: data.Get("allowed_subjects").([]string),
		AllowedGroups:   data.Get("allowed_groups").([]string),
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

func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

const pathRoleHelpSyn = `
Manage OCI credential roles.
`

const pathRoleHelpDesc = `
Roles define constraints and TTLs for OCI session tokens generated via token exchange.

Example:
  $ vault write oci/roles/developer \\
      description="Development environment access" \\
      default_ttl=3600 \\
      max_ttl=14400 \\
      allowed_groups="dev-team" \\
      allowed_subjects="user1@example.com,user2@example.com"
`

const pathRoleListHelpSyn = `
List configured OCI credential roles.
`

const pathRoleListHelpDesc = `
Lists the names of all configured roles in the OCI secrets engine.
`
