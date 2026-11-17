package ocibackend

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathRoles returns the role management paths
func (b *backend) pathRoles() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: path.Join("role", framework.MatchAllRegex("name")),
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
				"self_mint_custom_claims": {
					Type:        framework.TypeString,
					Description: "JSON object of additional claims to add only to self-minted subject tokens for this role",
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
			Pattern: "role/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathRoleList,
					Summary:  "List all roles",
				},
			},
			ExistenceCheck: func(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
				return false, nil // Allow list
			},
			HelpSynopsis:    pathRoleListHelpSyn,
			HelpDescription: pathRoleListHelpDesc,
		},
	}
}

// Role management
type roleEntry struct {
	Name                 string            `json:"name"`
	Description          string            `json:"description"`
	DefaultTTL           time.Duration     `json:"default_ttl"`
	MaxTTL               time.Duration     `json:"max_ttl"`
	SelfMintCustomClaims map[string]string `json:"self_mint_custom_claims,omitempty"`
}

// readStoredRole keeps obsolete fields out of the active role model while
// detecting configurations that require explicit operator cleanup.
func (b *backend) readStoredRole(ctx context.Context, storage logical.Storage, name string) (*roleEntry, []string, error) {
	entry, err := storage.Get(ctx, "role/"+name)
	if err != nil || entry == nil {
		return nil, nil, err
	}
	var raw map[string]json.RawMessage
	if err := entry.DecodeJSON(&raw); err != nil {
		return nil, nil, err
	}
	var obsolete []string
	for _, field := range []string{"allowed_subjects", "allowed_groups"} {
		value, ok := raw[field]
		if !ok || strings.TrimSpace(string(value)) == "null" {
			continue
		}
		var values []json.RawMessage
		if err := json.Unmarshal(value, &values); err == nil && len(values) == 0 {
			continue
		}
		obsolete = append(obsolete, field)
	}
	var role roleEntry
	if err := entry.DecodeJSON(&role); err != nil {
		return nil, nil, err
	}
	return &role, obsolete, nil
}

func obsoleteRoleFilterError(fields []string) error {
	return fmt.Errorf("role contains removed, never-enforced fields %s; review the role and its Vault/OCI policies, then explicitly delete and recreate the role without these fields", strings.Join(fields, ", "))
}

func (b *backend) getRole(ctx context.Context, storage logical.Storage, name string) (*roleEntry, error) {
	role, obsolete, err := b.readStoredRole(ctx, storage, name)
	if err != nil {
		return nil, err
	}
	if len(obsolete) > 0 {
		return nil, obsoleteRoleFilterError(obsolete)
	}
	return role, nil
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

	role, obsolete, err := b.readStoredRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"name":                    role.Name,
			"description":             role.Description,
			"default_ttl":             int(role.DefaultTTL.Seconds()),
			"max_ttl":                 int(role.MaxTTL.Seconds()),
			"self_mint_custom_claims": role.SelfMintCustomClaims,
		},
	}
	if len(obsolete) > 0 {
		resp.AddWarning(obsoleteRoleFilterError(obsolete).Error())
	}
	return resp, nil
}

func (b *backend) pathRoleWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := data.ValidateStrict(); err != nil {
		return logical.ErrorResponse("invalid role request: %v", err), nil
	}

	if err := validateTokenTTLInputs(data, false, "default_ttl", "max_ttl"); err != nil {
		return logical.ErrorResponse("invalid token TTL policy: %v", err), nil
	}

	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	_, obsolete, readErr := b.readStoredRole(ctx, req.Storage, name)
	if readErr != nil {
		return nil, readErr
	}
	if len(obsolete) > 0 {
		return logical.ErrorResponse("%v", obsoleteRoleFilterError(obsolete)), nil
	}

	config, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config != nil && config.StrictRoleNameMatch && !isStrictRoleNameValid(name) {
		return logical.ErrorResponse("invalid role name '%s': strict_role_name_match requires pattern [A-Za-z0-9._:-]+", name), nil
	}

	selfMintCustomClaims, err := decodeRoleSelfMintCustomClaims(data.Get("self_mint_custom_claims").(string))
	if err != nil {
		return logical.ErrorResponse("invalid self_mint_custom_claims: %v", err), nil
	}

	defaultTTL, ttlErr := tokenTTLDuration(data.Get("default_ttl").(int), "default_ttl")
	if ttlErr != nil {
		return logical.ErrorResponse("invalid role TTL policy: %v", ttlErr), nil
	}
	maxTTL, ttlErr := tokenTTLDuration(data.Get("max_ttl").(int), "max_ttl")
	if ttlErr == nil {
		ttlErr = validateTokenTTLPair(defaultTTL, maxTTL)
	}
	if ttlErr != nil {
		return logical.ErrorResponse("invalid role TTL policy: %v", ttlErr), nil
	}

	role := &roleEntry{
		Name:                 name,
		Description:          data.Get("description").(string),
		DefaultTTL:           defaultTTL,
		MaxTTL:               maxTTL,
		SelfMintCustomClaims: selfMintCustomClaims,
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

	entry, err := req.Storage.Get(ctx, "role/"+name)
	return entry != nil, err
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
  $ vault write oci/role/developer \\
      description="Development environment access" \\
      default_ttl=3600 \\
      max_ttl=14400
`

const pathRoleListHelpSyn = `
List configured OCI credential roles.
`

const pathRoleListHelpDesc = `
Lists the names of all configured roles in the OCI secrets engine.
`

func decodeRoleSelfMintCustomClaims(raw string) (map[string]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	var rawClaims map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &rawClaims); err != nil {
		return nil, fmt.Errorf("must be a JSON object: %w", err)
	}
	if len(rawClaims) == 0 {
		return nil, nil
	}

	claims := make(map[string]string, len(rawClaims))
	for claim, value := range rawClaims {
		if err := validateSelfMintCustomClaimName(claim); err != nil {
			return nil, err
		}
		template, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("claim %q must use a string template", claim)
		}
		if strings.TrimSpace(template) == "" {
			return nil, fmt.Errorf("claim %q must use a non-empty string template", claim)
		}
		if err := validateSelfMintCustomClaimTemplate(template); err != nil {
			return nil, fmt.Errorf("claim %q: %w", claim, err)
		}
		claims[claim] = template
	}

	return claims, nil
}

func validateSelfMintCustomClaimName(claim string) error {
	claim = strings.TrimSpace(claim)
	if claim == "" {
		return fmt.Errorf("claim names must be non-empty")
	}
	if isReservedSelfMintClaim(claim) {
		return fmt.Errorf("claim %q is reserved and cannot be overridden", claim)
	}
	if strings.HasPrefix(claim, "vault_") {
		return fmt.Errorf("claim %q uses the reserved vault_ namespace", claim)
	}
	return nil
}

func isReservedSelfMintClaim(claim string) bool {
	switch claim {
	case "iss", "sub", "aud", "iat", "exp", "nbf", "jti":
		return true
	default:
		return false
	}
}
