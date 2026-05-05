package ocibackend

import (
	"encoding/json"
	"fmt"
	"strings"
)

const (
	roleMappingOpEquals   = "eq"
	roleMappingOpContains = "co"
	roleMappingOpStarts   = "sw"
)

func decodeSubjectTokenRoleMappings(raw string) ([]subjectTokenRoleMapping, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	var mappings []subjectTokenRoleMapping
	if err := json.Unmarshal([]byte(raw), &mappings); err != nil {
		return nil, fmt.Errorf("must be a JSON array: %w", err)
	}
	for i, mapping := range mappings {
		if strings.TrimSpace(mapping.Claim) == "" {
			return nil, fmt.Errorf("rule %d missing claim", i)
		}
		if strings.TrimSpace(mapping.Value) == "" {
			return nil, fmt.Errorf("rule %d missing value", i)
		}
		if strings.TrimSpace(mapping.Role) == "" {
			return nil, fmt.Errorf("rule %d missing role", i)
		}
		switch mapping.Op {
		case roleMappingOpEquals, roleMappingOpContains, roleMappingOpStarts:
		default:
			return nil, fmt.Errorf("rule %d has unsupported op %q; supported ops are %q, %q, and %q", i, mapping.Op, roleMappingOpEquals, roleMappingOpContains, roleMappingOpStarts)
		}
	}
	return mappings, nil
}

func resolveRoleFromSubjectToken(token string, mappings []subjectTokenRoleMapping) (string, error) {
	if len(mappings) == 0 {
		return "", fmt.Errorf("no subject_token_role_mappings are configured")
	}

	claims, err := decodeJWTClaimsMap(token)
	if err != nil {
		return "", fmt.Errorf("unable to decode JWT claims: %w", err)
	}

	for _, mapping := range mappings {
		raw, ok := claims[mapping.Claim]
		if !ok {
			continue
		}

		matched, matchErr := subjectTokenRoleMappingMatches(raw, mapping)
		if matchErr != nil {
			return "", fmt.Errorf("claim %q: %w", mapping.Claim, matchErr)
		}
		if matched {
			return mapping.Role, nil
		}
	}

	return "", fmt.Errorf("no subject_token_role_mappings matched")
}

func subjectTokenRoleMappingMatches(raw interface{}, mapping subjectTokenRoleMapping) (bool, error) {
	if value, ok := raw.(string); ok {
		if value == "" {
			return false, fmt.Errorf("claim value is empty")
		}
		return matchRoleMappingValue(value, mapping), nil
	}

	values, ok := raw.([]interface{})
	if !ok {
		return false, fmt.Errorf("claim must be a string or array of strings")
	}
	if len(values) == 0 {
		return false, fmt.Errorf("claim array is empty")
	}

	for _, item := range values {
		value, itemIsString := item.(string)
		if !itemIsString || value == "" {
			return false, fmt.Errorf("claim array must contain only non-empty strings")
		}
		if matchRoleMappingValue(value, mapping) {
			return true, nil
		}
	}

	return false, nil
}

func matchRoleMappingValue(value string, mapping subjectTokenRoleMapping) bool {
	switch mapping.Op {
	case roleMappingOpEquals:
		return value == mapping.Value
	case roleMappingOpContains:
		return strings.Contains(value, mapping.Value)
	case roleMappingOpStarts:
		return strings.HasPrefix(value, mapping.Value)
	default:
		return false
	}
}
