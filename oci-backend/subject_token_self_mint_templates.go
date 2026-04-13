package ocibackend

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/vault/sdk/logical"
)

func validateSelfMintCustomClaimTemplate(template string) error {
	_, err := renderSelfMintCustomClaimTemplate(template, map[string]interface{}{}, nil)
	if err == nil || isSelfMintTemplateLookupError(err) {
		return nil
	}
	return err
}

func renderSelfMintCustomClaimMappings(templateContext map[string]interface{}, mappings map[string]string, brokeredClaims map[string]interface{}) (map[string]interface{}, error) {
	if len(mappings) == 0 {
		return nil, nil
	}

	out := make(map[string]interface{}, len(mappings))
	for claim, template := range mappings {
		if err := validateSelfMintCustomClaimName(claim); err != nil {
			return nil, err
		}
		if _, exists := out[claim]; exists {
			return nil, fmt.Errorf("duplicate self_mint_custom_claim %q", claim)
		}

		value, err := renderSelfMintCustomClaimTemplate(template, templateContext, brokeredClaims)
		if err != nil {
			return nil, fmt.Errorf("claim %q: %w", claim, err)
		}
		out[claim] = value
	}

	return out, nil
}

func renderSelfMintCustomClaimTemplate(template string, templateContext map[string]interface{}, brokeredClaims map[string]interface{}) (string, error) {
	var builder strings.Builder
	remaining := template

	for {
		start := strings.Index(remaining, "{{")
		endBeforeStart := strings.Index(remaining, "}}")
		if start == -1 {
			if endBeforeStart >= 0 {
				return "", fmt.Errorf("invalid template syntax")
			}
			builder.WriteString(remaining)
			return builder.String(), nil
		}
		if endBeforeStart >= 0 && endBeforeStart < start {
			return "", fmt.Errorf("invalid template syntax")
		}

		builder.WriteString(remaining[:start])
		remaining = remaining[start+2:]

		end := strings.Index(remaining, "}}")
		if end == -1 {
			return "", fmt.Errorf("invalid template syntax")
		}

		expression := strings.TrimSpace(remaining[:end])
		value, err := evaluateSelfMintTemplateExpression(expression, templateContext, brokeredClaims)
		if err != nil {
			return "", err
		}
		builder.WriteString(value)
		remaining = remaining[end+2:]
	}
}

func evaluateSelfMintTemplateExpression(expression string, templateContext map[string]interface{}, brokeredClaims map[string]interface{}) (string, error) {
	if expression == "" {
		return "", fmt.Errorf("invalid template syntax")
	}

	if strings.HasPrefix(expression, "join(") {
		return evaluateSelfMintJoinExpression(expression, templateContext, brokeredClaims)
	}
	if strings.HasPrefix(expression, "vault.") {
		value, err := lookupSelfMintTemplateValue(templateContext, expression)
		if err != nil {
			return "", err
		}
		return stringifySelfMintTemplateValue(value)
	}
	if strings.HasPrefix(expression, "brokered.claims.") {
		if brokeredClaims == nil {
			return "", selfMintTemplateLookupError{msg: "brokered claims are not available in this flow"}
		}
		value, err := lookupSelfMintTemplateValue(map[string]interface{}{
			"brokered": map[string]interface{}{
				"claims": brokeredClaims,
			},
		}, expression)
		if err != nil {
			return "", err
		}
		return stringifySelfMintTemplateValue(value)
	}

	return "", fmt.Errorf("unsupported template expression %q", expression)
}

func evaluateSelfMintJoinExpression(expression string, templateContext map[string]interface{}, brokeredClaims map[string]interface{}) (string, error) {
	if !strings.HasPrefix(expression, "join(") || !strings.HasSuffix(expression, ")") {
		return "", fmt.Errorf("invalid template syntax")
	}

	inner := strings.TrimSpace(expression[len("join(") : len(expression)-1])
	args, err := splitSelfMintJoinArgs(inner)
	if err != nil {
		return "", err
	}
	if len(args) != 2 {
		return "", fmt.Errorf("join() requires exactly two arguments")
	}

	path := strings.TrimSpace(args[0])
	separator, err := parseQuotedSelfMintTemplateString(strings.TrimSpace(args[1]))
	if err != nil {
		return "", err
	}

	var value interface{}
	switch {
	case strings.HasPrefix(path, "vault."):
		value, err = lookupSelfMintTemplateValue(templateContext, path)
	case strings.HasPrefix(path, "brokered.claims."):
		if brokeredClaims == nil {
			return "", selfMintTemplateLookupError{msg: "brokered claims are not available in this flow"}
		}
		value, err = lookupSelfMintTemplateValue(map[string]interface{}{
			"brokered": map[string]interface{}{
				"claims": brokeredClaims,
			},
		}, path)
	default:
		return "", fmt.Errorf("join() requires a vault.* or brokered.claims.* path argument")
	}
	if err != nil {
		return "", err
	}

	items, ok := value.([]interface{})
	if !ok {
		return "", fmt.Errorf("join() requires a list value")
	}
	rendered := make([]string, 0, len(items))
	for _, item := range items {
		stringValue, err := stringifySelfMintTemplateValue(item)
		if err != nil {
			return "", err
		}
		rendered = append(rendered, stringValue)
	}
	return strings.Join(rendered, separator), nil
}

func splitSelfMintJoinArgs(raw string) ([]string, error) {
	if raw == "" {
		return nil, fmt.Errorf("join() requires arguments")
	}

	var args []string
	var current strings.Builder
	inQuote := byte(0)
	for i := 0; i < len(raw); i++ {
		ch := raw[i]
		switch ch {
		case '\'', '"':
			if inQuote == 0 {
				inQuote = ch
			} else if inQuote == ch {
				inQuote = 0
			}
			current.WriteByte(ch)
		case ',':
			if inQuote == 0 {
				args = append(args, strings.TrimSpace(current.String()))
				current.Reset()
				continue
			}
			current.WriteByte(ch)
		default:
			current.WriteByte(ch)
		}
	}
	if inQuote != 0 {
		return nil, fmt.Errorf("invalid template syntax")
	}
	args = append(args, strings.TrimSpace(current.String()))
	return args, nil
}

func parseQuotedSelfMintTemplateString(raw string) (string, error) {
	if len(raw) < 2 {
		return "", fmt.Errorf("join() separator must be a quoted string")
	}
	if (raw[0] != '"' || raw[len(raw)-1] != '"') && (raw[0] != '\'' || raw[len(raw)-1] != '\'') {
		return "", fmt.Errorf("join() separator must be a quoted string")
	}
	if raw[0] == '"' {
		value, err := strconv.Unquote(raw)
		if err != nil {
			return "", fmt.Errorf("invalid quoted separator: %w", err)
		}
		return value, nil
	}
	return raw[1 : len(raw)-1], nil
}

func lookupSelfMintTemplateValue(templateContext map[string]interface{}, path string) (interface{}, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, selfMintTemplateLookupError{msg: "missing claim path"}
	}

	var current interface{} = templateContext
	for _, segment := range strings.Split(path, ".") {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			return nil, selfMintTemplateLookupError{msg: "invalid claim path"}
		}
		object, ok := current.(map[string]interface{})
		if !ok {
			return nil, selfMintTemplateLookupError{msg: fmt.Sprintf("claim %q does not resolve to an object", path)}
		}
		next, ok := object[segment]
		if !ok {
			return nil, selfMintTemplateLookupError{msg: fmt.Sprintf("claim %q not found", path)}
		}
		current = next
	}

	return current, nil
}

func stringifySelfMintTemplateValue(value interface{}) (string, error) {
	switch typed := value.(type) {
	case string:
		return typed, nil
	case bool:
		return strconv.FormatBool(typed), nil
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64), nil
	case float32:
		return strconv.FormatFloat(float64(typed), 'f', -1, 32), nil
	case int:
		return strconv.Itoa(typed), nil
	case int8:
		return strconv.FormatInt(int64(typed), 10), nil
	case int16:
		return strconv.FormatInt(int64(typed), 10), nil
	case int32:
		return strconv.FormatInt(int64(typed), 10), nil
	case int64:
		return strconv.FormatInt(typed, 10), nil
	case uint:
		return strconv.FormatUint(uint64(typed), 10), nil
	case uint8:
		return strconv.FormatUint(uint64(typed), 10), nil
	case uint16:
		return strconv.FormatUint(uint64(typed), 10), nil
	case uint32:
		return strconv.FormatUint(uint64(typed), 10), nil
	case uint64:
		return strconv.FormatUint(typed, 10), nil
	case nil:
		return "", fmt.Errorf("claim value is null")
	default:
		return "", fmt.Errorf("claim value %T cannot be interpolated as a string", value)
	}
}

func buildSelfMintTemplateContext(req *logical.Request, claims map[string]interface{}) map[string]interface{} {
	vaultContext := map[string]interface{}{
		"entity":  map[string]interface{}{},
		"alias":   map[string]interface{}{},
		"request": map[string]interface{}{},
		"groups":  []interface{}{},
	}

	if req != nil {
		if req.DisplayName != "" {
			vaultContext["request"].(map[string]interface{})["display_name"] = req.DisplayName
		}
		if req.MountAccessor != "" {
			vaultContext["request"].(map[string]interface{})["mount_accessor"] = req.MountAccessor
		}
		if req.MountType != "" {
			vaultContext["request"].(map[string]interface{})["mount_type"] = req.MountType
		}
		if req.ClientTokenAccessor != "" {
			vaultContext["request"].(map[string]interface{})["client_token_accessor"] = req.ClientTokenAccessor
		}
	}

	if value, ok := claims["vault_entity_id"]; ok {
		vaultContext["entity"].(map[string]interface{})["id"] = value
	}
	if value, ok := claims["vault_entity_name"]; ok {
		vaultContext["entity"].(map[string]interface{})["name"] = value
	}
	if value, ok := claims["vault_namespace_id"]; ok {
		vaultContext["entity"].(map[string]interface{})["namespace_id"] = value
	}
	if value, ok := claims["vault_entity_metadata"]; ok {
		vaultContext["entity"].(map[string]interface{})["metadata"] = normalizeSelfMintTemplateValue(value)
	}
	if value, ok := claims["vault_alias_name"]; ok {
		vaultContext["alias"].(map[string]interface{})["name"] = value
	}
	if value, ok := claims["vault_alias_mount_accessor"]; ok {
		vaultContext["alias"].(map[string]interface{})["mount_accessor"] = value
	}
	if value, ok := claims["vault_alias_mount_type"]; ok {
		vaultContext["alias"].(map[string]interface{})["mount_type"] = value
	}
	if value, ok := claims["vault_alias_metadata"]; ok {
		vaultContext["alias"].(map[string]interface{})["metadata"] = normalizeSelfMintTemplateValue(value)
	}
	if value, ok := claims["vault_alias_custom_metadata"]; ok {
		vaultContext["alias"].(map[string]interface{})["custom_metadata"] = normalizeSelfMintTemplateValue(value)
	}
	if value, ok := claims["vault_group_names"]; ok {
		if groups, ok := value.([]string); ok {
			list := make([]interface{}, 0, len(groups))
			for _, group := range groups {
				list = append(list, group)
			}
			vaultContext["groups"] = list
		} else if groups, ok := value.([]interface{}); ok {
			vaultContext["groups"] = groups
		}
	}

	return map[string]interface{}{
		"vault": vaultContext,
	}
}

func normalizeSelfMintTemplateValue(value interface{}) interface{} {
	switch typed := value.(type) {
	case map[string]string:
		out := make(map[string]interface{}, len(typed))
		for key, nested := range typed {
			out[key] = nested
		}
		return out
	case map[string]interface{}:
		out := make(map[string]interface{}, len(typed))
		for key, nested := range typed {
			out[key] = normalizeSelfMintTemplateValue(nested)
		}
		return out
	case []string:
		out := make([]interface{}, 0, len(typed))
		for _, item := range typed {
			out = append(out, item)
		}
		return out
	case []interface{}:
		out := make([]interface{}, 0, len(typed))
		for _, item := range typed {
			out = append(out, normalizeSelfMintTemplateValue(item))
		}
		return out
	default:
		return value
	}
}

type selfMintTemplateLookupError struct {
	msg string
}

func (e selfMintTemplateLookupError) Error() string {
	return e.msg
}

func isSelfMintTemplateLookupError(err error) bool {
	_, ok := err.(selfMintTemplateLookupError)
	return ok
}
