package ocibackend

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

func decodeBrokeredSubjectTokenClaimMappings(raw string) (map[string]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	var mappings map[string]string
	if err := json.Unmarshal([]byte(raw), &mappings); err != nil {
		return nil, fmt.Errorf("must be a JSON object: %w", err)
	}
	if len(mappings) == 0 {
		return nil, nil
	}

	for outputClaim, template := range mappings {
		if err := validateSelfMintCustomClaimName(outputClaim); err != nil {
			return nil, err
		}
		if strings.TrimSpace(template) == "" {
			return nil, fmt.Errorf("claim %q must use a non-empty string template", outputClaim)
		}
		if _, err := renderBrokeredClaimTemplate(template, map[string]interface{}{}); err != nil {
			if !isBrokeredTemplateClaimLookupError(err) {
				return nil, fmt.Errorf("claim %q: %w", outputClaim, err)
			}
		}
	}

	return mappings, nil
}

func renderBrokeredClaimMappings(validatedClaims map[string]interface{}, mappings map[string]string) (map[string]interface{}, error) {
	if len(mappings) == 0 {
		return nil, nil
	}

	out := make(map[string]interface{}, len(mappings))
	for outputClaim, template := range mappings {
		if err := validateSelfMintCustomClaimName(outputClaim); err != nil {
			return nil, err
		}
		if _, exists := out[outputClaim]; exists {
			return nil, fmt.Errorf("duplicate mapped output claim %q", outputClaim)
		}

		value, err := renderBrokeredClaimTemplate(template, validatedClaims)
		if err != nil {
			return nil, fmt.Errorf("claim %q: %w", outputClaim, err)
		}
		out[outputClaim] = value
	}

	return out, nil
}

func renderBrokeredClaimTemplate(template string, claims map[string]interface{}) (string, error) {
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
		if !strings.HasPrefix(expression, "claims.") {
			return "", fmt.Errorf("unsupported template expression %q", expression)
		}

		value, err := lookupBrokeredClaim(claims, strings.TrimPrefix(expression, "claims."))
		if err != nil {
			return "", err
		}
		stringValue, err := stringifyBrokeredClaimValue(value)
		if err != nil {
			return "", err
		}
		builder.WriteString(stringValue)
		remaining = remaining[end+2:]
	}
}

func lookupBrokeredClaim(claims map[string]interface{}, path string) (interface{}, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, brokeredTemplateClaimLookupError{msg: "missing claim path"}
	}

	var current interface{} = claims
	for _, segment := range strings.Split(path, ".") {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			return nil, brokeredTemplateClaimLookupError{msg: "invalid claim path"}
		}

		object, ok := current.(map[string]interface{})
		if !ok {
			return nil, brokeredTemplateClaimLookupError{msg: fmt.Sprintf("claim %q does not resolve to an object", path)}
		}

		next, ok := object[segment]
		if !ok {
			return nil, brokeredTemplateClaimLookupError{msg: fmt.Sprintf("claim %q not found", path)}
		}
		current = next
	}

	return current, nil
}

func stringifyBrokeredClaimValue(value interface{}) (string, error) {
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
	case json.Number:
		return typed.String(), nil
	case nil:
		return "", fmt.Errorf("claim value is null")
	default:
		return "", fmt.Errorf("claim value %T cannot be interpolated as a string", value)
	}
}

type brokeredTemplateClaimLookupError struct {
	msg string
}

func (e brokeredTemplateClaimLookupError) Error() string {
	return e.msg
}

func isBrokeredTemplateClaimLookupError(err error) bool {
	_, ok := err.(brokeredTemplateClaimLookupError)
	return ok
}
