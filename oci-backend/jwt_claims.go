package ocibackend

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

func jwtClaimContainsRole(token, claimKey, role string) (bool, string, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return false, "", fmt.Errorf("invalid JWT format")
	}

	payloadBytes, err := decodeBase64URL(parts[1])
	if err != nil {
		return false, "", fmt.Errorf("invalid JWT payload encoding: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return false, "", fmt.Errorf("invalid JWT payload JSON: %w", err)
	}

	raw, ok := claims[claimKey]
	if !ok {
		return false, "", fmt.Errorf("missing claim '%s'", claimKey)
	}

	if value, ok := raw.(string); ok {
		if value == "" {
			return false, "", fmt.Errorf("claim '%s' is empty", claimKey)
		}
		return value == role, value, nil
	}

	values, ok := raw.([]interface{})
	if !ok {
		return false, "", fmt.Errorf("claim '%s' must be a string or array of strings", claimKey)
	}

	if len(values) == 0 {
		return false, "", fmt.Errorf("claim '%s' array is empty", claimKey)
	}

	stringValues := make([]string, 0, len(values))
	for _, item := range values {
		s, itemIsString := item.(string)
		if !itemIsString || s == "" {
			return false, "", fmt.Errorf("claim '%s' array must contain only non-empty strings", claimKey)
		}
		stringValues = append(stringValues, s)
	}

	return stringSliceContains(stringValues, role), strings.Join(stringValues, ","), nil
}

func stringSliceContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func decodeBase64URL(input string) ([]byte, error) {
	if out, err := base64.RawURLEncoding.DecodeString(input); err == nil {
		return out, nil
	}
	return base64.URLEncoding.DecodeString(input)
}
