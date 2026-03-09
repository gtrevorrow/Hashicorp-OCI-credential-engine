package ocibackend

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

func extractStringJWTClaim(token, claimKey string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid JWT format")
	}

	payloadBytes, err := decodeBase64URL(parts[1])
	if err != nil {
		return "", fmt.Errorf("invalid JWT payload encoding: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return "", fmt.Errorf("invalid JWT payload JSON: %w", err)
	}

	raw, ok := claims[claimKey]
	if !ok {
		return "", fmt.Errorf("missing claim '%s'", claimKey)
	}

	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("claim '%s' must be a string", claimKey)
	}

	if value == "" {
		return "", fmt.Errorf("claim '%s' is empty", claimKey)
	}

	return value, nil
}

func decodeBase64URL(input string) ([]byte, error) {
	if out, err := base64.RawURLEncoding.DecodeString(input); err == nil {
		return out, nil
	}
	return base64.URLEncoding.DecodeString(input)
}
