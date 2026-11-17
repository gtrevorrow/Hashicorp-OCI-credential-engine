package ocibackend

import (
	"fmt"
	"strings"
	"unicode"
)

const (
	maxClaimTemplateBytes = 16 * 1024
	maxRenderedClaimBytes = 64 * 1024
)

type claimTemplatePart struct {
	literal    string
	expression string
}

// Parse the entire template before looking up data. Missing runtime values must
// never hide malformed trailing expressions during configuration writes.
func parseClaimTemplate(template string, validateExpression func(string) error) ([]claimTemplatePart, error) {
	if len(template) > maxClaimTemplateBytes {
		return nil, fmt.Errorf("template exceeds %d bytes", maxClaimTemplateBytes)
	}
	var parts []claimTemplatePart
	for {
		start := strings.Index(template, "{{")
		end := strings.Index(template, "}}")
		if end >= 0 && (start < 0 || end < start) {
			return nil, fmt.Errorf("invalid template syntax")
		}
		if start < 0 {
			return append(parts, claimTemplatePart{literal: template}), nil
		}
		parts = append(parts, claimTemplatePart{literal: template[:start]})
		template = template[start+2:]
		end = strings.Index(template, "}}")
		if end < 0 {
			return nil, fmt.Errorf("invalid template syntax")
		}
		expression := strings.TrimSpace(template[:end])
		if strings.Contains(expression, "{{") {
			return nil, fmt.Errorf("invalid template syntax")
		}
		if err := validateExpression(expression); err != nil {
			return nil, err
		}
		parts = append(parts, claimTemplatePart{expression: expression})
		template = template[end+2:]
	}
}

func appendClaimText(builder *strings.Builder, text string) error {
	if len(text) > maxRenderedClaimBytes-builder.Len() {
		return fmt.Errorf("rendered claim exceeds %d bytes", maxRenderedClaimBytes)
	}
	builder.WriteString(text)
	return nil
}

func renderClaimTemplate(parts []claimTemplatePart, evaluate func(string) (string, error)) (string, error) {
	var builder strings.Builder
	for _, part := range parts {
		value := part.literal
		if part.expression != "" {
			var err error
			value, err = evaluate(part.expression)
			if err != nil {
				return "", err
			}
		}
		if err := appendClaimText(&builder, value); err != nil {
			return "", err
		}
	}
	return builder.String(), nil
}

func validateClaimPath(path string, prefixes ...string) error {
	for _, prefix := range prefixes {
		if !strings.HasPrefix(path, prefix) {
			continue
		}
		for _, segment := range strings.Split(strings.TrimPrefix(path, prefix), ".") {
			if segment == "" {
				return fmt.Errorf("invalid claim path")
			}
			for _, char := range segment {
				if unicode.IsSpace(char) || unicode.IsControl(char) || strings.ContainsRune("{}[]()'\" ,\\", char) {
					return fmt.Errorf("invalid claim path")
				}
			}
		}
		return nil
	}
	return fmt.Errorf("unsupported template expression %q", path)
}

func validateSelfMintExpression(expression string) error {
	if strings.HasPrefix(expression, "join(") {
		_, _, err := parseSelfMintJoinExpression(expression)
		return err
	}
	return validateClaimPath(expression, "vault.", "brokered.claims.")
}

func validateBrokeredExpression(expression string) error {
	return validateClaimPath(expression, "claims.")
}
