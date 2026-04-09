package ocibackend

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	brokeredTrustTypeOIDCDiscovery = "oidc_discovery"
	brokeredTrustTypeJWKSURL       = "jwks_url"
	brokeredTrustTypeJWKSJSON      = "jwks_json"
	brokeredTrustTypePublicKeys    = "public_keys"
)

var brokeredSupportedAlgs = map[string]jose.SignatureAlgorithm{
	string(jose.RS256): jose.RS256,
	string(jose.RS384): jose.RS384,
	string(jose.RS512): jose.RS512,
	string(jose.ES256): jose.ES256,
	string(jose.ES384): jose.ES384,
	string(jose.ES512): jose.ES512,
}

func validateBrokeredSubjectTokenConfig(config *federatedConfig) error {
	if config == nil || !config.BrokeredSubjectTokenEnabled {
		return nil
	}

	config.BrokeredSubjectTokenTrustType = strings.TrimSpace(config.BrokeredSubjectTokenTrustType)
	config.BrokeredSubjectTokenIssuer = strings.TrimSpace(config.BrokeredSubjectTokenIssuer)
	config.BrokeredSubjectTokenAllowedAudiences = configBrokeredSubjectTokenAllowedAudiences(config)
	config.BrokeredSubjectTokenAllowedAlgs = configBrokeredSubjectTokenAllowedAlgs(config)

	if config.BrokeredSubjectTokenTrustType == "" {
		return fmt.Errorf("brokered_subject_token_trust_type is required when brokered_subject_token_enabled=true")
	}
	if config.BrokeredSubjectTokenIssuer == "" {
		return fmt.Errorf("brokered_subject_token_issuer is required when brokered_subject_token_enabled=true")
	}
	if len(config.BrokeredSubjectTokenAllowedAudiences) == 0 {
		return fmt.Errorf("brokered_subject_token_allowed_audiences must be non-empty when brokered_subject_token_enabled=true")
	}
	if len(config.BrokeredSubjectTokenAllowedAlgs) == 0 {
		return fmt.Errorf("brokered_subject_token_allowed_algs must be non-empty when brokered_subject_token_enabled=true")
	}
	if config.BrokeredSubjectTokenClockSkewSeconds < 0 {
		return fmt.Errorf("brokered_subject_token_clock_skew_seconds must be >= 0")
	}
	for _, alg := range config.BrokeredSubjectTokenAllowedAlgs {
		if _, ok := brokeredSupportedAlgs[alg]; !ok {
			return fmt.Errorf("unsupported brokered_subject_token_allowed_alg %q; phase 1 supports RSA and EC algorithms only", alg)
		}
	}

	switch config.BrokeredSubjectTokenTrustType {
	case brokeredTrustTypeOIDCDiscovery:
		if err := validateBrokeredTrustSources(config, false, false, false); err != nil {
			return err
		}
	case brokeredTrustTypeJWKSURL:
		if err := validateBrokeredTrustSources(config, true, false, false); err != nil {
			return err
		}
		if !strings.HasPrefix(strings.TrimSpace(config.BrokeredSubjectTokenJWKSURL), "https://") && !strings.HasPrefix(strings.TrimSpace(config.BrokeredSubjectTokenJWKSURL), "http://") {
			return fmt.Errorf("brokered_subject_token_jwks_url must start with https:// or http://")
		}
	case brokeredTrustTypeJWKSJSON:
		if err := validateBrokeredTrustSources(config, false, true, false); err != nil {
			return err
		}
		if _, err := parseBrokeredJWKS(config.BrokeredSubjectTokenJWKSJSON); err != nil {
			return fmt.Errorf("invalid brokered_subject_token_jwks_json: %w", err)
		}
	case brokeredTrustTypePublicKeys:
		if err := validateBrokeredTrustSources(config, false, false, true); err != nil {
			return err
		}
		if _, err := resolveBrokeredInlinePublicKeys(config.BrokeredSubjectTokenPublicKeys); err != nil {
			return fmt.Errorf("invalid brokered_subject_token_public_keys: %w", err)
		}
	default:
		return fmt.Errorf("invalid brokered_subject_token_trust_type %q", config.BrokeredSubjectTokenTrustType)
	}

	return nil
}

func validateBrokeredTrustSources(config *federatedConfig, requireJWKSURL, requireJWKSJSON, requirePublicKeys bool) error {
	hasJWKSURL := strings.TrimSpace(config.BrokeredSubjectTokenJWKSURL) != ""
	hasJWKSJSON := strings.TrimSpace(config.BrokeredSubjectTokenJWKSJSON) != ""
	hasPublicKeys := len(config.BrokeredSubjectTokenPublicKeys) > 0

	if requireJWKSURL && !hasJWKSURL {
		return fmt.Errorf("brokered_subject_token_jwks_url is required when brokered_subject_token_trust_type=%s", brokeredTrustTypeJWKSURL)
	}
	if requireJWKSJSON && !hasJWKSJSON {
		return fmt.Errorf("brokered_subject_token_jwks_json is required when brokered_subject_token_trust_type=%s", brokeredTrustTypeJWKSJSON)
	}
	if requirePublicKeys && !hasPublicKeys {
		return fmt.Errorf("brokered_subject_token_public_keys is required when brokered_subject_token_trust_type=%s", brokeredTrustTypePublicKeys)
	}

	sourceCount := 0
	if hasJWKSURL {
		sourceCount++
	}
	if hasJWKSJSON {
		sourceCount++
	}
	if hasPublicKeys {
		sourceCount++
	}
	if !requireJWKSURL && !requireJWKSJSON && !requirePublicKeys {
		// oidc_discovery uses the issuer itself as the single trust source.
		sourceCount++
	}
	if sourceCount != 1 {
		return fmt.Errorf("brokered_subject_token config must define exactly one trust source")
	}

	return nil
}

func decodeBrokeredSubjectTokenPublicKeys(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	if strings.HasPrefix(raw, "[") {
		var keys []string
		if err := json.Unmarshal([]byte(raw), &keys); err != nil {
			return nil, fmt.Errorf("must be a PEM string or JSON array of PEM strings: %w", err)
		}
		return trimBrokeredPublicKeys(keys), nil
	}

	return trimBrokeredPublicKeys([]string{raw}), nil
}

func trimBrokeredPublicKeys(keys []string) []string {
	if len(keys) == 0 {
		return nil
	}

	out := make([]string, 0, len(keys))
	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		out = append(out, key)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (b *backend) validateBrokeredSubjectToken(ctx context.Context, token string, config *federatedConfig) (map[string]interface{}, error) {
	allowedAlgs := make([]jose.SignatureAlgorithm, 0, len(config.BrokeredSubjectTokenAllowedAlgs))
	for _, alg := range config.BrokeredSubjectTokenAllowedAlgs {
		allowedAlgs = append(allowedAlgs, brokeredSupportedAlgs[alg])
	}

	jws, err := jose.ParseSigned(token, allowedAlgs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signed JWT: %w", err)
	}
	if len(jws.Signatures) != 1 {
		return nil, fmt.Errorf("expected exactly one JWT signature")
	}

	headerAlg := jws.Signatures[0].Header.Algorithm
	if _, ok := brokeredSupportedAlgs[headerAlg]; !ok {
		return nil, fmt.Errorf("unsupported JWT alg %q", headerAlg)
	}

	keys, err := b.resolveBrokeredVerificationKeys(ctx, config)
	if err != nil {
		return nil, err
	}

	var payload []byte
	for _, key := range keys {
		if !isBrokeredKeyCompatibleWithAlg(key, headerAlg) {
			continue
		}
		payload, err = jws.Verify(key.Key)
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("failed to verify JWT signature: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to decode JWT claims: %w", err)
	}

	if err := validateBrokeredTokenClaims(claims, config); err != nil {
		return nil, err
	}

	return claims, nil
}

func isBrokeredKeyCompatibleWithAlg(key jose.JSONWebKey, alg string) bool {
	switch key.Key.(type) {
	case *rsa.PublicKey, rsa.PublicKey:
		return strings.HasPrefix(alg, "RS")
	case *ecdsa.PublicKey, ecdsa.PublicKey:
		return strings.HasPrefix(alg, "ES")
	default:
		return false
	}
}

func validateBrokeredTokenClaims(claims map[string]interface{}, config *federatedConfig) error {
	issuer, ok := claims["iss"].(string)
	if !ok || strings.TrimSpace(issuer) == "" {
		return fmt.Errorf("JWT iss claim is missing or invalid")
	}
	if issuer != config.BrokeredSubjectTokenIssuer {
		return fmt.Errorf("JWT iss claim %q does not match configured brokered issuer", issuer)
	}

	if err := validateBrokeredAudienceClaim(claims["aud"], config.BrokeredSubjectTokenAllowedAudiences); err != nil {
		return err
	}

	now := time.Now().UTC()
	skew := time.Duration(configBrokeredSubjectTokenClockSkewSeconds(config)) * time.Second

	exp, err := brokeredNumericDateClaim(claims, "exp", true)
	if err != nil {
		return err
	}
	if now.After(exp.Add(skew)) {
		return fmt.Errorf("JWT exp claim is expired")
	}

	nbf, err := brokeredNumericDateClaim(claims, "nbf", false)
	if err != nil {
		return err
	}
	if !nbf.IsZero() && now.Add(skew).Before(nbf) {
		return fmt.Errorf("JWT nbf claim is not yet valid")
	}

	iat, err := brokeredNumericDateClaim(claims, "iat", false)
	if err != nil {
		return err
	}
	if !iat.IsZero() && now.Add(skew).Before(iat) {
		return fmt.Errorf("JWT iat claim is in the future")
	}

	return nil
}

func validateBrokeredAudienceClaim(raw interface{}, allowedAudiences []string) error {
	if len(allowedAudiences) == 0 {
		return fmt.Errorf("brokered audience allowlist is empty")
	}

	allowed := make(map[string]struct{}, len(allowedAudiences))
	for _, audience := range allowedAudiences {
		allowed[audience] = struct{}{}
	}

	switch typed := raw.(type) {
	case string:
		if _, ok := allowed[typed]; ok {
			return nil
		}
	case []interface{}:
		for _, item := range typed {
			audience, ok := item.(string)
			if ok {
				if _, exists := allowed[audience]; exists {
					return nil
				}
			}
		}
	default:
		return fmt.Errorf("JWT aud claim is missing or invalid")
	}

	return fmt.Errorf("JWT aud claim does not match configured brokered audiences")
}

func brokeredNumericDateClaim(claims map[string]interface{}, name string, required bool) (time.Time, error) {
	raw, ok := claims[name]
	if !ok {
		if required {
			return time.Time{}, fmt.Errorf("JWT %s claim is required", name)
		}
		return time.Time{}, nil
	}

	switch typed := raw.(type) {
	case float64:
		return time.Unix(int64(typed), 0).UTC(), nil
	case json.Number:
		seconds, err := typed.Int64()
		if err != nil {
			return time.Time{}, fmt.Errorf("JWT %s claim is invalid", name)
		}
		return time.Unix(seconds, 0).UTC(), nil
	default:
		return time.Time{}, fmt.Errorf("JWT %s claim is invalid", name)
	}
}

func (b *backend) resolveBrokeredVerificationKeys(ctx context.Context, config *federatedConfig) ([]jose.JSONWebKey, error) {
	switch config.BrokeredSubjectTokenTrustType {
	case brokeredTrustTypeOIDCDiscovery:
		return b.resolveBrokeredOIDCDiscoveryKeys(ctx, config)
	case brokeredTrustTypeJWKSURL:
		return b.resolveBrokeredJWKSURLKeys(ctx, config.BrokeredSubjectTokenJWKSURL)
	case brokeredTrustTypeJWKSJSON:
		keySet, err := parseBrokeredJWKS(config.BrokeredSubjectTokenJWKSJSON)
		if err != nil {
			return nil, err
		}
		return keySet.Keys, nil
	case brokeredTrustTypePublicKeys:
		return resolveBrokeredInlinePublicKeys(config.BrokeredSubjectTokenPublicKeys)
	default:
		return nil, fmt.Errorf("invalid brokered_subject_token_trust_type %q", config.BrokeredSubjectTokenTrustType)
	}
}

func (b *backend) resolveBrokeredOIDCDiscoveryKeys(ctx context.Context, config *federatedConfig) ([]jose.JSONWebKey, error) {
	var document struct {
		JWKSURI string `json:"jwks_uri"`
	}

	discoveryURL := strings.TrimRight(config.BrokeredSubjectTokenIssuer, "/") + "/.well-known/openid-configuration"
	if err := b.fetchBrokeredJSON(ctx, discoveryURL, &document); err != nil {
		return nil, fmt.Errorf("failed to fetch OIDC discovery document: %w", err)
	}
	if strings.TrimSpace(document.JWKSURI) == "" {
		return nil, fmt.Errorf("OIDC discovery document is missing jwks_uri")
	}

	return b.resolveBrokeredJWKSURLKeys(ctx, document.JWKSURI)
}

func (b *backend) resolveBrokeredJWKSURLKeys(ctx context.Context, rawURL string) ([]jose.JSONWebKey, error) {
	var keySet jose.JSONWebKeySet
	if err := b.fetchBrokeredJSON(ctx, rawURL, &keySet); err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	if len(keySet.Keys) == 0 {
		return nil, fmt.Errorf("JWKS did not contain any keys")
	}
	return keySet.Keys, nil
}

func parseBrokeredJWKS(raw string) (*jose.JSONWebKeySet, error) {
	var keySet jose.JSONWebKeySet
	if err := json.Unmarshal([]byte(raw), &keySet); err != nil {
		return nil, err
	}
	if len(keySet.Keys) == 0 {
		return nil, fmt.Errorf("JWKS did not contain any keys")
	}
	return &keySet, nil
}

func resolveBrokeredInlinePublicKeys(keys []string) ([]jose.JSONWebKey, error) {
	out := make([]jose.JSONWebKey, 0, len(keys))
	for _, keyPEM := range keys {
		key, err := parseBrokeredPublicKey(keyPEM)
		if err != nil {
			return nil, err
		}
		out = append(out, jose.JSONWebKey{
			Key: key,
			Use: "sig",
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no public keys were provided")
	}
	return out, nil
}

func parseBrokeredPublicKey(keyPEM string) (interface{}, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM public key")
	}

	switch block.Type {
	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		switch typed := key.(type) {
		case *rsa.PublicKey, *ecdsa.PublicKey:
			return typed, nil
		default:
			return nil, fmt.Errorf("public key type %T is not supported", key)
		}
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		switch typed := cert.PublicKey.(type) {
		case *rsa.PublicKey, *ecdsa.PublicKey:
			return typed, nil
		default:
			return nil, fmt.Errorf("certificate public key type %T is not supported", cert.PublicKey)
		}
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
}

func (b *backend) fetchBrokeredJSON(ctx context.Context, rawURL string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("unexpected status %d from %s: %s", resp.StatusCode, rawURL, strings.TrimSpace(string(body)))
	}

	return json.NewDecoder(resp.Body).Decode(out)
}
