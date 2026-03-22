package ocibackend

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/hashicorp/vault/sdk/helper/pluginutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) defaultSubjectTokenCallback(ctx context.Context, req *logical.Request, config *federatedConfig) (string, error) {
	audience, err := resolveSubjectTokenAudience(nil, config)
	if req != nil {
		fieldData := &logicalRequestFieldData{Request: req}
		audience, err = resolveSubjectTokenAudience(fieldData, config)
	}
	if err != nil {
		return "", err
	}

	// Prefer Vault plugin identity token generation where available.
	resp, err := b.System().GenerateIdentityToken(ctx, &pluginutil.IdentityTokenRequest{
		Audience: audience,
	})
	if err == nil && resp != nil && string(resp.Token) != "" {
		return string(resp.Token), nil
	}

	// Fallback to in-plugin self-mint when enabled.
	if !config.SubjectTokenSelfMintEnabled {
		if err != nil {
			return "", fmt.Errorf("plugin identity token generation unavailable and self-mint disabled: %w", err)
		}
		return "", fmt.Errorf("plugin identity token unavailable and self-mint disabled")
	}

	return b.selfMintSubjectToken(req, config, audience)
}

func (b *backend) selfMintSubjectToken(req *logical.Request, config *federatedConfig, audience string) (string, error) {
	privateKey, err := parseRSAPrivateKey(config.SubjectTokenSelfMintPrivateKey)
	if err != nil {
		return "", fmt.Errorf("invalid subject_token_self_mint_private_key: %w", err)
	}

	now := time.Now().UTC()
	ttl := time.Duration(configSubjectTokenSelfMintTTLSeconds(config)) * time.Second
	expiresAt := now.Add(ttl)

	claims := map[string]interface{}{
		"iss": config.SubjectTokenSelfMintIssuer,
		"sub": buildSelfMintSubject(req),
		"aud": audience,
		"iat": jwt.NewNumericDate(now),
		"exp": jwt.NewNumericDate(expiresAt),
		"jti": randomJTI(),
	}

	addSelfMintRequestClaims(claims, req)
	if err := b.addSelfMintIdentityClaims(claims, req); err != nil {
		return "", err
	}

	signer, err := newSelfMintSigner(privateKey)
	if err != nil {
		return "", err
	}

	return jwt.Signed(signer).Claims(claims).Serialize()
}

func decodeJWTClaimsMap(token string) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("token is not a JWT")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

type logicalRequestFieldData struct {
	*logical.Request
}

func (l *logicalRequestFieldData) GetOk(key string) (interface{}, bool) {
	if l == nil || l.Request == nil || l.Request.Data == nil {
		return nil, false
	}
	value, ok := l.Request.Data[key]
	return value, ok
}

func buildSelfMintSubject(req *logical.Request) string {
	if req != nil && req.EntityID != "" {
		return "vault:entity:" + req.EntityID
	}
	if req != nil && req.DisplayName != "" {
		return "vault:display:" + req.DisplayName
	}
	if req != nil && req.MountAccessor != "" {
		return "vault:mount:" + req.MountAccessor
	}
	return "vault-oci-plugin"
}

func addSelfMintRequestClaims(claims map[string]interface{}, req *logical.Request) {
	if req == nil {
		return
	}
	if req.EntityID != "" {
		claims["vault_entity_id"] = req.EntityID
	}
	if req.DisplayName != "" {
		claims["vault_display_name"] = req.DisplayName
	}
	if req.MountAccessor != "" {
		claims["vault_mount_accessor"] = req.MountAccessor
	}
	if req.MountType != "" {
		claims["vault_mount_type"] = req.MountType
	}
	if req.ClientTokenAccessor != "" {
		claims["vault_client_token_accessor"] = req.ClientTokenAccessor
	}
}

func (b *backend) addSelfMintIdentityClaims(claims map[string]interface{}, req *logical.Request) error {
	if req == nil || req.EntityID == "" {
		return nil
	}

	entity, err := b.System().EntityInfo(req.EntityID)
	if err != nil {
		return fmt.Errorf("failed to lookup entity info for self-mint claims: %w", err)
	}
	if entity != nil {
		if entity.Name != "" {
			claims["vault_entity_name"] = entity.Name
		}
		if entity.NamespaceID != "" {
			claims["vault_namespace_id"] = entity.NamespaceID
		}
		if len(entity.Metadata) > 0 {
			claims["vault_entity_metadata"] = copyStringMap(entity.Metadata)
		}
		if alias := selectEntityAliasForRequest(entity, req); alias != nil {
			if alias.Name != "" {
				claims["vault_alias_name"] = alias.Name
			}
			if alias.MountAccessor != "" {
				claims["vault_alias_mount_accessor"] = alias.MountAccessor
			}
			if alias.MountType != "" {
				claims["vault_alias_mount_type"] = alias.MountType
			}
			if len(alias.Metadata) > 0 {
				claims["vault_alias_metadata"] = copyStringMap(alias.Metadata)
			}
			if len(alias.CustomMetadata) > 0 {
				claims["vault_alias_custom_metadata"] = copyStringMap(alias.CustomMetadata)
			}
		}
	}

	groups, err := b.System().GroupsForEntity(req.EntityID)
	if err != nil {
		return fmt.Errorf("failed to lookup groups for self-mint claims: %w", err)
	}
	if len(groups) > 0 {
		var groupNames []string
		for _, group := range groups {
			if group != nil && group.Name != "" {
				groupNames = append(groupNames, group.Name)
			}
		}
		sort.Strings(groupNames)
		if len(groupNames) > 0 {
			claims["vault_group_names"] = groupNames
		}
	}

	return nil
}

func selectEntityAliasForRequest(entity *logical.Entity, req *logical.Request) *logical.Alias {
	if entity == nil || req == nil || len(entity.Aliases) == 0 {
		return nil
	}

	for _, alias := range entity.Aliases {
		if alias != nil && req.MountAccessor != "" && alias.MountAccessor == req.MountAccessor {
			return alias
		}
	}

	for _, alias := range entity.Aliases {
		if alias != nil && req.MountType != "" && alias.MountType == req.MountType {
			return alias
		}
	}

	return entity.Aliases[0]
}

func copyStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func parseRSAPrivateKey(pemString string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemString))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	key, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA")
	}
	return key, nil
}

func newSelfMintSigner(privateKey *rsa.PrivateKey) (jose.Signer, error) {
	jwk, err := buildSelfMintSigningJWK(privateKey)
	if err != nil {
		return nil, err
	}

	return jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.RS256,
			Key:       jwk,
		},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
}

func randomJTI() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
