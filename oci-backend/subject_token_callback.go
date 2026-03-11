package ocibackend

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/helper/pluginutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) defaultSubjectTokenCallback(ctx context.Context, req *logical.Request, config *federatedConfig) (string, error) {
	// Prefer Vault plugin identity token generation where available.
	resp, err := b.System().GenerateIdentityToken(ctx, &pluginutil.IdentityTokenRequest{
		Audience: configSubjectTokenSelfMintAudience(config),
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

	return selfMintSubjectToken(req, config)
}

func selfMintSubjectToken(req *logical.Request, config *federatedConfig) (string, error) {
	privateKey, err := parseRSAPrivateKey(config.SubjectTokenSelfMintPrivateKey)
	if err != nil {
		return "", fmt.Errorf("invalid subject_token_self_mint_private_key: %w", err)
	}

	now := time.Now().UTC()
	ttl := time.Duration(configSubjectTokenSelfMintTTLSeconds(config)) * time.Second
	expiresAt := now.Add(ttl)

	header := map[string]interface{}{
		"alg": "RS256",
		"typ": "JWT",
	}

	sub := "vault-oci-plugin"
	roleName, _ := req.Data["role"].(string)
	if roleName != "" {
		sub = roleName
	}

	claims := map[string]interface{}{
		"iss": config.SubjectTokenSelfMintIssuer,
		"sub": sub,
		"aud": configSubjectTokenSelfMintAudience(config),
		"iat": now.Unix(),
		"exp": expiresAt.Unix(),
		"jti": randomJTI(),
	}
	if roleName != "" {
		claims[configRoleClaimKey(config)] = roleName
	}

	return signJWT(header, claims, privateKey)
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

func signJWT(header, claims map[string]interface{}, privateKey *rsa.PrivateKey) (string, error) {
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedClaims := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := encodedHeader + "." + encodedClaims

	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}

	encodedSig := base64.RawURLEncoding.EncodeToString(signature)
	return strings.Join([]string{encodedHeader, encodedClaims, encodedSig}, "."), nil
}

func randomJTI() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
