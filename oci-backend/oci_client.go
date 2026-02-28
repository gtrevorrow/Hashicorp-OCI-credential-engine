package ocibackend

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// jwks represents a JSON Web Key Set
type jwks struct {
	Keys []jwk `json:"keys"`
}

// jwk represents a JSON Web Key
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg"`
}

// fetchJWKS retrieves the JWKS from the configured URL
func fetchJWKS(jwksURL string) (*jwks, error) {
	resp, err := http.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	var keySet jwks
	if err := json.NewDecoder(resp.Body).Decode(&keySet); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	return &keySet, nil
}

// getPublicKeyFromJWK extracts an RSA public key from a JWK
func getPublicKeyFromJWK(key *jwk) (*rsa.PublicKey, error) {
	if key.Kty != "RSA" {
		return nil, fmt.Errorf("unsupported key type: %s", key.Kty)
	}

	// Decode base64url encoded modulus
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}

	// Decode base64url encoded exponent
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes).Int64()

	return &rsa.PublicKey{
		N: n,
		E: int(e),
	}, nil
}

// parseSubjectToken parses and validates a JWT subject token
func (b *backend) parseSubjectToken(tokenString string, config *federatedConfig) (*jwt.Token, *tokenClaims, error) {
	// First, parse without validation to get the header (for kid)
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, &tokenClaims{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Get the key ID from the header
	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, nil, errors.New("token missing 'kid' header")
	}

	// Fetch JWKS if URL is configured
	var publicKey *rsa.PublicKey
	if config.JWKSURL != "" {
		keySet, err := fetchJWKS(config.JWKSURL)
		if err != nil {
			return nil, nil, err
		}

		// Find the matching key
		for _, key := range keySet.Keys {
			if key.Kid == kid {
				publicKey, err = getPublicKeyFromJWK(&key)
				if err != nil {
					return nil, nil, err
				}
				break
			}
		}
	}

	if publicKey == nil {
		return nil, nil, fmt.Errorf("could not find public key for kid: %s", kid)
	}

	// Parse and validate the token
	claims := &tokenClaims{}
	validatedToken, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// Ensure the signing method is RSA
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	}, jwt.WithValidMethods([]string{"RS256", "RS384", "RS512"}))

	if err != nil {
		return nil, nil, fmt.Errorf("token validation failed: %w", err)
	}

	return validatedToken, claims, nil
}

// tokenClaims represents the expected claims in a subject token
type tokenClaims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  []string `json:"aud"`
	Expiry    int64    `json:"exp"`
	NotBefore int64    `json:"nbf"`
	IssuedAt  int64    `json:"iat"`
	Email     string   `json:"email"`
	Groups    []string `json:"groups"`
}

// GetAudience implements jwt.Claims
func (c *tokenClaims) GetAudience() (jwt.ClaimStrings, error) {
	return c.Audience, nil
}

// GetExpirationTime implements jwt.Claims
func (c *tokenClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	if c.Expiry == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(c.Expiry, 0)), nil
}

// GetIssuedAt implements jwt.Claims
func (c *tokenClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	if c.IssuedAt == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(c.IssuedAt, 0)), nil
}

// GetIssuer implements jwt.Claims
func (c *tokenClaims) GetIssuer() (string, error) {
	return c.Issuer, nil
}

// GetNotBefore implements jwt.Claims
func (c *tokenClaims) GetNotBefore() (*jwt.NumericDate, error) {
	if c.NotBefore == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(c.NotBefore, 0)), nil
}

// GetSubject implements jwt.Claims
func (c *tokenClaims) GetSubject() (string, error) {
	return c.Subject, nil
}

// validateSubjectToken performs full validation of the JWT subject token
func (b *backend) validateSubjectTokenImpl(tokenString string, config *federatedConfig) (*tokenValidationResult, error) {
	// Parse and validate the token
	_, claims, err := b.parseSubjectToken(tokenString, config)
	if err != nil {
		return nil, err
	}

	// Validate issuer
	if len(config.AllowedIssuers) > 0 {
		issuerValid := false
		for _, allowed := range config.AllowedIssuers {
			if claims.Issuer == allowed {
				issuerValid = true
				break
			}
		}
		if !issuerValid {
			return nil, fmt.Errorf("issuer '%s' not in allowed list", claims.Issuer)
		}
	}

	// Extract groups if present
	groups := claims.Groups
	if groups == nil {
		groups = []string{}
	}

	return &tokenValidationResult{
		Issuer:  claims.Issuer,
		Subject: claims.Subject,
		Email:   claims.Email,
		Groups:  groups,
		Raw: map[string]interface{}{
			"issuer":   claims.Issuer,
			"subject":  claims.Subject,
			"audience": claims.Audience,
			"email":    claims.Email,
			"groups":   groups,
		},
	}, nil
}

// decodePrivateKey decodes a PEM-encoded RSA private key
func decodePrivateKey(keyPEM string, passphrase string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block")
	}

	var keyBytes []byte
	var err error

	if x509.IsEncryptedPEMBlock(block) && passphrase != "" {
		keyBytes, err = x509.DecryptPEMBlock(block, []byte(passphrase))
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt private key: %w", err)
		}
	} else {
		keyBytes = block.Bytes
	}

	var privateKey *rsa.PrivateKey
	if block.Type == "RSA PRIVATE KEY" {
		privateKey, err = x509.ParsePKCS1PrivateKey(keyBytes)
	} else if block.Type == "PRIVATE KEY" {
		key, err := x509.ParsePKCS8PrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS8 private key: %w", err)
		}
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("private key is not RSA")
		}
	} else {
		return nil, fmt.Errorf("unsupported key type: %s", block.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return privateKey, nil
}

// buildSubjectTokenForOCI creates a subject token for OCI token exchange
// This creates a JWT assertion that OCI will accept in exchange for an OCI session token
func buildSubjectTokenForOCI(externalToken string, config *federatedConfig, claims *tokenValidationResult) (string, error) {
	// The external token is passed through to OCI
	// OCI validates it against the configured IdP
	return externalToken, nil
}

// OCI Token Exchange API types

type ociTokenRequest struct {
	GrantType           string `json:"grant_type"`
	SubjectToken        string `json:"subject_token"`
	SubjectTokenType    string `json:"subject_token_type"`
	RequestedTokenType  string `json:"requested_token_type,omitempty"`
	Scope               string `json:"scope,omitempty"`
}

type ociTokenResponse struct {
	AccessToken     string `json:"access_token"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
	Scope           string `json:"scope,omitempty"`
}

// exchangeTokenWithOCI calls the OCI Identity Domain token endpoint
func (b *backend) exchangeTokenWithOCI(ctx context.Context, req *ociTokenRequest, config *federatedConfig) (*ociTokenResponse, error) {
	// TODO: Implement actual OCI API call
	// Endpoint: POST /oauth2/v1/token
	// Base URL: https://{domain}.identity.{region}.oci.oraclecloud.com
	// or: https://idcs-{domain}.identity.oraclecloud.com
	
	// The request body should be form-encoded or JSON depending on OCI's requirements
	// grant_type=urn:ietf:params:oauth:grant-type:token-exchange
	// subject_token={jwt}
	// subject_token_type=urn:ietf:params:oauth:token-type:jwt
	
	return nil, errors.New("OCI token exchange API not yet implemented")
}
