package ocibackend

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
	"path"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathJWKS() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: path.Join("jwks"),
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathJWKSRead,
					Summary:  "Read JWKS for self-mint subject token trust setup",
				},
			},
			HelpSynopsis:    pathJWKSHelpSyn,
			HelpDescription: pathJWKSHelpDesc,
		},
	}
}

func (b *backend) pathJWKSRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	config, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return logical.ErrorResponse("backend not configured"), nil
	}
	if !config.SubjectTokenSelfMintEnabled {
		return logical.ErrorResponse("subject_token_self_mint_enabled is false"), nil
	}
	if config.SubjectTokenSelfMintPrivateKey == "" {
		return logical.ErrorResponse("subject_token_self_mint_private_key is not configured"), nil
	}

	privateKey, err := parseRSAPrivateKey(config.SubjectTokenSelfMintPrivateKey)
	if err != nil {
		return logical.ErrorResponse("invalid subject_token_self_mint_private_key: %v", err), nil
	}

	jwk, err := buildRSAJWK(&privateKey.PublicKey)
	if err != nil {
		return logical.ErrorResponse("failed to build jwk: %v", err), nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"keys": []map[string]interface{}{jwk},
		},
	}, nil
}

func buildRSAJWK(publicKey *rsa.PublicKey) (map[string]interface{}, error) {
	n := publicKey.N
	if n == nil || publicKey.E <= 0 {
		return nil, fmt.Errorf("invalid RSA public key")
	}

	modulus := base64.RawURLEncoding.EncodeToString(n.Bytes())
	exponent := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes())

	pubDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(pubDER)
	kid := base64.RawURLEncoding.EncodeToString(sum[:])

	return map[string]interface{}{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": kid,
		"n":   modulus,
		"e":   exponent,
	}, nil
}

const pathJWKSHelpSyn = `
Read JWKS for subject token trust bootstrap.
`

const pathJWKSHelpDesc = `
Returns a JWKS document derived from the self-mint RSA signing key.
Use this endpoint to configure OCI Identity Domain token-exchange trust
for subject tokens minted by this plugin.
`
