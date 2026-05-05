package ocibackend

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"path"
	"time"

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

	jwk, err := buildRSAJWK(privateKey)
	if err != nil {
		return logical.ErrorResponse("failed to build jwk: %v", err), nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"keys": []map[string]interface{}{jwk},
		},
	}, nil
}

func buildRSAJWK(privateKey *rsa.PrivateKey) (map[string]interface{}, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("invalid RSA private key")
	}
	publicKey := &privateKey.PublicKey
	if publicKey.N == nil || publicKey.E <= 0 {
		return nil, fmt.Errorf("invalid RSA public key")
	}

	jwk, err := buildSelfMintSigningJWK(privateKey)
	if err != nil {
		return nil, err
	}
	jwk.Key = publicKey

	leafCertDER, err := buildSelfSignedJWTCertificate(privateKey, jwk.KeyID)
	if err != nil {
		return nil, err
	}
	jwk.Certificates, err = parseSingleCertificate(leafCertDER)
	if err != nil {
		return nil, err
	}

	return jsonWebKeyMap(jwk)
}

func buildSelfSignedJWTCertificate(privateKey *rsa.PrivateKey, kid string) ([]byte, error) {
	notBefore := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	serialNumber := deterministicJWKSCertificateSerial(privateKey, kid)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "vault-plugin-secrets-oci " + kid,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	return x509.CreateCertificate(nil, template, template, &privateKey.PublicKey, privateKey)
}

func deterministicJWKSCertificateSerial(privateKey *rsa.PrivateKey, kid string) *big.Int {
	hashInput := kid
	if privateKey != nil && privateKey.PublicKey.N != nil {
		hashInput = kid + ":" + privateKey.PublicKey.N.Text(16)
	}
	sum := sha256.Sum256([]byte(hashInput))
	serial := new(big.Int).SetBytes(sum[:16])
	if serial.Sign() <= 0 {
		return big.NewInt(1)
	}
	return serial
}

const pathJWKSHelpSyn = `
Read JWKS for subject token trust bootstrap.
`

const pathJWKSHelpDesc = `
Returns a JWKS document derived from the self-mint RSA signing key.
Use this endpoint to configure OCI Identity Domain token-exchange trust
for subject tokens minted by this plugin.
`
