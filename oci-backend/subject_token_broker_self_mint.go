package ocibackend

import (
	"context"
	"fmt"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) selfMintBrokeredSubjectToken(ctx context.Context, req *logical.Request, config *federatedConfig, mappedClaims map[string]interface{}) (string, error) {
	audience := configSubjectTokenSelfMintAudience(config)
	privateKey, err := parseRSAPrivateKey(config.SubjectTokenSelfMintPrivateKey)
	if err != nil {
		return "", fmt.Errorf("invalid subject_token_self_mint_private_key: %w", err)
	}

	claims := buildBaseSelfMintClaims(req, config, audience)
	addSelfMintRequestClaims(claims, req)
	if err := b.addSelfMintIdentityClaims(claims, req); err != nil {
		return "", err
	}
	if err := addBrokeredMappedClaims(claims, mappedClaims); err != nil {
		return "", err
	}
	if err := b.addSelfMintRoleCustomClaims(ctx, claims, req); err != nil {
		return "", err
	}

	signer, err := newSelfMintSigner(privateKey)
	if err != nil {
		return "", err
	}

	return jwt.Signed(signer).Claims(claims).Serialize()
}

func addBrokeredMappedClaims(claims map[string]interface{}, mappedClaims map[string]interface{}) error {
	for claim, value := range mappedClaims {
		if err := validateSelfMintCustomClaimName(claim); err != nil {
			return err
		}
		if _, exists := claims[claim]; exists {
			return fmt.Errorf("mapped brokered claim %q conflicts with existing claim", claim)
		}
		claims[claim] = value
	}

	return nil
}
