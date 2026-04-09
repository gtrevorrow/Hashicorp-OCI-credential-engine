package ocibackend

import (
	"context"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
)

func TestValidateBrokeredSubjectToken(t *testing.T) {
	b, _ := getTestBackend(t)

	rsaKey := generateTestRSAPrivateKey(t)
	ecKey := generateTestECDSAPrivateKey(t)
	now := time.Now().UTC()

	baseConfig := &federatedConfig{
		BrokeredSubjectTokenEnabled:          true,
		BrokeredSubjectTokenTrustType:        brokeredTrustTypePublicKeys,
		BrokeredSubjectTokenIssuer:           "https://issuer.example.com",
		BrokeredSubjectTokenAllowedAudiences: []string{"urn:test"},
		BrokeredSubjectTokenAllowedAlgs:      []string{"RS256"},
		BrokeredSubjectTokenPublicKeys:       []string{encodeTestPublicKeyPEM(t, &rsaKey.PublicKey)},
	}

	makeClaims := func() map[string]interface{} {
		return map[string]interface{}{
			"iss": "https://issuer.example.com",
			"sub": "user-123",
			"aud": "urn:test",
			"iat": now.Unix(),
			"nbf": now.Add(-time.Minute).Unix(),
			"exp": now.Add(time.Hour).Unix(),
		}
	}

	t.Run("Valid RSA Token", func(t *testing.T) {
		token := makeSignedTestJWT(t, rsaKey, jose.RS256, makeClaims())
		claims, err := b.validateBrokeredSubjectToken(context.Background(), token, baseConfig)
		require.NoError(t, err)
		require.Equal(t, "user-123", claims["sub"])
	})

	t.Run("Valid EC Token", func(t *testing.T) {
		config := *baseConfig
		config.BrokeredSubjectTokenAllowedAlgs = []string{"ES256"}
		config.BrokeredSubjectTokenPublicKeys = []string{encodeTestPublicKeyPEM(t, &ecKey.PublicKey)}
		token := makeSignedTestJWT(t, ecKey, jose.ES256, makeClaims())

		claims, err := b.validateBrokeredSubjectToken(context.Background(), token, &config)
		require.NoError(t, err)
		require.Equal(t, "user-123", claims["sub"])
	})

	t.Run("Bad Signature", func(t *testing.T) {
		otherKey := generateTestRSAPrivateKey(t)
		token := makeSignedTestJWT(t, otherKey, jose.RS256, makeClaims())

		_, err := b.validateBrokeredSubjectToken(context.Background(), token, baseConfig)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to verify JWT signature")
	})

	t.Run("Wrong Issuer", func(t *testing.T) {
		claims := makeClaims()
		claims["iss"] = "https://other.example.com"
		token := makeSignedTestJWT(t, rsaKey, jose.RS256, claims)

		_, err := b.validateBrokeredSubjectToken(context.Background(), token, baseConfig)
		require.Error(t, err)
		require.Contains(t, err.Error(), "does not match configured brokered issuer")
	})

	t.Run("Wrong Audience", func(t *testing.T) {
		claims := makeClaims()
		claims["aud"] = "urn:other"
		token := makeSignedTestJWT(t, rsaKey, jose.RS256, claims)

		_, err := b.validateBrokeredSubjectToken(context.Background(), token, baseConfig)
		require.Error(t, err)
		require.Contains(t, err.Error(), "does not match configured brokered audiences")
	})

	t.Run("Expired Token", func(t *testing.T) {
		claims := makeClaims()
		claims["exp"] = now.Add(-time.Minute).Unix()
		token := makeSignedTestJWT(t, rsaKey, jose.RS256, claims)

		_, err := b.validateBrokeredSubjectToken(context.Background(), token, baseConfig)
		require.Error(t, err)
		require.Contains(t, err.Error(), "expired")
	})

	t.Run("Unsupported Alg", func(t *testing.T) {
		config := *baseConfig
		config.BrokeredSubjectTokenAllowedAlgs = []string{"ES256"}
		token := makeSignedTestJWT(t, rsaKey, jose.RS256, makeClaims())

		_, err := b.validateBrokeredSubjectToken(context.Background(), token, &config)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse signed JWT")
	})
}
