package ocibackend

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	ociRequestedTokenTypeUPST = "urn:oci:token-type:oci-upst"
	ociRequestedTokenTypeRPST = "urn:oci:token-type:oci-rpst"
	ociGrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	ociSubjectTokenTypeJWT    = "jwt"
)

type tokenExchangeResult struct {
	AccessToken        string
	SessionToken       string
	RPSTToken          string
	TokenType          string
	RequestedTokenType string
	ExpiresIn          int
	PrivateKey         string
	PublicKey          string
}

type ociTokenExchangeResponse struct {
	AccessToken string `json:"access_token"`
	Token       string `json:"token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Error       string `json:"error"`
}

func isSupportedRequestedTokenType(requestedTokenType string) bool {
	return requestedTokenType == ociRequestedTokenTypeUPST || requestedTokenType == ociRequestedTokenTypeRPST
}

func shouldReturnGeneratedKeyPair(publicKey string) bool {
	return publicKey == ""
}

func (b *backend) exchangeTokenForOCI(ctx context.Context, subjectToken, requestedTokenType, resType, publicKey string, config *federatedConfig) (*tokenExchangeResult, error) {
	if requestedTokenType == "" {
		requestedTokenType = ociRequestedTokenTypeUPST
	}

	requestPublicKey, privateKeyPEM, publicKeyPEM, err := resolveExchangePublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	form := url.Values{}
	form.Set("grant_type", ociGrantTypeTokenExchange)
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", ociSubjectTokenTypeJWT)
	form.Set("requested_token_type", requestedTokenType)
	form.Set("public_key", requestPublicKey)
	if resType != "" {
		form.Set("res_type", resType)
	}

	tokenURL, err := tokenExchangeEndpoint(config.DomainUrl)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to construct token exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(config.ClientID, config.ClientSecret)

	client := b.httpClient
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unable to exchange JWT for security token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("unable to read OCI token exchange response: %w", err)
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("unable to exchange JWT for security token: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var tokenResp ociTokenExchangeResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("unable to decode OCI token exchange response: %w", err)
	}

	token := tokenResp.AccessToken
	if token == "" {
		token = tokenResp.Token
	}
	if token == "" {
		return nil, fmt.Errorf("OCI token exchange response did not include access_token")
	}

	tokenType := tokenResp.TokenType
	if tokenType == "" {
		tokenType = "Bearer"
	}

	return &tokenExchangeResult{
		AccessToken:        token,
		SessionToken:       tokenByType(requestedTokenType, ociRequestedTokenTypeUPST, token),
		RPSTToken:          tokenByType(requestedTokenType, ociRequestedTokenTypeRPST, token),
		TokenType:          tokenType,
		RequestedTokenType: requestedTokenType,
		ExpiresIn:          tokenResp.ExpiresIn,
		PrivateKey:         privateKeyPEM,
		PublicKey:          publicKeyPEM,
	}, nil
}

func tokenByType(requestedTokenType, wantedType, token string) string {
	if requestedTokenType == wantedType {
		return token
	}
	return ""
}

func resolveExchangePublicKey(publicKey string) (string, string, string, error) {
	if publicKey == "" {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return "", "", "", fmt.Errorf("failed to generate RSA keypair: %w", err)
		}

		privateKeyPEM, err := marshalPrivateKeyToPEM(privateKey)
		if err != nil {
			return "", "", "", fmt.Errorf("failed to marshal private key: %w", err)
		}
		publicKeyPEM, err := marshalPublicKeyToPEM(privateKey.Public())
		if err != nil {
			return "", "", "", fmt.Errorf("failed to marshal public key: %w", err)
		}
		encodedPublicKey, err := publicKeyPEMToOCIValue(publicKeyPEM)
		if err != nil {
			return "", "", "", err
		}
		return encodedPublicKey, privateKeyPEM, publicKeyPEM, nil
	}

	encodedPublicKey, err := publicKeyPEMToOCIValue(publicKey)
	if err != nil {
		return "", "", "", err
	}
	return encodedPublicKey, "", "", nil
}

// Encode the public key as Base64 encoded DER format as required by the OCI token exchange endpoint. If the public key is invalid, an error is returned.
func publicKeyPEMToOCIValue(publicKeyPEM string) (string, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return "", fmt.Errorf("invalid public_key PEM")
	}
	if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		return "", fmt.Errorf("invalid public_key PEM: %w", err)
	}
	return base64.StdEncoding.EncodeToString(block.Bytes), nil
}

func tokenExchangeEndpoint(domainURL string) (string, error) {
	if domainURL == "" {
		return "", fmt.Errorf("missing domain_url")
	}
	base, err := url.Parse(strings.TrimRight(domainURL, "/"))
	if err != nil {
		return "", fmt.Errorf("invalid domain_url: %w", err)
	}
	if base.Scheme == "" || base.Host == "" {
		return "", fmt.Errorf("invalid domain_url")
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/oauth2/v1/token"
	base.RawQuery = ""
	base.Fragment = ""
	return base.String(), nil
}

func marshalPrivateKeyToPEM(privateKey *rsa.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", err
	}

	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	return string(pem.EncodeToMemory(block)), nil
}

func marshalPublicKeyToPEM(publicKey interface{}) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}

	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	return string(pem.EncodeToMemory(block)), nil
}
