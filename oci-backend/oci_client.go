package ocibackend

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	ociRequestedTokenTypeUPST = "urn:oci:token-type:oci-upst"
	ociRequestedTokenTypeRPST = "urn:oci:token-type:oci-rpst"
	ociGrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	ociSubjectTokenTypeJWT    = "jwt"
)

type tokenExchangeResult struct {
	AccessToken         string
	SessionToken        string
	RPSTToken           string
	TokenType           string
	RequestedTokenType  string
	CredentialExpiresAt time.Time
	PrivateKey          string
	PublicKey           string
	HTTPStatus          int
	RequestID           string
}

type ociTokenExchangeResponse struct {
	AccessToken      string `json:"access_token"`
	Token            string `json:"token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        *int64 `json:"expires_in"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func isSupportedRequestedTokenType(requestedTokenType string) bool {
	return requestedTokenType == ociRequestedTokenTypeUPST || requestedTokenType == ociRequestedTokenTypeRPST
}

func shouldReturnGeneratedKeyPair(publicKey string) bool {
	return publicKey == ""
}

func (b *backend) exchangeTokenForOCI(ctx context.Context, subjectToken, requestedTokenType, resType, publicKey string, ttl time.Duration, config *federatedConfig) (*tokenExchangeResult, error) {
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
	if requestedTokenType == ociRequestedTokenTypeRPST && ttl > 0 {
		form.Set("rpst_exp", strconv.Itoa(int(ttl.Seconds())))
	}

	tokenURL, err := tokenExchangeEndpoint(config.DomainUrl)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, &ociExchangeError{reason: "oci_request_invalid"}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(config.ClientID, config.ClientSecret)

	client := b.httpClient
	if client == nil {
		client = http.DefaultClient
	}

	// Never forward a subject token in a redirected POST body.
	requestClient := *client
	requestClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	requestStarted := time.Now()
	resp, err := requestClient.Do(req)
	if err != nil {
		reason := "oci_transport_error"
		if errors.Is(err, context.DeadlineExceeded) {
			reason = "oci_timeout"
		}
		if errors.Is(err, context.Canceled) {
			reason = "request_canceled"
		}
		return nil, &ociExchangeError{reason: reason}
	}
	defer resp.Body.Close()

	requestID := validatedOCIRequestID(resp.Header.Get("opc-request-id"))
	body, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil {
		return nil, &ociExchangeError{reason: "oci_response_read_failed", status: resp.StatusCode, requestID: requestID}
	}

	if len(body) > 1<<20 {
		return nil, &ociExchangeError{reason: "oci_response_too_large", status: resp.StatusCode, requestID: requestID}
	}
	var tokenResp ociTokenExchangeResponse
	decodeErr := json.Unmarshal(body, &tokenResp)
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		code := ""
		if decodeErr == nil {
			code = allowedOAuthError(tokenResp.Error)
		}
		return nil, &ociExchangeError{reason: "oci_rejected", code: code, status: resp.StatusCode, requestID: requestID}
	}
	if decodeErr != nil {
		return nil, &ociExchangeError{reason: "oci_response_invalid", status: resp.StatusCode, requestID: requestID}
	}
	if tokenResp.Error != "" {
		return nil, &ociExchangeError{reason: "oci_rejected", code: allowedOAuthError(tokenResp.Error), status: resp.StatusCode, requestID: requestID}
	}

	token := tokenResp.AccessToken
	if token == "" {
		token = tokenResp.Token
	}
	if token == "" {
		return nil, &ociExchangeError{reason: "oci_token_missing", status: resp.StatusCode, requestID: requestID}
	}

	tokenType := tokenResp.TokenType
	if tokenType == "" {
		tokenType = "Bearer"
	}

	var credentialExpiresAt time.Time
	if tokenResp.ExpiresIn != nil {
		seconds := *tokenResp.ExpiresIn
		if seconds <= 0 || seconds > maxTokenTTLSeconds {
			return nil, &ociExchangeError{reason: "oci_expiry_invalid", status: resp.StatusCode, requestID: requestID}
		}
		// Start at request dispatch rather than receipt so network/processing
		// latency never extends the lifetime advertised by OCI.
		credentialExpiresAt = requestStarted.Add(time.Duration(seconds) * time.Second)
	}

	return &tokenExchangeResult{
		AccessToken:         token,
		HTTPStatus:          resp.StatusCode,
		RequestID:           requestID,
		SessionToken:        tokenByType(requestedTokenType, ociRequestedTokenTypeUPST, token),
		RPSTToken:           tokenByType(requestedTokenType, ociRequestedTokenTypeRPST, token),
		TokenType:           tokenType,
		RequestedTokenType:  requestedTokenType,
		CredentialExpiresAt: credentialExpiresAt,
		PrivateKey:          privateKeyPEM,
		PublicKey:           publicKeyPEM,
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
