package ocibackend

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

const loggingClientSecret = "CLIENT_SECRET_CANARY_74b615"
const loggingClaim = "IDENTITY_CLAIM_CANARY_d61a90"
const loggingSession = "OCI_SESSION_CANARY_26dc44"
const loggingRequestID = "c11d87cb-2a2a-4384-b41b-314c4cf8b94a"

type securityTestTransport func(*http.Request) (*http.Response, error)

func (f securityTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func loggingBackend(t *testing.T, level hclog.Level) (*backend, logical.Storage, *bytes.Buffer) {
	t.Helper()
	output := &bytes.Buffer{}
	logger := hclog.New(&hclog.LoggerOptions{Name: "oci-test", Level: level, JSONFormat: true, Output: output})
	result, err := Factory("test")(context.Background(), &logical.BackendConfig{Logger: logger, System: &mockSystemView{StaticSystemView: logical.StaticSystemView{DefaultLeaseTTLVal: time.Hour, MaxLeaseTTLVal: 24 * time.Hour}}})
	require.NoError(t, err)
	return result.(*backend), &logical.InmemStorage{}, output
}
func securityRequest(storage logical.Storage, path string, data map[string]interface{}) *logical.Request {
	return &logical.Request{ID: loggingRequestID, MountAccessor: "oci_test123", Operation: logical.UpdateOperation, Path: path, Storage: storage, Data: data}
}
func loggingConfig(t *testing.T, b *backend, storage logical.Storage, values map[string]interface{}) {
	t.Helper()
	data := map[string]interface{}{"domain_url": "https://oci.example", "client_id": "test-client", "client_secret": loggingClientSecret}
	for key, value := range values {
		data[key] = value
	}
	resp, err := b.HandleRequest(context.Background(), securityRequest(storage, "config", data))
	require.NoError(t, err)
	require.False(t, resp.IsError())
}
func loggingEvents(t *testing.T, output *bytes.Buffer) []map[string]interface{} {
	t.Helper()
	events := []map[string]interface{}{}
	for _, line := range strings.Split(strings.TrimSpace(output.String()), "\n") {
		if line == "" {
			continue
		}
		var event map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(line), &event))
		events = append(events, event)
	}
	return events
}
func assertNoCredentialValues(t *testing.T, output string, extra ...string) {
	t.Helper()
	values := append([]string{loggingClientSecret, loggingClaim, loggingSession, "BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY"}, extra...)
	for _, value := range values {
		if value != "" {
			require.NotContains(t, output, value)
		}
	}
}
func credentialResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Opc-Request-Id": []string{loggingRequestID}}, Body: io.NopCloser(strings.NewReader(body))}
}
func TestSecurityEventsExcludeCredentialMaterialAtEveryLogLevel(t *testing.T) {
	for _, level := range []hclog.Level{hclog.Trace, hclog.Debug, hclog.Info, hclog.Warn, hclog.Error, hclog.Off} {
		t.Run(level.String(), func(t *testing.T) {
			b, storage, output := loggingBackend(t, level)
			signingKey := generateTestRSAPrivateKeyPEM(t)
			loggingConfig(t, b, storage, map[string]interface{}{"subject_token_self_mint_private_key": signingKey})
			resp, err := b.HandleRequest(context.Background(), securityRequest(storage, "role/developer", map[string]interface{}{"description": loggingClaim, "self_mint_custom_claims": `{"label":"` + loggingClaim + `"}`}))
			require.NoError(t, err)
			require.False(t, resp.IsError())
			jwt := "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"`+loggingClaim+`"}`)) + ".signature"
			b.httpClient = &http.Client{Transport: securityTestTransport(func(r *http.Request) (*http.Response, error) {
				return credentialResponse(401, `{"error":"invalid_client","error_description":"`+loggingClientSecret+" "+jwt+`"}`), nil
			})}
			resp, err = b.HandleRequest(context.Background(), securityRequest(storage, "exchange/developer", map[string]interface{}{"subject_token": jwt}))
			require.NoError(t, err)
			require.True(t, resp.IsError())
			assertNoCredentialValues(t, output.String(), jwt, strings.Split(signingKey, "\n")[1])
			assertNoCredentialValues(t, resp.Error().Error(), jwt)
			if level <= hclog.Warn {
				events := loggingEvents(t, output)
				var exchange map[string]interface{}
				for _, event := range events {
					if event["event"] == "credential_exchange" {
						exchange = event
					}
				}
				require.NotNil(t, exchange)
				require.Equal(t, "failure", exchange["outcome"])
				require.Equal(t, "oci_rejected", exchange["reason_code"])
				require.Equal(t, loggingRequestID, exchange["request_id"])
				require.Equal(t, "developer", exchange["effective_role"])
				require.Equal(t, float64(401), exchange["upstream_status"])
				require.Equal(t, loggingRequestID, exchange["upstream_request_id"])
			} else {
				require.Empty(t, output.String())
			}
		})
	}
}
func TestOCIErrorResponsesContainOnlySafeClassification(t *testing.T) {
	for _, tc := range []struct {
		name      string
		status    int
		body      string
		transport bool
		reason    string
	}{
		{"HTTP rejection", 403, loggingClientSecret + "\nFORGED_LINE", false, "oci_rejected"},
		{"OAuth rejection", 200, `{"error":"invalid_grant","error_description":"` + loggingClaim + `"}`, false, "oci_rejected"},
		{"unknown OAuth code", 200, `{"error":"` + loggingClientSecret + `","error_description":"` + loggingClaim + `"}`, false, "oci_rejected"},
		{"malformed JSON", 200, loggingClientSecret, false, "oci_response_invalid"},
		{"oversized response", 200, strings.Repeat("X", (1<<20)+1) + loggingClientSecret, false, "oci_response_too_large"},
		{"transport failure", 0, "", true, "oci_transport_error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := &backend{httpClient: &http.Client{Transport: securityTestTransport(func(r *http.Request) (*http.Response, error) {
				if tc.transport {
					return nil, fmt.Errorf("%s %s", loggingClientSecret, loggingClaim)
				}
				response := credentialResponse(tc.status, tc.body)
				response.Header.Set("opc-request-id", loggingClientSecret+"\nFORGED_LINE")
				return response, nil
			})}}
			_, err := b.exchangeTokenForOCI(context.Background(), loggingClaim, ociRequestedTokenTypeUPST, "", "", 0, &federatedConfig{DomainUrl: "https://oci.example", ClientID: "client", ClientSecret: loggingClientSecret})
			require.Error(t, err)
			safe := safeExchangeError(err)
			require.Equal(t, tc.reason, safe.reason)
			assertNoCredentialValues(t, safe.Error(), "FORGED_LINE")
			require.Empty(t, safe.requestID)
		})
	}
}
func TestCredentialExchangeEventsDescribeEachTokenSource(t *testing.T) {
	key := generateTestRSAPrivateKey(t)
	incoming := makeSignedTestJWT(t, key, jose.RS256, map[string]interface{}{"iss": "https://issuer.example", "aud": "test-audience", "exp": time.Now().Add(time.Hour).Unix(), "sub": loggingClaim})
	for _, source := range []string{"caller", "vault_identity", "self_mint", "brokered_reissue"} {
		t.Run(source, func(t *testing.T) {
			b, storage, output := loggingBackend(t, hclog.Trace)
			config := map[string]interface{}{}
			data := map[string]interface{}{}
			mode := "plugin_issued"
			switch source {
			case "caller":
				data["subject_token"] = incoming
				mode = "direct"
			case "vault_identity":
				b.System().(*mockSystemView).mockIdentity = incoming
			case "self_mint":
				config["subject_token_self_mint_enabled"] = true
				config["subject_token_self_mint_issuer"] = "https://vault.example"
			case "brokered_reissue":
				mode = "brokered"
				data["subject_token"] = incoming
				config["brokered_subject_token_enabled"] = true
				config["subject_token_self_mint_issuer"] = "https://vault.example"
				config["brokered_subject_token_trust_type"] = "public_keys"
				config["brokered_subject_token_issuer"] = "https://issuer.example"
				config["brokered_subject_token_allowed_audiences"] = []string{"test-audience"}
				config["brokered_subject_token_allowed_algs"] = []string{"RS256"}
				config["brokered_subject_token_public_keys"] = encodeTestPublicKeyPEM(t, &key.PublicKey)
			}
			loggingConfig(t, b, storage, config)
			b.httpClient = &http.Client{Transport: securityTestTransport(func(r *http.Request) (*http.Response, error) {
				return credentialResponse(200, `{"access_token":"`+loggingSession+`","expires_in":600}`), nil
			})}
			resp, err := b.HandleRequest(context.Background(), securityRequest(storage, "exchange", data))
			require.NoError(t, err)
			require.False(t, resp.IsError())
			require.NotEmpty(t, resp.Data["private_key"])
			assertNoCredentialValues(t, output.String(), incoming)
			events := loggingEvents(t, output)
			final := events[len(events)-1]
			require.Equal(t, "credential_exchange", final["event"])
			require.Equal(t, "success", final["outcome"])
			require.Equal(t, mode, final["mode"])
			require.Equal(t, source, final["subject_source"])
			b.httpClient = &http.Client{Transport: securityTestTransport(func(r *http.Request) (*http.Response, error) {
				return credentialResponse(401, `{"error_description":"`+loggingClientSecret+`"}`), nil
			})}
			denied, err := b.HandleRequest(context.Background(), securityRequest(storage, "exchange", data))
			require.NoError(t, err)
			require.True(t, denied.IsError())
			assertNoCredentialValues(t, denied.Error().Error(), incoming)
			assertNoCredentialValues(t, output.String(), incoming)
		})
	}
}
func TestDiagnosticClaimWindowExpiresWithoutRenewingOnRestartOrOtherWrites(t *testing.T) {
	b, storage, output := loggingBackend(t, hclog.Trace)
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	b.now = func() time.Time { return now }
	loggingConfig(t, b, storage, map[string]interface{}{"debug_return_resolved_subject_token_claims": true})
	config, err := b.getConfig(context.Background(), storage)
	require.NoError(t, err)
	deadline := config.DebugResolvedClaimsExpiresAt
	require.Equal(t, now.Add(15*time.Minute), deadline)
	b.setTokenExchanger(func(context.Context, string, string, string, string, time.Duration, *federatedConfig) (*tokenExchangeResult, error) {
		return nil, fmt.Errorf("%s", loggingClientSecret)
	})
	token := "e30." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"`+loggingClaim+`"}`)) + ".signature"
	resp, err := b.HandleRequest(context.Background(), securityRequest(storage, "exchange", map[string]interface{}{"subject_token": token}))
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, fmt.Sprint(resp.Data["data"]), loggingClaim)
	assertNoCredentialValues(t, output.String(), token)
	now = now.Add(14 * time.Minute)
	loggingConfig(t, b, storage, map[string]interface{}{"default_ttl": 600})
	config, err = b.getConfig(context.Background(), storage)
	require.NoError(t, err)
	require.Equal(t, deadline, config.DebugResolvedClaimsExpiresAt)
	restarted, _, restartOutput := loggingBackend(t, hclog.Trace)
	restarted.now = func() time.Time { return deadline }
	installFailingTokenExchanger(restarted)
	resp, err = restarted.HandleRequest(context.Background(), securityRequest(storage, "exchange", map[string]interface{}{"subject_token": token}))
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.NotContains(t, fmt.Sprint(resp.Data), loggingClaim)
	read, err := restarted.HandleRequest(context.Background(), &logical.Request{Operation: logical.ReadOperation, Path: "config", Storage: storage})
	require.NoError(t, err)
	require.Equal(t, false, read.Data["debug_return_resolved_subject_token_claims"])
	require.Equal(t, deadline.Format(time.RFC3339), read.Data["debug_resolved_subject_token_claims_expires_at"])
	require.Contains(t, restartOutput.String(), "diagnostic_claims_inactive")
	legacy := *config
	legacy.DebugResolvedClaimsExpiresAt = time.Time{}
	require.NoError(t, restarted.saveConfig(context.Background(), storage, &legacy))
	require.False(t, debugClaimsActive(&legacy, deadline))
	loggingConfig(t, restarted, storage, map[string]interface{}{"debug_return_resolved_subject_token_claims": true})
	rearmed, err := restarted.getConfig(context.Background(), storage)
	require.NoError(t, err)
	require.Equal(t, deadline.Add(15*time.Minute), rearmed.DebugResolvedClaimsExpiresAt)
	loggingConfig(t, restarted, storage, map[string]interface{}{"debug_return_resolved_subject_token_claims": false})
	disabled, err := restarted.getConfig(context.Background(), storage)
	require.NoError(t, err)
	require.True(t, disabled.DebugResolvedClaimsExpiresAt.IsZero())
	require.False(t, debugClaimsActive(disabled, deadline))
}
func TestSecurityWarningsAreRateLimitedAndSummarizeSuppression(t *testing.T) {
	b, _, output := loggingBackend(t, hclog.Trace)
	now := time.Now()
	b.now = func() time.Time { return now }
	var workers sync.WaitGroup
	for i := 0; i < 40; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			b.securityEvent(nil, "credential_exchange", true, true, "brokered_signature_invalid")
		}()
	}
	workers.Wait()
	require.Len(t, loggingEvents(t, output), 1)
	now = now.Add(30 * time.Second)
	b.securityEvent(nil, "credential_exchange", true, true, "brokered_signature_invalid")
	events := loggingEvents(t, output)
	require.Len(t, events, 2)
	require.Equal(t, float64(39), events[1]["suppressed_count"])
	// Administrator changes are never suppressed by an attacker-generated warning burst.
	b.securityEvent(nil, "diagnostic_claims_enabled", true, false, "")
	b.securityEvent(nil, "diagnostic_claims_enabled", true, false, "")
	require.Len(t, loggingEvents(t, output), 4)
}

func TestSecurityLogAllowlistRejectsUntrustedFields(t *testing.T) {
	b, _, output := loggingBackend(t, hclog.Trace)
	req := &logical.Request{ID: loggingClientSecret, MountAccessor: loggingClaim + "\n"}
	b.securityEvent(req, "credential_exchange", true, true, loggingClientSecret,
		"error", fmt.Errorf("%s", loggingClientSecret), "config", map[string]string{"secret": loggingClaim},
		"mode", loggingClaim, "subject_source", map[string]string{"secret": loggingClaim},
		"upstream_request_id", loggingSession, "requested_token_type", loggingSession,
		"duration_ms", loggingClientSecret, "expires_at", loggingClaim,
		"changed_fields", []string{loggingClaim, "client_secret"}, "outcome", "failure")
	assertNoCredentialValues(t, output.String())
	events := loggingEvents(t, output)
	require.Len(t, events, 1)
	require.Equal(t, "internal_error", events[0]["reason_code"])
	require.Equal(t, "failure", events[0]["outcome"])
	require.Equal(t, []interface{}{"client_secret"}, events[0]["changed_fields"])
	require.NotContains(t, events[0], "request_id")
	require.NotContains(t, events[0], "mount_accessor")
	require.NotContains(t, events[0], "mode")
	require.NotContains(t, events[0], "config")
	require.NotContains(t, events[0], "error")
	b.securityEvent(req, loggingClientSecret, true, true, "")
	require.Len(t, loggingEvents(t, output), 1)
}
func TestRejectedExchangeInputsDoNotEchoValues(t *testing.T) {
	for _, data := range []map[string]interface{}{
		{"subject_token": loggingClaim, "requested_token_type": loggingClientSecret},
		{"subject_token": loggingClaim, "subject_token_audience": loggingClientSecret},
		{"subject_token": loggingClaim, loggingClientSecret: loggingClaim},
		{"subject_token_audience": loggingClientSecret},
	} {
		b, storage, output := loggingBackend(t, hclog.Trace)
		loggingConfig(t, b, storage, nil)
		installFailingTokenExchanger(b)
		resp, err := b.HandleRequest(context.Background(), securityRequest(storage, "exchange", data))
		require.NoError(t, err)
		require.True(t, resp.IsError())
		assertNoCredentialValues(t, resp.Error().Error())
		assertNoCredentialValues(t, output.String())
	}
}
func TestBrokeredIssuerMismatchIsClassifiedWithoutEchoingClaims(t *testing.T) {
	b, storage, output := loggingBackend(t, hclog.Trace)
	key := generateTestRSAPrivateKey(t)
	loggingConfig(t, b, storage, map[string]interface{}{
		"brokered_subject_token_enabled": true, "subject_token_self_mint_issuer": "https://vault.example",
		"brokered_subject_token_trust_type": "public_keys", "brokered_subject_token_issuer": "https://issuer.example",
		"brokered_subject_token_allowed_audiences": []string{"test-audience"}, "brokered_subject_token_allowed_algs": []string{"RS256"},
		"brokered_subject_token_public_keys": encodeTestPublicKeyPEM(t, &key.PublicKey),
	})
	token := makeSignedTestJWT(t, key, jose.RS256, map[string]interface{}{"iss": loggingClaim, "sub": loggingClientSecret, "aud": "test-audience", "exp": time.Now().Add(time.Hour).Unix()})
	resp, err := b.HandleRequest(context.Background(), securityRequest(storage, "exchange", map[string]interface{}{"subject_token": token}))
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "does not match configured brokered issuer")
	assertNoCredentialValues(t, resp.Error().Error(), token)
	assertNoCredentialValues(t, output.String(), token)
	require.Contains(t, output.String(), "brokered_issuer_mismatch")
}

func TestDiagnosticClaimsAreOmittedWhenExchangeCrossesDeadline(t *testing.T) {
	for _, rejected := range []bool{false, true} {
		t.Run(fmt.Sprintf("rejected=%v", rejected), func(t *testing.T) {
			b, storage, output := loggingBackend(t, hclog.Trace)
			now := time.Now()
			b.now = func() time.Time { return now }
			loggingConfig(t, b, storage, map[string]interface{}{"debug_return_resolved_subject_token_claims": true})
			b.setTokenExchanger(func(context.Context, string, string, string, string, time.Duration, *federatedConfig) (*tokenExchangeResult, error) {
				now = now.Add(15 * time.Minute)
				if rejected {
					return nil, fmt.Errorf("%s", loggingClientSecret)
				}
				return &tokenExchangeResult{AccessToken: loggingSession}, nil
			})
			token := "e30." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"`+loggingClaim+`"}`)) + ".signature"
			resp, err := b.HandleRequest(context.Background(), securityRequest(storage, "exchange", map[string]interface{}{"subject_token": token}))
			require.NoError(t, err)
			require.Equal(t, rejected, resp.IsError())
			require.NotContains(t, fmt.Sprint(resp.Data), loggingClaim)
			require.NotContains(t, output.String(), "diagnostic_claims_returned")
			assertNoCredentialValues(t, output.String(), token)
		})
	}
}
func TestAdministrativeSecurityEventsExcludeConfigurationValues(t *testing.T) {
	b, storage, output := loggingBackend(t, hclog.Trace)
	key := generateTestRSAPrivateKeyPEM(t)
	loggingConfig(t, b, storage, map[string]interface{}{
		"subject_token_self_mint_private_key":        key,
		"debug_return_resolved_subject_token_claims": "true", "debug_allow_brokered_http": true,
	})
	resp, err := b.HandleRequest(context.Background(), securityRequest(storage, "role/developer", map[string]interface{}{"description": loggingClaim}))
	require.NoError(t, err)
	require.False(t, resp.IsError())
	resp, err = b.HandleRequest(context.Background(), securityRequest(storage, "role/developer", map[string]interface{}{"self_mint_custom_claims": `{"sub":"` + loggingClaim + `"}`}))
	require.NoError(t, err)
	require.True(t, resp.IsError())
	for _, path := range []string{"role/developer", "config"} {
		req := securityRequest(storage, path, nil)
		req.Operation = logical.DeleteOperation
		_, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
	}
	names := map[string]bool{}
	for _, event := range loggingEvents(t, output) {
		names[event["event"].(string)] = true
	}
	for _, name := range []string{"configuration_changed", "signing_key_changed", "diagnostic_claims_enabled", "diagnostic_http_enabled", "role_changed", "role_change_failed", "role_deleted", "configuration_deleted"} {
		require.True(t, names[name], "missing event %s", name)
	}
	assertNoCredentialValues(t, output.String(), strings.Split(key, "\n")[1])
}
func TestTrustRefreshEventsExcludeURLsAndErrorDetails(t *testing.T) {
	key := generateTestRSAPrivateKey(t)
	for _, rejected := range []bool{false, true} {
		t.Run(fmt.Sprintf("rejected=%v", rejected), func(t *testing.T) {
			b, _, output := loggingBackend(t, hclog.Trace)
			c := brokeredRemoteTestConfig()
			c.BrokeredSubjectTokenJWKSURL += "/" + loggingClaim
			b.brokeredTransport = brokeredTestTransport(func(*http.Request) (*http.Response, error) {
				if rejected {
					return nil, fmt.Errorf("%s %s", loggingClientSecret, c.BrokeredSubjectTokenJWKSURL)
				}
				return brokeredTestResponse(200, brokeredTestJWKS(t, jose.JSONWebKey{Key: &key.PublicKey})), nil
			})
			req := &logical.Request{ID: loggingRequestID}
			ctx := context.WithValue(context.Background(), exchangeObservationKey{}, &exchangeObservation{request: req})
			_, err := b.cachedBrokeredVerificationKeys(ctx, c, false)
			require.Equal(t, rejected, err != nil)
			events := loggingEvents(t, output)
			require.Len(t, events, 1)
			require.Equal(t, "brokered_trust_refresh", events[0]["event"])
			require.Equal(t, loggingRequestID, events[0]["request_id"])
			if rejected {
				require.Equal(t, "refresh_failed", events[0]["reason_code"])
			}
			assertNoCredentialValues(t, output.String(), c.BrokeredSubjectTokenJWKSURL)
		})
	}
}
