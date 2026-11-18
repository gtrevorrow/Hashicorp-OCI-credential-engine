package ocibackend

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

const diagnosticClaimsWindow = 15 * time.Minute
const securityWarningInterval = 30 * time.Second

// Only fixed event/reason names and explicitly selected metadata reach the logger.
// In particular, error strings and request/config/response objects are never fields.
type securityWarning struct {
	last       time.Time
	suppressed uint64
}
type securityLogState struct {
	mu       sync.Mutex
	warnings map[string]securityWarning
}
type exchangeObservation struct {
	started                               time.Time
	request                               *logical.Request
	mode, source, role, tokenType, reason string
	status                                int
	upstreamID                            string
}

func roleSecurityFields(name string) []interface{} {
	if safeRoleLogValue.MatchString(name) {
		return []interface{}{"effective_role", name}
	}
	return nil
}

type exchangeObservationKey struct{}

var safeRoleLogValue = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
var safeMountLogValue = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
var safeUUID = regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$`)
var safeOCIRequestID = regexp.MustCompile(`^[a-fA-F0-9]{16,64}(/[a-fA-F0-9]{16,64}){0,2}$`)

func (b *backend) securityNow() time.Time {
	if b.now != nil {
		return b.now()
	}
	return time.Now()
}
func debugClaimsActive(c *federatedConfig, now time.Time) bool {
	return c != nil && c.DebugReturnResolvedSubjectTokenClaims && !c.DebugResolvedClaimsExpiresAt.IsZero() && now.Before(c.DebugResolvedClaimsExpiresAt)
}
func validatedOCIRequestID(value string) string {
	if len(value) <= 194 && (safeUUID.MatchString(value) || safeOCIRequestID.MatchString(value)) {
		return value
	}
	return ""
}
func requestSecurityFields(req *logical.Request) []interface{} {
	fields := []interface{}{}
	if req != nil {
		if safeUUID.MatchString(req.ID) {
			fields = append(fields, "request_id", req.ID)
		}
		if safeMountLogValue.MatchString(req.MountAccessor) {
			fields = append(fields, "mount_accessor", req.MountAccessor)
		}
	}
	return fields
}
func (b *backend) securityEvent(req *logical.Request, event string, warning, limit bool, reason string, fields ...interface{}) {
	if !permittedSecurityEvent(event) {
		return
	}
	if !permittedSecurityReason(reason) {
		reason = "internal_error"
	}
	logger := b.logger
	if b.Backend != nil {
		logger = b.Backend.Logger()
	}
	if logger == nil {
		return
	}
	args := append([]interface{}{"event", event}, requestSecurityFields(req)...)
	if reason != "" {
		args = append(args, "reason_code", reason)
	}
	if warning && limit {
		now := b.securityNow()
		key := event + "/" + reason // private callers supply fixed, finite names only
		b.securityLogs.mu.Lock()
		if b.securityLogs.warnings == nil {
			b.securityLogs.warnings = make(map[string]securityWarning)
		}
		previous, exists := b.securityLogs.warnings[key]
		if exists && now.Sub(previous.last) < securityWarningInterval {
			previous.suppressed++
			b.securityLogs.warnings[key] = previous
			b.securityLogs.mu.Unlock()
			return
		}
		b.securityLogs.warnings[key] = securityWarning{last: now}
		b.securityLogs.mu.Unlock()
		if previous.suppressed > 0 {
			args = append(args, "suppressed_count", previous.suppressed)
		}
	}
	args = append(args, b.permittedSecurityFields(fields)...)
	if warning {
		logger.Warn("OCI security event", args...)
	} else {
		logger.Info("OCI security event", args...)
	}
}
func (b *backend) finishExchange(req *logical.Request, observed *exchangeObservation, resp *logical.Response, err error) {
	failed := err != nil || (resp != nil && resp.IsError())
	outcome := "success"
	if failed {
		outcome = "failure"
		if observed.reason == "" {
			observed.reason = "internal_error"
		}
	}
	fields := []interface{}{"outcome", outcome, "mode", observed.mode, "subject_source", observed.source, "duration_ms", b.securityNow().Sub(observed.started).Milliseconds()}
	if safeRoleLogValue.MatchString(observed.role) {
		fields = append(fields, "effective_role", observed.role)
	}
	if isSupportedRequestedTokenType(observed.tokenType) {
		fields = append(fields, "requested_token_type", observed.tokenType)
	}
	if observed.status >= 100 && observed.status <= 599 {
		fields = append(fields, "upstream_status", observed.status)
	}
	if id := validatedOCIRequestID(observed.upstreamID); id != "" {
		fields = append(fields, "upstream_request_id", id)
	}
	b.securityEvent(req, "credential_exchange", failed, failed, observed.reason, fields...)
}
func observedSource(ctx context.Context, source string) {
	if observed, ok := ctx.Value(exchangeObservationKey{}).(*exchangeObservation); ok {
		observed.source = source
	}
}
func exchangeFailure(observed *exchangeObservation, reason, message string) (*logical.Response, error) {
	observed.reason = reason
	return logical.ErrorResponse("%s", message), nil
}

// A classified failure carries a fixed public message, never the original error.
type classifiedFailure struct{ reason, message string }

func (e *classifiedFailure) Error() string { return e.message }
func failure(reason, message string) error {
	return &classifiedFailure{reason: reason, message: message}
}
func failureReason(err error, fallback string) string {
	var classified *classifiedFailure
	if errors.As(err, &classified) {
		return classified.reason
	}
	return fallback
}

type ociExchangeError struct {
	reason, code, requestID string
	status                  int
}

func (e *ociExchangeError) Error() string {
	reason := e.reason
	if !permittedSecurityReason(reason) || reason == "" {
		reason = "oci_exchange_failed"
	}
	message := fmt.Sprintf("unable to exchange JWT for security token: %s", reason)
	if e.status >= 100 && e.status <= 599 {
		message += fmt.Sprintf(" (status %d)", e.status)
	}
	if code := allowedOAuthError(e.code); code != "" {
		message += "; OAuth error: " + code
	}
	if id := validatedOCIRequestID(e.requestID); id != "" {
		message += "; request_id: " + id
	}
	return message
}
func allowedOAuthError(code string) string {
	switch code {
	case "invalid_request", "invalid_client", "invalid_grant", "unauthorized_client", "unsupported_grant_type", "unsupported_token_type", "invalid_target", "access_denied", "server_error", "temporarily_unavailable":
		return code
	}
	return ""
}
func safeExchangeError(err error) *ociExchangeError {
	var upstream *ociExchangeError
	if errors.As(err, &upstream) {
		return upstream
	}
	return &ociExchangeError{reason: "oci_exchange_failed"}
}
func (b *backend) logConfigChange(req *logical.Request, before, after *federatedConfig) {
	// Names come from the endpoint schema, not arbitrary user-supplied map keys.
	known := b.pathConfig()[0].Fields
	fields := make([]string, 0)
	for name := range req.Data {
		if _, ok := known[name]; ok {
			fields = append(fields, name)
		}
	}
	sort.Strings(fields)
	b.securityEvent(req, "configuration_changed", false, false, "", "changed_fields", fields)
	if (before == nil && after.SubjectTokenSelfMintPrivateKey != "") || (before != nil && before.SubjectTokenSelfMintPrivateKey != after.SubjectTokenSelfMintPrivateKey) {
		b.securityEvent(req, "signing_key_changed", true, false, "")
	}
	if _, present := req.Data["debug_return_resolved_subject_token_claims"]; present && after.DebugReturnResolvedSubjectTokenClaims {
		b.securityEvent(req, "diagnostic_claims_enabled", true, false, "", "expires_at", after.DebugResolvedClaimsExpiresAt.UTC().Format(time.RFC3339))
	}
	if _, present := req.Data["debug_allow_brokered_http"]; present && after.DebugAllowBrokeredHTTP {
		b.securityEvent(req, "diagnostic_http_enabled", true, false, "")
	}
}

func publicFailureMessage(err error, fallback string) string {
	var classified *classifiedFailure
	if errors.As(err, &classified) {
		return classified.message
	}
	return fallback
}

func permittedSecurityEvent(event string) bool {
	switch event {
	case "credential_exchange", "configuration_changed", "configuration_change_failed", "configuration_deleted", "role_changed", "role_deleted", "role_change_failed", "signing_key_changed", "diagnostic_claims_enabled", "diagnostic_claims_inactive", "diagnostic_claims_returned", "diagnostic_http_enabled", "brokered_trust_refresh":
		return true
	}
	return false
}
func permittedSecurityReason(reason string) bool {
	switch reason {
	case "", "internal_error", "request_invalid", "ttl_invalid", "not_configured", "subject_token_empty", "token_type_invalid", "resource_type_missing", "role_path_disallowed", "subject_token_required", "audience_invalid", "subject_source_unavailable", "subject_resolution_failed", "subject_source_empty", "audience_disallowed", "claim_mapping_failed", "brokered_signing_failed", "role_mapping_failed", "role_invalid", "role_missing", "role_unavailable", "role_cleanup_required", "storage_error", "oci_exchange_failed", "oci_request_invalid", "oci_timeout", "request_canceled", "oci_transport_error", "oci_response_read_failed", "oci_response_too_large", "oci_rejected", "oci_response_invalid", "oci_token_missing", "oci_expiry_invalid", "brokered_validation_failed", "brokered_token_too_large", "brokered_token_invalid", "brokered_algorithm_disallowed", "brokered_trust_unavailable", "brokered_signature_invalid", "brokered_claims_invalid", "brokered_issuer_invalid", "brokered_issuer_mismatch", "brokered_token_expired", "brokered_token_not_yet_valid", "brokered_audience_invalid", "brokered_audience_mismatch", "request_rejected", "refresh_failed", "enabled", "expired_or_unarmed":
		return true
	}
	return false
}
func (b *backend) permittedSecurityFields(fields []interface{}) []interface{} {
	out := []interface{}{}
	for i := 0; i+1 < len(fields); i += 2 {
		name, ok := fields[i].(string)
		if !ok {
			continue
		}
		value := fields[i+1]
		switch name {
		case "outcome":
			value, ok := value.(string)
			if !ok {
				continue
			}
			if value == "success" || value == "failure" {
				out = append(out, name, value)
			}
		case "mode":
			value, ok := value.(string)
			if !ok {
				continue
			}
			if value == "undetermined" || value == "direct" || value == "brokered" || value == "plugin_issued" {
				out = append(out, name, value)
			}
		case "subject_source":
			value, ok := value.(string)
			if !ok {
				continue
			}
			if value == "unavailable" || value == "caller" || value == "vault_identity" || value == "self_mint" || value == "custom_callback" || value == "brokered_reissue" {
				out = append(out, name, value)
			}
		case "effective_role":
			if text, ok := value.(string); ok && safeRoleLogValue.MatchString(text) {
				out = append(out, name, text)
			}
		case "requested_token_type":
			if text, ok := value.(string); ok && isSupportedRequestedTokenType(text) {
				out = append(out, name, text)
			}
		case "duration_ms":
			if duration, ok := value.(int64); ok {
				if duration < 0 {
					duration = 0
				}
				out = append(out, name, duration)
			}
		case "upstream_status":
			if status, ok := value.(int); ok && status >= 100 && status <= 599 {
				out = append(out, name, status)
			}
		case "upstream_request_id":
			if text, ok := value.(string); ok {
				if id := validatedOCIRequestID(text); id != "" {
					out = append(out, name, id)
				}
			}
		case "expires_at":
			if text, ok := value.(string); ok {
				if parsed, err := time.Parse(time.RFC3339, text); err == nil {
					out = append(out, name, parsed.UTC().Format(time.RFC3339))
				}
			}
		case "changed_fields":
			if names, ok := value.([]string); ok {
				known := b.pathConfig()[0].Fields
				accepted := make([]string, 0, len(known))
				for field := range known {
					for _, name := range names {
						if field == name {
							accepted = append(accepted, field)
							break
						}
					}
				}
				sort.Strings(accepted)
				out = append(out, name, accepted)
			}
		}
	}
	return out
}
