# Security Logging and Diagnostics

[README](../README.md) · [Access controls](security.md) · [Configuration](configuration.md) · [Validation](../TEST_PLAN.md#security-logging-and-diagnostic-verification)

Vault audit devices provide the request/response audit trail. The plugin also emits structured operational events for exchange outcomes and administrative changes. These events help explain behavior without recording credentials; they are subject to log levels, warning suppression, and the availability of the server's log collector. They do not replace Vault audit devices.

## Operational events

The plugin writes JSON logs to stderr so Vault can preserve their levels and structured fields. Configure the plugin's minimum level with `VAULT_OCI_LOG_LEVEL`; Vault's server logging configuration also affects visibility. INFO includes successful exchanges and configuration/role changes. WARN includes failed exchanges, trust refresh failures, signing-key changes, and diagnostic activity. Raising the threshold above WARN hides these events.

| Event | Meaning |
|---|---|
| `credential_exchange` | Exchange completed with `outcome=success` or `failure` |
| `configuration_changed`, `configuration_deleted` | Config write/delete completed; writes list recognized submitted field names in `changed_fields`, never values |
| `configuration_change_failed` | Config write/delete failed |
| `role_changed`, `role_deleted`, `role_change_failed` | Role write/delete outcome |
| `signing_key_changed` | Issuer signing key was created, replaced, or cleared by a config write |
| `brokered_trust_refresh` | A remote verification-key refresh succeeded or failed; cache hits emit no refresh event |
| `diagnostic_claims_enabled` | An explicit config write armed a diagnostic window; includes `expires_at` |
| `diagnostic_claims_returned`, `diagnostic_claims_inactive` | An exchange returned diagnostic claims, or encountered an expired/unarmed diagnostic flag |
| `diagnostic_http_enabled` | A config write explicitly enabled loopback HTTP trust retrieval |

Exchange events include a fixed mode (`direct`, `brokered`, `plugin_issued`, or `undetermined`), subject source, duration in milliseconds, and a fixed `reason_code` on failure. Additional fields are included when available: Vault `request_id`, `mount_accessor`, successfully loaded `effective_role`, supported `requested_token_type`, `upstream_status`, and validated `upstream_request_id`. Source values distinguish `caller`, `brokered_reissue`, `vault_identity`, `self_mint`, `custom_callback`, and `unavailable`. Early validation failures may leave the mode/source undetermined/unavailable.

All event names, reasons, field names, enum values and identifier formats are allowlisted. Events exclude JWTs, identity claims, credentials, private/public keys, endpoint URLs, raw errors, and config/request/response objects, at every log level. Role names are operational metadata: use non-sensitive identifiers; names outside `[A-Za-z0-9._:-]{1,128}` are omitted. OCI request IDs are accepted only as UUIDs or bounded hexadecimal segments; other values are omitted.

Repeated failure/diagnostic warnings are limited to one per event/reason per mount every 30 seconds. The next matching warning after that interval includes `suppressed_count` when warnings were suppressed. Counters are in memory and reset on plugin restart; a quiet interval does not itself emit a summary. Successful exchanges and administrative changes are not rate limited. Vault audit records are unaffected. Use the audit trail for complete per-request accounting, including requests rejected by Vault before reaching the plugin.

## Errors returned to clients

OCI errors expose a fixed category such as `oci_rejected`, `oci_timeout`, or `oci_response_invalid`, plus HTTP status, an allowlisted standard OAuth error code, and a validated OCI request ID when available. The plugin never forwards the raw token-endpoint body or `error_description`. Unknown transport and callback errors become fixed messages. Exchange validation errors do not echo rejected input values; brokered verification failures do not echo token claims.

Clients should check the error outcome rather than parse earlier free-form error messages. Correlate the Vault request ID with operational/audit records and the OCI request ID with upstream diagnostics. This intentionally reduces detail in client errors that could otherwise be copied into logs or support bundles.

## Temporary claim diagnostics

`debug_return_resolved_subject_token_claims` defaults to false. An explicit write of `true` enables decoded resolved-token claims in exchange responses for **15 minutes**, and returns a warning. The deadline is persisted; restarting the plugin or updating unrelated fields does not renew it. Explicitly writing `true` again starts a new window. Writing `false` disables it and clears the deadline.

```bash
vault write oci/config debug_return_resolved_subject_token_claims=true
vault read oci/config
# Disable as soon as troubleshooting is complete.
vault write oci/config debug_return_resolved_subject_token_claims=false
```

Config reads report the effective flag and the read-only RFC3339 `debug_resolved_subject_token_claims_expires_at` when set, including an elapsed deadline. Older stored flags without a deadline are inactive until explicitly re-enabled. Claims are checked again before returning a response, so a request that crosses the deadline omits them. A concurrent config disable applies to subsequent requests; it cannot recall an in-flight request's config snapshot.

While active, this option intentionally discloses claims to the exchange caller, including on OCI rejection. Restrict config writes, use only controlled development/troubleshooting sessions, and protect response capture. It does not add claim values to operational events. Loopback HTTP debugging is a separate setting and has no automatic expiry.

## Vault audit configuration

Enable audit devices explicitly. Keep sensitive request/response strings HMACed: leave `log_raw=false` and avoid mount `audit_non_hmac_request_keys` / `audit_non_hmac_response_keys` exceptions for credentials or claims. Do not weaken audit hashing to obtain readable error classifications; use the safe operational events. HMAC does not hide field names or non-string values. See [Vault audit logging](https://developer.hashicorp.com/vault/docs/audit).

HashiCorp recommends two audit devices of different types with remote forwarding, combined analysis across devices, and monitoring/rotation appropriate to the deployment. Restrict access and retention for both operational and audit logs. Test device failure behavior before production rollout. See [audit logging best practices](https://developer.hashicorp.com/vault/docs/audit/best-practices).

The opt-in local acceptance test builds the plugin, starts a disposable Vault with a synthetic TLS OCI endpoint, and checks success/failure events and default audit HMAC handling for canary credentials. It does not configure an existing Vault or use an OCI account. Run it as described in [CONTRIBUTING](../CONTRIBUTING.md#local-vault-audit-acceptance).
