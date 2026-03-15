# Functional Test Plan: OCI Credential Engine Plugin

This document outlines the functional test cases for the HashiCorp Vault OCI Secrets Engine plugin.

## 1. Configuration Path Tests

| ID | Test Case | Input | Expected Result |
|---|---|---|---|
| CFG-01 | Valid minimal config | domain, client_id, secret | Success, defaults applied |
| CFG-02 | Valid full config | + default_ttl, max_ttl, enforce_role_claim_match=true, role_claim_key | Success, all fields stored |
| CFG-03 | Config without required field | Missing client_secret | Error: missing required field |
| CFG-04 | Config with invalid URL | domain_url="not-a-url" | Error: invalid URL format |
| CFG-05 | Config read returns secrets masked | Write config, then read | client_secret not in response |
| CFG-06 | Config update | Overwrite existing config | New values persisted |
| CFG-07 | Config delete | Delete after creation | Config removed, subsequent read fails |
| CFG-08 | role_claim_key without enforcement | Set role_claim_key while enforce_role_claim_match=false | Error: role_claim_key requires enforce_role_claim_match=true |
| CFG-09 | strict_role_name_match enabled | Set strict_role_name_match=true | Success, strict role-name validation enabled |
| CFG-10 | allow_plugin_identity_fallback disabled | Set allow_plugin_identity_fallback=false | Success, subject_token becomes required unless changed |
| CFG-11 | self-mint enabled without private key | Set subject_token_self_mint_enabled=true, issuer set, omit private key | Success, plugin auto-generates and stores RSA signing key |
| CFG-12 | allowlisted plugin-issued audiences configured | Set subject_token_allowed_audiences | Success, allowed plugin-issued audiences persisted |

## 2. Roles Path Tests

| ID | Test Case | Input | Expected Result |
|---|---|---|---|
| ROL-01 | Create role minimal | name="dev", default_ttl=1h | Success |
| ROL-02 | Create role full | + description, max_ttl, allowed_groups, allowed_subjects | Success |
| ROL-03 | Read role | Read existing role | All fields returned |
| ROL-04 | List roles | Create 3 roles, list | All 3 names returned |
| ROL-05 | Update role | Change TTL on existing role | New values persisted |
| ROL-06 | Delete role | Delete existing role | Role removed |
| ROL-07 | Role with TTL exceeding config max | role.max_ttl > config.max_ttl | Role creation succeeds; TTL clamped at exchange time |
| ROL-08 | Role with invalid name (default mode) | Empty name | Error |
| ROL-09 | Role with special chars (strict mode off) | name includes `@` or space | Success |
| ROL-10 | Role with invalid chars (strict mode on) | strict_role_name_match=true, name includes `@` or space | Error |

## 3. Exchange Path - Basic Flows

| ID | Test Case | Input | Expected Result |
|---|---|---|---|
| EXC-01 | Exchange for UPST (default) | subject_token, role | UPST token returned |
| EXC-02 | Exchange for RPST | + requested_token_type=oci-rpst, res_type | RPST token returned |
| EXC-03 | Exchange with explicit UPST type | requested_token_type=oci-upst | UPST token returned |
| EXC-04 | Exchange without subject_token (plugin-issued mode enabled) | role only, omit subject_token, enforce=false, allow_plugin_identity_fallback=true | Uses plugin-issued subject-token mode (Vault identity token first; self-mint if configured) |
| EXC-05 | Exchange with TTL override | ttl < role.default_ttl | Custom TTL applied |
| EXC-06 | Exchange with public_key provided | public_key in request | No private_key in response |
| EXC-07 | Exchange without subject_token (plugin-issued mode disabled) | omit subject_token, allow_plugin_identity_fallback=false | Error: missing subject_token and plugin-issued mode disabled |
| EXC-08 | Exchange without subject_token (enforcement enabled, no role) | omit subject_token, enforce_role_claim_match=true, no role | Error: missing role while enforcement enabled |
| EXC-09 | Exchange without subject_token (enforcement enabled, role set) | omit subject_token, enforce_role_claim_match=true, role set | Uses plugin-issued token; role-claim enforcement is skipped because no caller-provided JWT was supplied |
| EXC-10 | Exchange without subject_token (allowlisted audience override) | omit subject_token, set subject_token_audience to allowed value | Plugin-issued token uses requested audience |
| EXC-11 | Exchange with disallowed audience override | omit subject_token, set subject_token_audience to unlisted value | Error: audience override not allowed |
| EXC-12 | Exchange with subject_token_audience and caller-provided JWT | subject_token and subject_token_audience set | Error: audience override only applies to plugin-issued tokens |

## 4. Exchange Path - Token Content Validation

These cases are primarily OCI-behavior or end-to-end validation scenarios unless explicitly covered by local claim-parsing tests.

| ID | Test Case | Input | Expected Result |
|---|---|---|---|
| EXC-20 | Valid JWT exchange | Valid subject_token from external IdP | Valid UPST returned with lease |
| EXC-21 | Expired JWT | subject_token expired | Error from OCI IAM / trust evaluation |
| EXC-22 | Invalid JWT signature | Tampered subject_token | Error from OCI IAM / trust evaluation |
| EXC-23 | Wrong audience in JWT | JWT aud doesn't match OCI client | Error from OCI IAM |
| EXC-24 | Missing required claims | JWT missing claims required by OCI trust | Error from OCI IAM / trust evaluation |

## 5. Role Claim Matching (Security)

| ID | Test Case | Input | Expected Result |
|---|---|---|---|
| RCM-01 | Matching role claim | enforce=true, role_claim_key="vault_role", JWT claim matches requested role | Success |
| RCM-02 | Mismatched role claim | enforce=true, JWT claim="admin", request role="dev" | Error: role claim mismatch |
| RCM-03 | Missing claim key | enforce=true, JWT doesn't have role_claim_key | Error: required claim missing |
| RCM-04 | Enforcement disabled | enforce=false, mismatched claims | Success (no enforcement) |
| RCM-05 | String array claim matching | enforce=true, claim value is array containing requested role | Success |
| RCM-06 | Invalid claim array content | enforce=true, claim array contains non-string/empty values | Error |
| RCM-07 | Strict role name match in exchange | strict_role_name_match=true, role contains invalid chars | Error |

## 6. Lease & TTL Management

Current automated coverage is limited to TTL selection and clamping during exchange response creation. Lease renewal/revocation lifecycle tests are not yet implemented.

| ID | Test Case | Input | Expected Result |
|---|---|---|---|
| TTL-01 | Default TTL applied | No TTL specified | Uses role.default_ttl |
| TTL-02 | Request TTL clamped to max | Request TTL > role.max_ttl | Clamped to max |
| TTL-03 | Lease renewal | Renew valid lease | Deferred: handler behavior not yet covered by automated tests |
| TTL-04 | Lease revocation | Revoke lease | Deferred: local lease cleanup behavior not yet covered by automated tests |
| TTL-05 | Lease expiration | Wait for TTL | Deferred: time-based expiry behavior not yet covered by automated tests |

## 7. JWKS Path

| ID | Test Case | Input | Expected Result |
|---|---|---|---|
| JWK-01 | Read JWKS without config | `vault read oci/jwks` | Error: backend not configured |
| JWK-02 | Read JWKS when self-mint disabled | self-mint disabled | Error: subject_token_self_mint_enabled is false |
| JWK-03 | Read JWKS when self-mint enabled | self-mint enabled (auto key or supplied key) | Returns RFC-compatible RSA JWKS with `kid`, `n`, `e` |

## 8. Self-Mint Claim Contract

| ID | Test Case | Input | Expected Result |
|---|---|---|---|
| CLM-01 | Self-mint uses Vault-derived subject | plugin-issued self-mint with `EntityID` present | `sub` is derived from Vault identity, not request `role` |
| CLM-02 | Self-mint includes entity and alias claims | plugin-issued self-mint with entity/alias metadata available | JWT contains stable Vault-derived identity claims |
| CLM-03 | Self-mint excludes caller role selector | request includes `role` during plugin-issued self-mint | JWT does not contain `vault_role` or request `role` claim |

## 9. OCI API Integration (Mock/Real)

| ID | Test Case | Input | Expected Result |
|---|---|---|---|
| OCI-01 | Successful token exchange | Valid config + valid JWT | OCI returns UPST with access_token |
| OCI-02 | OCI IAM unavailable | Network failure to domain_url | Error: OCI IAM unreachable |
| OCI-03 | Invalid OCI client credentials | Wrong client_secret | Error: authentication failed |
| OCI-04 | Direct OCI token endpoint | domain_url="https://idcs-xxx.identity.oraclecloud.com" | Correct `/oauth2/v1/token` endpoint used |

## 10. End-to-End Workflows

| ID | Test Case | Steps |
|---|---|---|
| E2E-01 | Full Vault-Issued Token Flow | 1. Configure Vault identity token or plugin-issued self-mint mode<br>2. Configure OCI trust against Vault-derived claims<br>3. Invoke exchange via plugin without caller-supplied subject_token<br>4. Verify OCI UPST received |
| E2E-02 | External IdP to OCI | 1. Configure plugin with OCI domain<br>2. Get JWT from Auth0/Okta<br>3. Exchange via plugin<br>4. Use UPST with OCI CLI |
| E2E-03 | Multi-tenant setup | 1. Enable multiple plugin mounts (oci-tenant1, oci-tenant2)<br>2. Different configs per mount<br>3. Tokens isolated per tenant |

## Automated Coverage Snapshot

Currently covered by automated tests:
- `CFG-01`, `CFG-02`, `CFG-03`, `CFG-05`, `CFG-07`, `CFG-08`, `CFG-09`, `CFG-10`, `CFG-11`
- `CFG-12`
- `ROL-01`, `ROL-02`, `ROL-03`, `ROL-04`, `ROL-06`, `ROL-08`, `ROL-10`
- `EXC-04`, `EXC-07`, `EXC-08`, `EXC-09`, `EXC-10`, `EXC-11`, `EXC-12`
- Requested token-type validation for unsupported values and RPST missing `res_type`
- `RCM-01`, `RCM-02`, `RCM-03`, `RCM-05`, `RCM-06`, `RCM-07`
- `TTL-01`, `TTL-02`
- `CLM-01`, `CLM-02`, `CLM-03`
- `JWK-01`, `JWK-02`, `JWK-03`
- `OCI-01`, `OCI-03`

Covered partially or indirectly:
- `EXC-01`, `EXC-02`, `EXC-03`, `EXC-06`
  These are covered at the OCI client integration layer rather than as full `path_exchange` success-path tests.
- `RCM-04`
  Enforcement-disabled behavior is implicit in exchange tests that proceed without guardrail checks, but there is no named dedicated test case.

Not yet covered by automated tests:
- `CFG-04`, `CFG-06`
- `ROL-05`, `ROL-07`, `ROL-09`
- `EXC-05`
- `EXC-20`, `EXC-21`, `EXC-22`, `EXC-23`, `EXC-24`
- `TTL-03`, `TTL-04`, `TTL-05`
- `OCI-02`, `OCI-04`
- `E2E-01`, `E2E-02`, `E2E-03`

## Priority Matrix

### MVP Tests (Must Have)
- **CFG-01, CFG-05** - Basic config write/read
- **ROL-01, ROL-03** - Basic role create/read
- **EXC-01, EXC-10** - Basic exchange success
- **RCM-01, RCM-02** - Role claim enforcement
- **TTL-01** - Default TTL behavior

### Error Handling (Should Have)
- **CFG-03, CFG-04** - Config validation errors
- **EXC-21, EXC-22, EXC-23, EXC-24** - Token validation errors
- **RCM-03, RCM-04, RCM-06** - Claim matching edge cases

### Advanced Features (Nice to Have)
- **E2E-02** - External IdP integration
- **OCI-04** - Direct domain token endpoint support
- **EXC-04** - Plugin-issued subject-token flow
- **E2E-03** - Multi-tenant isolation

## Running Tests

### Manual Testing

```bash
# Set environment
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='root'

# Test config (CFG-01)
vault write oci/config \
    domain_url="https://idcs-test.identity.oraclecloud.com" \
    client_id="ocid1.oauth2client.oc1..test" \
    client_secret="test-secret"

# Test read (CFG-05)
vault read oci/config

# Test role create (ROL-01)
vault write oci/roles/dev default_ttl=3600 max_ttl=7200

# Test role read (ROL-03)
vault read oci/roles/dev
```

### Automated Testing

Current coverage includes:
- Unit tests in `oci-backend/*_test.go` for config, roles, claim enforcement, plugin-issued subject-token flow, self-mint, and JWKS behavior
- Integration tests in [oci_client_integration_test.go](/Users/gordon/Documents/projects/Hashicorp-OCI-credential-engine/oci-backend/oci_client_integration_test.go) for mock OCI token exchange behavior

Future additions:
- Broader `path_exchange` success-path integration tests
- Lease lifecycle tests
- End-to-end tests with test OCI tenancy

## Notes

- OCI IAM tokens cannot be actively revoked server-side; Vault lease revocation only drops local tracking
- `client_secret` is write-only and never returned on read
- `enforce_role_claim_match` can use default `role_claim_key` (`vault_role`) unless overridden
- If `enforce_role_claim_match=true`, it applies to caller-provided `subject_token` values; plugin-issued tokens are evaluated under the plugin-issued/self-mint trust model instead
- `subject_token_audience` is accepted only when `subject_token` is omitted and the requested audience is present in `subject_token_allowed_audiences`
- If `allow_plugin_identity_fallback=false`, callers must supply `subject_token`
