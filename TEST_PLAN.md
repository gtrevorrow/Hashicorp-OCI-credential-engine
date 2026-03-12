# Functional Test Plan: OCI Credential Engine Plugin

This document outlines the functional test cases for the HashiCorp Vault OCI Secrets Engine plugin.

## 1. Configuration Path Tests

| ID | Test Case | Input | Expected Result |
|---|---|---|---|
| CFG-01 | Valid minimal config | tenancy, domain, client_id, secret, region | Success, defaults applied |
| CFG-02 | Valid full config | + default_ttl, max_ttl, enforce_role_claim_match=true, role_claim_key | Success, all fields stored |
| CFG-03 | Config without required field | Missing tenancy_ocid | Error: missing required field |
| CFG-04 | Config with invalid URL | domain_url="not-a-url" | Error: invalid URL format |
| CFG-05 | Config read returns secrets masked | Write config, then read | client_secret not in response |
| CFG-06 | Config update | Overwrite existing config | New values persisted |
| CFG-07 | Config delete | Delete after creation | Config removed, subsequent read fails |
| CFG-08 | role_claim_key without enforcement | Set role_claim_key while enforce_role_claim_match=false | Error: role_claim_key requires enforce_role_claim_match=true |
| CFG-09 | strict_role_name_match enabled | Set strict_role_name_match=true | Success, strict role-name validation enabled |
| CFG-10 | allow_plugin_identity_fallback disabled | Set allow_plugin_identity_fallback=false | Success, subject_token becomes required unless changed |
| CFG-11 | self-mint enabled without private key | Set subject_token_self_mint_enabled=true, issuer set, omit private key | Success, plugin auto-generates and stores RSA signing key |

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
| EXC-01 | Exchange for UPST (default) | subject_token, subject_token_type, role | UPST token returned |
| EXC-02 | Exchange for RPST | + requested_token_type=oci-rpst, res_type | RPST token returned |
| EXC-03 | Exchange with explicit UPST type | requested_token_type=oci-upst | UPST token returned |
| EXC-04 | Exchange without subject_token (fallback enabled) | role only, omit subject_token, enforce=false, allow_plugin_identity_fallback=true | Uses callback fallback (Vault identity token first; self-mint if configured) |
| EXC-05 | Exchange with TTL override | ttl < role.default_ttl | Custom TTL applied |
| EXC-06 | Exchange with public_key provided | public_key in request | No private_key in response |
| EXC-07 | Exchange without subject_token (fallback disabled) | omit subject_token, allow_plugin_identity_fallback=false | Error: missing subject_token and fallback disabled |
| EXC-08 | Exchange without subject_token (enforcement enabled, no role) | omit subject_token, enforce_role_claim_match=true, no role | Error: missing role while enforcement enabled |
| EXC-09 | Exchange without subject_token (enforcement enabled, role set) | omit subject_token, enforce_role_claim_match=true, role set | Uses fallback token and enforces role claim match |

## 4. Exchange Path - Token Content Validation

| ID | Test Case | Input | Expected Result |
|---|---|---|---|
| EXC-10 | Valid JWT exchange | Valid subject_token from external IdP | Valid UPST returned with lease |
| EXC-11 | Expired JWT | subject_token expired | Error: token expired |
| EXC-12 | Invalid JWT signature | Tampered subject_token | Error: invalid signature |
| EXC-13 | Wrong audience in JWT | JWT aud doesn't match OCI client | Error from OCI IAM |
| EXC-14 | Missing required claims | JWT missing sub, iss, etc. | Error: missing claims |

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

| ID | Test Case | Input | Expected Result |
|---|---|---|---|
| TTL-01 | Default TTL applied | No TTL specified | Uses role.default_ttl |
| TTL-02 | Request TTL clamped to max | Request TTL > role.max_ttl | Clamped to max |
| TTL-03 | Lease renewal | Renew valid lease | Extended lease |
| TTL-04 | Lease revocation | Revoke lease | Token invalidated in Vault (local only) |
| TTL-05 | Lease expiration | Wait for TTL | Lease expires, token no longer valid |

## 7. JWKS Path

| ID | Test Case | Input | Expected Result |
|---|---|---|---|
| JWK-01 | Read JWKS without config | `vault read oci/jwks` | Error: backend not configured |
| JWK-02 | Read JWKS when self-mint disabled | self-mint disabled | Error: subject_token_self_mint_enabled is false |
| JWK-03 | Read JWKS when self-mint enabled | self-mint enabled (auto key or supplied key) | Returns RFC-compatible RSA JWKS with `kid`, `n`, `e` |

## 8. OCI API Integration (Mock/Real)

| ID | Test Case | Input | Expected Result |
|---|---|---|---|
| OCI-01 | Successful token exchange | Valid config + valid JWT | OCI returns UPST with access_token |
| OCI-02 | OCI IAM unavailable | Network failure to domain_url | Error: OCI IAM unreachable |
| OCI-03 | Invalid OCI client credentials | Wrong client_secret | Error: authentication failed |
| OCI-04 | Different OCI regions | region="eu-frankfurt-1" | Correct regional endpoint used |

## 9. End-to-End Workflows

| ID | Test Case | Steps |
|---|---|---|
| E2E-01 | Full Vault-Issued Token Flow | 1. Configure Vault OIDC key<br>2. Create token role with vault_role claim<br>3. Mint identity token<br>4. Exchange via plugin<br>5. Verify OCI UPST received |
| E2E-02 | External IdP to OCI | 1. Configure plugin with OCI domain<br>2. Get JWT from Auth0/Okta<br>3. Exchange via plugin<br>4. Use UPST with OCI CLI |
| E2E-03 | Multi-tenant setup | 1. Enable multiple plugin mounts (oci-tenant1, oci-tenant2)<br>2. Different configs per mount<br>3. Tokens isolated per tenant |

## Priority Matrix

### MVP Tests (Must Have)
- **CFG-01, CFG-05** - Basic config write/read
- **ROL-01, ROL-03** - Basic role create/read
- **EXC-01, EXC-10** - Basic exchange success
- **RCM-01, RCM-02** - Role claim enforcement
- **TTL-01** - Default TTL behavior

### Error Handling (Should Have)
- **CFG-03, CFG-04** - Config validation errors
- **EXC-11, EXC-12, EXC-13, EXC-14** - Token validation errors
- **RCM-03, RCM-04, RCM-06** - Claim matching edge cases

### Advanced Features (Nice to Have)
- **E2E-02** - External IdP integration
- **OCI-04** - Multi-region support
- **EXC-04** - Callback fallback flow
- **E2E-03** - Multi-tenant isolation

## Running Tests

### Manual Testing

```bash
# Set environment
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='root'

# Test config (CFG-01)
vault write oci/config \
    tenancy_ocid="ocid1.tenancy.oc1..test" \
    domain_url="https://idcs-test.identity.oraclecloud.com" \
    client_id="ocid1.oauth2client.oc1..test" \
    client_secret="test-secret" \
    region="us-ashburn-1"

# Test read (CFG-05)
vault read oci/config

# Test role create (ROL-01)
vault write oci/roles/dev default_ttl=3600 max_ttl=7200

# Test role read (ROL-03)
vault read oci/roles/dev
```

### Automated Testing

Current coverage includes unit tests in `oci-backend/*_test.go` for config, roles, claim enforcement, and exchange validation paths.

Future additions:
- Integration tests with mock OCI IAM
- End-to-end tests with test OCI tenancy

## Notes

- OCI IAM tokens cannot be actively revoked server-side; Vault lease revocation only drops local tracking
- `client_secret` is write-only and never returned on read
- `enforce_role_claim_match` can use default `role_claim_key` (`vault_role`) unless overridden
- If `enforce_role_claim_match=true`, fallback can still be used; `role` must be provided and must match configured claim key in the effective subject token
- If `allow_plugin_identity_fallback=false`, `subject_token` is required
