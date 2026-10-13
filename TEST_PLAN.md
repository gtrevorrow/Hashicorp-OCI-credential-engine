# Functional Test Plan: OCI Credential Engine Plugin

This document tracks the functional and security test contracts for the HashiCorp Vault OCI Secrets Engine plugin. A listed case is a test requirement, not a claim that it is automated; see the coverage snapshot and outstanding work below.

Last reconciled: **2026-10-13**, for integration of `feature/remove-unused-role-filters`, based on `development` at `5a39d74`. Includes removal of unsupported role filters and explicit cleanup checks alongside the prior security fixes.

The trust boundaries differ by mode:

- **Direct:** the plugin reads JWT claims for configured `subject_token_role_mappings` and sends the original JWT to OCI for validation. Mapping is intentional role delegation; named-role Vault ACL access is not additionally required. Local claim parsing does not authenticate the JWT.
- **Brokered:** the plugin verifies the incoming JWT before mapping claims and signing a replacement JWT; OCI validates that replacement. Direct `subject_token_role_mappings` do not apply.
- **Plugin-issued:** Vault identity-token generation is attempted first, with self-mint fallback when configured. Tests using a mocked system view do not establish compatibility with a running Vault Enterprise server.

## 1. Configuration Path Tests

| ID | Test Case | Input | Expected Result |
|---|---|---|---|
| CFG-01 | Valid minimal config | domain_url, client_id, client_secret | Success, defaults applied |
| CFG-02 | Valid full config | + default_ttl, max_ttl, subject_token_role_mappings | Success, all fields stored |
| CFG-03 | Config without required field | Missing client_secret | Error: missing required field |
| CFG-04 | Config with invalid URL | domain_url="not-a-url" | Error: invalid URL format |
| CFG-05 | Config read returns secrets masked | Write config, then read | client_secret not in response |
| CFG-06 | Config partial update | Update one or more fields on existing config | Updated values persisted without rewriting unchanged fields |
| CFG-07 | Config delete | Delete after creation | Config removed; subsequent read returns no data |
| CFG-08 | Invalid role-mapping config | Set malformed or unsupported subject_token_role_mappings | Error: invalid subject_token_role_mappings |
| CFG-09 | strict_role_name_match enabled | Set strict_role_name_match=true | Success, strict role-name validation enabled |
| CFG-10 | plugin-issued subject token disabled | Set enable_plugin_issued_subject_token=false | Success, subject_token becomes required unless changed |
| CFG-11 | self-mint enabled without private key | Set subject_token_self_mint_enabled=true, issuer set, omit private key | Success, plugin auto-generates and stores RSA signing key |
| CFG-12 | allowlisted plugin-issued audiences configured | Set subject_token_allowed_audiences | Success, allowed plugin-issued audiences persisted |
| CFG-13 | brokered mode enabled with valid trust config | Set brokered mode, trust type, issuer, audiences, algs, trust source, mappings | Success, brokered settings persisted |
| CFG-14 | brokered mode invalid trust-source combination | Enable brokered mode with multiple trust sources | Error: exactly one trust source required |
| CFG-15 | brokered mode invalid alg config | Enable brokered mode with unsupported alg | Error: unsupported brokered_subject_token_allowed_alg |
| CFG-16 | brokered mode invalid mapping config | Set malformed brokered_subject_token_claim_mappings | Error: invalid brokered_subject_token_claim_mappings |
| CFG-17 | brokered mode reserved output claim rejection | brokered_subject_token_claim_mappings includes reserved JWT claim | Error: reserved claim cannot be overridden |
| CFG-18 | brokered mode reserved vault namespace rejection | brokered_subject_token_claim_mappings includes `vault_*` claim | Error: reserved vault_ namespace |

Additional plugin-issued audience-validation cases:

| ID | Test Case | Input | Expected Result |
|---|---|---|---|
| CFG-19 | Normalize audience allowlist | Whitespace-padded and duplicate entries | Trimmed, deduplicated values persist |
| CFG-20 | Reject invalid audience entries | Blank after trimming, control characters remaining after trimming, or more than 512 bytes after trimming | Configuration rejected |

## 2. Roles Path Tests

| ID | Test Case | Input | Expected Result |
|---|---|---|---|
| ROL-01 | Create role minimal | name="dev", default_ttl=1h | Success |
| ROL-02 | Create role full | + description, max_ttl, templated self_mint_custom_claims | Success |
| ROL-03 | Read role | Read existing role | All fields returned, including templated self_mint_custom_claims when configured |
| ROL-04 | List roles | Create 3 roles, list | All 3 names returned |
| ROL-05 | Update role | Change TTL on existing role | New values persisted |
| ROL-06 | Delete role | Delete existing role | Role removed |
| ROL-07 | Role with TTL exceeding config max | role.max_ttl > config.max_ttl | Role may retain its own valid default/maximum pair; exchange is capped at the lower backend, role, and Vault maximum |
| ROL-08 | Role with invalid name (default mode) | Empty name | Error |
| ROL-09 | Role with special chars (strict mode off) | name includes `@` or space | Success |
| ROL-10 | Role with invalid chars (strict mode on) | strict_role_name_match=true, name includes `@` or space | Error |
| ROL-11 | Role with invalid self-mint custom claims JSON | self_mint_custom_claims is malformed JSON | Error: invalid self_mint_custom_claims |
| ROL-12 | Role with reserved JWT claim override | self_mint_custom_claims includes `sub`, `iss`, `aud`, `exp`, `iat`, `nbf`, or `jti` | Error: reserved claim cannot be overridden |
| ROL-13 | Role with reserved Vault namespace claim | self_mint_custom_claims includes `vault_*` | Error: reserved vault_ namespace |
| ROL-14 | Role with non-string custom claim value | self_mint_custom_claims contains array, object, number, or bool | Error: claim must use a string template |
| ROL-15 | Role with invalid self-mint template syntax | self_mint_custom_claims contains malformed template | Reject malformed syntax throughout the template; existing tests cover only a simple malformed expression (see outstanding work) |

### Removed role filter contracts

| ID | Test case | Expected result |
|---|---|---|
| ROL-16 | Removed or unknown field on create/update | Reject even empty/null values; no role record created |
| ROL-17 | Stored nonempty or malformed removed filters | Supported fields remain readable with a warning; exchange and overwrite fail without changing storage |
| ROL-18 | Explicit delete/recreate cleanup | Deletion remains available; recreation with supported fields succeeds and does not persist removed fields |
| ROL-19 | Empty or null stored removed fields | Read/use permitted without warnings; removed fields are not exposed |
| ROL-20 | Role guard across modes | Direct named, direct JWT-mapped, self-mint, and brokered paths reject affected roles before OCI exchange |

## 3. Exchange Path - Basic Flows

| ID | Test Case | Input | Expected Result |
|---|---|---|---|
| EXC-01 | Exchange for UPST (default) | subject_token on `/exchange/:role` | UPST token returned |
| EXC-02 | Exchange for RPST | + requested_token_type=`urn:oci:token-type:oci-rpst`, res_type | RPST token returned |
| EXC-03 | Exchange with explicit UPST type | requested_token_type=`urn:oci:token-type:oci-upst` | UPST token returned |
| EXC-04 | Exchange without subject_token (plugin-issued mode enabled) | call `/exchange/:role` or bare `/exchange`, omit subject_token, enable_plugin_issued_subject_token=true | Uses plugin-issued subject-token mode (Vault identity token first; self-mint if configured) |
| EXC-05 | Exchange with TTL override | ttl < role.default_ttl | Custom TTL applied |
| EXC-06 | Exchange with public_key provided | public_key in request | No generated key material in response |
| EXC-07 | Exchange without subject_token (plugin-issued mode disabled) | omit subject_token, enable_plugin_issued_subject_token=false | Error: missing subject_token and plugin-issued mode disabled |
| EXC-08 | Exchange with caller-supplied JWT and derived role mapping | subject_token provided, subject_token_role_mappings configured, use bare `/exchange` | First matching mapping selects Vault role and exchange proceeds |
| EXC-09 | Exchange with caller-supplied JWT and explicit role path while mappings enabled | subject_token provided, call `/exchange/:role`, subject_token_role_mappings configured | Error: role-specific exchange paths cannot be used |
| EXC-10 | Exchange without subject_token (allowlisted audience override) | omit subject_token, set subject_token_audience to allowed value | Plugin-issued token uses requested audience |
| EXC-11 | Exchange with disallowed audience override | omit subject_token, set subject_token_audience to unlisted value | Error: audience override not allowed |
| EXC-12 | Exchange with subject_token_audience and caller-provided JWT | subject_token and subject_token_audience set | Error: audience override only applies to plugin-issued tokens |
| EXC-13 | Brokered mode uses re-issued token | subject_token provided, brokered_subject_token_enabled=true | OCI exchange receives plugin-issued brokered JWT, not original external token |
| EXC-14 | Brokered mode explicit role path adds self-mint custom claims | brokered mode + `/exchange/:role` + templated role self_mint_custom_claims | Brokered JWT includes mapped claims plus rendered additive custom claims |
| EXC-15 | Brokered bare exchange omits role-scoped custom claims | brokered mode + bare `/exchange`, with no body `role` | Brokered JWT includes mapped claims only, without role-scoped custom claims |
| EXC-16 | Brokered mode disabled preserves direct pass-through | subject_token provided, brokered mode off | OCI exchange receives original caller-supplied token |

Additional exchange cases:

| ID | Test Case | Input | Expected Result |
|---|---|---|---|
| EXC-17 | Explicit empty subject token | `subject_token=""` | Reject without plugin-issued fallback |
| EXC-18 | Invalid requested token type or missing RPST resource type | Unsupported type, or RPST without `res_type` | Reject before exchange |
| EXC-19 | Normalize or reject audience override | Padded allowed audience, or whitespace-only value | Normalized audience reaches self-mint/Vault identity-token callback; blank value rejected |

Exchange schema coverage: `TestPathExchange_RejectsUnknownFieldsBeforeTokenResolution` checks create/update requests in direct, self-mint, and brokered modes. It rejects body `role` on bare exchange and unknown fields on bare/named routes before token processing. Existing role-mapping and named-role tests preserve supported role selection.

## 4. Exchange Path - Token Content Validation

These cases are primarily OCI-behavior or end-to-end validation scenarios unless explicitly covered by local claim-parsing tests.

| ID | Test Case | Input | Expected Result |
|---|---|---|---|
| EXC-20 | Valid JWT exchange | Valid subject_token from external IdP | Valid UPST returned with lease |
| EXC-21 | Expired JWT | subject_token expired | Error from OCI IAM / trust evaluation |
| EXC-22 | Invalid JWT signature | Tampered subject_token | Error from OCI IAM / trust evaluation |
| EXC-23 | Wrong audience in JWT | JWT aud violates the configured OCI trust requirements | Error from OCI IAM |
| EXC-24 | Missing required claims | JWT missing claims required by OCI trust | Error from OCI IAM / trust evaluation |

## 5. Subject Token Role Mapping

| ID | Test Case | Input | Expected Result |
|---|---|---|---|
| RCM-01 | Exact string match | mapping op=`eq`, JWT claim matches rule value | First matching rule selects role |
| RCM-02 | Contains match | mapping op=`co`, JWT claim contains rule value | First matching rule selects role |
| RCM-03 | Starts-with match | mapping op=`sw`, JWT claim starts with rule value | First matching rule selects role |
| RCM-04 | No mapping match | JWT does not match any configured rule | Error: no subject_token_role_mappings matched |
| RCM-05 | String array claim matching | claim value is array containing an element that matches a rule | Matching rule selects role |
| RCM-06 | Explicit role path rejected when mappings enabled | subject_token provided and `/exchange/:role` used while mappings are configured | Error: role-specific exchange paths cannot be used |
| RCM-07 | Strict role name match in config | strict_role_name_match=true, mapped role contains invalid chars | Error |

## 5.1 Brokered Subject Token Validation

| ID | Test Case | Input | Expected Result |
|---|---|---|---|
| BRV-01 | Valid RSA token | Brokered mode with RSA public key trust, valid RS256 JWT | Incoming token validates successfully |
| BRV-02 | Valid EC token | Brokered mode with EC public key trust, valid ES256 JWT | Incoming token validates successfully |
| BRV-03 | Bad signature | Signed JWT with non-matching key | Error before OCI exchange |
| BRV-04 | Wrong issuer | JWT `iss` does not match configured brokered issuer | Error before OCI exchange |
| BRV-05 | Wrong audience | JWT `aud` not in configured brokered allowlist | Error before OCI exchange |
| BRV-06 | Expired token | JWT `exp` already elapsed | Error before OCI exchange |
| BRV-07 | Unsupported alg | JWT alg not in configured brokered allowlist | Error before OCI exchange |

## 5.2 Brokered Claim Mapping

| ID | Test Case | Input | Expected Result |
|---|---|---|---|
| BRM-01 | Simple one-to-one mapping | `{"external_sub":"{{ claims.sub }}"}` | Output claim rendered from validated input claim |
| BRM-02 | Concatenated mapping | `{"principal":"{{ claims.org }}:{{ claims.sub }}"}` | Output claim renders literals plus multiple claims |
| BRM-03 | Nested claim mapping | `{"employee_id":"{{ claims.user.id }}"}` | Nested claim resolves successfully |
| BRM-04 | Missing claim reference | Template references absent claim | Error, fail closed |
| BRM-05 | Reserved output claim rejection | Mapping outputs reserved JWT claim | Error, fail closed |
| BRM-06 | Vault namespace output rejection | Mapping outputs `vault_*` claim | Error, fail closed |

## 5.3 Brokered Remote Trust and Key Retrieval

The unit cases below use synthetic keys and an injected HTTP transport unless noted. Source: [subject_token_broker_trust_test.go](oci-backend/subject_token_broker_trust_test.go).

| ID | Contract and asserted behavior | Automated evidence |
|---|---|---|
| BRT-01 | HTTPS by default; HTTP only with `debug_allow_brokered_http=true` for localhost/literal loopback. Reject credentials, query, fragment, and unsupported schemes | `TestBrokeredTrustURLPolicy` |
| BRT-02 | Persist debug flag and allowed JWKS origins; reject disabling debug while HTTP trust configuration remains, preserving previous config | `TestBrokeredTrustConfigPersistsDebugAndOrigins` |
| BRT-03 | Exact discovery issuer match, including trailing slash; discovered JWKS stays on issuer origin or an explicitly allowed origin; reject HTTP downgrade | `TestBrokeredDiscoveryIssuerAndOrigin` |
| BRT-04 | Reject redirects, non-200 responses, documents exceeding 1 MiB, and trailing JSON; do not expose upstream error bodies | `TestBrokeredTrustRejectsRedirectsAndOversizedDocuments` |
| BRT-05 | Reject weak RSA (<2048 bits), private/encryption keys, algorithm/EC-curve mismatch, unsuitable `key_ops`, and JWKS with >64 keys; accept tested suitable keys | `TestBrokeredSigningKeySuitability` |
| BRT-06 | Coordinate concurrent fetches, respect 30-second forced-refresh cooldown and five-minute cache expiry, cache failures briefly, fail closed after refresh failure, invalidate on trust URL change | `TestBrokeredTrustCacheCoordinatesRefreshAndFailsClosed` |
| BRT-07 | A caller waiting for refresh can cancel; a canceled fetch does not poison subsequent requests | `TestBrokeredTrustRefreshWaitIsCancelable`, `TestBrokeredCanceledRefreshDoesNotPoisonCache` |
| BRT-08 | Unknown `kid` refresh accepts newly published key after cooldown; a known `kid` paired with the wrong signing key fails | `TestBrokeredUnknownKeyRefreshSupportsRotation` |
| BRT-09 | Address-policy checks reject tested private, loopback, and link-local destinations; debug localhost must resolve to loopback | `TestBrokeredEgressAddressPolicy` |
| BRT-10 | Inline PEM trust verifies a correctly signed JWT that carries a `kid` | `TestBrokeredInlinePublicKeysAcceptJWTKeyID` |
| BRT-11 | Actual loopback HTTP retrieval fails without debug and succeeds with debug | `TestIntegrationBrokeredLocalHTTPRequiresDebug` (integration tag) |
| BRT-12 | Actual loopback HTTP redirect is rejected | `TestIntegrationBrokeredHTTPRedirectIsRejected` (integration tag) |

The two socket-based cases live in [subject_token_broker_trust_integration_test.go](oci-backend/subject_token_broker_trust_integration_test.go). They do not exercise production HTTPS, DNS rebinding, or environment-proxy behavior. Those remain validation tasks below. Upstream verification-key rotation in BRT-08 does not implement rotation of the plugin's own signing key.

## 5.4 Exchange Request Schema Regression Gate

| ID | Required behavior | Status in this checkout |
|---|---|---|
| SCH-01 | Reject undeclared body fields, including body `role` on bare `/exchange`, before token resolution, signing, or OCI exchange; cover create/update across direct, self-mint, and brokered modes | `TestPathExchange_RejectsUnknownFieldsBeforeTokenResolution`: 18 combinations covering all three modes, both operations, and bare/named routes |
| SCH-02 | Retain named-path role selection and intentional direct JWT-to-role mapping after strict validation | Existing direct role-mapping, named-role self-mint, and named-role brokered tests run together with SCH-01 |

Strict field validation runs before configuration lookup and token processing. SCH-01 fails if a token callback or exchange stub is invoked; brokered cases use an invalid JWT and still receive schema rejection. It replaces the earlier direct-only `TestPathExchange_RequestBodyRoleIsIgnored` test. EXC-15 and CLM-05 retain positive bare-path coverage, while SCH-01 covers the malicious body input. Deployed Vault ACL enforcement remains an E2E validation task.

## 6. Lease & TTL Management

Handler tests now assert request/role/backend default selection, each limiting layer, named and mapped roles, and the TTL/MaxTTL returned to Vault for both UPST and RPST. An HTTP integration case asserts a stored role with a one-hour default/maximum sends `rpst_exp=60` under a one-minute backend ceiling. UPST lifetime is OCI-controlled. The handler reports upstream-derived expiry separately from lease policy. Known remaining lifetime caps the lease; missing/null upstream expiry produces `credential_expiry_known=false` with omitted expiry fields and a policy-only lease.

| ID | Test Case | Input | Expected Result |
|---|---|---|---|
| TTL-01 | Default TTL applied | No TTL specified | Uses role.default_ttl when present, otherwise backend default_ttl; RPST sends matching `rpst_exp` |
| TTL-02 | Request TTL clamped to max | Request/default TTL exceeds a backend, role, or Vault ceiling | Clamp to the lowest positive ceiling; RPST sends clamped `rpst_exp` |
| TTL-03 | Lease renewal | Renew valid lease | Unit tests assert a nonrenewable secret and absent renewal callback; verify actual renewal rejection through a running Vault server |
| TTL-04 | Lease revocation | Revoke lease | Unit test asserts the revoke callback makes no OCI request; deployed lease cleanup and OCI validity remain separate live checks |
| TTL-05 | Lease expiration | Wait for TTL | Verify Vault lease expiry and OCI token expiry independently; no lifecycle automation yet |

Additional TTL contracts:

| ID | Test Case | Expected Result |
|---|---|---|
| TTL-06 | Invalid writes and partial backend updates | Reject zero, negative, fractional, overflowing values and default > maximum without changing stored policy. For example, reject a partial backend max of 30 seconds when the stored default is 60 seconds |
| TTL-07 | Invalid request or stored policy | Fail before OCI exchange; do not silently reinterpret invalid policy as an unlimited lifetime |
| TTL-08 | Compatibility defaults | Omitted/zero request selects defaults, then applies ceilings; legacy zero role values inherit backend policy. Configuration writes with zero values are rejected (TTL-06) |
| TTL-09 | Vault maximum precision | Round fractional ceilings down; reject positive ceilings below one second and negative ceilings |
| TTL-10 | Conversion boundary | Accept maximum whole-second duration representable in time.Duration and reject one second more |

### OCI Credential Expiry Contracts

| ID | Test case | Expected result |
|---|---|---|
| EXP-01 | OCI lifetime shorter than policy | Report OCI remaining lifetime and deadline; cap both lease TTL and maximum |
| EXP-02 | OCI lifetime longer than policy | Keep shorter policy lease; report longer OCI lifetime independently |
| EXP-03 | Missing or null OCI expires_in | Mark expiry unknown; omit expiry fields; retain policy lease |
| EXP-04 | Zero, negative, fractional, string, or overflowing expires_in | Reject without returning credential material or a lease |
| EXP-05 | Expired or less than one second remaining | Reject; round usable remaining lifetime down, never up |
| EXP-06 | Network and processing time | Anchor deadline before HTTP transport; subtract elapsed time at response construction |
| EXP-07 | Lease lifecycle declaration | Explicitly nonrenewable; no renewal callback; revoke callback makes no OCI request |

## 7. JWKS Path

| ID | Test Case | Input | Expected Result |
|---|---|---|---|
| JWK-01 | Read JWKS without config | `vault read oci/jwks` | Error: backend not configured |
| JWK-02 | Read JWKS when self-mint disabled | self-mint disabled | Error: subject_token_self_mint_enabled is false |
| JWK-03 | Read JWKS when self-mint enabled | self-mint enabled (auto key or supplied key) | Returns RFC-compatible RSA JWKS with `kid`, `n`, `e`, and compatibility `x5c` |

The JWKS suite also verifies a self-minted signature against the exported key (`TestSelfMintedTokenValidatesAgainstJWKS`) and stable `x5c` across reads (`TestPathJWKSRead_X5CIsStableAcrossReads`). Multi-key rollover remains unimplemented.

## 8. Self-Mint Claim Contract

| ID | Test Case | Input | Expected Result |
|---|---|---|---|
| CLM-01 | Self-mint uses Vault-derived subject | plugin-issued self-mint with `EntityID` present | `sub` is derived from Vault identity, not the selected exchange role |
| CLM-02 | Self-mint includes entity and alias claims | plugin-issued self-mint with entity metadata and explicitly configured linked alias accessor | JWT contains stable Vault-derived identity claims |
| CLM-03 | Self-mint excludes exchange role selector | plugin-issued self-mint invoked through `/exchange/:role` | JWT does not automatically expose the role selector as `vault_role`; configured additive custom claims are checked separately |
| CLM-04 | Self-mint adds role-scoped custom claims on role path | plugin-issued self-mint invoked through `/exchange/:role` and that role has self_mint_custom_claims | JWT contains the configured rendered additive custom claims |
| CLM-05 | Bare self-mint does not infer role-scoped custom claims | plugin-issued self-mint invoked through bare `/exchange`, with no body `role`, while roles with self_mint_custom_claims exist | JWT does not contain role-scoped custom claims because no explicit role was selected |
| CLM-06 | Brokered self-mint adds mapped claims additively | brokered mode with claim mappings | JWT contains mapped external claims without overriding reserved or `vault_*` claims |
| CLM-07 | Self-mint custom claims can render trusted Vault metadata | role self_mint_custom_claims references `vault.entity.*` or `vault.alias.*` | JWT contains rendered string claims from trusted Vault context |
| CLM-08 | Self-mint custom claims can condense group names | role self_mint_custom_claims uses `join(vault.groups, ",")` | JWT contains joined group-name string |
| CLM-09 | Brokered role templates can read validated brokered claims | brokered mode + `/exchange/:role` + `{{ brokered.claims.sub }}` | JWT contains rendered string claim from validated brokered claims |

## 9. OCI API Integration (Mock/Real)

| ID | Test Case | Input | Expected Result |
|---|---|---|---|
| OCI-01 | Successful token exchange | Valid config + valid JWT | OCI returns UPST with access_token |
| OCI-02 | OCI endpoint unavailable or slow | Connection failure, DNS failure, or timeout | Exchange fails; timeout is mock-tested, other transport failures remain untested |
| OCI-03 | Invalid OCI client credentials | Wrong client_secret | Error: authentication failed |
| OCI-04 | Direct OCI token endpoint | domain_url="https://idcs-xxx.identity.oraclecloud.com" | Correct `/oauth2/v1/token` endpoint used |
| OCI-05 | Error payload with HTTP 200 | Mock endpoint returns OAuth error JSON | Error surfaced; no successful token result |
| OCI-06 | Token POST redirect | Mock endpoint returns HTTP 307 | Error; only one request, with no redirect forwarding |

## 10. End-to-End Workflows

| ID | Test Case | Steps |
|---|---|---|
| E2E-01 | Full Vault-Issued Token Flow | 1. Configure Vault identity token or plugin-issued self-mint mode<br>2. Configure OCI trust against Vault-derived claims<br>3. Invoke exchange via plugin without caller-supplied subject_token<br>4. Verify OCI UPST received |
| E2E-02 | External IdP to OCI | 1. Configure plugin with OCI domain<br>2. Get JWT from Auth0/Okta<br>3. Exchange via plugin<br>4. Use UPST with OCI CLI |
| E2E-03 | Multi-tenant setup | 1. Enable multiple plugin mounts (oci-tenant1, oci-tenant2)<br>2. Different configs per mount<br>3. Tokens isolated per tenant |
| E2E-04 | Brokered IdP to OCI | Validate external JWT, map claims, reissue, exchange, and use resulting OCI credential; exercise IdP verification-key rollover and rejection cases |
| E2E-05 | Vault ACL and role delegation | Use non-root callers with different bare/named path policies; verify intentional direct mapping delegation and rejection of body-controlled role selection |
| E2E-06 | Production network trust retrieval | Use actual HTTPS discovery/JWKS endpoints and approved separate key host; verify certificate validation, egress policy, proxy bypass, and refresh during outage/rotation |

## Automated Coverage Snapshot

Coverage means assertions at the specified layer. Unit tests use in-memory Vault storage, mocked identity data, and stubbed exchanges. They do not exercise Vault server ACL enforcement or OCI trust evaluation.

| Area | Evidence and limits |
|---|---|
| CFG-01–03, CFG-05–18 | [path_config_test.go](oci-backend/path_config_test.go): creation/defaults, read/delete, partial updates, mappings, self-mint key generation/reuse, and brokered validation. CFG-04 has no dedicated test; implementation currently checks the `https://` prefix, not full URL validity |
| CFG-19–20, EXC-19 | Integrated: `TestPathConfig_SubjectTokenAllowedAudiencesValidation` covers normalization/deduplication and blank/control/overlong entries. `TestPathExchange_SubjectTokenAudienceOverrideRejectsInvalidValue` rejects whitespace-only overrides; `TestPathExchange_DefaultCallbackSelfMintUsesAudienceOverride` and `TestPathExchange_DefaultCallbackGenerateIdentityTokenUsesAudienceOverride` assert the normalized audience reaches both issuance paths |
| ROL-16–20 | [role_filter_removal_test.go](oci-backend/role_filter_removal_test.go): unknown-field rejection, stored-value detection, preserved state on rejected writes, warned reads, explicit deletion/recreation, empty/null compatibility, and four exchange modes |
| ROL-01–04, ROL-06, ROL-08, ROL-10–15 | [path_roles_test.go](oci-backend/path_roles_test.go): representative creation/read/list/delete and validation. ROL-04 asserts a single listed role, not the three-role scenario; ROL-15 tests simple malformed syntax, not every expression position |
| EXC-04, EXC-06–18 | [path_exchange_test.go](oci-backend/path_exchange_test.go): callback/fallback, key handling, mappings, audience constraints, brokered reissue, direct pass-through, empty-token and requested-type validation. Several tests intentionally fail at the exchange stub after checking earlier behavior; these are not full exchange success proofs |
| EXC-01–03 | Partial: OCI client mock success cases for UPST/RPST; no full Vault-to-OCI success workflow |
| RCM-01–07 | [subject_token_role_mappings_test.go](oci-backend/subject_token_role_mappings_test.go), config validation, and `TestPathExchange_SubjectTokenRoleMappings`; local rule evaluation, not JWT authenticity or Vault ACLs |
| BRV-01–07 | `TestValidateBrokeredSubjectToken` in [subject_token_broker_validation_test.go](oci-backend/subject_token_broker_validation_test.go); local RSA/EC verification and issuer/audience/expiry/algorithm rejection |
| BRM-01–06 | `TestRenderBrokeredClaimMappings` in [subject_token_broker_mapping_test.go](oci-backend/subject_token_broker_mapping_test.go) |
| BRT-01–12 | Named tests in section 5.3; transport-policy units plus two loopback integration cases |
| TTL-01–02, TTL-06–10, EXC-05, ROL-07 | [token_ttl_test.go](oci-backend/token_ttl_test.go): `TestExchangeTTLPolicy`, `TestTTLWritesRejectInvalidPolicyWithoutChangingStorage`, `TestExchangeRejectsInvalidTTLBeforeOCI`, and `TestTokenTTLConversionBounds`. `TestIntegrationExchangeRPSTRespectsBackendTTLCeiling` verifies the capped HTTP form and lease in [oci_client_integration_test.go](oci-backend/oci_client_integration_test.go) |
| JWK-01–03 | [path_jwks_test.go](oci-backend/path_jwks_test.go); also signature verification and stable certificate output |
| CLM-01–09 | Handler/callback tests in [path_exchange_test.go](oci-backend/path_exchange_test.go) and [subject_token_self_mint_templates_test.go](oci-backend/subject_token_self_mint_templates_test.go). Identity/alias data is mocked; bare-path cases exclude a body `role` |
| OCI-01, OCI-03, OCI-05 | [oci_client_integration_test.go](oci-backend/oci_client_integration_test.go): successful token responses, HTTP 401, and HTTP 200 error JSON |
| OCI-02 | Partial: timeout is tested; DNS failure and refused connections are not |
| OCI-04 | No explicit request-path assertion for `/oauth2/v1/token` |
| OCI-06 | `TestOCITokenExchangeDoesNotFollowRedirect` in the brokered trust unit suite |
| SCH-01–02 | Integrated: strict-schema rejection tests plus existing supported role-selection tests in [path_exchange_test.go](oci-backend/path_exchange_test.go) |
| EXP-01–07 | [credential_expiry_test.go](oci-backend/credential_expiry_test.go): deterministic lifetime/lease reconciliation, UPST/RPST handler responses, transport timestamp, and local revocation contract. `TestIntegrationExchangeCredentialExpiry` in [oci_client_integration_test.go](oci-backend/oci_client_integration_test.go) covers upstream JSON through handler output |
| EXC-20–24, TTL-03–05, E2E-01–06 | No automated live OCI/Vault lifecycle coverage; local lease flags/callback behavior are covered by EXP-07 |

ROL-05 (updating an existing role) and ROL-09 (special characters with strict mode off) also lack dedicated tests. The name `TestPathRoles_CreateUpdate` does not imply that it tests an update of an existing role.

## Outstanding Work and Release Validation

1. **Deployed authorization:** SCH-01–02 and audience cases CFG-19–20/EXC-19 are integrated and locally tested. Add non-root Vault ACL tests; direct role mapping remains intentional delegation. Extend audience coverage to exact byte boundaries, multibyte strings, and invalid previously stored allowlists on partial updates.
2. **Live expiry and lease validation:** Finding #4 is locally implemented and covered by EXP-01–07. Verify actual OCI expiry response shapes and credential validity, and renewal/revocation/expiry through a running Vault server. The revoke callback makes no OCI call; do not infer upstream invalidation from Vault lease removal.
3. **Role and identity contracts:** unsupported filters have been removed; verify operator cleanup and authorization in a deployed Vault environment. Verify explicit linked alias selection with multiple real auth methods, including login through a different linked alias. Confirm OCI treats selected alias data as linked identity, not current-login evidence. Add malformed-template cases after an otherwise valid missing-context lookup, where current configuration validation can stop before inspecting trailing syntax.
4. **Trust boundary and resource limits:** add exact-boundary tests for 1 MiB documents/JWTs/aggregate PEM and 64 keys, malformed/missing time claims and future `nbf`/`iat`, invalid origin paths/ports, and more address classes. Existing tests reject an oversized fetched document and 65-key JWKS; they do not exhaust all implemented limits.
5. **Transport and rotation:** exercise actual TLS, mixed public/private DNS answers, checked-address dialing, environment-proxy bypass, refresh timeouts, policy changes beyond the JWKS URL, and unknown-key floods during cooldown. Test upstream key rollover with unique key IDs and the documented publication overlap. Plugin signing-key rotation and multi-key JWKS need implementation and separate tests.
6. **Live acceptance:** complete E2E-01–06 with a disposable OCI domain/tenancy, real Vault policies, and a trusted IdP. Verify OCI API use with the returned credential, rejection cases, and mount isolation. Validate actual Vault Enterprise identity-token behavior and any FIPS deployment claims separately from mocked tests.
7. **Routine coverage gaps:** add CFG-04, ROL-05/09, multi-role listing, broader OCI transport failures, and an explicit OCI endpoint-path assertion. Keep build/release reproducibility and platform checks separate from functional test success.

## Running Tests

Follow [CONTRIBUTING.md](CONTRIBUTING.md) for build and local Vault setup. From the repository root:

```bash
# Default suite: unit and in-memory handler tests
make test-unit

# Nine integration-tagged tests: seven mock OCI cases and two loopback trust cases
make test-integration

# Uncached verification without a workstation go.work override
GOWORK=off go test -count=1 ./...
GOWORK=off go test -count=1 -tags=integration ./oci-backend -run Integration -v

# Additional code-change checks
GOWORK=off go test -race -count=1 ./...
GOWORK=off go vet ./...
```

`make test` currently aliases `make test-unit`; it does not run the integration suite. `GOWORK=off` verifies repository dependencies; omit it when intentionally testing a documented workspace override.

Integration tests use local mock HTTP servers, not a live IdP or OCI tenancy. `newIntegrationServer` skips when TCP binding is unavailable: inspect verbose output for `SKIP`, and do not count skipped tests as validated behavior. A restricted runner needs loopback access to execute all nine cases.

### Latest Verification

On **2026-10-13**, using the security integration, audience validation, TTL ceiling, credential-expiry, and role-filter removal changes described above:

- `GOWORK=off GOCACHE=/tmp/oci-review-cache go test -race -count=1 ./...` — passed, including TTL policy cases, the 18 schema-rejection subcases, and positive role-selection tests.
- `GOWORK=off GOCACHE=/tmp/oci-review-cache go test -count=1 -tags=integration ./oci-backend -run Integration -v` — all nine tests passed, none skipped, with loopback TCP access.

`GOWORK=off GOCACHE=/tmp/oci-review-cache go vet ./...` and a native `go build -trimpath` also passed. These results include role-filter removal/cleanup, credential-expiry reconciliation, TTL ceilings, and audience validation with their regression tests. They do not establish live OCI/IdP behavior, Vault ACL enforcement, Enterprise/FIPS compatibility, or production-network readiness.

### Manual Acceptance

Use the dev-server and non-root smoke-test procedure in [CONTRIBUTING.md](CONTRIBUTING.md#testing-locally-with-vault). Its self-mint smoke script requires a successfully seeded configuration; it is not a substitute for OCI trust setup or a complete E2E test.

For each live case, record the revision, Vault edition/version, mode, relevant non-secret configuration, caller policy, selected role source, expected claims, actual result, and cleanup. Keep credentials, private keys, and raw tokens out of committed test evidence.

For direct mode, provision OCI trust for the external issuer. For self-mint/brokered mode, configure the signing key and plugin issuer and publish its verification JWKS to an OCI-reachable HTTPS endpoint; brokered mode additionally needs incoming issuer/key/audience trust and claim mappings. Use the full token-type URNs in section 3 and a tenant-appropriate RPST `res_type`. Demonstrate both allowed and rejected requests, then use the issued credential for an authorized OCI API call.

HTTP trust endpoints are permitted only for local testing with `debug_allow_brokered_http=true` and loopback destinations. Production acceptance uses HTTPS with the debug exception disabled. Do not confuse this brokered trust setting with the local Vault dev server's listener URL.

## Notes

- `client_secret` is not returned by configuration reads.
- Direct `subject_token_role_mappings` is first-match-wins; rule order matters. It does not apply to brokered reissuance or plugin-issued tokens.
- `subject_token_allowed_audiences` entries are trimmed and deduplicated on configuration writes; entries that are blank, exceed 512 bytes, or contain control characters after trimming are rejected. An empty allowlist remains valid and disables overrides. Stored entries are revalidated on partial configuration updates.
- A supplied nonempty `subject_token_audience` is trimmed and validated before allowlist comparison. Omitted or empty-string overrides retain the configured default; whitespace-only overrides are rejected. These controls do not change incoming brokered JWT audience validation.
- `subject_token_audience` applies only when `subject_token` is omitted and the audience is allowlisted. An explicitly empty `subject_token` fails rather than triggering fallback.
- With `enable_plugin_issued_subject_token=false`, callers must supply `subject_token`.
- Generated exchange key material is returned as `private_key`; the generated public key is omitted from the response.
- The current revoke callback is a no-op. Vault lease removal must not be reported as verified OCI credential invalidation.

## Explicit Linked Alias Selection Verification

Feature: `feature/explicit-identity-alias`, based on development `b801445`.

| ID | Contract | Evidence / acceptance |
|---|---|---|
| ALIAS-01 | Empty accessor emits no alias claims despite available aliases or matching request mount | `TestSignedAliasClaimsRequireExplicitUniqueMount`, both signing flows |
| ALIAS-02 | Explicit accessor selects the same linked alias regardless of order; nil entries are safe; request body cannot override selection | Same test, both signing flows |
| ALIAS-03 | Missing entity/match or duplicate match fails without a signed token | Same test, both signing flows; nil entity checked separately |
| ALIAS-04 | Alias-dependent templates fail when alias context is absent | `TestAliasTemplatesFailWithoutSelectedAlias` |
| ALIAS-05 | Config create/read, partial update preservation, and explicit clearing work | `TestAliasConfigurationPersistsPreservesAndClears` |
| ALIAS-06 | Exchange mount remains the secrets engine; selected alias mount is distinct | `TestDefaultCallbackSelfMintUsesTrustedVaultIdentityClaims` |
| ALIAS-07 | Real multi-auth entity and OCI trust migration | Outstanding live acceptance: test tokens from both auth methods; verify same configured linked identity, ACL enforcement, default omission, and downstream rejection of missing required claims |

Verified locally: full race suite, all nine mock OCI integration tests, vet, native build, shell syntax, and diff checks passed. Live Vault/OCI multi-auth acceptance is separate and is not established by mocked identity tests.

## Development Helper Security Verification

Feature: `feature/harden-dev-helpers`, based on development `768e775` (finding 6 merged).

| ID | Contract | Automated evidence / live acceptance |
|---|---|---|
| DEV-01 | Secret config uses stdin; random root token uses environment; no credential-bearing arguments or printed responses | `scripts/tests/test_dev_vault.py`: payload, startup, exports, and smoke tests |
| DEV-02 | Refuse a different address, stale/reused PID, or mismatched cluster before mutation | Target/address/stop tests |
| DEV-03 | Owner-only files/directories; reject symlinks/shared permissions | Private-path and startup tests |
| DEV-04 | Ignore inherited Vault routing, namespaces, proxies, OCI settings and tokens | Environment and settings tests |
| DEV-05 | Unique smoke resources, exact claim assertions, token revocation, resource cleanup and configuration restoration | Smoke success, exchange failure, bad-claims and cleanup-failure tests |
| DEV-06 | Real dev lifecycle and OCI exchange | Outstanding: start/env/smoke/stop with supported Vault; inspect argv and permissions; verify cleanup and restored config after success/failure; confirm no root token-helper writes |

Run `make test-dev-helpers` (also in PR CI). Python tests mock Vault/process interfaces; no real Vault or OCI tenant is exercised. Bash syntax and `git diff --check` are also required for these script changes. Sequence diagrams are unchanged because the plugin exchange/authentication sequence is unchanged; the smoke harness now provisions isolated temporary resources around that sequence.

Local verification for DEV-01–05: all 14 helper security tests passed, along with shell syntax and diff checks. DEV-06 remains unexecuted because Vault is not installed in this environment.
