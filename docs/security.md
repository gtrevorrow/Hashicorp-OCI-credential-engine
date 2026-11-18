# Exchange Security and Access Controls

[README](../README.md) · [Mode selection](../README.md#how-configuration-selects-the-mode) · [Operator configuration](configuration.md)

## Security Considerations

- **Threat Model**: For a deep-dive into the trust architecture, attack vectors, and mitigations (especially concerning self-minted and brokered modes), see [THREAT_MODEL.md](../THREAT_MODEL.md).
- **Token Validation**: In direct pass-through mode, OCI IAM validates the caller-supplied subject token during exchange. In brokered mode, the plugin validates the external JWT locally, self-mints a new plugin-issued JWT, and OCI validates that brokered JWT during exchange.
- **TTL Semantics**: RPST requests can be bounded by plugin TTL policy. UPST lifetime is determined by OCI; plugin TTL settings mainly control Vault lease metadata for UPST responses.
- **Lease Management**: Vault lease lifecycle is applied to issued secrets, but this plugin does not call OCI to invalidate exchanged credentials on revocation. Leases are nonrenewable; see the [expiry contract](usage.md#exchange-path).
- **Audit Logging**: Configure Vault audit devices and review their redaction settings. The plugin does not enable audit logging itself. Its structured operational events supplement the audit trail; see [security logging and diagnostics](security-logging.md) for the event contract, redacted errors, and temporary claim diagnostics.
- **Self-Mint Key Handling**: When `subject_token_self_mint_enabled=true` and no private key is supplied, the plugin generates an RSA key pair and persists the private key in plugin storage. The key is never returned by `read oci/config`.

## Access Controls For Self-Mint And Exchange

Use Vault policy boundaries as the primary control plane:

1. Grant `update` on `oci/exchange` only to trusted workloads that should use no-role or JWT-derived-role exchange, and grant `update` on specific `oci/exchange/<role>` paths when workloads should be limited to specific plugin roles.
2. Restrict role usage with path-based ACLs so each workload can only call specific role paths or namespaces.
3. Set `enable_plugin_issued_subject_token=false` for general clients (the implementation default is `true`), and enable plugin-issued subject-token mode only for tightly scoped policies.
4. Use `subject_token_role_mappings` when callers provide their own JWTs and you want Vault role selection to come from decoded JWT claims rather than an explicit role path; OCI must validate the unchanged token.
5. Treat plugin-issued self-mint as a separate trust model: OCI should rely on Vault-derived claims such as entity, alias, group, or namespace attributes, not the selected exchange role path. If you add `self_mint_custom_claims`, keep them additive and derive them only from trusted Vault context rather than caller-controlled request inputs.
6. Enable `strict_role_name_match=true` to prevent malformed role values.
7. Protect `oci/config` write access so only operators can rotate or replace self-mint settings and signing keys.
8. Treat `oci/exchange` as a privileged identity-issuance path when plugin-issued subject-token mode is enabled; do not grant it broadly just because OCI permissions are controlled later by service-user policy.
9. Expose `oci/jwks` as read-only to systems that need trust bootstrap; do not grant broader plugin capabilities with it.

Vault policy on `oci/config` and `oci/exchange` is part of the security boundary for the self-minted flow. Broad access can let callers mint Vault-backed subject tokens or alter the signing/trust configuration.

Vault enforces this with its normal path-based ACL policies. A common split is:

- operator/admin policy: can manage `oci/config` and `oci/role/*`
- workload policy: can call `oci/exchange` or selected `oci/exchange/<role>` paths but cannot read or write `oci/config`

Example workload policy:

```hcl
path "oci/exchange" {
  capabilities = ["create", "update"]
}

path "oci/exchange/developer" {
  capabilities = ["create", "update"]
}
```

Example operator policy:

```hcl
path "oci/config" {
  capabilities = ["create", "read", "update", "delete"]
}

path "oci/role/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
```
