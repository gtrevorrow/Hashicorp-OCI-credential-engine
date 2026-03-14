# Project TODO

This file is the working backlog for the OCI credential engine plugin. It tracks implementation gaps, follow-up work, and deferred ideas so they do not get lost in the README.

## Active Backlog

### Operational Hardening

- [ ] Add metrics and telemetry for token exchange rate, error rate, and latency
- [ ] Build end-to-end integration tests against an OCI sandbox or disposable test domain
- [ ] Add a documented operational runbook for self-mint key rollover and JWKS republishing

### Self-Mint and JWKS

- [ ] Add self-mint key rotation with overlapping verification keys
- [ ] Publish multi-key JWKS with stable `kid` handling during rotation
- [ ] Add an explicit rotate/promote/retire workflow for self-mint signing keys

## Deferred / Optional Work

These items are intentionally deferred. They are not part of the current preferred design, but they may become relevant later.

### Optional Future Mode: Plugin-Issued Subject Tokens

- [ ] Add a more complete plugin-issued subject-token mode trusted by OCI Identity Domains
- [ ] Add support for multiple issuers or IdPs per backend in plugin-issued token mode
- [ ] Implement claims mapping or policy translation for plugin-issued token mode
- [ ] Evaluate OCI Cloud Shell integration for plugin-issued token workflows

## Explicit Non-Goals For Now

- General external REST callback pluggability for subject-token resolution
- Caller-controlled identity-selection claims in self-minted tokens
- Making Vault-authenticated `oci/jwks` the direct OCI discovery endpoint

## Current Design Notes

- Primary integration path: caller supplies `subject_token`
- Optional convenience path: built-in Vault-native fallback (`GenerateIdentityToken` first, then optional self-mint)
- OCI remains the authority for token validation, token exchange trust, and final authorization mapping
- For self-mint JWKS discovery, the plugin is the source of truth and operators publish the JWKS to an OCI-reachable HTTPS location
