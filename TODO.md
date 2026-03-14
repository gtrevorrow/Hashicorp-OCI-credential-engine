# Project TODO

This file is the working backlog for the OCI credential engine plugin. It tracks implementation gaps, follow-up work, and deferred ideas so they do not get lost in the README.

## Active Backlog

### Operational Hardening

- [ ] Add metrics and telemetry for token exchange rate, error rate, and latency
- [ ] Build end-to-end integration tests against an OCI sandbox or disposable test domain
- [ ] Add a documented operational runbook for self-mint key rollover and JWKS republishing
- [ ] Harden `subject_token_allowed_audiences` handling with request normalization and validation (trim, empty/control-character rejection, reasonable length limit)

### Self-Mint and JWKS

- [ ] Add self-mint key rotation with overlapping verification keys
- [ ] Publish multi-key JWKS with stable `kid` handling during rotation
- [ ] Add an explicit rotate/promote/retire workflow for self-mint signing keys

## Deferred / Optional Work

These items are intentionally deferred. They are not part of the current preferred design, but they may become relevant later.

### Optional Future Mode: Plugin-Issued Subject Tokens

- [ ] Add support for multiple issuers or IdPs per backend in plugin-issued token mode
- [ ] Implement claims mapping or policy translation for plugin-issued token mode

## Explicit Non-Goals For Now

- General external REST callback pluggability for subject-token resolution
- Caller-controlled identity-selection claims in self-minted tokens
- Making Vault-authenticated `oci/jwks` the direct OCI discovery endpoint

## Current Design Notes

- Primary integration path: caller supplies `subject_token`
- Optional plugin-issued subject-token mode: `GenerateIdentityToken` first, then self-mint only if needed and configured
- OCI remains the authority for token validation, token exchange trust, and final authorization mapping
- For self-mint JWKS discovery, the plugin is the source of truth and operators publish the JWKS to an OCI-reachable HTTPS location
