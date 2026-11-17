# Sequence Diagram Sources

The repository README presents exchange modes from the client perspective. Its three embedded diagrams match the sources under [client/](client/). They show where the subject token comes from, what the client sends, which token is exchanged with OCI, and what the client receives. Assume Vault authentication and operator configuration are already complete.

| Client view | Source |
|---|---|
| Caller JWT exchanged directly with OCI | [Direct exchange](client/01-direct-exchange.mmd) |
| Caller JWT reissued by the engine before OCI exchange | [Brokered exchange](client/02-brokered-exchange.mmd) |
| Engine obtains the subject token for the client | [Plugin-issued exchange](client/03-plugin-issued-exchange.mmd) |

Keep storage reads, request validation, TTL calculations, key handling, caches, template evaluation, and upgrade guardrails in the maintainer diagrams and reference documentation. Role mapping and the two plugin-issued token sources are variants of the client modes, rather than additional client request flows.

The detailed sources in this directory remain available for developers and maintainers:

| Maintainer or operator view | Source |
|---|---|
| Direct caller-token exchange | [01-caller-supplied-subject-token.mmd](01-caller-supplied-subject-token.mmd) |
| Vault-issued identity-token exchange | [02-plugin-issued-vault-identity-token.mmd](02-plugin-issued-vault-identity-token.mmd) |
| Self-mint exchange | [03-plugin-issued-self-mint.mmd](03-plugin-issued-self-mint.mmd) |
| Caller JWT role mapping | [04-role-claim-guardrail.mmd](04-role-claim-guardrail.mmd) |
| JWKS publication by an operator | [05-jwks-publication-workflow.mmd](05-jwks-publication-workflow.mmd) |
| Brokered caller-token exchange | [06-brokered-subject-token.mmd](06-brokered-subject-token.mmd) |

When exchange behavior changes, review both views and keep the README's embedded blocks synchronized with the client sources.

Escape literal semicolons in diagram labels as `#59;`. Mermaid treats unescaped semicolons as statement separators, which can make GitHub reject an otherwise readable diagram. Validate both the embedded README diagrams and these sources with a Mermaid renderer after editing them.

The old `assets/diagram-1.svg`, `diagram-2.svg` and `diagram-3.svg` exports were removed because they showed retired body-role and role-claim-enforcement fields. They were not referenced by the current README. Do not use those historical images as API documentation.

These are logical sequences, not proof of deployed Vault/OCI behavior. Failure details, compatibility constraints and remaining acceptance tests are documented in the README and TEST_PLAN.
