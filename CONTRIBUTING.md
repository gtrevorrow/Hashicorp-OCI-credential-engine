# Contributing to Hashicorp OCI Credential Engine

Thank you for your interest in contributing to the Hashicorp OCI Credential Engine! This document outlines our development process, branching strategy, and how we manage releases using Semantic Versioning.

## Development Workflow & Branching Strategy

We follow a strict branching model to ensure stability and automated releases:

1. **`master` branch**: The source of truth for all production-ready, stable releases.
2. **`development` branch**: The staging area where all feature branches are merged. This branch reflects the latest bleeding-edge code that has passed CI.
3. **Feature branches (`feature/*`, `fix/*`, `docs/*`)**: All active development happens here.

### Process:
1. Create a new branch off of `development` (e.g., `git checkout -b feature/my-new-feature development`).
2. Make your code changes and commit them using [Conventional Commits](#conventional-commits).
3. Open a Pull Request targeting the `development` branch.
4. Once reviewed and CI passes, your PR will be merged into `development`, which automatically triggers a **pre-release** (e.g., `v1.2.0-dev.1`).
5. Periodically, the maintainers will open a PR from `development` to `master` to cut a new stable release.

## Conventional Commits

We use `semantic-release` to automate our versioning and GitHub release notes. Because of this, **all commits must follow the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification**. 

Format: `<type>(<scope>): <short summary>`

Common types:
* `feat`: A new feature (correlates to a `MINOR` version bump)
* `fix`: A bug fix (correlates to a `PATCH` version bump)
* `docs`: Documentation only changes
* `style`: Changes that do not affect the meaning of the code (white-space, formatting, missing semi-colons, etc)
* `refactor`: A code change that neither fixes a bug nor adds a feature
* `perf`: A code change that improves performance
* `test`: Adding missing tests or correcting existing tests
* `build`: Changes that affect the build system or external dependencies
* `ci`: Changes to our CI configuration files and scripts

*Note: If you add `BREAKING CHANGE:` in the footer of a commit message, it will trigger a `MAJOR` version bump.*

Our GitHub Actions PR workflow utilizes `commitlint` to enforce these rules.

## Building and Local Development

We use `make` to streamline building the Vault plugin.

This document is the source of truth for contributor build, local Vault dev, and test workflows. The [README](README.md) keeps only a short install overview and links back here for contributor-facing detail.

### Prerequisites
* Go 1.21 or later
* Vault 1.12+ (for local testing)
* Python 3.9+ on macOS or Linux (standard library only, for local dev helpers and their tests)

### Build the Plugin
The `Makefile` is configured to automatically inject the current semantic git tag into the binary for self-reporting to Vault.

```bash
# Downloads dependencies and builds the plugin for your current OS/Architecture
make build

# Builds the plugin for linux, darwin (amd64/arm64), and windows
make build-all
```

### Overriding Dependencies Locally (Go Workspaces)

If you are developing this plugin in tandem with local changes to its dependencies (e.g., the `oci-go-sdk`), do **not** modify `go.mod` with local `replace` directives. Those are workstation-specific and will break the build for others if committed.

Instead, use [Go Workspaces](https://go.dev/doc/tutorial/workspaces):
```bash
go work init . /path/to/your/local/oci-go-sdk
```

This generates a `go.work` file that tells the Go compiler to use your local SDK. We already include `go.work` in our `.gitignore` to prevent it from being pushed.

### Testing Locally with Vault
To iteratively test the plugin locally:

1. Start Vault in dev mode using the helper script:
```bash
./scripts/dev_vault.sh start
```

This is the preferred local workflow. The helper script:
- runs `make build`
- copies the rebuilt binary into Vault's dev plugin directory
- starts Vault dev mode
- registers the plugin
- enables the `oci` mount
- seeds `oci/config` from `.env.local` when that file is present

2. Load the dev Vault environment into your current shell:
```bash
eval "$(./scripts/dev_vault.sh env)"
```

3. If you change code and want a clean dev refresh, restart through the same helper instead of relying on ad hoc rebuild and reload steps:
```bash
./scripts/dev_vault.sh stop
./scripts/dev_vault.sh start
eval "$(./scripts/dev_vault.sh env)"
```

4. Register and enable the plugin manually only if you are not relying on the helper script to do it for you:
```bash
# Automatically calculates SHA256 and registers the plugin
./scripts/register_plugin.sh

vault secrets enable -path=oci -plugin-name=oci plugin
```

5. For a representative non-root self-mint smoke test, use the helper script:
```bash
./scripts/smoke_self_mint_non_root.sh
```

This script assumes the dev server is already running through `./scripts/dev_vault.sh start` and that `oci/config` has been seeded successfully. It:
- creates a uniquely named `userpass` auth mount
- creates a non-root user with a random password and a uniquely named internal identity group
- attaches the user's entity to that group
- writes a role with templated self-mint custom claims
- runs `/oci/exchange/:role` as the non-root user
- asserts the expected identity/group claims and presence of an OCI credential without printing either
- removes its temporary auth mount, policy, role, group, entity, and login tokens, and restores the alias/debug settings it changed

This is the easiest representative local test for:
- `vault.entity.*`
- `vault.alias.*`
- `vault.groups`
- `join(vault.groups, ",")`

*(Note: When you are finished developing, you can stop the server with `./scripts/dev_vault.sh stop`)*

### Dev helper security and upgrade notes

`dev_vault.sh` and `smoke_self_mint_non_root.sh` keep their existing command names. They now use a shared Python helper and only operate on the disposable Vault instance started by this checkout at `http://127.0.0.1:8200`. Unset a different `VAULT_ADDR` before running them. Inherited Vault namespaces, agent routes, proxies, and tokens are not used by the helpers. Manual `register_plugin.sh` requires an explicit `VAULT_ADDR` and `VAULT_TOKEN`.

Runtime state lives in the ignored `.vault-dev/` directory with owner-only permissions. Each startup creates a private run directory for the plugin, root-token file, and Vault log. Startup refuses an occupied port or an existing session. Stop checks the recorded process identity before sending a signal; it never uses `pkill` or a shared `/tmp/vault.pid`. Smoke checks verify both the process and Vault cluster identity before mutations and cleanup. Do not modify the managed Vault concurrently with a smoke run; its alias/debug configuration changes are temporary and restored at the end.

The root token is random on each startup. It is passed to Vault through its environment, never as a command argument, and Vault's token-helper persistence is disabled with [`-dev-no-store-token`](https://developer.hashicorp.com/vault/docs/commands/server). The `env` command emits a shell command that reads the private token file, rather than printing the credential itself. Do not evaluate those exports with shell tracing enabled. Startup logs can contain Vault-generated credentials: they remain private and are deleted on a normal stop. Failed-start logs remain in `.vault-dev/run-*/vault.log` for local diagnosis; do not share them unredacted. These controls do not protect secrets from processes running as the same OS user or from root.

The trusted `.env.local` shell file and an existing `.vault-dev-self-mint-key.pem` must be regular files owned by you with no group/other permissions. Before upgrading, apply `chmod 600` to those files if present. The persistent signing key is intentionally retained across restarts; startup sends it and the OAuth secret through JSON stdin. CLI error bodies are suppressed because they can contain credentials. Smoke failures return a nonzero exit status and attempt cleanup; a cleanup failure identifies the test resource prefix and instructs you to stop the disposable server. The old `SMOKE_USERNAME`, `SMOKE_PASSWORD`, `SMOKE_GROUP_NAME`, and `SMOKE_ROLE_NAME` overrides are no longer used. `SMOKE_REQUESTED_TOKEN_TYPE` and `SMOKE_RES_TYPE` remain supported.

Before the first upgraded start, stop any server launched by the old helper using its known process identity. The new helper does not adopt old `/tmp` PID files or kill an unrecognized process. If a managed process has already died or its PID has been reused, inspect the private session state and confirm the original server is gone before manually removing that stale session/run directory. A stale or mismatched process fails closed.

## Test Strategy

We run Go tests in two layers, plus separate dev-helper security tests:

1. **Unit tests** (fast, default)
```bash
make test-unit
```
This runs all standard Go tests under `./...`.

2. **Integration tests** (mock OCI token endpoint)
```bash
make test-integration
```
This runs the integration-tagged suite in `oci-backend` and validates plugin-to-OCI exchange behavior against a local mock HTTP server.

3. **Dev helper security tests** (no Vault or OCI credentials required)
```bash
make test-dev-helpers
```
These use mocked CLI/process boundaries to verify secret handling, target checks, state permissions, smoke assertions, and cleanup. They do not replace a live Vault/OCI smoke run.

### CI Behavior

- PR checks run:
  - `make test-unit`
  - `make test-integration`
  - `make test-dev-helpers`
- CI configures a temporary local `go.work` replacement for `github.com/oracle/oci-go-sdk/v65`.

### Notes

- In restricted local sandbox environments, integration tests may be skipped if local TCP bind is not permitted.
- `make test` currently aliases `make test-unit`.

## IDE Setup

We recommend utilizing an IDE with Go support (like GoLand or VSCode with the Go extension) and ensuring your editor applies `gofmt` on save. You can manually run the formatter with `make fmt`.
