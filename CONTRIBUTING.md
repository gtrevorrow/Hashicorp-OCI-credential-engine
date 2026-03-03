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

### Prerequisites
* Go 1.21 or later
* Vault 1.12+ (for local testing)

### Build the Plugin
The `Makefile` is configured to automatically inject the current semantic git tag into the binary for self-reporting to Vault.

```bash
# Downloads dependencies and builds the plugin for your current OS/Architecture
make build

# Builds the plugin for linux, darwin (amd64/arm64), and windows
make build-all
```

### Testing Locally with Vault
To iteratively test the plugin locally:

1. Build the plugin:
```bash
make build
```

2. Start Vault in dev mode on a separate terminal:
```bash
vault server -dev -dev-root-token-id=root -dev-plugin-dir=./bin
```

3. Enable and test the plugin:
```bash
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='root'

# Register the plugin (our Makefile provides a helper for this):
make register
# (Copy and paste the output of make register to run it)

vault secrets enable -path=oci vault-plugin-secrets-oci
```

## IDE Setup

We recommend utilizing an IDE with Go support (like GoLand or VSCode with the Go extension) and ensuring your editor applies `gofmt` on save. You can manually run the formatter with `make fmt`.
