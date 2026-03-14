# AGENTS.md

## Repository Workflow Guardrails

- Before creating branches, committing, opening PRs, or preparing releases, read and follow [CONTRIBUTING.md](CONTRIBUTING.md).
- Treat `CONTRIBUTING.md` as the source of truth for:
  - Branching strategy (`development` integration branch, `master` stable branch, feature/fix/docs branches)
  - Commit message format (Conventional Commits)
  - Release process (semantic-release behavior on `development` and `master`)

## Commit Requirements

- Use Conventional Commit messages exactly as documented in [CONTRIBUTING.md](CONTRIBUTING.md).
- Do not create ad-hoc version tags or alter release tags unless explicitly requested by maintainers.

## Pre-Commit Checklist

- Confirm current branch is correct for the change.
- Ensure commit message complies with Conventional Commits.
- Verify any release-related action aligns with [CONTRIBUTING.md](CONTRIBUTING.md).

## Sync With Remote

- Before pushing changes, sync with remote:
  - `git fetch --all --prune`
  - `git pull --ff-only`
- If local branch is behind, integrate remote changes before push (fast-forward/rebase/merge as appropriate).

## Documentation Maintenance

- When changing exchange flows, auth behavior, trust assumptions, or other use cases that affect request/response sequencing, review the Mermaid sources under `docs/sequence-diagrams/` and update them if needed.
- Treat the Mermaid sequence-diagram sources as maintainable design artifacts separate from the README SVGs.
