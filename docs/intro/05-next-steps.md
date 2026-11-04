# Next steps

You've completed the EpiGraph onboarding. Where to from here depends on what you want to do.

## Extending the kernel

If you want to add features to EpiGraph itself, start with [`CLAUDE.md`](../../CLAUDE.md) — it documents the agent conventions (backlog retirement, schema/migrations, claim mechanics, the test database recipe, the `cargo sqlx prepare` workflow). The architecture pattern that governs how new writers should behave is [`docs/architecture/noun-claims-and-verb-edges.md`](../architecture/noun-claims-and-verb-edges.md).

## Adding science-specific tooling

If your use case involves experiments, protocols, samples, blobs, countersignatures, or synthesis claims, you want the **episcience** layer on top of the kernel. See https://github.com/epigraph-io/episcience.

## Deploying in production

See [`docs/deploy.md`](../deploy.md), the install and operations runbook. Start with [section 2, a production install from an empty cluster](../deploy.md#2-a-production-install-from-an-empty-cluster). A database provisioned outside the public migration series needs [section 13, the legacy one-time procedures](../deploy.md#13-legacy-one-time-procedures), first.

## Building a downstream application

The reference pattern for depending on EpiGraph from another Rust project is the [episcience `Cargo.toml`](https://github.com/epigraph-io/episcience/blob/main/Cargo.toml) — it pins specific epigraph crates to a known-good git rev and documents how to swap in local paths for development via `~/.cargo/config.toml` (not the committed `Cargo.toml`).

If you run several development sessions (for example, several Claude Code sessions) against one clone, give each its own `git worktree`. Sessions that share a single working tree collide on branch state.

## Change log

Newest first. Where a commit reached `main` through a merge, the PR is given
as "via #N".

- 2026-11-04 (PR #764): pointed the deploy link at the production install
  (section 2) and the legacy procedures (section 13) of the rewritten
  `docs/deploy.md`, in place of the 2026-05-05 reconcile alone. Replaced a
  reference to a private note with the `git worktree` advice itself. Added
  this change log.
- 2026-05-19 5b735ab82 (via #168) and 8cbab1248 (via #175): first version,
  with contributor, deploy and downstream pointers.
