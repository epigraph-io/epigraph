# Next steps

You've completed the EpiGraph onboarding. Where to from here depends on what you want to do.

## Extending the kernel

If you want to add features to EpiGraph itself, start with [`CLAUDE.md`](../../CLAUDE.md) — it documents the agent conventions (backlog retirement, schema/migrations, claim mechanics, the test database recipe, the `cargo sqlx prepare` workflow). The architecture pattern that governs how new writers should behave is [`docs/architecture/noun-claims-and-verb-edges.md`](../architecture/noun-claims-and-verb-edges.md).

## Adding science-specific tooling

If your use case involves experiments, protocols, samples, blobs, countersignatures, or synthesis claims, you want the **episcience** layer on top of the kernel. See https://github.com/epigraph-io/episcience.

## Deploying in production

See [`docs/deploy.md`](../deploy.md) for the deploy runbook including the 2026-05-05 sqlx-migrations reconcile procedure.

## Building a downstream application

The reference pattern for depending on EpiGraph from another Rust project is the [episcience `Cargo.toml`](https://github.com/epigraph-io/episcience/blob/main/Cargo.toml) — it pins specific epigraph crates to a known-good git rev and documents how to swap in local paths for development via `~/.cargo/config.toml` (not the committed `Cargo.toml`).

If you'll run multiple concurrent Claude Code sessions against the same repo, set up git worktrees per the pattern described in the user-level "use git worktrees" memory note — sessions sharing a single working tree collide on branch state.
