## What this changes

<!-- One claim per logical decision, as in the commits (CLAUDE.md, "The Epistemic Commit Protocol"). -->

## Verification

<!-- The tests and checks you ran, with their result. -->

## Checklist

- [ ] Shared logic added to `epigraph-service`, not to a front end (`epigraph-api`, `epigraph-mcp`, `epigraph-cli`); or this PR adds no logic that more than one front end uses. See `docs/architecture/crate-layering.md`.
- [ ] No e-mail address, home-directory path, host address or private name in this title or body (the `PR text lint` check fails on them).
- [ ] After each review round, the PR body was updated to match the final commits (no stale claims); the body is the merge record a later reader trusts.
- [ ] A design spec this PR adds has a `proposed` row in `docs/superpowers/README.md`, and one it implements, deviates from or abandons has its Status line and its row updated (or no spec is affected).
