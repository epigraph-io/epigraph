## What this changes

<!-- One claim per logical decision, as in the commits (CLAUDE.md, "The Epistemic Commit Protocol"). -->

## Verification

<!-- The tests and checks you ran, with their result. -->

## Checklist

- [ ] Shared logic added to `epigraph-service`, not to a front end (`epigraph-api`, `epigraph-mcp`, `epigraph-cli`); or this PR adds no logic that more than one front end uses. See `docs/architecture/crate-layering.md`.
- [ ] No e-mail address, home-directory path, host address or private name in this title or body (the `PR text lint` check fails on them).
- [ ] A design spec this PR implements, deviates from or abandons has its Status line and its `docs/superpowers/README.md` row updated (or no spec is affected).
