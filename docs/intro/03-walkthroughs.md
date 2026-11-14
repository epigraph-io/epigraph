# Walkthrough: a repository's history as a domain

This page sets up one knowledge domain from start to finish: a git repository
whose commits follow the Epistemic Commit Protocol (`type(scope): claim` plus
**Evidence**, **Reasoning** and **Verification** sections, as in
[`CLAUDE.md`](../../CLAUDE.md)). The tool is `ingest_git`
(`crates/epigraph-cli/src/bin/ingest_git.rs`). In PR mode it turns one merged
pull request into a `repo → PR → commit` claim tree. The reconciler,
`scripts/git_ingest_reconciler.py`, runs it for each newly merged PR.

The dry-run output below was captured against this repository's `main`. The
live write in step 2 of the end-to-end task has **not** been run for this
page. Its description comes from the code.

## Config keys

`ingest_git --pr-ingest` takes the PR's metadata as flags. These are required:
`--repo-slug`, `--pr-number`, `--pr-title`, `--merge-sha`, `--merged-at` and
`--rev-range` (the PR's own commits, `A..B`). These are optional: `--pr-body`,
`--pr-author`, `--repo` (the clone, default `.`), `--endpoint` (default
`http://localhost:8080`), `--token`, `--orchestrator-id` and `--dry-run`.

The PR claim is authored by an *orchestrator* agent, which must already be
registered. `ingest_git` takes the first of these that is set:

1. `--orchestrator-id`;
2. an `Epigraph-Orchestrator-Id: <uuid>` line in the PR body;
3. `EPIGRAPH_DEFAULT_ORCHESTRATOR_ID`.

A trailer in a commit message is not read: only each commit's header line
reaches the resolver.

The reconciler reads a TOML file. Every key is optional and has a default
(`repos` defaults to none):

```toml
repos = ["epigraph-io/epigraph"]           # slugs to watch
endpoint = "http://127.0.0.1:8080"         # the API ingest_git writes to
window_minutes = 240                       # look back this far for merges
state_dir = "<a directory the reconciler owns>"
ingest_git_bin = "<path to the built ingest_git>"
default_orchestrator_id = "<uuid of a registered agent>"
```

If `default_orchestrator_id` is set, the reconciler passes it as
`--orchestrator-id`. It then wins over a PR body's trailer and is not a
fallback. The reconciler does not pass `--token`, so a live run of it is
refused (every write route needs a Bearer token). Use it with `--dry-run`.

## Three worked entries

Each commit becomes one claim with the content `[type][scope] claim`:

- Every non-empty line under **Evidence** or **Verification** becomes one
  evidence row. A wrapped bullet counts once per line, and trailer lines after
  **Verification** (`Co-Authored-By:` and the like) count as Verification.
- **Reasoning** becomes the reasoning trace.
- The type sets the methodology and the initial truth. For `feat` and `perf`
  the initial truth is 0.6 with a **Verification** section and 0.4 without.
- Confidence is 85% when all three sections are present.

To dry-run one commit, run `ingest_git --repo <clone> --dry-run --limit 1`
with that commit checked out as `HEAD`. This is captured output, trimmed to
the packet lines (the progress, `Author:`, `Date:` and `Files changed:` lines
are cut). The `fix` commit is the only commit of PR #825, used again below:

```
Packet 1: "[feat][api] refuse pgvector below 0.8.0 in epigraph-migrate"
  Hash: fc76a8c95f58
  Evidence: 5 item(s), Verification: 15 item(s)
  Methodology: extraction, confidence: 85%, initial_truth: 0.6

Packet 1: "[fix][mcp] map verify_claim, reconcile_sheaf and stage_claims to claims:read"
  Hash: 430d3816bf29
  Evidence: 14 item(s), Verification: 12 item(s)
  Methodology: deductive, confidence: 85%, initial_truth: 0.7

Packet 1: "[docs][readme,intro,deploy] state the minimum pgvector version (0.8.0)"
  Hash: 7c73e0917ae1
  Evidence: 5 item(s), Verification: 10 item(s)
  Methodology: heuristic, confidence: 85%, initial_truth: 0.4
```

Each commit packet carries the idempotency key `git:<full sha>`, and its
properties include `source`, `commit_hash`, `commit_type`, `scope` and `files_changed`.

## End to end: one merged PR

1. **Dry run.** `ingest_git` makes no network calls in this mode. PR #825
   was merged with a merge commit, so its own commits are `M^1..M^2`:

   ```bash
   cargo build --release --locked -p epigraph-cli --bin ingest_git
   M=d678d9f87030e659809aa0351105d4c9d1a1db8d
   BODY=$(gh pr view 825 --json body --jq .body)
   AUTHOR=$(gh pr view 825 --json author --jq .author.login)
   ./target/release/ingest_git --pr-ingest --dry-run --repo . \
     --repo-slug epigraph-io/epigraph --pr-number 825 \
     --pr-title "fix(mcp): map verify_claim, reconcile_sheaf and stage_claims to claims:read" \
     --pr-body "$BODY" \
     --merge-sha "$M" --merged-at 2026-11-14T14:51:23Z \
     --pr-author "$AUTHOR" --rev-range "$M^1..$M^2"
   #   [dry-run] repo=epigraph-io/epigraph pr=#825 commits=1 refs=References { claim_uuids: [], pr_numbers: [] }
   ```

2. **Live run (untested).** Drop `--dry-run` and add `--token "$TOKEN"`.
   The token comes from the `epigraph-wo` client, as in
   [quickstart step 5](01-quickstart.md#step-5--get-an-api-token). Also add
   `--orchestrator-id <uuid>`. The packets carry an all-zero placeholder
   signature, so the server must run with `EPIGRAPH_REQUIRE_SIGNATURES` unset
   or false.

   This step has not been run end to end, and it may be refused. The
   token's principal is never an author of these packets: the authors are
   the agents in the table below. A deployment that checks whether a caller
   may write on an author's behalf can refuse the run at the first packet,
   the repository node. Where the run is allowed, the packets send no
   `visibility`, so each claim takes its author's default under
   [claim visibility controls](../tenancy/claim-visibility-controls.md)
   (team or private), and step 3 from another principal may find nothing.

   | Node | Labels | Author |
   |---|---|---|
   | repository | `source:git-history`, `node:repo`, `repo:<slug>` | one fixed system agent |
   | pull request | `source:git-history`, `node:pr`, `repo:<slug>` | the orchestrator |
   | commit | `source:git-history`, `node:commit`, `repo:<slug>` | an agent derived from the author's email |

   **Re-runs.** The packets carry the idempotency keys `repo:<slug>`,
   `pr:<slug>#<n>` and `git:<sha>`, but the server checks those keys only
   in an in-process cache, which a restart empties. What holds across
   restarts is the claim store's dedup on content and author agent, and
   every edge is posted with `if_not_exists`. So a re-run with the same
   inputs makes nothing new, with two exceptions:

   - a re-run under a different orchestrator makes a second PR claim and a
     second `repo decomposes_to PR` edge;
   - two commits by one author with the same header (`[chore][deps] bump
     lockfile`, say) become one commit claim.

   The edges are `repo decomposes_to PR`, dated at the merge time, and
   `PR decomposes_to commit`, dated at the commit time. A UUID in the PR body
   or in a commit header adds `<that claim> RESOLVED_BY PR`, if the claim
   exists. A `#N` token does the same for up to 25 current claims whose
   content contains `PR #N`.

3. **Read it back.** In an MCP session, call
   `query_claims_by_label(labels=["node:pr", "repo:epigraph-io/epigraph"])`
   to find the PR claim, then
   `get_neighborhood(node_id=<its id>, relationship="decomposes_to")` to see
   its repository and its commits.

**What just happened.** Each commit and PR is a noun-claim, and the tree
between them is verb-edges
([concepts §1](02-concepts.md#1--noun-claims-vs-verb-edges)). It has the same
`decomposes_to` shape as a document's thesis, sections, paragraphs and atoms
([§5](02-concepts.md#5--hierarchical-extraction)). Each node is keyed by its
content and its author agent ([§2](02-concepts.md#2--agents-and-signing)), so a
re-run finds the same node again instead of making a new one.

## Change log

Newest first.

- 2026-11-14 (review of backlog 2c2b335d): the worked `feat` and `fix`
  entries are now commits on `main`; step 2 is marked untested and says why
  the live write can be refused; re-runs are described by the dedup that
  survives a restart, with its two exceptions; the `feat`/`perf` truth
  depends on **Verification**.
- 2026-11-14 (backlog 2c2b335d): first version. It is a domain instantiation
  recipe for `ingest_git --pr-ingest`, in place of the transcripts that the
  onboarding spec planned for this number.
