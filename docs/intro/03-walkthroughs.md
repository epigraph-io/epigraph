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
`http://localhost:8080`), `--token` (else `EPIGRAPH_TOKEN`),
`--author-key-file` (else `EPIGRAPH_GIT_AUTHOR_KEY_FILE`),
`--orchestrator-id` and `--dry-run`.

A live run also needs the author key file: 64 hex characters (32 bytes,
`openssl rand -hex 32`, kept private to the ingest host). Every author's
agent key is derived from that secret and the author's email, and the
repository node's system agent from the secret alone. Without the secret the
key would be a function of the email, which anyone can read in `git log`,
and the server gives each newly registered agent a login, so `ingest_git`
refuses a live run without it. A dry run without one uses a random secret.
Changing the secret changes every author agent.

The PR claim is authored by an *orchestrator* agent, which must already be
registered. `ingest_git` takes the first of these that is set:

1. `--orchestrator-id`;
2. an `Epigraph-Orchestrator-Id: <uuid>` line in the PR body;
3. that trailer in a commit message's trailer block (the last paragraph,
   when every line of it is `Key: value` with a hyphenated key or one of
   `Fixes`, `Closes`, `Resolves`, `Refs`, `References`, `Cc`, `Link` and
   `Bug`), oldest commit first;
4. `EPIGRAPH_DEFAULT_ORCHESTRATOR_ID`.

The reconciler reads a TOML file. Every key is optional and has a default
(`repos` defaults to none):

```toml
repos = ["epigraph-io/epigraph"]           # slugs to watch
endpoint = "http://127.0.0.1:8080"         # the API ingest_git writes to
window_minutes = 240                       # overlap before the saved cursor
state_dir = "<a directory the reconciler owns>"
ingest_git_bin = "<path to the built ingest_git>"
token_file = "<a file holding an API Bearer token>"
author_key_file = "<the author key file above>"
default_orchestrator_id = "<uuid of a registered agent>"
```

The reconciler hands both values to `ingest_git` in its environment, never
on its command line, so neither shows in the process list and the token is
never logged. The token goes in as `EPIGRAPH_TOKEN`. It is read from
`token_file` on every run, or, without that key, taken from the
reconciler's own `EPIGRAPH_TOKEN`. An unreadable `token_file` fails the run
before any PR is ingested. `default_orchestrator_id` goes in as
`EPIGRAPH_DEFAULT_ORCHESTRATOR_ID`, step 4 above, so it is a fallback: a
trailer in the PR body or a commit wins over it. The reconciler does not
mint or refresh the token. Whatever writes `token_file` has to keep it
current, or the writes are refused once the token expires.

`author_key_file` (else the reconciler's own `EPIGRAPH_GIT_AUTHOR_KEY_FILE`)
is passed as `--author-key-file`; the path is not secret, the file is. A
live run without one fails before any PR is ingested. A dry run reads
neither the key file nor `token_file`.

`state_dir` also holds one `<owner>__<repo>.state.json` per repo: a cursor
(the start of the last run whose discovery succeeded) and a retry list of
PRs whose ingest failed. A run scans the PRs merged since the cursor minus
`window_minutes` (since now minus `window_minutes` on the first run) and
re-tries the retry list, so an outage longer than the window or a failed
ingest does not lose a PR. A failed PR waits 15 minutes before its next
attempt, twice as long after each further failure, at most a day. A dry run
reads the state and writes none.
A rebase-merged PR is ingested commit by commit: the reconciler matches the
PR's commits, as GitHub lists them, against main's history.

## Three worked entries

Each commit becomes one claim with the content `[type][scope] claim`:

- Every item under **Evidence** or **Verification** becomes one evidence
  row. An item starts at a list marker (`- `, `* `, `+ `, `1. `), at any
  indent, so a nested bullet is an item of its own. A wrapped line with no
  list marker and no blank line before it joins the item above it. The
  trailer block (`Co-Authored-By:` and the like) is in no section.
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
  Evidence: 1 item(s), Verification: 4 item(s)
  Methodology: extraction, confidence: 85%, initial_truth: 0.6

Packet 1: "[fix][mcp] map verify_claim, reconcile_sheaf and stage_claims to claims:read"
  Hash: 430d3816bf29
  Evidence: 5 item(s), Verification: 4 item(s)
  Methodology: deductive, confidence: 85%, initial_truth: 0.7

Packet 1: "[docs][readme,intro,deploy] state the minimum pgvector version (0.8.0)"
  Hash: 7c73e0917ae1
  Evidence: 1 item(s), Verification: 3 item(s)
  Methodology: heuristic, confidence: 85%, initial_truth: 0.4
```

The second packet is a real historical commit: `stage_claims`, which it names,
was later removed from the MCP server (backlog 90993e95).

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

2. **Live run (untested).** Drop `--dry-run`, add
   `--author-key-file <path>`, and export the token as
   `EPIGRAPH_TOKEN` (or pass `--token "$TOKEN"`, which puts it in the
   process list). The token comes from the `epigraph-wo` client, as in
   [quickstart step 5](01-quickstart.md#step-5--get-an-api-token). Also add
   `--orchestrator-id <uuid>` unless the PR body or a commit carries the
   trailer. The repository-node and commit packets are signed by their
   authors' keys, but the PR-node packet still carries an all-zero
   placeholder signature, because its author is the orchestrator agent and
   the ingester does not hold that agent's key. So the server must run with
   `EPIGRAPH_REQUIRE_SIGNATURES` unset or false. That is a known limit, as
   is the in-process idempotency cache below.

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
   | commit | `source:git-history`, `node:commit`, `repo:<slug>` | an agent keyed by the author key file and the author's email |

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
   exists. A `#N` token does the same for the current claims that cite
   exactly `PR #N` (`PR #80` and `SPR #8` do not count for `#8`). The server's search
   is a substring match that returns up to 25 current claims, and the exact
   match is applied to those 25, so with many `PR #8…` claims an exact one
   can fall outside them.

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

- 2026-11-26 (backlog 39dfef78): the reconciler keeps a per-repo cursor and a
  retry list in `state_dir`, so an outage longer than the window or a failed
  ingest no longer loses a PR (failed PRs are retried with a backoff of up
  to a day), and it ingests every commit of a rebase-merged PR instead of
  only the last.

- 2026-11-15 (review of backlog 7d9e60c6): a live run needs the author key
  file, which keys every author agent; the bare email-derived key was
  computable by anyone. A dry run reads neither the key file nor the token.
  A trailer key is hyphenated or a listed single word. `SPR #8` no longer
  counts as `PR #8`. Nested bullets are described as the code parses them.

- 2026-11-15 (backlog 7d9e60c6): the tool's defects that this page
  described are fixed. A commit's orchestrator trailer is read (step 3 of
  the resolution order). The reconciler passes the token and the default
  orchestrator in the environment, so the default is a fallback. `#N`
  matches the exact PR number. Wrapped bullets and trailer lines no longer
  make extra evidence rows, so the worked entries were re-counted.

- 2026-11-14 (review of backlog 2c2b335d): the worked `feat` and `fix`
  entries are now commits on `main`; step 2 is marked untested and says why
  the live write can be refused; re-runs are described by the dedup that
  survives a restart, with its two exceptions; the `feat`/`perf` truth
  depends on **Verification**.
- 2026-11-14 (backlog 2c2b335d): first version. It is a domain instantiation
  recipe for `ingest_git --pr-ingest`, in place of the transcripts that the
  onboarding spec planned for this number.
