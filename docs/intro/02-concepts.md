# EpiGraph Concepts

EpiGraph is an evidence-graph database that records *what is claimed*, *who claimed it*, *when it occurred*, and *how strongly it is believed* — all in a way that survives re-ingest, re-extraction, and disagreement between agents. This page is the orientation layer: each sub-section explains one core idea, points at a worked example, and links to the canonical deeper doc for the specialist details. Read it once front-to-back; later you can jump back via the table of contents below.

If you have not yet read [`01-overview.md`](01-overview.md), do that first — it frames *why* EpiGraph exists. This file answers *what the moving parts are*. The [`04-glossary.md`](04-glossary.md) entries refer back into the sections below by anchor.

## Table of contents

1. [Noun-claims vs verb-edges](#1--noun-claims-vs-verb-edges) — what goes in `claims` vs `edges`
2. [Agents and signing](#2--agents-and-signing) — who authors and how authorship is cryptographically anchored
3. [Beliefs and DST](#3--beliefs-and-dst) — how the graph carries uncertainty (BetP, mass functions, discounting)
4. [Perspectives, frames, themes](#4--perspectives-frames-themes) — viewpoints, hypothesis spaces, topical clusters
5. [Hierarchical extraction](#5--hierarchical-extraction) — papers → paragraphs → atoms and why paragraphs are primary
6. [Backlog discipline](#6--backlog-discipline) — how operational follow-ups live inside the graph

---

## 1 — Noun-claims vs verb-edges

EpiGraph has two write surfaces — `claims` and `edges` — and the
rule for which row belongs in which table is the single most
important architectural fact in the system. The codebase drifted
into using `claims` for both kinds of write before 2026-04-25; the
canonical pattern below is the post-S1 state.

A row in `claims` is a **noun**: a stable-identity entity or
assertion. Its canonical key is `(content_hash, agent_id)`, and
there is at most one row per key. Examples:

- "Evidence supports H₀ at confidence 0.8" (a textbook fact)
- "Container `epiclaw-tg-7173612411` exists" (entity)
- "Task `epistemic-gaps` is scheduled" (operational entity)
- "The message body 'ok'" (content blob)

Each one names something that has identity independent of any
particular time it was observed.

A row in `edges` is a **verb event**: a timestamped occurrence or
relationship involving one or more noun-claims. The edge carries
`relationship` (the verb), `created_at` (the event time), optional
`valid_from`/`valid_to`, a `properties` JSONB blob with event
metadata, and a `signature` / `signer_id` pair. Re-occurrence of the
same event creates a new edge, never a duplicated noun. Examples:

- `host_agent --[spawned @ T1, props={group:"..."}]--> container_claim`
- `host_agent --[executed @ T2, props={status:"completed"}]--> task_claim`
- `paper_artifact --[asserts @ T3, props={extraction_run:"..."}]--> fact_claim`

Worked example — textbook ingest, abbreviated:

```text
# run 1
POST /claims  {content="evidence supports H0 at conf 0.8",
               agent_id=ingest_agent, if_not_exists: true}
            -> {claim_id=X, was_created: true}
POST /edges   {source=paper_artifact_run1, target=X,
               relationship="asserts", created_at="2026-03-30T..."}

# run 2 — same content extracted from a fresh ingest run
POST /claims  {content="evidence supports H0 at conf 0.8",
               agent_id=ingest_agent, if_not_exists: true}
            -> {claim_id=X, was_created: false}   # canonical row already exists
POST /edges   {source=paper_artifact_run2, target=X,
               relationship="asserts", created_at="2026-03-31T..."}
```

The fact-claim is canonical (one row); each run's per-run `paper_artifact` noun gets its own fresh `asserts` verb-edge to the canonical fact.

Three rules fall out of this pattern:

1. **Re-occurrence of a lifecycle event = new edge, not new claim.**
   Spawning the same container twice produces two `spawned` edges,
   not two container-claims. The container's existence is the noun;
   each spawn is a verb event at a different `created_at`.

2. **Re-ingesting the same source = new edge from a per-run
   source-artifact to the existing fact-claim.** No duplicate fact
   rows; the audit trail lives in the edges. Per-run paper artifacts
   are themselves noun-claims (one per run), each with its own
   `asserts` verb-edge to the canonical fact.

3. **`provenance_log` is unchanged.** Every successful create or
   patch lands a cryptographic provenance row, whether `was_created`
   was true or false. The noun/verb split affects what *writers
   create*, not what the audit log records.

A useful mental check when modelling new data: ask "does this thing
have stable identity, or is it an event?" Stable identity → noun-claim,
keyed by `(content_hash, agent_id)`. Event → verb-edge, with `created_at`
carrying the time and `properties` carrying the metadata.

**See also:** [`docs/architecture/noun-claims-and-verb-edges.md`](../architecture/noun-claims-and-verb-edges.md) for the full migration history, the `if_not_exists: true` semantics, the layered dedup story for LLM-driven writers, and the sub-project map (S1–S4).

---

## 2 — Agents and signing

Every write to EpiGraph is attributed to an **agent** — a signing identity with an Ed25519 keypair and an `agent_id` UUID. Human contributors, ingest scripts, MCP-driven LLMs, host processes, and scheduled tasks all submit work under stable agent IDs, so authorship survives across sessions and across machines. The agent is half of the canonical identity of every claim: `(content_hash, agent_id)` is the dedup key in the noun-claim model from §1.

Agent identity is **deterministic**: rather than minting a fresh keypair
per process, EpiGraph derives the keypair from a seed string via BLAKE3
→ Ed25519, so the same logical agent maps to the same `did:key` URI
everywhere. Three seed strategies are in use today:

- **Human authors** — the seed is an ORCID
  (e.g., `"orcid:0000-0002-1825-0097"`); for authors without an ORCID,
  a normalized name string is the fallback. Same author across years
  of work, one signing identity.
- **System agents** — fixed strings like `"workflow-ingest-system"`
  (see [`crates/epigraph-ingest-executor/src/system_agent.rs`](../../crates/epigraph-ingest-executor/src/system_agent.rs)).
  The same string always produces the same agent across processes,
  so the get-or-create lookup is idempotent. Container restart, fresh
  deploy, parallel host — all the same agent UUID.
- **LLM-driven agents (planned)** — the seed is a hash of
  `(model identifier, system prompt)` so the same model+prompt pair
  resolves to the same agent identity across sessions
  (see user-memory `project_epigraph_agent_identity.md`).
  User OAuth passthrough sits next on that roadmap, so writes
  attributed to "Claude with prompt X acting for Jeremy" can be
  distinguished from "Claude with prompt X acting for Carrie".

A `did:key` URI looks like this:

```text
did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
```

The `z` is base58btc multibase, the leading bytes inside the base58 payload are the multicodec prefix `0xed01` for Ed25519, and the rest is the 32-byte public key. Resolving a DID requires no network call — the public key is in the URI, so signature verification is purely local.

Claim signatures and edge signatures use the same audit guarantee: the schema carries `signature` and `signer_id` columns on both `claims` and `edges` (edge signing was added in migration 073). Today claim signatures are universally populated; edge signing is realised per writer in the S3 plans documented in the noun/verb architecture doc — see "Edge signing" there for the current state of which writers sign. The `provenance_log` table records every create or patch independently of the row-level signature, so even an unsigned edge has a tamper-evident audit trail keyed by the requesting principal.

Two flows mint different tokens, and it is easy to confuse them:

- **Agent identity** (this section) — a long-lived signing keypair
  derived deterministically from a seed; this is *who* a claim is
  from, and it stays the same for years.
- **Bearer tokens for the HTTP API** — short-lived JWTs (or
  OAuth-issued tokens from `/oauth/token`) that authorise a
  *request*. For bootstrap scripts, the dev helper is
  [`scripts/_api_client.py::mint_bearer_token`](../../scripts/_api_client.py)
  (HS256 JWT with `EPIGRAPH_JWT_SECRET`); for production clients the
  canonical mint flow is the `/oauth/token` endpoint mounted in
  `crates/epigraph-api/src/routes/mod.rs`, using an Ed25519 client
  assertion of `ts(8B BE) || nonce(16B) || sig(64B)`.

The bearer-token's `agent_id` claim — when present — pins the resulting writes to a specific agent; without it, writes are attributed to the OAuth client's default agent. Either way the agent identity is the *durable* identity; the bearer token is just the per-session capability that lets a process act on its behalf.

Practical implication for new code: never generate an Ed25519 keypair at runtime "to identify this process". Pick a seed string that describes the *role* (`"my-extractor-v3"`, an ORCID, or a model+prompt hash), pass it through `did_key_for_author`, and let the get-or-create pattern in `system_agent.rs` find or insert the matching `agents` row. The same role on a different machine then writes against the same agent UUID and the same signing key, so attribution composes cleanly across hosts.

**See also:** [`crates/epigraph-crypto/src/did_key.rs`](../../crates/epigraph-crypto/src/did_key.rs) for `did:key` derivation; [`crates/epigraph-ingest-executor/src/system_agent.rs`](../../crates/epigraph-ingest-executor/src/system_agent.rs) for the get-or-create pattern; user-memory `project_epigraph_agent_identity.md` for the LLM-agent identity roadmap; user-memory `reference_epigraph_oauth_mint.md` for the Ed25519 client-assertion shape against `/oauth/token`.

---

## 3 — Beliefs and DST

EpiGraph does not store a single scalar "truth" for each claim. Instead, every claim that has been judged carries a **Dempster-Shafer mass function** over a frame of discernment, and beliefs are projected from that mass function on demand. This matters because real-world evidence is often partial, conflicting, or missing entirely, and a single scalar cannot distinguish "we think it's 0.5" from "we have no idea, so we are reporting 0.5".

A frame of discernment is the finite set of mutually-exclusive hypotheses the claim ranges over — `{H0, H1}` for a binary fact, or a longer list for multi-class assertions. A mass function assigns probability mass to *subsets* of the frame (focal elements), not just to singletons; mass on the full frame represents ignorance. Mass that does not fit anywhere lands in two diagnostic buckets: `mass_on_conflict` (combination produced contradictory evidence) and `mass_on_missing` (the writer ran out of evidence to attribute). DST handles "we do not know yet" cleanly because ignorance is a first-class quantity, not a synthetic prior.

The canonical scalar belief score in EpiGraph is **BetP** — pignistic probability — which projects a mass function onto a probability over singletons by distributing each focal set's mass uniformly across its members. BetP is a single number in `[0, 1]`; sort by it when you need to rank claims, but read the underlying mass function when you need to know *how confident the rank is*. A `get_belief` response looks like:

```json
{
  "claim_id": "8f1de9e2-...-...",
  "belief": 0.71,
  "plausibility": 0.86,
  "ignorance": 0.15,
  "pignistic_prob": 0.78,
  "mass_on_conflict": 0.04,
  "mass_on_missing": 0.00,
  "source": "combined"
}
```

The fields decode like this:

- `belief` (lower bound) and `plausibility` (upper bound) define the
  DST interval — `belief` is the sum of mass on focal sets fully
  inside the hypothesis, `plausibility` is the sum of mass on focal
  sets that *intersect* it.
- `ignorance` is the gap between them, i.e., mass that supports
  neither side of the question yet.
- `pignistic_prob` is BetP and is the field downstream ranking code
  reads when it needs a single number.
- `mass_on_conflict` flags conflict from combination; high values
  mean the sources disagree.
- `mass_on_missing` tracks mass that the writer could not attribute
  to any focal set — open-world ignorance, distinct from the
  "neither side" ignorance counted under `ignorance`.
- `source` reports how the value was assembled (`"stored"`,
  `"combined"`, etc.) so callers can tell whether they got a fresh
  combination or a cached value.

The struct lives at `BeliefResponse` in `crates/epigraph-mcp/src/types.rs`.

When evidence from multiple sources is combined, the writer
**discounts** each input mass function by a reliability factor in
`[0, 1]` (1.0 = fully trusted, 0.0 = belief moves entirely to
ignorance) before applying Dempster combination — this is the
correct way to fuse evidence under uncertainty per Shenoy-Shafer.
The `submit_ds_evidence` MCP tool exposes the `reliability`
parameter directly; multiple combination methods are wired in
(`Dempster`, `Conjunctive`, `YagerOpen`, `YagerClosed`,
`DuboisPrade`, `Inagaki`) and `compare_methods` projects all of
them so you can see how sensitive a claim is to the choice.

Scalar Bayesian belief propagation was tried earlier and removed: multiplying scalar truth values along edges collapses them toward zero independently of how strong the evidence actually is (see user-memory `project_bp_cdst_primary.md` and `feedback_pignistic_not_bayesian.md`). The deprecated `truth_value` column is still present in some rows for back-compat; do not order claims by it. The `bp_messages` table that backed the scalar engine is dead and a candidate for drop (`project_bp_messages_dead.md`).

Math kept at intro level: full DST adds operations like Yager normalisation (re-attributing conflict mass to ignorance), Dubois-Prade combination (used when sources are not independent), and discounting with `mass_on_missing` to model open-world ignorance. Those live in the deeper architecture docs — for the intro, hold onto the three-bucket story: belief, plausibility, ignorance, with BetP as the scalar projection you sort by.

**See also:** the LANL Open World DST paper (LA-UR-25-23655) — user-memory `reference_lanl_open_world_dst.md` — for the practitioner's foundation; [`crates/epigraph-mcp/src/tools/ds.rs`](../../crates/epigraph-mcp/src/tools/ds.rs) for `submit_ds_evidence`, `get_belief`, and `compare_methods`; user-memory `feedback_pignistic_not_bayesian.md` for the BetP-first rule; user-memory `project_bp_cdst_primary.md` for why CDST replaced scalar BP.

---

## 4 — Perspectives, frames, themes

Three vocabulary words sit close enough together that newcomers conflate them. They are different things.

A **frame** is the hypothesis space a single mass function is defined over — `{H0, H1}`, `{accepts, rejects, undecided}`, or any finite mutually-exclusive set. Frames are stored in their own table and re-used across claims that share a hypothesis space; refinements (one frame nested inside another) are first-class via `parent_frame_id`.

A **perspective** is a *viewpoint*: an agent-owned (or community-owned) lens that selects, weights, or filters claims when computing belief. The same atom can carry different BetP values from different perspectives without one overwriting the other — disagreement stays visible instead of being averaged away. Perspectives have a `perspective_type` ("analytical", "narrative", etc.), an optional list of `frame_ids` they operate over, and a `confidence_calibration` factor in `[0, 1]`.

```json
// mcp__epigraph__list_perspectives  →
[
  {
    "perspective_id": "c5d7...",
    "name": "biophysics-skeptic",
    "owner_agent_id": "8f1d...",
    "perspective_type": "analytical",
    "confidence_calibration": 0.6
  },
  {
    "perspective_id": "9a02...",
    "name": "ndi-house-view",
    "owner_agent_id": "2b46...",
    "perspective_type": "narrative",
    "confidence_calibration": 0.8
  }
]
```

A **theme** is a topical cluster derived from semantic clustering
over claim embeddings. Themes are stored as rows in `claim_themes`
(`label`, `description`, `centroid` vector, `claim_count`), and
each clustered claim points to one theme via `claims.theme_id` —
theme membership is single-valued at the schema level. Themes are
how you navigate the graph at coarser granularity than individual
atoms; the `theme_cluster` MCP tool in
[`crates/epigraph-mcp/src/tools/themes.rs`](../../crates/epigraph-mcp/src/tools/themes.rs)
(re)builds them from the live corpus by running k-means over
paragraph embeddings, with elbow-penalised search over
`k_min..=k_max` when `k` is not pinned. The default `limit` is 500
(VM OOMs at ~2000 embeddings, per `feedback_memory_limits.md`),
and `wipe_first=true` is the safe default because `claim_themes`
has no `UNIQUE(label)` constraint and additive runs silently
duplicate `auto-00, auto-01, …` rows.

Rule of thumb:

- A **frame** is *what is being judged* — a fixed hypothesis space.
- A **perspective** is *who is judging* — an agent's or group's lens.
- A **theme** is *what topic* the claims are about — a cluster label.

They are orthogonal. A single claim can sit in one frame, be
evaluated under three perspectives, and belong to one theme all
at the same time, and none of those facts contradict each other.

**See also:** [`crates/epigraph-mcp/src/tools/perspectives.rs`](../../crates/epigraph-mcp/src/tools/perspectives.rs) for `create_perspective`, `list_perspectives`, and `get_perspective`; [`crates/epigraph-mcp/src/tools/themes.rs`](../../crates/epigraph-mcp/src/tools/themes.rs) for theme clustering; the DST tools in `ds.rs` for frame creation.

---

## 5 — Hierarchical extraction

EpiGraph stores documents as a tree, not a flat bag of sentences. Each ingested source becomes a **paper** node; each paper has child **paragraph** nodes; each paragraph has child **atom** nodes. The level lives in `properties->>'level'`: papers are level 1, paragraphs are level 2, atoms are level 3. Edges link each level to its parent so the tree is graph-traversable in either direction, and each child carries its own embedding so searches at any granularity are possible — but only paragraph-level search is *canonical*.

```text
                paper (level 1)
                  │
        ┌─────────┼─────────┐
   paragraph    paragraph    paragraph   (level 2)
        │
   ┌────┼────┐
  atom atom atom                          (level 3)
```

**Paragraphs are the primary search target.** The `recall_with_context` MCP tool runs vector kNN over level-2 paragraphs first, then *batches in* the structural context for each hit: the paragraph's atoms (level 3), its sibling paragraphs in the same section (level 2), its corroborating edges, and its neighbor paragraphs. The level-2-only filter is explicit in the SQL (see `(properties->>'level')::int = 2` throughout [`crates/epigraph-mcp/src/tools/recall.rs`](../../crates/epigraph-mcp/src/tools/recall.rs)). Searching at atom level is too noisy — atoms strip away their surrounding context and the kNN catches spurious near-matches. Searching at paper level is too coarse — a 50-page document averages out into a single embedding that does not retrieve well. Paragraphs are the unit of meaning that recall is tuned for.

This shape exists only because ingestion *creates* it that way. The
single canonical ingest path is **Tier 1 hierarchical extraction**:
the `extract-claims` LLM extractor consumes a paper, emits
paragraph- and atom-level claims as a tree, and the
`ingest_document` writer lands them with the parent edges already
in place. There is no supported flat-extraction path. Two
historical failure modes are worth knowing about:

- **Jina embeddings in the primary column.** Earlier attempts at
  populating the primary embedding column with Jina vectors broke
  `recall_with_context` because the column held vectors from a
  model the kNN index was not built against. Never put Jina
  embeddings in the primary embedding column (user-memory
  `feedback_tier1_ingestion_only.md`).
- **Flat extraction without the level-2 paragraph layer.** Without
  paragraphs, `recall_with_context` has nothing to search at the
  right granularity — atom-level results lose context and
  paper-level results lose precision. The tree must exist before
  search works.

The dimensionality choice is the only thing recall is willing to
negotiate at query time: it auto-detects 1536 vs 3072 dimensions
from how the paragraph rows are populated (see
`paragraph_3072_population` and `detect_centroid_dim` in
`recall.rs`), defaulting to 3072 when ≥50% of paragraphs carry the
larger embedding.

Every `recall_with_context` response also carries a `corpus_scope` summary — `claims_total`, `paragraph_total`, `paper_total`, `themes_total` — so callers can tell how big the corpus was at query time. That number changes as ingest runs, and the LLM consuming the result needs to know whether it just searched 200 paragraphs or 200,000 before deciding how much faith to place in "we found nothing relevant".

A single recall hit, abbreviated, looks like this — note the structural batches around each paragraph:

```json
{
  "paragraph_id": "8f1d...",
  "paragraph_content": "DNA-origami actuators driven by ...",
  "similarity": 0.83,
  "truth_value": 0.71,
  "paper": {"doi": "10.1038/s41586-024-...", "title": "..."},
  "atoms":       [/* level-3 children */],
  "siblings":    [/* level-2 siblings in same section */],
  "corroborates":[/* CORROBORATES edges */],
  "neighbor_paragraphs": [/* nearby level-2 paragraphs */]
}
```

Each batched list also carries a `_total` and `_truncated` field (e.g., `atoms_total`, `atoms_truncated`) so the caller can tell when the structural fan-out was clipped. The `truth_value` field on `RecallHit` is a legacy scalar carried for back-compat; treat `pignistic_prob` from `get_belief` (§3) as the authoritative belief signal for ranking.

**See also:** [`crates/epigraph-mcp/src/tools/recall.rs`](../../crates/epigraph-mcp/src/tools/recall.rs) for the paragraph-primary kNN logic and the full `RecallHit` shape; user-memory `feedback_tier1_ingestion_only.md` for the single-canonical-ingest-path rule; the `extract-claims` skill (`.claude/skills/extract-claims/`) for the hierarchical extraction protocol the LLM follows.

---

## 6 — Backlog discipline

EpiGraph eats its own dog food: operational follow-ups are stored *as claims in the graph*, not in an external tracker. A backlog item is a claim filed with `labels=["backlog"]` via `submit_claim` (or `memorize`), with self-contained prose describing what needs to happen.

The retirement rule is rigid and worth memorising — there is exactly one correct tool:

```python
mcp__epigraph__resolve_backlog_item(
    original_id=<UUID of backlog claim>,
    resolution_content="<what was done, why it closes the item>",
)
```

`resolve_backlog_item` does two things in a single call: it creates a *resolution claim* labelled `["resolved"]` with content prefixed `"Resolves <id>: "`, and it patches the original backlog claim's labels with `add=["resolved"]`. Skipping either half leaves drift in the graph.

Do **not**:

- File a free-text "Resolves <UUID>" claim alone without patching the original's labels. The original keeps the `[backlog]` label and stays visible in every open-backlog query forever.
- Use `supersedes` / `is_current` for status. Those are reserved for **epistemic** replacement (one claim refining another's factual content), not operational status.
- Reach for raw `update_labels` to add `["resolved"]`. That bypasses the canonical resolution-claim trail and breaks downstream queries that join on the resolution prose.

The canonical "query open backlog" snippet from `CLAUDE.md`:

```python
mcp__epigraph__query_claims_by_label(
    labels=["backlog"],
    exclude_labels=["resolved"],
    current_only=True,
)
```

`exclude_labels=["resolved"]` is the half that catches retired items; `current_only=True` drops anything that has been epistemically superseded.

There is a daily safety net:
[`scripts/reconcile_backlog_labels.py`](../../scripts/reconcile_backlog_labels.py)
scans for free-text "Resolves <UUID>" claims filed without
`resolve_backlog_item` and back-fills the missing label patch.
Ambiguous matches go to
`docs/superpowers/reports/reconciler-needs-review.log` for human
triage — do not rely on the reconciler, fix the call site.

Why this matters: open backlog is the *operational* memory of the
system. If retired items linger as "open", every backlog review
spends time re-evaluating already-done work, and the open-vs-done
ratio stops being a usable signal. The `resolve_backlog_item` tool
exists specifically so that "I closed this" and "the graph knows I
closed this" are the same act, not two acts where the second one
gets forgotten.

Related but not the same:

- **Cross-agent backlog retire** is not allowed via
  `resolve_backlog_item` directly — it enforces owner-equality. The
  workaround is a free-text "Resolves <UUID>:" prefix on the
  resolution claim and letting the daily reconciler patch the
  label (user-memory `feedback_cross_agent_backlog_retire.md`).
- **EpiClaw dedup-first rule** — EpiClaw's `CLAUDE.md` requires a
  `recall()` and a restatement test *before* `submit_claim` or
  `memorize`, including before filing a backlog item. This stops
  the backlog from accumulating near-duplicates that defeat the
  open-backlog query.

**See also:** [`docs/conventions/backlog-retirement.md`](../conventions/backlog-retirement.md) for the canonical convention; `CLAUDE.md` for the rule of thumb every session loads; the design spec at `docs/superpowers/specs/2026-05-16-backlog-retirement-design.md` for the full rationale.
