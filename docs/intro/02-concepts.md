# EpiGraph Concepts

EpiGraph is an evidence-graph database that records *what is claimed*, *who claimed it*, *when it occurred*, and *how strongly it is believed* — all in a way that survives re-ingest, re-extraction, and disagreement between agents. This page is the orientation layer: each sub-section explains one core idea, points at a worked example, and links to the canonical deeper doc for the specialist details. Read it once front-to-back; later you can jump back via the table of contents below.

If you have not yet run through [`01-quickstart.md`](01-quickstart.md), do that first — it gets a kernel up so the examples below have somewhere to land. This file answers *what the moving parts are*. The [`04-glossary.md`](04-glossary.md) entries refer back into the sections below by anchor.

## Table of contents

1. [Noun-claims vs verb-edges](#1--noun-claims-vs-verb-edges) — what goes in `claims` vs `edges`
2. [Agents and signing](#2--agents-and-signing) — who authors and how authorship is cryptographically anchored
3. [Beliefs and DST](#3--beliefs-and-dst) — how the graph carries uncertainty (BetP, mass functions, discounting)
4. [Perspectives, frames, themes](#4--perspectives-frames-themes) — viewpoints, hypothesis spaces, topical clusters
5. [Hierarchical extraction](#5--hierarchical-extraction) — thesis → sections → paragraphs → atoms and why paragraphs are primary
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
the writers are meant to keep one row per key. That is a writer
contract, not a database constraint: migration 150 dropped
`UNIQUE (content_hash, agent_id)` because the long-lived database
holds duplicate groups it could never satisfy. The idempotent create
paths take an advisory lock on the pair before they look for an
existing row; a writer that inserts without it can still add a second
row for the same key (the architecture doc linked below lists which
writers take the lock). Examples:

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
  deploy, parallel host — all the same agent UUID. That string is only
  the LEGACY seed: once a deployment registers its system agent in the
  `system_agents` registry (migration 148), the registry is
  authoritative and the agent's key can be rotated to a secret one.
- **LLM-driven agents** — the seed is the model identifier plus the
  BLAKE3 hash of the system prompt, so the same model+prompt pair
  resolves to the same agent identity across sessions. The MCP server
  derives its signer this way when it is started with `--agent-model`
  (`EPIGRAPH_AGENT_MODEL`) and `--agent-system-prompt` or
  `--agent-system-prompt-hash` (`keypair_from_llm_agent` in
  `epigraph-crypto`; first tracked in
  [issue #166](https://github.com/epigraph-io/epigraph/issues/166)).
  Both inputs are public, so anyone who can read them can recompute
  that private key. User OAuth passthrough sits next on that roadmap,
  so writes attributed to "Claude with prompt X acting for Jeremy" can
  be distinguished from "Claude with prompt X acting for Carrie".

A seed is not the only way the MCP server gets its identity. It picks its signer in this order (`select_signer` in `crates/epigraph-mcp/src/main.rs`), first match wins:

1. `EPIGRAPH_AGENT_IDENTITY_PUBKEY` together with `EPIGRAPH_AGENT_SIGNING_KEY`: the agent is named by the identity key and signs with a separate random key. Both are required, and they cannot be combined with the two options below.
2. `--agent-model`, the LLM-agent seed above. It takes precedence over `--agent-key`.
3. `--agent-key` (`EPIGRAPH_MCP_AGENT_KEY`): a fixed 32-byte secret key that you generate once and keep. This is what the [quickstart](01-quickstart.md) sets up.
4. None of these: the server generates a fresh keypair on every launch and says so on stderr. Each launch then authors as a different agent, and the server warns that ownership cannot be decided for such a signer.

A `did:key` URI looks like this:

```text
did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
```

The `z` is base58btc multibase, the leading bytes inside the base58 payload are the multicodec prefix `0xed01` for Ed25519, and the rest is the 32-byte public key. Resolving a DID requires no network call — the public key is in the URI, so signature verification is purely local.

The schema carries `signature`, `signer_id` and `content_hash` columns on `claims`, `evidence` and `edges` (all three since the initial schema). Every claim and evidence signature written by the MCP server and the in-tree CLIs is over an entity-tagged message, never a bare digest: `b"epigraph-sig-v1:<claim|evidence|edge>:" || digest` (`epigraph_crypto::signing_message`), and a new claim row stores only a v1 claim signature. The tag is the domain separation: a v1 signature over an evidence row's hash does not verify as a signature over a claim with the same hash. The exceptions: rows written before v1 carry a legacy signature over the bare digest; evidence signatures that HTTP packet clients supply are stored as sent (no evidence verifier checks them); and the canonical-JSON struct signatures (`Signable`, used by the harvester) and the `submit_packet` envelope signature are a separate, untagged scheme. The claim verifier tries the v1 message first and then the legacy bare digest, and reports which one verified (`verify_claim`'s `signature_scheme`: `v1` or `legacy`); a legacy signature binds no type, so a legacy evidence signature copied onto a same-content claim still verifies, reported `legacy`. The edge verifier accepts v1 only. Only the signed message changed: stored content hashes and every identity derived from one are unchanged. Claims and evidence written through MCP are signed. Edge signing has a defined attestation (`epigraph_db::repos::edge_signature`), a verifier and a coverage metric (`system_stats` with `detailed: true` reports `edges_signed` / `edges_unsigned`), and some edge writers sign: the MCP server signs the edges its tools write, at INSERT, with the server's own signing key, and the HTTP API's routes sign with the API's separate key when `EPIGRAPH_API_SIGNING_KEY_FILE` is configured (with no key they write unsigned). The repository acts (supersede, dedup, consolidate, match promotion), the ingest executor, the operator CLIs and the database functions that insert edges do not sign. See ["Edge signing" in the noun/verb architecture doc](../architecture/noun-claims-and-verb-edges.md#edge-signing) for the writer table and why. The `provenance_log` table records every create or patch independently of the row-level signature, so even an unsigned edge has a tamper-evident audit trail keyed by the requesting principal.

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

Practical implication for new code: never generate an Ed25519 keypair on each run "to identify this process" (rung 4 above is the fallback, not a pattern to copy). Give the process a stable identity: a fixed key generated once and stored (`--agent-key`), or the deterministic helper that matches the actor type: `did_key_for_author` for human authors, fixed system-agent seed helpers for named infrastructure agents, and `keypair_from_llm_agent(model_id, system_prompt)` for autonomous LLM agents (`did_key_for_llm_agent` returns the `did:key` of the same keypair). The LLM helper hashes the system prompt and combines it with the model identifier, so the same model+prompt pair gets the same DID across hosts while any model or prompt revision becomes a distinct signing identity. Let the get-or-create pattern in `system_agent.rs` find or insert the matching `agents` row. The same role on a different machine then writes against the same agent UUID and the same signing key, so attribution composes cleanly across hosts.

**See also:** [`crates/epigraph-crypto/src/did_key.rs`](../../crates/epigraph-crypto/src/did_key.rs) for `did:key` derivation; [`crates/epigraph-ingest-executor/src/system_agent.rs`](../../crates/epigraph-ingest-executor/src/system_agent.rs) for the get-or-create pattern; user-memory `reference_epigraph_oauth_mint.md` for the Ed25519 client-assertion shape against `/oauth/token`.

---

## 3 — Beliefs and DST

EpiGraph does not treat a single scalar as a claim's belief. Every claim row does carry one scalar, `truth_value` (`NOT NULL`, default 0.5). A claim that has been judged also carries **Dempster-Shafer mass functions** over a frame of discernment, stored per `(claim, frame)`, and its belief is their combination. This matters because real-world evidence is often partial, conflicting, or missing entirely, and a single scalar cannot distinguish "we think it's 0.5" from "we have no idea, so we are reporting 0.5".

Which number you are served depends on the read:

- **Unframed `get_belief`** returns the combination cached on the claim row (`belief`, `plausibility`, `pignistic_prob`, and the two diagnostic masses). The cache holds ONE frame's combination, recorded in `claims.belief_frame_id`. A cache recompute (`recompute_claim_cached_belief` in `crates/epigraph-engine/src/edge_factor.rs`) picks that frame as `binary_truth` when the claim has evidence there, else `claim_validity`, else the frame already recorded, else the frame of the claim's earliest evidence.
- **Framed `get_belief`** (a `frame_id`, optionally a perspective) recombines the stored mass functions on that frame at read time.
- **A claim no Dempster-Shafer write has touched** has no cache. `get_belief` then reports an interval rebuilt from `truth_value` (`belief = pignistic_prob = truth_value`, `plausibility = 1.0`), so that an unassessed claim does not read as a refuted one.

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
  "source": "cached"
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
- `source` reports how the value was assembled: `"cached"` for an
  unframed read (the claim row's cache, or the `truth_value` fallback
  described above), `"recomputed"` or `"recomputed_perspective"` for a
  framed read, and `"no_bbas"` when the frame holds no mass function
  for the claim.

The struct lives at `BeliefResponse` in `crates/epigraph-mcp/src/types.rs`.

When evidence from multiple sources is combined, the writer
**discounts** each input mass function by a reliability factor in
`[0, 1]` (1.0 = fully trusted, 0.0 = belief moves entirely to
ignorance) before applying Dempster combination — this is the
correct way to fuse evidence under uncertainty per Shenoy-Shafer.
The `submit_ds_evidence` MCP tool exposes the `reliability`
parameter directly. A claim's belief is always recomputed by one
shared Dempster fold. `submit_ds_evidence` still accepts a
`combination_method` (`Dempster`, `Conjunctive`, `YagerOpen`,
`YagerClosed`, `DuboisPrade`, `Inagaki`), but the parameter is
deprecated: the name is validated, stored on the mass function and
echoed back as `method_used`, and has no effect on belief; any value
other than `Dempster` adds a warning to the response. The other
rules are implemented in `crates/epigraph-ds`, and the read-only
`compare_methods` tool runs all six over a claim's stored mass
functions so you can see how sensitive it is to the choice.

Scalar propagation is no longer what belief is served from, but it has not been removed from the tree. Multiplying scalar truth values along edges collapses them toward zero independently of how strong the evidence actually is, which is why the Dempster-Shafer path is primary. What remains: the loopy belief-propagation engine (`crates/epigraph-engine/src/bp.rs`) is reachable through `POST /api/v1/bp/propagate` as a read-only diagnostic (a request to write its results is refused with 409 unless the server was started with `EPIGRAPH_BP_APPLY=on`), and a few HTTP paths still write `truth_value` through the deprecated `BayesianUpdater`: a packet submission's initial truth, the workflow outcome report, and forgetting a convention.

`truth_value` is not a leftover column. It is set on every claim and the kernel still reads and writes it:

- **What it holds.** The scalar the claim was authored with, or a copy of the cache: `submit_claim` and `update_with_evidence` store `truth_value = clamped(pignistic_prob)` when they fold evidence. A later cache recompute rewrites the cache and not `truth_value`, so such a copy can be stale; the operator binary `refresh_truth_mirrors` (`crates/epigraph-cli`) brings stale copies back in step with the cache.
- **Where it is read.** The belief score that `recall` and `query_claims` gate on with `min_truth` is the pignistic probability when the claim has a Dempster-Shafer cache and `truth_value` when it does not. Several queries order by the column directly: `ClaimRepository::get_high_truth` / `get_low_truth`, the workflow listings in `crates/epigraph-db/src/repos/workflow.rs`, and the ranking of a recall hit's epistemic neighbors.

So rank by `pignistic_prob` (or a result's `belief_score`) in your own code, and expect `truth_value` to decide the order wherever the kernel's own queries sort by it.

The `bp_messages` table has not been dropped either. `FactorRepository` keeps its read and write functions for it (nothing outside the tests calls the write at the time of writing), and retiring a promoted match candidate deletes that factor's rows from it.

Math kept at intro level: full DST adds operations like Yager normalisation (re-attributing conflict mass to ignorance), Dubois-Prade combination (each conflicting pair's mass goes to the union of the two sets), the cautious rule (for sources that are not independent), and discounting with `mass_on_missing` to model open-world ignorance. Those live in `crates/epigraph-ds/src/combination.rs` — for the intro, hold onto the three-bucket story: belief, plausibility, ignorance, with BetP as the scalar projection you sort by.

**See also:** the LANL Open World DST paper (LA-UR-25-23655) for the practitioner's foundation; [`crates/epigraph-mcp/src/tools/ds.rs`](../../crates/epigraph-mcp/src/tools/ds.rs) for `submit_ds_evidence`, `get_belief`, and `compare_methods`; [`crates/epigraph-engine/src/belief_query.rs`](../../crates/epigraph-engine/src/belief_query.rs) for the unframed and framed reads.

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

The `perspectives` table also has a second, internal use that is not a
viewpoint. A machine-written mass function is keyed by
`(claim, frame, agent, perspective)`, and `mass_functions.perspective_id`
is a foreign key, so the kernel creates a synthetic perspective row to
give each such mass function its own slot:

- one per epistemic edge: `name = 'edge_factor'`,
  `perspective_type = 'edge'`, and the row's `id` is the edge's id
  (`PerspectiveRepository::ensure_edge_perspective`);
- one per evidence row or assessment slot: `name = 'evidence_grounded'`,
  `perspective_type = 'evidence'`; for an evidence row it shares the
  evidence id (`PerspectiveRepository::ensure_evidence_perspective`).

These rows are slots, not lenses. `list_perspectives` does not filter
them out (`PerspectiveRepository::list` has no `perspective_type`
predicate), so on a graph with epistemic edges or evidence its output
includes rows of those two types; skip them when you choose a lens.

A **theme** is a topical cluster derived from semantic clustering
over claim embeddings. Themes are stored as rows in `claim_themes`
(`label`, `description`, `centroid` vector, `claim_count`), and
each clustered claim points to one theme via `claims.theme_id` —
theme membership is single-valued at the schema level. Themes are
how you navigate the graph at coarser granularity than individual
atoms. They are built and maintained by the UMAP theme pipeline:
`scripts/cluster_claims.py` (UMAP projection and clustering, run on the host
for a full rebuild) and `scripts/maintain_themes.py` (incremental: assign
unthemed claims, reassign by boundary ratio, split high-variance themes,
recompute centroids, all through `/api/v1/themes/*`). Agents read them with
the `list_themes` / `get_theme` MCP tools. The earlier k-means prototype
(`theme_cluster`, `POST /api/v1/themes/build-from-corpus`, the
`theme_cluster_rebuild` job) is retired; the `theme_cluster` name only
answers "retired". Because `claim_themes` has no `UNIQUE(label)`
constraint, the `auto-00, auto-01, …` rows that prototype left may repeat a
label.

Rule of thumb:

- A **frame** is *what is being judged* — a fixed hypothesis space.
- A **perspective** is *who is judging* — an agent's or group's lens
  (apart from the internal `edge` and `evidence` rows above).
- A **theme** is *what topic* the claims are about — a cluster label.

They are orthogonal. A single claim can sit in one frame, be
evaluated under three perspectives, and belong to one theme all
at the same time, and none of those facts contradict each other.

**See also:** [`crates/epigraph-mcp/src/tools/perspectives.rs`](../../crates/epigraph-mcp/src/tools/perspectives.rs) for `create_perspective`, `list_perspectives`, and `get_perspective`; [`crates/epigraph-mcp/src/tools/themes.rs`](../../crates/epigraph-mcp/src/tools/themes.rs) for theme clustering; the DST tools in `ds.rs` for frame creation.

---

## 5 — Hierarchical extraction

EpiGraph stores documents as a tree, not a flat bag of sentences. Each ingested source becomes four levels of claims: a **thesis** (when the extraction has one), its **sections**, each section's **paragraphs**, and each paragraph's **atoms**. The level lives in `properties->>'level'`: the thesis is level 0, sections are level 1, paragraphs are level 2, atoms are level 3. A `decomposes_to` edge links each node to its children, so the tree is graph-traversable in either direction, and each claim carries its own embedding, so every level is searchable; `recall_with_context` searches all of them and uses the tree as context (next paragraph).

The source itself is not a claim in that tree. It is a row in the `papers` table, and an `asserts` edge runs from the paper to each claim of the document. A query for `properties->>'level' = '1'` returns section headings, not papers.

```text
                  thesis (level 0)
                     │
          ┌──────────┼──────────┐
       section    section    section       (level 1)
          │
    ┌─────┼─────┐
paragraph paragraph paragraph              (level 2)
    │
 ┌──┼──┐
atom atom atom                             (level 3)

papers row ──asserts──▶ each claim above
```

**Every embedded claim is a search candidate; the hierarchy is context.** The `recall_with_context` MCP tool runs vector kNN over every claim that carries an embedding — paragraphs, atoms, sections, workflow steps, and claims written on their own with `submit_claim` or `memorize` — then *batches in* the structural context for each hit: its parent paper and section, its atoms (level 3), its sibling paragraphs in the same section (level 2), its corroborating and epistemic edges, and its neighbor paragraphs. Parentage is an enrichment attribute, not an eligibility filter: a hit with no paper attribution comes back without a `paper` key and with `section: null`, rather than being dropped. The hierarchy lists (atoms, siblings, neighbor paragraphs) are filled only for paragraph hits; corroborating and epistemic edges come from the hit's own edges whatever its level (backlog `a1d89aab`, drain U082). Paragraphs are still the unit of meaning the hierarchy is built around — an atom on its own strips away its surrounding context, and a 50-page document averages out into a single embedding that does not retrieve well — which is why the tree's context travels with every hit that has one. Earlier versions searched level-2 paragraphs only; an exactly matching standalone claim then lost to weaker paragraphs because it was never a candidate.

This shape exists only because ingestion *creates* it that way.
Hierarchical extraction is the canonical shape, and more than one
writer produces it. The MCP server registers four document tools:

- `structure_source` — read-only and deterministic. It splits raw
  markdown or plain text into a `DocumentExtraction` whose sections
  and paragraphs are byte-exact slices of the source, with the atoms
  left empty. No LLM rewrites the spine text.
- `ingest_document_inline` — the writer. It takes a complete
  `DocumentExtraction` in the call and lands the thesis, sections,
  paragraphs and atoms with their edges; when the extraction carries
  `source_text` it re-verifies the spans against it. For an authored
  record with no external source to quote (a lab-notebook entry, a run
  summary), omit `source_text` and this one call is the whole path.
- `ingest_document` — the same writer, reading the extraction from a
  JSON file inside the server's working directory.
- `ingest_document_spine` — phase 1 of a two-phase flow: it writes the
  thesis, sections and paragraphs, ignores atoms, and returns the paths
  of the paragraphs that are new, so only those are atomized before
  `ingest_document_inline` adds the atoms.

The `extract-claims` skill drives the first route for extracted
sources: `structure_source`, then the LLM fills in atoms only, then
`ingest_document_inline`. Outside MCP, the operator `ingest_document`
CLI runs the document writer on the maintenance connection, and the
`ingest_literature` CLI is a flat path: it submits each extracted
claim as its own packet, with no tree. Two historical failure modes
are worth knowing about:

- **Jina embeddings in the primary column.** Earlier attempts at
  populating the primary embedding column with Jina vectors broke
  `recall_with_context` because the column held vectors from a
  model the kNN index was not built against. Never put Jina
  embeddings in the primary embedding column (user-memory
  `feedback_tier1_ingestion_only.md`).
- **Flat extraction without the level-2 paragraph layer.** Without
  paragraphs, `recall_with_context` still finds the flat claims, but
  it has no paragraph-granularity hits and no structure to batch in
  around them — atom-level results lose context and paper-level
  results lose precision. The tree must exist for recall to return
  context.

The dimensionality choice is the only thing recall is willing to
negotiate at query time: it auto-detects 1536 vs 3072 dimensions
from how the embedded claims it searches are populated (see
`embedded_3072_population` and `detect_centroid_dim` in
`recall.rs`), defaulting to 3072 when ≥50% of the embedded claims
carry the larger embedding. The write paths embed at 1536 only
(`epigraph-cli reembed` writes the 3072 column), so measuring
paragraphs alone would switch to 3072 and hide every claim that was
never re-embedded.

Every `recall_with_context` response also carries a `corpus_scope` summary — `claims_total`, `paragraph_total`, `paper_total`, `themes_total` — so callers can tell how big the corpus was at query time. That number changes as ingest runs, and the LLM consuming the result needs to know whether it just searched 200 paragraphs or 200,000 before deciding how much faith to place in "we found nothing relevant".

A single recall hit for an ingested paragraph, abbreviated, looks like this — note the structural batches around it (a hit with no parent paper omits `paper` and has `section: null`; a hit that is not a paragraph gets empty atom, sibling and neighbor-paragraph lists):

```json
{
  "paragraph_id": "8f1d...",
  "paragraph_content": "DNA-origami actuators driven by ...",
  "similarity": 0.83,
  "truth_value": 0.71,
  "belief_score": 0.78,
  "paper": {"doi": "10.1038/s41586-024-...", "title": "..."},
  "atoms":       [/* level-3 children */],
  "siblings":    [/* level-2 siblings in same section */],
  "corroborates":[/* CORROBORATES edges */],
  "neighbor_paragraphs": [/* nearby level-2 paragraphs */]
}
```

Each batched list also carries a `_total` and `_truncated` field (e.g., `atoms_total`, `atoms_truncated`) so the caller can tell when the structural fan-out was clipped. The `truth_value` field on `RecallHit` is the claim's own `claims.truth_value`, reported unchanged; it is not what `min_truth` compares against. That is the hit's `belief_score`: the pignistic probability when the claim has a Dempster-Shafer cache, and `truth_value` when it does not (§3).

**See also:** [`crates/epigraph-mcp/src/tools/recall.rs`](../../crates/epigraph-mcp/src/tools/recall.rs) for the whole-corpus kNN logic and the full `RecallHit` shape; `docs/superpowers/specs/2026-06-18-deterministic-spine-ingest-design.md` for the verbatim-spine design; the `extract-claims` skill (`.claude/skills/extract-claims/`) for the hierarchical extraction protocol the LLM follows.

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

- **Who may retire an item.** `resolve_backlog_item` checks who owns
  the original claim, and the same check runs on any `update_labels`,
  `patch_claim` or `update_with_evidence` call that adds or removes
  `resolved`. The owner is the claim's author. On stdio it is also an
  agent linked to the same operator as the author (so an agent whose
  model was bumped, and which therefore runs under a new identity, can
  retire its predecessor's items) and an agent live-linked to the
  author itself (its delegate). Over HTTP it is the author's operator
  or a live delegated run token, and a `claims:admin` token also
  passes. A stdio agent that shares no operator with the author is
  refused, and so is a stdio server with no declared signer
  (`--agent-key` / `--agent-model`) on any claim it did not author.
  There is no free-text workaround: a bare "Resolves <UUID>:" claim is
  exactly the drift the "Do **not**" list above forbids. If you are
  refused, have an owner retire the item.
- **EpiClaw dedup-first rule** — EpiClaw's `CLAUDE.md` requires a
  `recall()` and a restatement test *before* `submit_claim` or
  `memorize`, including before filing a backlog item. This stops
  the backlog from accumulating near-duplicates that defeat the
  open-backlog query.

**See also:** [`docs/conventions/backlog-retirement.md`](../conventions/backlog-retirement.md) for the canonical convention; `CLAUDE.md` for the rule of thumb every session loads; the design spec at `docs/superpowers/specs/2026-05-16-backlog-retirement-design.md` for the full rationale.
