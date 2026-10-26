# Noun-Claims and Verb-Edges

**Status:** Canonical (S1 — 2026-04-25)
**Owners:** epigraph-internal
**Sub-projects:** S1 (this doc), S2 (backfill, future), S3a–S3d (writer migrations, future), S4 (apply migration 107, future)

---

## The pattern

EpiGraph's `claims` and `edges` tables encode two distinct kinds of element. Until 2026-04-25 the codebase had drifted into using `claims` for both. This document is the canonical statement of the pattern.

**Noun-claim** — a `claims` row representing an entity or assertion that has stable identity. Its `(content_hash, agent_id)` is the canonical key: there is at most one row per `(content_hash, agent)`. Examples:

- "Container `epiclaw-tg-7173612411` exists for group `telegram-7173612411`"
- "Task `epistemic-gaps` is scheduled"
- The textbook fact "evidence supports H₀ at confidence 0.8"
- The message body "ok"

**Verb-edge** — an `edges` row representing a timestamped occurrence or relationship involving one or more noun-claims. The edge's `created_at` (and optional `valid_from` / `valid_to`) carries the event time; `properties` JSONB carries event metadata; `relationship` carries the verb; `signature` / `signer_id` give the same audit guarantee as claim signatures (see "Edge signing" below). Examples:

- `host_agent --[spawned @ 2026-04-25T03:03:59Z, props={group: "epistemic-gaps"}]--> container_claim`
- `host_agent --[executed @ 2026-04-25T07:43:13Z, props={status: completed, duration_ms: 1342}]--> task_claim`
- `paper_artifact --[asserts @ 2026-03-30T23:50:03Z, props={extraction_run: "2026-03-30"}]--> textbook_fact_claim`

**Three rules that fall out of this:**

1. Re-occurrence of the same lifecycle event = new edge, not new claim.
2. Re-ingesting the same source content = new edge from a (per-run) source-artifact noun to the existing fact-claim, not a duplicated fact-claim.
3. `provenance_log` (cryptographic audit) is unchanged. Every claim/edge create still gets a row there. The change is what writers *create*: more edges, fewer duplicate claims.

The schema already supports this: `edges` carries `created_at`, `valid_from`/`valid_to`, `properties` JSONB, `labels`, `signature`, `signer_id`. The schema was designed for this; the writers drifted. No new columns are required.

## Worked examples

### Cause 1 — textbook ingest

Pre-pattern:
```
[run 1] INSERT claims (id=X, content="evidence supports H0 at conf 0.8", agent=ingest_agent, content_hash=h1, ...)
[run 2] INSERT claims (id=Y, content="evidence supports H0 at conf 0.8", agent=ingest_agent, content_hash=h1, ...)  -- DUPLICATE
```

Post-pattern:
```
[run 1] POST /claims {content="evidence supports H0 at conf 0.8", agent_id=ingest_agent, if_not_exists: true}
        → {claim_id=X, was_created: true}
        POST /edges  {source=paper_artifact_run1, target=X, relationship="asserts", created_at="2026-03-30T..."}
[run 2] POST /claims {content="evidence supports H0 at conf 0.8", agent_id=ingest_agent, if_not_exists: true}
        → {claim_id=X, was_created: false}
        POST /edges  {source=paper_artifact_run2, target=X, relationship="asserts", created_at="2026-03-31T..."}
```

The fact-claim is canonical (one row). Each run's `paper_artifact_runN` (a separate noun-claim) gets a fresh `asserts` verb-edge to the canonical fact.

### Cause 2 — MCP-driven agent submission

Pre-pattern: same agent submits the same content multiple times → multiple `claims` rows with same `(content_hash, agent_id)`.

Post-pattern: each call uses `if_not_exists: true`. The first submission creates the noun-claim; later submissions return `was_created: false`. The auto-emitted `AUTHORED` verb-edge on each submission is preserved — each submission is a distinct verb-event even when the noun-claim already exists.

### Cause 3 — host provenance

Pre-pattern: host writer records spawn / execution / lifecycle events as full `claims` rows where `content_hash = hash(container_name)` etc. Same container spawning twice produces duplicate claim rows.

Post-pattern: container existence is a noun-claim (created once, idempotent on re-spawn). Each spawn / execution / lifecycle event is a verb-edge from the `host_agent` to the container/task noun-claim, with `created_at = event_time` and `properties` carrying the event metadata.

## Recommended call sequence

```
POST /api/v1/claims  {content, content_hash, agent_id, if_not_exists: true}
    → {claim_id, was_created}

POST /api/v1/edges   {source_id: actor_agent_id, source_type: "agent",
                      target_id: claim_id, target_type: "claim",
                      relationship: <verb>, properties: {...}, created_at: <T>}
    → {edge_id}
```

Two calls. Two transactions. Composes cleanly. A combined "create-claim-and-edge" atomic helper endpoint is **not** provided in S1 (YAGNI); if composability problems show up later, a single-shot helper can wrap both.

### `if_not_exists: true` semantics

- The server checks for an existing row by `(content_hash, agent_id)` and returns the existing claim's id if found; else inserts.
- Response body adds `was_created: bool` so the caller can tell which branch ran.
- When `was_created: false`, the handler skips the `properties` / `labels` UPDATEs entirely. Mutating an existing canonical noun-claim from a different caller's request is surprising; it bypasses ownership/authorisation checks and can clobber metadata. Callers needing metadata changes go through PATCH endpoints.
- **MCP writers (post-S3a):** every submission emits its own Evidence and Trace as standalone noun-claims linked via `HAS_TRACE` and `DERIVED_FROM` verb-edges to the canonical claim, on every branch (first-create AND resubmit). The `was_created` marker on edge `properties` lets queries distinguish first-create from resubmit edges. This realizes the "re-occurrence = new edge" rule uniformly across `submit_claim`, `memorize`, `store_workflow`, `improve_workflow`, and `ingest_paper` (the Option-A tools — `memorize`, `store_workflow`, `improve_workflow` — choose to skip Evidence/Trace creation altogether on resubmit, so they don't emit these edges at all on resubmit; the Option-B tools — `submit_claim`, `ingest_paper` — create per-submission Evidence/Trace and emit per-submission edges).
- **API handler (`POST /api/v1/claims`, pre-S3a behavior, pending alignment):** when `was_created: false`, skips the `HAS_TRACE` and `DERIVED_FROM` edges (only `AUTHORED` accumulates). This was the original rule before S3a, motivated by metadata-clobber concerns from non-owner submitters. The MCP writers diverged from this in S3a; aligning the API handler to MCP's accumulating semantics is spec backlog item #10. Until aligned, callers see different lineage cardinality depending on which writer wrote the claim.
- The DB schema enforces no triple-uniqueness (migration 109 dropped it). Verb-edges accumulate freely; application code is responsible for noun-edge idempotency where the relationship represents an invariant (e.g., `improve_workflow`'s `variant_of` skip on resubmit).
- `if_not_exists: true` × `privacy_tier != "public"` returns `400 Bad Request`. Encrypted claims store ciphertext keyed by group epoch; cross-group dedup on plaintext hash would either leak content equality across groups or no-op against the `[private]` placeholder. Encrypted submissions stay on the `if_not_exists: false` (raw insert) path until a future spec.
- `if_not_exists: true` × `content_hash` override returns `400 Bad Request`. The override is a textbook-ingest-script feature that S3c retires; new callers should compute hashes server-side.

### Pre-107 race window (acknowledged, not solved in S1)

Until migration 107 lands, the DB has no `(content_hash, agent_id)` UNIQUE constraint. Two concurrent `if_not_exists: true` requests for the same key can both find no existing row and both insert. Once 107 is applied, the second insert fails with a constraint violation; the handler catches that error and returns the existing row. S1 does not add advisory-lock serialization in the pre-107 window — the race window already exists for every claim-creation path today, S2 backfill cleans up any extra rows, and adding a per-key advisory lock now would be removed when 107 lands.

## Atomicity policy

Writers are responsible for retry/cleanup if the verb-edge call fails after the noun-claim call succeeds. Orphaned noun-claims are tolerated — they have no effect on graph queries that traverse from edges, and S2-style sweeps can collect them. S3 writer plans may add per-writer retry-on-edge-failure if the writer's audit semantics require strict consistency. The auto-emitted `AUTHORED` edge already gives every successful `POST /api/v1/claims` a baseline edge anchor, so total orphans only occur on transaction-commit failure.

## Boundary with the `activities` audit table

`activities` rows describe events without graph traversal. Verb-edges replace `activities` for graph-traversable events (where the edge connects two entities and graph queries reach the event). `activities` remains for non-graph audit (bulk operations, system-level events without entity targets). S3d (host provenance porting) is the canonical migration target — host events currently written to `activities` move to verb-edges as part of that work. Migration 106's `ALTER TABLE activities ALTER COLUMN agent_id DROP NOT NULL` predates this architectural pivot and is preserved; it has no bearing on verb-edge semantics.

## Edge signing

`edges` carries `signature`, `signer_id` and `content_hash` (initial schema; migration 117's `edges_repoint_unsign` clears all three when a non-privileged session re-points an edge). What an edge signature covers, how it is written and how it is checked are defined below; the MCP and HTTP edge writers sign (rulings R-49, R-50), and the writers listed as unsigned in the inventory do not yet.

**What is signed** (`epigraph_db::repos::edge_signature`). The attestation digest is BLAKE3 over the canonical JSON of the stored row's `{schema: "epigraph-edge-attestation/1", id, source_id, source_type, target_id, target_type, relationship, properties, valid_from, created_at}` (timestamps RFC 3339, microseconds, UTC). It is stored in `edges.content_hash`, and the signature is over the v1 edge message `epigraph-sig-v1:edge:` || digest, so it never verifies as a claim or evidence signature. `id` and `created_at` bind it to the row; `valid_to` is excluded, so a retraction never reads as tampering; `properties` is included, so a later patch (`patch_edge`, a workflow's `plan_index` rewrite) or an administrative re-point leaves `signature_valid: true` with `content_matches: false` ("changed since it was signed").

**How it is written.** At INSERT (ruling R-50), the way the MCP and HTTP writers sign: every `EdgeRepository` insert primitive has a signed twin (`create_signed_conn`, `create_signed` on a pool, `create_if_not_exists_signed_conn`, `create_if_absent_including_retracted_signed_conn`, `create_processed_by_stamp_if_absent_signed_conn`, the symmetric `*_signed_conn` forms) that takes the writer's `EdgeSigningKey { signer, signer_id }`. The writer chooses the edge's `id` and `created_at` (at the microsecond), so the digest exists before the row; `edge_signature::insert_attested_conn` writes the row, `content_hash`, the signature and `signer_id` in one INSERT inside a savepoint, recomputes the digest from the RETURNING row and, if the database rewrote a column, re-makes the INSERT once over the stored values (a second mismatch writes nothing). A dedup hit returns the existing row and writes nothing onto it. This is the only way a world-owned structural edge (an `agent` endpoint, `processed_by`) is signed at all: no application session may UPDATE it (migration 117). After the INSERT, for an edge the writer owns: `EdgeSignatureRepository::sign_created_edge_conn(conn, viewer, edge_id, signer, signer_id)` runs on the writer's own stamped connection with the write predicate (`{WRITABLE:e}`), right after the INSERT, and only for an edge this act created (never on a dedup hit). It locks the row `FOR UPDATE`, so migration 117's owner-scoped UPDATE policy stops anyone but the edge's owner from attesting it, and it never overwrites an existing attestation. `verify_conn` checks it under the signer's keys that were admitted when the edge was created: an attested key whose status and window (`agent_key::key_window_admits`) admit the edge's `created_at`, or the bare `agents.public_key` only when no `agent_keys` row carries those bytes, so a revoked, pending or out-of-window key never verifies an edge. That admission rule is `agent_key::admitted_signature_keys`, and `verify_claim` applies the same one (backlog 06a50a30): the two verifiers differ only in which message they accept. Edges accept ONLY the v1 edge message, never a legacy bare digest: the attestation schema is new, so no pre-v1 signature can be over an attestation digest, and a claim whose content is an edge's canonical attestation JSON has a content hash equal to that digest, so a legacy rung would accept a pre-v1 claim signature as an edge signature. A signed edge that is not a v1 attestation by any key of its signer (the bulk attestations written before this scheme, see below) reports `pre_attestation: true`, is never valid, and gets no `content_matches` comparison. `coverage` (viewer-scoped) is the unsigned-edge metric, reported by `system_stats` (`detailed: true`) as `edges_signed` / `edges_unsigned`; `edges_signed` counts rows CARRYING a signature, including those pre-attestation rows, so it is an upper bound on verifiable edges.

**Writer inventory.** `crates/epigraph-db/tests/edge_writer_signing_ratchet.rs` is the measured register of every edge-emitting site under `crates/*/src` (98 sites in 58 functions when it landed) AND of every SQL function in `migrations/*.sql` whose live definition inserts into `edges` (5 when it landed), each with its signing status. A new site fails the test until it is registered; a site registered `Signed` must call `sign_created_edge_conn`, or a signed twin and name its key (`edge_signing_key()` / `EdgeSigningKey`); a migration that redefines a registered database writer trips it again; the unsigned count (103 when it landed, 46 once the MCP and HTTP writers signed) should only go down, and raising it is a reviewed change to that file. Who signs, and why the rest do not:

| Writers | Key material | Status |
|---|---|---|
| `epigraph-mcp` (verb-edges in `claim_helper.rs`, the `link_*` tools, ingestion, perspectives, auth lineage, `resolve_backlog_item`) | the MCP server's signing key (`EpiGraphMcpFull::edge_signing_key`) | Signed at INSERT (R-49): `signer_id` = the server's signer agent, never the edge's author |
| `epigraph-api` routes | the API's OWN key (`EPIGRAPH_API_SIGNING_KEY_FILE`, `epigraph_api::edge_signer`; a separate signer agent) | Signed at INSERT when the key is configured (R-50); with no key they write unsigned and the server says so once at boot. `promote_staged_edges` (one bulk INSERT .. SELECT) is still unsigned |
| `epigraph-ingest-executor`, `epigraph-engine` matching, operator CLIs | none | Unsigned; a caller that holds a key would sign through the returned edge ids |
| repository acts in `epigraph-db` (supersede, dedup, consolidate, analysis, semantic links, match promotion) and the `EdgeRepository` primitives | none | Unsigned; the signing caller has to receive the edge id |
| database functions: `epigraph_link_operator_body` (OPERATED_BY, behind `epigraph_link_operator` and the identity lineage), `epigraph_link_retired_agent`, `epigraph_link_retired_shared_signer`, `epigraph_link_legacy_authors`, and the `epigraph_role_assignments_audit` trigger (OCCUPIES) | none (a database function holds no entity key) | Unsigned; these edges could only be signed at INSERT time with a key the caller passes in, or by a database-held key |

Since migration 120 the author of an edge is `edges.writer_group_id`, not `signer_id`; readers that need an agent take the source claim's (`backfill_factors::EDGE_QUERY`, the operator's edge-writer read). On legacy rows `signer_id` is, where set, a bulk attestation key; `epigraph_reown_legacy_edges_to_signer` takes a mandatory exclusion list of non-author signing keys, which the operator passes by hand and which must now include the MCP server's signer agent and the API's signer agent (no in-tree caller passes it).

**Provisioning the API key (operator).** Generate a fresh random Ed25519 key, distinct from every MCP key; write its 32 private bytes as 64 hex characters to a file readable only by the API unit's user; set `EPIGRAPH_API_SIGNING_KEY_FILE` to that path in the API unit's environment (never the key itself). On first boot the server registers an `epigraph-api-signer` agent with the public half, or uses the agent whose active `signing` key it is, and logs the agent id and public key. To rotate, register the new public key as that agent's active `signing` key in `agent_keys`, mark the old row rotated with its `valid_until` set, and point the file at the new key; edges signed under the old key keep verifying because their `created_at` falls inside that recorded window (a rotated row with no `valid_until` admits nothing). Add the signer agent to `p_exclude_signers` on any later `epigraph_reown_legacy_edges_to_signer` run.

## Supersession carries verb-edges, except a step's frozen ones

When a claim is replaced (`supersede_claim`, or `evolve_step` with `supersedes`), the new claim records `claims.supersedes = <old>`, and the Supersede admin cascade (`ClaimRepository::migrate_superseded_edges_conn`, run on the maintenance connection after the act commits, or by the deferred replay) re-points the old claim's edges onto the replacement. Weakening edges (`refutes`, `contradicts`) stay on the content they were filed against (issue #398). A STEP-LINEAGE supersession (old and new share a `step_lineage_id`: `evolve_step(supersedes)`) also leaves four kinds of edge on the retired step:

- `executes` (workflow → step): it names the FROZEN original step; readers reach the live head through the lineage (`ClaimRepository::latest_in_lineage`).
- the workflow's chain, `step_follows` and `phase_follows`, in either direction: it links the same frozen steps `executes` names, and `workflow_steps::ordered_steps` walks it only inside that set, so a chain edge moved onto the head would break the step order.
- `revises`, in either direction: like `supersedes`, it is the lineage's own branch history (`R -revises-> S` says R branched from S), so it stays between the versions it was written between.
- an agent's `asserts` / `AUTHORED`: the evolved step is written by the evolve_step caller, so another agent's assertion of the old content is not an assertion of the new one.

Everything else moves with the head: `decomposes_to` in both directions, `continues_argument`, `section_follows`, `alternative_of`, and strengthening edges such as `supports`. The rule is derived from the rows, so the deferred replay applies it without knowing the original caller (backlog 8d3b4527).

## Migration sequence

- **Migration 106** (`migrations/106_security_and_hardening.sql`) — composite index, bp_messages factor_id index, `activities.agent_id` nullability comment + DROP NOT NULL. Applicable to the live DB today (idempotent or no-op against current state).
- **Migration 107** (`migrations/107_claims_unique_content_hash_agent.sql`) — `UNIQUE (content_hash, agent_id)` on `claims`. **Will fail until S2 backfill completes.** Failure mode is loud and explicit (a `duplicate key value violates unique constraint` error); the migration is intentionally not wrapped with `NOT VALID` + later `VALIDATE`, because the constraint represents a real architectural invariant and any future apply attempt should refuse on a dirty table.

## Writer dedup beyond content_hash (S3 cross-cutting)

S1's `if_not_exists: true` primitive dedups on byte-identical content_hash. That catches every deterministic re-run — host provenance (whose hashes are stable by construction: `hash(container_name)`, `hash(task_id:status)`), agents re-submitting identical text, scripts re-posting cached content. It does **not** catch LLM-driven extractors that reword the same fact across runs. "Evidence supports H₀ at conf 0.8" and "the data supports the null hypothesis with confidence 0.8" hash to different values, both rows are written, and migration 107's UNIQUE constraint won't fire.

To keep the LLM-judged "same-as" pass to the long tail rather than the main path, S3 writers (especially S3c, which handles non-deterministic LLM extraction) implement layered dedup:

- **Layer 0 — content_hash exact match.** S1's `if_not_exists: true` primitive. Mandatory for every S3 writer; fires first.
- **Layer 1 — source-coordinate dedup.** *Before* invoking the extractor on a source location, query the graph for an existing fact-claim already extracted from that location: `edges WHERE source.properties->>'paper' = q AND source.properties->>'paragraph' = p AND relationship = 'asserts'`. On hit, post a new `asserts` verb-edge from this run's artifact to the existing canonical claim and skip the LLM call entirely. The cheapest defense against LLM non-determinism — you never invoke the model if you've already covered the source. The per-run source-artifact pattern is what makes this query natural; without it, source coordinates have nowhere to live.
- **Layer 2 — embedding near-neighbor.** When the writer *has* invoked the extractor and obtained a candidate, embed it and search same-agent claims for cosine ≥ ~0.92. On hit, post the verb-edge to the existing canonical, skip the insert. Cheap inference (one embedding + HNSW lookup). Threshold is a starting point, tunable against pairs labeled during S2 backfill — any pair S2 chooses to merge is a labeled positive. Recall: commit 8f1de9e culled `CORROBORATES` at <0.80 because that was too loose for *related* edges; *identity* needs stricter.
- **Layer 3 — LLM same-as judge.** Reserved for the ambiguous band (Layer 2 cosine in 0.85–0.92, or cross-agent near-matches). Fired inline at write time, never as a periodic graph-wide sweep. Rare by construction; if volume grows large, lower Layer 2's threshold rather than scaling Layer 3.

Per-sub-project applicability:

| Writer | Layer 0 | Layer 1 | Layer 2 | Layer 3 |
|---|---|---|---|---|
| S3a `epigraph-mcp` | required | n/a (no source coords) | optional | optional |
| S3b `epigraph-agent` `submit_claim` | required | n/a | required | when L2 is ambiguous |
| S3c V2 ingest scripts | required | **required** | required | when L2 is ambiguous |
| S3d host provenance | required | n/a (deterministic hashes) | n/a | n/a |

Architectural point: byte-equality dedup is necessary but insufficient for LLM-driven writers. Layered defense at write time keeps the same-as judge off the periodic-sweep path. A graph-wide LLM same-as sweep is the failure mode this layering exists to prevent.

## Sub-project map

- **S1 (this doc):** pattern + idempotent claim-create primitive + migration split. Done in PR #6.
- **S2 (backfill):** convert each of the ~95,214 existing `(content_hash, agent_id)` duplicate groups into one canonical claim plus (N-1) timestamped verb-edges. Redirect the 413k existing edges, 95k MFs, and 2.3k evidence rows pointing at non-canonical rows. Pairs merged during backfill are labeled training data for tuning Layer 2's threshold (see "Writer dedup beyond content_hash" above). Future spec.
- **S3 (writers):** four sub-plans (S3a `epigraph-mcp`, S3b `epigraph-agent` `submit_claim` builtin, S3c V2 ingest scripts, S3d V2 `epigraph-nano/provenance.rs`). All implement layered dedup per the previous section; S3c specifically requires Layers 0–2 because LLM extraction non-determinism otherwise defeats Layer 0 alone. S3a runs first to stop new dups accumulating; S3b–S3d parallelisable with S2 once S3a deploys.
- **S4 (apply migration 107):** one-liner once writers are clean and S2 has settled. User-authorized `sqlx migrate run`.

Each sub-project gets its own brainstorm → spec → plan cycle.
