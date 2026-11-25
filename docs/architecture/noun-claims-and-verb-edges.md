# Noun-Claims and Verb-Edges

**Status:** Canonical (S1 — 2026-04-25)
**Owners:** epigraph-internal
**Sub-projects:** S1 (this doc), S2 (backfill), S3a–S3d (writer migrations), S4 (the `UNIQUE (content_hash, agent_id)` constraint, abandoned by migration 150). Status of each is in "Sub-project map" below.

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
- **API handler (`POST /api/v1/claims`, and `POST /api/v1/claims/batch` per item):** when `was_created: false`, the handler emits a new `AUTHORED` edge only when the caller is the matched claim's author (the token's principal equals the row's `agent_id`), as MCP's writers do on every submission (backlog 4952d77a). A dedup hit on a claim someone else authored writes no edge at all: the request body's `agent_id` is not a credential, so without that check any caller could hang an edge off another tenant's claim. `HAS_TRACE` and `DERIVED_FROM` are still emitted only for a row the request created; re-emitting them on resubmit, as the MCP writers do since S3a, is the part of spec backlog item #10 still pending, so the two writers still differ in trace and evidence lineage cardinality, not in `AUTHORED`.
- The DB schema enforces no triple-uniqueness (migration 109 dropped it). Verb-edges accumulate freely; application code is responsible for noun-edge idempotency where the relationship represents an invariant (e.g., `improve_workflow`'s `variant_of` skip on resubmit).
- `if_not_exists: true` × `privacy_tier != "public"` returns `400 Bad Request`. Encrypted claims store ciphertext keyed by group epoch; cross-group dedup on plaintext hash would either leak content equality across groups or no-op against the `[private]` placeholder. Encrypted submissions stay on the `if_not_exists: false` (raw insert) path until a future spec.
- `if_not_exists: true` × `content_hash` override returns `400 Bad Request`. The override is a textbook-ingest-script feature that S3c retires; new callers should compute hashes server-side.

### The create race: closed by an advisory lock, not by a constraint

The database has no `(content_hash, agent_id)` UNIQUE constraint (see "Migration sequence" below), so the one-row-per-key rule is a contract the writers keep. S1 left the race open, expecting the constraint to close it: two concurrent `if_not_exists: true` requests for the same key could both find no row and both insert. The constraint never became possible on the long-lived database, so the race is closed in the application instead: `ClaimRepository::create_or_get_signed` and `POST /claims` (`if_not_exists=false`) take a transaction-scoped advisory lock on the pair (`ClaimRepository::lock_content_hash_agent`) before their find, so two concurrent first creates serialize.

Not every writer takes the lock, and a row written without it is not deduplicated by it. Writers that take it: the idempotent creates above, the legacy content-hash creates (`ClaimRepository::create`, `create_conn`, `create_with_tx`), `consolidate_act_conn`'s existing-merge probe and the `method_search` maintenance binary. Writers that do not: the unconditional INSERTs with no find (`create_strict`, supersede, `evolve_step`, `batch_create`, hypothesis creation), the deterministic-id paths (`create_with_id_if_absent`, the ingest-executor's workflow `add_step`), the policy-challenge route (its own lock, its own narrower find), and raw-SQL fixtures. The maintained list is `lock_content_hash_agent`'s doc comment ("Who takes it") and `migrations/README.md`, "Known schema drift: `uq_claims_content_hash_agent` (013)".

## Atomicity policy

Writers are responsible for retry/cleanup if the verb-edge call fails after the noun-claim call succeeds. Orphaned noun-claims are tolerated — they have no effect on graph queries that traverse from edges, and S2-style sweeps can collect them. S3 writer plans may add per-writer retry-on-edge-failure if the writer's audit semantics require strict consistency. The auto-emitted `AUTHORED` edge already gives every successful `POST /api/v1/claims` a baseline edge anchor, so total orphans only occur on transaction-commit failure.

## Boundary with the `activities` audit table

`activities` rows describe events without graph traversal. Verb-edges replace `activities` for graph-traversable events (where the edge connects two entities and graph queries reach the event). `activities` remains for non-graph audit (bulk operations, system-level events without entity targets). S3d (host provenance porting) is the canonical migration target — host events currently written to `activities` move to verb-edges as part of that work. Migration 106's `ALTER TABLE activities ALTER COLUMN agent_id DROP NOT NULL` predates this architectural pivot and is preserved; it has no bearing on verb-edge semantics.

## Edge signing

`edges` carries `signature`, `signer_id` and `content_hash` (initial schema; migration 117's `edges_repoint_unsign` clears all three when a non-privileged session re-points an edge). What an edge signature covers, how it is written and how it is checked are defined below; the MCP and HTTP edge writers sign (rulings R-49, R-50), and the writers listed as unsigned in the inventory do not yet.

**What is signed** (`epigraph_db::repos::edge_signature`). The attestation digest is BLAKE3 over the canonical JSON of the stored row's `{schema: "epigraph-edge-attestation/1", id, source_id, source_type, target_id, target_type, relationship, properties, valid_from, created_at}` (timestamps RFC 3339, microseconds, UTC). It is stored in `edges.content_hash`, and the signature is over the v1 edge message `epigraph-sig-v1:edge:` || digest, so it never verifies as a claim or evidence signature. `id` and `created_at` bind it to the row; `valid_to` is excluded, so a retraction never reads as tampering; `properties` is included, so a later patch (`patch_edge`, a workflow's `plan_index` rewrite) or an administrative re-point leaves `signature_valid: true` with `content_matches: false` ("changed since it was signed").

**How it is written.** At INSERT (ruling R-50), the way the MCP and HTTP writers sign: every `EdgeRepository` insert primitive has a signed twin (`create_signed_conn`, `create_signed` on a pool, `create_if_not_exists_signed_conn`, `create_if_absent_including_retracted_signed_conn`, `create_processed_by_stamp_if_absent_signed_conn`, the symmetric `*_signed_conn` forms) that takes the writer's `EdgeSigningKey { signer, signer_id }`. The writer chooses the edge's `id` and `created_at` (at the microsecond), so the digest exists before the row; `edge_signature::insert_attested_conn` writes the row, `content_hash`, the signature and `signer_id` in one INSERT inside a savepoint, recomputes the digest from the RETURNING row and, if the database rewrote a column, re-makes the INSERT once over the stored values (a second mismatch writes nothing). A dedup hit returns the existing row and writes nothing onto it. This is the only way a world-owned structural edge (an `agent` endpoint, `processed_by`) is signed at all: no application session may UPDATE it (migration 117). After the INSERT, for an edge the writer owns: `EdgeSignatureRepository::sign_created_edge_conn(conn, viewer, edge_id, signer, signer_id)` runs on the writer's own stamped connection with the write predicate (`{WRITABLE:e}`), right after the INSERT, and only for an edge this act created (never on a dedup hit). It locks the row `FOR UPDATE`, so migration 117's owner-scoped UPDATE policy stops anyone but the edge's owner from attesting it, and it never overwrites an existing attestation. `verify_conn` checks it under the signer's keys that were admitted when the edge was created: an attested key whose status and window (`agent_key::key_window_admits`) admit the edge's `created_at`, or the bare `agents.public_key` only when no ATTESTED (`signing` / `identity-legacy`) `agent_keys` row carries those bytes, so a revoked, pending or out-of-window key never verifies an edge; a row of any other type is application-insertable and neither admits nor suppresses a key. That admission rule is `agent_key::admitted_signature_keys`, and `verify_claim` applies the same one (backlog 06a50a30). The two verifiers differ in which message they accept and in which rows they pass the rule: `verify_claim` passes the attested rows of the claim's author and of its signer, the edge verifier the rows of the edge's signer (an edge has no author agent), so an attested row of a claim's AUTHOR that carries the signer's bare key governs that key for the claim only. Edges accept ONLY the v1 edge message, never a legacy bare digest: the attestation schema is new, so no pre-v1 signature can be over an attestation digest, and a claim whose content is an edge's canonical attestation JSON has a content hash equal to that digest, so a legacy rung would accept a pre-v1 claim signature as an edge signature. A signed edge that is not a v1 attestation by any key of its signer (the bulk attestations written before this scheme, see below) reports `pre_attestation: true`, is never valid, and gets no `content_matches` comparison. `coverage` (viewer-scoped) is the unsigned-edge metric, reported by `system_stats` (`detailed: true`) as `edges_signed` / `edges_unsigned`; `edges_signed` counts rows CARRYING a signature, including those pre-attestation rows, so it is an upper bound on verifiable edges.

**Writer inventory.** `crates/epigraph-db/tests/edge_writer_signing_ratchet.rs` is the measured register of every edge-emitting site under `crates/*/src` (98 sites in 58 functions when it landed) AND of every SQL function in `migrations/*.sql` whose live definition inserts into `edges` (5 when it landed), each with its signing status. A new site fails the test until it is registered; a site registered `Signed` must call `sign_created_edge_conn`, or a signed twin and name its key (`edge_signing_key()` / `EdgeSigningKey`); a migration that redefines a registered database writer trips it again; the unsigned count is pinned by that file's `UNSIGNED_SITES_HIGH_WATER` constant. It was 103 when the register landed and 46 once the MCP and HTTP writers signed, and it has been raised since for newly registered unsigned sites (each raise is explained in the comment above the constant), so read the current value there, not here. It should only go down, and raising it is a reviewed change to that file. Who signs, and why the rest do not:

| Writers | Key material | Status |
|---|---|---|
| `epigraph-mcp` (verb-edges in `claim_helper.rs`, the `link_*` tools, ingestion, perspectives, auth lineage, `resolve_backlog_item`) | the MCP server's signing key (`EpiGraphMcpFull::edge_signing_key`) | Signed at INSERT (R-49): `signer_id` = the server's signer agent, never the edge's author |
| `epigraph-api` routes | the API's OWN key (`EPIGRAPH_API_SIGNING_KEY_FILE`, `epigraph_api::edge_signer`; a separate signer agent) | Signed at INSERT when the key is configured; with no key they write unsigned and the server says so once at boot. `promote_staged_edges` copies each approved staged row through the signed primitive, one row at a time |
| `epigraph-ingest-executor` (the workflow plan walk, `add_step`, caller authorship) | the calling surface's key, passed in as `Option<EdgeSigningKey>`: the MCP server's for the `workflow_ingest` / `add_step` tools, the API's for the `/workflows` routes | Signed at INSERT on every production path; a caller that passes `None` (test fixtures, an API with no key) writes unsigned |
| repository acts in `epigraph-db` (supersede, evolve_step, dedup mark, consolidate, the analysis bundle, match promotion) | the calling surface's key, passed in as `Option<EdgeSigningKey>`: the MCP server's for the claim-act and `decide_match_candidate` tools, the API's for their routes | Signed at INSERT on every request path; a caller that passes `None` writes unsigned: test fixtures, an API with no key, and the operator CLIs (the custodian supersede, the semantic-duplicate sweep's marks) |
| `epigraph-engine` matching (the matcher pipeline's `write_edge`), the legacy dedup identity backfill, operator CLIs | none | Unsigned; their only callers are operator CLIs on the maintenance DSN, which hold no entity signer |
| the `EdgeRepository` primitives | the caller's, through each `*_signed_conn` twin | Their unsigned arm (no key) writes unsigned |
| database functions: `epigraph_link_operator_body` (OPERATED_BY, behind `epigraph_link_operator` and the identity lineage), `epigraph_link_retired_agent`, `epigraph_link_retired_shared_signer`, `epigraph_link_legacy_authors`, and the `epigraph_role_assignments_audit` trigger (OCCUPIES) | none (a database function holds no entity key) | Unsigned; these edges could only be signed at INSERT time with a key the caller passes in, or by a database-held key |

Since migration 120 the author of an edge is `edges.writer_group_id`, not `signer_id`; readers that need an agent take the source claim's (`backfill_factors::EDGE_QUERY`, the operator's edge-writer read). On legacy rows `signer_id` is, where set, a bulk attestation key; `epigraph_reown_legacy_edges_to_signer` never follows a server signer: since migration 253 it excludes, by itself on every call, every agent named `epigraph-api-signer`, every agent that signed a claim another agent authored (the MCP server signs its callers' claims), every agent that signed an edge whose recorded writer group is not the group it would re-own that signer's edges to (an HTTP route's edge records its caller's group), and every agent that holds an attested `signing` key row, has signed an edge and has authored no claim (a server agent provisioned with its own signing row). Its audit row names each excluded signer under the rule that excluded it. Its mandatory exclusion list (no in-tree caller passes it) now only adds to that: the operator still passes the legacy bulk attestation keys, which sign no new rows and so no lookup can name.

**Provisioning the API key (operator).** Generate a fresh random Ed25519 key, distinct from every MCP key; write its 32 private bytes as 64 hex characters to a file readable only by the API unit's user; set `EPIGRAPH_API_SIGNING_KEY_FILE` to that path in the API unit's environment (never the key itself). On first boot the server registers an `epigraph-api-signer` agent with the public half (and logs a WARNING that it did, so an unplanned rotation that mints a second signer agent is visible), or uses the agent whose active `signing` key it is, and logs the agent id and public key. A key that is some OTHER agent's `agents.public_key` (the MCP server's, an author's) is accepted with a WARNING that the API signs as that agent, which ruling R-50's separate signer forbids; boot does not refuse on database state. A configured key that is unreadable or malformed, or that an attested `agent_keys` row records as not an active, in-window `signing` key of exactly one agent, refuses the boot; rows of other key types are ignored, as the verifiers ignore them. The key's admission is checked at boot and then while the server runs: at once and every `EPIGRAPH_API_SIGNING_KEY_RECHECK_SECS` seconds (default 30, clamped to 1..=300) `edge_signer::watch_admission` asks, on the database clock, whether and until when the edge verifier admits the key for the signer agent (`AgentKeyRepository::signer_key_admission`, the verifier's own rule). When the key is not admitted (revoked, rotated out, window closed), or its recorded window ends within `edge_signer::STOP_LEAD_SECS` (5 s), the API logs an ERROR and exits; it never downgrades to unsigned. A known end is not left to the interval: the watch sleeps until 5 s before it, so a planned cut-over stops the API before the old window closes. A revocation is seen at the next check, so edges written between the revocation and that check (at most one interval) carry a signature the verifier refuses; lower the interval to narrow that gap. Boot refuses a key whose window ends within the 5 s lead, so a key that passes boot never restart-loops the unit. A failed re-check is logged (WARN, then ERROR after 5 in a row) and does not stop it. The exit is abrupt: requests in flight are cut off. So revoking the API's key, or closing its window, stops the API (reads included), and it stays down until the variable points at an admitted key; the unit must restart on failure. `signing` rows are attested state: migration 161's guard refuses them to the application role, so every `agent_keys` write below is made from a maintenance session. To rotate without an outage, the NEW key comes first: (1) register the new public key as the signer agent's `active` `signing` row with `valid_from` no later than now, and point the file at the new key (the running API keeps signing with the key it loaded; any restart from here on boots on the new one). (2) Retire the old key with a cut-over time T in the future. If it has no `agent_keys` row (the agent was registered by the first boot, so the key is only its `agents.public_key`), record it as a `signing` row of that agent, status `rotated`, `valid_from` = the agent's creation and `valid_until` = T. This is not optional: the verifier admits a bare `agents.public_key` with NO window whenever no `agent_keys` row carries those bytes, so without the row the old key would keep verifying edges, including any forged after it leaked. If it already has a row, mark it `rotated` with `valid_until` = T (a rotated row with no `valid_until` admits nothing). (3) Five seconds before T the running API stops, and the unit comes back on the new key. Doing (2) before (1) risks an outage: a restart in between refuses the old key, since boot admits only an `active` row. Edges signed under the old key keep verifying because their `created_at` falls inside its recorded window. Provisioning the API agent with a `signing` row from the start (as the MCP separate-key mode does) makes the bare-key branch of (2) unnecessary. To revoke after a suspected exposure: mark (or, for a bare key, record) its `signing` row `revoked`, which the verifier treats as compromised from the start, or `rotated` with `valid_until` = now to keep earlier edges verifying; the API stops at its next check and refuses to start until step (1) is done for a fresh key. `epigraph_reown_legacy_edges_to_signer` excludes the signer agent by itself (migration 253): by its name when boot registered it, by its `signing` row when it was provisioned with one (it authors no claim), and otherwise once it has signed the edge of an HTTP caller whose writer group is not the signer's own. The one shape it cannot name is the one boot warns about: an API signing with another agent's bare `agents.public_key` that has signed no other author's claim and no such edge; pass that agent in `p_exclude_signers`.

## Supersession carries verb-edges, except a step's frozen ones

When a claim is replaced (`supersede_claim`, or `evolve_step` with `supersedes`), the new claim records `claims.supersedes = <old>`, and the Supersede admin cascade (`ClaimRepository::migrate_superseded_edges_conn`, run on the maintenance connection after the act commits, or by the deferred replay) re-points the old claim's edges onto the replacement. Weakening edges (`refutes`, `contradicts`) stay on the content they were filed against (issue #398). A STEP-LINEAGE supersession (old and new share a `step_lineage_id`: `evolve_step(supersedes)`) also leaves four kinds of edge on the retired step:

- `executes` (workflow → step): it names the FROZEN original step; readers reach the live head through the lineage (`ClaimRepository::latest_in_lineage`).
- the workflow's chain, `step_follows` and `phase_follows`, in either direction: it links the same frozen steps `executes` names, and `workflow_steps::ordered_steps` walks it only inside that set, so a chain edge moved onto the head would break the step order.
- `revises`, in either direction: like `supersedes`, it is the lineage's own branch history (`R -revises-> S` says R branched from S), so it stays between the versions it was written between.
- an agent's `asserts` / `AUTHORED`: the evolved step is written by the evolve_step caller, so another agent's assertion of the old content is not an assertion of the new one.

Everything else moves with the head: `decomposes_to` in both directions, `continues_argument`, `section_follows`, `alternative_of`, and strengthening edges such as `supports`. The rule is derived from the rows, so the deferred replay applies it without knowing the original caller (backlog 8d3b4527).

## Migration sequence

S1 planned two files, numbered at the time as `106_security_and_hardening.sql` and `107_claims_unique_content_hash_agent.sql`. Neither name exists in this repository: here `106` is `106_community_membership_integrity.sql` and `107` is `107_operator_link.sql`, both unrelated. What this repository carries instead:

- **Migration 013** (`migrations/013_code_review_hardening.sql`) holds the content of both planned files: the hardening items (the `bp_messages` `factor_id` index among them) and `ALTER TABLE claims ADD CONSTRAINT uq_claims_content_hash_agent UNIQUE (content_hash, agent_id)`. A database migrated from empty therefore had the constraint; the long-lived database recorded 013 as applied and did not have it.
- **Migration 150** (`migrations/150_drop_uq_claims_content_hash_agent.sql`, decided 2026-10-12, backlog `00f1a517`) drops that constraint `IF EXISTS`, so no database carries it. Its header records why it cannot be restored (about 95k duplicate groups on the long-lived database, most of them supersession history that a full UNIQUE would force us to delete) and what replaces it: the advisory lock described under "The create race" above.
- **Future target, not yet a migration:** a partial unique index `(content_hash, agent_id) WHERE is_current`, after the live duplicate groups are reconciled with `mark_duplicate`. `scripts/audit_claims_content_hash_agent.py` counts them, read-only. Do not re-add the full constraint (`migrations/README.md` explains the deploy outage that would cause).

## Writer dedup beyond content_hash (S3 cross-cutting)

S1's `if_not_exists: true` primitive dedups on byte-identical content_hash. That catches every deterministic re-run — host provenance (whose hashes are stable by construction: `hash(container_name)`, `hash(task_id:status)`), agents re-submitting identical text, scripts re-posting cached content. It does **not** catch LLM-driven extractors that reword the same fact across runs. "Evidence supports H₀ at conf 0.8" and "the data supports the null hypothesis with confidence 0.8" hash to different values, both rows are written, and no rule keyed on `(content_hash, agent_id)` would catch it.

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
- **S2 (backfill):** as planned, convert each of the ~95,214 existing `(content_hash, agent_id)` duplicate groups into one canonical claim plus (N-1) timestamped verb-edges, and redirect the 413k existing edges, 95k MFs, and 2.3k evidence rows pointing at non-canonical rows. Not carried out in that form: migration 150 (2026-10-12) records the duplicate groups as still present and most of them as supersession history that must be kept. What remains of S2 is reconciling the live duplicate groups with `mark_duplicate` ahead of the partial index.
- **S3 (writers):** four sub-plans (S3a `epigraph-mcp`, S3b `epigraph-agent` `submit_claim` builtin, S3c V2 ingest scripts, S3d V2 `epigraph-nano/provenance.rs`). All implement layered dedup per the previous section; S3c specifically requires Layers 0–2 because LLM extraction non-determinism otherwise defeats Layer 0 alone. S3a runs first to stop new dups accumulating; S3b–S3d parallelisable with S2 once S3a deploys.
- **S4 (the UNIQUE constraint):** abandoned. Migration 150 dropped the constraint instead of applying it; see "Migration sequence" for the advisory lock that replaces it and the partial index that may follow.

Each sub-project gets its own brainstorm → spec → plan cycle.
