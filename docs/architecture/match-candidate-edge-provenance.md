# Match-Candidate Edge Provenance: Informal Linkage Design Note

**Status:** Informational — documents an intentional gap, not a resolved design.
**Related:** `decide_match_candidate` reject-does-not-retract-edge bug
(`crates/epigraph-mcp/src/tools/matching.rs`), `EdgeRepository`
(`crates/epigraph-db/src/repos/edge.rs`).

---

## (a) Current linkage mechanism

When a `match_candidates` row is promoted via `decide_match_candidate`
(`crates/epigraph-mcp/src/tools/matching.rs`, `"promote"` arm), a
`CORROBORATES` edge is written between `claim_a` and `claim_b` via
`EdgeRepository::create_symmetric_if_absent`. The edge's `properties` JSONB
carries the originating candidate's id:

```rust
let props = serde_json::json!({
    "candidate_id":     candidate_id,
    "score":            row.score,
    "features":         row.features,
    "verifier_verdict": row.verifier_verdict,
    "decided_by":       acting_agent,
    "source":           "cross_source_matcher",
});
```

This is the *only* link from the edge back to the `match_candidates` row that
produced it. It is:

- **Informal** — a plain string key inside a `jsonb` blob, not a typed
  column.
- **Unenforced** — there is no `FOREIGN KEY` from `edges.properties->>'candidate_id'`
  to `match_candidates.id`, so a candidate row can be deleted (or never have
  existed) while an edge still claims that `candidate_id` in its properties.
- **Un-indexed** — no expression index exists on
  `(edges.properties->>'candidate_id')`, so any query that needs to go from a
  `match_candidates.id` to the edge(s) it produced (e.g. "which edges did
  this candidate write?") requires a sequential scan over `edges.properties`.

Concretely, this means `decide_match_candidate("reject")` on a
previously-promoted candidate has no way to cheaply find and retract the
`CORROBORATES` edge that `"promote"` wrote earlier — the edge is orphaned,
connected to its origin only by an unindexed, unenforced JSONB string match.

## (b) Why the minimal fix keeps the informal linkage

A natural "proper" fix would add a typed column,
`edges.candidate_id UUID REFERENCES match_candidates(id)`, with a supporting
(partial) index. This change set deliberately does **not** do that, for
three reasons:

1. **Schema/migration risk.** `edges` is a hot, high-write-volume table
   (`COMMENT ON TABLE public.edges`: *"LPG-style edges table for flexible
   graph relationships"*, `migrations/001_initial_schema.sql`). Adding a
   nullable FK column is low-risk in isolation, but any migration against
   this table needs to be weighed against lock contention and the ongoing
   edge-write traffic from ingestion, the cross-source matcher, and MCP
   tools running concurrently. That risk is disproportionate to a targeted
   bug fix.
2. **`edges` is polymorphic, not match-candidate-specific.** `source_type`
   / `target_type` range over `claim`, `agent`, `evidence`, `trace`, `node`,
   `activity`, `paper`, `perspective`, `community`, `context`, `frame`,
   `analysis`, `source_artifact`, `span`, `entity`, `task`, `event`
   (`edges_entity_types_valid` check constraint). Only `CORROBORATES` edges
   written by `decide_match_candidate("promote")` ever populate
   `candidate_id`; a first-class column would sit `NULL` for the vast
   majority of rows and would encode a match-candidate-specific concept
   into a table whose whole purpose is to stay relationship-agnostic.
3. **Out of scope for a targeted bug fix.** The bug this change set
   addresses is behavioral (reject doesn't retract a promoted edge), not
   structural. Fixing the behavior only requires *reading* the existing
   `properties->>'candidate_id'` value to find the edge(s) to retract on
   reject — it does not require making that link queryable at scale or
   enforced by the database. A full migration is a separate, larger piece
   of work that should be scoped and reviewed on its own.

## (c) Recommendation for a future follow-up

If this pattern — an external system (or MCP tool) writing `edges` rows
keyed by an id embedded in `properties`, with nothing else tying the edge
back to its origin — recurs elsewhere in the codebase, it is worth
introducing a proper `edge_provenance` mechanism rather than adding more
one-off typed FK columns per producer. Two shapes are worth evaluating:

- **Option 1 — single-purpose column.** A nullable
  `candidate_id UUID REFERENCES match_candidates(id) ON DELETE SET NULL`
  column on `edges`, with a partial index
  (`CREATE INDEX ... ON edges (candidate_id) WHERE candidate_id IS NOT NULL`).
  Simple and fast for this one producer, but doesn't generalize to the next
  producer that needs the same pattern (e.g. a future bulk-import job or
  another matcher).
- **Option 2 — generic provenance pair.** A `provenance_kind TEXT` /
  `provenance_id UUID` pair (nullable, with a partial composite index) that
  any edge-writing producer can populate — `provenance_kind = 'match_candidate'`,
  `provenance_id = candidate_id` today, and e.g.
  `provenance_kind = 'decompose_run'` for a future producer, without adding
  a new column per producer. This is the better long-term shape *if* more
  than one producer needs traceable, retractable edges; it costs a slightly
  more awkward join (`provenance_kind = 'match_candidate' AND provenance_id = $1`
  instead of a direct FK) in exchange for not growing the `edges` schema
  per producer.

Either option should ship together with the query/retraction path that
needs it (e.g. "find all edges for candidate X" used by a reject-time
cleanup), rather than as schema-only groundwork, so the index is validated
against a real access pattern instead of speculative future use.

---

## (d) Update: the retraction path shipped without either option

`MatchCandidateRepo::retire` (exposed as the `retire` verdict on
`POST /api/v1/match_candidates/:id/decide` and on the `decide_match_candidate`
MCP tool) is the "retraction path" section (c) said either schema option should
ship with. It shipped with **neither**, because it does not need the
`candidate_id` link at all: it finds the edges to delete by
**claim pair + `properties->>'source' = 'cross_source_matcher'`**, which is
served by the ordinary `(source_id, target_id)` indexes and needs no sequential
scan over `properties`.

That scoping is not a workaround, it is more correct than the `candidate_id`
join would have been:

- reversed-duplicate candidates share a single edge stamped with only one of
  their two ids, so a `candidate_id` lookup misses the edge for the other;
- `promote` writes `contradicts` as well as `CORROBORATES`, and both are
  equally retirable, so keying on `relationship` is wrong too;
- every matcher-written edge between a pair being retired is in scope by
  definition.

Section (a)'s "no way to cheaply find and retract the edge" therefore remains
true only for a lookup **keyed on `candidate_id`**. The statement in (a) that
`decide_match_candidate("reject")` cannot retract a promoted edge is still
accurate — `reject` deliberately does not retract; `retire` is the verdict that
does, and it also removes the `factors` / `bp_messages` the `edges_auto_factor`
trigger derived from the edge, which a bare edge delete would have orphaned.

A typed `candidate_id` column is still the right shape if a future caller needs
"which edges did *this candidate* write" as a first-class question. Nothing
does today.
