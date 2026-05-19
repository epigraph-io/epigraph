# Glossary

Concise definitions for the vocabulary used throughout EpiGraph. Terms are listed alphabetically; each entry links to the file where the concept is treated in depth.

---

## agent

A signing identity that authors claims and edges. Every claim is keyed by `(content_hash, agent_id)` — the agent is half of the canonical identity of every assertion in the graph. Agents are durable: human contributors, ingest scripts, MCP-driven LLMs, and host processes all submit work under stable agent IDs so authorship survives across sessions. [see 02-concepts.md §3 (Agents and authorship)](02-concepts.md)

## atom

The finest-grained extracted unit produced by hierarchical extraction — a single self-contained assertion lifted out of a paragraph. Atoms are the children of paragraphs in the paper → paragraph → atom hierarchy and are the unit at which Dempster-Shafer belief is tracked. [see 02-concepts.md §4 (Hierarchical extraction)](02-concepts.md)

## backlog

A label applied via `submit_claim` (or `memorize`) with `labels=["backlog"]` to file an issue or follow-up item as a claim. Open backlog is queried with `labels=["backlog"], exclude_labels=["resolved"]`; retirement always goes through `resolve_backlog_item`, which creates a `"Resolves <id>: "` resolution claim and patches the original's labels in one call. See [docs/conventions/backlog-retirement.md](../conventions/backlog-retirement.md) for the canonical convention.

## BetP

The pignistic probability: a scalar in `[0, 1]` derived from a Dempster-Shafer mass function by distributing the mass of each focal set uniformly over its singletons. BetP is the standard projection used to order claims by belief and is the primary belief signal EpiGraph exposes — Bayesian `truth_value` is deprecated. See the LANL Open World DST paper (LA-UR-25-23655) for the standard treatment. [see 02-concepts.md §6 (Belief and DST)](02-concepts.md)

## challenge

A first-class objection or counter-claim posted against an existing claim. Challenges are recorded through the MCP `challenges` tool and feed into the belief layer so that disagreement is visible rather than hidden inside prose. [see 02-concepts.md §7 (Challenges and disagreement)](02-concepts.md)

## claim

A row in the `claims` table representing an entity or assertion with stable identity, canonically keyed by `(content_hash, agent_id)`. In the noun/verb split, claims are the nouns — facts, entities, tasks, container existence — while timestamped occurrences are verb-edges. See [docs/architecture/noun-claims-and-verb-edges.md](../architecture/noun-claims-and-verb-edges.md) for the canonical pattern.

## content_hash

The deterministic hash of a claim's normalized content; together with `agent_id` it forms the canonical key for a noun-claim. POSTing a claim with `if_not_exists: true` and a matching `(content_hash, agent_id)` returns the existing row with `was_created: false` instead of inserting a duplicate. See [docs/architecture/noun-claims-and-verb-edges.md](../architecture/noun-claims-and-verb-edges.md) for the dedup semantics.

## DST

Dempster-Shafer Theory: the mass-function-based belief calculus EpiGraph uses for combining evidence under uncertainty. Each atom carries a mass function over a frame of discernment; evidence is combined via discounted Dempster combination, and BetP projects the result to a scalar for ranking. See the LANL Open World DST paper (LA-UR-25-23655) for the practitioner's treatment. [see 02-concepts.md §6 (Belief and DST)](02-concepts.md)

## edge

A row in the `edges` table representing a timestamped occurrence or relationship between two entities (claims, agents, or papers). Edges carry `relationship` (the verb), `created_at`, optional `valid_from` / `valid_to`, a `properties` JSONB blob, and optional `signature` / `signer_id`. See [docs/architecture/noun-claims-and-verb-edges.md](../architecture/noun-claims-and-verb-edges.md) for verb-edge semantics.

## evidence

A noun-claim attached to a submission that records the supporting material an agent cited for a claim — quoted text, links, observations. Evidence is linked to the target claim with a `HAS_TRACE` verb-edge so the provenance chain is graph-traversable. [see 02-concepts.md §5 (Evidence and trace)](02-concepts.md)

## factor

A node in the factor-graph representation of belief propagation: a local function that constrains the mass on one or more atoms. Factors are how DST combination is structured for incremental, message-passing updates rather than a single all-at-once combination. [see 02-concepts.md §6.3 (Factor graphs)](02-concepts.md)

## frame

The frame of discernment — the finite set of mutually-exclusive hypotheses over which a mass function is defined. For a binary claim the frame is `{true, false}`; for richer claims it can include disjoint alternatives plus the full set representing ignorance. [see 02-concepts.md §6.1 (Frames and mass functions)](02-concepts.md)

## hierarchical extraction

The canonical ingest pipeline that decomposes a source into paper → paragraph (level 2) → atom, with edges linking each level to its parent. Tier 1 hierarchical extraction (`extract-claims` → `ingest_document`) is the only supported ingest path; legacy flat extraction and Jina embeddings break primary-column search and are not used. [see 02-concepts.md §4 (Hierarchical extraction)](02-concepts.md)

## MCP

Model Context Protocol — the protocol Claude Code and other LLM clients use to call EpiGraph tools. EpiGraph exposes its MCP surface through the `epigraph-mcp-full` binary, whose tool set lives under `crates/epigraph-mcp/src/tools/` (claims, recall, ds, challenges, themes, workflows, and others). [see 02-concepts.md §2 (How clients talk to EpiGraph)](02-concepts.md)

## methodology

A named, structured procedure or playbook ingested into the graph as a hierarchical claim tree (root methodology claim → steps → sub-steps). Methodologies are the unit by which reusable processes — Renaissance Philanthropy playbooks, ingest protocols, governance routines — are represented and applied. [see 02-concepts.md §8 (Methodologies and workflows)](02-concepts.md)

## noun-claim

A `claims` row treated as an entity with stable identity: at most one row per `(content_hash, agent_id)`, keyed for idempotent re-creation. Lifecycle events and relationships about that entity are recorded as verb-edges, not as new claims. Canonical reference: [docs/architecture/noun-claims-and-verb-edges.md](../architecture/noun-claims-and-verb-edges.md).

## paragraph

A level-2 claim in the hierarchical extraction tree: a contiguous span of source text that sits between the paper and its atoms. Paragraphs are the primary target of semantic search (`recall_with_context` searches at level 2, then batches in atoms, siblings, corroborating edges, and neighbor paragraphs). [see 02-concepts.md §4 (Hierarchical extraction)](02-concepts.md)

## perspective

A named viewpoint — typically an agent's or a group's — under which belief and challenges can be projected separately. Perspectives let the graph carry disagreement explicitly: the same atom can have different BetP values from different perspectives without one overwriting the other. [see 02-concepts.md §7 (Challenges and disagreement)](02-concepts.md)

## pignistic probability

Synonym for BetP: the scalar probability obtained by distributing each focal set's mass uniformly over its singleton elements of the frame. It is the standard decision-theoretic projection from a DST mass function and replaces the deprecated `truth_value` for all belief ordering. See the LANL Open World DST paper (LA-UR-25-23655) for derivation. [see 02-concepts.md §6 (Belief and DST)](02-concepts.md)

## provenance

The cryptographically-audited trail of every write: each create or patch lands a row in `provenance_log` regardless of whether the write produced a new claim or matched an existing one. Provenance is preserved across the noun/verb split — re-ingest produces new edges and new provenance rows, never a duplicate fact-claim. [see 02-concepts.md §5 (Evidence and trace)](02-concepts.md)

## recall

The graph's semantic-search entry point, exposed via the `recall_with_context` MCP tool. It performs paragraph-primary vector search at level 2, batches in structural context (atoms, sibling paragraphs, `CORROBORATES` edges, neighbor paragraphs), and always returns a `corpus_scope` summary so callers can tell how big the searched corpus was. [see 02-concepts.md §2 (How clients talk to EpiGraph)](02-concepts.md)

## signature

An Ed25519 signature attached to a claim or edge by its signer agent, with `signer_id` identifying the key. Signatures give every assertion in the graph an audit guarantee independent of the database; edge signing is schema-supported (migration 073) and writer-realised per S3 plans. [see 02-concepts.md §3 (Agents and authorship)](02-concepts.md)

## supports

A verb-edge `relationship` value indicating that the source claim's content lends evidential weight to the target claim. `supports` is one of the core epistemic relations alongside `CORROBORATES`, `CHALLENGES`, and `DERIVED_FROM`; `supports` is overloaded historically (Episcience separates epistemic and dependency edges into different tables; EpiGraph conflates them via `supports`). [see 02-concepts.md §1 (Noun-claims vs verb-edges)](02-concepts.md)

## synthesis

A claim that integrates or summarises several upstream claims, typically produced by an LLM extraction step that consumes a paragraph and emits both atomic facts and a synthesised summary. Synthesis claims are linked to their inputs via `DERIVED_FROM` verb-edges so the upstream chain is recoverable. [see 02-concepts.md §4 (Hierarchical extraction)](02-concepts.md)

## theme

A cluster label that groups semantically-related claims into a named higher-level topic. Themes are stored in `claim_themes`, surfaced by the `themes` MCP tool, and used to navigate the graph at a coarser granularity than individual atoms. [see 02-concepts.md §9 (Themes and clusters)](02-concepts.md)

## verb-edge

An `edges` row treated as a timestamped occurrence or relationship between entities, with the `relationship` field carrying the verb and `properties` carrying event metadata. Re-occurrence of the same event creates a new verb-edge, not a duplicated noun-claim. Canonical reference: [docs/architecture/noun-claims-and-verb-edges.md](../architecture/noun-claims-and-verb-edges.md).

## workflow

A stored, re-runnable procedure represented in the graph as a hierarchical claim tree (`store_workflow` / `improve_workflow` MCP tools). Workflows differ from methodologies in operational stance: methodologies are normative playbooks, workflows are executable sequences an agent can step through. [see 02-concepts.md §8 (Methodologies and workflows)](02-concepts.md)
