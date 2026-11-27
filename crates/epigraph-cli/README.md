# epigraph-cli

Command-line binaries for operating, maintaining and experimenting with an
EpiGraph deployment, plus the library they share (`src/lib.rs`). Each binary's
own `//!` header is the reference for its flags, its connection and what it
writes; `docs/deploy.md` lists the schedules and environment variables.

The crate mixes several kinds of tool, and that is not visible from
`Cargo.toml`. The table below classifies every `[[bin]]` target.
`tests/readme_bin_classification.rs` fails when a `[[bin]]` has no row, when a
row names no `[[bin]]`, or when a row's class is not one of the five below.

## Classes

| Class | Meaning |
|---|---|
| `standing` | Standing maintenance: runs on a timer or at a regular cadence against a live deployment. |
| `admin` | Operator admin or ceremony: a deliberate, reusable operator act run by hand when needed (provisioning, authority and ownership, group keys and sealing, reviewed belief-cache waves and their undo, repairs of named rows). |
| `one-shot` | A backfill, sweep, repair or measurement tied to one change, migration or incident. Once that change has been applied everywhere it is a retirement candidate (backlog `02de2b85`). |
| `ingest` | Ingest client: writes source content into the graph, through the HTTP API or the ingestion pipeline. |
| `experiment` | Research experiment or analysis: graph analyses, enrichment and bridging pipelines, hypothesis and experiment tooling, calibration harnesses. Not needed to operate a deployment. |

## Binaries

| Binary | Class | What it does |
|---|---|---|
| `replay_deferred_cascades` | standing | Applies the administrative cascades request processes defer (every 90 s on the cascade-replay timer). |
| `enqueue_job` | standing | Enqueues one job for the job-drain timer (e.g. the nightly graph clustering). |
| `embed_backfill` | standing | Fills missing claim embeddings and workflow goal embeddings; the recovery path for the write paths. |
| `prune_recall_events` | standing | Daily retention prune of the recall audit log and telemetry events. |
| `assign_unthemed_themes` | standing | Nightly: assigns every unthemed, embedded claim to its nearest theme. |
| `atlas_nightly` | standing | The nightly Atlas refresh (`deploy/systemd/epigraph-atlas-nightly.timer`). |
| `cross_source_sweep` | standing | Batch driver for the cross-source matcher over recently touched, unscanned claims. |
| `sweep_semantic_duplicates` | standing | Sweeps one page of the corpus for semantic near-duplicates; collapses exact restatements with `--apply`. |
| `atomicity_sweep` | standing | Labels current atoms that still assert several things `compound-atom`, and unlabels claims that no longer qualify. |
| `decompose_claims` | standing | Splits standalone compound claims into atoms with `decomposes_to` edges (the decomposition schedule's primitive). |
| `epigraph-operator` | admin | The audited operator verbs: role grants, passkeys, groups and roles, client approval, identity links, reownership, restriction. |
| `epigraph-instance-admin` | admin | Checks and lists the privatization authority (writes nothing since migration 123). |
| `epigraph-group` | admin | Client-side group key ceremony: mint, wrap, unwrap, rotate and re-wrap group keys; talks to no server or database. |
| `epigraph-privatize` | admin | Client half of the seal ceremony: seals, unseals and reseals a plan's members over HTTP with locally derived keys. |
| `epigraph-tenancy-backfill` | admin | The batched tenancy backfill of pre-existing rows, and the `verify` subcommand used as a deploy pre-flight. |
| `bootstrap_clients` | admin | Idempotently provisions the three service OAuth clients of a new deployment. |
| `unmark_duplicate` | admin | Un-marks a duplicate (or every mark of one label-dedup apply) on the maintenance connection. |
| `export_provenance` | admin | Exports a claim's provenance graph as PROV-O JSON-LD; read-only. |
| `recompute_claim_belief` | admin | Recomputes the cached belief columns of listed claims from their current mass functions. |
| `recompute_betp` | admin | Reviewed belief-cache waves over evidenced atoms, and the accepted-vacate path. |
| `belief_snapshot` | admin | Snapshots every current claim's belief-cache columns to JSON lines (the rollback baseline). |
| `restore_belief_cache` | admin | Undoes a wave's belief-cache writes by compare-and-swap. |
| `atlas_layout` | admin | Builds the shared Atlas theme layout from public claims and edges as one layout run, by hand (the nightly refresh lays out changed levels itself). |
| `atlas_meaning` | admin | Hand-run export/apply halves of the Atlas "by meaning" hierarchy for one map. |
| `atlas_links` | admin | Hand-run export/apply halves of the Atlas "by links" hierarchy for one map. |
| `atlas_naming` | admin | Hand-run LLM naming of one Atlas map's groups. |
| `cache_owner_audit` | one-shot | Read-only measurement for the cache-owner repair (backlog `d33a5c9f`). |
| `belief_shadow_report` | one-shot | Read-only report of served beliefs beside the atom-fold derivation, for the atom-level belief cutover review. |
| `supersede_belief_delta` | one-shot | Read-only dry-run belief delta of the supersede belief fixes. |
| `r131_factor_mint` | one-shot | Mints the missing BP factors of factorless claim-to-claim `corroborates`/`refutes` edges (backlog `5094766c`). |
| `decomposes_to_factor_sweep` | one-shot | Exports and deletes the BP factors of `decomposes_to` edges minted before migration 262 (backlog `444b1f4a`). |
| `sweep_retired_source_bbas` | one-shot | Retroactively removes the BBAs retired claims froze onto current claims, with dry run and undo. |
| `backfill_factors` | one-shot | Tier A factor backfill (evidence phase, edge rewire phases). |
| `restore_edge_factors` | one-shot | Undoes a targeted edge-factor rewire's row writes by compare-and-swap. |
| `refresh_truth_mirrors` | one-shot | Compare-and-set refresh of `claims.truth_value` copies of an old belief cache, from recompute wave files, and its undo. |
| `retire_match_candidates` | one-shot | Retires listed match candidates and retracts the evidential edges they promoted (a same-source provenance leak). |
| `backfill_evidence_type` | one-shot | Types legacy mass-function rows whose provenance determines their evidence type (backlog `bc06ec6f`). |
| `replay_beta_track` | one-shot | Rebuilds the Beta-Bernoulli track of claims still on the prior by replaying their BBAs. |
| `rebuild_moved_beta_tracks` | one-shot | Rebuilds the Beta-Bernoulli track of claims moved to a new audience before the act rebuilt it (backlog `6e4ff46e`). |
| `backfill_dedup_identity_edges` | one-shot | Writes the missing `same_as` identity edge of duplicates the legacy raw-SQL dedup script marked (backlog `d5781a48`). |
| `ingest_literature` | ingest | Submits a JSON file of literature extractions as signed packets to the API. |
| `ingest_git` | ingest | Submits the repository's git history (Epistemic Commit Protocol) as signed packets to the API. |
| `ingest-document` | ingest | Operator wrapper of the hierarchical `ingest_document` pipeline with a per-invocation database target. |
| `dekg` | ingest | HTTP client for the Dempster-Shafer routes: frames, beliefs, divergence, evidence submission, entities. |
| `analyze_graph` | experiment | Runs the Datalog reasoning engine over all claims and edges and prints an analysis report. |
| `compare_routes` | experiment | Compares reasoning entropy across database variants of evidence-promotion routes. |
| `embed_bridge` | experiment | Embedding-based cross-component bridge detection with LLM classification. |
| `rerank_bridges` | experiment | LLM re-ranking of embedding-similar claim pairs before they become edges. |
| `bridge_component` | experiment | Bridges one disconnected component into the giant component via LLM-validated edges. |
| `bridge_sweep` | experiment | Bridges many disconnected components, with a combined spine-destination report. |
| `calibrate_matcher` | experiment | SciFact-driven calibration harness for the cross-source matcher thresholds. |
| `contamination_split` | experiment | Post-sweep contamination split of a cross-source run's pairs. |
| `reembed` | experiment | Batch re-embedding at 3072 dimensions for side-by-side large-model experiments. |
| `hypothesis` | experiment | Hypothesis lifecycle: create, status, promote. |
| `experiment` | experiment | Experiment lifecycle: create, design, search methods, start, submit results. |
| `method_search` | experiment | Web search for experimental method evidence for a hypothesis. |
| `protocol_gen` | experiment | LLM-generated experimental protocol for a hypothesis. |

## Examples

`examples/table_graph` is a cargo example, not a binary: it narrates each
migration table of two checkouts (`cargo run -p epigraph-cli --example
table_graph -- discover --epigraph-root <dir> --episcience-root <dir>`).
