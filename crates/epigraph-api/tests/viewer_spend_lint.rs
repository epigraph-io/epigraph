//! Source lint: in a handler that holds a `Viewer`, every database call that
//! does NOT receive that viewer is named and reviewed (backlog 4815dcf7,
//! `F-single-spend-handlers-unreviewed` in `docs/tenancy/progress.json`).
//!
//! # The gap this closes
//!
//! Every handler that takes `ViewerExtractor` spends its viewer at least once,
//! so "is the viewer used" is not a useful check. The defect is a viewer spent
//! on the WRONG read: `hypothesis_status` (B1) spent it on two scalars while
//! the claim content came from a raw-pool read, and `belief_at_time` (M5) had
//! the same shape. Both were found by reading the file. Nothing in the tree
//! could tell a handler whose viewer filters the read it returns from one whose
//! viewer filters a side read while the read that matters takes the pool alone.
//!
//! This lint makes that distinction mechanical. It does not try to decide
//! which call is "the content read", which a source scan cannot know. Instead
//! it enumerates, per handler, every database call whose arguments do not
//! name the viewer, and asserts that list EXACTLY against [`REVIEWED`]. A new
//! unviewed call in a viewer-holding handler, including a repo function called
//! without its viewer argument, fails the build until someone reads it and
//! registers it with a reason. Removing one fails too, until the register is
//! lowered, so the register cannot rot into folklore.
//!
//! # The population
//!
//! Every `fn` in `src/routes/` that holds a viewer: a handler (it destructures
//! `ViewerExtractor(<ident>)`) or a route helper a handler delegates to (it
//! takes an `<ident>: &Viewer` parameter, whatever the ident). A handler that
//! passes `&viewer` to a helper counts that call as viewed, so the helper's own
//! body is measured as well; its `&PgPool` and connection parameters are
//! database handles there. A helper declared inside a handler is measured once,
//! as itself. Viewer-holding code outside `src/routes/` (the MCP tools, the
//! repo layer) is not in this population; `visibility_lint.rs` covers the
//! repo layer's SQL.
//!
//! # What counts as a database call
//!
//! A call (function or method) whose argument list names, after comments are
//! removed and string contents blanked:
//!
//! * the raw pool: `state.db_pool`, or a local bound to it;
//! * a connection: `&mut *x` (a `ScopedRead`, `ScopedTx` or `Transaction`
//!   deref), or `&mut x` where `x` is a `let mut` bound from a connection
//!   constructor (`read_as`, `write_as`, `begin_claim_write`, `begin_as`,
//!   `maintenance`, `Connection::begin`, `.begin()`, `.acquire()`), from
//!   `state`, or from another connection;
//! * `state` itself (`&state`, `state.clone()`): a helper handed the whole
//!   `AppState` can reach the pool;
//! * in a route helper, a parameter typed as a pool (`&PgPool`) or as a
//!   connection (`&mut PgConnection`, `ScopedRead`, `ScopedTx`, `Transaction`),
//!   passed bare or dereferenced.
//!
//! Plus `state.read_as` / `state.write_as` / `state.begin_claim_write`, receiver
//! calls on the pool (`state.db_pool.begin()`), and method calls on a repo
//! object built from the pool (`let r = MatchCandidateRepo::new(..)`).
//!
//! A call is VIEWED when its argument list spends the handler's viewer
//! variable as a WHOLE value: the bare identifier (`&viewer`, `viewer,`), or a
//! method that hands the whole viewer on ([`WHOLE_VIEWER_METHODS`]: `clone`,
//! `detach_scoped`, `splice`, `group_bind`, ..). A scalar projection
//! (`viewer.principal()`, `viewer.writable_groups()`) is NOT a spend: a
//! raw-pool read keyed on the caller's id filters nothing, which is exactly
//! the "viewer spent on an unrelated scalar" shape. For a `sqlx` chain (`sqlx::query(..).bind(..).fetch_one(conn)`)
//! the whole chain counts, and so does the `let` binding of a statement or SQL
//! string it reads (`let sql = viewer.splice(..)`), because that is where a
//! spliced predicate is spent.
//!
//! # A stamped connection is NOT a spend
//!
//! `ExperimentRepository::get_for_hypothesis(&mut *read, id)` runs on a
//! connection stamped with the viewer, and it is still registered. Stamping
//! gives the read row security under an application role and nothing else: no
//! in-query predicate, and no control at all on a table without row security
//! (`factors`, `experiments`, `methods`, `papers`). Whether that single layer
//! is enough is a per-site judgement, so it is a register entry, not a pass.
//!
//! # Labels
//!
//! A repo or helper call is labelled by its last two path segments
//! (`ClaimRepository::get_by_id`). A `sqlx` chain is labelled by its head, the
//! first word of its SQL and its terminal (`sqlx::query_as(SELECT).fetch_one`),
//! so swapping a write for a read in the same handler changes the label even
//! when the count stays the same.

use std::collections::BTreeMap;
use std::path::Path;

/// Every database call that does not receive the handler's viewer, per
/// viewer-holding handler, as measured and reviewed on **2026-10-26**, and
/// re-reviewed on **2026-10-29** for the viewer-holding code `origin/main`
/// gained since (merged at e0c1d482: the group routes' stamped connections,
/// BBA retraction, challenge resolution, the R-22 cache narrowing, the
/// workflow goal embedding).
///
/// The edge writes that moved to their signed variants (`EdgeRepository::
/// create*` and raw `INSERT INTO edges` -> `create*_signed*`) keep the reason
/// class of the call they replaced: the same write, with an attestation added,
/// on the same pool or connection.
///
/// Asserted as an exact multiset per handler. The comment above each group is
/// the review. Reason classes, used below:
///
/// * **gated** — the handler reads its target through the viewer first and
///   refuses (404) what the caller cannot read; the listed calls act on that
///   same target.
/// * **write** — the call writes (or locks) a row; read authority over the
///   target is established by the viewed call(s) before it, and write
///   authority is the database's (`WITH CHECK`) and the write-side registers'.
/// * **untenanted** — the table has no tenancy columns (`agents`, `methods`,
///   `experiments`, `experiment_results`, `behavioral_executions`,
///   `match_candidates`, `entities`, `claim_themes`, `graph_cluster_runs`,
///   `claim_encryption`), or the read is the caller's own membership.
///   `workflows` left this list with migration 183 (ruling R-74): a row
///   carries its plan's tenancy under forced row security, so a `workflows`
///   read is **stamped**, never untenanted.
/// * **stamped** — runs on a connection stamped with this viewer, for an id
///   the viewer already read; row security filters it under an application
///   role.
/// * **no SQL** — handed `AppState` or a pool and runs no tenancy read
///   (embedding, config, a lifecycle switch).
/// * **narrows** — a filter over rows the handler already read through the
///   viewer (`derivation_scope::retain_for_cache`, ruling R-22: keep only the
///   rows a cache may fold): it can drop a row, never add one, and returns
///   nothing it was not given.
/// * **lifecycle** — the privatization lifecycle: the plan is loaded through
///   the viewer (`load_plan_for_actor`), authority is checked against the
///   plan's group, and the act then runs on the maintenance connection by
///   design.
/// * **open finding** — a known residual owned by the named entry in
///   `docs/tenancy/progress.json`; listed so it cannot grow unseen.
///
/// Do not add an entry to make the build pass. Read the call; if it reads
/// something the caller may not read, give it the viewer.
const REVIEWED: &[(&str, &str, &[&str])] = &[
    // stamped: the caller's own pending acts.
    (
        "admin_acts.rs",
        "list_acts",
        &["AdminActCeremony::list_mine"],
    ),
    // stamped: a security-definer read that refuses a caller who is neither
    // the agent's operator nor an admin; agents are untenanted.
    (
        "agent_prompt_history.rs",
        "get_prompt_history",
        &[
            "AgentIdentityRepository::prompt_history_index",
            "AgentRepository::get_by_id",
        ],
    ),
    (
        "agent_prompt_history.rs",
        "get_prompt_history_blob",
        &["AgentIdentityRepository::prompt_history_blob"],
    ),
    // untenanted: the agent row; its claims are read through the viewer.
    ("agents.rs", "agent_claims", &["AgentRepository::get_by_id"]),
    (
        "agents.rs",
        "get_agent_reputation",
        &["AgentRepository::get_by_id"],
    ),
    // gated (`ClaimRepository::get_by_id`) then write; `human_of` is an agents
    // read; the SELECT is an advisory lock. narrows: `retain_for_cache` (and
    // the `acquire` it runs on) filters the BBAs just read through the viewer
    // (`get_for_claim_frame`). untenanted: `analyze_independence` groups those
    // rows' source agents by owner (`AgentRepository::humans_of`, ruling R-36);
    // it took the viewer only while it read lineage, and no longer reads any.
    (
        "assess.rs",
        "assess_claim",
        &[
            "AgentRepository::human_of",
            "AgentRepository::human_of",
            "EdgeRepository::create_signed",
            "EdgeRepository::create_signed",
            "EdgeRepository::create_signed",
            "MassFunctionRepository::store_with_perspective",
            "PerspectiveRepository::ensure_evidence_perspective",
            "ScopedBeliefRepository::upsert",
            "db_pool.acquire",
            "db_pool.acquire",
            "db_pool.acquire",
            "db_pool.acquire",
            "db_pool.begin",
            "derivation_scope::retain_for_cache",
            "independence::analyze_independence",
            "sqlx::query(INSERT).execute",
            "sqlx::query(SELECT).execute",
            "sqlx::query(UPDATE).execute",
        ],
    ),
    // stamped: the write transaction is stamped from the caller's viewer, and
    // the retract / un-retract definer (migration 184) selects the BBA only
    // when it is public or owned by a group in the session's read set, so an
    // unreadable BBA is the missing-id 404; the cache refresh is viewed.
    (
        "bba_retract.rs",
        "retract_bba",
        &["MassFunctionRepository::retract_conn"],
    ),
    (
        "bba_retract.rs",
        "unretract_bba",
        &["MassFunctionRepository::unretract_conn"],
    ),
    // open finding: F-aggregate-existence-oracles (the frame's conflict
    // aggregate over mass_functions).
    (
        "belief.rs",
        "frame_conflict",
        &["sqlx::query_as(SELECT).fetch_one"],
    ),
    // gated (parent frame) then write.
    (
        "belief.rs",
        "refine_frame",
        &["FrameRepository::create_refinement"],
    ),
    // narrows: the perspective / community rows its caller read through the
    // viewer (`get_for_claim_frame_perspective(s)`), filtered to the rows a
    // scoped belief may fold.
    (
        "belief.rs",
        "scoped_belief_write",
        &["derivation_scope::retain_for_cache"],
    ),
    // gated (the claim is read through the viewer on the write transaction
    // first); the reads are the gated claim's own columns, its agent's
    // properties (agents), neighbour truth values for ids that came from
    // viewer-filtered edges, and best-effort derived rows (community scope,
    // silence alarm) that reach no response field. narrows: the source count
    // keeps only the cache-admissible rows of `get_for_claim_frame`, read
    // through the viewer just before it.
    (
        "belief.rs",
        "submit_evidence",
        &[
            "CommunityRepository::communities_for_perspective",
            "CommunityRepository::member_perspective_ids",
            "ConflictDensityRepository::for_frames",
            "DivergenceRepository::store",
            "MassFunctionRepository::store_with_perspective",
            "ScopedBeliefRepository::upsert",
            "ScopedBeliefRepository::upsert",
            "create_edge_under_savepoint",
            "create_edge_under_savepoint",
            "create_edge_under_savepoint",
            "create_edge_under_savepoint",
            "create_edge_under_savepoint",
            "create_edge_under_savepoint",
            "derivation_scope::retain_for_cache",
            "sqlx::query(INSERT).execute",
            "sqlx::query(UPDATE).execute",
            "sqlx::query_as(SELECT).fetch_all",
            "sqlx::query_as(SELECT).fetch_all",
            "sqlx::query_as(SELECT).fetch_optional",
            "sqlx::query_as(SELECT).fetch_optional",
            "sqlx::query_as(SELECT).fetch_optional",
            "sqlx::query_scalar(SELECT).fetch_optional",
        ],
    ),
    // gated (`ChallengeRepository::admission_of`) then write.
    (
        "challenge.rs",
        "submit_challenge",
        &[
            "ChallengeRepository::create",
            "EventRepository::publish_or_log_conn",
        ],
    ),
    // stamped: the resolution definer (`epigraph_resolve_challenge`, migration
    // 168 section 7, the only resolution path since 170) runs on the caller's
    // stamped write transaction; a missing challenge and one whose claim the
    // session cannot read are one not-found (CR02), and a reader that does not
    // write the claim's group is 42501 (CR03). The row returned is read
    // through the viewer.
    (
        "challenge.rs",
        "resolve_challenge",
        &["ChallengeRepository::resolve_as_claim_owner"],
    ),
    // untenanted: the caller's own membership, and the seal record of a claim
    // already read through the viewer.
    (
        "claims.rs",
        "get_claim",
        &[
            "ClaimEncryptionRepository::get_by_claim_id_conn",
            "GroupMembershipRepository::is_member",
        ],
    ),
    (
        "claims.rs",
        "list_claims",
        &[
            "ClaimEncryptionRepository::get_by_claim_id_conn",
            "GroupMembershipRepository::is_member",
        ],
    ),
    // gated (`write_target_of`) then write; the owner read is re-checked by the
    // in-transaction viewer re-fetch (F-write-authz-reads-unfiltered).
    (
        "claims.rs",
        "patch_claim",
        &[
            "ClaimRepository::admin_patch_claim_conn",
            "ClaimRepository::patch_claim_atomic_conn",
            "ProvenanceRepository::append_conn",
            "db_pool.begin",
            "sqlx::query_scalar(SELECT).fetch_optional",
        ],
    ),
    // gated (`ClaimRepository::get_by_id`) then write.
    (
        "claims.rs",
        "update_claim",
        &[
            "ClaimRepository::store_embedding",
            "ClaimRepository::update_trace_id",
            "ClaimRepository::update_truth_value",
            "provenance::record_provenance",
            "sqlx::query(UPDATE).execute",
        ],
    ),
    // gated (`write_target_of`) then write, stamped from the author's viewer on
    // the audited admin path.
    (
        "claims.rs",
        "update_labels",
        &[
            "ClaimRepository::admin_patch_claim_conn",
            "ClaimRepository::update_labels_conn",
            "state.write_as",
        ],
    ),
    // write: the caller's principal is the community's creator (one `groups`
    // insert, no read).
    (
        "community.rs",
        "create_community",
        &["CommunityRepository::create"],
    ),
    // gated (community and perspective) then write. The membership write is a
    // SECURITY DEFINER function on a transaction stamped from this viewer
    // (`membership_tx`); the principal argument names the actor, and the
    // function checks it against the stamped one.
    (
        "community.rs",
        "add_member",
        &[
            "CommunityRepository::add_member",
            "EdgeRepository::create_signed",
        ],
    ),
    (
        "community.rs",
        "remove_member",
        &["CommunityRepository::remove_member"],
    ),
    // open finding: F-SHARD4-A2.
    (
        "computation.rs",
        "propagate_beliefs",
        &[
            "sqlx::query_as(SELECT).fetch_all",
            "sqlx::query_as(SELECT).fetch_all",
            "sqlx::query_as(SELECT).fetch_all",
        ],
    ),
    // narrows: an `apply` run keeps the cache-admissible rows of the BBAs it
    // read through the viewer (`get_for_claims`); a read-only run filters them
    // through the viewer instead (`retain_for_viewer`, viewed).
    (
        "computation.rs",
        "bp_seed_rows",
        &["derivation_scope::retain_for_cache"],
    ),
    // gated (`ClaimRepository::get_by_id`) then write; agents are untenanted.
    // The REFUTES edge write runs on a transaction bound by
    // `if let Ok(mut tx) = state.write_as(..)` and passed as `&mut tx`, a
    // binding this scanner does not recognise as a connection, so it is not
    // measured here.
    (
        "conventions.rs",
        "forget_convention",
        &[
            "AgentRepository::create",
            "AgentRepository::get_by_public_key",
            "ClaimRepository::update_truth_value",
            "EvidenceRepository::create",
            "sqlx::query_scalar(SELECT).fetch_optional",
        ],
    ),
    (
        "conventions.rs",
        "share_skill",
        &[
            "AgentRepository::create",
            "AgentRepository::get_by_public_key",
            "ClaimRepository::create",
            "ClaimRepository::default_decl_for_author_pool",
            "EdgeRepository::create_signed_conn",
            "sqlx::query(UPDATE).execute",
        ],
    ),
    // untenanted: match_candidates rows; both claims are checked through the
    // viewer (`are_all_current`) before a promotion writes.
    (
        "cross_source.rs",
        "decide_candidate",
        &[
            "MatchCandidateRepo::get",
            "MatchCandidateRepo::get",
            "MatchCandidateRepo::get",
            "MatchCandidateRepo::new",
            "MatchCandidateRepo::promote_if_pending",
            "MatchCandidateRepo::reject_if_pending",
            "admin_cascade::record_deferral",
        ],
    ),
    (
        "cross_source.rs",
        "get_cross_source_matches",
        &["MatchCandidateRepo::new"],
    ),
    (
        "cross_source.rs",
        "list_candidates",
        &["MatchCandidateRepo::new"],
    ),
    // gated: the frame and (since backlog 4815dcf7) the claim are read through
    // the viewer before the binding is written.
    (
        "crud.rs",
        "assign_claim_to_frame",
        &[
            "FrameRepository::assign_claim",
            "provenance::record_provenance",
        ],
    ),
    // untenanted: claim_themes; the centroid is computed from viewer-filtered
    // claims (`set_centroid_from_claims`).
    (
        "crud.rs",
        "create_theme_with_centroid",
        &[
            "ClaimThemeRepository::bulk_assign",
            "ClaimThemeRepository::create",
            "ClaimThemeRepository::set_centroid",
            "ClaimThemeRepository::update_count",
        ],
    ),
    // gated (the claim's embedding is read through the viewer, and an
    // unreadable claim is skipped) then theme reads and writes.
    (
        "crud.rs",
        "reassign_claim",
        &[
            "ClaimThemeRepository::assign_claim",
            "ClaimThemeRepository::find_similar_themes",
            "ClaimThemeRepository::unassign_claim",
            "sqlx::query(SELECT).fetch_optional",
        ],
    ),
    // write: the viewer gates the update itself.
    (
        "crud.rs",
        "update_evidence",
        &["provenance::record_provenance"],
    ),
    // gated: as assign_claim_to_frame (the claim is read through the viewer
    // before the frame is found or created and the binding written).
    (
        "crud.rs",
        "upsert_cluster",
        &[
            "FrameRepository::assign_claim",
            "FrameRepository::create",
            "provenance::record_provenance",
        ],
    ),
    // stamped: `edges` id projections for a claim already read through the
    // viewer (see viewer_route_table_lint.rs's note on this handler).
    (
        "edges.rs",
        "claim_provenance",
        &[
            "sqlx::query_as(SELECT).fetch_all",
            "sqlx::query_as(SELECT).fetch_all",
        ],
    ),
    // write on a transaction stamped with the caller's viewer: the endpoint
    // existence checks run on it, and the edge trigger and WITH CHECK decide
    // the write.
    (
        "edges.rs",
        "create_edge",
        &[
            "EdgeRepository::create_if_not_exists_signed_conn",
            "EdgeRepository::create_signed_conn",
            "EdgeRepository::create_symmetric_if_absent_row_signed_conn",
            "EdgeRepository::owned_by_session",
            "entity_exists",
            "entity_exists",
            "is_valid_entity_type",
            "is_valid_entity_type",
            "provenance::record_provenance",
            "valid_entity_type_names",
            "valid_entity_type_names",
        ],
    ),
    // gated (both claims through the viewer) then write.
    (
        "edges.rs",
        "create_hierarchical_edge",
        &[
            "EdgeRepository::create_if_not_exists_signed_conn",
            "EdgeRepository::owned_by_session",
        ],
    ),
    // gated (`EdgeRepository::refusal_for`) then write.
    (
        "edges.rs",
        "delete_edge",
        &[
            "EdgeRepository::retract_by_id",
            "EdgeRepository::withdraw_edge_bbas_conn",
            "provenance::record_provenance",
        ],
    ),
    // stamped: the edges naming an evidence row already read through the
    // viewer (F-edges-unfiltered owns their predicate).
    (
        "edges.rs",
        "get_evidence",
        &[
            "sqlx::query_as(SELECT).fetch_optional",
            "sqlx::query_as(SELECT).fetch_optional",
        ],
    ),
    (
        "edges.rs",
        "patch_edge",
        &[
            "EdgeRepository::update_valid_to_and_properties",
            "EdgeRepository::withdraw_edge_bbas_conn",
            "provenance::record_provenance",
        ],
    ),
    // gated (both claims through the viewer) then write.
    (
        "edges.rs",
        "relate_claims",
        &[
            "EdgeRepository::create_signed_conn",
            "EdgeRepository::create_signed_conn",
            "provenance::record_provenance",
        ],
    ),
    // gated (`require_writable_targets`) then write.
    (
        "entities.rs",
        "batch_create_mentions",
        &["TripleRepository::batch_create_mentions"],
    ),
    (
        "entities.rs",
        "batch_create_triples",
        &["TripleRepository::batch_create_triples"],
    ),
    // untenanted: entities, on a transaction stamped with the caller's viewer.
    (
        "entities.rs",
        "create_entity",
        &["EntityRepository::upsert"],
    ),
    (
        "entities.rs",
        "entity_neighborhood",
        &["EntityRepository::get"],
    ),
    (
        "entities.rs",
        "query_triples",
        &[
            "EntityRepository::find_by_name_and_type",
            "EntityRepository::find_by_name_and_type",
        ],
    ),
    // gated (operator ruling R-51: `require_experiment_hypothesis` reads the
    // experiment's hypothesis through the viewer, requires it writable and the
    // result to belong to `:eid`) then the untenanted result row it named.
    (
        "experiment_loop.rs",
        "add_measurements",
        &[
            "ExperimentResultRepository::add_measurements",
            "ExperimentResultRepository::get",
        ],
    ),
    // gated (the result must belong to the named experiment, and that
    // experiment's hypothesis is read through the viewer and required
    // writable, `require_experiment_hypothesis` with the result, so a hidden
    // hypothesis is the same `result` 404 as a missing result, before
    // anything is written; until
    // backlog 4815dcf7 and ruling R-51 neither held) then untenanted reads
    // (experiments, experiment_results, frames by name) and writes against it.
    (
        "experiment_loop.rs",
        "analyze_result",
        &[
            "EdgeRepository::create_signed",
            "EdgeRepository::create_signed",
            "ExperimentRepository::get",
            "ExperimentRepository::update_status",
            "ExperimentRepository::update_status",
            "ExperimentResultRepository::get",
            "ExperimentResultRepository::update_status",
            "MassFunctionRepository::store",
            "sqlx::query_as(INSERT).fetch_one",
            "sqlx::query_as(SELECT).fetch_one",
        ],
    ),
    // gated (R-51: `require_hypothesis` reads the body's hypothesis through
    // the viewer and requires it writable) then write: the untenanted
    // experiment row and its `tests_hypothesis` edge onto that hypothesis.
    (
        "experiment_loop.rs",
        "create_experiment",
        &[
            "EdgeRepository::create_signed",
            "ExperimentRepository::create",
        ],
    ),
    // gated (R-51: `require_hypothesis`, read access) then untenanted:
    // experiments carry no tenancy columns; the hypothesis they list under was
    // read through the viewer first.
    (
        "experiment_loop.rs",
        "list_experiments",
        &["ExperimentRepository::get_for_hypothesis"],
    ),
    // gated (R-51: `require_experiment_hypothesis`, write access) then write
    // on the untenanted experiment row.
    (
        "experiment_loop.rs",
        "start_experiment",
        &["ExperimentRepository::update_status"],
    ),
    // gated (R-51: `require_experiment_hypothesis`, write access) then writes
    // on untenanted rows: the result, its `result_of` edge to the experiment,
    // and the experiment's status.
    (
        "experiment_loop.rs",
        "submit_results",
        &[
            "EdgeRepository::create_signed",
            "ExperimentRepository::update_status",
            "ExperimentResultRepository::create",
        ],
    ),
    // untenanted: methods.
    (
        "experiments.rs",
        "design_experiment",
        &["MethodRepository::get"],
    ),
    (
        "experiments.rs",
        "method_gap_analysis",
        &["MethodRepository::get_methods_for_capability"],
    ),
    // write: the stored analysis is computed from viewer-filtered claims.
    (
        "gaps.rs",
        "gap_analysis",
        &["GapRepository::store_gap_analysis"],
    ),
    // stamped: cluster-run metadata (untenanted) and the edges among nodes the
    // viewer already read (F-edges-unfiltered owns their predicate).
    (
        "graph.rs",
        "expand",
        &[
            "fetch_subgraph_edges",
            "sqlx::query_as(SELECT).fetch_optional",
            "sqlx::query_as(SELECT).fetch_optional",
        ],
    ),
    // open finding: F-aggregate-existence-oracles (the two decomposes_to
    // counts deciding center_kind).
    (
        "graph_neighborhood.rs",
        "claim_compound_neighborhood",
        &[
            "sqlx::query_scalar(SELECT).fetch_one",
            "sqlx::query_scalar(SELECT).fetch_one",
        ],
    ),
    // untenanted: the neighborhood id in the latest run.
    (
        "graph_neighborhood.rs",
        "expand",
        &["sqlx::query_as(SELECT).fetch_optional"],
    ),
    // stamped: `groups`, `group_memberships` and `group_key_epochs` have row
    // security (077), and each route runs on ONE connection stamped with the
    // caller's viewer; the group-admin check is the database's, for the caller.
    // add_member and remove_member: the admin check first, then the group, its
    // epoch and the roster write. create_group: the INSERT's `WITH CHECK` binds
    // the creator to the stamped principal. get_group: the caller's own
    // membership first (a non-member is refused before existence is told),
    // then the group, its roster and epoch under row security.
    (
        "groups.rs",
        "add_member",
        &[
            "GroupKeyEpochRepository::get_current_epoch_conn",
            "GroupMembershipRepository::add_member_conn",
            "GroupRepository::get_by_id_conn",
            "group_authz::require_group_admin_conn",
        ],
    ),
    (
        "groups.rs",
        "create_group",
        &["GroupRepository::create_with_admin_conn"],
    ),
    (
        "groups.rs",
        "get_group",
        &[
            "GroupKeyEpochRepository::get_current_epoch_conn",
            "GroupMembershipRepository::get_members_conn",
            "GroupMembershipRepository::is_member_conn",
            "GroupRepository::get_by_id_conn",
        ],
    ),
    (
        "groups.rs",
        "remove_member",
        &[
            "GroupMembershipRepository::revoke_member_unless_last_admin_conn",
            "GroupRepository::get_by_id_conn",
            "group_authz::require_group_admin_conn",
        ],
    ),
    (
        "groups.rs",
        "rotate_key",
        &[
            "GroupKeyEpochRepository::rotate_conn",
            "group_authz::require_group_admin_conn",
        ],
    ),
    // write on a transaction stamped with the caller's viewer (the new claim
    // and its frame binding); the neighbourhood read is viewer-spliced.
    (
        "hypothesis.rs",
        "create_hypothesis",
        &[
            "ClaimRepository::default_decl_for_author_pool",
            "MassFunctionRepository::store_with_perspective",
            "sqlx::query(INSERT).execute",
            "sqlx::query(UPDATE).execute",
            "sqlx::query_as(INSERT).fetch_one",
            "sqlx::query_as(SELECT).fetch_one",
        ],
    ),
    // gated (`content_and_properties`): experiments (untenanted), the frame by
    // name, and an EXISTS over the gated claim's analyses, all stamped.
    (
        "hypothesis.rs",
        "hypothesis_status",
        &[
            "ExperimentRepository::get_for_hypothesis",
            "sqlx::query_as(SELECT).fetch_one",
            "sqlx::query_as(SELECT).fetch_optional",
        ],
    ),
    // gated: the status re-check calls `hypothesis_status` with a scoped copy
    // of the caller's own viewer (`detach_scoped`), then writes; the two
    // SELECTs are frames by name.
    (
        "hypothesis.rs",
        "promote_hypothesis",
        &[
            "MassFunctionRepository::copy_to_frame",
            "db_pool.begin",
            "hypothesis_status",
            "sqlx::query(INSERT).execute",
            "sqlx::query(UPDATE).execute",
            "sqlx::query(UPDATE).execute",
            "sqlx::query_as(SELECT).fetch_one",
            "sqlx::query_as(SELECT).fetch_one",
        ],
    ),
    // untenanted: methods.
    ("methods.rs", "get_method", &["MethodRepository::get"]),
    // write on a transaction stamped with the caller's viewer; the system
    // agent and its declaration are agents reads.
    (
        "policies.rs",
        "create_challenge",
        &[
            "ClaimRepository::default_decl_for_author_pool",
            "sqlx::query(SELECT).execute",
            "sqlx::query_scalar(INSERT).fetch_one",
            "sqlx::query_scalar(SELECT).fetch_optional",
            "workflows::get_or_create_system_agent",
        ],
    ),
    // untenanted: the agent row; the profile reads are viewer-spliced.
    (
        "political.rs",
        "compare_agents",
        &["AgentRepository::get_by_id"],
    ),
    (
        "political.rs",
        "epistemic_profile",
        &["AgentRepository::get_by_id"],
    ),
    (
        "political.rs",
        "inflation_index",
        &["AgentRepository::get_by_id"],
    ),
    (
        "political.rs",
        "originated_claims",
        &["AgentRepository::get_by_id"],
    ),
    (
        "political.rs",
        "position_timeline",
        &["AgentRepository::get_by_id"],
    ),
    // lifecycle (every privatization.rs entry).
    (
        "privatization.rs",
        "abort_plan",
        &[
            "Connection::begin",
            "PrivatizationRepository::record_plan_audit_conn",
            "PrivatizationRepository::transition_plan_conn",
            "lifecycle_served",
            "maintenance",
            "record_custodial_act",
            "require_plan_authority",
        ],
    ),
    (
        "privatization.rs",
        "apply_plan",
        &["dispatch", "lifecycle_served", "require_plan_authority"],
    ),
    (
        "privatization.rs",
        "approve_plan",
        &[
            "Connection::begin",
            "PrivatizationRepository::record_plan_audit_conn",
            "PrivatizationRepository::transition_plan_conn",
            "lifecycle_served",
            "maintenance",
            "record_custodial_act",
            "require_plan_authority",
        ],
    ),
    // lifecycle: instance-admin authority over the target group is checked
    // before the maintenance reads; the previews are rendered through the
    // viewer.
    (
        "privatization.rs",
        "create_plan",
        &[
            "Connection::begin",
            "PrivatizationRepository::create_previewed_plan",
            "PrivatizationRepository::select",
            "PrivatizationRepository::shared_fragment_count_conn",
            "authors_losing_own_claims",
            "boundary_edge_counts",
            "freeze_into",
            "instance_authz::require_instance_admin_for_group",
            "lifecycle_served",
            "maintenance",
            "omitted_edge_types",
            "record_custodial_act",
            "resolve_seeds",
        ],
    ),
    // lifecycle: the audit read is stamped; the maintenance write logs it.
    (
        "privatization.rs",
        "get_audit",
        &[
            "PrivatizationRepository::load_audit_conn",
            "SecurityEventRepository::log_conn",
            "lifecycle_served",
            "maintenance",
        ],
    ),
    (
        "privatization.rs",
        "get_plan",
        &[
            "PrivatizationRepository::item_state_counts_conn",
            "lifecycle_served",
            "require_plan_authority",
        ],
    ),
    (
        "privatization.rs",
        "get_plan_items",
        &[
            "PrivatizationRepository::load_plan_conn",
            "PrivatizationRepository::load_plan_items_conn",
            "lifecycle_served",
            "require_plan_authority",
        ],
    ),
    (
        "privatization.rs",
        "list_plans",
        &[
            "PrivatizationRepository::list_plans_conn",
            "lifecycle_served",
        ],
    ),
    (
        "privatization.rs",
        "revert_plan",
        &[
            "PrivatizationRepository::sealed_item_count_conn",
            "dispatch",
            "lifecycle_served",
            "maintenance",
            "require_plan_authority",
        ],
    ),
    (
        "privatization.rs",
        "seal_commit",
        &[
            "Connection::begin",
            "PrivatizationRepository::active_epoch_conn",
            "PrivatizationRepository::begin_batch_conn",
            "PrivatizationRepository::enqueue_job_conn",
            "PrivatizationRepository::plan_contains_conn",
            "PrivatizationRepository::record_seal_audit_conn",
            "PrivatizationRepository::seal_claims_conn",
            "PrivatizationRepository::seal_tcb_shape_conn",
            "lifecycle_served",
            "maintenance",
            "require_plan_authority",
        ],
    ),
    (
        "privatization.rs",
        "seal_manifest",
        &[
            "PrivatizationRepository::active_epoch_conn",
            "PrivatizationRepository::seal_manifest_page_conn",
            "lifecycle_served",
            "log_manifest_read",
            "maintenance",
            "require_plan_authority",
        ],
    ),
    (
        "privatization.rs",
        "unseal_commit",
        &[
            "Connection::begin",
            "PrivatizationRepository::begin_batch_conn",
            "PrivatizationRepository::enqueue_job_conn",
            "PrivatizationRepository::enqueue_job_conn",
            "PrivatizationRepository::plan_contains_conn",
            "PrivatizationRepository::record_seal_audit_conn",
            "PrivatizationRepository::unseal_claims_conn",
            "PrivatizationRepository::unseal_tcb_shape_conn",
            "lifecycle_served",
            "maintenance",
            "require_plan_authority",
        ],
    ),
    (
        "privatization.rs",
        "unseal_manifest",
        &[
            "PrivatizationRepository::unseal_manifest_page_conn",
            "lifecycle_served",
            "log_manifest_read",
            "maintenance",
            "require_plan_authority",
        ],
    ),
    // no SQL: the query embedding.
    ("rag.rs", "rag_context", &["generate_query_embedding"]),
    ("rag.rs", "search_evidence", &["generate_query_embedding"]),
    // no SQL (embeddings), untenanted (claim_themes, the centroid-dimension
    // probe), and the content read registered in viewer_route_table_lint.rs's
    // UNCOMPENSATED_INLINE_READS (ids from a viewer-spliced theme read).
    (
        "search.rs",
        "semantic_search",
        &[
            "ClaimThemeRepository::find_similar_themes_at_dim",
            "generate_query_embedding",
            "generate_query_embedding",
            "generate_query_embedding_with_dim",
            "sqlx::query(SELECT).fetch_all",
            "sqlx::query_scalar(SELECT).fetch_one",
        ],
    ),
    // write: embeddings and propagation for the claim this request just
    // persisted through the viewer (`persist_packet`); `validate_packet` runs
    // no tenancy read.
    (
        "submit.rs",
        "submit_packet",
        &[
            "propagate_from",
            "sqlx::query(UPDATE).execute",
            "sqlx::query(UPDATE).execute",
            "validate_packet",
        ],
    ),
    // gated (`write_target_of`) then write.
    (
        "versioning.rs",
        "mark_duplicate",
        &[
            "ClaimRepository::mark_duplicate_act_attributed_conn",
            "ProvenanceRepository::append_conn",
            "admin_session_or_deferral",
            "db_pool.begin",
        ],
    ),
    // gated (`write_target_of`) then write; the factors SELECT feeds the
    // write's re-pointing.
    (
        "versioning.rs",
        "supersede_claim",
        &[
            "ClaimRepository::supersede_act_conn",
            "ClaimVersionRepository::create",
            "admin_session_or_deferral",
            "sqlx::query_as(SELECT).fetch_all",
        ],
    ),
    (
        "versioning.rs",
        "unmark_duplicate",
        &["ClaimRepository::session_may_unmark_conn"],
    ),
    // gated (`get_by_id_with_labels`) then write.
    (
        "workflows.rs",
        "deprecate_workflow",
        &[
            "ClaimRepository::deprecate_claim",
            "EventRepository::insert",
            "WorkflowRepository::set_truth_value",
        ],
    ),
    // write on a transaction stamped with the caller's viewer, after the
    // database's lineage-authority check for the caller.
    (
        "workflows.rs",
        "evolve_step",
        &[
            "ClaimRepository::evolve_step_conn",
            "record_api_lineage_writes",
            "require_api_lineage_authority",
            "versioning::admin_session_or_deferral",
        ],
    ),
    // stamped: both searches run on the caller's viewer-stamped connection,
    // and since migration 183 (ruling R-74) row security on `workflows` admits
    // only public rows and rows of the caller's read set.
    (
        "workflows.rs",
        "find_workflow_hierarchical",
        &[
            "WorkflowRepository::find_hierarchical_by_embedding",
            "WorkflowRepository::search_hierarchical_by_text",
        ],
    ),
    // write: the ingest transaction is stamped with the system agent and binds
    // the caller's principal for the database's write-authority check
    // (`begin_system_ingest_stamped_tx`); the authorship edges name that
    // principal; embeddings for the rows this request just ingested (the
    // claims', and the workflow row's goal embedding, each on a transaction
    // stamped from the workflow-ingest system agent).
    (
        "workflows.rs",
        "ingest_workflow",
        &[
            "begin_system_ingest_stamped_tx",
            "embed_inserted_workflow_claims",
            "record_api_authorship",
            "store_workflow_goal_embedding",
        ],
    ),
    // stamped: the `workflows` row is locked (SELECT .. FOR UPDATE) and its
    // counters updated on the caller's stamped write transaction, where row
    // security (migration 183, ruling R-74) hides a row the caller does not
    // read, so it takes the missing-id 404; `viewer_reads_plan_structure`
    // (viewed) then requires a readable step before any write. untenanted:
    // behavioral_executions. write.
    (
        "workflows.rs",
        "report_hierarchical_outcome",
        &[
            "BehavioralExecutionRepository::create",
            "sqlx::query(UPDATE).execute",
            "sqlx::query_as(SELECT).fetch_optional",
        ],
    ),
    // gated (`get_by_id_with_labels`) then write on the stamped transaction.
    (
        "workflows.rs",
        "report_outcome",
        &[
            "BehavioralExecutionRepository::create",
            "ClaimRepository::set_properties_conn",
            "ClaimRepository::update_truth_value_conn",
            "sqlx::query_as(SELECT).fetch_optional",
        ],
    ),
    // untenanted: behavioral_executions.
    (
        "workflows.rs",
        "search_workflows",
        &[
            "BehavioralExecutionRepository::rolling_success_rate",
            "BehavioralExecutionRepository::rolling_success_rate",
        ],
    ),
    // write: as ingest_workflow (stamped system ingest binding the caller's
    // principal, authorship edges), the ingest and the embeddings of the rows it
    // inserted.
    (
        "workflows.rs",
        "store_workflow",
        &[
            "EventRepository::insert",
            "begin_system_ingest_stamped_tx",
            "embed_inserted_workflow_claims",
            "epigraph_ingest_executor::execute_workflow_ingest_plan",
            "record_api_authorship",
            "store_workflow_goal_embedding",
        ],
    ),
    // ── route helpers a handler hands its viewer to ──────────────────────
    //
    // A handler that passes `&viewer` to one of these counts that call as
    // viewed, so each helper's own body is measured and reviewed here.
    //
    // claims.rs::create_claim_core (POST /claims, /claims/batch). untenanted:
    // the CALLER's own membership of the group it asks to encrypt into (the
    // authenticated id, never the body), then that group's current key epoch,
    // read only after the membership check passed; the author's agent row.
    // write: everything else runs on the claim-write transaction stamped with
    // this viewer, except the best-effort post-commit embedding, AUTHORED /
    // HAS_TRACE / DERIVED_FROM edges and provenance row, which are raw-pool
    // writes for a row this call created (`was_created`; ROUTE_LAYER_WRITES in
    // viewer_route_table_lint.rs).
    (
        "claims.rs",
        "create_claim_core",
        &[
            "AgentRepository::get_by_id",
            "ClaimEncryptionRepository::insert_conn",
            "ClaimRepository::create_strict",
            "ClaimRepository::default_decl_for_author",
            "ClaimRepository::lock_content_hash_agent",
            "EdgeRepository::create_signed",
            "EdgeRepository::create_signed",
            "EdgeRepository::create_signed",
            "GroupKeyEpochRepository::get_current_epoch",
            "GroupMembershipRepository::is_member",
            "provenance::record_provenance",
            "sqlx::query(UPDATE).execute",
            "sqlx::query(UPDATE).execute",
            "sqlx::query(UPDATE).execute",
        ],
    ),
    // stamped: computation.rs::apply_bp_updates runs on a write transaction
    // stamped with this viewer; its "which ids are visible" read and the role
    // read are row security's (a single layer, as every stamped entry), and
    // the writes are WITH CHECK's. BP apply is off unless the operator turns
    // it on (EPIGRAPH_BP_APPLY).
    (
        "computation.rs",
        "apply_bp_updates",
        &[
            "sqlx::query(UPDATE).execute",
            "sqlx::query(UPDATE).execute",
            "sqlx::query_scalar(SELECT).fetch_all",
            "sqlx::query_scalar(dynamic).fetch_all",
        ],
    ),
    // edges.rs's DS recomputation after an edge write: the raw-pool reads (the
    // source claim's author id, for BBA attribution; the reasoning traces that
    // name the updated claim) reach no response field, the acquires are
    // mechanical (no_unscoped_pool.rs counts these edges.rs sites), and the
    // wiring and recomputation themselves take the viewer.
    (
        "edges.rs",
        "propagate_to_dependents",
        &["sqlx::query_as(SELECT).fetch_all"],
    ),
    ("edges.rs", "recompute_claim_belief", &["db_pool.acquire"]),
    (
        "edges.rs",
        "trigger_edge_ds_recomputation",
        &[
            "db_pool.acquire",
            "sqlx::query_scalar(SELECT).fetch_optional",
        ],
    ),
    // stamped: the neighborhood's edge projections, on the caller's stamped
    // connection, are constrained in Rust to endpoints that survived the
    // viewer-filtered node projection (PR-07); the edges' own predicate is
    // F-edges-unfiltered.
    (
        "graph_neighborhood.rs",
        "atomic_response",
        &["sqlx::query_as(SELECT).fetch_all"],
    ),
    (
        "graph_neighborhood.rs",
        "compound_response",
        &[
            "sqlx::query_as(WITH).fetch_all",
            "sqlx::query_as(WITH).fetch_all",
            "sqlx::query_as(WITH).fetch_all",
        ],
    ),
    // no SQL: the acquire is mechanical and unstamped (graph_query.rs is an
    // unconverted no_unscoped_pool.rs site); every projection in
    // load_subgraph_conn splices the viewer except `agents` (untenanted).
    (
        "graph_query_utils.rs",
        "load_subgraph",
        &["db_pool.acquire"],
    ),
    (
        "graph_query_utils.rs",
        "load_subgraph_conn",
        &["sqlx::query_as(SELECT).fetch_all"],
    ),
    // stamped: the plan read on the actor's own stamped connection; the 404 is
    // migration 087's SELECT policy.
    (
        "privatization.rs",
        "load_plan_for_actor",
        &["PrivatizationRepository::load_plan_conn"],
    ),
    // no SQL: the savepoint around the viewer-taking theme probe.
    (
        "search.rs",
        "probe_theme_coverage_isolated",
        &[
            "sqlx::query(RELEASE).execute",
            "sqlx::query(SAVEPOINT).execute",
        ],
    ),
    // write: submit.rs::persist_packet runs on the claim-write transaction
    // stamped with this viewer (claim, trace, evidence, edges); the raw-pool
    // read is the packet's author agent (untenanted).
    (
        "submit.rs",
        "persist_packet",
        &[
            "AgentRepository::get_by_id",
            "ClaimRepository::default_decl_for_author",
            "EdgeRepository::create_signed_conn",
            "EdgeRepository::create_signed_conn",
            "EdgeRepository::create_signed_conn",
            "EdgeRepository::create_signed_conn",
            "EdgeRepository::create_signed_conn",
            "sqlx::query(?).execute",
            "sqlx::query(?).execute",
            "sqlx::query(?).execute",
            "sqlx::query(UPDATE).execute",
            "sqlx::query(UPDATE).execute",
        ],
    ),
    // write: workflows.rs's ingest helpers run on the system-ingest transaction
    // that binds the caller's principal for the database's write-authority
    // check; the lineage anchors are workflows rows, read under row security
    // on that stamped transaction (migration 183, ruling R-74), the
    // authority check is for the caller's principal over each anchor, and the
    // rest record the submitter, the per-anchor provenance and the admin audit.
    (
        "workflows.rs",
        "auto_wire_inserted_edges",
        &["begin_system_ingest_stamped_tx"],
    ),
    (
        "workflows.rs",
        "record_workflow_submitter",
        &[
            "WorkflowRepository::record_submitter",
            "audit_api_admin_workflow_write",
            "record_api_caller_workflow_write",
        ],
    ),
    (
        "workflows.rs",
        "workflow_ingest_submitter",
        &["WorkflowRepository::ingest_anchors", "workflow_authority"],
    ),
];

// ── source views ────────────────────────────────────────────────────────────

/// Two views of `src`, byte-for-byte the same length as it, so offsets agree:
///
/// * `code`: comments and string/char-literal CONTENTS replaced by spaces (the
///   quotes stay). Everything structural is read here, so a viewer named in a
///   comment or in a string does not count as a spend.
/// * `sql`: comments replaced by spaces, string contents kept. Read only for
///   the first word of a statement and for `#[cfg(..)]` predicates.
fn views(src: &str) -> (String, String) {
    let s = src.as_bytes();
    let n = s.len();
    let mut code = s.to_vec();
    let mut sql = s.to_vec();
    let blank = |code: &mut Vec<u8>, sql: &mut Vec<u8>, a: usize, b: usize, both: bool| {
        for k in a..b.min(n) {
            if s[k] != b'\n' {
                code[k] = b' ';
                if both {
                    sql[k] = b' ';
                }
            }
        }
    };
    let mut i = 0;
    while i < n {
        if s[i..].starts_with(b"//") {
            let j = s[i..].iter().position(|&c| c == b'\n').map_or(n, |p| i + p);
            blank(&mut code, &mut sql, i, j, true);
            i = j;
            continue;
        }
        if s[i..].starts_with(b"/*") {
            let (mut depth, mut j) = (0usize, i);
            while j < n {
                if s[j..].starts_with(b"/*") {
                    depth += 1;
                    j += 2;
                } else if s[j..].starts_with(b"*/") {
                    depth -= 1;
                    j += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    j += 1;
                }
            }
            blank(&mut code, &mut sql, i, j, true);
            i = j;
            continue;
        }
        let prev_is_ident = i > 0 && is_ident(s[i - 1]);
        if !prev_is_ident && (s[i] == b'r' || s[i] == b'b') {
            let mut j = i;
            if s[j] == b'b' {
                j += 1;
            }
            if j < n && s[j] == b'r' {
                let mut k = j + 1;
                while k < n && s[k] == b'#' {
                    k += 1;
                }
                if k < n && s[k] == b'"' {
                    let hashes = k - (j + 1);
                    let mut end = vec![b'"'];
                    end.extend(std::iter::repeat_n(b'#', hashes));
                    let close = find(s, &end, k + 1).unwrap_or(n);
                    blank(&mut code, &mut sql, k + 1, close, false);
                    i = close + end.len();
                    continue;
                }
            }
            if s[i] == b'b' && i + 1 < n && s[i + 1] == b'"' {
                i += 1;
            }
        }
        if s[i] == b'"' {
            let mut j = i + 1;
            while j < n && s[j] != b'"' {
                if s[j] == b'\\' {
                    j += 1;
                }
                j += 1;
            }
            blank(&mut code, &mut sql, i + 1, j, false);
            i = j + 1;
            continue;
        }
        if s[i] == b'\'' {
            // A char literal ('x', '\n', '\u{..}'); otherwise a lifetime.
            if i + 2 < n && s[i + 1] == b'\\' {
                let j = s[i + 2..]
                    .iter()
                    .position(|&c| c == b'\'')
                    .map_or(n, |p| i + 2 + p);
                blank(&mut code, &mut sql, i + 1, j, false);
                i = j + 1;
                continue;
            }
            if i + 2 < n && s[i + 2] == b'\'' {
                blank(&mut code, &mut sql, i + 1, i + 2, false);
                i += 3;
                continue;
            }
        }
        i += 1;
    }
    (
        String::from_utf8(code).expect("only ASCII spaces were written"),
        String::from_utf8(sql).expect("only ASCII spaces were written"),
    )
}

fn is_ident(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if from > hay.len() {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| from + p)
}

/// Offsets in `[a, b)` where `word` occurs with no identifier byte on either side.
fn words(code: &str, word: &str, a: usize, b: usize) -> Vec<usize> {
    let s = code.as_bytes();
    let mut out = Vec::new();
    let mut from = a;
    while let Some(p) = find(s, word.as_bytes(), from) {
        if p >= b {
            break;
        }
        let end = p + word.len();
        if (p == 0 || !is_ident(s[p - 1])) && (end >= s.len() || !is_ident(s[end])) {
            out.push(p);
        }
        from = p + 1;
    }
    out
}

fn skip_ws(s: &[u8], mut i: usize) -> usize {
    while i < s.len() && s[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

fn ident_at(s: &[u8], i: usize) -> &str {
    let mut j = i;
    while j < s.len() && is_ident(s[j]) {
        j += 1;
    }
    std::str::from_utf8(&s[i..j]).expect("ASCII identifier")
}

/// The offset of the bracket closing the one at `open`.
fn close_of(s: &[u8], open: usize) -> usize {
    let (o, c) = match s[open] {
        b'(' => (b'(', b')'),
        b'[' => (b'[', b']'),
        b'{' => (b'{', b'}'),
        b'<' => (b'<', b'>'),
        other => panic!("close_of on {:?}", other as char),
    };
    let mut depth = 0usize;
    for (j, &ch) in s.iter().enumerate().skip(open) {
        if ch == o {
            depth += 1;
        } else if ch == c {
            depth -= 1;
            if depth == 0 {
                return j;
            }
        }
    }
    s.len() - 1
}

/// Spans of items under `#[cfg(test)]`, `#[cfg(all(test, ..))]` or
/// `#[cfg(not(feature = "db"))]`: test modules and the stub arm a handler has
/// when the database is compiled out. Neither serves a request.
fn excluded_spans(code: &str, sql: &str) -> Vec<(usize, usize)> {
    let (c, q) = (code.as_bytes(), sql.as_bytes());
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(at) = find(c, b"#[cfg(", from) {
        from = at + 1;
        let open = at + 5;
        let close = close_of(c, open);
        let pred: String = std::str::from_utf8(&q[open + 1..close])
            .expect("utf-8")
            .chars()
            .filter(|ch| !ch.is_whitespace())
            .collect();
        if pred == "test" || pred.starts_with("all(test") || pred == "not(feature=\"db\")" {
            let brace = find(c, b"{", close).unwrap_or(c.len() - 1);
            let semi = find(c, b";", close).unwrap_or(c.len() - 1);
            let end = if semi < brace {
                semi
            } else {
                close_of(c, brace)
            };
            out.push((at, end));
        }
    }
    out
}

// ── handlers and their calls ────────────────────────────────────────────────

struct Handler {
    name: String,
    viewer: String,
    body: (usize, usize),
    /// Parameters typed as a pool (`&PgPool`): aliases of `state.db_pool`.
    pools: Vec<String>,
    /// Parameters typed as a connection (`&mut PgConnection`, `ScopedRead`,
    /// `ScopedTx`, `Transaction`): any use inside a call is a database call.
    conns: Vec<String>,
}

/// `(name, flattened type)` of each `<ident>: <type>` parameter in `params`
/// (the text between, and including, the parentheses). Pattern parameters
/// (`State(state): ..`) have no plain name and are skipped.
fn typed_params(params: &str) -> Vec<(String, String)> {
    let p = params.as_bytes();
    let inner = &p[1..p.len() - 1];
    let mut parts = Vec::new();
    let (mut depth, mut start) = (0i32, 0usize);
    for (i, &c) in inner.iter().enumerate() {
        match c {
            b'>' if i > 0 && inner[i - 1] == b'-' => {}
            b'(' | b'<' | b'[' | b'{' => depth += 1,
            b')' | b'>' | b']' | b'}' => depth -= 1,
            b',' if depth == 0 => {
                parts.push(&inner[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&inner[start..]);
    let mut out = Vec::new();
    for part in parts {
        let part = std::str::from_utf8(part).expect("ASCII params");
        let Some(colon) = part.find(':') else {
            continue;
        };
        let name = part[..colon].trim().trim_start_matches("mut ").trim();
        if name.is_empty() || !name.bytes().all(is_ident) || part[colon..].starts_with("::") {
            continue;
        }
        let ty: String = part[colon + 1..]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        out.push((name.to_string(), ty));
    }
    out
}

/// Is `ty` (flattened) a reference to `Viewer`: `&Viewer`, `&epigraph_db::Viewer`,
/// `&epigraph_db::visibility::Viewer`?
fn is_viewer_ref(ty: &str) -> bool {
    let Some(rest) = ty.strip_prefix('&') else {
        return false;
    };
    let rest = rest.trim_start_matches("'_").trim_start_matches("mut");
    rest == "Viewer"
        || (rest.ends_with("::Viewer") && rest.bytes().all(|c| is_ident(c) || c == b':'))
}

/// Every viewer-holding `fn`: one whose parameters destructure
/// `ViewerExtractor(<ident>)` (a handler), or one with an `<ident>: &Viewer`
/// parameter (a route helper a handler delegates its viewer to). A handler
/// that passes `&viewer` to a helper counts that call as viewed, so the
/// helper's own body has to be measured too, or a raw-pool read inside it
/// would be invisible.
fn handlers(code: &str, sql: &str) -> Vec<Handler> {
    let s = code.as_bytes();
    let excluded = excluded_spans(code, sql);
    let mut out = Vec::new();
    for at in words(code, "fn", 0, s.len()) {
        if excluded.iter().any(|&(a, b)| a <= at && at <= b) {
            continue;
        }
        let mut j = skip_ws(s, at + 2);
        let name = ident_at(s, j).to_string();
        if name.is_empty() {
            continue;
        }
        j = skip_ws(s, j + name.len());
        if j < s.len() && s[j] == b'<' {
            j = skip_ws(s, close_of(s, j) + 1);
        }
        if j >= s.len() || s[j] != b'(' {
            continue;
        }
        let params_end = close_of(s, j);
        let params = &code[j..=params_end];
        let p = params.as_bytes();
        let mut viewer = None;
        for k in words(params, "ViewerExtractor", 0, p.len()) {
            let m = skip_ws(p, k + "ViewerExtractor".len());
            if m < p.len() && p[m] == b'(' {
                let v_at = skip_ws(p, m + 1);
                let v = ident_at(p, v_at);
                let after = skip_ws(p, v_at + v.len());
                if !v.is_empty() && after < p.len() && p[after] == b')' {
                    viewer = Some(v.to_string());
                    break;
                }
            }
        }
        let typed = typed_params(params);
        if viewer.is_none() {
            viewer = typed
                .iter()
                .find(|(_, ty)| is_viewer_ref(ty))
                .map(|(n, _)| n.clone());
        }
        let Some(viewer) = viewer else { continue };
        let pools = typed
            .iter()
            .filter(|(_, ty)| ty.contains("PgPool"))
            .map(|(n, _)| n.clone())
            .collect();
        let conns = typed
            .iter()
            .filter(|(_, ty)| {
                ["PgConnection", "ScopedRead", "ScopedTx", "Transaction<"]
                    .iter()
                    .any(|t| ty.contains(t))
            })
            .map(|(n, _)| n.clone())
            .collect();
        let (Some(brace), semi) = (find(s, b"{", params_end), find(s, b";", params_end)) else {
            continue;
        };
        if semi.is_some_and(|semi| semi < brace) {
            continue;
        }
        out.push(Handler {
            name,
            viewer,
            body: (brace, close_of(s, brace)),
            pools,
            conns,
        });
    }
    out
}

/// `let [mut] <name> [: T] = <rhs>;` bindings in `[a, b)`, as
/// `(name, is_mut, let_offset, rhs_start, rhs_end)`.
fn lets(code: &str, a: usize, b: usize) -> Vec<(String, bool, usize, usize, usize)> {
    let s = code.as_bytes();
    let mut out = Vec::new();
    for at in words(code, "let", a, b) {
        let mut j = skip_ws(s, at + 3);
        let mut is_mut = false;
        if s[j..].starts_with(b"mut") && !is_ident(s[j + 3]) {
            is_mut = true;
            j = skip_ws(s, j + 3);
        }
        let name = ident_at(s, j).to_string();
        if name.is_empty() {
            continue;
        }
        j = skip_ws(s, j + name.len());
        if j < b && s[j] == b':' {
            let mut depth = 0i32;
            while j < b {
                match s[j] {
                    b'(' | b'<' | b'[' => depth += 1,
                    b')' | b'>' | b']' => depth -= 1,
                    b'=' if depth <= 0 && s[j + 1] != b'>' => break,
                    b';' => break,
                    _ => {}
                }
                j += 1;
            }
        }
        if j >= b || s[j] != b'=' || matches!(s[j + 1], b'=' | b'>') {
            continue;
        }
        let rhs_start = j + 1;
        let (mut depth, mut k) = (0i32, rhs_start);
        while k < b {
            match s[k] {
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' => {
                    depth -= 1;
                    if depth < 0 {
                        break;
                    }
                }
                b';' if depth == 0 => break,
                _ => {}
            }
            k += 1;
        }
        out.push((name, is_mut, at, rhs_start, k));
    }
    out
}

const CONNECTION_CTORS: &[&str] = &[
    "read_as(",
    "write_as(",
    "begin_claim_write(",
    "begin_as(",
    "acquire_as(",
    "maintenance(",
    "Connection::begin(",
    ".begin()",
    ".acquire()",
];
const STATE_DB_METHODS: &[&str] = &["read_as", "write_as", "begin_claim_write"];
const TERMINALS: &[&str] = &[
    "fetch_one",
    "fetch_all",
    "fetch_optional",
    "fetch",
    "execute",
];
const KEYWORDS: &[&str] = &[
    "if", "match", "while", "for", "return", "in", "loop", "move", "async", "await", "let", "else",
];

fn has_word(hay: &str, word: &str) -> bool {
    !words(hay, word, 0, hay.len()).is_empty()
}

/// `Viewer` methods that hand on the WHOLE viewer (its predicate, its bind, or
/// a scoped copy of it). Any other method is a scalar projection.
const WHOLE_VIEWER_METHODS: &[&str] = &[
    "clone",
    "detach_scoped",
    "splice",
    "splice_write",
    "group_bind",
    "writable_bind",
    "render_predicate",
    "render_edge_predicate",
    "render_writable_predicate",
];

/// Does `region` spend the viewer `v` as a whole value: the bare identifier
/// (`&viewer`, `viewer,`, `viewer)`), or one of [`WHOLE_VIEWER_METHODS`] on it?
/// A scalar projection (`viewer.principal()`, `viewer.writable_groups()`) is
/// not a spend: a raw-pool read keyed on the caller's id filters nothing.
fn spends_viewer(region: &str, v: &str) -> bool {
    let s = region.as_bytes();
    words(region, v, 0, s.len()).into_iter().any(|p| {
        let q = skip_ws(s, p + v.len());
        if s.get(q) != Some(&b'.') {
            return true;
        }
        let m_at = skip_ws(s, q + 1);
        WHOLE_VIEWER_METHODS.contains(&ident_at(s, m_at))
    })
}

/// The path written immediately before the `(` at `open`, and where it starts.
fn callee_before(s: &[u8], open: usize) -> (String, usize) {
    let mut j = open as isize - 1;
    while j >= 0 && s[j as usize].is_ascii_whitespace() {
        j -= 1;
    }
    // A turbofish `::<..>` between the path and the call.
    if j >= 0 && s[j as usize] == b'>' {
        let mut depth = 0;
        while j >= 0 {
            match s[j as usize] {
                b'>' => depth += 1,
                b'<' => {
                    depth -= 1;
                    if depth == 0 {
                        j -= 1;
                        break;
                    }
                }
                _ => {}
            }
            j -= 1;
        }
        if j >= 1 && &s[(j - 1) as usize..=j as usize] == b"::" {
            j -= 2;
        }
    }
    let end = (j + 1) as usize;
    while j >= 0 && (is_ident(s[j as usize]) || s[j as usize] == b':') {
        j -= 1;
    }
    let start = (j + 1) as usize;
    (
        std::str::from_utf8(&s[start..end])
            .expect("ASCII path")
            .to_string(),
        start,
    )
}

/// The innermost function or method call whose argument list contains `p`,
/// skipping tuple-struct constructors (`Some(..)`, `State(..)`), keywords and
/// bare tuples. `None` when `p` sits in a block or a struct literal first.
fn enclosing_call(s: &[u8], p: usize, lo: usize) -> Option<(String, usize)> {
    let mut i = p;
    let mut depth = 0usize;
    while i > lo {
        i -= 1;
        match s[i] {
            b')' | b']' | b'}' => depth += 1,
            b'(' | b'[' | b'{' => {
                if depth > 0 {
                    depth -= 1;
                    continue;
                }
                if s[i] != b'(' {
                    return None;
                }
                let (callee, _) = callee_before(s, i);
                let last = callee.rsplit("::").next().unwrap_or("");
                let constructor = !callee.contains("::")
                    && callee
                        .as_bytes()
                        .first()
                        .is_some_and(u8::is_ascii_uppercase);
                if callee.is_empty() || KEYWORDS.contains(&last) || constructor {
                    continue;
                }
                return Some((callee, i));
            }
            _ => {}
        }
    }
    None
}

/// The first word of the first string literal in `[a, b)` of the `sql` view.
fn first_literal_word(sql: &str, a: usize, b: usize) -> Option<String> {
    let q = sql.as_bytes();
    let quote = find(q, b"\"", a).filter(|&x| x < b)?;
    let start = skip_ws(q, quote + 1);
    let word: String = q[start..]
        .iter()
        .take_while(|c| c.is_ascii_alphabetic())
        .map(|&c| c as char)
        .collect();
    (!word.is_empty()).then(|| word.to_ascii_uppercase())
}

type Lets = Vec<(String, bool, usize, usize, usize)>;

/// The RHS span of the last `let <name>` before `before`.
fn resolve_let(lets: &Lets, name: &str, before: usize) -> Option<(usize, usize)> {
    lets.iter()
        .filter(|(n, _, at, _, _)| n == name && *at < before)
        .map(|&(_, _, _, a, b)| (a, b))
        .next_back()
}

/// Is `[a, z)` one expression: no `;` outside brackets, never closing more
/// than it opened?
fn same_expression(s: &[u8], a: usize, z: usize) -> bool {
    let mut depth = 0i32;
    for &c in &s[a..z] {
        match c {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            b';' if depth == 0 => return false,
            _ => {}
        }
    }
    depth == 0
}

/// Label a `sqlx` chain ending in `terminal` (whose name starts at `term_at`),
/// and return the extra text (bindings it reads) that counts toward its spend.
fn chain_label(
    code: &str,
    sql: &str,
    body_start: usize,
    term_at: usize,
    terminal: &str,
    lets: &Lets,
) -> (String, String) {
    let s = code.as_bytes();
    let mut extra = String::new();
    let mut head = None;
    if let Some(cand) = code[body_start..term_at]
        .rfind("sqlx")
        .map(|p| body_start + p)
    {
        if !words(code, "sqlx", cand, cand + 1).is_empty() && same_expression(s, cand, term_at) {
            head = Some(cand);
        }
    }
    if head.is_none() {
        // `<receiver>.fetch_one(..)`: resolve the receiver's binding.
        let mut k = term_at - 1;
        while s[k].is_ascii_whitespace() {
            k -= 1;
        }
        if s[k] == b'.' {
            let mut j = k - 1;
            while s[j].is_ascii_whitespace() {
                j -= 1;
            }
            let end = j + 1;
            while is_ident(s[j]) {
                j -= 1;
            }
            let receiver = &code[j + 1..end];
            if let Some((a, b)) = resolve_let(lets, receiver, j) {
                extra.push_str(&code[a..b]);
                if let Some(p) = code[a..b].find("sqlx") {
                    head = Some(a + p);
                }
            }
        }
    }
    let Some(head) = head else {
        return (format!("?.{terminal}"), extra);
    };
    let mut op = skip_ws(s, head + 4);
    op = skip_ws(s, op + 2); // `::`
    let fun = ident_at(s, op).to_string();
    op = skip_ws(s, op + fun.len());
    if s[op..].starts_with(b"::") {
        op = skip_ws(s, op + 2);
        if s[op] == b'<' {
            op = skip_ws(s, close_of(s, op) + 1);
        }
    }
    if s[op] != b'(' {
        return (format!("sqlx::{fun}(?).{terminal}"), extra);
    }
    let close = close_of(s, op);
    let mut verb = first_literal_word(sql, op, close);
    if verb.is_none() {
        let arg = code[op + 1..close].trim().trim_start_matches('&').trim();
        if !arg.is_empty() && arg.bytes().all(is_ident) {
            if let Some((a, b)) = resolve_let(lets, arg, op) {
                extra.push_str(&code[a..b]);
                verb = first_literal_word(sql, a, b);
            }
        }
    }
    (
        format!(
            "sqlx::{fun}({}).{terminal}",
            verb.as_deref().unwrap_or("dynamic")
        ),
        extra,
    )
}

/// Every database call in `h`'s body as `(label, viewed)`, except calls inside
/// the `nested` spans (the bodies of viewer-holding fns declared inside this
/// one, which are measured on their own).
fn db_calls(code: &str, sql: &str, h: &Handler, nested: &[(usize, usize)]) -> Vec<(String, bool)> {
    let s = code.as_bytes();
    let (b, e) = h.body;
    let bindings: Lets = lets(code, b, e)
        .into_iter()
        .filter(|(_, _, at, _, _)| !nested.iter().any(|&(x, y)| x <= *at && *at <= y))
        .collect();
    let mut pool_aliases: Vec<String> = h.pools.clone();
    let mut conns: Vec<String> = h.conns.clone();
    let mut repos: Vec<(String, String)> = Vec::new();
    for (name, is_mut, _, ra, rb) in &bindings {
        let rhs = &code[*ra..*rb];
        let flat: String = rhs.chars().filter(|c| !c.is_whitespace()).collect();
        let names_pool = has_word(rhs, "state") || pool_aliases.iter().any(|a| has_word(rhs, a));
        if matches!(
            flat.as_str(),
            "&state.db_pool" | "state.db_pool" | "state.db_pool.clone()" | "&state.db_pool.clone()"
        ) {
            pool_aliases.push(name.clone());
            continue;
        }
        if let Some(new_at) = flat.find("::new(") {
            let path = &flat[..new_at];
            if !path.is_empty() && path.bytes().all(|c| is_ident(c) || c == b':') && names_pool {
                let ty = path.rsplit("::").next().unwrap_or(path).to_string();
                repos.push((name.clone(), ty));
                continue;
            }
        }
        if *is_mut
            && (CONNECTION_CTORS.iter().any(|c| flat.contains(c))
                || flat.contains("&mut*")
                || names_pool
                || conns.iter().any(|c| has_word(rhs, c)))
        {
            conns.push(name.clone());
        }
    }

    // open-paren offset -> (label, is a plain call whose label needs resolving)
    let mut calls: BTreeMap<usize, (String, bool)> = BTreeMap::new();
    let enclose = |calls: &mut BTreeMap<usize, (String, bool)>, p: usize| {
        if let Some((callee, open)) = enclosing_call(s, p, b) {
            calls.entry(open).or_insert((callee, true));
        }
    };
    // `.<method>(` right after offset `q`: `Some((method, open_paren))`.
    let method_after = |q: usize| -> Option<(String, usize)> {
        let q = skip_ws(s, q);
        if s.get(q) != Some(&b'.') {
            return None;
        }
        let m_at = skip_ws(s, q + 1);
        let m = ident_at(s, m_at).to_string();
        let open = skip_ws(s, m_at + m.len());
        (s.get(open) == Some(&b'(')).then_some((m, open))
    };

    for p in words(code, "state", b, e) {
        let q = skip_ws(s, p + 5);
        if s[q] == b'.' {
            let f_at = skip_ws(s, q + 1);
            let field = ident_at(s, f_at).to_string();
            let after = skip_ws(s, f_at + field.len());
            if field == "db_pool" {
                match method_after(after) {
                    Some((m, open)) if m != "clone" => {
                        calls.entry(open).or_insert((format!("db_pool.{m}"), false));
                    }
                    _ => enclose(&mut calls, p),
                }
            } else if field == "clone" {
                // `state.clone()` handed to a helper.
                enclose(&mut calls, p);
            } else if s[after] == b'(' && STATE_DB_METHODS.contains(&field.as_str()) {
                calls
                    .entry(after)
                    .or_insert((format!("state.{field}"), false));
            }
            continue;
        }
        enclose(&mut calls, p);
    }
    for alias in &pool_aliases {
        for p in words(code, alias, b, e) {
            // The binding itself (`let pool = ..` / `let mut pool = ..`).
            if bindings
                .iter()
                .any(|(n, _, at, _, _)| n == alias && *at < p && p < *at + 12)
            {
                continue;
            }
            match method_after(p + alias.len()) {
                Some((m, open)) if m != "clone" => {
                    calls.entry(open).or_insert((format!("db_pool.{m}"), false));
                }
                _ => enclose(&mut calls, p),
            }
        }
    }
    for p in words(code, "mut", b, e) {
        let mut k = p - 1;
        while k > b && s[k].is_ascii_whitespace() {
            k -= 1;
        }
        if s[k] != b'&' {
            continue;
        }
        let q = skip_ws(s, p + 3);
        if s[q] == b'*' || conns.iter().any(|c| c == ident_at(s, q)) {
            enclose(&mut calls, p);
        }
    }
    for (alias, ty) in &repos {
        for p in words(code, alias, b, e) {
            if let Some((m, open)) = method_after(p + alias.len()) {
                calls.entry(open).or_insert((format!("{ty}::{m}"), false));
            }
        }
    }
    // A connection parameter handed on as it is (`Repo::get(conn, id)`).
    for conn in &h.conns {
        for p in words(code, conn, b, e) {
            enclose(&mut calls, p);
        }
    }
    calls.retain(|&open, _| !nested.iter().any(|&(x, y)| x <= open && open <= y));

    let mut out = Vec::new();
    for (&open, (callee, plain)) in &calls {
        let close = close_of(s, open);
        let mut region = code[open..=close].to_string();
        let last = callee.rsplit("::").next().unwrap_or(callee);
        let label = if *plain && TERMINALS.contains(&last) {
            let (_, term_at) = callee_before(s, open);
            let (label, extra) = chain_label(code, sql, b, term_at, last, &bindings);
            let chain_start = code[b..term_at]
                .rfind("sqlx")
                .map(|x| b + x)
                .filter(|&x| same_expression(s, x, term_at))
                .unwrap_or(term_at);
            region = format!("{extra}{}", &code[chain_start..=close]);
            label
        } else if *plain {
            let parts: Vec<&str> = callee.split("::").collect();
            parts[parts.len().saturating_sub(2)..].join("::")
        } else {
            callee.clone()
        };
        out.push((label, spends_viewer(&region, &h.viewer)));
    }
    out
}

/// `(file, handler) -> sorted unviewed labels`, for every handler with any,
/// plus the population size `(handlers, calls)`.
type Measured = BTreeMap<(String, String), Vec<String>>;

/// Every viewer-holding fn measured, as `(file, fn)`.
type Population = std::collections::BTreeSet<(String, String)>;

fn measure_source(
    file: &str,
    src: &str,
    out: &mut Measured,
    pop: &mut Population,
) -> (usize, usize) {
    let (code, sql) = views(src);
    let hs = handlers(&code, &sql);
    let mut n_calls = 0;
    for h in &hs {
        pop.insert((file.to_string(), h.name.clone()));
        let nested: Vec<(usize, usize)> = hs
            .iter()
            .map(|o| o.body)
            .filter(|&(x, y)| h.body.0 < x && y < h.body.1)
            .collect();
        let calls = db_calls(&code, &sql, h, &nested);
        n_calls += calls.len();
        let mut unviewed: Vec<String> = calls
            .into_iter()
            .filter(|(_, viewed)| !viewed)
            .map(|(l, _)| l)
            .collect();
        if !unviewed.is_empty() {
            let entry = out.entry((file.to_string(), h.name.clone())).or_default();
            entry.append(&mut unviewed);
            entry.sort();
        }
    }
    (hs.len(), n_calls)
}

fn measure_tree() -> (Measured, usize, usize, Population) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/routes");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .expect("read routes dir")
        .map(|e| e.expect("dir entry").path())
        .collect();
    files.sort();
    let mut out = Measured::new();
    let mut pop = Population::new();
    let (mut n_handlers, mut n_calls, mut n_files) = (0, 0, 0);
    for path in files {
        if path.is_dir() {
            let nested_rs = std::fs::read_dir(&path).expect("read nested dir").any(|e| {
                e.expect("entry")
                    .path()
                    .extension()
                    .is_some_and(|x| x == "rs")
            });
            assert!(
                !nested_rs,
                "{} holds Rust sources this lint does not walk; extend measure_tree",
                path.display()
            );
            continue;
        }
        if path.extension().and_then(|x| x.to_str()) != Some("rs") {
            continue;
        }
        n_files += 1;
        let name = path.file_name().and_then(|n| n.to_str()).expect("utf-8");
        let src = std::fs::read_to_string(&path).expect("read route file");
        let (h, c) = measure_source(name, &src, &mut out, &mut pop);
        n_handlers += h;
        n_calls += c;
    }
    assert!(
        n_files > 40,
        "found {n_files} route files; wrong directory?"
    );
    (out, n_handlers, n_calls, pop)
}

fn reviewed() -> Measured {
    let mut out = Measured::new();
    for (file, handler, labels) in REVIEWED {
        let mut v: Vec<String> = labels.iter().map(|l| (*l).to_string()).collect();
        v.sort();
        let prev = out.insert(((*file).to_string(), (*handler).to_string()), v);
        assert!(prev.is_none(), "REVIEWED lists {file}::{handler} twice");
    }
    out
}

fn multiset_diff(a: &[String], b: &[String]) -> Vec<String> {
    let mut rest = b.to_vec();
    let mut out = Vec::new();
    for x in a {
        if let Some(i) = rest.iter().position(|y| y == x) {
            rest.remove(i);
        } else {
            out.push(x.clone());
        }
    }
    out
}

#[test]
fn every_unviewed_database_call_in_a_viewer_handler_is_reviewed() {
    let (measured, _, _, _) = measure_tree();
    let want = reviewed();
    let mut report = String::new();
    let keys: std::collections::BTreeSet<_> = measured.keys().chain(want.keys()).collect();
    for key in keys {
        let got = measured.get(key).cloned().unwrap_or_default();
        let exp = want.get(key).cloned().unwrap_or_default();
        let new = multiset_diff(&got, &exp);
        let gone = multiset_diff(&exp, &got);
        if !new.is_empty() || !gone.is_empty() {
            report.push_str(&format!(
                "  {}::{}\n    NEW (unreviewed, no viewer in its arguments): {new:?}\n    \
                 GONE (lower REVIEWED): {gone:?}\n    measured: {got:?}\n",
                key.0, key.1
            ));
        }
    }
    assert!(
        report.is_empty(),
        "viewer-holding handlers' unviewed database calls drifted from REVIEWED.\n\
         A NEW call is a read or write that does not receive the handler's viewer: \
         give it the viewer, or read it and register it with a reason. A GONE call \
         must be removed from REVIEWED.\n{report}"
    );
}

/// The population is the whole viewer-holding surface, not a corner of it. A
/// scanner that silently stopped recognising handlers or calls would pass the
/// exact-set test above with an empty register.
#[test]
fn the_scanner_sees_the_whole_viewer_surface() {
    let (measured, handlers, calls, pop) = measure_tree();
    eprintln!(
        "population: {handlers} viewer-holding fns, {calls} database calls, {} with an \
         unviewed call, {} unviewed calls",
        measured.len(),
        measured.values().map(Vec::len).sum::<usize>()
    );
    // Route helpers a handler delegates its viewer to, including one nested in
    // a handler (edges.rs) and one whose viewer is not called `viewer`.
    for (file, helper) in [
        ("claims.rs", "create_claim_core"),
        ("crud.rs", "require_readable_claim"),
        ("edges.rs", "build_evidence_chains"),
        ("edges.rs", "evidence_by_relationship"),
        ("graph_query_utils.rs", "load_subgraph_conn"),
        ("lineage.rs", "get_ancestor_lineage"),
        ("privatization.rs", "resolve_seeds"),
        ("submit.rs", "persist_packet"),
    ] {
        assert!(
            pop.contains(&(file.to_string(), helper.to_string())),
            "{file}::{helper} takes a `&Viewer` and must be in the measured population"
        );
    }
    assert!(
        handlers >= 160,
        "found {handlers} viewer-holding fns (handlers and route helpers); measured 176 \
         on 2026-10-26, 192 on 2026-10-29"
    );
    assert!(
        calls >= 700,
        "found {calls} database calls in them; measured 768 on 2026-10-26, 827 on 2026-10-29"
    );
    assert!(
        measured.len() >= 80,
        "found {} viewer-holding fns with an unviewed call; measured 102 on 2026-10-26, 116 on \
         2026-10-29",
        measured.len()
    );
}

fn unviewed_in(src: &str) -> Measured {
    let mut out = Measured::new();
    measure_source("fixture.rs", src, &mut out, &mut Population::new());
    out
}

fn labels(m: &Measured, handler: &str) -> Vec<String> {
    m.get(&("fixture.rs".to_string(), handler.to_string()))
        .cloned()
        .unwrap_or_default()
}

/// The shapes this lint exists for, and the ones it must not be fooled by.
#[test]
fn the_scanner_distinguishes_the_spend_from_a_side_read() {
    let src = r##"
pub async fn b1_shape(
    ViewerExtractor(viewer): ViewerExtractor,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> R {
    // The viewer is spent on a scalar ...
    let n = ClaimRepository::count_visible(&state.db_pool, &viewer).await?;
    // ... and the content comes from the raw pool.
    let row: (String,) = sqlx::query_as("SELECT content FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(&state.db_pool)
        .await?;
    Ok(row)
}

pub async fn fixed_shape(
    ViewerExtractor(viewer): ViewerExtractor,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> R {
    let mut read = state.read_as(&viewer).await?;
    let row = ClaimRepository::content_and_properties(&mut *read, &viewer, id).await?;
    let sql = viewer.splice("SELECT c.id FROM claims c WHERE c.id = $1 /* {VISIBILITY:c} */", 2);
    let mut q = sqlx::query_scalar::<_, Uuid>(&sql).bind(id);
    if let Some(g) = viewer.group_bind() {
        q = q.bind(g);
    }
    let _ = q.fetch_optional(&mut *read).await?;
    Ok(row)
}

pub async fn aliases(
    ViewerExtractor(viewer): ViewerExtractor,
    State(state): State<AppState>,
) -> R {
    let pool = &state.db_pool;
    let a = MethodRepository::get(pool, id).await?;
    let repo = epigraph_db::MatchCandidateRepo::new(state.db_pool.clone());
    let b = repo.list(10).await?;
    let c = helper(&state, id).await?;
    let mut tx = pool.begin().await?;
    let d = sqlx::query("UPDATE claims SET x = 1").execute(&mut *tx).await?;
    Ok((a, b, c, d))
}

pub async fn decoys(
    ViewerExtractor(viewer): ViewerExtractor,
    State(state): State<AppState>,
) -> R {
    let a = Repo::get(&state.db_pool, /* &viewer, */ id).await?;
    let b = Repo::get(&state.db_pool, id).await?; // &viewer
    let c = Repo::log(&state.db_pool, "viewer").await?;
    Ok((a, b, c))
}

pub async fn scalar_projection(
    ViewerExtractor(viewer): ViewerExtractor,
    State(state): State<AppState>,
) -> R {
    // The caller's id is not a predicate: this read filters nothing.
    let a = Repo::get(&state.db_pool, viewer.principal()).await?;
    let b = Repo::in_groups(&state.db_pool, viewer
        .writable_groups()).await?;
    // A scoped copy, a clone and the bind still carry the whole viewer.
    let c = Repo::get_as(&state.db_pool, &viewer.clone()).await?;
    let d = Repo::get_as(&state.db_pool, viewer.detach_scoped()).await?;
    let e = Repo::get_in(&state.db_pool, viewer
        .group_bind()).await?;
    Ok((a, b, c, d, e))
}

pub async fn other_name(
    ViewerExtractor(status_viewer): ViewerExtractor,
    State(state): State<AppState>,
) -> R {
    let viewer = 1;
    Repo::get(&state.db_pool, viewer).await
}

#[cfg(not(feature = "db"))]
pub async fn b1_shape(ViewerExtractor(viewer): ViewerExtractor, State(state): State<AppState>) -> R {
    Repo::get(&state.db_pool).await
}

#[cfg(test)]
mod tests {
    async fn in_tests(ViewerExtractor(viewer): ViewerExtractor, State(state): State<AppState>) {
        Repo::get(&state.db_pool).await
    }
}
"##;
    let m = unviewed_in(src);
    assert_eq!(
        labels(&m, "b1_shape"),
        vec!["sqlx::query_as(SELECT).fetch_one".to_string()],
        "the B1 shape: the raw-pool content read is the one unviewed call (and the \
         cfg(not(db)) stub arm adds nothing)"
    );
    assert!(
        labels(&m, "fixed_shape").is_empty(),
        "every call in the fixed shape receives the viewer, through its arguments or \
         through the spliced SQL binding it reads: {:?}",
        labels(&m, "fixed_shape")
    );
    assert_eq!(
        labels(&m, "aliases"),
        vec![
            "MatchCandidateRepo::list",
            "MatchCandidateRepo::new",
            "MethodRepository::get",
            "db_pool.begin",
            "helper",
            "sqlx::query(UPDATE).execute",
        ],
        "a pool alias, a repo object, a helper handed AppState, a raw transaction and a \
         statement on it are all database calls"
    );
    assert_eq!(
        labels(&m, "decoys"),
        vec!["Repo::get", "Repo::get", "Repo::log"],
        "a viewer named in a comment or a string is not a spend"
    );
    assert_eq!(
        labels(&m, "scalar_projection"),
        vec!["Repo::get", "Repo::in_groups"],
        "a scalar projection of the viewer (its principal, its writable groups) is not \
         a spend; a clone, a scoped copy or its group bind is"
    );
    assert_eq!(
        labels(&m, "other_name"),
        vec!["Repo::get"],
        "the spend is of the handler's OWN viewer variable, not of any `viewer` word"
    );
    assert!(
        !m.contains_key(&("fixture.rs".to_string(), "in_tests".to_string())),
        "a #[cfg(test)] item is not a handler"
    );
}

/// A route helper a handler hands its viewer to is measured on its own: its pool, connection and `AppState`
/// parameters are database handles, its own `&Viewer` parameter (whatever it
/// is called) is the viewer, and a helper declared inside a handler is
/// measured once, as itself.
#[test]
fn the_scanner_measures_route_helpers() {
    let src = r##"
async fn state_helper(state: &AppState, viewer: &epigraph_db::Viewer, id: Uuid) -> R {
    let ok = Repo::get_as(&state.db_pool, viewer, id).await?;
    let raw = Repo::is_member(&state.db_pool, id).await?;
    Ok((ok, raw))
}

async fn pool_helper(
    pool: &sqlx::PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    id: Uuid,
) -> R {
    let ok = Repo::get_as(pool, viewer, id).await?;
    let raw = Repo::get(pool, id).await?;
    let mut tx = pool.begin().await?;
    Ok((ok, raw))
}

async fn conn_helper(conn: &mut sqlx::PgConnection, bypass: &Viewer, id: Uuid) -> R {
    let a = Repo::get(conn, id).await?;
    let b = sqlx::query_as("SELECT 1").bind(id).fetch_one(&mut *conn).await?;
    let c = Repo::get_as(&mut *conn, bypass, id).await?;
    Ok((a, b, c))
}

pub async fn outer(
    ViewerExtractor(viewer): ViewerExtractor,
    State(state): State<AppState>,
) -> R {
    async fn inner(conn: &mut sqlx::PgConnection, viewer: &Viewer) -> R {
        Repo::list(conn).await
    }
    let mut read = state.read_as(&viewer).await?;
    inner(&mut *read, &viewer).await
}

async fn not_a_viewer(pool: &PgPool, viewers: &[Viewer], f: impl Fn(u8) -> u8) -> R {
    Repo::get(pool).await
}
"##;
    let m = unviewed_in(src);
    assert_eq!(
        labels(&m, "state_helper"),
        vec!["Repo::is_member"],
        "a helper handed the viewer and AppState: its raw-pool read is reported"
    );
    assert_eq!(
        labels(&m, "pool_helper"),
        vec!["Repo::get", "db_pool.begin"],
        "a helper's `&PgPool` parameter is the pool"
    );
    assert_eq!(
        labels(&m, "conn_helper"),
        vec!["Repo::get", "sqlx::query_as(SELECT).fetch_one"],
        "a helper's connection parameter, passed bare or dereferenced, is a connection, \
         and its `&Viewer` parameter is the viewer whatever its name"
    );
    assert!(
        labels(&m, "outer").is_empty(),
        "the nested helper's calls are not the outer handler's: {:?}",
        labels(&m, "outer")
    );
    assert_eq!(
        labels(&m, "inner"),
        vec!["Repo::list"],
        "a helper nested in a handler is measured as itself"
    );
    assert!(
        !m.contains_key(&("fixture.rs".to_string(), "not_a_viewer".to_string())),
        "a slice of viewers is not a viewer parameter"
    );
}

/// A stamped connection is NOT a spend (see the module doc): a read on
/// `read_as(&viewer)` that does not pass the viewer is measured unviewed, while
/// the `let` binding that names the viewer DOES count for a `sqlx` chain that
/// reads it (the spliced SQL). The two rules sit side by side, so both are
/// pinned in one fixture.
#[test]
fn the_scanner_does_not_count_a_stamped_connection_as_a_spend() {
    let src = r##"
pub async fn stamped(
    ViewerExtractor(viewer): ViewerExtractor,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> R {
    // Row security on the stamped connection, and no in-query predicate.
    let mut read = state.read_as(&viewer).await?;
    let row = Repo::get(&mut *read, id).await?;
    let raw = sqlx::query_scalar::<_, Uuid>("SELECT id FROM claims WHERE id = $1")
        .bind(id)
        .fetch_optional(&mut *read)
        .await?;
    // The spliced statement on the same connection IS a spend.
    let sql = viewer.splice("SELECT c.id FROM claims c WHERE c.id = $1 /* {VISIBILITY:c} */", 2);
    let spliced = sqlx::query_scalar::<_, Uuid>(&sql).bind(id).fetch_optional(&mut *read).await?;
    Ok((row, raw, spliced))
}
"##;
    let m = unviewed_in(src);
    assert_eq!(
        labels(&m, "stamped"),
        vec!["Repo::get", "sqlx::query_scalar(SELECT).fetch_optional"],
        "reads on a connection stamped with the viewer are measured unviewed unless \
         the viewer reaches the statement; stamping is row security only"
    );
}
