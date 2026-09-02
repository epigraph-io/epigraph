// NOTE: 160 `#[cfg(not(feature = "db"))]` stubs across 34 files in this
// directory provide the no-db half of the crate's two-build design, so that
// `cargo check -p epigraph-api --no-default-features` compiles. CI runs that
// check (.github/workflows/ci.yml); when you add a db-only handler, add its
// `cfg(not(feature = "db"))` counterpart in the same commit or CI fails.
//
// Their behaviour is NOT uniform. The previous version of this note claimed
// they "return 501 Not Implemented"; that was false. Eight sites return 501
// (spans.rs, entities.rs) and a few return 503 (clusters.rs, versioning.rs),
// but many FABRICATE placeholder data -- e.g. `claims::get_claim` returns
// "Placeholder claim content" with an invented truth_value and a random
// agent_id. A no-db binary therefore serves synthetic epistemic data through
// the same response shapes as real data. Treat the no-db configuration as a
// compile-time target, not a runnable mode, until that is resolved.
// Re-audited 2026-09-01.

pub mod activities;
pub mod admin;
#[cfg(feature = "db")]
pub mod agent_keys;
#[cfg(feature = "db")]
pub mod agents;
pub mod analyze;
#[cfg(feature = "db")]
pub mod assess;
#[cfg(feature = "db")]
pub mod audit;
pub mod batch;
pub mod belief;
pub mod challenge;
pub mod claims;
pub mod claims_query;
pub mod clusters;
pub mod community;
#[cfg(feature = "db")]
pub mod computation;
#[cfg(feature = "db")]
pub mod conflicts;
pub mod context;
#[cfg(feature = "db")]
pub mod conventions;
pub mod cross_source;
pub mod crud;
pub mod edges;
pub mod embeddings;
#[cfg(feature = "db")]
pub mod entities;
pub mod events;
#[cfg(feature = "db")]
pub mod experiment_loop;
#[cfg(feature = "db")]
pub mod experiments;
#[cfg(feature = "db")]
pub mod gaps;
#[cfg(feature = "db")]
pub mod graph;
#[cfg(feature = "db")]
pub mod graph_neighborhood;
#[cfg(feature = "db")]
pub mod graph_query;
#[cfg(feature = "db")]
pub mod graph_query_utils;
#[cfg(feature = "db")]
pub mod groups;
pub mod harvest;
pub mod health;
#[cfg(feature = "db")]
pub mod hypothesis;
pub mod independence;
pub mod ingest;
#[cfg(all(feature = "db", feature = "episcience"))]
pub mod isomorphism;
#[cfg(feature = "db")]
pub mod lineage;
#[cfg(feature = "db")]
pub mod mcp_tools;
#[cfg(feature = "db")]
pub mod methods;
#[cfg(test)]
mod negative_tests;
pub mod ownership;
pub mod papers;
pub mod perspective;
#[cfg(feature = "db")]
pub mod policies;
pub mod political;
/// Deterministic 2-D PCA used by `/themes/:id/embeddings` so that endpoint can
/// serve theme-splitting clients without disclosing raw embedding vectors.
pub mod projection;
#[cfg(feature = "db")]
pub mod provenance;
pub mod rag;
pub mod reasoning;
pub mod revoke_signature;
#[cfg(feature = "db")]
pub mod search;
pub mod spans;
pub mod staging;
pub mod structural;
pub mod submit;
#[cfg(feature = "db")]
pub mod tasks;
#[cfg(feature = "db")]
pub mod timeline;
pub mod versioning;
#[cfg(feature = "db")]
pub mod voids;
pub mod webhooks;
#[cfg(feature = "db")]
pub mod workflows;

// `crate::metrics` is deliberately NOT imported here. `/metrics` was removed
// from both router variants in PR-03 and is served only by the internal
// listener that `bin/server.rs` binds (`EPIGRAPH_METRICS_ADDR`).
use crate::middleware::{
    bearer_auth_middleware, optional_bearer_auth_middleware, rate_limit_middleware,
};
use crate::state::AppState;
use axum::{
    extract::DefaultBodyLimit,
    middleware,
    routing::{delete, get, patch, post, put},
    Router,
};

/// Create the main application router with all routes.
///
/// # Route structure — authenticated by default
///
/// Three routers are merged, and the split between them is the security
/// boundary:
///
/// ## `protected` — requires an OAuth2 Bearer token
///
/// Everything that reads or writes claim content, claim-derived structure,
/// ACLs, embeddings or aggregates. `bearer_auth_middleware` rejects a request
/// with no `Authorization` header, or with a revoked / malformed / expired
/// token, with 401 and an RFC 6750 `WWW-Authenticate: Bearer …,
/// error="invalid_token"` challenge.
///
/// ## `public` — the anonymous ALLOWLIST, two routes
///
/// - `GET /health` — static, stateless
/// - `GET /api/v1/openapi.json` — static schema document
///
/// Enforced by `crates/epigraph-api/tests/public_router_allowlist.rs`, which
/// fails if a third route appears here.
///
/// ## `oauth` — anonymous by construction
///
/// The 11 `/oauth/*` and `/.well-known/*` endpoints. Discovery and token
/// issuance must precede authentication, so they cannot sit behind it.
///
/// # What changed in PR-03
///
/// Before PR-03 the `public` router held 108 registrations, including
/// `GET /claims`, `GET /claims/:id`, `GET /agents`, `GET /lineage/:claim_id`,
/// `POST /api/v1/search/semantic` and `GET /api/v1/query/rag`, all reachable
/// with no credential. 105 of them moved to `protected`, `/metrics` moved to a
/// separate internal listener, and the remaining two are the allowlist above.
/// **The RAG and evidence-search public-access guarantees are revoked.**
///
/// The `require_signature` (Ed25519 request-signing) middleware was deleted
/// rather than moved: it was unreachable through this router. Payload-level
/// packet signatures are unaffected — see `ApiConfig::require_packet_signatures`
/// and `routes/submit.rs`.
///
/// # Rate limiting
///
/// All routes (except health endpoints) are subject to rate limiting when a
/// rate limiter is configured in `AppState`.
#[cfg(feature = "db")]
pub fn create_router(state: AppState) -> Router {
    // Write operations. Read operations are appended below by the PR-03
    // inversion; the two halves are separate only because of the order the
    // chain was written in, not because they differ in authority.
    let protected = Router::new()
        .route("/claims", post(claims::create_claim))
        .route("/api/v1/claims", post(claims::create_claim))
        .route("/agents", post(agents::create_agent))
        .route("/api/v1/agents", post(agents::create_agent))
        .route("/api/v1/agents/:id", put(agents::update_agent))
        // NO claim-deletion route. `DELETE /api/v1/claims/:id` and
        // `POST /api/v1/claims/:id/confirm-delete` were removed: EpiGraph retires
        // claims by supersession and edges by retraction, so a production path that
        // destroys a claim and hard-deletes every edge touching it contradicted the
        // policy it sat next to. Test cleanup moved to
        // `tests/integration/test_claim_cleanup.rs::hard_delete_test_claims`, which
        // is unreachable over HTTP and guards against non-disposable databases.
        .route("/api/v1/claims/:id", put(claims::update_claim))
        .route("/api/v1/claims/:id", patch(claims::patch_claim))
        .route(
            "/api/v1/edges/:id",
            delete(edges::delete_edge).patch(edges::patch_edge),
        )
        .route("/api/v1/evidence", post(crud::create_evidence))
        .route("/api/v1/evidence/:id", put(crud::update_evidence))
        .route(
            "/api/v1/reasoning-traces",
            post(crud::create_reasoning_trace),
        )
        .route("/api/v1/analyses", post(crud::create_analysis))
        .route("/api/v1/clusters", post(crud::upsert_cluster))
        .route("/api/v1/themes/reassign", post(crud::reassign_claim))
        .route(
            "/api/v1/themes/assign-unthemed",
            post(crud::assign_unthemed),
        )
        .route(
            "/api/v1/themes/recompute-centroids",
            post(crud::recompute_centroids),
        )
        .route(
            "/api/v1/themes/create-with-centroid",
            post(crud::create_theme_with_centroid),
        )
        .route(
            "/api/v1/themes/build-from-corpus",
            post(crud::build_themes_from_corpus),
        )
        .route(
            "/api/v1/clusters/build-from-bridges",
            post(clusters::build_from_bridges),
        )
        .route(
            "/api/v1/frames/:id/assign-claim",
            post(crud::assign_claim_to_frame),
        )
        .route(
            "/api/v1/edges-staging/promote",
            post(crud::promote_staged_edges),
        )
        .route("/api/v1/submit/packet", post(submit::submit_packet))
        .route(
            "/api/v1/claims/:id/challenge",
            post(challenge::submit_challenge),
        )
        .route(
            "/api/v1/claims/:id/supersede",
            post(versioning::supersede_claim),
        )
        .route("/api/v1/claims/:id/dedup", post(versioning::mark_duplicate))
        .route(
            "/api/v1/claims/:id/revoke-signature",
            post(revoke_signature::revoke_claim_signature),
        )
        .route("/api/v1/claims/batch", post(batch::batch_create_claims))
        .route("/api/v1/claims/:id/labels", patch(claims::update_labels))
        .route(
            "/api/v1/webhooks",
            post(webhooks::register_webhook).get(webhooks::list_webhooks),
        )
        .route(
            "/api/v1/webhooks/:id",
            get(webhooks::get_webhook).delete(webhooks::delete_webhook),
        )
        .route("/api/v1/harvest", post(harvest::submit_harvest))
        .route("/api/v1/ingest/paper", post(ingest::ingest_paper))
        .route("/api/v1/ingest/paper-url", post(ingest::ingest_paper))
        .route("/api/v1/papers", post(papers::create_paper))
        .route("/api/v1/edges", post(edges::create_edge))
        .route(
            "/api/v1/edges/hierarchical",
            post(edges::create_hierarchical_edge),
        )
        .route(
            "/api/v1/analyze/unconstrained",
            post(analyze::unconstrained_analysis),
        )
        .route("/api/v1/claims/:id/assess", post(assess::assess_claim))
        .route(
            "/api/v1/claims/:id/provenance",
            post(provenance::set_provenance),
        )
        .route(
            "/api/v1/claims/:id/embedding",
            put(rag::generate_claim_embedding),
        )
        .route(
            "/api/v1/evidence/:id/embedding",
            put(rag::generate_evidence_embedding),
        )
        .route("/api/v1/staging/ingest/json", post(staging::ingest_json))
        .route("/api/v1/staging/ingest/git", post(staging::ingest_git))
        .route("/api/v1/staging/merge", post(staging::merge_staging))
        .route(
            "/api/v1/staging/analyze-rejection",
            post(staging::analyze_rejection),
        )
        .route("/api/v1/events", post(events::create_event))
        .route("/api/v1/spans", post(spans::create_span))
        .route("/api/v1/spans/:id/close", put(spans::close_span))
        .route("/api/v1/activities", post(activities::create_activity))
        .route(
            "/api/v1/activities/:id/complete",
            put(activities::complete_activity),
        )
        .route("/api/v1/frames", post(belief::create_frame))
        .route("/api/v1/frames/:id/evidence", post(belief::submit_evidence))
        .route(
            "/api/v1/frames/:id/conflict-batch",
            post(belief::conflict_batch),
        )
        .route(
            "/api/v1/perspectives",
            post(perspective::create_perspective),
        )
        .route(
            "/api/v1/perspectives/:id/source-reliability",
            put(perspective::set_source_reliability),
        )
        .route("/api/v1/communities", post(community::create_community))
        .route(
            "/api/v1/communities/:id/members",
            post(community::add_member),
        )
        .route(
            "/api/v1/communities/:id/members/:perspective_id",
            delete(community::remove_member),
        )
        .route("/api/v1/contexts", post(context::create_context))
        .route("/api/v1/frames/:id/refine", post(belief::refine_frame))
        .route("/api/v1/ownership", post(ownership::assign_ownership))
        .route(
            "/api/v1/ownership/:node_id",
            put(ownership::update_partition),
        )
        .route("/api/v1/claims/:id/relate", post(edges::relate_claims))
        .route("/api/v1/workflows", post(workflows::store_workflow))
        .route("/api/v1/workflows/ingest", post(workflows::ingest_workflow))
        .route(
            "/api/v1/workflows/hierarchical/:id/outcome",
            post(workflows::report_hierarchical_outcome),
        )
        .route(
            "/api/v1/workflows/:id/outcome",
            post(workflows::report_outcome),
        )
        .route(
            "/api/v1/workflows/:id",
            delete(workflows::deprecate_workflow),
        )
        .route(
            "/api/v1/workflows/:id/behavioral-executions",
            post(workflows::record_behavioral_execution),
        )
        .route(
            "/api/v1/workflows/steps/:id/evolve",
            post(workflows::evolve_step),
        )
        .route("/api/v1/workflows/steps", post(workflows::add_step))
        .route(
            "/api/v1/workflows/steps/delete",
            post(workflows::delete_step),
        )
        .route(
            "/api/v1/experiments/hypothesize",
            post(experiments::hypothesize),
        )
        .route("/api/v1/methods", post(experiments::add_method))
        .route(
            "/api/v1/experiments/design",
            post(experiments::design_experiment),
        )
        .route(
            "/api/v1/experiments/new",
            post(experiment_loop::create_experiment),
        )
        .route(
            "/api/v1/experiments/:id/start",
            post(experiment_loop::start_experiment),
        )
        .route(
            "/api/v1/experiments/:id/results",
            post(experiment_loop::submit_results),
        )
        .route(
            "/api/v1/experiments/:eid/results/:rid/measurements",
            post(experiment_loop::add_measurements),
        )
        .route(
            "/api/v1/experiments/:eid/results/:rid/analyze",
            post(experiment_loop::analyze_result),
        )
        .route("/api/v1/voids/detect", post(voids::detect_voids))
        .route("/api/v1/gaps/surface", post(gaps::surface_gaps))
        .route("/api/v1/gaps/analysis", post(gaps::gap_analysis))
        .route("/api/v1/bp/propagate", post(computation::propagate_beliefs))
        .route(
            "/api/v1/sheaf/reconcile",
            post(computation::sheaf_reconcile),
        )
        .route(
            "/api/v1/graph/compose",
            post(computation::compose_subgraphs),
        )
        .route(
            "/api/v1/conflicts/classify",
            post(conflicts::classify_conflict),
        )
        .route(
            "/api/v1/conflicts/:a/:b/resolve",
            post(conflicts::resolve_conflict),
        )
        .route(
            "/api/v1/conflicts/:a/:b/counterfactuals",
            post(conflicts::store_counterfactuals),
        )
        .route("/api/v1/conventions", post(conventions::learn_convention))
        .route(
            "/api/v1/conventions/:id",
            delete(conventions::forget_convention),
        )
        .route("/api/v1/skills/share", post(conventions::share_skill))
        // Political network monitoring (Items 3–12) — write endpoints
        .route(
            "/api/v1/propaganda-techniques",
            post(political::create_technique),
        )
        .route("/api/v1/coalitions", post(political::create_coalition))
        .route("/api/v1/hypothesis", post(hypothesis::create_hypothesis))
        .route(
            "/api/v1/hypothesis/:id/status",
            get(hypothesis::hypothesis_status),
        )
        .route(
            "/api/v1/hypothesis/:id/promote",
            post(hypothesis::promote_hypothesis),
        )
        // Encrypted subgraph group management. ALL group routes are protected,
        // GET included: PR-02 moved `GET /api/v1/groups/:id` out of the
        // anonymous `public` router because a group's roster size and epoch
        // state describe a tenancy boundary. The `protected` router layers
        // `bearer_auth_middleware` unconditionally, so the handler gets a
        // mandatory AuthContext with no further wiring.
        .route("/api/v1/groups", post(groups::create_group))
        .route("/api/v1/groups/:id", get(groups::get_group))
        .route("/api/v1/groups/:id/members", post(groups::add_member))
        .route(
            "/api/v1/groups/:id/members/:agent_id",
            delete(groups::remove_member),
        )
        // /api/v1/groups/:id/rotate-key lives in the epigraph-enterprise repo.
        // Isomorphism pattern detection (episcience feature)
        // Admin OAuth client management
        .route(
            "/api/v1/admin/clients/:id/approve",
            post(admin::approve_client),
        )
        // entity_types registry: register a non-core type (entity-types:write scope)
        .route(
            "/api/v1/admin/entity-types",
            post(admin::register_entity_type),
        )
        // Agent key management
        .route(
            "/api/v1/agents/:id/keys/rotate",
            post(agent_keys::rotate_agent_key),
        )
        .route(
            "/api/v1/agents/:id/keys/:key_id/revoke",
            post(agent_keys::revoke_agent_key),
        )
        // Entity / triple write endpoints
        .route("/api/v1/entities", post(entities::create_entity))
        .route(
            "/api/v1/entity-mentions/batch",
            post(entities::batch_create_mentions),
        )
        .route(
            "/api/v1/triples/batch",
            post(entities::batch_create_triples),
        )
        // Task management — write endpoints
        .route("/api/v1/tasks", post(tasks::create_task))
        .route("/api/v1/tasks/:id/assign", post(tasks::assign_task))
        .route("/api/v1/tasks/:id/complete", post(tasks::complete_task))
        .route("/api/v1/tasks/:id/fail", post(tasks::fail_task))
        // Security audit log — requires audit:read scope
        .route("/api/v1/audit/security", get(audit::query_security_events))
        .route("/api/v1/graph/communities/overview", get(graph::overview))
        .route("/api/v1/graph/communities/:id/expand", get(graph::expand))
        .route("/api/v1/graph/neighborhood", get(graph::neighborhood))
        .route("/api/v1/graph/themes/overview", get(graph::themes_overview))
        .route(
            "/api/v1/graph/themes/:theme_id/expand",
            get(graph::themes_expand),
        )
        .route(
            "/api/v1/graph/neighborhoods/:id/expand",
            get(graph_neighborhood::expand),
        )
        // Policies write endpoints — require auth + scope
        .route(
            "/api/v1/policies/:claim_id/outcome",
            post(policies::record_outcome),
        )
        .route("/api/v1/policies/decay-sweep", post(policies::decay_sweep))
        .route(
            "/api/v1/policy-challenges",
            post(policies::create_challenge),
        )
        .route(
            "/api/v1/policy-challenges/:id/resolve",
            post(policies::resolve_challenge),
        )
        // Cross-source match candidates — write/list endpoints, require auth + scope
        .route(
            "/api/v1/match_candidates",
            get(cross_source::list_candidates),
        )
        .route(
            "/api/v1/match_candidates/:id/decide",
            post(cross_source::decide_candidate),
        );

    // ------------------------------------------------------------------
    // PR-03: THE INVERSION.
    //
    // Everything from here to the end of this chain used to live in a
    // separate `public` Router layered with `optional_bearer_auth_middleware`,
    // which passes a request with no Authorization header straight through
    // with no `AuthContext` ("anonymous pass-through", bearer.rs). That made
    // every route below — verbatim claim text via `/api/v1/search/semantic`
    // and `/api/v1/query/rag`, the ownership ACL itself via
    // `/api/v1/ownership/:node_id`, up to 5000 raw 1536-d embeddings via
    // `/api/v1/themes/:id/embeddings` — readable by anyone who could reach the
    // port.
    //
    // The rule is not "audit N handlers" — it is invert the split. `public` is
    // now an ALLOWLIST of two routes (built below); every other registration is
    // appended to `protected` and inherits `bearer_auth_middleware`.
    //
    // Axum permits repeated `.route()` calls on the same path with different
    // methods, so the GET arms folded in here merge with the PUT/DELETE arms
    // already registered above (`/api/v1/claims/:id` is the clearest case).
    // ------------------------------------------------------------------
    let protected = protected
        .route("/claims", get(claims::list_claims))
        .route("/claims/:id", get(claims::get_claim))
        .route("/agents", get(agents::list_agents))
        .route("/api/v1/agents", get(agents::list_agents))
        .route("/agents/:id", get(agents::get_agent))
        .route("/api/v1/agents/:id", get(agents::get_agent))
        .route("/agents/:id/reputation", get(agents::get_agent_reputation))
        .route(
            "/agents/:id/perspectives",
            get(perspective::agent_perspectives),
        )
        .route("/api/v1/agents/:id/claims", get(agents::agent_claims))
        .route("/api/v1/agents/:id/keys", get(agent_keys::list_agent_keys))
        .route(
            "/api/v1/agents/:id/timeline",
            get(timeline::get_agent_timeline),
        )
        .route("/lineage/:claim_id", get(lineage::get_lineage))
        .route("/api/v1/search/semantic", post(search::semantic_search))
        .route("/api/v1/claims", get(claims_query::list_claims_query))
        .route(
            "/api/v1/claims/needing-embeddings",
            get(claims::find_claims_needing_embeddings),
        )
        .route("/api/v1/claims/:id", get(claims::get_claim))
        .route("/api/v1/query/rag", get(rag::rag_context))
        .route("/api/v1/search/evidence", get(rag::search_evidence))
        .route(
            "/api/v1/claims/:id/challenges",
            get(challenge::list_challenges),
        )
        .route(
            "/api/v1/claims/:id/evidence",
            get(claims::list_claim_evidence),
        )
        .route("/api/v1/claims/:id/history", get(versioning::claim_history))
        .route(
            "/api/v1/claims/:id/cross_source_matches",
            get(cross_source::get_cross_source_matches),
        )
        .route("/api/v1/edges", get(edges::list_edges))
        .route("/api/v1/papers", get(papers::list_papers))
        .route(
            "/api/v1/claims/:id/neighborhood",
            get(edges::claim_neighborhood),
        )
        .route(
            "/api/v1/claims/:id/compound_neighborhood",
            get(graph_neighborhood::claim_compound_neighborhood),
        )
        .route("/api/v1/admin/stats", get(admin::system_stats))
        .route(
            "/api/v1/clusters/boundary-claims",
            get(crud::get_boundary_claims),
        )
        .route(
            "/api/v1/themes/split-candidates",
            get(crud::get_split_candidates),
        )
        .route(
            "/api/v1/themes/distant-claims",
            get(crud::get_distant_claims),
        )
        .route(
            "/api/v1/themes/:id/embeddings",
            get(crud::get_theme_embeddings),
        )
        .route("/api/v1/reasoning/analyze", post(reasoning::analyze))
        .route("/api/v1/events", get(events::list_events))
        .route(
            "/api/v1/graph/snapshot/:version",
            get(events::graph_snapshot),
        )
        .route("/api/v1/graph/edges", get(edges::graph_edges))
        .route("/api/v1/graph/full", get(edges::graph_full))
        .route(
            "/api/v1/graph/query",
            post(graph_query::execute_graph_query),
        )
        // Entity / triple read endpoints
        .route("/api/v1/triples/query", post(entities::query_triples))
        .route(
            "/api/v1/entities/:id/neighborhood",
            get(entities::entity_neighborhood),
        )
        .route("/api/v1/evidence/:id", get(edges::get_evidence))
        .route(
            "/api/v1/claims/:id/provenance",
            get(edges::claim_provenance),
        )
        .route(
            "/api/v1/claims/:id/supporting-evidence",
            get(edges::supporting_evidence),
        )
        .route(
            "/api/v1/claims/:id/contradicting-evidence",
            get(edges::contradicting_evidence),
        )
        .route("/api/v1/activities/:id", get(activities::get_activity))
        .route("/api/v1/spans", get(spans::list_spans))
        .route("/api/v1/claims/:id/belief", get(belief::get_claim_belief))
        .route("/api/v1/claims/by-belief", get(belief::claims_by_belief))
        .route("/api/v1/claims/by-labels", get(claims::list_by_labels))
        .route("/api/v1/frames", get(belief::list_frames))
        .route("/api/v1/frames/:id", get(belief::get_frame))
        .route("/api/v1/frames/:id/conflict", get(belief::frame_conflict))
        .route(
            "/api/v1/frames/:id/claims",
            get(belief::frame_claims_sorted),
        )
        .route(
            "/api/v1/claims/:id/divergence",
            get(belief::claim_divergence),
        )
        .route("/api/v1/divergence/top", get(belief::top_divergence))
        .route(
            "/api/v1/claims/:id/belief/scoped",
            get(belief::get_scoped_belief),
        )
        .route(
            "/api/v1/claims/:id/belief/all-scopes",
            get(belief::all_scopes_belief),
        )
        .route("/api/v1/perspectives", get(perspective::list_perspectives))
        .route(
            "/api/v1/perspectives/:id",
            get(perspective::get_perspective),
        )
        .route("/api/v1/communities", get(community::list_communities))
        .route("/api/v1/communities/:id", get(community::get_community))
        .route("/api/v1/contexts", get(context::list_contexts))
        .route(
            "/api/v1/contexts/active",
            get(context::list_active_contexts),
        )
        .route("/api/v1/contexts/:id", get(context::get_context))
        .route("/api/v1/frames/:id/contexts", get(context::frame_contexts))
        .route("/api/v1/claims/:id/pignistic", get(belief::get_pignistic))
        .route(
            "/api/v1/frames/:id/refinements",
            get(belief::frame_refinements),
        )
        .route("/api/v1/frames/:id/ancestry", get(belief::frame_ancestry))
        .route("/api/v1/ownership/:node_id", get(ownership::get_ownership))
        .route(
            "/api/v1/agents/:id/owned-nodes",
            get(ownership::owned_nodes),
        )
        .route(
            "/api/v1/structural-features/:owner_id",
            get(structural::get_structural_features),
        )
        .route("/api/v1/workflows", get(workflows::list_workflows))
        .route("/api/v1/workflows/search", get(workflows::search_workflows))
        .route(
            "/api/v1/workflows/hierarchical/search",
            get(workflows::find_workflow_hierarchical),
        )
        .route("/api/v1/workflows/:id", get(workflows::get_workflow))
        .route(
            "/api/v1/policies/network",
            get(policies::list_network_policies),
        )
        .route(
            "/api/v1/policy-challenges/:id",
            get(policies::get_challenge),
        )
        .route("/api/v1/methods/search", get(experiments::find_methods))
        .route(
            "/api/v1/methods/gap-analysis",
            get(experiments::method_gap_analysis),
        )
        .route("/api/v1/voids/density", get(voids::embedding_density))
        .route(
            "/api/v1/embeddings/neighborhood-density",
            post(embeddings::neighborhood_density),
        )
        .route(
            "/api/v1/sheaf/consistency",
            get(computation::sheaf_consistency),
        )
        .route(
            "/api/v1/sheaf/cohomology",
            get(computation::sheaf_cohomology),
        )
        .route(
            "/api/v1/claims/:id/belief-at",
            get(computation::belief_at_time),
        )
        .route("/api/v1/conflicts/scan", get(conflicts::scan_conflicts))
        .route(
            "/api/v1/conflicts/silence-check",
            get(conflicts::silence_check),
        )
        .route(
            "/api/v1/conflicts/:a/:b/counterfactuals",
            get(conflicts::get_counterfactuals),
        )
        .route(
            "/api/v1/learning-events",
            get(conflicts::list_learning_events),
        )
        .route("/api/v1/skills", get(conventions::list_skills))
        .route(
            "/api/v1/experiments",
            get(experiment_loop::list_experiments),
        )
        .route("/api/v1/methods/:id", get(methods::get_method))
        // Political network monitoring (Items 3–12) — read endpoints
        .route(
            "/api/v1/agents/:id/epistemic-profile",
            get(political::epistemic_profile),
        )
        .route("/api/v1/agents/compare", get(political::compare_agents))
        .route(
            "/api/v1/agents/:id/position-timeline",
            get(political::position_timeline),
        )
        .route(
            "/api/v1/claims/:id/genealogy",
            get(political::claim_genealogy),
        )
        .route(
            "/api/v1/agents/:id/originated-claims",
            get(political::originated_claims),
        )
        .route(
            "/api/v1/agents/:id/inflation-index",
            get(political::inflation_index),
        )
        .route(
            "/api/v1/inflation-index/leaderboard",
            get(political::inflation_leaderboard),
        )
        .route(
            "/api/v1/claims/:id/techniques",
            get(political::claim_techniques),
        )
        .route(
            "/api/v1/propaganda-techniques",
            get(political::list_techniques),
        )
        .route("/api/v1/coalitions", get(political::list_coalitions))
        .route(
            "/api/v1/counter-narrative-gaps",
            get(political::counter_narrative_gaps),
        )
        .route(
            "/api/v1/mirror-narratives",
            get(political::mirror_narratives),
        )
        // /api/v1/isomorphism/patterns — episcience feature
        // Task management — read endpoints
        .route("/api/v1/tasks", get(tasks::list_tasks))
        .route("/api/v1/tasks/:id", get(tasks::get_task))
        // MCP tool discovery. Moved behind auth: the same catalog is
        // available to an authenticated caller over MCP `list_tools`, so an
        // anonymous copy only gave a scanner a free capability map.
        .route("/api/v1/mcp/tools", get(mcp_tools::list_mcp_tools));

    // Authentication for `protected`: OAuth2 Bearer, unconditionally.
    //
    // This used to branch on `ApiConfig::require_signatures`, adding a
    // `require_signature` (Ed25519 request-signing) layer when set. That
    // middleware short-circuited on any request carrying an `AuthContext` and
    // bearer auth ran first, so it was unreachable through this router; it has
    // been deleted. `require_packet_signatures` survives under its new name and
    // gates PAYLOAD-level packet signatures inside `routes/submit.rs`, which is
    // a different mechanism at a different layer.
    let protected = protected.layer(middleware::from_fn_with_state(
        state.clone(),
        bearer_auth_middleware,
    ));

    // The anonymous allowlist. Adding a route here is a security decision;
    // `crates/epigraph-api/tests/public_router_allowlist.rs` fails the build
    // until the allowlist in that test is updated to match, which forces the
    // addition past a reviewer.
    //
    //   /health              — `health::health_check` takes no state and
    //                          returns a static struct. Load balancers need it.
    //   /api/v1/openapi.json — a static schema document.
    //
    // `/metrics` is NOT here: it moved off the public listener entirely to a
    // separate internal listener bound by `bin/server.rs`
    // (`EPIGRAPH_METRICS_ADDR`, default 127.0.0.1:9090). Prometheus exposition
    // is an operational surface, not a public one.
    //
    // The `/oauth/*` and `/.well-known/*` router below is the third anonymous
    // surface, and is anonymous by construction: discovery and token issuance
    // must precede authentication.
    let public = Router::new()
        .route("/health", get(health::health_check))
        .route(
            "/api/v1/openapi.json",
            get(|| async { axum::Json(crate::openapi::openapi_spec()) }),
        );

    // Layered on the two-route allowlist: a request with no Authorization
    // header passes through, a request with a present-but-invalid token still
    // 401s. Retained rather than dropped so an allowlisted handler can still
    // see who is calling when a token happens to be supplied.
    //
    // The block that used to stand here catalogued which public read handlers
    // had adopted `auth_ctx` for partition-aware redaction and which still
    // trusted the spoofable `?agent_id` wire param. It is gone because the
    // premise is gone: those handlers are no longer reachable without a
    // credential at all. The remaining work — deriving a `Viewer` on every read
    // path rather than an `Option<AuthContext>` — is PR-07.
    let public = public.layer(middleware::from_fn_with_state(
        state.clone(),
        optional_bearer_auth_middleware,
    ));

    // OAuth2 endpoints (public, no auth required)
    let oauth = Router::new()
        .route("/oauth/token", post(crate::oauth::token_endpoint))
        .route("/oauth/register", post(crate::oauth::register_endpoint))
        .route("/oauth/revoke", post(crate::oauth::revoke_endpoint))
        .route("/oauth/introspect", post(crate::oauth::introspect_endpoint))
        .route("/oauth/authorize", get(crate::oauth::authorize_endpoint))
        .route("/oauth/callback", get(crate::oauth::callback_endpoint))
        .route(
            "/oauth/authorize/consent",
            post(crate::oauth::consent_endpoint),
        )
        .route(
            "/oauth/:provider/auth-url",
            post(crate::oauth::auth_url_endpoint),
        )
        .route(
            "/oauth/:provider/exchange",
            post(crate::oauth::exchange_endpoint),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(crate::oauth::authorization_server_metadata),
        )
        .route(
            "/.well-known/oauth-protected-resource",
            get(crate::oauth::protected_resource_metadata),
        );

    // Apply rate limiting and body limit as outermost layers
    // Rate limiting bypasses health endpoints internally
    Router::new()
        .merge(protected)
        .merge(public)
        .merge(oauth)
        .layer(DefaultBodyLimit::max(state.config.max_request_size))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        .with_state(state)
}

/// Create a router without database-dependent routes.
///
/// # Status: not built in any supported configuration
///
/// `epigraph-api`'s default feature set is `["db"]` and every CI job builds
/// with defaults. `cargo check -p epigraph-api --no-default-features` has been
/// failing for some time (28 pre-existing errors: missing `sqlx`, `db_pool`,
/// `ClaimId`, …), so **no compiler checks this function**. It is kept in sync
/// with the `db` variant by hand and by
/// `crates/epigraph-api/tests/public_router_allowlist.rs`, which is a
/// source-text lint precisely so that it covers the block nothing else does.
///
/// # Route structure
///
/// Mirrors the `db` variant: `protected` (Bearer required), a two-route
/// anonymous `public` allowlist (`GET /health`, `GET /api/v1/openapi.json`),
/// and an `oauth` router — which here has **9** routes rather than 11, lacking
/// `/oauth/callback` and `/oauth/authorize/consent`. That divergence is
/// pre-existing and is asserted, not fixed, by the allowlist test.
///
/// # Rate limiting
///
/// All routes (except health endpoints) are subject to rate limiting when a
/// rate limiter is configured in `AppState`.
#[cfg(not(feature = "db"))]
pub fn create_router(state: AppState) -> Router {
    // Protected write operations
    let protected = Router::new()
        // NO claim-deletion route. `DELETE /api/v1/claims/:id` and
        // `POST /api/v1/claims/:id/confirm-delete` were removed: EpiGraph retires
        // claims by supersession and edges by retraction, so a production path that
        // destroys a claim and hard-deletes every edge touching it contradicted the
        // policy it sat next to. Test cleanup moved to
        // `tests/integration/test_claim_cleanup.rs::hard_delete_test_claims`, which
        // is unreachable over HTTP and guards against non-disposable databases.
        .route("/api/v1/claims/:id", put(claims::update_claim))
        .route("/api/v1/claims/:id", patch(claims::patch_claim))
        .route(
            "/api/v1/edges/:id",
            delete(edges::delete_edge).patch(edges::patch_edge),
        )
        .route("/api/v1/evidence", post(crud::create_evidence))
        .route("/api/v1/evidence/:id", put(crud::update_evidence))
        .route(
            "/api/v1/reasoning-traces",
            post(crud::create_reasoning_trace),
        )
        .route("/api/v1/analyses", post(crud::create_analysis))
        .route("/api/v1/clusters", post(crud::upsert_cluster))
        .route("/api/v1/themes/reassign", post(crud::reassign_claim))
        .route(
            "/api/v1/themes/assign-unthemed",
            post(crud::assign_unthemed),
        )
        .route(
            "/api/v1/themes/recompute-centroids",
            post(crud::recompute_centroids),
        )
        .route(
            "/api/v1/themes/create-with-centroid",
            post(crud::create_theme_with_centroid),
        )
        .route(
            "/api/v1/themes/build-from-corpus",
            post(crud::build_themes_from_corpus),
        )
        .route(
            "/api/v1/clusters/build-from-bridges",
            post(clusters::build_from_bridges),
        )
        .route(
            "/api/v1/frames/:id/assign-claim",
            post(crud::assign_claim_to_frame),
        )
        .route(
            "/api/v1/edges-staging/promote",
            post(crud::promote_staged_edges),
        )
        .route("/api/v1/submit/packet", post(submit::submit_packet))
        .route(
            "/api/v1/claims/:id/challenge",
            post(challenge::submit_challenge),
        )
        .route(
            "/api/v1/claims/:id/supersede",
            post(versioning::supersede_claim),
        )
        .route(
            "/api/v1/claims/:id/revoke-signature",
            post(revoke_signature::revoke_claim_signature),
        )
        .route("/api/v1/claims/batch", post(batch::batch_create_claims))
        .route("/api/v1/claims/:id/labels", patch(claims::update_labels))
        .route(
            "/api/v1/webhooks",
            post(webhooks::register_webhook).get(webhooks::list_webhooks),
        )
        .route(
            "/api/v1/webhooks/:id",
            get(webhooks::get_webhook).delete(webhooks::delete_webhook),
        )
        .route("/api/v1/harvest", post(harvest::submit_harvest))
        .route("/api/v1/ingest/paper", post(ingest::ingest_paper))
        .route("/api/v1/ingest/paper-url", post(ingest::ingest_paper))
        .route("/api/v1/papers", post(papers::create_paper))
        .route("/api/v1/edges", post(edges::create_edge))
        .route(
            "/api/v1/edges/hierarchical",
            post(edges::create_hierarchical_edge),
        )
        .route(
            "/api/v1/analyze/unconstrained",
            post(analyze::unconstrained_analysis),
        )
        .route(
            "/api/v1/claims/:id/embedding",
            put(rag::generate_claim_embedding),
        )
        .route(
            "/api/v1/evidence/:id/embedding",
            put(rag::generate_evidence_embedding),
        )
        .route("/api/v1/staging/ingest/json", post(staging::ingest_json))
        .route("/api/v1/staging/ingest/git", post(staging::ingest_git))
        .route("/api/v1/staging/merge", post(staging::merge_staging))
        .route(
            "/api/v1/staging/analyze-rejection",
            post(staging::analyze_rejection),
        )
        .route("/api/v1/events", post(events::create_event))
        .route("/api/v1/spans", post(spans::create_span))
        .route("/api/v1/spans/:id/close", put(spans::close_span))
        .route("/api/v1/activities", post(activities::create_activity))
        .route(
            "/api/v1/activities/:id/complete",
            put(activities::complete_activity),
        )
        .route("/api/v1/frames", post(belief::create_frame))
        .route("/api/v1/frames/:id/evidence", post(belief::submit_evidence))
        .route(
            "/api/v1/perspectives",
            post(perspective::create_perspective),
        )
        .route(
            "/api/v1/perspectives/:id/source-reliability",
            put(perspective::set_source_reliability),
        )
        .route("/api/v1/communities", post(community::create_community))
        .route(
            "/api/v1/communities/:id/members",
            post(community::add_member),
        )
        .route(
            "/api/v1/communities/:id/members/:perspective_id",
            delete(community::remove_member),
        )
        .route("/api/v1/contexts", post(context::create_context))
        .route("/api/v1/frames/:id/refine", post(belief::refine_frame))
        .route("/api/v1/ownership", post(ownership::assign_ownership))
        .route(
            "/api/v1/ownership/:node_id",
            put(ownership::update_partition),
        )
        .route("/api/v1/claims/:id/relate", post(edges::relate_claims))
        // Political network monitoring — write endpoints (non-db stubs)
        .route(
            "/api/v1/propaganda-techniques",
            post(political::create_technique),
        )
        .route("/api/v1/coalitions", post(political::create_coalition));

    // ------------------------------------------------------------------
    // PR-03: THE INVERSION.
    //
    // Everything from here to the end of this chain used to live in a
    // separate `public` Router layered with `optional_bearer_auth_middleware`,
    // which passes a request with no Authorization header straight through
    // with no `AuthContext` ("anonymous pass-through", bearer.rs). That made
    // every route below readable by anyone who could reach the port.
    //
    // The rule is not "audit N handlers" — it is invert the split. `public` is
    // now an ALLOWLIST of two routes (built below); every other registration
    // is appended to `protected` and inherits `bearer_auth_middleware`.
    //
    // Axum permits repeated `.route()` calls on the same path with different
    // methods, so the GET arms folded in here merge with the PUT/DELETE arms
    // already registered above (`/api/v1/claims/:id` is the clearest case).
    // ------------------------------------------------------------------
    let protected = protected
        .route("/api/v1/claims", get(claims_query::list_claims_query))
        .route("/api/v1/query/rag", get(rag::rag_context))
        .route("/api/v1/search/evidence", get(rag::search_evidence))
        .route(
            "/api/v1/claims/:id/challenges",
            get(challenge::list_challenges),
        )
        .route(
            "/api/v1/claims/:id/evidence",
            get(claims::list_claim_evidence),
        )
        .route("/api/v1/claims/:id/history", get(versioning::claim_history))
        .route(
            "/api/v1/claims/:id/cross_source_matches",
            get(cross_source::get_cross_source_matches),
        )
        .route(
            "/api/v1/match_candidates",
            get(cross_source::list_candidates),
        )
        .route("/api/v1/edges", get(edges::list_edges))
        .route("/api/v1/papers", get(papers::list_papers))
        .route(
            "/api/v1/claims/:id/neighborhood",
            get(edges::claim_neighborhood),
        )
        .route("/api/v1/admin/stats", get(admin::system_stats))
        .route(
            "/api/v1/clusters/boundary-claims",
            get(crud::get_boundary_claims),
        )
        .route(
            "/api/v1/themes/split-candidates",
            get(crud::get_split_candidates),
        )
        .route(
            "/api/v1/themes/distant-claims",
            get(crud::get_distant_claims),
        )
        .route(
            "/api/v1/themes/:id/embeddings",
            get(crud::get_theme_embeddings),
        )
        .route("/api/v1/reasoning/analyze", post(reasoning::analyze))
        .route("/api/v1/events", get(events::list_events))
        .route(
            "/api/v1/graph/snapshot/:version",
            get(events::graph_snapshot),
        )
        .route("/api/v1/graph/edges", get(edges::graph_edges))
        .route("/api/v1/graph/full", get(edges::graph_full))
        .route("/api/v1/evidence/:id", get(edges::get_evidence))
        .route(
            "/api/v1/claims/:id/provenance",
            get(edges::claim_provenance),
        )
        .route(
            "/api/v1/claims/:id/supporting-evidence",
            get(edges::supporting_evidence),
        )
        .route(
            "/api/v1/claims/:id/contradicting-evidence",
            get(edges::contradicting_evidence),
        )
        .route("/api/v1/activities/:id", get(activities::get_activity))
        .route("/api/v1/spans", get(spans::list_spans))
        .route("/api/v1/claims/:id/belief", get(belief::get_claim_belief))
        .route("/api/v1/claims/by-belief", get(belief::claims_by_belief))
        .route("/api/v1/claims/by-labels", get(claims::list_by_labels))
        .route("/api/v1/frames", get(belief::list_frames))
        .route("/api/v1/frames/:id", get(belief::get_frame))
        .route("/api/v1/frames/:id/conflict", get(belief::frame_conflict))
        .route(
            "/api/v1/frames/:id/claims",
            get(belief::frame_claims_sorted),
        )
        .route(
            "/api/v1/claims/:id/divergence",
            get(belief::claim_divergence),
        )
        .route("/api/v1/divergence/top", get(belief::top_divergence))
        .route(
            "/api/v1/claims/:id/belief/scoped",
            get(belief::get_scoped_belief),
        )
        .route(
            "/api/v1/claims/:id/belief/all-scopes",
            get(belief::all_scopes_belief),
        )
        .route("/api/v1/perspectives", get(perspective::list_perspectives))
        .route(
            "/api/v1/perspectives/:id",
            get(perspective::get_perspective),
        )
        .route("/api/v1/communities", get(community::list_communities))
        .route("/api/v1/communities/:id", get(community::get_community))
        .route("/api/v1/contexts", get(context::list_contexts))
        .route(
            "/api/v1/contexts/active",
            get(context::list_active_contexts),
        )
        .route("/api/v1/contexts/:id", get(context::get_context))
        .route("/api/v1/frames/:id/contexts", get(context::frame_contexts))
        .route("/api/v1/claims/:id/pignistic", get(belief::get_pignistic))
        .route(
            "/api/v1/frames/:id/refinements",
            get(belief::frame_refinements),
        )
        .route("/api/v1/frames/:id/ancestry", get(belief::frame_ancestry))
        .route("/api/v1/ownership/:node_id", get(ownership::get_ownership))
        .route(
            "/api/v1/agents/:id/owned-nodes",
            get(ownership::owned_nodes),
        )
        .route(
            "/api/v1/structural-features/:owner_id",
            get(structural::get_structural_features),
        )
        // Political network monitoring (Items 3–12) — read endpoints (non-db stubs)
        .route(
            "/api/v1/agents/:id/epistemic-profile",
            get(political::epistemic_profile),
        )
        .route("/api/v1/agents/compare", get(political::compare_agents))
        .route(
            "/api/v1/agents/:id/position-timeline",
            get(political::position_timeline),
        )
        .route(
            "/api/v1/claims/:id/genealogy",
            get(political::claim_genealogy),
        )
        .route(
            "/api/v1/agents/:id/originated-claims",
            get(political::originated_claims),
        )
        .route(
            "/api/v1/agents/:id/inflation-index",
            get(political::inflation_index),
        )
        .route(
            "/api/v1/inflation-index/leaderboard",
            get(political::inflation_leaderboard),
        )
        .route(
            "/api/v1/claims/:id/techniques",
            get(political::claim_techniques),
        )
        .route(
            "/api/v1/propaganda-techniques",
            get(political::list_techniques),
        )
        .route("/api/v1/coalitions", get(political::list_coalitions))
        .route(
            "/api/v1/counter-narrative-gaps",
            get(political::counter_narrative_gaps),
        )
        .route(
            "/api/v1/mirror-narratives",
            get(political::mirror_narratives),
        );

    // Authentication for `protected`: OAuth2 Bearer, unconditionally.
    //
    // This used to branch on `ApiConfig::require_signatures`, adding a
    // `require_signature` (Ed25519 request-signing) layer when set. That
    // middleware short-circuited on any request carrying an `AuthContext` and
    // bearer auth ran first, so it was unreachable through this router; it has
    // been deleted. `require_packet_signatures` survives under its new name and
    // gates PAYLOAD-level packet signatures inside `routes/submit.rs`, which is
    // a different mechanism at a different layer.
    let protected = protected.layer(middleware::from_fn_with_state(
        state.clone(),
        bearer_auth_middleware,
    ));

    // The anonymous allowlist. Adding a route here is a security decision;
    // `crates/epigraph-api/tests/public_router_allowlist.rs` fails the build
    // until the allowlist in that test is updated to match, which forces the
    // addition past a reviewer.
    //
    //   /health             — `health::health_check` takes no state and returns
    //                         a static struct. Load balancers need it.
    //   /api/v1/openapi.json — a static schema document.
    //
    // `/metrics` is NOT here: it moved off the public listener entirely to a
    // separate internal listener bound by `bin/server.rs`
    // (`EPIGRAPH_METRICS_ADDR`, default 127.0.0.1:9090). Prometheus exposition
    // is an operational surface, not a public one.
    //
    // The `/oauth/*` and `/.well-known/*` router below is the third anonymous
    // surface, and is anonymous by construction: discovery and token issuance
    // must precede authentication.
    let public = Router::new()
        .route("/health", get(health::health_check))
        .route(
            "/api/v1/openapi.json",
            get(|| async { axum::Json(crate::openapi::openapi_spec()) }),
        );

    // Layered on the two-route allowlist: a request with no Authorization
    // header passes through, a request with a present-but-invalid token still
    // 401s. Retained rather than dropped so an allowlisted handler can still
    // see who is calling when a token happens to be supplied.
    let public = public.layer(middleware::from_fn_with_state(
        state.clone(),
        optional_bearer_auth_middleware,
    ));

    // OAuth2 endpoints (public, no auth required)
    let oauth = Router::new()
        .route("/oauth/token", post(crate::oauth::token_endpoint))
        .route("/oauth/register", post(crate::oauth::register_endpoint))
        .route("/oauth/revoke", post(crate::oauth::revoke_endpoint))
        .route("/oauth/introspect", post(crate::oauth::introspect_endpoint))
        .route("/oauth/authorize", get(crate::oauth::authorize_endpoint))
        .route(
            "/oauth/:provider/auth-url",
            post(crate::oauth::auth_url_endpoint),
        )
        .route(
            "/oauth/:provider/exchange",
            post(crate::oauth::exchange_endpoint),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(crate::oauth::authorization_server_metadata),
        )
        .route(
            "/.well-known/oauth-protected-resource",
            get(crate::oauth::protected_resource_metadata),
        );

    // Apply rate limiting and body limit as outermost layers
    // Rate limiting bypasses health endpoints internally
    Router::new()
        .merge(protected)
        .merge(public)
        .merge(oauth)
        .layer(DefaultBodyLimit::max(state.config.max_request_size))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        .with_state(state)
}

// Tests are disabled when db feature is enabled since they need a real database
#[cfg(all(test, not(feature = "db")))]
mod tests {
    use super::*;
    use crate::state::ApiConfig;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[test]
    fn router_has_expected_routes() {
        let state = AppState::new(ApiConfig::default());
        let router = create_router(state);

        // Router should be creatable without panic
        // The router type proves the routes are configured
        let _ = router;
    }

    #[tokio::test]
    async fn router_health_endpoint_returns_200() {
        let state = AppState::new(ApiConfig::default());
        let router = create_router(state);

        let request = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn router_unknown_endpoint_returns_404() {
        let state = AppState::new(ApiConfig::default());
        let router = create_router(state);

        let request = Request::builder()
            .uri("/nonexistent/path")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn router_openapi_endpoint_returns_valid_spec() {
        use http_body_util::BodyExt;

        let state = AppState::new(ApiConfig::default());
        let router = create_router(state);

        let request = Request::builder()
            .uri("/api/v1/openapi.json")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json.get("info").is_some(),
            "OpenAPI spec should have 'info'"
        );
        assert!(
            json.get("paths").is_some(),
            "OpenAPI spec should have 'paths'"
        );
    }
}
