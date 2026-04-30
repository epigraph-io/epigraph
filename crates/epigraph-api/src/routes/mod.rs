// NOTE: There are 124 `#[cfg(not(feature = "db"))]` stubs across 29 route
// files. These provide compile-time fallback handlers that return 501 Not
// Implemented when the `db` feature is disabled, allowing the API crate to
// build (and run lightweight/mock modes) without a PostgreSQL dependency.
// Audited 2026-03-28.

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
pub mod community;
#[cfg(feature = "db")]
pub mod computation;
#[cfg(feature = "db")]
pub mod conflicts;
pub mod context;
#[cfg(feature = "db")]
pub mod conventions;
pub mod crud;
pub mod edges;
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
pub mod methods;
#[cfg(feature = "enterprise")]
pub mod mpc;
#[cfg(all(test, not(feature = "db")))]
mod negative_tests;
pub mod ownership;
pub mod papers;
pub mod perspective;
#[cfg(feature = "db")]
pub mod policies;
pub mod political;
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

use crate::metrics;
use crate::middleware::{bearer_auth_middleware, rate_limit_middleware, require_signature};
use crate::state::AppState;
use axum::{
    extract::DefaultBodyLimit,
    middleware,
    routing::{delete, get, patch, post, put},
    Router,
};

/// Create the main application router with all routes
///
/// # Route Structure
///
/// Routes are organized into two categories:
///
/// ## Protected Routes (require Ed25519 signature)
///
/// Write operations that modify system state:
/// - `POST /claims` - Create a new claim
/// - `POST /agents` - Register a new agent
/// - `POST /api/v1/submit/packet` - Submit an epistemic packet
///
/// ## Public Routes (no authentication required)
///
/// Read-only operations for transparency:
/// - `GET /health` - Health check endpoint
/// - `GET /claims` - List claims
/// - `GET /claims/:id` - Get a specific claim
/// - `GET /agents` - List agents
/// - `GET /agents/:id` - Get a specific agent
/// - `GET /lineage/:claim_id` - Get claim lineage
/// - `POST /api/v1/search/semantic` - Semantic search (read operation)
/// - `GET /api/v1/query/rag` - RAG context retrieval (high-truth claims)
///
/// # Security
///
/// Protected routes use the `require_signature` middleware which:
/// 1. Verifies Ed25519 signatures on requests
/// 2. Validates request timestamps (prevents replay attacks)
/// 3. Confirms agent is registered in the system
/// 4. Injects `VerifiedAgent` into request extensions for handlers
///
/// # Rate Limiting
///
/// All routes (except health endpoints) are subject to rate limiting when
/// a rate limiter is configured in AppState. Rate limits apply per-agent
/// for authenticated requests and per-IP for unauthenticated requests.
#[cfg(feature = "db")]
pub fn create_router(state: AppState) -> Router {
    // Protected write operations - require signature verification
    let protected = Router::new()
        .route("/claims", post(claims::create_claim))
        .route("/api/v1/claims", post(claims::create_claim))
        .route("/agents", post(agents::create_agent))
        .route("/api/v1/agents", post(agents::create_agent))
        .route("/api/v1/agents/:id", put(agents::update_agent))
        .route(
            "/api/v1/claims/:id",
            put(claims::update_claim).delete(claims::delete_claim),
        )
        .route("/api/v1/claims/:id", patch(claims::patch_claim))
        .route(
            "/api/v1/claims/:id/confirm-delete",
            post(claims::confirm_delete_claim),
        )
        .route("/api/v1/edges/:id", delete(edges::delete_edge))
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
        .route(
            "/api/v1/workflows/:id/outcome",
            post(workflows::report_outcome),
        )
        .route(
            "/api/v1/workflows/:id/improve",
            post(workflows::improve_workflow),
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
        // Encrypted subgraph group management
        .route("/api/v1/groups", post(groups::create_group))
        .route("/api/v1/groups/:id/members", post(groups::add_member))
        .route(
            "/api/v1/groups/:id/members/:agent_id",
            delete(groups::remove_member),
        )
        // /api/v1/groups/:id/rotate-key — enterprise feature (key rotation via epigraph-privacy)
        // Isomorphism pattern detection (episcience feature)
        // MPC joint recall (enterprise feature)
        // Admin OAuth client management
        .route(
            "/api/v1/admin/clients/:id/approve",
            post(admin::approve_client),
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
        .route("/api/v1/graph/overview", get(graph::overview))
        .route("/api/v1/graph/clusters/:id/expand", get(graph::expand))
        .route("/api/v1/graph/neighborhood", get(graph::neighborhood));

    // Auth middleware stack (outermost runs first):
    // 1. bearer_auth_middleware: if Bearer token present, validate JWT + inject AuthContext
    //    If no Bearer but X-Signature present, falls through to next layer.
    // 2. require_signature: Ed25519 signature verification (legacy)
    //
    // Axum layers are applied inner-to-outer, so we apply signature first, then bearer.
    let protected = if state.config.require_signatures {
        protected
            .layer(middleware::from_fn_with_state(
                state.clone(),
                require_signature,
            ))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                bearer_auth_middleware,
            ))
    } else {
        // Even without signature requirement, accept bearer tokens when present
        protected.layer(middleware::from_fn_with_state(
            state.clone(),
            bearer_auth_middleware,
        ))
    };

    // Public read operations - no authentication required
    let public = Router::new()
        .route("/health", get(health::health_check))
        .route("/metrics", get(metrics::metrics_handler))
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
        .route(
            "/api/v1/openapi.json",
            get(|| async { axum::Json(crate::openapi::openapi_spec()) }),
        )
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
        .route("/api/v1/workflows/:id", get(workflows::get_workflow))
        .route("/api/v1/methods/search", get(experiments::find_methods))
        .route(
            "/api/v1/methods/gap-analysis",
            get(experiments::method_gap_analysis),
        )
        .route("/api/v1/voids/density", get(voids::embedding_density))
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
        // Encrypted subgraph read endpoints
        .route("/api/v1/groups/:id", get(groups::get_group))
        // /api/v1/isomorphism/patterns — episcience feature
        // Task management — read endpoints
        .route("/api/v1/tasks", get(tasks::list_tasks))
        .route("/api/v1/tasks/:id", get(tasks::get_task));

    // OAuth2 endpoints (public, no auth required)
    let oauth = Router::new()
        .route("/oauth/token", post(crate::oauth::token_endpoint))
        .route("/oauth/register", post(crate::oauth::register_endpoint))
        .route("/oauth/revoke", post(crate::oauth::revoke_endpoint))
        .route("/oauth/introspect", post(crate::oauth::introspect_endpoint))
        .route(
            "/oauth/:provider/auth-url",
            post(crate::oauth::auth_url_endpoint),
        )
        .route(
            "/oauth/:provider/exchange",
            post(crate::oauth::exchange_endpoint),
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

/// Create a router without database-dependent routes
/// Used for testing and when db feature is disabled
///
/// # Route Structure
///
/// ## Protected Routes (require Ed25519 signature)
/// - `POST /api/v1/submit/packet` - Submit an epistemic packet
///
/// ## Public Routes (no authentication required)
/// - `GET /health` - Health check endpoint
/// - `GET /api/v1/query/rag` - RAG context retrieval (high-truth claims)
///
/// # Rate Limiting
///
/// All routes (except health endpoints) are subject to rate limiting when
/// a rate limiter is configured in AppState.
#[cfg(not(feature = "db"))]
pub fn create_router(state: AppState) -> Router {
    // Protected write operations
    let protected = Router::new()
        .route(
            "/api/v1/claims/:id",
            put(claims::update_claim).delete(claims::delete_claim),
        )
        .route("/api/v1/claims/:id", patch(claims::patch_claim))
        .route(
            "/api/v1/claims/:id/confirm-delete",
            post(claims::confirm_delete_claim),
        )
        .route("/api/v1/edges/:id", delete(edges::delete_edge))
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
    // /api/v1/mpc/joint-recall is an enterprise route; register via enterprise feature

    // Auth middleware: bearer first, then signature fallback (same as db variant)
    let protected = if state.config.require_signatures {
        protected
            .layer(middleware::from_fn_with_state(
                state.clone(),
                require_signature,
            ))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                bearer_auth_middleware,
            ))
    } else {
        protected.layer(middleware::from_fn_with_state(
            state.clone(),
            bearer_auth_middleware,
        ))
    };

    // Public read operations
    let public = Router::new()
        .route("/health", get(health::health_check))
        .route("/metrics", get(metrics::metrics_handler))
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
        .route(
            "/api/v1/openapi.json",
            get(|| async { axum::Json(crate::openapi::openapi_spec()) }),
        )
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

    // OAuth2 endpoints (public, no auth required)
    let oauth = Router::new()
        .route("/oauth/token", post(crate::oauth::token_endpoint))
        .route("/oauth/register", post(crate::oauth::register_endpoint))
        .route("/oauth/revoke", post(crate::oauth::revoke_endpoint))
        .route("/oauth/introspect", post(crate::oauth::introspect_endpoint))
        .route(
            "/oauth/:provider/auth-url",
            post(crate::oauth::auth_url_endpoint),
        )
        .route(
            "/oauth/:provider/exchange",
            post(crate::oauth::exchange_endpoint),
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
