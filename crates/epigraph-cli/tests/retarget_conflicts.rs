//! End-to-end cover for `decompose_claims --retarget`: a contradicts edge on a
//! decomposed parent is moved onto the atom it disputes, through a REAL
//! epigraph-api server built from this branch.
//!
//! The server is the production `create_edge` / `patch_edge` handlers mounted
//! on a loopback TCP listener, so the retarget client's `reqwest` calls cross a
//! real socket and the API's create→wire path runs exactly as it would in
//! production: `trigger_edge_ds_recomputation` → `auto_wire_edge_if_epistemic`
//! → a `mass_functions` row on the atom keyed by the new edge's id.
//!
//! The LLM is the deterministic `FixtureLlmClient`, keyed by the SOURCE claim's
//! text; its call counter is what proves "no second LLM call".
//!
//! Every test goes through `run_retarget`, the function the binary's
//! `--retarget` / `--retarget --apply` branch calls, so the dry-run gate under
//! test is the one the operator runs.
#![cfg(feature = "db")]

mod viewer_fixture;

use axum::{
    extract::Request,
    middleware::Next,
    routing::{patch, post},
    Router,
};
use epigraph_api::routes;
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_cli::enrichment::llm_client::FixtureLlmClient;
use epigraph_cli::retarget::{
    apply_retarget, run_retarget, verdict, AtomRef, EdgeApiClient, RetargetOptions,
    RetargetPlanEntry,
};
use sqlx::PgPool;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use uuid::Uuid;

const PARENT: &str = "Gravity bends light, and time dilates near mass.";
const ATOM_0: &str = "Gravity bends light.";
const ATOM_1: &str = "Time dilates near mass.";
const SOURCE: &str = "Clocks near massive bodies tick at exactly the same rate as distant clocks.";

/// The conflict relationship the world is seeded with. `refutes`, because
/// `contradicts` retargets are HELD (`retarget::HELD_RELATIONSHIPS`): a
/// regression test built on a held relationship would pass on the hold alone,
/// whatever the guard it claims to test does.
const REL: &str = "refutes";

struct World {
    agent: Uuid,
    parent: Uuid,
    atoms: [Uuid; 2],
    source: Uuid,
    parent_edge: Uuid,
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    let mut pk = vec![0u8; 32];
    for b in pk.iter_mut() {
        *b = rand::random();
    }
    sqlx::query_scalar("INSERT INTO agents (public_key, display_name) VALUES ($1, $2) RETURNING id")
        .bind(&pk)
        .bind("retarget-test")
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Insert a claim `age_secs` in the past, so atom numbering (created_at, id)
/// is deterministic.
async fn seed_claim(pool: &PgPool, agent: Uuid, content: &str, age_secs: i64) -> Uuid {
    let hash = epigraph_crypto::ContentHasher::hash(content.as_bytes());
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, agent_id, truth_value, created_at) \
         VALUES ($1, $2, $3, 0.5, now() - make_interval(secs => $4)) RETURNING id",
    )
    .bind(content)
    .bind(hash.as_slice())
    .bind(agent)
    .bind(age_secs as f64)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn seed_edge(pool: &PgPool, src: Uuid, tgt: Uuid, rel: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', $3) RETURNING id",
    )
    .bind(src)
    .bind(tgt)
    .bind(rel)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// Compound parent + two atoms + a believed source + `source -refutes->
/// parent`.
async fn seed_world(pool: &PgPool) -> World {
    seed_world_with(pool, REL).await
}

async fn seed_world_with(pool: &PgPool, rel: &str) -> World {
    let agent = seed_agent(pool).await;
    let parent = seed_claim(pool, agent, PARENT, 30).await;
    let a0 = seed_claim(pool, agent, ATOM_0, 20).await;
    let a1 = seed_claim(pool, agent, ATOM_1, 10).await;
    seed_edge(pool, parent, a0, "decomposes_to").await;
    seed_edge(pool, parent, a1, "decomposes_to").await;
    let source = seed_claim(pool, agent, SOURCE, 5).await;
    // A source with no belief interval is `SourceFactorless` and wires
    // nothing; give it one so the DS assertion is meaningful.
    sqlx::query("UPDATE claims SET belief = 0.8, plausibility = 0.9 WHERE id = $1")
        .bind(source)
        .execute(pool)
        .await
        .unwrap();
    let parent_edge = seed_edge(pool, source, parent, rel).await;
    World {
        agent,
        parent,
        atoms: [a0, a1],
        source,
        parent_edge,
    }
}

/// The two production handlers the retarget client calls, on a real socket,
/// behind a request counter.
async fn serve_api(pool: &PgPool, agent: Uuid) -> (EdgeApiClient, Arc<AtomicUsize>) {
    let state = AppState::with_scoped_pool(
        viewer_fixture::scoped_pool(pool).await,
        ApiConfig::default(),
    );
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_mw = hits.clone();
    let app = Router::new()
        .route("/api/v1/edges", post(routes::edges::create_edge))
        .route("/api/v1/edges/:id", patch(routes::edges::patch_edge))
        .layer(axum::middleware::from_fn(
            move |req: Request, next: Next| {
                let hits = hits_mw.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    next.run(req).await
                }
            },
        ))
        // The bearer middleware installs this in production. The principal is
        // a REAL agents row: the edge perspective the auto-wire creates is
        // signed by the source claim's agent, and a phantom principal would
        // turn an FK failure inside the swallowed auto-wire into a silently
        // missing BBA.
        .layer(axum::Extension(
            epigraph_api::middleware::bearer::AuthContext {
                client_id: agent,
                agent_id: Some(agent),
                owner_id: Some(agent),
                client_type: epigraph_api::middleware::bearer::ClientType::Service,
                scopes: vec![
                    "epigraph:write".to_string(),
                    "epigraph:read".to_string(),
                    "claims:read".to_string(),
                    "claims:write".to_string(),
                    "edges:write".to_string(),
                ],
                jti: Uuid::new_v4(),
            },
        ))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });
    (
        EdgeApiClient {
            http: reqwest::Client::new(),
            api_base: format!("http://{addr}"),
            token: "test-token".to_string(),
        },
        hits,
    )
}

fn fixture(answer: serde_json::Value) -> FixtureLlmClient {
    FixtureLlmClient::from_json(&serde_json::json!({ SOURCE: answer })).unwrap()
}

fn manifest_path() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("retarget-manifest-{}.jsonl", Uuid::new_v4()))
}

fn opts(apply: bool) -> RetargetOptions {
    RetargetOptions {
        include_marked: false,
        limit: 100,
        batch_size: 10,
        apply,
    }
}

async fn edges_between(
    pool: &PgPool,
    src: Uuid,
    tgt: Uuid,
    rel: &str,
) -> Vec<(Uuid, serde_json::Value)> {
    sqlx::query_as(
        // Case-insensitive, so a wrongly-spelled duplicate is still counted.
        "SELECT id, properties FROM edges WHERE source_id = $1 AND target_id = $2 \
         AND lower(relationship) = lower($3) ORDER BY created_at, id",
    )
    .bind(src)
    .bind(tgt)
    .bind(rel)
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn count(pool: &PgPool, sql: &str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(pool).await.unwrap()
}

/// Row counts of every table an apply could touch, plus the in-process event
/// store's events that mention this world (the store is process-global and
/// other tests share it, so only this world's events are counted).
async fn snapshot(pool: &PgPool, w: &World) -> Vec<(String, i64)> {
    let mut out = Vec::new();
    for t in [
        "edges",
        "claims",
        "mass_functions",
        "claim_frames",
        "factors",
        "provenance_log",
        "events",
        "perspectives",
    ] {
        out.push((
            t.to_string(),
            count(pool, &format!("SELECT COUNT(*) FROM {t}")).await,
        ));
    }
    let (events, _) = epigraph_api::routes::events::global_event_store()
        .list(&epigraph_api::routes::events::EventFilter {
            since: None,
            event_type: None,
            limit: Some(1000),
            offset: None,
        })
        .await;
    let mine = events
        .iter()
        .filter(|e| {
            let p = e.payload.to_string();
            p.contains(&w.source.to_string()) || p.contains(&w.parent_edge.to_string())
        })
        .count();
    out.push(("in_memory_events_for_world".to_string(), mine as i64));
    out
}

/// Every relationship that is NOT held must be sent in a spelling the API
/// accepts, and a relationship is held EXACTLY while the API refuses its
/// lower-case spelling. Pinned against the handler's own whitelist, so the day
/// `routes/edges.rs` accepts lower-case `contradicts` this fails and tells the
/// reader to release the hold (`retarget::HELD_RELATIONSHIPS`).
#[test]
fn the_hold_tracks_the_edges_route_whitelist() {
    use epigraph_cli::retarget::{api_relationship, hold_reason};
    for stored in [
        "contradicts",
        "CONTRADICTS",
        "Contradicts",
        "refutes",
        "REFUTES",
    ] {
        let sent = api_relationship(stored);
        assert_eq!(
            sent,
            stored.to_ascii_lowercase(),
            "atom edges are stored in the lower-case spelling exact-case readers match"
        );
        assert_eq!(
            hold_reason(stored).is_some(),
            !routes::edges::is_valid_relationship(&sent),
            "{stored}: held={} but POST /api/v1/edges accepts {sent:?}={}; \
             release or add the hold in retarget::HELD_RELATIONSHIPS",
            hold_reason(stored).is_some(),
            routes::edges::is_valid_relationship(&sent),
        );
    }
}

/// A `contradicts` parent edge is HELD on apply: the LLM plan is still made
/// (the dry run shows it), but nothing crosses the socket, no row is written,
/// the parent stays unmarked, and the entry says why.
#[sqlx::test(migrations = "../../migrations")]
async fn contradicts_retargets_are_held_and_write_nothing(pool: PgPool) {
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let w = seed_world_with(&pool, "contradicts").await;
    let (api, hits) = serve_api(&pool, w.agent).await;
    let llm = fixture(serde_json::json!({"atoms": [1]}));
    let before = snapshot(&pool, &w).await;
    let manifest = manifest_path();

    let run = run_retarget(&pool, &viewer, &llm, Some(&api), &manifest, opts(true))
        .await
        .unwrap();

    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "a held retarget sends no request"
    );
    assert_eq!(
        snapshot(&pool, &w).await,
        before,
        "a held retarget writes nothing"
    );
    assert_eq!(
        run.plan[0].verdict,
        verdict::ATOMS,
        "the plan is still made"
    );
    let applied = &run.applied[0];
    assert!(applied.held, "{applied:?}");
    assert!(!applied.parent_marked);
    assert!(
        applied.errors.iter().any(|e| e.starts_with("HELD")),
        "{:?}",
        applied.errors
    );
    std::fs::remove_file(&manifest).ok();
}

/// THE CORE CLAIM. `--retarget --apply` with the fixture choosing atom 1
/// creates exactly `source -refutes-> atom1` with provenance, wires DS on
/// the atom, creates nothing toward atom 0, KEEPS the parent edge, marked, and
/// recall's dispute signal (`dispute_batch`) now sees the atom as disputed.
#[sqlx::test(migrations = "../../migrations")]
async fn apply_moves_the_conflict_onto_the_chosen_atom_with_ds_wired(pool: PgPool) {
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let w = seed_world(&pool).await;
    let (api, hits) = serve_api(&pool, w.agent).await;
    let llm = fixture(serde_json::json!({"atoms": [1]}));
    let manifest = manifest_path();

    let run = run_retarget(&pool, &viewer, &llm, Some(&api), &manifest, opts(true))
        .await
        .unwrap();

    assert_eq!(llm.call_count(), 1);
    assert_eq!(run.plan.len(), 1);
    assert_eq!(run.plan[0].verdict, verdict::ATOMS);
    assert_eq!(
        run.plan[0].chosen_atom_ids,
        vec![w.atoms[1]],
        "index 1 = the newer atom"
    );
    assert_eq!(run.applied.len(), 1);
    let applied = &run.applied[0];
    assert_eq!(applied.created_edge_ids.len(), 1, "{applied:?}");
    assert!(applied.existing_edge_ids.is_empty());
    assert!(applied.errors.is_empty(), "{:?}", applied.errors);
    let new_edge = applied.created_edge_ids[0];

    // Exactly one source->atom1 edge, with the provenance properties.
    let to_atom1 = edges_between(&pool, w.source, w.atoms[1], REL).await;
    assert_eq!(to_atom1.len(), 1);
    assert_eq!(to_atom1[0].0, new_edge);
    let props = &to_atom1[0].1;
    assert_eq!(
        props["retargeted_from_edge"],
        serde_json::json!(w.parent_edge)
    );
    assert_eq!(props["from_parent"], serde_json::json!(w.parent));
    assert_eq!(props["method"], serde_json::json!("llm-retarget"));
    assert_eq!(props["model"], serde_json::json!("fixture"));
    // Nothing toward the atom the source does NOT dispute.
    assert!(edges_between(&pool, w.source, w.atoms[0], REL)
        .await
        .is_empty());

    // DS wired on the ATOM: a mass_functions row keyed by the new edge.
    let bba_on_atom: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mass_functions WHERE claim_id = $1 AND perspective_id = $2",
    )
    .bind(w.atoms[1])
    .bind(new_edge)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        bba_on_atom, 1,
        "the API create->wire path must put a BBA on the atom"
    );
    assert_eq!(applied.ds_wired_edge_ids, vec![new_edge]);

    // Stored in the exact spelling every exact-case reader matches, so the
    // atom is disputed where recall looks.
    let stored: String = sqlx::query_scalar("SELECT relationship FROM edges WHERE id = $1")
        .bind(new_edge)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(stored, REL);
    let disputes = epigraph_db::ClaimRepository::dispute_batch(&pool, &viewer, &[w.atoms[1]])
        .await
        .unwrap();
    assert_eq!(
        disputes.get(&w.atoms[1]).map(|d| d.dispute_count),
        Some(1),
        "dispute_batch must report the retargeted atom as disputed"
    );

    // The parent edge is KEPT (in force) and MARKED with the atom edge.
    let parent_rows = edges_between(&pool, w.source, w.parent, REL).await;
    assert_eq!(parent_rows.len(), 1);
    assert_eq!(parent_rows[0].0, w.parent_edge);
    assert_eq!(
        parent_rows[0].1["retargeted_to"],
        serde_json::json!([new_edge])
    );
    let in_force: bool = sqlx::query_scalar("SELECT valid_to IS NULL FROM edges WHERE id = $1")
        .bind(w.parent_edge)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(in_force, "the parent edge must not be retired");
    assert!(applied.parent_marked);

    // One POST + one PATCH crossed the socket.
    assert_eq!(hits.load(Ordering::SeqCst), 2);

    // The manifest carries the plan line AND the applied line with the id.
    let raw = std::fs::read_to_string(&manifest).unwrap();
    assert_eq!(raw.lines().count(), 2, "{raw}");
    assert!(raw.lines().nth(1).unwrap().contains(&new_edge.to_string()));
    std::fs::remove_file(&manifest).ok();
}

/// Idempotency guard 1: a re-run after a successful apply finds the parent
/// marked, plans NOTHING (no LLM call), sends nothing, and creates nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn rerun_after_apply_calls_no_llm_and_creates_nothing(pool: PgPool) {
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let w = seed_world(&pool).await;
    let (api, hits) = serve_api(&pool, w.agent).await;
    let llm = fixture(serde_json::json!({"atoms": [1]}));

    let m1 = manifest_path();
    run_retarget(&pool, &viewer, &llm, Some(&api), &m1, opts(true))
        .await
        .unwrap();
    let before = snapshot(&pool, &w).await;
    let calls_before = llm.call_count();
    let hits_before = hits.load(Ordering::SeqCst);

    let m2 = manifest_path();
    let rerun = run_retarget(&pool, &viewer, &llm, Some(&api), &m2, opts(true))
        .await
        .unwrap();

    assert!(
        rerun.plan.is_empty(),
        "a marked parent edge must not be re-planned"
    );
    assert_eq!(
        llm.call_count(),
        calls_before,
        "re-run must make no LLM call"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        hits_before,
        "re-run must send nothing"
    );
    assert_eq!(
        snapshot(&pool, &w).await,
        before,
        "re-run must write nothing"
    );
    assert_eq!(
        edges_between(&pool, w.source, w.atoms[1], REL).await.len(),
        1
    );
    std::fs::remove_file(&m1).ok();
    std::fs::remove_file(&m2).ok();
}

/// Idempotency guard 2: the atom edge exists but the parent is NOT marked
/// (a run whose PATCH failed). A re-run re-plans, but adopts the existing atom
/// edge instead of creating a second one, and re-marks the parent with it.
#[sqlx::test(migrations = "../../migrations")]
async fn unmarked_parent_with_an_existing_atom_edge_creates_no_duplicate(pool: PgPool) {
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let w = seed_world(&pool).await;
    let (api, _hits) = serve_api(&pool, w.agent).await;
    let llm = fixture(serde_json::json!({"atoms": [1]}));

    let m1 = manifest_path();
    let first = run_retarget(&pool, &viewer, &llm, Some(&api), &m1, opts(true))
        .await
        .unwrap();
    let atom_edge = first.applied[0].created_edge_ids[0];
    // Simulate the lost PATCH.
    sqlx::query("UPDATE edges SET properties = properties - 'retargeted_to' WHERE id = $1")
        .bind(w.parent_edge)
        .execute(&pool)
        .await
        .unwrap();
    let edges_before = count(&pool, "SELECT COUNT(*) FROM edges").await;

    let m2 = manifest_path();
    let second = run_retarget(&pool, &viewer, &llm, Some(&api), &m2, opts(true))
        .await
        .unwrap();

    assert_eq!(
        second.plan.len(),
        1,
        "an unmarked parent edge is re-planned"
    );
    let applied = &second.applied[0];
    assert!(applied.created_edge_ids.is_empty(), "{applied:?}");
    assert_eq!(applied.existing_edge_ids, vec![atom_edge]);
    assert_eq!(
        count(&pool, "SELECT COUNT(*) FROM edges").await,
        edges_before
    );
    assert_eq!(
        edges_between(&pool, w.source, w.atoms[1], REL).await.len(),
        1,
        "exactly one source->atom edge after two applies"
    );
    let marked = &edges_between(&pool, w.source, w.parent, REL).await[0].1;
    assert_eq!(marked["retargeted_to"], serde_json::json!([atom_edge]));
    std::fs::remove_file(&m1).ok();
    std::fs::remove_file(&m2).ok();
}

/// The dry run (the binary's DEFAULT) calls the LLM and writes the manifest,
/// and writes NOTHING else: no HTTP request, no row in any table the apply
/// path touches, no event — even though it is handed a live API client.
#[sqlx::test(migrations = "../../migrations")]
async fn dry_run_calls_the_llm_and_writes_nothing(pool: PgPool) {
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let w = seed_world(&pool).await;
    let (api, hits) = serve_api(&pool, w.agent).await;
    let llm = fixture(serde_json::json!({"atoms": [0, 1]}));
    let before = snapshot(&pool, &w).await;
    let manifest = manifest_path();

    let run = run_retarget(&pool, &viewer, &llm, Some(&api), &manifest, opts(false))
        .await
        .unwrap();

    assert_eq!(llm.call_count(), 1, "the dry-run plan is a REAL LLM plan");
    assert_eq!(run.plan[0].chosen_atom_ids, vec![w.atoms[0], w.atoms[1]]);
    // The observable effects first, so a broken gate fails on WHAT it wrote.
    assert_eq!(
        snapshot(&pool, &w).await,
        before,
        "dry run must write nothing"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "dry run must send no request"
    );
    assert!(run.applied.is_empty());
    let parent_props = &edges_between(&pool, w.source, w.parent, REL).await[0].1;
    assert!(parent_props.get("retargeted_to").is_none());
    let raw = std::fs::read_to_string(&manifest).unwrap();
    assert_eq!(raw.lines().count(), 1, "one plan line, no applied line");
    std::fs::remove_file(&manifest).ok();
}

/// `whole`, `unclear` and a malformed answer each leave the edge on the
/// parent, unmarked, with no request sent; each is labelled in the plan.
#[sqlx::test(migrations = "../../migrations")]
async fn whole_unclear_and_malformed_leave_the_parent_edge_untouched(pool: PgPool) {
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let w = seed_world(&pool).await;
    let (api, hits) = serve_api(&pool, w.agent).await;
    for (answer, expect) in [
        (serde_json::json!("whole"), verdict::WHOLE),
        (serde_json::json!("unclear"), verdict::UNCLEAR),
        (serde_json::json!({"atoms": [7]}), verdict::MALFORMED),
        (serde_json::json!({"atoms": []}), verdict::MALFORMED),
    ] {
        let before = snapshot(&pool, &w).await;
        let llm = fixture(answer.clone());
        let manifest = manifest_path();
        let run = run_retarget(&pool, &viewer, &llm, Some(&api), &manifest, opts(true))
            .await
            .unwrap();
        assert_eq!(run.plan[0].verdict, expect, "{answer}");
        assert!(run.applied.is_empty(), "{answer}: no action");
        assert_eq!(
            snapshot(&pool, &w).await,
            before,
            "{answer}: nothing written"
        );
        std::fs::remove_file(&manifest).ok();
    }
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

/// A RETIRED source->atom edge is a retraction: the pass must not resurrect
/// it (the API's `if_not_exists` would hand back the dead row, which never
/// wires), and must say so.
#[sqlx::test(migrations = "../../migrations")]
async fn a_retired_atom_edge_blocks_the_retarget_instead_of_being_resurrected(pool: PgPool) {
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let w = seed_world(&pool).await;
    let (api, hits) = serve_api(&pool, w.agent).await;
    let retired = seed_edge(&pool, w.source, w.atoms[1], REL).await;
    sqlx::query("UPDATE edges SET valid_to = now() - interval '1 day' WHERE id = $1")
        .bind(retired)
        .execute(&pool)
        .await
        .unwrap();
    let llm = fixture(serde_json::json!({"atoms": [1]}));
    let manifest = manifest_path();

    let run = run_retarget(&pool, &viewer, &llm, Some(&api), &manifest, opts(true))
        .await
        .unwrap();

    let applied = &run.applied[0];
    assert_eq!(applied.blocked_by_retired_edge, vec![w.atoms[1]]);
    assert!(applied.created_edge_ids.is_empty());
    assert!(
        !applied.parent_marked,
        "nothing resolved, so nothing is marked"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    assert_eq!(
        edges_between(&pool, w.source, w.atoms[1], REL).await.len(),
        1,
        "still only the retired edge"
    );
    std::fs::remove_file(&manifest).ok();
}

/// A manifest entry as an operator could hand-edit it.
fn entry_for(
    w: &World,
    edge: Uuid,
    rel: &str,
    parent: Uuid,
    atoms: Vec<Uuid>,
) -> RetargetPlanEntry {
    RetargetPlanEntry {
        kind: RetargetPlanEntry::KIND.into(),
        edge_id: edge,
        relationship: rel.into(),
        source_id: w.source,
        parent_id: parent,
        atoms: atoms
            .iter()
            .enumerate()
            .map(|(index, a)| AtomRef { index, atom_id: *a })
            .collect(),
        verdict: verdict::ATOMS.into(),
        reason: None,
        chosen_atom_ids: atoms,
        model: "hand-edited".into(),
    }
}

/// `--retarget --apply-plan` trusts nothing in the manifest the live graph
/// does not confirm. Each tampered entry is refused with a reason, sends no
/// request, and writes no row:
/// * a real `supports` edge relabelled as a retarget (would have created a
///   `supports` edge on the atom and stamped `retargeted_to` on it);
/// * an atom of a DIFFERENT parent;
/// * a chosen atom the entry never listed as shown to the model.
#[sqlx::test(migrations = "../../migrations")]
async fn tampered_manifest_entries_are_refused_and_write_nothing(pool: PgPool) {
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let w = seed_world(&pool).await;
    let supports = seed_edge(&pool, w.source, w.parent, "supports").await;
    let other_parent = seed_claim(&pool, w.agent, "Other compound. With two parts.", 40).await;
    let other_atom = seed_claim(&pool, w.agent, "Other atom text here.", 35).await;
    seed_edge(&pool, other_parent, other_atom, "decomposes_to").await;
    let (api, hits) = serve_api(&pool, w.agent).await;
    let before = snapshot(&pool, &w).await;

    let non_conflict = entry_for(&w, supports, "supports", w.parent, vec![w.atoms[0]]);
    let foreign_atom = entry_for(&w, w.parent_edge, REL, w.parent, vec![other_atom]);
    let mut unshown = entry_for(&w, w.parent_edge, REL, w.parent, vec![w.atoms[0]]);
    unshown.chosen_atom_ids = vec![w.atoms[1]];

    let applied = apply_retarget(&pool, &viewer, &api, &[non_conflict, foreign_atom, unshown])
        .await
        .unwrap();

    assert_eq!(applied.len(), 3);
    for a in &applied {
        assert!(
            !a.errors.is_empty(),
            "every tampered entry is refused: {a:?}"
        );
        assert!(a.created_edge_ids.is_empty() && !a.parent_marked, "{a:?}");
    }
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "no request for a refused entry"
    );
    assert_eq!(
        snapshot(&pool, &w).await,
        before,
        "a refused entry writes nothing"
    );
    let supports_props: serde_json::Value =
        sqlx::query_scalar("SELECT properties FROM edges WHERE id = $1")
            .bind(supports)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        supports_props.get("retargeted_to").is_none(),
        "{supports_props}"
    );
}

/// A source claim retired between the reviewed dry run and the apply gains
/// no conflict edge: the apply re-checks both endpoints.
#[sqlx::test(migrations = "../../migrations")]
async fn an_endpoint_retired_after_the_dry_run_is_not_applied(pool: PgPool) {
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let w = seed_world(&pool).await;
    let (api, hits) = serve_api(&pool, w.agent).await;
    let llm = fixture(serde_json::json!({"atoms": [1]}));
    let manifest = manifest_path();
    let dry = run_retarget(&pool, &viewer, &llm, None, &manifest, opts(false))
        .await
        .unwrap();
    assert_eq!(dry.plan[0].chosen_atom_ids, vec![w.atoms[1]]);
    sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(w.source)
        .execute(&pool)
        .await
        .unwrap();

    let applied = apply_retarget(&pool, &viewer, &api, &dry.plan)
        .await
        .unwrap();

    assert!(
        applied[0]
            .errors
            .iter()
            .any(|e| e.contains("no longer current")),
        "{:?}",
        applied[0]
    );
    assert!(applied[0].created_edge_ids.is_empty());
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    assert!(
        edges_between(&pool, w.source, w.atoms[1], REL)
            .await
            .is_empty(),
        "a retired source must not gain a conflict edge"
    );
    std::fs::remove_file(&manifest).ok();
}
