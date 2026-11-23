#![cfg(feature = "db")]
//! `POST /api/v1/claims/:id/assess` records WHO wrote each assessment, and
//! whether it replaced and contested the owner's earlier one, durably
//! (backlog 4a7f90f8, part 1).
//!
//! # What was wrong, measured on the branch before this file
//!
//! The slot row stores the OWNER (the caller's human) as `source_agent_id`.
//! The agent that actually made the call appeared only in the response
//! (`assessed_by`), and the replacement and contest only in
//! `replaced_assessments`. Once the response was gone nothing said which of
//! a human's agents wrote the slot's current masses, which one wrote the
//! masses it overwrote, or that the overwrite reversed the verdict.
//!
//! # The oracle
//!
//! Two agents of ONE human, so the writer is never the owner: an
//! implementation that recorded the owner (what the row already holds) as
//! the writer fails the `actor_id` assertions. The first agent supports, the
//! second refutes (a contest), then the first refutes too, agreeing with the
//! second (a replacement that is NOT a contest), so `contested` cannot be a
//! constant.
//! Every fact is read back from the `events` table alone, never from the
//! response, and then cross-checked against the response so the two cannot
//! disagree.

mod viewer_fixture;

use axum::extract::{Path, State};
use axum::Json;
use epigraph_api::errors::ApiError;
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::routes::assess::{assess_claim, AssessClaimRequest, AssessClaimResponse};
use epigraph_api::routes::events::{create_event, CreateEventRequest};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{seed_agent_with_group, seed_human_operator, seed_public_claim};

fn request(supports: bool, confidence: f64) -> AssessClaimRequest {
    serde_json::from_value(serde_json::json!({
        "evidence_type": "empirical",
        "methodology": "instrumental",
        "confidence": confidence,
        "supports": supports,
    }))
    .expect("AssessClaimRequest deserializes")
}

async fn assess(
    pool: &PgPool,
    caller: Uuid,
    claim: Uuid,
    req: AssessClaimRequest,
) -> AssessClaimResponse {
    let viewer = Viewer::resolve(pool, caller).await.expect("resolve caller");
    let state = AppState::with_db(pool.clone(), ApiConfig::default());
    let Json(resp) = assess_claim(
        write_scope(),
        ViewerExtractor(viewer),
        State(state),
        Path(claim),
        Json(req),
    )
    .await
    .unwrap_or_else(|e| panic!("assess_claim failed: {e:?}"));
    resp
}

async fn link(pool: &PgPool, agent: Uuid, human: Uuid) {
    let mut conn = pool.acquire().await.expect("acquire");
    let out = epigraph_db::AgentRepository::link_operator(&mut conn, agent, human)
        .await
        .expect("link the agent to its human");
    assert!(out.link_live, "{out:?}");
}

/// The assessment events naming `claim`, in write order. `graph_version` is
/// drawn under the slot lock, so it orders one slot's writes; `created_at`
/// does not (it is not commit-ordered).
async fn assessment_events(pool: &PgPool, claim: Uuid) -> Vec<(Option<Uuid>, serde_json::Value)> {
    sqlx::query_as(
        "SELECT actor_id, payload FROM events \
          WHERE event_type = 'claim.assessed' AND payload->>'claim_id' = $1::text \
          ORDER BY graph_version",
    )
    .bind(claim)
    .fetch_all(pool)
    .await
    .expect("read assessment events")
}

fn uuid_at(payload: &serde_json::Value, key: &str) -> Option<Uuid> {
    payload
        .get(key)
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
}

fn bool_at(payload: &serde_json::Value, key: &str) -> bool {
    payload
        .get(key)
        .and_then(|v| v.as_bool())
        .unwrap_or_else(|| panic!("payload has no boolean {key:?}: {payload}"))
}

#[sqlx::test(migrations = "../../migrations")]
async fn each_assessment_records_its_writer_and_any_contest_durably(pool: PgPool) {
    let (author, _) = seed_agent_with_group(&pool, "assess-writer-author").await;
    let (human, _) = seed_human_operator(&pool, "assess-writer-human").await;
    let (one, _) = seed_agent_with_group(&pool, "assess-writer-one").await;
    let (two, _) = seed_agent_with_group(&pool, "assess-writer-two").await;
    // An agent with no human: its own owner, so its own slot row on the claim.
    let (other, _) = seed_agent_with_group(&pool, "assess-writer-other").await;
    link(&pool, one, human).await;
    link(&pool, two, human).await;
    let claim = seed_public_claim(&pool, author, "assess writer record").await;

    let first = assess(&pool, one, claim, request(true, 0.9)).await;
    let second = assess(&pool, two, claim, request(false, 0.6)).await;
    // Interleaved on ANOTHER slot of the same claim, between the human's
    // second and third writes: it is the latest record naming the claim when
    // the third call lands, so a prior-writer rule that ignored
    // `mass_function_id` would credit it with the masses the third call
    // replaced.
    let interleaved = assess(&pool, other, claim, request(true, 0.8)).await;
    let third = assess(&pool, one, claim, request(false, 0.7)).await;
    assert_eq!(
        first.mass_function_id, second.mass_function_id,
        "PREMISE: one human, one slot row"
    );
    assert_eq!(second.mass_function_id, third.mass_function_id);
    assert_ne!(
        interleaved.mass_function_id, third.mass_function_id,
        "PREMISE: the interleaved call writes a different slot row"
    );
    assert!(
        interleaved.replaced_assessments.is_empty(),
        "PREMISE: the interleaved call is its slot's first write"
    );
    assert_eq!(
        first.owner_agent_id,
        Some(human),
        "PREMISE: the owner is the human"
    );
    assert!(
        second.replaced_assessments[0].contested,
        "PREMISE: the sibling's refutation reverses the first verdict"
    );
    assert!(
        !third.replaced_assessments[0].contested,
        "PREMISE: the third call agrees with the second"
    );

    let events = assessment_events(&pool, claim).await;
    assert_eq!(
        events.len(),
        4,
        "one durable record per assessment call, got {events:?}"
    );

    // Who wrote each call: the AGENT, not the owner the row already names.
    let writers: Vec<Option<Uuid>> = events.iter().map(|(actor, _)| *actor).collect();
    assert_eq!(
        writers,
        vec![Some(one), Some(two), Some(other), Some(one)],
        "each record's actor is the calling agent (human {human})"
    );

    for ((_, payload), resp) in events.iter().zip([&first, &second, &interleaved, &third]) {
        assert_eq!(
            uuid_at(payload, "mass_function_id"),
            Some(resp.mass_function_id)
        );
        assert_eq!(uuid_at(payload, "frame_id"), Some(resp.frame_id));
        assert_eq!(uuid_at(payload, "owner_agent_id"), resp.owner_agent_id);
        assert_eq!(uuid_at(payload, "assessed_by"), resp.assessed_by);
        assert_eq!(
            bool_at(payload, "replaced"),
            !resp.replaced_assessments.is_empty(),
            "{payload}"
        );
        assert_eq!(
            bool_at(payload, "contested"),
            resp.replaced_assessments.iter().any(|r| r.contested),
            "the record and the response must agree on the contest: {payload}"
        );
    }
    for (_, payload) in [&events[0], &events[1], &events[3]] {
        assert_eq!(uuid_at(payload, "owner_agent_id"), Some(human));
    }
    assert_eq!(uuid_at(&events[2].1, "owner_agent_id"), Some(other));
    assert!(!bool_at(&events[0].1, "replaced"));
    assert!(bool_at(&events[1].1, "replaced"));
    assert!(bool_at(&events[1].1, "contested"));
    assert!(!bool_at(&events[2].1, "replaced"));
    assert!(bool_at(&events[3].1, "replaced"));
    assert!(!bool_at(&events[3].1, "contested"));

    // The documented rule, applied to the log alone: the writer of the masses
    // a record replaced is the actor of the latest EARLIER record with the
    // same `mass_function_id`. The second call overwrote agent one's
    // support; the third overwrote agent two's refutation, not the
    // interleaved agent's write on the other slot.
    let prior_writers: Vec<(usize, Option<Uuid>)> = events
        .iter()
        .enumerate()
        .filter(|(_, (_, p))| bool_at(p, "replaced"))
        .map(|(i, (_, p))| {
            let slot = uuid_at(p, "mass_function_id");
            let prior = events[..i]
                .iter()
                .rev()
                .find(|(_, q)| uuid_at(q, "mass_function_id") == slot)
                .unwrap_or_else(|| panic!("record {i} replaced masses with no earlier record"))
                .0;
            (i, prior)
        })
        .collect();
    assert_eq!(
        prior_writers,
        vec![(1, Some(one)), (3, Some(two))],
        "the replaced masses' writers, read from the log"
    );
}

/// `claim.assessed` is the server's own record, so neither caller-typed
/// publish path may file one. The scenario the review measured: an agent
/// files a `claim.assessed` naming a real slot row, which the prior-writer
/// rule would then read as the slot's latest record, crediting the next real
/// overwrite as replacing the forger's masses. Padded and re-cased spellings
/// are refused too, and an ordinary type still publishes, so the refusal is
/// about the type and not a broken path.
#[sqlx::test(migrations = "../../migrations")]
async fn the_rest_publish_path_refuses_a_forged_assessment_record(pool: PgPool) {
    let (author, _) = seed_agent_with_group(&pool, "assess-writer-forge-author").await;
    let (writer, _) = seed_agent_with_group(&pool, "assess-writer-forge-writer").await;
    let (forger, _) = seed_agent_with_group(&pool, "assess-writer-forge-forger").await;
    let claim = seed_public_claim(&pool, author, "assess writer record: forgery").await;
    let real = assess(&pool, writer, claim, request(true, 0.9)).await;

    // The forger posts AS ITSELF: since backlog 1dea9589 a body `actor_id`
    // must be the caller (or an agent it speaks for), and the actor is decided
    // on a viewer-stamped read, so the state carries a scoped pool.
    let state = AppState::with_scoped_pool(
        viewer_fixture::scoped_pool(&pool).await,
        ApiConfig::default(),
    );
    let post = |event_type: &str| {
        let body: CreateEventRequest = serde_json::from_value(serde_json::json!({
            "event_type": event_type,
            "actor_id": forger,
            "payload": {
                "claim_id": claim,
                "frame_id": real.frame_id,
                "mass_function_id": real.mass_function_id,
                "owner_agent_id": real.owner_agent_id,
                "assessed_by": forger,
                "replaced": true,
                "contested": true,
            },
        }))
        .expect("CreateEventRequest deserializes");
        let state = state.clone();
        let pool = pool.clone();
        async move {
            let viewer = Viewer::resolve(&pool, forger)
                .await
                .expect("resolve forger");
            create_event(
                write_scope_as(forger),
                ViewerExtractor(viewer),
                State(state),
                Json(body),
            )
            .await
        }
    };

    for spelling in ["claim.assessed", "  claim.assessed\t", "Claim.Assessed"] {
        let refused = post(spelling).await;
        assert!(
            matches!(refused, Err(ApiError::ValidationError { ref field, .. }) if field == "event_type"),
            "a caller must not file {spelling:?}: {refused:?}"
        );
    }
    let filed: Vec<Option<Uuid>> = sqlx::query_scalar(
        "SELECT actor_id FROM events \
          WHERE lower(btrim(event_type, E' \\t\\n\\r')) = 'claim.assessed' \
          ORDER BY graph_version",
    )
    .fetch_all(&pool)
    .await
    .expect("read assessment records");
    assert_eq!(
        filed,
        vec![Some(writer)],
        "only the route's own record exists; nothing a caller posted was written"
    );

    let Json(ordinary) = post("review.note")
        .await
        .expect("an ordinary event type still publishes");
    assert_eq!(ordinary.event_type, "review.note");
}

/// The record is part of the slot write, not a best-effort side effect: when
/// the event INSERT fails, the call is refused AND the slot upsert rolls back.
/// A savepoint-wrapped (log-and-continue) insert would answer 200 with the row
/// stored and no record; a strict insert issued after the slot transaction
/// commits would refuse with the row already stored. Both leave an
/// assessment with no writer on record, which is what this item closes.
#[sqlx::test(migrations = "../../migrations")]
async fn a_failed_record_refuses_the_call_and_stores_no_assessment(pool: PgPool) {
    let (author, _) = seed_agent_with_group(&pool, "assess-writer-strict-author").await;
    let (caller, _) = seed_agent_with_group(&pool, "assess-writer-strict-caller").await;
    let claim = seed_public_claim(&pool, author, "assess writer record: strict").await;
    sqlx::query(
        "CREATE FUNCTION refuse_assessment_event() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN \
           IF NEW.event_type = 'claim.assessed' THEN \
             RAISE EXCEPTION 'test: assessment record refused'; \
           END IF; \
           RETURN NEW; \
         END $$",
    )
    .execute(&pool)
    .await
    .expect("create the refusing trigger function");
    sqlx::query(
        "CREATE TRIGGER refuse_assessment_event BEFORE INSERT ON events \
         FOR EACH ROW EXECUTE FUNCTION refuse_assessment_event()",
    )
    .execute(&pool)
    .await
    .expect("install the refusing trigger");

    let viewer = Viewer::resolve(&pool, caller)
        .await
        .expect("resolve caller");
    let state = AppState::with_db(pool.clone(), ApiConfig::default());
    let result = assess_claim(
        write_scope(),
        ViewerExtractor(viewer),
        State(state),
        Path(claim),
        Json(request(true, 0.9)),
    )
    .await;
    assert!(
        result.is_err(),
        "an assessment whose writer could not be recorded must be refused"
    );
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM mass_functions WHERE claim_id = $1")
        .bind(claim)
        .fetch_one(&pool)
        .await
        .expect("count slot rows");
    assert_eq!(
        rows, 0,
        "the refused call's slot upsert must roll back with its record"
    );
}

/// Re-assessing with the masses the slot already holds files no second
/// record (backlog a278f16d, migration 250).
///
/// Migration 250's `events_assessment_guard` admits a record on an
/// application session only when the same transaction wrote the slot row's
/// masses, and an upsert of identical masses writes none, so a record of it
/// would be refused and the call would answer 500 (that refusal is pinned at
/// the database level by `epigraph-db/tests/assessment_event_reservation.rs::
/// an_identical_reassessment_writes_no_masses_and_is_detected`). The route
/// therefore files no record when `slot_holds_masses` says the slot already
/// holds the masses. This runs on the harness pool, where the guard admits
/// every record, so it isolates the route's decision: red with
/// `assess_claim`'s `masses_unchanged` check removed (a second record lands).
/// A third call with new masses is recorded again.
#[sqlx::test(migrations = "../../migrations")]
async fn an_identical_reassessment_files_no_second_record(pool: PgPool) {
    let (author, _) = seed_agent_with_group(&pool, "assess-same-author").await;
    let (caller, _) = seed_agent_with_group(&pool, "assess-same-caller").await;
    let claim = seed_public_claim(&pool, author, "assess writer record: identical").await;

    let first = assess(&pool, caller, claim, request(true, 0.9)).await;
    assert_eq!(assessment_events(&pool, claim).await.len(), 1);

    let second = assess(&pool, caller, claim, request(true, 0.9)).await;
    assert_eq!(
        second.mass_function_id, first.mass_function_id,
        "PREMISE: the same slot row"
    );
    let events = assessment_events(&pool, claim).await;
    assert_eq!(
        events.len(),
        1,
        "no record of a call that wrote no masses: {events:?}"
    );

    assess(&pool, caller, claim, request(false, 0.7)).await;
    let events = assessment_events(&pool, claim).await;
    assert_eq!(
        events.len(),
        2,
        "a call that changes the masses is recorded"
    );
    assert_eq!(events[1].0, Some(caller));
}

/// The `claims:write` scope the write handlers now take as their first
/// extractor (backlog f00d75ab). A direct handler call stands in for the
/// bearer middleware, so it supplies the scope the route checks.
fn write_scope() -> epigraph_api::middleware::bearer::RequireScopeWrite {
    write_scope_as(uuid::Uuid::new_v4())
}

fn write_scope_as(principal: Uuid) -> epigraph_api::middleware::bearer::RequireScopeWrite {
    epigraph_api::middleware::bearer::RequireScopeWrite(
        epigraph_api::middleware::bearer::AuthContext {
            client_id: principal,
            agent_id: Some(principal),
            owner_id: Some(principal),
            client_type: epigraph_api::middleware::ClientType::Service,
            scopes: vec!["claims:write".to_string()],
            jti: uuid::Uuid::new_v4(),
            family_id: None,
            elevation_claim: None,
            elevation: None,
            admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
            delegated_by: None,
        },
    )
}
