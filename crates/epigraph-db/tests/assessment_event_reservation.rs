//! Migration 250, section 2: the database refuses a `claim.assessed` event
//! that does not describe a slot write made in the same transaction
//! (backlog a278f16d).
//!
//! # What was wrong, measured on the base
//!
//! `claim.assessed` is the assess route's durable writer record: the writer
//! of masses a later call replaces is the `actor_id` of the previous record
//! with the same `mass_function_id`. `EventRepository::RESERVED_EVENT_TYPES`
//! refused the type on the two caller-typed publish surfaces only (REST
//! `POST /api/v1/events`, MCP `publish_event`). Nothing in the database did,
//! so any session holding an application DSN could INSERT a record naming a
//! real slot row's `mass_function_id` and be credited as that row's writer.
//!
//! # What is pinned
//!
//! * an application session cannot insert a `claim.assessed` row naming a
//!   mass function it did not write in the same transaction, nor any
//!   near-miss spelling of the type, nor one with a malformed id (42501,
//!   never 22P02); its other events still land (red on the base: every
//!   forged insert lands);
//! * the assess route's shape still lands on an application session: the
//!   slot upsert and the record in ONE transaction, the record's
//!   `claim_id` / `frame_id` / `owner_agent_id` naming that row and its
//!   `actor_id` equal to `assessed_by`; each mismatch is refused;
//! * a maintenance session may still write one.
//!
//! Every app-role check runs on a real `epigraph_app` session stamped as
//! `ScopedPool::begin_as` would stamp it: the superuser fixture pool would be
//! admitted by `epigraph_bypass()` and prove nothing.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::visibility::Viewer;
use epigraph_db::{EventRepository, MassFunctionRepository};
use sqlx::PgPool;
use uuid::Uuid;

const MASSES: &str = r#"{"0": 0.6, "0,1": 0.4}"#;

fn csv(ids: &[Uuid]) -> String {
    ids.iter()
        .map(Uuid::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// A pool of `epigraph_app` sessions stamped for `agent` (its read set,
/// writable set and principal), as `ScopedPool::begin_as` stamps them.
async fn app_pool_for(pool: &PgPool, agent: Uuid) -> PgPool {
    use sqlx::Executor;
    let v = Viewer::resolve(pool, agent).await.expect("resolve viewer");
    let groups = csv(v.group_bind().expect("scoped viewer"));
    let writable = csv(v.writable_groups());
    assert!(!writable.is_empty(), "the agent writes somewhere");
    let principal = agent.to_string();
    let url = fixture::database_url_for(pool).await;
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .after_connect(move |conn, _meta| {
            let (groups, writable, principal) =
                (groups.clone(), writable.clone(), principal.clone());
            Box::pin(async move {
                conn.execute("SET SESSION AUTHORIZATION epigraph_app")
                    .await?;
                sqlx::query(
                    "SELECT set_config('epigraph.group_ids', $1, false), \
                            set_config('epigraph.writable_group_ids', $2, false), \
                            set_config('epigraph.principal_id', $3, false)",
                )
                .bind(groups)
                .bind(writable)
                .bind(principal)
                .execute(&mut *conn)
                .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .expect("stamped app pool")
}

async fn maintenance_pool(pool: &PgPool) -> PgPool {
    use sqlx::Executor;
    let url = fixture::database_url_for(pool).await;
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .after_connect(|conn, _meta| {
            Box::pin(async move {
                conn.execute("SET SESSION AUTHORIZATION epigraph_maintenance")
                    .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .expect("maintenance pool")
}

fn code(r: Result<Uuid, sqlx::Error>) -> Result<Uuid, String> {
    r.map_err(|e| {
        e.as_database_error()
            .and_then(|d| d.code().map(|c| c.into_owned()))
            .unwrap_or_else(|| e.to_string())
    })
}

struct World {
    agent: Uuid,
    other: Uuid,
    claim: Uuid,
    other_claim: Uuid,
    frame: Uuid,
}

async fn world(pool: &PgPool, tag: &str) -> World {
    let (agent, _) = fixture::seed_agent_with_group(pool, &format!("{tag}-agent")).await;
    let (other, _) = fixture::seed_agent_with_group(pool, &format!("{tag}-other")).await;
    let claim = fixture::seed_public_claim(pool, agent, &format!("{tag} claim")).await;
    let other_claim = fixture::seed_public_claim(pool, agent, &format!("{tag} other")).await;
    let frame: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) \
         VALUES ('t62 ' || gen_random_uuid(), ARRAY['TRUE','FALSE']) RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("frame");
    World {
        agent,
        other,
        claim,
        other_claim,
        frame,
    }
}

/// The record the assess route writes for `mf`.
fn record(w: &World, mf: Uuid, owner: Uuid, by: Uuid) -> serde_json::Value {
    serde_json::json!({
        "claim_id": w.claim,
        "frame_id": w.frame,
        "mass_function_id": mf,
        "owner_agent_id": owner,
        "assessed_by": by,
        "replaced": false,
        "contested": false,
    })
}

async fn store<'e, E: sqlx::PgExecutor<'e>>(ex: E, w: &World, owner: Uuid) -> Uuid {
    let masses: serde_json::Value = serde_json::from_str(MASSES).expect("masses");
    MassFunctionRepository::store_with_perspective(
        ex,
        w.claim,
        w.frame,
        Some(owner),
        None,
        &masses,
        None,
        Some("discount"),
        None,
        None,
        "unknown",
        None,
    )
    .await
    .expect("the slot write")
}

async fn assessed_rows(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM events \
          WHERE lower(btrim(event_type, E' \\t\\n\\r')) = 'claim.assessed'",
    )
    .fetch_one(pool)
    .await
    .expect("count")
}

/// The red test for a278f16d: on the base every insert below lands.
#[sqlx::test(migrations = "../../migrations")]
async fn an_application_session_cannot_forge_an_assessment_record(pool: PgPool) {
    let w = world(&pool, "t62-forge").await;
    // A real slot row, written (and committed) by its owner earlier.
    let real = store(&pool, &w, w.agent).await;
    let app = app_pool_for(&pool, w.other).await;

    // The forgery the backlog item names: a record naming that real row,
    // every field consistent with it, filed by a stranger.
    let forged = record(&w, real, w.agent, w.other);
    assert_eq!(
        code(EventRepository::insert(&app, "claim.assessed", Some(w.other), &forged).await),
        Err("42501".to_string()),
        "a record of a slot row this transaction did not write"
    );
    // The same as a raw statement, so no repository path is assumed.
    let raw: Result<Uuid, sqlx::Error> = sqlx::query_scalar(
        "INSERT INTO events (event_type, actor_id, payload, graph_version) \
         VALUES ('claim.assessed', $1, $2, nextval('events_graph_version_seq')) RETURNING id",
    )
    .bind(w.other)
    .bind(&forged)
    .fetch_one(&app)
    .await;
    assert_eq!(code(raw), Err("42501".to_string()), "raw INSERT");
    // Near-miss spellings are refused outright: no reader has a reason to
    // accept one, and the API layer refuses them too.
    for spelling in ["  claim.assessed\t", "Claim.Assessed", "CLAIM.ASSESSED\n"] {
        assert_eq!(
            code(EventRepository::insert(&app, spelling, Some(w.other), &forged).await),
            Err("42501".to_string()),
            "spelling {spelling:?}"
        );
    }
    // Malformed or missing ids are a refusal, not a cast error.
    for payload in [
        serde_json::json!({ "mass_function_id": "not-a-uuid" }),
        serde_json::json!({ "claim_id": w.claim }),
        serde_json::json!("a string"),
    ] {
        assert_eq!(
            code(EventRepository::insert(&app, "claim.assessed", Some(w.other), &payload).await),
            Err("42501".to_string()),
            "payload {payload}"
        );
    }
    // Control: the guard is not a blanket refusal of the application role.
    EventRepository::insert(&app, "claim.created", Some(w.other), &forged)
        .await
        .expect("an ordinary event still lands");
    app.close().await;

    assert_eq!(assessed_rows(&pool).await, 0, "no assessment record landed");
}

/// The assess route's own shape lands on an application session, and every
/// field that ties the record to the row is checked.
#[sqlx::test(migrations = "../../migrations")]
async fn an_application_session_records_an_assessment_of_its_own_slot_write(pool: PgPool) {
    let w = world(&pool, "t62-own").await;
    let app = app_pool_for(&pool, w.agent).await;

    // The route: slot upsert and record in ONE transaction.
    let mut tx = app.begin().await.expect("begin");
    let mf = store(&mut *tx, &w, w.agent).await;
    EventRepository::insert_on(
        &mut *tx,
        "claim.assessed",
        Some(w.agent),
        &record(&w, mf, w.agent, w.agent),
    )
    .await
    .expect("the record of this transaction's own slot write lands");
    tx.commit().await.expect("commit");
    assert_eq!(assessed_rows(&pool).await, 1);

    // Each field that ties the record to the row, broken one at a time, in
    // a transaction that did write the row.
    let mut cases: Vec<(&str, Option<Uuid>, serde_json::Value)> = Vec::new();
    let mut wrong_claim = record(&w, Uuid::nil(), w.agent, w.agent);
    wrong_claim["claim_id"] = serde_json::json!(w.other_claim);
    cases.push(("another claim", Some(w.agent), wrong_claim));
    let mut wrong_frame = record(&w, Uuid::nil(), w.agent, w.agent);
    wrong_frame["frame_id"] = serde_json::json!(Uuid::new_v4());
    cases.push(("another frame", Some(w.agent), wrong_frame));
    cases.push((
        "another owner",
        Some(w.agent),
        record(&w, Uuid::nil(), w.other, w.agent),
    ));
    cases.push((
        "actor is not assessed_by",
        Some(w.other),
        record(&w, Uuid::nil(), w.agent, w.agent),
    ));
    cases.push(("no actor", None, record(&w, Uuid::nil(), w.agent, w.agent)));
    for (why, actor, mut payload) in cases {
        let mut tx = app.begin().await.expect("begin");
        let mf = store(&mut *tx, &w, w.agent).await;
        payload["mass_function_id"] = serde_json::json!(mf);
        let r = EventRepository::insert_on(&mut *tx, "claim.assessed", actor, &payload).await;
        assert_eq!(code(r), Err("42501".to_string()), "{why}");
        tx.rollback().await.expect("rollback");
    }

    // A row this session wrote in an EARLIER transaction is no longer its
    // to record, even with every field right.
    let mut tx = app.begin().await.expect("begin");
    let r = EventRepository::insert_on(
        &mut *tx,
        "claim.assessed",
        Some(w.agent),
        &record(&w, mf, w.agent, w.agent),
    )
    .await;
    assert_eq!(
        code(r),
        Err("42501".to_string()),
        "a slot row committed earlier"
    );
    tx.rollback().await.expect("rollback");
    app.close().await;

    assert_eq!(assessed_rows(&pool).await, 1, "only the genuine record");
}

/// The maintenance role is trusted to write one (repair and backfill).
#[sqlx::test(migrations = "../../migrations")]
async fn a_maintenance_session_may_record_an_assessment(pool: PgPool) {
    let w = world(&pool, "t62-maint").await;
    let real = store(&pool, &w, w.agent).await;
    let maint = maintenance_pool(&pool).await;
    EventRepository::insert(
        &maint,
        "claim.assessed",
        Some(w.agent),
        &record(&w, real, w.agent, w.agent),
    )
    .await
    .expect("a maintenance session writes an assessment record");
    maint.close().await;
    assert_eq!(assessed_rows(&pool).await, 1);
}
