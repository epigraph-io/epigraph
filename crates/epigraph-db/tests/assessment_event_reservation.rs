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
//!   mass function whose masses it did not write in the same transaction,
//!   nor any near-miss spelling of the type (Unicode padding included), nor
//!   one with a malformed id (42501, never 22P02); its other events still
//!   land (red on the base: every forged insert lands);
//! * the assess route's shape still lands on an application session: the
//!   slot upsert and the record in ONE transaction, the record's
//!   `claim_id` / `frame_id` / `owner_agent_id` naming that row and its
//!   `actor_id` equal to `assessed_by`; each mismatch is refused;
//! * a stranger that stamps itself into the slot row's writable group (the
//!   tenancy GUCs are session-settable) and runs a no-op UPDATE of the row,
//!   or writes the `mass_function_masses_writes` stamp itself (no privilege:
//!   42501), still cannot file a record naming it; one that really rewrites
//!   the masses can (the documented residual);
//! * a slot write made under a SAVEPOINT (or a sqlx nested transaction) is
//!   recorded, and one rolled back to its savepoint is not;
//! * the bind is a 64-bit (epoch-aware) comparison: a stamp equal to this
//!   transaction's id modulo 2^32 but from another epoch is refused;
//! * an upsert of identical masses writes no masses, so it cannot be
//!   recorded, and `MassFunctionRepository::slot_holds_masses` says so
//!   before the upsert (the route then files no record);
//! * a maintenance session may still write one (a PIN: it passes on the base
//!   too, where nothing guarded the type).
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
          WHERE epigraph_event_type_norm(event_type) = 'claim.assessed'",
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
    // Unicode padding included: `is_reserved_type` trims with Rust's
    // `str::trim`, which strips NBSP and the U+2000 block, and so must the
    // database (a POSIX `[[:space:]]` trim under a C ctype does not).
    for spelling in [
        "  claim.assessed\t",
        "Claim.Assessed",
        "CLAIM.ASSESSED\n",
        "claim.assessed\u{a0}",
        "\u{2003}claim.assessed",
        "claim.assessed\u{3000}",
    ] {
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

/// The maintenance role is trusted to write one (repair and backfill). A
/// PIN, not a proving test: it passes on the base too, where nothing guarded
/// the type.
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

/// The record the route writes for `mf`, on `w.claim` / `w.frame`.
async fn file_record<'e, E: sqlx::PgExecutor<'e>>(
    ex: E,
    w: &World,
    mf: Uuid,
    owner: Uuid,
    by: Uuid,
) -> Result<Uuid, String> {
    code(
        EventRepository::insert_on(ex, "claim.assessed", Some(by), &record(w, mf, owner, by)).await,
    )
}

/// The slot row's owning group, read on the harness connection.
async fn owner_group_of(pool: &PgPool, mf: Uuid) -> Uuid {
    sqlx::query_scalar("SELECT owner_group_id FROM mass_functions WHERE id = $1")
        .bind(mf)
        .fetch_one(pool)
        .await
        .expect("slot row's owning group")
}

/// The stranger's recipe from the review of the first draft (which bound the
/// record to `xmin`): an application-DSN holder stamps itself into the slot
/// row's writable group, touches the row without changing its masses, and
/// files a record naming it. Red on that draft: the no-op UPDATE gave the row
/// this transaction's `xmin`, and the forged record landed.
#[sqlx::test(migrations = "../../migrations")]
async fn a_stranger_cannot_claim_a_slot_row_by_touching_it(pool: PgPool) {
    let w = world(&pool, "t62-touch").await;
    // The victim writes its slot row and its record, as the route does.
    let victim = app_pool_for(&pool, w.agent).await;
    let mut tx = victim.begin().await.expect("begin");
    let real = store(&mut *tx, &w, w.agent).await;
    file_record(&mut *tx, &w, real, w.agent, w.agent)
        .await
        .expect("the victim's genuine record");
    tx.commit().await.expect("commit");
    victim.close().await;
    let group = owner_group_of(&pool, real).await;

    let stranger = app_pool_for(&pool, w.other).await;
    let self_stamp = "SELECT set_config('epigraph.writable_group_ids', $1, true), \
                             set_config('epigraph.group_ids', $1, true)";

    // (1) A no-op UPDATE of the masses.
    let mut tx = stranger.begin().await.expect("begin");
    sqlx::query(self_stamp)
        .bind(group.to_string())
        .execute(&mut *tx)
        .await
        .expect("self-stamp");
    let touched = sqlx::query("UPDATE mass_functions SET masses = masses WHERE id = $1")
        .bind(real)
        .execute(&mut *tx)
        .await
        .expect("PREMISE: the self-stamped stranger may update the row")
        .rows_affected();
    assert_eq!(
        touched, 1,
        "PREMISE: the stranger's no-op UPDATE hit the row"
    );
    assert_eq!(
        file_record(&mut *tx, &w, real, w.agent, w.other).await,
        Err("42501".to_string()),
        "a record of a row whose masses this transaction did not change"
    );
    tx.rollback().await.expect("rollback");

    // (2) The stamp written by the caller itself: the application role holds
    // no privilege on `mass_function_masses_writes`, so neither an INSERT nor
    // an UPDATE of it lands (each in its own transaction: a refused statement
    // aborts the transaction).
    for plant in [
        "INSERT INTO mass_function_masses_writes (mass_function_id, written_xact) \
         VALUES ($1, pg_current_xact_id()) \
         ON CONFLICT (mass_function_id) DO UPDATE SET written_xact = EXCLUDED.written_xact",
        "UPDATE mass_function_masses_writes SET written_xact = pg_current_xact_id() \
          WHERE mass_function_id = $1",
    ] {
        let mut tx = stranger.begin().await.expect("begin");
        sqlx::query(self_stamp)
            .bind(group.to_string())
            .execute(&mut *tx)
            .await
            .expect("self-stamp");
        let planted = sqlx::query(plant)
            .bind(real)
            .execute(&mut *tx)
            .await
            .map(|_| Uuid::nil());
        assert_eq!(
            code(planted),
            Err("42501".to_string()),
            "a caller-written stamp: {plant}"
        );
        tx.rollback().await.expect("rollback");
    }
    assert_eq!(assessed_rows(&pool).await, 1, "only the victim's record");

    // (3) CONTROL, and the documented residual: a stranger that really
    // rewrites the masses holds a true record of that write. Without this
    // the refusals above could be the self-stamp failing, not the bind.
    let mut tx = stranger.begin().await.expect("begin");
    sqlx::query(self_stamp)
        .bind(group.to_string())
        .execute(&mut *tx)
        .await
        .expect("self-stamp");
    sqlx::query(
        "UPDATE mass_functions SET masses = '{\"0\": 0.9, \"0,1\": 0.1}'::jsonb WHERE id = $1",
    )
    .bind(real)
    .execute(&mut *tx)
    .await
    .expect("the stranger rewrites the masses");
    file_record(&mut *tx, &w, real, w.agent, w.other)
        .await
        .expect("a record of a masses write this transaction made");
    tx.commit().await.expect("commit");
    stranger.close().await;
    assert_eq!(assessed_rows(&pool).await, 2);
}

/// The stamp is the TOP-level transaction's id, so a slot write made under a
/// savepoint (an explicit SAVEPOINT, or a sqlx nested transaction) is
/// recorded. Red on the first draft's `xmin` bind: the row carried the
/// subtransaction's xid and the genuine record was refused.
#[sqlx::test(migrations = "../../migrations")]
async fn a_slot_write_made_under_a_savepoint_is_recorded(pool: PgPool) {
    let w = world(&pool, "t62-savepoint").await;
    let app = app_pool_for(&pool, w.agent).await;

    // An explicit savepoint, released before the record.
    let mut tx = app.begin().await.expect("begin");
    sqlx::query("SAVEPOINT slot_write")
        .execute(&mut *tx)
        .await
        .expect("savepoint");
    let mf = store(&mut *tx, &w, w.agent).await;
    sqlx::query("RELEASE SAVEPOINT slot_write")
        .execute(&mut *tx)
        .await
        .expect("release");
    file_record(&mut *tx, &w, mf, w.agent, w.agent)
        .await
        .expect("a slot write made under a released savepoint is recorded");
    tx.commit().await.expect("commit");

    // A sqlx nested transaction (a savepoint), new masses, recorded outside
    // it; then a second nested write whose savepoint is rolled back is not
    // this transaction's write any more.
    let mut tx = app.begin().await.expect("begin");
    {
        let mut inner = sqlx::Acquire::begin(&mut *tx).await.expect("nested begin");
        sqlx::query(
            "UPDATE mass_functions SET masses = '{\"0\": 0.7, \"0,1\": 0.3}' WHERE id = $1",
        )
        .bind(mf)
        .execute(&mut *inner)
        .await
        .expect("nested slot write");
        inner
            .commit()
            .await
            .expect("release the nested transaction");
    }
    file_record(&mut *tx, &w, mf, w.agent, w.agent)
        .await
        .expect("a slot write made in a nested transaction is recorded");
    tx.commit().await.expect("commit");

    let mut tx = app.begin().await.expect("begin");
    {
        let mut inner = sqlx::Acquire::begin(&mut *tx).await.expect("nested begin");
        sqlx::query(
            "UPDATE mass_functions SET masses = '{\"0\": 0.2, \"0,1\": 0.8}' WHERE id = $1",
        )
        .bind(mf)
        .execute(&mut *inner)
        .await
        .expect("nested slot write");
        inner.rollback().await.expect("roll the nested write back");
    }
    assert_eq!(
        file_record(&mut *tx, &w, mf, w.agent, w.agent).await,
        Err("42501".to_string()),
        "a slot write rolled back to its savepoint is not this transaction's"
    );
    tx.rollback().await.expect("rollback");
    app.close().await;
    assert_eq!(assessed_rows(&pool).await, 2);
}

/// The bind compares full 64-bit, epoch-aware transaction ids. The first
/// draft compared `xmin` (a raw 32-bit xid, which freezing keeps) with the
/// current id modulo 2^32, so after a wrap an old row could match. A wrap
/// cannot be produced in a test, so the stamp is planted directly in
/// `mass_function_masses_writes` (superuser) and the record is then filed in
/// the SAME transaction as an application session.
#[sqlx::test(migrations = "../../migrations")]
async fn the_bind_compares_epoch_aware_transaction_ids(pool: PgPool) {
    let w = world(&pool, "t62-epoch").await;
    let mf = store(&pool, &w, w.agent).await;
    let v = Viewer::resolve(&pool, w.agent)
        .await
        .expect("resolve viewer");
    let groups = csv(v.group_bind().expect("scoped viewer"));
    let writable = csv(v.writable_groups());

    // `offset` is added to this transaction's id to make the planted stamp:
    // 2^32 is the same 32-bit xid in the next epoch.
    for (offset, admitted) in [("0", true), ("4294967296", false)] {
        let mut tx = pool.begin().await.expect("begin");
        let planted = sqlx::query(
            "UPDATE mass_function_masses_writes \
                SET written_xact = \
                    ((pg_current_xact_id()::text::numeric + $2::numeric)::text)::xid8 \
              WHERE mass_function_id = $1",
        )
        .bind(mf)
        .bind(offset)
        .execute(&mut *tx)
        .await
        .expect("plant the stamp");
        assert_eq!(
            planted.rows_affected(),
            1,
            "PREMISE: the slot insert left a stamp row to plant over"
        );
        sqlx::query("SET LOCAL SESSION AUTHORIZATION epigraph_app")
            .execute(&mut *tx)
            .await
            .expect("become the application role");
        sqlx::query(
            "SELECT set_config('epigraph.group_ids', $1, true), \
                    set_config('epigraph.writable_group_ids', $2, true), \
                    set_config('epigraph.principal_id', $3, true)",
        )
        .bind(&groups)
        .bind(&writable)
        .bind(w.agent.to_string())
        .execute(&mut *tx)
        .await
        .expect("stamp the application session");
        let r = file_record(&mut *tx, &w, mf, w.agent, w.agent).await;
        if admitted {
            r.expect("CONTROL: a stamp equal to this transaction's id is admitted");
        } else {
            assert_eq!(
                r,
                Err("42501".to_string()),
                "a stamp from another epoch with the same 32-bit xid"
            );
        }
        tx.rollback().await.expect("rollback");
    }
}

/// The route's slot upsert: `w.agent`'s assessment slot on `w.claim` / `w.frame`.
async fn store_slot(
    conn: &mut sqlx::PgConnection,
    w: &World,
    slot: Uuid,
    masses: &serde_json::Value,
) -> Uuid {
    MassFunctionRepository::store_in_slot(
        conn,
        w.claim,
        w.frame,
        Some(w.agent),
        epigraph_db::BbaSlot::Assessment(slot),
        masses,
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

/// An upsert of the masses the slot already holds writes no masses, so it is
/// not recordable, and `slot_holds_masses` (which the route asks before the
/// upsert, to file no record then) answers true for it and false for new
/// masses or a slot with no row.
#[sqlx::test(migrations = "../../migrations")]
async fn an_identical_reassessment_writes_no_masses_and_is_detected(pool: PgPool) {
    let w = world(&pool, "t62-same").await;
    let app = app_pool_for(&pool, w.agent).await;
    let viewer = Viewer::resolve(&pool, w.agent)
        .await
        .expect("resolve viewer");
    let slot = epigraph_db::repos::mass_function::assessment_slot_perspective(Some(w.agent));
    let same: serde_json::Value = serde_json::from_str(MASSES).expect("masses");
    let other: serde_json::Value =
        serde_json::from_str(r#"{"0": 0.3, "0,1": 0.7}"#).expect("masses");
    let mut tx = app.begin().await.expect("begin");
    assert!(
        !MassFunctionRepository::slot_holds_masses(
            &mut *tx, &viewer, w.claim, w.frame, w.agent, slot, &same
        )
        .await
        .expect("ask"),
        "no row yet"
    );
    let mf = store_slot(&mut tx, &w, slot, &same).await;
    file_record(&mut *tx, &w, mf, w.agent, w.agent)
        .await
        .expect("the first write is recorded");
    tx.commit().await.expect("commit");

    let mut tx = app.begin().await.expect("begin");
    assert!(
        MassFunctionRepository::slot_holds_masses(
            &mut *tx, &viewer, w.claim, w.frame, w.agent, slot, &same
        )
        .await
        .expect("ask"),
        "the slot already holds these masses"
    );
    let again = store_slot(&mut tx, &w, slot, &same).await;
    assert_eq!(again, mf, "PREMISE: the upsert hit the same slot row");
    assert_eq!(
        file_record(&mut *tx, &w, mf, w.agent, w.agent).await,
        Err("42501".to_string()),
        "an upsert of identical masses wrote no masses"
    );
    tx.rollback().await.expect("rollback");

    let mut tx = app.begin().await.expect("begin");
    assert!(
        !MassFunctionRepository::slot_holds_masses(
            &mut *tx, &viewer, w.claim, w.frame, w.agent, slot, &other
        )
        .await
        .expect("ask"),
        "new masses"
    );
    store_slot(&mut tx, &w, slot, &other).await;
    file_record(&mut *tx, &w, mf, w.agent, w.agent)
        .await
        .expect("a write of new masses is recorded");
    tx.commit().await.expect("commit");
    app.close().await;
    assert_eq!(assessed_rows(&pool).await, 2);
}
