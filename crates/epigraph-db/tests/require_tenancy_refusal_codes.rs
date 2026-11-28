//! Migration 362 (backlog baac4c90) codes the caller-reachable refusals of the
//! three `*_require_tenancy` trigger bodies.
//!
//! Each coded arm is raised for real by an INSERT on the application role
//! (`SET SESSION AUTHORIZATION epigraph_app`: the harness role holds a grant of
//! `epigraph_seed`, so on the default connection every undeclared write takes
//! the seed arm and succeeds). Each test asserts the code is in the message,
//! the SQLSTATE is the one it had before 362, and no row id is in the
//! message. The predecessor arm stays uncoded (a code would tell a missing
//! claim from a private one).
//!
//! Uses the non-macro `sqlx::query` forms so the offline `.sqlx/` cache is not
//! extended.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::DbError;
use sqlx::PgPool;
use uuid::Uuid;

/// What a refused statement reports.
struct Refusal {
    sqlstate: String,
    message: String,
    detail: Option<String>,
    error: sqlx::Error,
}

/// Run `sql` (with `binds` as uuids) as `epigraph_app` and return its refusal.
/// The session must not be a seed session, or the undeclared arms never fire.
async fn refused_as_app(pool: &PgPool, sql: &'static str, binds: Vec<Uuid>) -> Refusal {
    fixture::grant_app_privileges(pool, "epigraph_app").await;
    let error = fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        let seed: bool = sqlx::query_scalar("SELECT public.epigraph_session_is_seed()")
            .fetch_one(&mut *conn)
            .await
            .expect("ask the seed question");
        assert!(
            !seed,
            "PREMISE: the application session is not a seed session, so the undeclared arms fire"
        );
        let mut q = sqlx::query(sql);
        for b in binds {
            q = q.bind(b);
        }
        let e = q
            .execute(&mut *conn)
            .await
            .expect_err("the tenancy trigger refuses the insert");
        (conn, e)
    })
    .await;
    let pg = error
        .as_database_error()
        .and_then(|d| d.try_downcast_ref::<sqlx::postgres::PgDatabaseError>())
        .expect("a PostgreSQL error");
    Refusal {
        sqlstate: pg.code().to_string(),
        message: pg.message().to_string(),
        detail: pg.detail().map(str::to_string),
        error,
    }
}

fn assert_coded(r: &Refusal, code: &str, sqlstate: &str) {
    assert_eq!(
        r.sqlstate, sqlstate,
        "{code} keeps its SQLSTATE: {}",
        r.message
    );
    assert!(
        r.message
            .starts_with(&format!("{code}: epigraph tenancy: ")),
        "the refusal opens with {code}: {}",
        r.message
    );
    assert_eq!(
        epigraph_db::caller_refusal_code(&r.message),
        Some(code),
        "{code} is a listed caller-refusal code"
    );
}

/// The message names none of `ids` (they belong in DETAIL).
fn assert_no_uuid_in_message(r: &Refusal, ids: &[Uuid]) {
    for id in ids {
        assert!(
            !r.message.contains(&id.to_string()),
            "row id {id} is in the MESSAGE, not DETAIL: {}",
            r.message
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_undeclared_claim_is_refused_with_ten03_and_its_ids_in_detail(pool: PgPool) {
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "ten03").await;
    let id = Uuid::new_v4();
    let r = refused_as_app(
        &pool,
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current) \
         VALUES ($1, 'undeclared', decode(md5('ten03') || md5('ten03'), 'hex'), 0.5, $2, true)",
        vec![id, agent],
    )
    .await;
    assert_coded(&r, "TEN03", "23502");
    assert_no_uuid_in_message(&r, &[id, agent]);
    let detail = r.detail.as_deref().unwrap_or_default();
    assert!(
        detail.contains(&id.to_string()) && detail.contains(&agent.to_string()),
        "the row ids are in DETAIL: {detail:?}"
    );
    // 23502 has no dedicated DbError arm: it stays `QueryFailed`, which the
    // HTTP mapper answers 400 with the message because the code is listed.
    assert!(
        matches!(DbError::from(r.error), DbError::QueryFailed { .. }),
        "a coded 23502 stays QueryFailed"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_orphan_derived_row_is_refused_with_ten04(pool: PgPool) {
    let missing = Uuid::new_v4();
    let r = refused_as_app(
        &pool,
        "INSERT INTO evidence (id, claim_id, content_hash, evidence_type) \
         VALUES (gen_random_uuid(), $1, decode(md5('ten04') || md5('ten04'), 'hex'), 'document')",
        vec![missing],
    )
    .await;
    assert_coded(&r, "TEN04", "23503");
    assert!(
        r.message
            .contains("evidence.claim_id references a nonexistent claim"),
        "the message names the table: {}",
        r.message
    );
    assert_no_uuid_in_message(&r, &[missing]);
    assert_eq!(
        r.detail.as_deref(),
        Some(format!("claim_id={missing}").as_str()),
        "the claim id is in DETAIL"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_undeclared_derived_row_without_a_claim_is_refused_with_ten05(pool: PgPool) {
    let r = refused_as_app(
        &pool,
        "INSERT INTO evidence (id, claim_id, content_hash, evidence_type) \
         VALUES (gen_random_uuid(), NULL, decode(md5('ten05') || md5('ten05'), 'hex'), 'document')",
        vec![],
    )
    .await;
    assert_coded(&r, "TEN05", "23502");
    assert!(
        r.message
            .contains("INSERT INTO evidence without an explicit"),
        "{}",
        r.message
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_undeclared_root_row_is_refused_with_ten06(pool: PgPool) {
    let r = refused_as_app(
        &pool,
        "INSERT INTO frames (name, hypotheses) VALUES ('ten06', ARRAY['a','b'])",
        vec![],
    )
    .await;
    assert_coded(&r, "TEN06", "23502");
    assert!(
        r.message.contains("INSERT INTO frames without an explicit"),
        "{}",
        r.message
    );
}

/// The predecessor arm stays uncoded (it would tell a missing claim from a
/// private one), so its 23503 stays the generic foreign-key answer.
#[sqlx::test(migrations = "../../migrations")]
async fn a_supersedes_naming_no_claim_stays_uncoded(pool: PgPool) {
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "ten-pred").await;
    let r = refused_as_app(
        &pool,
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             supersedes) \
         VALUES (gen_random_uuid(), 'successor', decode(md5('tenp') || md5('tenp'), 'hex'), \
                 0.5, $1, true, $2)",
        vec![agent, Uuid::new_v4()],
    )
    .await;
    assert_eq!(r.sqlstate, "23503", "{}", r.message);
    assert!(
        r.message
            .starts_with("epigraph tenancy: claims.supersedes="),
        "the predecessor arm carries no code: {}",
        r.message
    );
    assert!(
        matches!(DbError::from(r.error), DbError::ForeignKeyViolation { .. }),
        "an uncoded 23503 stays ForeignKeyViolation"
    );
}
