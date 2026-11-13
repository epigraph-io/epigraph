//! Migration 208: the ingest marker's LABEL form (the legacy backfill) and
//! the countersign route's labels, under the same `edges` guard as the
//! marker property.
//!
//! Pinned here:
//! * no undeclared write, application or privileged, can add, change or
//!   remove a reserved `epigraph:` edge label; a declared one can; a
//!   re-pointed edge loses them;
//! * a label-marked legacy edge reads as ingest-written by its `by`, so a
//!   legacy unmarked row stops withholding another principal's own row once
//!   it is backfilled, and the supersede cascade leaves it on its claim;
//! * the countersign definer: no principal and a stranger are refused with
//!   nothing written; the named person confirms (the card stops counting the
//!   paper as pending), a non-pending row is a no-op, the agent's live
//!   operator may act (its link while not retired, else its unrevoked client
//!   allowance), a retired link's former operator and a revoked allowance's
//!   operator may not (a retired link never falls back to an allowance), every
//!   act is audited, and a DECLINED naming never stops the person's own later
//!   ingest of the same fact.
//!
//! The application-path cases run on an `epigraph_app` `ScopedPool`
//! transaction stamped from the caller's viewer, as a request would.
//! All names are invented.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::pool::{ScopedPool, SessionGucMode};
use epigraph_db::visibility::Viewer;
use epigraph_db::{
    AgentLookupRepository, AgentRepository, ClaimRepository, CountersignDecision,
    CountersignRepository, DbError,
};
use sqlx::PgPool;
use uuid::Uuid;

const SETTING: &str = "epigraph.ingest_written_edge";
const SENTINEL: &str = "epigraph:ingest_written";

async fn app_pool(pool: &PgPool) -> ScopedPool {
    ScopedPool::connect_downgraded_for_tests(
        &fixture::database_url_for(pool).await,
        SessionGucMode::Session,
        "epigraph_app",
    )
    .await
    .expect("app-role ScopedPool")
}

async fn viewer(pool: &PgPool, who: Uuid) -> Viewer {
    Viewer::resolve(pool, who).await.expect("resolve viewer")
}

async fn paper(pool: &PgPool, doi: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO papers (doi, title) VALUES ($1, 'A Fixture Paper') RETURNING id",
    )
    .bind(doi)
    .fetch_one(pool)
    .await
    .expect("paper")
}

/// A pre-marker edge, written raw.
async fn legacy_edge(pool: &PgPool, src: (Uuid, &str), tgt: (Uuid, &str), rel: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(src.0)
    .bind(src.1)
    .bind(tgt.0)
    .bind(tgt.1)
    .bind(rel)
    .fetch_one(pool)
    .await
    .expect("legacy edge")
}

/// The backfill's write of the label form, declared, on a privileged session.
async fn stamp(pool: &PgPool, edge: Uuid, by: Uuid) {
    let mut tx = pool.begin().await.expect("tx");
    sqlx::query("SELECT pg_catalog.set_config($1, 'on', true)")
        .bind(SETTING)
        .execute(&mut *tx)
        .await
        .expect("declare");
    sqlx::query("UPDATE edges SET labels = labels || $2::text[] WHERE id = $1")
        .bind(edge)
        .bind(epigraph_db::ingest_written::ingest_written_labels(by).to_vec())
        .execute(&mut *tx)
        .await
        .expect("stamp");
    tx.commit().await.expect("commit");
}

fn iwe02<T: std::fmt::Debug>(r: &Result<T, sqlx::Error>) -> bool {
    matches!(r, Err(sqlx::Error::Database(d)) if d.message().contains("IWE02"))
}

async fn labels_of(pool: &PgPool, edge: Uuid) -> Vec<String> {
    sqlx::query_scalar("SELECT labels FROM edges WHERE id = $1")
        .bind(edge)
        .fetch_one(pool)
        .await
        .expect("edge")
}

#[sqlx::test(migrations = "../../migrations")]
async fn no_undeclared_write_can_touch_a_reserved_label(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "label-stranger").await;
    let v = viewer(&pool, stranger).await;
    let p = paper(&pool, "10.9999/labels.guard").await;
    let x = fixture::seed_public_claim(&pool, stranger, "a stranger's finding").await;

    for label in [
        SENTINEL.to_string(),
        format!("epigraph:ingest_written_by:{stranger}"),
        format!("epigraph:countersigned_by:{stranger}"),
        "epigraph:anything".to_string(),
    ] {
        // The application role, stamped as a writer.
        let mut tx = scoped.begin_as(&v).await.expect("stamped tx");
        let r: Result<Uuid, _> = sqlx::query_scalar(
            "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                                labels) \
             VALUES ($1, 'paper', $2, 'claim', 'asserts', ARRAY[$3]) RETURNING id",
        )
        .bind(p)
        .bind(x)
        .bind(&label)
        .fetch_one(&mut *tx)
        .await;
        assert!(iwe02(&r), "an undeclared app INSERT carried {label}: {r:?}");
        drop(tx);
        // No privileged arm.
        let r: Result<Uuid, _> = sqlx::query_scalar(
            "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                                labels) \
             VALUES ($1, 'paper', $2, 'claim', 'asserts', ARRAY[$3]) RETURNING id",
        )
        .bind(p)
        .bind(x)
        .bind(&label)
        .fetch_one(&pool)
        .await;
        assert!(
            iwe02(&r),
            "an undeclared superuser INSERT carried {label}: {r:?}"
        );
    }

    // An ordinary label is untouched by the guard.
    let e = legacy_edge(&pool, (p, "paper"), (x, "claim"), "asserts").await;
    sqlx::query("UPDATE edges SET labels = labels || ARRAY['stage:one'] WHERE id = $1")
        .bind(e)
        .execute(&pool)
        .await
        .expect("CALIBRATION: an ordinary label is writable");

    // UPDATE adding one: refused.
    let r = sqlx::query("UPDATE edges SET labels = labels || ARRAY[$2] WHERE id = $1")
        .bind(e)
        .bind(SENTINEL)
        .execute(&pool)
        .await;
    assert!(iwe02(&r), "an undeclared UPDATE added the sentinel: {r:?}");

    // Declared: admitted. Then removing it undeclared: refused (a person's
    // decision or a backfill marker is never silently withdrawn).
    stamp(&pool, e, stranger).await;
    assert!(labels_of(&pool, e).await.contains(&SENTINEL.to_string()));
    let r = sqlx::query("UPDATE edges SET labels = array_remove(labels, $2) WHERE id = $1")
        .bind(e)
        .bind(SENTINEL)
        .execute(&pool)
        .await;
    assert!(
        iwe02(&r),
        "an undeclared UPDATE removed the sentinel: {r:?}"
    );
    // An UPDATE that keeps them is admitted.
    sqlx::query("UPDATE edges SET labels = labels || ARRAY['stage:two'] WHERE id = $1")
        .bind(e)
        .execute(&pool)
        .await
        .expect("keeping the reserved labels is admitted");

    // Re-pointing drops them: the moved edge is no ingest's.
    let y = fixture::seed_public_claim(&pool, stranger, "another finding").await;
    sqlx::query("UPDATE edges SET target_id = $2 WHERE id = $1")
        .bind(e)
        .bind(y)
        .execute(&pool)
        .await
        .expect("re-point");
    let after = labels_of(&pool, e).await;
    assert_eq!(
        after,
        vec!["stage:one".to_string(), "stage:two".to_string()],
        "a re-pointed edge keeps its ordinary labels in order and loses the reserved ones"
    );
}

/// A legacy unmarked `paper -asserts-> claim` row stops another principal's
/// ingest writing its own row (the ingest-record regression); once the backfill labels
/// it, it reads as the legacy principal's, and the other principal writes
/// its own.
#[sqlx::test(migrations = "../../migrations")]
async fn a_backfilled_legacy_row_stops_withholding_another_principals_row(pool: PgPool) {
    let (legacy, _) = fixture::seed_agent_with_group(&pool, "label-legacy").await;
    let (newcomer, _) = fixture::seed_agent_with_group(&pool, "label-newcomer").await;
    let p = paper(&pool, "10.9999/labels.legacy-withholds").await;
    let c = fixture::seed_public_claim(&pool, newcomer, "a legacy finding").await;
    let e = legacy_edge(&pool, (p, "paper"), (c, "claim"), "asserts").await;

    let write = |pool: PgPool| async move {
        let mut conn = pool.acquire().await.expect("conn");
        epigraph_db::create_ingest_written_edge_if_absent_conn(
            &mut conn,
            None,
            "ingest_document",
            newcomer,
            p,
            "paper",
            c,
            "claim",
            "asserts",
            None,
        )
        .await
        .expect("write")
    };
    let (row, created) = write(pool.clone()).await;
    assert!(
        !created && row.id == e,
        "CALIBRATION: the unmarked legacy row stops the write"
    );
    stamp(&pool, e, legacy).await;
    let (row, created) = write(pool.clone()).await;
    assert!(
        created,
        "a backfilled row no longer withholds another principal's row"
    );
    assert_ne!(row.id, e);

    // The label form reads as the marker, naming its principal.
    let (marked, by): (bool, Option<String>) = sqlx::query_as(&format!(
        "SELECT {}, {} FROM edges e WHERE e.id = $1",
        epigraph_db::ingest_written_edge_sql("e"),
        epigraph_db::ingest_written_by_sql("e"),
    ))
    .bind(e)
    .fetch_one(&pool)
    .await
    .expect("read");
    assert!(marked);
    assert_eq!(by, Some(legacy.to_string()));
}

/// The supersede cascade leaves a label-marked paper assertion on the claim
/// its ingest stated, as it does a property-marked one.
#[sqlx::test(migrations = "../../migrations")]
async fn the_supersede_cascade_leaves_a_backfilled_assertion_in_place(pool: PgPool) {
    let (legacy, _) = fixture::seed_agent_with_group(&pool, "label-cascade").await;
    let p = paper(&pool, "10.9999/labels.cascade").await;
    let old = fixture::seed_public_claim(&pool, legacy, "the stated finding").await;
    let new = fixture::seed_public_claim(&pool, legacy, "its successor").await;
    let stamped = legacy_edge(&pool, (p, "paper"), (old, "claim"), "asserts").await;
    let q = paper(&pool, "10.9999/labels.cascade.2").await;
    let unmarked = legacy_edge(&pool, (q, "paper"), (old, "claim"), "asserts").await;
    stamp(&pool, stamped, legacy).await;
    // The supersession the cascade follows.
    sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(old)
        .execute(&pool)
        .await
        .expect("retire");
    sqlx::query("UPDATE claims SET supersedes = $2 WHERE id = $1")
        .bind(new)
        .bind(old)
        .execute(&pool)
        .await
        .expect("supersedes");
    let mut conn = pool.acquire().await.expect("conn");
    ClaimRepository::migrate_superseded_edges_conn(&mut conn, old, new)
        .await
        .expect("cascade");
    let target = |id: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, Uuid>("SELECT target_id FROM edges WHERE id = $1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .expect("edge")
        }
    };
    assert_eq!(
        target(unmarked).await,
        new,
        "CALIBRATION: an unmarked paper assertion follows the successor"
    );
    assert_eq!(
        target(stamped).await,
        old,
        "a backfilled assertion stays on its claim"
    );
}

/// A stranger S's ingest named person H on paper P: H's authorship is S's
/// word, pending, written through the walk's own writer.
async fn pending_naming(pool: &PgPool, s: Uuid, h: Uuid, p: Uuid) -> Uuid {
    let mut conn = pool.acquire().await.expect("conn");
    let (row, created) = epigraph_db::create_ingest_written_edge_if_absent_conn(
        &mut conn,
        None,
        "ingest_document",
        s,
        h,
        "agent",
        p,
        "paper",
        "authored",
        Some(serde_json::json!({
            "pending_countersign": true,
            "ingested_by": s.to_string(),
            "position": 0,
        })),
    )
    .await
    .expect("pending naming");
    assert!(created);
    row.id
}

async fn countersign(
    pool: &PgPool,
    scoped: &ScopedPool,
    caller: Uuid,
    paper: Uuid,
    agent: Option<Uuid>,
    decision: CountersignDecision,
) -> Result<Vec<epigraph_db::CountersignedRow>, DbError> {
    let v = viewer(pool, caller).await;
    let mut tx = scoped.begin_as(&v).await.expect("stamped tx");
    let r = CountersignRepository::countersign_conn(&mut tx, paper, agent, decision, None).await;
    if r.is_ok() {
        tx.commit().await.expect("commit");
    }
    r
}

async fn card(pool: &PgPool, scoped: &ScopedPool, caller: Uuid, agent: Uuid) -> (i64, i64) {
    let v = viewer(pool, caller).await;
    let mut read = scoped.read_as(&v).await.expect("read");
    let c = AgentLookupRepository::card(&mut read, &v, agent)
        .await
        .expect("card")
        .expect("agent");
    read.commit().await.expect("finish");
    (c.counts.authored_papers, c.counts.pending_authored_papers)
}

async fn edge_state(pool: &PgPool, e: Uuid) -> (Vec<String>, bool, serde_json::Value) {
    sqlx::query_as(
        "SELECT labels, (valid_to IS NULL OR valid_to > now()), properties FROM edges WHERE id = $1",
    )
    .bind(e)
    .fetch_one(pool)
    .await
    .expect("edge")
}

fn refused(r: &Result<Vec<epigraph_db::CountersignedRow>, DbError>, code: &str) -> bool {
    matches!(r, Err(DbError::Refused { message, .. }) if message.starts_with(code))
}

#[sqlx::test(migrations = "../../migrations")]
async fn only_the_named_person_or_its_live_operator_countersigns(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (s, _) = fixture::seed_agent_with_group(&pool, "cs-stranger-ingester").await;
    let (h, _) = fixture::seed_human_operator(&pool, "cs-person").await;
    let (t, _) = fixture::seed_agent_with_group(&pool, "cs-third").await;
    let p = paper(&pool, "10.9999/countersign.confirm").await;
    let e = pending_naming(&pool, s, h, p).await;
    let state0 = edge_state(&pool, e).await;
    assert_eq!(
        card(&pool, &scoped, t, h).await,
        (0, 1),
        "CALIBRATION: pending"
    );

    // A stranger, and the ingester itself, are refused; nothing written.
    for who in [t, s] {
        let r = countersign(
            &pool,
            &scoped,
            who,
            p,
            Some(h),
            CountersignDecision::Confirm,
        )
        .await;
        assert!(refused(&r, "CSG02"), "{who} countersigned: {r:?}");
    }
    let r = countersign(&pool, &scoped, t, p, None, CountersignDecision::Confirm).await;
    assert_eq!(
        r.expect("for itself").len(),
        0,
        "a stranger has no pending row of its own"
    );
    assert_eq!(
        edge_state(&pool, e).await,
        state0,
        "a refusal writes nothing"
    );

    // No principal at all: refused.
    let mut conn = pool.acquire().await.expect("conn");
    let r = CountersignRepository::countersign_conn(
        &mut conn,
        p,
        Some(h),
        CountersignDecision::Confirm,
        None,
    )
    .await;
    assert!(refused(&r, "CSG01"), "{r:?}");
    drop(conn);

    // The named person confirms: the row stops being pending, its signed
    // properties untouched.
    let rows = countersign(&pool, &scoped, h, p, None, CountersignDecision::Confirm)
        .await
        .expect("confirm");
    assert_eq!(rows.len(), 1);
    assert_eq!((rows[0].edge_id, rows[0].ingested_by), (e, Some(s)));
    assert_eq!(rows[0].outcome, "confirmed");
    let (labels, in_force, props) = edge_state(&pool, e).await;
    assert!(
        labels.contains(&format!("epigraph:countersigned_by:{h}")),
        "{labels:?}"
    );
    assert!(in_force);
    assert_eq!(props, state0.2, "the signed properties are never edited");
    assert_eq!(card(&pool, &scoped, t, h).await, (1, 0), "the card flips");

    // A non-pending row: a no-op.
    let again = countersign(&pool, &scoped, h, p, None, CountersignDecision::Decline)
        .await
        .expect("no-op");
    assert!(again.is_empty());
    assert!(edge_state(&pool, e).await.1, "nothing was declined");

    let audit: Vec<(String, Option<Uuid>, serde_json::Value)> = sqlx::query_as(
        "SELECT event_type::text, agent_id, details FROM security_events \
          WHERE event_type LIKE 'authorship.countersign%' ORDER BY created_at",
    )
    .fetch_all(&pool)
    .await
    .expect("audit");
    assert_eq!(
        audit.len(),
        1,
        "one audit row per act, none for a refusal or a no-op"
    );
    assert_eq!(audit[0].0, "authorship.countersigned");
    assert_eq!(audit[0].1, Some(h));
    assert_eq!(audit[0].2["edges"], serde_json::json!([e]));
    assert_eq!(audit[0].2["acting_as"], "self");

    // A live operator acts for its agent.
    let (g, _) = fixture::seed_agent_with_group(&pool, "cs-operated").await;
    let link = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r = AgentRepository::link_operator(&mut conn, g, h).await;
        (conn, r)
    })
    .await
    .expect("link");
    assert!(link.link_live);
    let p2 = paper(&pool, "10.9999/countersign.operator").await;
    let e2 = pending_naming(&pool, s, g, p2).await;
    let r = countersign(&pool, &scoped, t, p2, Some(g), CountersignDecision::Decline).await;
    assert!(refused(&r, "CSG02"), "{r:?}");
    let rows = countersign(&pool, &scoped, h, p2, Some(g), CountersignDecision::Decline)
        .await
        .expect("the operator declines for its agent");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].outcome, "declined");
    let (labels, in_force, _) = edge_state(&pool, e2).await;
    assert!(!in_force, "a declined naming is retracted");
    assert!(labels.contains(&format!("epigraph:countersign_declined_by:{h}")));
    assert_eq!(card(&pool, &scoped, t, g).await, (0, 0));
}

/// A declined naming never stops the person's own later ingest of the same
/// fact (the dedup probe's retracted-row stop skips it), while the naming
/// ingester's own re-run still finds its row and names nobody again.
#[sqlx::test(migrations = "../../migrations")]
async fn a_declined_naming_never_stops_the_persons_own_row(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (s, _) = fixture::seed_agent_with_group(&pool, "cs-decline-ingester").await;
    let (h, _) = fixture::seed_human_operator(&pool, "cs-decline-person").await;
    let p = paper(&pool, "10.9999/countersign.decline").await;
    let e = pending_naming(&pool, s, h, p).await;
    countersign(&pool, &scoped, h, p, None, CountersignDecision::Decline)
        .await
        .expect("decline");
    let write = |by: Uuid| {
        let pool = pool.clone();
        async move {
            let mut conn = pool.acquire().await.expect("conn");
            epigraph_db::create_ingest_written_edge_if_absent_conn(
                &mut conn,
                None,
                "ingest_document",
                by,
                h,
                "agent",
                p,
                "paper",
                "authored",
                None,
            )
            .await
            .expect("write")
        }
    };
    let (row, created) = write(h).await;
    assert!(created, "the person's own ingest writes its own row");
    assert_ne!(row.id, e);
    let (row, created) = write(s).await;
    assert!(
        !created && row.id == e,
        "the naming ingest's re-run dedups onto its declined row"
    );
}

/// Retire `agent`'s live link through migration 191's maintenance verb.
async fn retire_link(pool: &PgPool, agent: Uuid) {
    let outcome: String = fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let r: String = sqlx::query_scalar(
            "SELECT outcome FROM public.epigraph_retire_operator_link($1, 'countersign test', \
                                                                     true)",
        )
        .bind(agent)
        .fetch_one(&mut *conn)
        .await
        .expect("retire the link");
        (conn, r)
    })
    .await;
    assert_eq!(outcome, "retired", "CALIBRATION: the link was live");
}

/// A fresh agent bound to `operator` by a migration-149 client allowance (a
/// service client on the maintenance-only registry). Returns
/// `(agent, client)`.
async fn allowance_bound(pool: &PgPool, operator: Uuid, name: &str) -> (Uuid, Uuid) {
    let (agent, _) = fixture::seed_agent_with_group(pool, name).await;
    let client: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    status, agent_id, legal_entity_name, legal_contact_email) \
         VALUES ($1, 'countersign allowance fixture', 'service', ARRAY['claims:write'], \
                 'active', $2, 'Fixture Org', 'fixture@example.invalid') RETURNING id",
    )
    .bind(format!("countersign-allowance-{}", Uuid::new_v4()))
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("service client");
    let allowed: bool = fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let r: bool = sqlx::query_scalar(
            "SELECT allowed_now FROM public.epigraph_allow_author_binding_client($1, $2, $3)",
        )
        .bind(client)
        .bind(operator)
        .bind("countersign test")
        .fetch_one(&mut *conn)
        .await
        .expect("allow the client for the operator");
        (conn, r)
    })
    .await;
    assert!(allowed, "CALIBRATION: the allowance is in force");
    (agent, client)
}

async fn countersign_audit_rows(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM security_events WHERE event_type LIKE 'authorship.countersign%'",
    )
    .fetch_one(pool)
    .await
    .expect("audit")
}

/// A retired link's former operator may no longer act for the agent, and
/// a retired link never falls back to the operator's still-unrevoked client
/// allowance for the same agent: CSG02, nothing written.
#[sqlx::test(migrations = "../../migrations")]
async fn a_retired_links_former_operator_cannot_countersign(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (s, _) = fixture::seed_agent_with_group(&pool, "cs-retired-ingester").await;
    let (h, _) = fixture::seed_human_operator(&pool, "cs-retired-operator").await;
    // An allowance first (its client revoked, as 149 requires before a
    // link), then the link: the allowance row stays unrevoked.
    let (g, client) = allowance_bound(&pool, h, "cs-retired-agent").await;
    sqlx::query("UPDATE oauth_clients SET status = 'revoked' WHERE id = $1")
        .bind(client)
        .execute(&pool)
        .await
        .expect("client revoked");
    let link = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r = AgentRepository::link_operator(&mut conn, g, h).await;
        (conn, r)
    })
    .await
    .expect("link");
    assert!(link.link_live, "CALIBRATION: live link");

    // While the link is live, the operator acts.
    let p0 = paper(&pool, "10.9999/countersign.retired-live").await;
    pending_naming(&pool, s, g, p0).await;
    let rows = countersign(&pool, &scoped, h, p0, Some(g), CountersignDecision::Confirm)
        .await
        .expect("CALIBRATION: the live operator confirms");
    assert_eq!(rows.len(), 1);
    assert_eq!(countersign_audit_rows(&pool).await, 1);

    retire_link(&pool, g).await;
    let unrevoked: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM author_binding_clients WHERE agent_id = $1 AND revoked_at IS NULL",
    )
    .bind(g)
    .fetch_one(&pool)
    .await
    .expect("allowance rows");
    assert_eq!(unrevoked, 1, "CALIBRATION: the allowance row is unrevoked");

    let p = paper(&pool, "10.9999/countersign.retired").await;
    let e = pending_naming(&pool, s, g, p).await;
    let state0 = edge_state(&pool, e).await;
    for decision in [CountersignDecision::Confirm, CountersignDecision::Decline] {
        let r = countersign(&pool, &scoped, h, p, Some(g), decision).await;
        assert!(
            refused(&r, "CSG02"),
            "a retired link's former operator acted: {r:?}"
        );
    }
    assert_eq!(edge_state(&pool, e).await, state0, "nothing written");
    assert_eq!(countersign_audit_rows(&pool).await, 1, "no audit row");
    assert_eq!(card(&pool, &scoped, s, g).await, (1, 1), "still pending");
}

/// An agent with no operator link is acted for by the operator its
/// unrevoked client allowance names; once that allowance is revoked, the
/// operator is refused CSG02 with nothing written.
#[sqlx::test(migrations = "../../migrations")]
async fn an_allowance_bound_operator_countersigns_until_the_allowance_is_revoked(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (s, _) = fixture::seed_agent_with_group(&pool, "cs-allow-ingester").await;
    let (h, _) = fixture::seed_human_operator(&pool, "cs-allow-operator").await;
    let (t, _) = fixture::seed_agent_with_group(&pool, "cs-allow-stranger").await;
    let (k, client) = allowance_bound(&pool, h, "cs-allow-agent").await;
    let linked: i64 = sqlx::query_scalar("SELECT count(*) FROM operator_links WHERE agent_id = $1")
        .bind(k)
        .fetch_one(&pool)
        .await
        .expect("links");
    assert_eq!(linked, 0, "CALIBRATION: bound by the allowance alone");

    let p = paper(&pool, "10.9999/countersign.allowance").await;
    let e = pending_naming(&pool, s, k, p).await;
    let r = countersign(&pool, &scoped, t, p, Some(k), CountersignDecision::Confirm).await;
    assert!(refused(&r, "CSG02"), "a stranger acted: {r:?}");
    let rows = countersign(&pool, &scoped, h, p, Some(k), CountersignDecision::Confirm)
        .await
        .expect("the allowance's operator confirms for its agent");
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (rows[0].edge_id, rows[0].outcome.as_str()),
        (e, "confirmed")
    );
    let (labels, in_force, _) = edge_state(&pool, e).await;
    assert!(
        labels.contains(&format!("epigraph:countersigned_by:{h}")),
        "{labels:?}"
    );
    assert!(in_force);
    let acting: serde_json::Value = sqlx::query_scalar(
        "SELECT details -> 'acting_as' FROM security_events \
          WHERE event_type = 'authorship.countersigned'",
    )
    .fetch_one(&pool)
    .await
    .expect("audit");
    assert_eq!(acting, "operator");
    assert_eq!(card(&pool, &scoped, t, k).await, (1, 0), "the card flips");

    let revoked: bool = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r: bool = sqlx::query_scalar(
            "SELECT revoked_now FROM public.epigraph_revoke_author_binding_client($1, \
                                                                              'countersign test')",
        )
        .bind(client)
        .fetch_one(&mut *conn)
        .await
        .expect("revoke the allowance");
        (conn, r)
    })
    .await;
    assert!(revoked, "CALIBRATION: the allowance was live");
    let p2 = paper(&pool, "10.9999/countersign.allowance-revoked").await;
    let e2 = pending_naming(&pool, s, k, p2).await;
    let state0 = edge_state(&pool, e2).await;
    let r = countersign(&pool, &scoped, h, p2, Some(k), CountersignDecision::Decline).await;
    assert!(
        refused(&r, "CSG02"),
        "a revoked allowance's operator acted: {r:?}"
    );
    assert_eq!(edge_state(&pool, e2).await, state0, "nothing written");
    assert_eq!(countersign_audit_rows(&pool).await, 1, "no audit row");
}
