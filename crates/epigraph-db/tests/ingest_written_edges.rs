//! The ingest-written edge marker (`properties.ingest_written`) and the
//! `edges` guard that makes it unforgeable.
//!
//! # What is under test
//!
//! Provenance reads (the agent card's counts first) trust an `authored` or
//! `asserts` edge only when the document ingest wrote it. The walk proves that
//! with a reserved property, and the database refuses that property on any
//! write that is not the walk's:
//!
//! * an INSERT carrying the key is refused unless the writing transaction
//!   declared itself the walk (a transaction-local setting the ingest sets
//!   around its own writes), on the application role AND on a privileged
//!   session, whatever the key's value (JSON `null` included);
//! * an UPDATE that adds or changes the key is refused the same way; one that
//!   keeps or drops it is not;
//! * an UPDATE that moves an endpoint or the relationship of a marked edge
//!   drops the key: the moved edge is not what the walk wrote;
//! * the declaration ends with its transaction, so a pooled connection never
//!   carries it into the next request.
//!
//! The SQL here spells the key and the setting literally, so this file pins
//! the strings the walk and the readers share
//! (`epigraph_db::ingest_written`, checked against these literals below).
//!
//! # Why the writes run as `epigraph_app`
//!
//! `#[sqlx::test]` connects as a superuser. The guard has no privileged arm,
//! and the superuser cases below prove that, but every application-path case
//! runs on an `epigraph_app` `ScopedPool` transaction stamped from the
//! writer's viewer, as a request would.
//!
//! All names are invented.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::pool::{ScopedPool, SessionGucMode};
use epigraph_db::visibility::Viewer;
use sqlx::PgPool;
use uuid::Uuid;

const KEY: &str = "ingest_written";
const SETTING: &str = "epigraph.ingest_written_edge";

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
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO papers (id, doi, title) VALUES ($1, $2, 'A Fixture Paper')")
        .bind(id)
        .bind(doi)
        .execute(pool)
        .await
        .expect("paper");
    id
}

/// One INSERT on an `epigraph_app` transaction stamped as `writer`, with the
/// walk's declaration made first when `declared`. Committed on success.
async fn insert_as(
    scoped: &ScopedPool,
    v: &Viewer,
    declared: bool,
    src: (Uuid, &str),
    tgt: (Uuid, &str),
    rel: &str,
    props: serde_json::Value,
) -> Result<Uuid, sqlx::Error> {
    let mut tx = scoped.begin_as(v).await.expect("stamped tx");
    if declared {
        sqlx::query("SELECT pg_catalog.set_config($1, 'on', true)")
            .bind(SETTING)
            .execute(&mut *tx)
            .await
            .expect("declare");
    }
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            properties) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(src.0)
    .bind(src.1)
    .bind(tgt.0)
    .bind(tgt.1)
    .bind(rel)
    .bind(props)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await.expect("commit");
    Ok(id)
}

/// One UPDATE on an `epigraph_app` transaction stamped as `writer`; returns
/// the rows it changed.
async fn update_as(
    scoped: &ScopedPool,
    v: &Viewer,
    sql: &str,
    edge: Uuid,
) -> Result<u64, sqlx::Error> {
    let mut tx = scoped.begin_as(v).await.expect("stamped tx");
    let n = sqlx::query(sql)
        .bind(edge)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    tx.commit().await.expect("commit");
    Ok(n)
}

async fn props_of(pool: &PgPool, edge: Uuid) -> serde_json::Value {
    sqlx::query_scalar("SELECT properties FROM edges WHERE id = $1")
        .bind(edge)
        .fetch_one(pool)
        .await
        .expect("edge row")
}

fn refused(r: &Result<impl std::fmt::Debug, sqlx::Error>) -> bool {
    matches!(r, Err(sqlx::Error::Database(d)) if d.message().contains("IWE01"))
}

#[test]
fn the_strings_here_are_the_crates() {
    assert_eq!(epigraph_db::INGEST_WRITTEN_PROPERTY, KEY);
    assert_eq!(epigraph_db::INGEST_WRITTEN_SETTING, SETTING);
    assert_eq!(
        epigraph_db::ingest_written_edge_sql("pa"),
        "((pa.properties ->> 'ingest_written') IS NOT NULL)"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn no_undeclared_write_can_carry_the_marker(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "stranger").await;
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let v = viewer(&pool, stranger).await;
    let p = paper(&pool, "10.9999/marker.insert.1").await;
    let x = fixture::seed_public_claim(&pool, stranger, "a stranger's finding").await;

    // CALIBRATION: the same rows without the key are writable by this session.
    insert_as(
        &scoped,
        &v,
        false,
        (p, "paper"),
        (x, "claim"),
        "asserts",
        serde_json::json!({}),
    )
    .await
    .expect("CALIBRATION: an unmarked paper assertion is writable");

    for (src, rel, value) in [
        (
            (author, "agent"),
            "asserts",
            serde_json::json!("ingest_document"),
        ),
        ((author, "agent"), "authored", serde_json::json!(true)),
        ((author, "agent"), "asserts", serde_json::Value::Null),
    ] {
        let tgt = if rel == "authored" {
            (p, "paper")
        } else {
            (x, "claim")
        };
        let r = insert_as(
            &scoped,
            &v,
            false,
            src,
            tgt,
            rel,
            serde_json::json!({ KEY: value }),
        )
        .await;
        assert!(
            refused(&r),
            "an undeclared {rel} carrying {KEY}={value} was written: {r:?}"
        );
    }

    // The application repository call POST /api/v1/edges makes, too.
    let mut tx = scoped.begin_as(&v).await.expect("stamped tx");
    let r = epigraph_db::EdgeRepository::create(
        &mut *tx,
        author,
        "agent",
        x,
        "claim",
        "asserts",
        Some(serde_json::json!({ KEY: "ingest_document", "role": "author" })),
        None,
        None,
    )
    .await;
    assert!(
        r.as_ref()
            .is_err_and(|e| format!("{e:?}").contains("IWE01")),
        "EdgeRepository::create wrote a marked edge: {r:?}"
    );
    drop(tx);

    // No privileged arm: a superuser session is refused as well.
    let r = sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            properties) \
         VALUES ($1, 'agent', $2, 'claim', 'asserts', $3)",
    )
    .bind(author)
    .bind(x)
    .bind(serde_json::json!({ KEY: "ingest_document" }))
    .execute(&pool)
    .await;
    assert!(refused(&r), "a superuser wrote an undeclared marker: {r:?}");

    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM edges WHERE properties ? $1")
        .bind(KEY)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(n, 0, "no marked edge exists");
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_undeclared_update_cannot_add_or_change_the_marker(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (writer, group) = fixture::seed_agent_with_group(&pool, "writer").await;
    let v = viewer(&pool, writer).await;
    let p = paper(&pool, "10.9999/marker.update.1").await;
    let x = fixture::seed_group_claim(&pool, writer, group, "a group finding").await;
    let y = fixture::seed_group_claim(&pool, writer, group, "another group finding").await;

    // An unmarked edge this session owns (it takes the claim's group).
    let plain = insert_as(
        &scoped,
        &v,
        false,
        (p, "paper"),
        (x, "claim"),
        "asserts",
        serde_json::json!({}),
    )
    .await
    .expect("plain edge");
    // CALIBRATION: the session may update it at all.
    let n = update_as(
        &scoped,
        &v,
        "UPDATE edges SET properties = properties || '{\"note\": \"kept\"}' WHERE id = $1",
        plain,
    )
    .await
    .expect("CALIBRATION: an owner property patch");
    assert_eq!(n, 1, "CALIBRATION: the owner's update reached the row");

    let r = update_as(
        &scoped,
        &v,
        "UPDATE edges SET properties = properties || '{\"ingest_written\": \"ingest_document\"}' \
          WHERE id = $1",
        plain,
    )
    .await;
    assert!(refused(&r), "an owner added the marker: {r:?}");
    assert!(props_of(&pool, plain).await.get(KEY).is_none());

    // A marked edge the walk wrote, in the same group.
    let marked = insert_as(
        &scoped,
        &v,
        true,
        (p, "paper"),
        (y, "claim"),
        "asserts",
        serde_json::json!({ KEY: "ingest_document" }),
    )
    .await
    .expect("the declared walk write");
    let r = update_as(
        &scoped,
        &v,
        "UPDATE edges SET properties = properties || '{\"ingest_written\": \"forged\"}' \
          WHERE id = $1",
        marked,
    )
    .await;
    assert!(refused(&r), "an owner changed the marker: {r:?}");
    // Keeping it, or dropping it, is not refused.
    update_as(
        &scoped,
        &v,
        "UPDATE edges SET properties = properties || '{\"note\": \"kept\"}' WHERE id = $1",
        marked,
    )
    .await
    .expect("an update that keeps the marker");
    assert_eq!(props_of(&pool, marked).await[KEY], "ingest_document");
    update_as(
        &scoped,
        &v,
        "UPDATE edges SET properties = properties - 'ingest_written' WHERE id = $1",
        marked,
    )
    .await
    .expect("an update that drops the marker");
    assert!(props_of(&pool, marked).await.get(KEY).is_none());

    // Superuser: refused too.
    let r = sqlx::query(
        "UPDATE edges SET properties = properties || '{\"ingest_written\": \"x\"}' WHERE id = $1",
    )
    .bind(plain)
    .execute(&pool)
    .await;
    assert!(refused(&r), "a superuser added the marker: {r:?}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_moved_marked_edge_loses_the_marker(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (writer, group) = fixture::seed_agent_with_group(&pool, "writer").await;
    let v = viewer(&pool, writer).await;
    let p = paper(&pool, "10.9999/marker.move.1").await;
    let x = fixture::seed_group_claim(&pool, writer, group, "the asserted finding").await;
    let y = fixture::seed_group_claim(&pool, writer, group, "an unrelated finding").await;
    let z = fixture::seed_group_claim(&pool, writer, group, "a third finding").await;

    let a = insert_as(
        &scoped,
        &v,
        true,
        (p, "paper"),
        (x, "claim"),
        "asserts",
        serde_json::json!({ KEY: "ingest_document", "section": "kept" }),
    )
    .await
    .expect("the declared walk write");
    // An owner re-point (117 section 1a lets the owner move an edge).
    let n = update_as(
        &scoped,
        &v,
        &format!("UPDATE edges SET target_id = '{y}' WHERE id = $1"),
        a,
    )
    .await
    .expect("the owner's re-point");
    assert_eq!(n, 1, "CALIBRATION: the re-point reached the row");
    let after = props_of(&pool, a).await;
    assert!(
        after.get(KEY).is_none(),
        "a re-pointed edge kept the marker: {after}"
    );
    assert_eq!(after["section"], "kept", "only the marker is dropped");

    // A privileged re-point (the supersede and dedup cascades) drops it too.
    let b = insert_as(
        &scoped,
        &v,
        true,
        (p, "paper"),
        (x, "claim"),
        "asserts",
        serde_json::json!({ KEY: "ingest_document" }),
    )
    .await
    .expect("the declared walk write");
    sqlx::query("UPDATE edges SET target_id = $2 WHERE id = $1")
        .bind(b)
        .bind(z)
        .execute(&pool)
        .await
        .expect("a privileged re-point");
    assert!(props_of(&pool, b).await.get(KEY).is_none());

    // And a relationship change.
    let c = insert_as(
        &scoped,
        &v,
        true,
        (p, "paper"),
        (x, "claim"),
        "asserts",
        serde_json::json!({ KEY: "ingest_document" }),
    )
    .await;
    // (x is asserted again: the triple of `a` and `b` moved away.)
    let c = c.expect("the declared walk write");
    sqlx::query("UPDATE edges SET relationship = 'cites' WHERE id = $1")
        .bind(c)
        .execute(&pool)
        .await
        .expect("a relationship change");
    assert!(props_of(&pool, c).await.get(KEY).is_none());
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_declaration_ends_with_its_transaction(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let p = paper(&pool, "10.9999/marker.local.1").await;
    let x = fixture::seed_public_claim(&pool, author, "a finding").await;
    let mut conn = pool.acquire().await.expect("one connection");

    let mut tx = sqlx::Connection::begin(&mut *conn).await.expect("tx");
    sqlx::query("SELECT pg_catalog.set_config($1, 'on', true)")
        .bind(SETTING)
        .execute(&mut *tx)
        .await
        .expect("declare");
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            properties) VALUES ($1, 'paper', $2, 'claim', 'asserts', $3)",
    )
    .bind(p)
    .bind(x)
    .bind(serde_json::json!({ KEY: "ingest_document" }))
    .execute(&mut *tx)
    .await
    .expect("CALIBRATION: the declared write");
    tx.commit().await.expect("commit");

    // The same connection, the next transaction: no declaration.
    let r = sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            properties) VALUES ($1, 'agent', $2, 'claim', 'asserts', $3)",
    )
    .bind(author)
    .bind(x)
    .bind(serde_json::json!({ KEY: "ingest_document" }))
    .execute(&mut *conn)
    .await;
    assert!(
        refused(&r),
        "the declaration outlived its transaction: {r:?}"
    );
}

/// The walk's writer marks its edge, declares the walk for that INSERT only
/// (a later write of the same transaction cannot carry the key), and writes
/// no shape outside the three a provenance read trusts.
#[sqlx::test(migrations = "../../migrations")]
async fn the_walks_writer_declares_only_its_own_insert(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (ingester, _) = fixture::seed_agent_with_group(&pool, "ingest-runner").await;
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let v = viewer(&pool, ingester).await;
    let p = paper(&pool, "10.9999/marker.writer.1").await;
    let x = fixture::seed_public_claim(&pool, ingester, "a finding").await;

    let mut tx = scoped.begin_as(&v).await.expect("stamped tx");
    let (row, created) = epigraph_db::create_ingest_written_edge_if_absent_conn(
        &mut tx,
        None,
        "ingest_document",
        p,
        "paper",
        x,
        "claim",
        "asserts",
        Some(serde_json::json!({"section": "results"})),
    )
    .await
    .expect("the walk's write");
    assert!(created);
    assert_eq!(row.properties[KEY], "ingest_document");
    assert_eq!(row.properties["section"], "results");
    let r = sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            properties) VALUES ($1, 'agent', $2, 'claim', 'asserts', $3)",
    )
    .bind(author)
    .bind(x)
    .bind(serde_json::json!({ KEY: "ingest_document" }))
    .execute(&mut *tx)
    .await;
    assert!(
        refused(&r),
        "a write after the walk's own kept its declaration: {r:?}"
    );
    drop(tx);

    let mut tx = scoped.begin_as(&v).await.expect("stamped tx");
    let r = epigraph_db::create_ingest_written_edge_if_absent_conn(
        &mut tx,
        None,
        "ingest_document",
        x,
        "claim",
        p,
        "paper",
        "asserts",
        None,
    )
    .await;
    assert!(r.is_err(), "a shape no read trusts was marked: {r:?}");
}
