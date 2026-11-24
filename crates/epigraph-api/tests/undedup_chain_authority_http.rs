#![cfg(feature = "db")]
//! `POST /api/v1/claims/:id/undedup`: the chain-wide database authority check
//! (backlog 065d0d9b part 1).
//!
//! The route proves the caller's authority twice. The per-claim rule
//! (`require_claim_act_authority`) admits a `claims:admin` caller over every
//! claim it can read. Then the database's write predicate
//! (`ClaimRepository::session_may_unmark_conn`) is asked, on the caller's
//! stamped transaction, for the duplicate against EVERY claim of the
//! canonical's chain, because the reversal (on the maintenance connection)
//! moves rows off each of them. Nothing pinned that loop: the existing route
//! tests run on a superuser pool (where the predicate is always true) or use
//! public claims (which it admits), so deleting it, or narrowing it to the
//! canonical alone, left every test green.
//!
//! Here the canonical was merged, by another agent, with that agent's
//! group-private claim: the chain is [canonical, merged], the merged claim is
//! private to a group the caller only READS, and the caller holds
//! `claims:admin`. The per-claim rule admits it; the loop's second link does
//! not.

mod viewer_fixture;

use axum::extract::{Path, State};
use axum::response::IntoResponse;
use axum::Extension;
use axum::Json;
use epigraph_api::middleware::bearer::AuthContext;
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::middleware::ClientType;
use epigraph_api::routes::versioning::{mark_duplicate, unmark_duplicate, DedupRequest};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{database_url_for, downgraded_pool, seed_agent_with_group};

/// Both request pools on the application role, the maintenance pool a
/// NOSUPERUSER `epigraph_maintenance` login, and the administrative cascade on:
/// the un-mark's act and reversal commit in the request.
async fn app_role_state(pool: &PgPool) -> AppState {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(!bypassrls, "epigraph_app holds BYPASSRLS: vacuous");
    let url = database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool")
            .with_maintenance_pool(downgraded_pool(pool, "epigraph_maintenance").await);
    let raw = downgraded_pool(pool, "epigraph_app").await;
    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(scoped);
    state.admin_cascade = true;
    state
        .load_entity_type_cache()
        .await
        .expect("load the entity-type cache");
    state
}

fn token(agent: Uuid, scopes: &[&str]) -> Option<Extension<AuthContext>> {
    Some(Extension(AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: Some(Uuid::new_v4()),
        client_type: ClientType::Human,
        scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }))
}

async fn claim_of(pool: &PgPool, agent: Uuid, group: Uuid, visibility: &str, tag: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, $5, $6)",
    )
    .bind(id)
    .bind(format!("{tag} {id}"))
    .bind(&hash)
    .bind(agent)
    .bind(visibility)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

async fn dup_state(pool: &PgPool, dup: Uuid) -> (Option<Uuid>, bool) {
    sqlx::query_as("SELECT supersedes, is_current FROM claims WHERE id = $1")
        .bind(dup)
        .fetch_one(pool)
        .await
        .expect("dup")
}

async fn undedup_rows(pool: &PgPool, dup: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM security_events \
          WHERE details->>'cause' = 'undedup' AND details->'trigger'->>'subject_id' = $1",
    )
    .bind(dup.to_string())
    .fetch_one(pool)
    .await
    .expect("count undedup rows")
}

/// A `claims:admin` caller that writes the duplicate and the canonical, but
/// only READS the claim another agent merged the canonical into, is refused
/// 403 with nothing written: the database's predicate over the chain's second
/// link says no although the per-claim rule (`claims:admin`) said yes.
///
/// Red if the chain loop is removed (the un-mark lands, 200), or narrowed to
/// the canonical (the first link, which the caller writes).
///
/// CONTROL: once the caller WRITES the merged claim's group, the same un-mark
/// lands, so the 403 is that link's and not the fixture's.
#[sqlx::test(migrations = "../../migrations")]
async fn undedup_needs_database_write_authority_over_every_link_of_the_chain(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (c, cg) = seed_agent_with_group(&pool, "065d-caller").await;
    let (o, og) = seed_agent_with_group(&pool, "065d-other").await;
    let dup = claim_of(&pool, c, cg, "public", "065d duplicate").await;
    let canonical = claim_of(&pool, c, cg, "public", "065d canonical").await;
    let partner = claim_of(&pool, o, og, "group", "065d private partner").await;

    let viewer_c = || async { Viewer::resolve(&pool, c).await.expect("resolve") };
    let Json(marked) = mark_duplicate(
        ViewerExtractor(viewer_c().await),
        State(state.clone()),
        token(c, &["claims:write"]),
        Path(dup),
        Json(DedupRequest {
            canonical_id: canonical,
            reason: None,
        }),
    )
    .await
    .expect("the caller marks its own duplicate");
    assert_eq!(
        serde_json::to_value(&marked.cascade).expect("cascade")["status"],
        "applied",
        "calibration: the mark's repair ran in the request (a revert record exists)"
    );

    // The other agent merges the canonical with its own private claim.
    let merged = {
        let mut conn = pool.acquire().await.expect("acquire");
        let merged = epigraph_db::ClaimRepository::consolidate_act_conn(
            &mut conn,
            None,
            &[canonical, partner],
            &format!("065d merged {}", Uuid::new_v4()),
            0.5,
            epigraph_db::repos::claim::ConsolidateMode::Merge,
            "merge",
            o,
        )
        .await
        .expect("the other agent merges the canonical")
        .merged_id;
        epigraph_db::ClaimRepository::migrate_consolidated_edges_conn(
            &mut conn,
            merged,
            &[canonical, partner],
        )
        .await
        .expect("edge migration");
        merged
    };
    let (vis, owner): (String, Uuid) =
        sqlx::query_as("SELECT visibility::text, owner_group_id FROM claims WHERE id = $1")
            .bind(merged)
            .fetch_one(&pool)
            .await
            .expect("merged");
    assert_eq!(
        (vis.as_str(), owner),
        ("group", og),
        "calibration: the merged claim is private to the other agent's group"
    );

    // The caller READS that group, and does not write it.
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'reader')",
    )
    .bind(og)
    .bind(c)
    .execute(&pool)
    .await
    .expect("reader membership");
    let v = viewer_c().await;
    assert!(
        v.group_bind().is_some_and(|g| g.contains(&og)),
        "calibration: the caller reads the merged claim's group"
    );
    assert!(
        !v.writable_groups().contains(&og) && v.writable_groups().contains(&cg),
        "calibration: the caller writes its own group and not the merged claim's"
    );

    let admin = ["claims:write", "claims:admin"];
    let e = unmark_duplicate(
        ViewerExtractor(v),
        State(state.clone()),
        token(c, &admin),
        Path(dup),
    )
    .await
    .expect_err("the caller cannot write the merged claim");
    let resp = e.into_response();
    let status = resp.status().as_u16();
    let body = String::from_utf8_lossy(&resp.into_body().collect().await.expect("body").to_bytes())
        .into_owned();
    assert_eq!(status, 403, "{body}");
    assert!(
        body.contains("no write authority over the group that owns this claim"),
        "the database's refusal, not the per-claim rule's (claims:admin passed it): {body}"
    );
    assert_eq!(
        dup_state(&pool, dup).await,
        (Some(canonical), false),
        "the duplicate stays marked"
    );
    assert_eq!(undedup_rows(&pool, dup).await, 0, "no un-mark recorded");

    // CONTROL: the caller now writes the merged claim's group.
    sqlx::query(
        "UPDATE group_memberships SET role = 'writer' WHERE group_id = $1 AND agent_id = $2",
    )
    .bind(og)
    .bind(c)
    .execute(&pool)
    .await
    .expect("writer membership");
    let Json(resp) = unmark_duplicate(
        ViewerExtractor(viewer_c().await),
        State(state),
        token(c, &admin),
        Path(dup),
    )
    .await
    .unwrap_or_else(|e| panic!("CONTROL: a writer of every link un-marks: {e:?}"));
    assert_eq!(resp.current_canonical_id, merged, "followed to the merge");
    assert_eq!(dup_state(&pool, dup).await, (None, true), "un-marked");
}
