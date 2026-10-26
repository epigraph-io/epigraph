//! `theme_cluster`'s destructive wipe is admin-only and canonical-prefix-only
//! (backlog 5abe23de).
//!
//! On 2026-09-23 a post-tenancy sweep probe called `theme_cluster` with
//! `label_prefix = "sweep-probe"` and no `wipe_first`. The MCP tool defaulted
//! `wipe_first` to `true` and gated only on `reject_if_read_only`, so the call
//! ran `ClaimThemeRepository::delete_all_conn` (every theme, every
//! `claims.theme_id`) and replaced the production theme set with probe output.
//! The REST twin (`POST /api/v1/themes/build-from-corpus`) already defaulted to
//! `false` behind `claims:admin`.
//!
//! # Fixture
//!
//! Each test runs on its own freshly migrated database (`sqlx::test`), seeded
//! with:
//! * a SENTINEL theme row standing in for the live theme set, and a sentinel
//!   claim assigned to it that carries NO embedding (so a run cannot re-assign
//!   it: only a wipe can move its `theme_id`);
//! * two public claims WITH embeddings, so the corpus read returns rows and the
//!   run reaches the persist step, where the wipe lives.
//!
//! The run is pinned to `k = 1` with `min_claims_per_theme` far above the
//! corpus, so the single cluster is skipped: no theme is created and no
//! `bulk_assign` runs. What remains observable is exactly the wipe.
//! `admin_wipe_with_the_canonical_prefix_replaces_the_set` is the calibration:
//! it proves this fixture DOES observe a wipe, so the "untouched" assertions
//! elsewhere are not vacuous.
//!
//! # Out of scope
//!
//! These tests pin the WIPE only. An admitted additive run (the default, open
//! to a `claims:write` caller under any prefix) that does create themes still
//! re-points its clustered claims' `theme_id` at the new themes
//! (`ClaimThemeRepository::bulk_assign`); this fixture deliberately cannot
//! observe that, and nothing here claims it is prevented.

mod common;

use common::*;
use epigraph_mcp::tools::themes::{theme_cluster, ThemeClusterParams};
use sqlx::PgPool;
use uuid::Uuid;

fn unit_embedding(axis: usize) -> String {
    let mut v = vec!["0.0"; 1536];
    v[axis] = "0.1";
    format!("[{}]", v.join(","))
}

/// The sentinel theme id and its (embedding-less) member claim.
async fn seed_live_theme_set(pool: &PgPool) -> (Uuid, Uuid) {
    let theme: Uuid = sqlx::query_scalar(
        "INSERT INTO claim_themes (label, description) VALUES ('live-00', 'the live set') \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed sentinel theme");
    let member = seed_claim(pool, "sentinel member of the live theme set", 0.5).await;
    sqlx::query("UPDATE claims SET theme_id = $1 WHERE id = $2")
        .bind(theme)
        .bind(member)
        .execute(pool)
        .await
        .expect("assign sentinel member");

    for axis in 0..2 {
        let id = seed_claim(pool, &format!("embedded corpus claim {axis}"), 0.5).await;
        sqlx::query("UPDATE claims SET embedding = $1::vector WHERE id = $2")
            .bind(unit_embedding(axis))
            .bind(id)
            .execute(pool)
            .await
            .expect("plant embedding");
    }
    let public_embedded: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM claims WHERE embedding IS NOT NULL AND visibility = 'public'",
    )
    .fetch_one(pool)
    .await
    .expect("count corpus");
    assert!(
        public_embedded >= 1,
        "calibration: the run must reach the persist step, so the corpus read needs a row"
    );
    (theme, member)
}

/// `(sentinel theme still present, sentinel member's theme_id)`.
async fn live_set_state(pool: &PgPool, theme: Uuid, member: Uuid) -> (bool, Option<Uuid>) {
    let present: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM claim_themes WHERE id = $1)")
            .bind(theme)
            .fetch_one(pool)
            .await
            .expect("read sentinel theme");
    let theme_id: Option<Uuid> = sqlx::query_scalar("SELECT theme_id FROM claims WHERE id = $1")
        .bind(member)
        .fetch_one(pool)
        .await
        .expect("read sentinel member");
    (present, theme_id)
}

fn params(wipe_first: Option<bool>, label_prefix: Option<&str>) -> ThemeClusterParams {
    ThemeClusterParams {
        k: Some(1),
        k_min: Some(1),
        k_max: Some(1),
        // Far above the corpus: the one cluster is skipped, so the run creates
        // no theme and assigns no claim; only the wipe can change anything.
        min_claims_per_theme: Some(100_000),
        limit: None,
        label_prefix: label_prefix.map(str::to_string),
        centroid_dim: None,
        wipe_first,
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn non_admin_call_with_defaults_does_not_wipe_the_theme_set(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let (theme, member) = seed_live_theme_set(&pool).await;
    let (_, writer, _) = seed_caller(&pool, &["claims:write"]).await;

    let result = theme_cluster(&server, params(None, Some("sweep-probe")), Some(&writer))
        .await
        .expect("an additive run is open to a claims:write caller");
    let body = first_text(&result);
    assert_eq!(
        body["themes_created"], 0,
        "calibration: no cluster survives: {body}"
    );

    assert_eq!(
        live_set_state(&pool, theme, member).await,
        (true, Some(theme)),
        "a theme_cluster call that did not ask for a wipe must not wipe: the sentinel theme \
         survives and its embedding-less member keeps its theme_id (backlog 5abe23de: the \
         default used to be wipe_first=true)"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn non_admin_wipe_is_refused_and_writes_nothing(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let (theme, member) = seed_live_theme_set(&pool).await;
    let (_, writer, _) = seed_caller(&pool, &["claims:write"]).await;

    let err = theme_cluster(&server, params(Some(true), None), Some(&writer))
        .await
        .expect_err("wipe_first=true from a caller without claims:admin must be refused");
    assert!(
        err.message.contains("claims:admin"),
        "the refusal must name the scope a wipe needs: {}",
        err.message
    );
    assert_eq!(
        live_set_state(&pool, theme, member).await,
        (true, Some(theme)),
        "a refused wipe must write nothing"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn admin_wipe_with_a_non_canonical_prefix_is_refused(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let (theme, member) = seed_live_theme_set(&pool).await;
    let (admin, _) = server_admin(&server).await;

    let err = theme_cluster(
        &server,
        params(Some(true), Some("sweep-probe")),
        Some(&admin),
    )
    .await
    .expect_err(
        "a wipe replaces the WHOLE live set, so it may only rebuild the canonical \
             \"auto\" family, never a probe- or test-prefixed one",
    );
    assert!(
        err.message.contains("\"auto\""),
        "the refusal must name the canonical prefix: {}",
        err.message
    );
    assert_eq!(
        live_set_state(&pool, theme, member).await,
        (true, Some(theme)),
        "a refused wipe must write nothing"
    );
}

/// Calibration for the three tests above: in this fixture an admitted wipe IS
/// observable (the sentinel theme is deleted and its member's `theme_id`
/// cleared). It also pins that the gate is not a blanket refusal: a
/// `claims:admin` caller rebuilding the canonical family still wipes.
#[sqlx::test(migrations = "../../migrations")]
async fn admin_wipe_with_the_canonical_prefix_replaces_the_set(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let (theme, member) = seed_live_theme_set(&pool).await;
    let (admin, _) = server_admin(&server).await;

    theme_cluster(&server, params(Some(true), None), Some(&admin))
        .await
        .expect("a claims:admin wipe of the canonical family is admitted");

    assert_eq!(
        live_set_state(&pool, theme, member).await,
        (false, None),
        "an admitted wipe deletes every theme and clears every claims.theme_id"
    );
}
