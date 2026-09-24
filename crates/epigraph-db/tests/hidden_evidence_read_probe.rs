//! B-H3 (operator directive 2026-09-23, Amendment 2): does a HIDDEN evidence
//! row reach a viewer outside its group through any read path that returns
//! `evidence.raw_content`, `source_url` or `properties`?
//!
//! # The shape probed
//!
//! A hidden row is `evidence.visibility = 'group'`, owned by the operator's
//! personal group, hanging off a claim that stays PUBLIC, with the
//! `evidence → claim` edge left `('public', world)` — the hide changes exactly
//! the selected rows' visibility and no other row's, so the edge keeps its
//! tenancy. The write path that produces this state is `epigraph-operator
//! hide-evidence --apply` (`epigraph-cli/src/operator/hide.rs`, which also
//! pins the row under migration 110); a crate-level test cannot run that
//! binary, so the fixture constructs the same state directly, and the read
//! side cannot tell the difference.
//!
//! # The read paths, enumerated
//!
//! Every non-test function in `crates/` that reads `evidence` content columns
//! (`raw_content`, `source_url`, `properties`), found by scanning each
//! function body for a `FROM/JOIN evidence` together with one of those
//! columns:
//!
//! * `EvidenceRepository::{get_by_id, get_by_claim, provided_for_claim_as_of,
//!   detail_by_id, by_relationship_for_claim, list_filtered, count_filtered,
//!   search_by_embedding}` and `GraphViewRepository::subgraph_evidence` —
//!   every HTTP route and MCP tool that returns evidence content reaches it
//!   through one of these, with the request's `Viewer`
//!   (`routes/crud.rs`, `routes/edges.rs`, `routes/rag.rs`, `routes/claims.rs`,
//!   `routes/graph_query_utils.rs`, `routes/staging.rs`). PROBED below.
//! * `ClaimRepository::inherit_evidence` writes a `derived_from` edge to every
//!   evidence row of the old claim, hidden ones included; PROBED in
//!   [`the_surfaces_outside_the_content_reads_are_measured`] (the edge takes
//!   the meet and is withheld). `epigraph_engine::edge_factor::auto_wire_ds_for_edge`
//!   reads `properties` to WRITE a DS factor, not to return it. Not probed;
//!   listed in the branch's not_done.
//! * Maintenance and operator binaries on a privileged pool, which see every
//!   row by design: `epigraph-cli`'s `analyze_graph`, `backfill_factors`,
//!   `ingest_literature::build_packets`, `reembed`, and
//!   `PrivatizationRepository::{seal,unseal}_manifest_page_conn`. Not a viewer
//!   path; listed.
//!
//! No event payload carries evidence content (`EventRepository` publishes
//! claim- and edge-shaped events only), and there is no evidence export route.
//!
//! # Two executors per probe, because a bypass pool ignores RLS
//!
//! * PREDICATE path: the harness's superuser pool, which bypasses RLS, with the
//!   stranger's `Viewer`. Only the in-query `{VISIBILITY:…}` predicate stands
//!   between the row and the caller — the situation of every handler that runs
//!   on a privileged pool.
//! * RLS path: `epigraph_app` via `SET SESSION AUTHORIZATION`, stamped with the
//!   stranger's groups, so the policies are live too.
//!
//! Each is CALIBRATED: the owner's viewer on the same executor does see the
//! row, so "the stranger saw nothing" is not an empty table.
//!
//! MEASURED as known surfaces in
//! [`the_surfaces_outside_the_content_reads_are_measured`]: the claim's own
//! text and an edge touching the hidden row stay readable to a non-member.
//! NOT covered here: `harvester_fragments.content_text`,
//! `mass_functions.evidence_type`, a BYPASSRLS or superuser connection with a
//! bypass viewer, and anything emitted before a row was hidden. Hiding is
//! forward-only.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_core::{ClaimId, EvidenceId};
use epigraph_db::repos::GraphViewRepository;
use epigraph_db::{EvidenceListFilter, EvidenceRepository, Viewer};
use sqlx::{PgConnection, PgPool};
use std::collections::BTreeMap;
use uuid::Uuid;

const SENTINEL: &str = "HIDDEN-EVIDENCE-SENTINEL";

struct Fx {
    owner_group: Uuid,
    owner: Uuid,
    stranger: Uuid,
    claim: Uuid,
    hidden: Uuid,
}

fn vec_literal(x: f32) -> String {
    let v: Vec<String> = (0..1536).map(|_| format!("{x}")).collect();
    format!("[{}]", v.join(","))
}

async fn seed(pool: &PgPool) -> Fx {
    let (owner, owner_group) = fixture::seed_agent_with_group(pool, "hide-owner").await;
    let (stranger, _) = fixture::seed_agent_with_group(pool, "hide-stranger").await;
    let claim =
        fixture::seed_public_claim(pool, owner, "a public claim with hidden evidence").await;
    let hidden = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO evidence (id, claim_id, evidence_type, content_hash, raw_content, \
                               source_url, properties, embedding) \
         VALUES ($1, $2, 'testimony', $3, $4, $5, $6, $7::vector)",
    )
    .bind(hidden)
    .bind(claim)
    .bind(
        hidden
            .as_bytes()
            .iter()
            .copied()
            .cycle()
            .take(32)
            .collect::<Vec<u8>>(),
    )
    .bind(format!("{SENTINEL} raw content"))
    .bind(format!("https://hidden.example/{SENTINEL}"))
    .bind(serde_json::json!({ "note": SENTINEL }))
    .bind(vec_literal(0.01))
    .execute(pool)
    .await
    .expect("seed evidence");
    // Hide it the way the operator tool would leave it: the row alone.
    sqlx::query("UPDATE evidence SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
        .bind(hidden)
        .bind(owner_group)
        .execute(pool)
        .await
        .expect("hide evidence");
    // The evidence -> claim edge, left public exactly as a hide leaves it.
    let edge = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, \
                            properties) \
         VALUES ($1, $2, 'evidence', $3, 'claim', 'supports', '{\"strength\": 0.9}')",
    )
    .bind(edge)
    .bind(hidden)
    .bind(claim)
    .execute(pool)
    .await
    .expect("seed edge");
    sqlx::query(
        "UPDATE edges SET visibility = 'public', owner_group_id = $2, co_owner_group_id = NULL \
          WHERE id = $1",
    )
    .bind(edge)
    .bind(Uuid::nil())
    .execute(pool)
    .await
    .expect("leave the edge public");
    Fx {
        owner_group,
        owner,
        stranger,
        claim,
        hidden,
    }
}

/// Which read paths returned the hidden row to `viewer` on `conn`.
async fn probe(conn: &mut PgConnection, viewer: &Viewer, fx: &Fx) -> BTreeMap<&'static str, bool> {
    let mut seen = BTreeMap::new();
    let h = fx.hidden;
    seen.insert(
        "EvidenceRepository::get_by_id",
        EvidenceRepository::get_by_id(&mut *conn, viewer, EvidenceId::from(h))
            .await
            .expect("get_by_id")
            .is_some(),
    );
    seen.insert(
        "EvidenceRepository::get_by_claim",
        EvidenceRepository::get_by_claim(&mut *conn, viewer, ClaimId::from(fx.claim))
            .await
            .expect("get_by_claim")
            .iter()
            .any(|e| Uuid::from(e.id) == h),
    );
    seen.insert(
        "EvidenceRepository::provided_for_claim_as_of",
        EvidenceRepository::provided_for_claim_as_of(
            &mut *conn,
            viewer,
            fx.claim,
            chrono::Utc::now() + chrono::Duration::hours(1),
        )
        .await
        .expect("provided_for_claim_as_of")
        .iter()
        .any(|r| r.id == h),
    );
    seen.insert(
        "EvidenceRepository::detail_by_id",
        EvidenceRepository::detail_by_id(&mut *conn, viewer, h)
            .await
            .expect("detail_by_id")
            .is_some(),
    );
    seen.insert(
        "EvidenceRepository::by_relationship_for_claim",
        EvidenceRepository::by_relationship_for_claim(&mut *conn, viewer, fx.claim, "supports")
            .await
            .expect("by_relationship_for_claim")
            .iter()
            .any(|r| r.evidence_id == h),
    );
    let filter = EvidenceListFilter {
        claim_id: Some(fx.claim),
        ..Default::default()
    };
    seen.insert(
        "EvidenceRepository::list_filtered",
        EvidenceRepository::list_filtered(&mut *conn, viewer, &filter, 100, 0)
            .await
            .expect("list_filtered")
            .iter()
            .any(|r| r.id == h),
    );
    seen.insert(
        "EvidenceRepository::count_filtered",
        EvidenceRepository::count_filtered(&mut *conn, viewer, &filter)
            .await
            .expect("count_filtered")
            > 0,
    );
    seen.insert(
        "EvidenceRepository::search_by_embedding",
        EvidenceRepository::search_by_embedding(&mut *conn, viewer, &vec_literal(0.01), 50)
            .await
            .expect("search_by_embedding")
            .iter()
            .any(|r| r.id == h),
    );
    seen.insert(
        "GraphViewRepository::subgraph_evidence",
        GraphViewRepository::subgraph_evidence(&mut *conn, viewer, &[h])
            .await
            .expect("subgraph_evidence")
            .iter()
            .any(|r| r.id == h),
    );
    seen
}

async fn stamp(conn: &mut PgConnection, v: &Viewer) {
    let join = |ids: Option<&[Uuid]>| {
        ids.unwrap_or(&[])
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    };
    sqlx::query(
        "SELECT set_config('epigraph.group_ids', $1, false), \
                set_config('epigraph.writable_group_ids', $2, false), \
                set_config('epigraph.principal_id', $3, false)",
    )
    .bind(join(v.group_bind()))
    .bind(join(v.writable_bind()))
    .bind(v.principal().map(|p| p.to_string()).unwrap_or_default())
    .execute(&mut *conn)
    .await
    .expect("stamp GUCs");
}

fn leaks(seen: &BTreeMap<&'static str, bool>) -> Vec<&'static str> {
    seen.iter().filter(|(_, v)| **v).map(|(k, _)| *k).collect()
}

fn misses(seen: &BTreeMap<&'static str, bool>) -> Vec<&'static str> {
    seen.iter().filter(|(_, v)| !**v).map(|(k, _)| *k).collect()
}

/// PREDICATE path: a privileged pool that bypasses RLS, with the stranger's
/// viewer. Every enumerated read must withhold the hidden row; the owner's
/// viewer on the same pool must get it from every one.
#[sqlx::test(migrations = "../../migrations")]
async fn a_hidden_evidence_row_is_withheld_on_a_privileged_pool(pool: PgPool) {
    let fx = seed(&pool).await;
    let stranger = Viewer::resolve(&pool, fx.stranger).await.expect("resolve");
    let owner = Viewer::resolve(&pool, fx.owner).await.expect("resolve");
    assert!(
        owner.group_bind().unwrap_or(&[]).contains(&fx.owner_group),
        "calibration: the owner is a member of the hiding group"
    );
    let mut conn = pool.acquire().await.unwrap();
    let as_owner = probe(&mut conn, &owner, &fx).await;
    assert!(
        misses(&as_owner).is_empty(),
        "calibration: the owner must see the row through every path, missed {:?}",
        misses(&as_owner)
    );
    let as_stranger = probe(&mut conn, &stranger, &fx).await;
    assert!(
        leaks(&as_stranger).is_empty(),
        "a non-member received the hidden row through {:?}",
        leaks(&as_stranger)
    );
}

/// RLS path: `epigraph_app` under `SET SESSION AUTHORIZATION`, stamped as the
/// stranger, then as the owner for calibration.
#[sqlx::test(migrations = "../../migrations")]
async fn a_hidden_evidence_row_is_withheld_on_an_app_session(pool: PgPool) {
    let fx = seed(&pool).await;
    let stranger = Viewer::resolve(&pool, fx.stranger).await.expect("resolve");
    let owner = Viewer::resolve(&pool, fx.owner).await.expect("resolve");
    let mut conn = pool.acquire().await.unwrap();
    sqlx::query("SET SESSION AUTHORIZATION epigraph_app")
        .execute(&mut *conn)
        .await
        .expect("become epigraph_app");
    let bypass: bool = sqlx::query_scalar("SELECT public.epigraph_bypass()")
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    assert!(
        !bypass,
        "epigraph_app must not bypass, or this arm is vacuous"
    );

    stamp(&mut conn, &owner).await;
    let as_owner = probe(&mut conn, &owner, &fx).await;
    stamp(&mut conn, &stranger).await;
    let as_stranger = probe(&mut conn, &stranger, &fx).await;
    sqlx::query("RESET SESSION AUTHORIZATION")
        .execute(&mut *conn)
        .await
        .expect("reset");

    assert!(
        misses(&as_owner).is_empty(),
        "calibration: the stamped owner must see the row through every path, missed {:?}",
        misses(&as_owner)
    );
    assert!(
        leaks(&as_stranger).is_empty(),
        "a stamped non-member received the hidden row through {:?}",
        leaks(&as_stranger)
    );
}

/// Count of rows `sql` (one uuid bind) returns to `epigraph_app` stamped as
/// `viewer`.
async fn app_count(pool: &PgPool, viewer: &Viewer, sql: &str, id: Uuid) -> i64 {
    let mut conn = pool.acquire().await.unwrap();
    sqlx::query("SET SESSION AUTHORIZATION epigraph_app")
        .execute(&mut *conn)
        .await
        .expect("become epigraph_app");
    stamp(&mut conn, viewer).await;
    let n: i64 = sqlx::query_scalar(sql)
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .unwrap_or_else(|e| panic!("{sql}: {e}"));
    sqlx::query("RESET SESSION AUTHORIZATION")
        .execute(&mut *conn)
        .await
        .expect("reset");
    n
}

/// B-H3's surfaces OUTSIDE the evidence content reads, MEASURED as a
/// non-member on an `epigraph_app` session, so the operator tool's
/// `HIDE-SURFACE` lines describe observed behaviour rather than a reading of
/// the code:
///
/// * the hidden row itself (`raw_content`, `source_url`, `properties` by a
///   direct SELECT): WITHHELD;
/// * an edge touching the hidden row, left public by the hide: READABLE (ids,
///   relationship and properties; no evidence content), a known surface;
/// * the claim the row hangs off, and its text: READABLE, by design;
/// * the `derived_from` edge `ClaimRepository::inherit_evidence` writes from a
///   survivor claim to every evidence row of the old claim, hidden ones
///   included: WITHHELD, because the edge tenancy trigger takes the meet of a
///   public claim and a `group` evidence row, which is `group` in the hiding
///   group.
///
/// If a surface changes, this test fails and the tool's lines must change
/// with it.
#[sqlx::test(migrations = "../../migrations")]
async fn the_surfaces_outside_the_content_reads_are_measured(pool: PgPool) {
    let fx = seed(&pool).await;
    let stranger = Viewer::resolve(&pool, fx.stranger).await.expect("resolve");
    let owner = Viewer::resolve(&pool, fx.owner).await.expect("resolve");

    let direct = "SELECT count(*) FROM evidence WHERE id = $1 \
                  AND (raw_content IS NOT NULL OR source_url IS NOT NULL OR properties IS NOT NULL)";
    assert_eq!(
        app_count(&pool, &owner, direct, fx.hidden).await,
        1,
        "calibration"
    );
    assert_eq!(
        app_count(&pool, &stranger, direct, fx.hidden).await,
        0,
        "the hidden row's content is withheld from a non-member"
    );

    let touching = "SELECT count(*) FROM edges WHERE source_id = $1 AND source_type = 'evidence' \
                    AND properties ? 'strength'";
    assert_eq!(
        app_count(&pool, &stranger, touching, fx.hidden).await,
        1,
        "KNOWN SURFACE: an edge touching a hidden row stays readable (ids, relationship, \
         properties) where the hide left it"
    );

    let claim_text = "SELECT count(*) FROM claims WHERE id = $1 AND content IS NOT NULL";
    assert_eq!(
        app_count(&pool, &stranger, claim_text, fx.claim).await,
        1,
        "BY DESIGN: the claim and its text stay public; hiding evidence does not hide the claim"
    );

    let survivor =
        fixture::seed_public_claim(&pool, fx.owner, "a survivor that inherits evidence").await;
    let inherited = epigraph_db::ClaimRepository::inherit_evidence(&pool, fx.claim, survivor)
        .await
        .expect("inherit_evidence");
    assert_eq!(
        inherited, 1,
        "the hidden row is inherited as a derived_from edge"
    );
    let derived = "SELECT count(*) FROM edges WHERE target_id = $1 AND target_type = 'evidence' \
                   AND relationship = 'derived_from'";
    assert_eq!(
        app_count(&pool, &owner, derived, fx.hidden).await,
        1,
        "calibration: the hiding group's member reads the inherited edge"
    );
    assert_eq!(
        app_count(&pool, &stranger, derived, fx.hidden).await,
        0,
        "the inherited derived_from edge takes the meet with the group row and is withheld"
    );
}
