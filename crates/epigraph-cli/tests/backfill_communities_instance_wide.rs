//! `communities` is an instance-wide registry: the backfill does not re-own it
//! and `verify` does not count a `('public', world)` community as residue.
//!
//! The production writer, `CommunityRepository::create`, declares
//! `TenancyDecl::instance_wide()` on purpose: the community's projected group
//! is "not the owner of the registry row" (its own comment), and migration
//! 077's registry WITH CHECK admits exactly that declaration. `run` used to
//! re-stamp every world-owned community to `('public', communities.id)`, and
//! `verify` counted every world-owned community as residue in every mode, so
//! the deploy pre-flight failed after every community created once the
//! backfill had finished, and each re-run re-owned a directory entry the
//! writer had declared shared. This is the same conflict `perspectives` had
//! (`backfill_perspectives_instance_wide.rs`).
//!
//! The community is written through the REAL writer, by an agent holding a
//! LIVE operator link (the author shape `--legacy-owner platform` stamps), so
//! the writer's projected group, epoch and creator admin membership all exist,
//! as they do in production.
//!
//! Verified to fail (on the tree before this change):
//! * `verify --legacy-owner platform` exits 1 naming `communities`, for the
//!   community the writer produced after a completed run;
//! * `run --legacy-owner platform --entity communities` moves the community
//!   into its own projected group;
//! * dropping `communities` from `verify`'s skip list (the fix half alone)
//!   fails both tests again.

mod viewer_fixture;

use epigraph_db::CommunityRepository;
use sqlx::PgPool;
use std::process::Command;
use uuid::Uuid;
use viewer_fixture as fixture;

const BIN: &str = env!("CARGO_BIN_EXE_epigraph-tenancy-backfill");
const WORLD: Uuid = Uuid::nil();

async fn run_backfill(pool: &PgPool, args: &[&str]) -> (i32, String) {
    let url = fixture::database_url_for(pool).await;
    let out = Command::new(BIN)
        .args(args)
        .env("DATABASE_URL", &url)
        .env("MAINTENANCE_DATABASE_URL", &url)
        .env("RUST_LOG", "warn")
        .output()
        .expect("spawn epigraph-tenancy-backfill");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

async fn owner_of(pool: &PgPool, table: &str, id: Uuid) -> Uuid {
    sqlx::query_scalar(&format!("SELECT owner_group_id FROM {table} WHERE id = $1"))
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("owner")
}

/// A human operator and an agent holding a LIVE link to it.
async fn live_linked_author(pool: &PgPool) -> (Uuid, Uuid) {
    let (operator, operator_group) = fixture::seed_human_operator(pool, "operator").await;
    let (live, _) = fixture::seed_agent_with_group(pool, "live-linked fleet agent").await;
    let mut conn = pool.acquire().await.expect("acquire");
    epigraph_db::AgentRepository::link_operator(&mut conn, live, operator)
        .await
        .expect("live link");
    (live, operator_group)
}

/// A community created through the production writer by `creator`, with the
/// precondition that the writer declared it instance-wide and projected its
/// own group (the group the old `run` re-stamped it to).
async fn write_community(pool: &PgPool, name: &str, creator: Uuid) -> Uuid {
    let id = CommunityRepository::create(
        pool,
        name,
        Some("a community created after the backfill"),
        None,
        None,
        Some(creator),
    )
    .await
    .expect("create community")
    .id;
    assert_eq!(
        owner_of(pool, "communities", id).await,
        WORLD,
        "precondition: the writer declares the community instance-wide"
    );
    let projected: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM groups WHERE id = $1 AND kind = 'community')",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("projected group");
    assert!(
        projected,
        "precondition: the writer projects the community's own group"
    );
    id
}

#[sqlx::test(migrations = "../../migrations")]
async fn communities_written_after_a_run_do_not_fail_verify(pool: PgPool) {
    let (live, _) = live_linked_author(&pool).await;
    let (code, stderr) = run_backfill(&pool, &["run", "--legacy-owner", "platform"]).await;
    assert_eq!(
        code, 0,
        "the backfill completes on the seeded database:\n{stderr}"
    );

    write_community(&pool, "written after the run", live).await;

    let (code, stderr) = run_backfill(&pool, &["verify", "--legacy-owner", "platform"]).await;
    assert_eq!(
        code, 0,
        "an instance-wide community is a declaration, not residue:\n{stderr}"
    );
    assert!(!stderr.contains("communities still owned"), "{stderr}");
    let (code, stderr) = run_backfill(&pool, &["verify"]).await;
    assert_eq!(
        code, 0,
        "the strict verify agrees (no claim residue in this fixture):\n{stderr}"
    );
    assert!(!stderr.contains("communities still owned"), "{stderr}");

    // The exemption is scoped to communities: a world-owned claim by the same
    // live-linked author, written after the run, still fails the pre-flight.
    fixture::seed_public_claim(&pool, live, "written after the run").await;
    let (code, stderr) = run_backfill(&pool, &["verify", "--legacy-owner", "platform"]).await;
    assert_eq!(code, 1, "a world-owned claim still fails verify:\n{stderr}");
    assert!(stderr.contains("claims still owned"), "{stderr}");
    assert!(!stderr.contains("communities still owned"), "{stderr}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_run_leaves_instance_wide_communities_where_the_writer_put_them(pool: PgPool) {
    let (live, operator_group) = live_linked_author(&pool).await;
    let community = write_community(&pool, "written before the run", live).await;
    let claim = fixture::seed_public_claim(&pool, live, "a live-linked author's claim").await;

    for args in [
        &[
            "run",
            "--legacy-owner",
            "platform",
            "--entity",
            "communities",
        ][..],
        &["run", "--legacy-owner", "platform"][..],
        &["run", "--legacy-owner", "operator"][..],
    ] {
        let (code, stderr) = run_backfill(&pool, args).await;
        assert_eq!(code, 0, "{args:?}:\n{stderr}");
        assert_eq!(
            owner_of(&pool, "communities", community).await,
            WORLD,
            "{args:?}: the run must not re-own an instance-wide community"
        );
    }
    // The run did its job on the author's other rows, so the community staying
    // put is the exemption and not a run that stamped nothing.
    assert_eq!(owner_of(&pool, "claims", claim).await, operator_group);

    let complete: bool = sqlx::query_scalar(
        "SELECT complete FROM tenancy_backfill_progress WHERE entity = 'communities'",
    )
    .fetch_one(&pool)
    .await
    .expect("progress row");
    assert!(complete, "a full run settles the communities progress row");
}
