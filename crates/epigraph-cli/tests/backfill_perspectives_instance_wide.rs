//! `perspectives` is an instance-wide registry: the backfill does not re-own it
//! and `verify` does not count a `('public', world)` perspective as residue.
//!
//! Every production writer of `perspectives` declares
//! `TenancyDecl::instance_wide()` on purpose (`PerspectiveRepository::create`,
//! `ensure_evidence_perspective`, `ensure_edge_perspective`; migration 077's
//! registry WITH CHECK admits exactly that declaration). `verify` used to count
//! such a row as residue whenever its `owner_agent_id` held a live operator
//! link, and `run` used to move it into that operator's group, so the deploy
//! pre-flight failed again after every perspective an operator-linked agent
//! wrote, and every re-run re-owned a lens the writers had declared shared.
//!
//! Rows are written through the REAL writers, after a completed run, which is
//! the shape that broke: the backfill is finished, then the application keeps
//! writing.
//!
//! Verified to fail (on the tree before this change):
//! * `verify --legacy-owner platform` exits 1 naming `perspectives`, for the
//!   three rows the writers produced after the run;
//! * `run --legacy-owner platform --entity perspectives` moves all three into
//!   the operator's group;
//! * dropping `perspectives` from `verify`'s skip list (the fix half alone)
//!   fails both tests again.
//!
//! The strict `verify` assertion is not reached on the old tree (the platform
//! one fails first); it rests on the same residual count, unfiltered.

mod viewer_fixture;

use epigraph_db::PerspectiveRepository;
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

/// A human operator and an agent holding a LIVE link to it: the author shape
/// `--legacy-owner platform` stamps.
async fn live_linked_author(pool: &PgPool) -> (Uuid, Uuid) {
    let (operator, operator_group) = fixture::seed_human_operator(pool, "operator").await;
    let (live, _) = fixture::seed_agent_with_group(pool, "live-linked fleet agent").await;
    let mut conn = pool.acquire().await.expect("acquire");
    epigraph_db::AgentRepository::link_operator(&mut conn, live, operator)
        .await
        .expect("live link");
    (live, operator_group)
}

/// One perspective from each production writer, all attributed to `author`:
/// a named lens (`create`), an evidence-keyed BBA perspective and an
/// edge-keyed one (the two `ensure_*` the DS auto-wire calls).
async fn write_perspectives(pool: &PgPool, author: Uuid) -> [Uuid; 3] {
    let lens = PerspectiveRepository::create(
        pool,
        "a named lens",
        None,
        Some(author),
        Some("analytical"),
        &[],
        Some("ai_generated"),
        Some(0.5),
    )
    .await
    .expect("create perspective")
    .id;
    let evidence_key = Uuid::new_v4();
    PerspectiveRepository::ensure_evidence_perspective(pool, evidence_key, Some(author))
        .await
        .expect("evidence perspective");
    let edge_key = Uuid::new_v4();
    PerspectiveRepository::ensure_edge_perspective(pool, edge_key, Some(author))
        .await
        .expect("edge perspective");
    [lens, evidence_key, edge_key]
}

#[sqlx::test(migrations = "../../migrations")]
async fn perspectives_written_after_a_run_do_not_fail_verify(pool: PgPool) {
    let (live, _) = live_linked_author(&pool).await;
    let (code, stderr) = run_backfill(&pool, &["run", "--legacy-owner", "platform"]).await;
    assert_eq!(
        code, 0,
        "the backfill completes on the seeded database:\n{stderr}"
    );

    let ids = write_perspectives(&pool, live).await;
    for id in ids {
        assert_eq!(
            owner_of(&pool, "perspectives", id).await,
            WORLD,
            "precondition: the writers declare the perspective instance-wide"
        );
    }

    let (code, stderr) = run_backfill(&pool, &["verify", "--legacy-owner", "platform"]).await;
    assert_eq!(
        code, 0,
        "an instance-wide perspective is a declaration, not residue:\n{stderr}"
    );
    assert!(!stderr.contains("perspectives still owned"), "{stderr}");
    let (code, stderr) = run_backfill(&pool, &["verify"]).await;
    assert_eq!(
        code, 0,
        "the strict verify agrees (no claim residue in this fixture):\n{stderr}"
    );

    // The exemption is scoped to perspectives: a world-owned claim by the same
    // live-linked author, written after the run, still fails the pre-flight.
    fixture::seed_public_claim(&pool, live, "written after the run").await;
    let (code, stderr) = run_backfill(&pool, &["verify", "--legacy-owner", "platform"]).await;
    assert_eq!(code, 1, "a world-owned claim still fails verify:\n{stderr}");
    assert!(stderr.contains("claims still owned"), "{stderr}");
    assert!(!stderr.contains("perspectives still owned"), "{stderr}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_run_leaves_instance_wide_perspectives_where_the_writers_put_them(pool: PgPool) {
    let (live, operator_group) = live_linked_author(&pool).await;
    let ids = write_perspectives(&pool, live).await;
    let claim = fixture::seed_public_claim(&pool, live, "a live-linked author's claim").await;

    for args in [
        &[
            "run",
            "--legacy-owner",
            "platform",
            "--entity",
            "perspectives",
        ][..],
        &["run", "--legacy-owner", "platform"][..],
        &["run", "--legacy-owner", "operator"][..],
    ] {
        let (code, stderr) = run_backfill(&pool, args).await;
        assert_eq!(code, 0, "{args:?}:\n{stderr}");
        for id in ids {
            assert_eq!(
                owner_of(&pool, "perspectives", id).await,
                WORLD,
                "{args:?}: the run must not re-own an instance-wide perspective"
            );
        }
    }
    // The run did its job on the author's other rows, so the perspectives
    // staying put is the exemption and not a run that stamped nothing.
    assert_eq!(owner_of(&pool, "claims", claim).await, operator_group);

    let complete: bool = sqlx::query_scalar(
        "SELECT complete FROM tenancy_backfill_progress WHERE entity = 'perspectives'",
    )
    .fetch_one(&pool)
    .await
    .expect("progress row");
    assert!(complete, "a full run settles the perspectives progress row");
}
