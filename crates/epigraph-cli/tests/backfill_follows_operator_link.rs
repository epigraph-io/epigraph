//! `epigraph-tenancy-backfill` under operator binding (migration 122): the
//! claims arm stamps a LINKED author's world-owned claims to the OPERATOR's
//! group (derived rows follow through 070's arm (d)), an unlinked author's to
//! its own personal group as before, and `verify` REPORTS (never fails on)
//! claims still owned by a linked author's own personal group.
//!
//! Driven through the real binary, as `backfill_idempotence.rs` is.
//!
//! Verified to fail:
//! * `owner_group_sql` reduced to `personal_group_sql` -> the linked author's
//!   claim (and its evidence) land in the author's own group;
//! * the REPORT loop removed from `verify` -> the stderr assertion fails.

mod viewer_fixture;

use sqlx::PgPool;
use std::process::Command;
use uuid::Uuid;
use viewer_fixture as fixture;

const BIN: &str = env!("CARGO_BIN_EXE_epigraph-tenancy-backfill");

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

#[sqlx::test(migrations = "../../migrations")]
async fn the_backfill_stamps_a_linked_authors_claims_to_the_operators_group(pool: PgPool) {
    let (operator, operator_group) = fixture::seed_human_operator(&pool, "operator").await;
    let (linked, linked_group) = fixture::seed_agent_with_group(&pool, "linked").await;
    let (unlinked, unlinked_group) = fixture::seed_agent_with_group(&pool, "unlinked").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_db::AgentRepository::link_retired_agent(&mut conn, linked, operator)
            .await
            .expect("retired link");
    }
    let c_linked = fixture::seed_public_claim(&pool, linked, "legacy by a linked author").await;
    let ev = fixture::seed_evidence(&pool, c_linked, "testimony").await;
    let c_unlinked = fixture::seed_public_claim(&pool, unlinked, "legacy by an unlinked one").await;

    let (code, stderr) = run_backfill(&pool, &["run", "--legacy-owner", "operator"]).await;
    assert_eq!(code, 0, "run must complete:\n{stderr}");
    assert_eq!(
        owner_of(&pool, "claims", c_linked).await,
        operator_group,
        "a linked author's legacy claim belongs to its operator"
    );
    assert_eq!(
        owner_of(&pool, "evidence", ev).await,
        operator_group,
        "its derived row follows (070 arm (d))"
    );
    assert_eq!(
        owner_of(&pool, "claims", c_unlinked).await,
        unlinked_group,
        "an unlinked author keeps the personal-group fallback"
    );
    assert_ne!(operator_group, linked_group);

    // A claim the linked author's OWN group owns is declared, so verify passes,
    // and REPORTS it for `reown-linked`.
    let hash = Uuid::new_v4().as_bytes().repeat(2);
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, 'written before the link', $2, 0.5, $3, true, 'public', $4)",
    )
    .bind(Uuid::new_v4())
    .bind(hash)
    .bind(linked)
    .bind(linked_group)
    .execute(&pool)
    .await
    .expect("personal-group claim");
    let (code, stderr) = run_backfill(&pool, &["verify"]).await;
    assert_eq!(code, 0, "the residue is a REPORT, not a failure:\n{stderr}");
    assert!(
        stderr.contains("REPORT: 1 row(s) in claims"),
        "verify must report the linked author's personal-group claim:\n{stderr}"
    );
}

/// `--legacy-owner platform` (decision D1's default shape): only rows of
/// authors with a LIVE link to a registered human move (to that operator's
/// group, derived rows following); rows of retired-linked and unlinked authors
/// STAY world-owned as the platform corpus, derived rows included. `verify
/// --legacy-owner platform` passes and reports the corpus; the strict `verify`
/// fails on it. A re-run walks nothing.
///
/// Verified to fail: `author_filter`'s platform arm replaced by `TRUE` -> the
/// retired-linked and unlinked authors' claims are stamped (to the operator /
/// NULL-skipped), and the "stays world-owned" assertions or the verify exit
/// codes fail.
#[sqlx::test(migrations = "../../migrations")]
async fn a_platform_run_moves_only_live_linked_authors(pool: PgPool) {
    let (operator, operator_group) = fixture::seed_human_operator(&pool, "operator").await;
    let (live, _) = fixture::seed_agent_with_group(&pool, "live").await;
    let (retired, _) = fixture::seed_agent_with_group(&pool, "retired").await;
    let (unlinked, _) = fixture::seed_agent_with_group(&pool, "unlinked").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_db::AgentRepository::link_operator(&mut conn, live, operator)
            .await
            .expect("live link");
        epigraph_db::AgentRepository::link_retired_agent(&mut conn, retired, operator)
            .await
            .expect("retired link");
    }
    let c_live = fixture::seed_public_claim(&pool, live, "by a live-linked agent").await;
    let ev_live = fixture::seed_evidence(&pool, c_live, "testimony").await;
    let c_retired = fixture::seed_public_claim(&pool, retired, "by a retired identity").await;
    let ev_retired = fixture::seed_evidence(&pool, c_retired, "testimony").await;
    let c_unlinked = fixture::seed_public_claim(&pool, unlinked, "by an unlinked agent").await;

    let (code, stderr) = run_backfill(
        &pool,
        &["run", "--legacy-owner", "platform", "--batch-size", "2"],
    )
    .await;
    assert_eq!(code, 0, "a platform run completes:\n{stderr}");
    assert_eq!(owner_of(&pool, "claims", c_live).await, operator_group);
    assert_eq!(owner_of(&pool, "evidence", ev_live).await, operator_group);
    let world = Uuid::nil();
    assert_eq!(
        owner_of(&pool, "claims", c_retired).await,
        world,
        "platform corpus"
    );
    assert_eq!(
        owner_of(&pool, "evidence", ev_retired).await,
        world,
        "its derived row"
    );
    assert_eq!(
        owner_of(&pool, "claims", c_unlinked).await,
        world,
        "platform corpus"
    );

    let (code, stderr) = run_backfill(&pool, &["verify", "--legacy-owner", "platform"]).await;
    assert_eq!(
        code, 0,
        "verify under the platform decision passes:\n{stderr}"
    );
    assert!(
        stderr.contains("REPORT: 2 world-owned claim(s) form the platform corpus"),
        "{stderr}"
    );
    let (code, _) = run_backfill(&pool, &["verify"]).await;
    assert_eq!(
        code, 1,
        "the strict verify still fails on the platform corpus"
    );

    let (code, stderr) = run_backfill(&pool, &["run", "--legacy-owner", "platform"]).await;
    assert_eq!(code, 0, "a re-run is a no-op:\n{stderr}");
    assert_eq!(owner_of(&pool, "claims", c_retired).await, world);
}

async fn world_claims_by(pool: &PgPool, agent: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM claims WHERE agent_id = $1 AND owner_group_id = $2")
        .bind(agent)
        .bind(Uuid::nil())
        .fetch_one(pool)
        .await
        .expect("world count")
}

/// Reviews C3 and C8: under `--legacy-owner platform` a registered human
/// operator's OWN world-owned claims are its (stamped to its personal group,
/// DESIGN D1: "the operator's own backlog ... stay his"), and a live link to an
/// operator that is no longer a registered human stamps nothing (such a link
/// binds nothing, migration 122).
///
/// Verified to fail, each alone: `PLATFORM_STAMPED_AUTHORS` / `owner_sql`
/// reduced to live-linked authors (the pre-review filter) -> the human's own
/// claim stays world-owned; `public.epigraph_is_human_operator(l.operator_id)`
/// removed from both -> the revoked operator's agent's claim moves.
#[sqlx::test(migrations = "../../migrations")]
async fn a_platform_run_owns_a_humans_own_rows_and_nothing_for_a_revoked_operator(pool: PgPool) {
    let (human, human_group) = fixture::seed_human_operator(&pool, "human").await;
    let (gone, _) = fixture::seed_human_operator(&pool, "revoked-human").await;
    let (agent_of_gone, _) = fixture::seed_agent_with_group(&pool, "agent-of-revoked").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_db::AgentRepository::link_operator(&mut conn, agent_of_gone, gone)
            .await
            .expect("live link");
    }
    sqlx::query("SELECT * FROM public.epigraph_revoke_human_operator($1, 'left')")
        .bind(gone)
        .execute(&pool)
        .await
        .expect("revoke");
    let own = fixture::seed_public_claim(&pool, human, "the operator's own legacy claim").await;
    let orphaned =
        fixture::seed_public_claim(&pool, agent_of_gone, "by a revoked human's agent").await;

    let (code, stderr) = run_backfill(&pool, &["run", "--legacy-owner", "platform"]).await;
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(
        owner_of(&pool, "claims", own).await,
        human_group,
        "a human operator's own legacy claim is its own"
    );
    assert_eq!(
        owner_of(&pool, "claims", orphaned).await,
        Uuid::nil(),
        "a link to a revoked operator binds nothing and stamps nothing"
    );
}

/// Review C4: under `platform` a WORLD-owned edge between a platform-corpus
/// claim (which never moves) and a group-private claim used to stay stale, and
/// `run` / `verify` failed on it with no remedy. The run now re-stamps it to
/// its endpoints' meet and completes.
///
/// Verified to fail: the `settle_world_edges_with_private_endpoints` call
/// removed from `settle_remaining` -> `run` exits 1 on the edge check.
#[sqlx::test(migrations = "../../migrations")]
async fn a_platform_run_repairs_a_world_edge_onto_a_private_endpoint(pool: PgPool) {
    let (human, human_group) = fixture::seed_human_operator(&pool, "human").await;
    let (retired, _) = fixture::seed_agent_with_group(&pool, "retired").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_db::AgentRepository::link_retired_agent(&mut conn, retired, human)
            .await
            .expect("retired link");
    }
    let corpus = fixture::seed_public_claim(&pool, retired, "platform corpus").await;
    let private = fixture::seed_group_claim(&pool, human, human_group, "private endpoint").await;
    let edge = fixture::seed_edge(&pool, corpus, private).await;
    sqlx::query(
        "UPDATE edges SET owner_group_id = $2, visibility = 'public', co_owner_group_id = NULL \
          WHERE id = $1",
    )
    .bind(edge)
    .bind(Uuid::nil())
    .execute(&pool)
    .await
    .expect("stale edge");

    let (code, stderr) = run_backfill(&pool, &["run", "--legacy-owner", "platform"]).await;
    assert_eq!(
        code, 0,
        "the run repairs the stale edge and completes:\n{stderr}"
    );
    let (owner, vis): (Uuid, String) =
        sqlx::query_as("SELECT owner_group_id, visibility::text FROM edges WHERE id = $1")
            .bind(edge)
            .fetch_one(&pool)
            .await
            .expect("edge");
    assert_eq!((owner, vis.as_str()), (human_group, "group"));
    assert_eq!(owner_of(&pool, "claims", corpus).await, Uuid::nil());
}

/// Reviews C2 and C8 (OB6's flags, previously unpinned):
/// * a claims cursor CARRIED OVER from an earlier run (an aborted run, or one
///   under the other `--legacy-owner`) no longer hides the rows below it: the
///   single-entity run rewinds and walks again, and exits 0 only when nothing
///   is left (it used to exit 0 WITH residue);
/// * `--entity` runs that arm alone (another entity leaves claims untouched);
/// * `--max-runtime` stops between batches and exits 3, keeping the committed
///   batch; a re-run completes.
///
/// Verified to fail, each alone: the `continue 'passes` rewind removed ->
/// the carried-cursor run exits 1 with residue; `wants` ignoring `--entity` ->
/// the harvester-fragments run stamps the claims; `Deadline::expired` always
/// false -> the budgeted run exits 0.
#[sqlx::test(migrations = "../../migrations")]
async fn the_claims_walk_resumes_rewinds_and_honours_its_budget(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    for i in 0..3 {
        fixture::seed_public_claim(&pool, author, &format!("carried {i}")).await;
    }

    // --entity: another arm alone leaves the claims walk untouched.
    let (code, stderr) = run_backfill(
        &pool,
        &[
            "run",
            "--legacy-owner",
            "operator",
            "--entity",
            "harvester-fragments",
        ],
    )
    .await;
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(
        world_claims_by(&pool, author).await,
        3,
        "not the claims arm"
    );

    // A cursor an earlier run left ABOVE every world-owned claim.
    sqlx::query(
        "UPDATE tenancy_backfill_progress SET last_id = 'ffffffff-ffff-ffff-ffff-ffffffffffff', \
                rows_done = 5000 WHERE entity = 'claims'",
    )
    .execute(&pool)
    .await
    .expect("carried cursor");
    let (code, stderr) = run_backfill(
        &pool,
        &[
            "run",
            "--legacy-owner",
            "operator",
            "--entity",
            "claims",
            "--batch-size",
            "1",
        ],
    )
    .await;
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(
        world_claims_by(&pool, author).await,
        0,
        "the carried cursor is rewound in the same run"
    );

    // --max-runtime: a statement-level sleep makes one batch outlast a 1s
    // budget, so the walk stops after exactly one batch and exits 3.
    for i in 0..3 {
        fixture::seed_public_claim(&pool, author, &format!("budgeted {i}")).await;
    }
    sqlx::query(
        "CREATE FUNCTION test_slow_batch() RETURNS trigger LANGUAGE plpgsql AS \
         $$ BEGIN PERFORM pg_sleep(1.2); RETURN NULL; END $$",
    )
    .execute(&pool)
    .await
    .expect("slow fn");
    sqlx::query(
        "CREATE TRIGGER zz_test_slow_batch AFTER UPDATE ON claims \
         FOR EACH STATEMENT EXECUTE FUNCTION test_slow_batch()",
    )
    .execute(&pool)
    .await
    .expect("slow trigger");
    let budgeted = [
        "run",
        "--legacy-owner",
        "operator",
        "--entity",
        "claims",
        "--batch-size",
        "1",
        "--max-runtime",
        "1s",
    ];
    let (code, stderr) = run_backfill(&pool, &budgeted).await;
    assert_eq!(code, 3, "a spent budget is a partial run:\n{stderr}");
    assert!(stderr.contains("PARTIAL"), "{stderr}");
    assert_eq!(
        world_claims_by(&pool, author).await,
        2,
        "exactly the one committed batch is kept"
    );
    sqlx::query("DROP TRIGGER zz_test_slow_batch ON claims")
        .execute(&pool)
        .await
        .expect("drop slow trigger");
    let (code, stderr) = run_backfill(&pool, &budgeted).await;
    assert_eq!(code, 0, "a re-run resumes and completes:\n{stderr}");
    assert_eq!(world_claims_by(&pool, author).await, 0);
}
