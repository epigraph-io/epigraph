//! `epigraph-operator privatization abort|revert` (backlog bb682f72): the
//! recovery for a privatization plan stranded in `applying`, on the
//! operator's maintenance login, ending in a `drain_jobs` run that exits 0.
//!
//! Before this verb, under operator decision D9 the stock server serves no
//! privatization lifecycle route (501), so nothing could move a stranded plan
//! and every drain run exited 5 (`EXIT_PLAN_STRANDED`) forever.
//!
//! The verbs run as the spawned binary on a fresh NOSUPERUSER login in
//! `epigraph_maintenance`, as an operator runs them, so their grants are the
//! real ones. The drain runs as `drain_jobs` builds it, on a pool downgraded
//! to `epigraph_maintenance`. The superuser fixture pool only seeds and reads.

#[path = "../../epigraph-api/tests/privatization_fixture.rs"]
mod fx;

use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use epigraph_api::embedding_restore::EmbeddingProviderKind;
use epigraph_api::jobs_drain;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_jobs::{JobQueue, PostgresJobQueue};
use fx::viewer_fixture;
use sqlx::PgPool;
use uuid::Uuid;

const BIN: &str = env!("CARGO_BIN_EXE_epigraph-operator");
const DSN_ENV: &str = "EPIGRAPH_OPERATOR_MAINTENANCE_DSN";

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Run {
    fn show(&self) -> String {
        format!(
            "exit={}\n--- stdout\n{}\n--- stderr\n{}",
            self.code, self.stdout, self.stderr
        )
    }
}

fn operator(args: &[&str], dsn: &str) -> Run {
    let out = Command::new(BIN)
        .args(args)
        .env("RUST_LOG", "warn")
        .env_remove("DATABASE_URL")
        .env_remove("MAINTENANCE_DATABASE_URL")
        .env(DSN_ENV, dsn)
        .output()
        .expect("spawn epigraph-operator");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// A fresh NOSUPERUSER login in `epigraph_maintenance`: its DSN.
async fn maintenance_login(pool: &PgPool) -> String {
    let url = viewer_fixture::database_url_for(pool).await;
    let role = format!("priv_maint_{}", Uuid::new_v4().simple());
    sqlx::query(&format!(
        "CREATE ROLE {role} LOGIN PASSWORD 'probe-only' NOSUPERUSER IN ROLE epigraph_maintenance"
    ))
    .execute(pool)
    .await
    .expect("create the maintenance login");
    let (scheme, rest) = url.split_once("://").expect("scheme");
    let (_, host) = rest.split_once('@').expect("credentials");
    format!("{scheme}://{role}:probe-only@{host}")
}

/// The drain, built as `drain_jobs` builds it, on a pool downgraded to
/// `epigraph_maintenance`.
async fn drain_runner(pool: &PgPool) -> (epigraph_jobs::JobRunner, PostgresJobQueue) {
    let url = viewer_fixture::database_url_for(pool).await;
    let scoped = Arc::new(
        ScopedPool::connect_downgraded_for_tests(
            &url,
            SessionGucMode::Session,
            "epigraph_maintenance",
        )
        .await
        .expect("a ScopedPool downgraded to epigraph_maintenance"),
    );
    let queue = PostgresJobQueue::new(scoped.inner().clone());
    let runner = jobs_drain::build_job_runner(
        Arc::clone(&scoped),
        Arc::new(queue.clone()),
        Arc::new(epigraph_embeddings::MockProvider::new(
            epigraph_embeddings::EmbeddingConfig::openai(1536),
        )),
        EmbeddingProviderKind::Mock,
    );
    (runner, queue)
}

async fn drain(
    runner: &epigraph_jobs::JobRunner,
    queue: &PostgresJobQueue,
) -> jobs_drain::DrainReport {
    jobs_drain::drain(runner, queue, Duration::from_secs(600))
        .await
        .expect("a drain run")
}

/// The actor's live `role:platform-custodian` assignment.
async fn custodian_assignment(pool: &PgPool, actor: Uuid) -> Uuid {
    sqlx::query_scalar(
        "SELECT public.epigraph_role_assignment_for($1, 'role:platform-custodian', now())",
    )
    .bind(actor)
    .fetch_one(pool)
    .await
    .expect("the actor's custodian assignment")
}

/// `platform.custodial_act` rows naming `plan`.
async fn custodial_acts(pool: &PgPool, plan: Uuid) -> Vec<serde_json::Value> {
    sqlx::query_scalar(
        "SELECT details -> 'details' FROM security_events \
          WHERE event_type = 'platform.custodial_act' AND details ->> 'target' = $1::text \
          ORDER BY created_at",
    )
    .bind(plan)
    .fetch_all(pool)
    .await
    .expect("read custodial acts")
}

async fn jobs_naming(pool: &PgPool, plan: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM jobs \
          WHERE payload -> 'PrivatizationRevert' ->> 'plan_id' = $1::text",
    )
    .bind(plan)
    .fetch_one(pool)
    .await
    .expect("count revert jobs")
}

/// The whole recovery, on a plan whose apply run crashed after its last
/// batch committed and before its terminal write (a separate transaction in
/// the handler): every item applied, the plan still `applying`, its job
/// failed by the reaper. The drain exits 5 naming it. Then:
///
/// 1. `abort` without `--apply` writes nothing (the drain still exits 5);
/// 2. `abort` with an assignment the actor does not hold is refused (CUS04);
/// 3. `abort --apply` sets `failed` with its `plan.abort` audit row and a
///    custodial act, and the next drain run exits 0;
/// 4. a second `abort --apply` writes nothing and exits 0;
/// 5. `revert --apply` without the plan's digest, or with a wrong one, is
///    refused; its dry run writes no job;
/// 6. `revert --apply --plan-digest <digest>` dispatches; the drain runs the
///    revert job, the plan ends `reverted`, the claim is public again, and the
///    run exits 0.
///
/// Verified to fail: with `--apply` committing nothing (`finish` rolling
/// back), the plan is still `applying` after step 3; with the dispatch's
/// `security_events` row written under another event type, the drain's
/// revert job is refused as unattributed (a drain failure, and the plan never
/// reaches `reverted`).
#[sqlx::test(migrations = "../../migrations")]
async fn a_stranded_plan_is_aborted_and_reverted_by_the_operator_and_the_drain_exits_0(
    pool: PgPool,
) {
    let world = fx::World::seed(&pool).await;
    let claim = viewer_fixture::seed_public_claim(&pool, world.actor, "stranded plan seed").await;
    let (plan, digest) = fx::create_plan(&pool, &world, &[claim]).await;
    let before = fx::tenancy(&pool, claim).await;
    assert_eq!(before.0, "public", "CALIBRATION: the seed is public");
    let correlation = fx::dispatch(&pool, &world, plan, "applying").await;
    let job = fx::apply_job(plan, world.actor, &correlation);
    let job_id: Uuid = job.id.into();
    PostgresJobQueue::new(pool.clone())
        .enqueue(job.clone())
        .await
        .expect("seed the apply job");

    // The run: every batch commits, then the process dies before the
    // terminal write, and the reaper fails the job.
    fx::run_apply(&fx::scoped(&pool).await, &job, 50)
        .await
        .expect("the apply run");
    sqlx::query("UPDATE privatization_plans SET state = 'applying' WHERE id = $1")
        .bind(plan)
        .execute(&pool)
        .await
        .expect("the terminal write never happened");
    sqlx::query("UPDATE jobs SET state = 'failed', error_message = $2 WHERE id = $1")
        .bind(job_id)
        .bind(epigraph_jobs::REAPED_REDELIVERIES_SPENT_MESSAGE)
        .execute(&pool)
        .await
        .expect("the reaper failed the job");
    assert_eq!(
        fx::tenancy(&pool, claim).await,
        ("group".to_string(), world.target_group),
        "CALIBRATION: the applied prefix is the whole plan"
    );

    let (runner, queue) = drain_runner(&pool).await;
    let stranded = drain(&runner, &queue).await;
    assert_eq!(
        stranded.exit_code(),
        jobs_drain::EXIT_PLAN_STRANDED,
        "CALIBRATION: the drain names the stranded plan: {stranded:?}"
    );
    assert_eq!(stranded.stranded_privatization_plans[0].plan_id, plan);

    let dsn = maintenance_login(&pool).await;
    let assignment = custodian_assignment(&pool, world.actor).await;
    let (p, actor, asg) = (
        plan.to_string(),
        world.actor.to_string(),
        assignment.to_string(),
    );
    let act = |verb: &'static str, extra: &[&str]| -> Run {
        let mut args = vec![
            "privatization",
            verb,
            "--plan",
            &p,
            "--actor",
            &actor,
            "--assignment",
            &asg,
            "--reason",
            "recover a stranded plan",
        ];
        args.extend_from_slice(extra);
        operator(&args, &dsn)
    };

    // 1. The dry run is the default, and it writes nothing.
    let dry = act("abort", &[]);
    assert_eq!(dry.code, 0, "{}", dry.show());
    assert!(dry.stdout.contains("WOULD BE ABORTED"), "{}", dry.show());
    assert_eq!(fx::plan_state(&pool, plan).await, "applying");
    assert!(
        !fx::audit_actions(&pool, plan)
            .await
            .contains(&"plan.abort".to_string()),
        "a dry-run abort wrote its audit row"
    );
    assert!(custodial_acts(&pool, plan).await.is_empty());
    assert_eq!(
        drain(&runner, &queue).await.exit_code(),
        jobs_drain::EXIT_PLAN_STRANDED,
        "a dry run recovered nothing"
    );

    // 2. An assignment the actor does not hold refuses the whole act.
    let stranger = Uuid::new_v4().to_string();
    let refused = operator(
        &[
            "privatization",
            "abort",
            "--plan",
            &p,
            "--actor",
            &actor,
            "--assignment",
            &stranger,
            "--reason",
            "no authority",
            "--apply",
        ],
        &dsn,
    );
    assert_ne!(refused.code, 0, "{}", refused.show());
    assert!(refused.stderr.contains("CUS04"), "{}", refused.show());
    assert_eq!(fx::plan_state(&pool, plan).await, "applying");

    // 3. The abort.
    let aborted = act("abort", &["--apply"]);
    assert_eq!(aborted.code, 0, "{}", aborted.show());
    assert!(aborted.stdout.starts_with("ABORTED"), "{}", aborted.show());
    assert_eq!(fx::plan_state(&pool, plan).await, "failed");
    assert!(fx::audit_actions(&pool, plan)
        .await
        .contains(&"plan.abort".to_string()));
    let acts = custodial_acts(&pool, plan).await;
    assert_eq!(acts.len(), 1, "{acts:?}");
    assert_eq!(acts[0]["transition"], "abort");
    assert_eq!(acts[0]["reason"], "recover a stranded plan");
    let after_abort = drain(&runner, &queue).await;
    assert!(
        after_abort.stranded_privatization_plans.is_empty(),
        "{after_abort:?}"
    );
    assert_eq!(after_abort.exit_code(), 0, "{after_abort:?}");
    assert_eq!(
        fx::tenancy(&pool, claim).await,
        ("group".to_string(), world.target_group),
        "an abort stops; the applied prefix stays applied"
    );

    // 4. Idempotent.
    let again = act("abort", &["--apply"]);
    assert_eq!(again.code, 0, "{}", again.show());
    assert!(
        again.stdout.starts_with("ALREADY-FAILED"),
        "{}",
        again.show()
    );
    assert_eq!(custodial_acts(&pool, plan).await.len(), 1);

    // 5. The revert needs the digest echoed back; its dry run writes no job.
    let no_digest = act("revert", &["--apply"]);
    assert_eq!(no_digest.code, 1, "{}", no_digest.show());
    let wrong = format!("b3:{}", "00".repeat(32));
    let wrong_digest = act("revert", &["--apply", "--plan-digest", &wrong]);
    assert_eq!(wrong_digest.code, 1, "{}", wrong_digest.show());
    let rehearsal = act("revert", &[]);
    assert_eq!(rehearsal.code, 0, "{}", rehearsal.show());
    let echoed = format!("b3:{}", hex::encode(digest));
    assert!(
        rehearsal.stdout.contains(&echoed),
        "the dry run prints the digest to echo: {}",
        rehearsal.show()
    );
    assert_eq!(fx::plan_state(&pool, plan).await, "failed");
    assert_eq!(
        jobs_naming(&pool, plan).await,
        0,
        "a dry-run revert wrote a job"
    );

    // 6. The revert, run by the drain.
    let reverted = act("revert", &["--apply", "--plan-digest", &echoed]);
    assert_eq!(reverted.code, 0, "{}", reverted.show());
    assert!(
        reverted.stdout.starts_with("REVERT-DISPATCHED"),
        "{}",
        reverted.show()
    );
    assert_eq!(fx::plan_state(&pool, plan).await, "reverting");
    let ran = drain(&runner, &queue).await;
    assert!(ran.failures.is_empty(), "{ran:?}");
    assert_eq!(ran.exit_code(), 0, "{ran:?}");
    assert_eq!(
        fx::plan_state(&pool, plan).await,
        "reverted",
        "the drain's revert job re-validated the operator's dispatch and finished it"
    );
    assert_eq!(
        fx::tenancy(&pool, claim).await,
        before,
        "the revert un-applied the applied item"
    );
}

/// `purge-sealed-centroids` (backlog 06cdffaa's one-off pass, for clusters
/// a seal emptied before the seal cleared their centroids): without
/// `--apply` it only lists, and it does so on the maintenance login; on that
/// login `--apply` is refused by the missing DELETE grant and writes nothing;
/// as the table owner it deletes exactly the listed row.
///
/// Verified to fail: with the dry run routed to the delete, the row is gone
/// after the first run (and the maintenance login's run fails on the grant).
#[sqlx::test(migrations = "../../migrations")]
async fn the_centroid_pass_lists_by_default_and_deletes_only_as_the_table_owner(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    let sealed =
        viewer_fixture::seed_group_claim(&pool, world.actor, world.target_group, "sealed").await;
    let kept =
        viewer_fixture::seed_group_claim(&pool, world.actor, world.target_group, "kept").await;
    fx::encrypt_claim(&pool, sealed, world.target_group).await;
    let run_id = Uuid::new_v4();
    for (claim, cluster) in [(sealed, 0), (kept, 1)] {
        sqlx::query(
            "INSERT INTO claim_clusters (claim_id, cluster_id, centroid_distance, \
                second_centroid_dist, boundary_ratio, silhouette_score, cluster_run_id) \
             VALUES ($1, $2, 0.1, 0.2, 0.5, 0.5, $3)",
        )
        .bind(claim)
        .bind(cluster)
        .bind(run_id)
        .execute(&pool)
        .await
        .expect("seed the membership");
        sqlx::query(
            "INSERT INTO cluster_centroids (cluster_run_id, cluster_id, umap_centroid) \
             VALUES ($1, $2, array_fill(0.5::real, ARRAY[32])::vector)",
        )
        .bind(run_id)
        .bind(cluster)
        .execute(&pool)
        .await
        .expect("seed the centroid");
    }
    let clusters = || async {
        sqlx::query_scalar::<_, i32>(
            "SELECT cluster_id FROM cluster_centroids WHERE cluster_run_id = $1 \
              ORDER BY cluster_id",
        )
        .bind(run_id)
        .fetch_all(&pool)
        .await
        .expect("read the centroids")
    };

    let maint = maintenance_login(&pool).await;
    let listed = operator(&["privatization", "purge-sealed-centroids"], &maint);
    assert_eq!(listed.code, 0, "{}", listed.show());
    assert!(
        listed
            .stdout
            .contains(&format!("SEALED-ONLY-CENTROID\trun={run_id}\tcluster=0")),
        "{}",
        listed.show()
    );
    assert!(
        listed.stdout.contains("DRY RUN: found 1"),
        "{}",
        listed.show()
    );
    assert_eq!(clusters().await, vec![0, 1], "a dry run deletes nothing");

    let refused = operator(
        &["privatization", "purge-sealed-centroids", "--apply"],
        &maint,
    );
    assert_eq!(refused.code, 1, "{}", refused.show());
    assert!(
        refused
            .stderr
            .contains("permission denied for table cluster_centroids"),
        "{}",
        refused.show()
    );
    assert_eq!(clusters().await, vec![0, 1]);

    let owner = viewer_fixture::database_url_for(&pool).await;
    let deleted = operator(
        &["privatization", "purge-sealed-centroids", "--apply"],
        &owner,
    );
    assert_eq!(deleted.code, 0, "{}", deleted.show());
    assert!(deleted.stdout.contains("deleted 1"), "{}", deleted.show());
    assert_eq!(
        clusters().await,
        vec![1],
        "only the sealed-only cluster's row goes"
    );
}

/// The revert verb's thresholds are the route's (`instance_authz`), which
/// are pinned to migration 081's literals there. A drift would let the
/// operator verb revert where the route refuses, or the reverse.
#[test]
fn the_revert_gates_thresholds_are_the_routes() {
    use epigraph_api::middleware::instance_authz as route;
    use epigraph_cli::operator::privatization as verb;
    assert_eq!(
        verb::TARGET_GROUP_MIN_AGE_HOURS,
        route::TARGET_GROUP_MIN_AGE_HOURS
    );
    assert_eq!(
        verb::TARGET_GROUP_MIN_OTHER_ADMINS,
        route::TARGET_GROUP_MIN_OTHER_ADMINS
    );
}

/// An applied plan of `world.target_group` in `mode`, its seed claim, and its
/// digest as the verb echoes it.
async fn applied_plan(pool: &PgPool, world: &fx::World, mode: &str) -> (Uuid, Uuid, String) {
    let claim = viewer_fixture::seed_public_claim(pool, world.actor, "revert subject").await;
    let (plan, digest) = fx::create_plan_with_mode(pool, world, &[claim], mode).await;
    let correlation = fx::dispatch(pool, world, plan, "applying").await;
    fx::run_apply(
        &fx::scoped(pool).await,
        &fx::apply_job(plan, world.actor, &correlation),
        50,
    )
    .await
    .expect("the apply run");
    assert_eq!(
        fx::plan_state(pool, plan).await,
        "applied",
        "CALIBRATION: the plan is revertible by state"
    );
    (plan, claim, format!("b3:{}", hex::encode(digest)))
}

fn revert_args<'a>(
    plan: &'a str,
    actor: &'a str,
    assignment: &'a str,
    extra: &[&'a str],
) -> Vec<&'a str> {
    let mut args = vec![
        "privatization",
        "revert",
        "--plan",
        plan,
        "--actor",
        actor,
        "--assignment",
        assignment,
        "--reason",
        "revert test",
    ];
    args.extend_from_slice(extra);
    args
}

/// Review finding M1: the revert verb applies the route's authority gate,
/// not only the live custodian assignment. A custodian holding the
/// maintenance DSN but no membership in the plan's target group is refused,
/// dry run and `--apply` alike, and nothing is written: no flip, no job, no
/// custodial act. The plan's own group admin, a custodian too, is admitted
/// (the calibration that the refusal is about the group, not the plan).
///
/// Verified to fail: with condition 4 removed from
/// `revert_authority_refusal`, the outsider's dry run exits 0 (admitted).
#[sqlx::test(migrations = "../../migrations")]
async fn a_custodian_outside_the_target_group_cannot_revert_its_plan(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    let (plan, _claim, echoed) = applied_plan(&pool, &world, "restrict").await;

    let (outsider, _) = viewer_fixture::seed_agent_with_group(&pool, "d4-outsider").await;
    let outsider_assignment = viewer_fixture::make_custodian(&pool, outsider).await;
    let member_of_target: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM group_memberships \
                         WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL)",
    )
    .bind(world.target_group)
    .bind(outsider)
    .fetch_one(&pool)
    .await
    .expect("read the outsider's membership");
    assert!(
        !member_of_target,
        "CALIBRATION: the outsider is not in the group"
    );

    let dsn = maintenance_login(&pool).await;
    let p = plan.to_string();

    // CALIBRATION: the group's own admin passes the gate (dry run).
    let (actor, actor_asg) = (
        world.actor.to_string(),
        custodian_assignment(&pool, world.actor).await.to_string(),
    );
    let admitted = operator(&revert_args(&p, &actor, &actor_asg, &[]), &dsn);
    assert_eq!(admitted.code, 0, "{}", admitted.show());
    assert!(
        admitted.stdout.contains("WOULD BE REVERT-DISPATCHED"),
        "{}",
        admitted.show()
    );

    let (o, o_asg) = (outsider.to_string(), outsider_assignment.to_string());
    let dry = operator(&revert_args(&p, &o, &o_asg, &[]), &dsn);
    assert_eq!(dry.code, 1, "{}", dry.show());
    assert!(
        dry.stdout.contains("admin role in the plan's target group"),
        "the dry run tells the truth: {}",
        dry.show()
    );
    let applied = operator(
        &revert_args(&p, &o, &o_asg, &["--apply", "--plan-digest", &echoed]),
        &dsn,
    );
    assert_eq!(applied.code, 1, "{}", applied.show());
    assert!(
        applied.stdout.starts_with("REFUSED")
            && applied
                .stdout
                .contains("admin role in the plan's target group"),
        "refused on condition 4, not on the digest or the state: {}",
        applied.show()
    );
    assert_eq!(fx::plan_state(&pool, plan).await, "applied");
    assert_eq!(
        jobs_naming(&pool, plan).await,
        0,
        "a refused revert wrote a job"
    );
    assert!(
        custodial_acts(&pool, plan).await.is_empty(),
        "a refused revert recorded a custodial act"
    );
}

/// Review finding m3: the verb path refuses to revert a `seal` plan while
/// one of its items is still sealed, as `revert_plan` does, and writes
/// nothing. Setup as `privatization_revert.rs::
/// revert_is_refused_while_a_seal_plan_item_is_still_sealed`.
///
/// Verified to fail: with the `sealed_item_count_conn` check removed from
/// the verb, the dry run exits 0 (admitted).
#[sqlx::test(migrations = "../../migrations")]
async fn the_revert_verb_refuses_a_seal_plan_with_a_sealed_item(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    sqlx::query(
        "UPDATE groups SET kind = 'team', public_key = decode(repeat('ab', 32), 'hex') \
          WHERE id = $1",
    )
    .bind(world.target_group)
    .execute(&pool)
    .await
    .expect("promote the target group to a keyed one");
    sqlx::query(
        "INSERT INTO group_key_epochs (group_id, epoch, status) VALUES ($1, 0, 'active') \
         ON CONFLICT DO NOTHING",
    )
    .bind(world.target_group)
    .execute(&pool)
    .await
    .expect("seed the active key epoch");
    let (plan, claim, echoed) = applied_plan(&pool, &world, "seal").await;
    fx::encrypt_claim(&pool, claim, world.target_group).await;

    let dsn = maintenance_login(&pool).await;
    let (p, actor, asg) = (
        plan.to_string(),
        world.actor.to_string(),
        custodian_assignment(&pool, world.actor).await.to_string(),
    );
    for extra in [&[][..], &["--apply", "--plan-digest", &echoed][..]] {
        let run = operator(&revert_args(&p, &actor, &asg, extra), &dsn);
        assert_eq!(run.code, 1, "{}", run.show());
        assert!(
            run.stdout.contains("still sealed"),
            "refused on the sealed item: {}",
            run.show()
        );
    }
    assert_eq!(fx::plan_state(&pool, plan).await, "applied");
    assert_eq!(jobs_naming(&pool, plan).await, 0);
    assert!(custodial_acts(&pool, plan).await.is_empty());
}
