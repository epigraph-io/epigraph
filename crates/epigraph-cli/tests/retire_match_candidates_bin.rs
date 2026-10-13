//! `retire_match_candidates --apply`, driven as a real process on real LOGIN
//! roles (an `epigraph_app` application DSN and an `epigraph_maintenance`
//! maintenance DSN, neither a superuser), must leave the retired pair's
//! endpoints with a belief re-derived from the `mass_functions` that survive,
//! as the online retirement (`admin_cascade::apply_match_retire`) does
//! (U043, backlog 110f666a gap 3).
//!
//! Before this, the binary printed "run `POST /api/v1/bp/propagate`" as the
//! follow-up. That cannot repair a BP-written `pignistic_prob`: propagate builds
//! its variables from the surviving `factors` only, so an endpoint whose only
//! factor was the matcher edge is no longer a variable, and scalar BP seeds its
//! priors from the stored (biased) value.
//!
//! The superuser fixture pool only seeds rows and reads results.

#[path = "viewer_fixture.rs"]
mod viewer_fixture;

use std::process::Command;

use sqlx::PgPool;
use uuid::Uuid;

const RETIRE: &str = env!("CARGO_BIN_EXE_retire_match_candidates");

/// A stale BP-written value, far from any value the BBA below derives.
const POISONED_BETP: f64 = 0.93;

async fn create_login(pool: &PgPool, parent: &str) -> (String, String) {
    let role = format!("u043_{}_{}", parent, Uuid::new_v4().simple());
    let password = Uuid::new_v4().simple().to_string();
    sqlx::query(&format!(
        "CREATE ROLE {role} LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '{password}' IN ROLE {parent}"
    ))
    .execute(pool)
    .await
    .expect("create the login");
    let base = viewer_fixture::database_url_for(pool).await;
    let scheme_end = base.find("://").expect("a scheme") + 3;
    let host_path = &base[base.find('@').expect("credentials in the DSN") + 1..];
    let url = format!("{}{role}:{password}@{host_path}", &base[..scheme_end]);
    (role, url)
}

async fn drop_login(pool: &PgPool, role: &str) {
    let _ = sqlx::query(&format!("DROP ROLE IF EXISTS {role}"))
        .execute(pool)
        .await;
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'u043-bin', 'system', ARRAY['test']) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

async fn betp_of(pool: &PgPool, claim: Uuid) -> Option<f64> {
    sqlx::query_scalar("SELECT pignistic_prob FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("read pignistic_prob")
}

/// Give `claim` one BBA on the engine's own `binary_truth` frame, keyed on no
/// edge (so the retirement leaves it in place), derive its cache through the
/// engine's own entry point, and return the derived `pignistic_prob`.
async fn seed_surviving_bba_and_derive(pool: &PgPool, claim: Uuid, source_agent: Uuid) -> f64 {
    let scoped = epigraph_db::ScopedPool::connect(
        &viewer_fixture::database_url_for(pool).await,
        epigraph_db::SessionGucMode::Session,
    )
    .await
    .expect("ScopedPool over the test database")
    .with_maintenance_pool(pool.clone());
    let mut session = scoped
        .maintenance_session(epigraph_db::visibility::SystemReason::BeliefRecomputation)
        .await
        .expect("maintenance session");
    let (conn, viewer) = session.split();
    let frame = epigraph_engine::edge_factor::ensure_binary_frame(&mut *conn, viewer)
        .await
        .expect("the engine's binary frame");
    sqlx::query(
        "INSERT INTO mass_functions \
           (claim_id, frame_id, source_agent_id, perspective_id, masses, source_strength, \
            evidence_type) \
         VALUES ($1, $2, $3, NULL, $4, 1.0, 'empirical')",
    )
    .bind(claim)
    .bind(frame)
    .bind(source_agent)
    .bind(serde_json::json!({"0": 0.6, "1": 0.1, "0,1": 0.3}))
    .execute(&mut *conn)
    .await
    .expect("seed a surviving BBA");
    let derived =
        epigraph_engine::edge_factor::recompute_claim_cached_belief(&mut *conn, viewer, claim)
            .await
            .expect("derive the claim's belief from its BBA");
    assert!(
        derived,
        "CALIBRATION: the BBA is on a frame the recompute reads"
    );
    let d = betp_of(pool, claim)
        .await
        .expect("CALIBRATION: the recompute wrote pignistic_prob");
    assert!(
        (d - POISONED_BETP).abs() > 0.1,
        "CALIBRATION: the derived value ({d}) must be distinguishable from the poison"
    );
    d
}

/// A promoted candidate between `a` and `b` with its matcher edge (the
/// `edges_auto_factor` trigger derives the factor).
async fn promoted_candidate(pool: &PgPool, a: Uuid, b: Uuid) -> Uuid {
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            properties) \
         VALUES ($1, 'claim', $2, 'claim', 'CORROBORATES', \
                 '{\"source\": \"cross_source_matcher\"}'::jsonb)",
    )
    .bind(a)
    .bind(b)
    .execute(pool)
    .await
    .expect("the matcher edge");
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    sqlx::query_scalar(
        "INSERT INTO match_candidates (claim_a, claim_b, score, features, status) \
         VALUES ($1, $2, 0.9, '{}'::jsonb, 'promoted') RETURNING id",
    )
    .bind(lo)
    .bind(hi)
    .fetch_one(pool)
    .await
    .expect("the promoted candidate")
}

/// A candidate between `a` and `b` in `status`, with NO matcher edge between
/// them: retiring it withdraws nothing.
async fn edgeless_candidate(pool: &PgPool, a: Uuid, b: Uuid, status: &str) -> Uuid {
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    sqlx::query_scalar(
        "INSERT INTO match_candidates (claim_a, claim_b, score, features, status) \
         VALUES ($1, $2, 0.9, '{}'::jsonb, $3) RETURNING id",
    )
    .bind(lo)
    .bind(hi)
    .bind(status)
    .fetch_one(pool)
    .await
    .expect("the edgeless candidate")
}

/// Simulate a past `bp/propagate` with `apply_updates: true` on `claim`. A
/// claim with no BBA gets a cache only the factor graph can have written.
async fn poison_betp(pool: &PgPool, claim: Uuid) {
    sqlx::query(
        "UPDATE claims SET belief = COALESCE(belief, 0.5), \
                           plausibility = COALESCE(plausibility, 0.95), \
                           pignistic_prob = $2 WHERE id = $1",
    )
    .bind(claim)
    .bind(POISONED_BETP)
    .execute(pool)
    .await
    .expect("simulate a BP-written value");
}

async fn status_of(pool: &PgPool, candidate: Uuid) -> String {
    sqlx::query_scalar("SELECT status FROM match_candidates WHERE id = $1")
        .bind(candidate)
        .fetch_one(pool)
        .await
        .expect("candidate")
}

/// Run `retire_match_candidates --apply` over `candidates` as the non-superuser
/// LOGIN roles; returns (exit code, stdout, stderr).
async fn run_retire_apply(pool: &PgPool, candidates: &[Uuid]) -> (Option<i32>, String, String) {
    let (app_role, app_url) = create_login(pool, "epigraph_app").await;
    let (maint_role, maint_url) = create_login(pool, "epigraph_maintenance").await;
    let dir = std::env::temp_dir();
    let tag = Uuid::new_v4().simple().to_string();
    let ids = dir.join(format!("u043-ids-{tag}.txt"));
    let dump = dir.join(format!("u043-dump-{tag}.json"));
    let body: String = candidates.iter().map(|c| format!("{c}\n")).collect();
    std::fs::write(&ids, body).expect("write the ids file");
    let out = Command::new(RETIRE)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("DATABASE_URL", &app_url)
        .env("MAINTENANCE_DATABASE_URL", &maint_url)
        .env("RUST_LOG", "warn")
        .arg("--ids-file")
        .arg(&ids)
        .arg("--dump")
        .arg(&dump)
        .arg("--apply")
        .current_dir(&dir)
        .output()
        .expect("run the binary");
    let _ = std::fs::remove_file(&ids);
    let _ = std::fs::remove_file(&dump);
    drop_login(pool, &app_role).await;
    drop_login(pool, &maint_role).await;
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[sqlx::test(migrations = "../../migrations")]
async fn retire_apply_rederives_the_endpoints_belief(pool: PgPool) {
    let operator = seed_agent(&pool).await;
    let a = viewer_fixture::seed_public_claim(&pool, operator, "u043 cli a").await;
    let b = viewer_fixture::seed_public_claim(&pool, operator, "u043 cli b").await;
    let candidate = promoted_candidate(&pool, a, b).await;

    // b: backed by a BBA, its cache since overwritten by a BP apply.
    let d = seed_surviving_bba_and_derive(&pool, b, operator).await;
    // a: no BBA on any frame, and a cache only the factor graph can have written.
    poison_betp(&pool, a).await;
    poison_betp(&pool, b).await;

    let (code, stdout, stderr) = run_retire_apply(&pool, &[candidate]).await;
    assert_eq!(code, Some(0), "{stdout}\n{stderr}");
    assert_eq!(
        status_of(&pool, candidate).await,
        "stale",
        "CALIBRATION: the retirement applied"
    );

    let after = betp_of(&pool, b)
        .await
        .unwrap_or_else(|| panic!("b keeps a cache: a BBA backs it\n{stdout}"));
    assert!(
        (after - d).abs() < 1e-9,
        "the retirement must re-derive b from its surviving BBA: expected {d}, found {after} \
         (still {POISONED_BETP} means nothing re-derived it)\n{stdout}"
    );
    assert_eq!(
        betp_of(&pool, a).await,
        None,
        "an endpoint no BBA backs must have its stale cache cleared\n{stdout}"
    );
    assert!(
        !stdout.contains("bp/propagate reloads"),
        "the printed follow-up must no longer send the operator to bp/propagate:\n{stdout}"
    );
    // The report itself, not the no-op branch's "no belief was re-derived".
    for line in [
        "Belief re-derived on the 2 affected endpoint(s)",
        "recomputed:                   1",
        "cache cleared (no BBA backs): 1",
    ] {
        assert!(
            stdout.contains(line),
            "the run reports the re-derivation it did ({line:?}):\n{stdout}"
        );
    }
}

/// The re-derivation is per pair, like the online path's `withdrew` guard: a
/// batch mixing a promoted pair with a pending one (the binary stales both,
/// after its "not currently 'promoted'" NOTE) must re-derive only the endpoints
/// of the pair it withdrew something from. The pending pair's endpoints fed no
/// cache, and with no BBA behind them a re-derivation would CLEAR them.
#[sqlx::test(migrations = "../../migrations")]
async fn retire_apply_rederives_only_the_pairs_it_withdrew_from(pool: PgPool) {
    let operator = seed_agent(&pool).await;
    let a = viewer_fixture::seed_public_claim(&pool, operator, "u043 mixed a").await;
    let b = viewer_fixture::seed_public_claim(&pool, operator, "u043 mixed b").await;
    let c = viewer_fixture::seed_public_claim(&pool, operator, "u043 mixed c").await;
    let e = viewer_fixture::seed_public_claim(&pool, operator, "u043 mixed e").await;
    let promoted = promoted_candidate(&pool, a, b).await;
    let pending = edgeless_candidate(&pool, c, e, "pending").await;

    let d = seed_surviving_bba_and_derive(&pool, b, operator).await;
    for claim in [a, b, c, e] {
        poison_betp(&pool, claim).await;
    }

    let (code, stdout, stderr) = run_retire_apply(&pool, &[promoted, pending]).await;
    assert_eq!(code, Some(0), "{stdout}\n{stderr}");
    assert_eq!(
        (
            status_of(&pool, promoted).await,
            status_of(&pool, pending).await
        ),
        ("stale".to_string(), "stale".to_string()),
        "CALIBRATION: the binary stales the whole batch"
    );
    let after = betp_of(&pool, b)
        .await
        .unwrap_or_else(|| panic!("b keeps a cache: a BBA backs it\n{stdout}"));
    assert!(
        (after - d).abs() < 1e-9,
        "CALIBRATION: the promoted pair is re-derived (expected {d}, found {after})\n{stdout}"
    );
    for claim in [c, e] {
        assert_eq!(
            betp_of(&pool, claim).await,
            Some(POISONED_BETP),
            "the pending pair withdrew nothing, so its endpoint {claim} must keep its cache\n{stdout}"
        );
    }
    assert!(
        stdout.contains("Belief re-derived on the 2 affected endpoint(s)"),
        "only the promoted pair's two endpoints are re-derived:\n{stdout}"
    );
}

/// A run that withdrew nothing (a candidate marked promoted whose matcher edge
/// is gone) re-derives nothing, even on an endpoint whose cache disagrees with
/// its BBA: nothing this run removed fed that cache.
#[sqlx::test(migrations = "../../migrations")]
async fn retire_apply_that_withdrew_nothing_rederives_nothing(pool: PgPool) {
    let operator = seed_agent(&pool).await;
    let a = viewer_fixture::seed_public_claim(&pool, operator, "u043 noop a").await;
    let b = viewer_fixture::seed_public_claim(&pool, operator, "u043 noop b").await;
    let candidate = edgeless_candidate(&pool, a, b, "promoted").await;
    seed_surviving_bba_and_derive(&pool, b, operator).await;
    poison_betp(&pool, b).await;

    let (code, stdout, stderr) = run_retire_apply(&pool, &[candidate]).await;
    assert_eq!(code, Some(0), "{stdout}\n{stderr}");
    assert_eq!(
        status_of(&pool, candidate).await,
        "stale",
        "CALIBRATION: the retirement applied"
    );
    assert_eq!(
        betp_of(&pool, b).await,
        Some(POISONED_BETP),
        "nothing this run removed fed b's cache\n{stdout}"
    );
    assert!(
        stdout.contains("Nothing was withdrawn, so no belief was re-derived."),
        "{stdout}"
    );
}

/// A pair retired already, by an earlier run or the online path: its matcher
/// edge carries `valid_to` and its derived factor and bp_messages are gone.
/// The edge query still selects it (it has no `valid_to` filter, so the undo
/// dump records it), but nothing the run does to it changes a row. This makes
/// it the only input on which the per-edge `withdrew_here > 0` guard decides
/// anything.
async fn already_retired_candidate(pool: &PgPool, a: Uuid, b: Uuid) -> Uuid {
    let edge: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            properties) \
         VALUES ($1, 'claim', $2, 'claim', 'CORROBORATES', \
                 '{\"source\": \"cross_source_matcher\"}'::jsonb) RETURNING id",
    )
    .bind(a)
    .bind(b)
    .fetch_one(pool)
    .await
    .expect("the matcher edge");
    // The `edges_auto_factor` trigger ignores `valid_to`, so it derived a
    // factor; the earlier retirement deleted it, bp_messages first.
    let eid = edge.to_string();
    sqlx::query(
        "DELETE FROM bp_messages WHERE factor_id IN \
         (SELECT id FROM factors WHERE properties->>'source_edge_id' = $1)",
    )
    .bind(&eid)
    .execute(pool)
    .await
    .expect("drop the derived bp_messages");
    sqlx::query("DELETE FROM factors WHERE properties->>'source_edge_id' = $1")
        .bind(&eid)
        .execute(pool)
        .await
        .expect("drop the derived factor");
    sqlx::query("UPDATE edges SET valid_to = now() WHERE id = $1")
        .bind(edge)
        .execute(pool)
        .await
        .expect("retract the edge");
    let (factors, retracted): (i64, bool) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM factors WHERE properties->>'source_edge_id' = $2), \
                (SELECT valid_to IS NOT NULL FROM edges WHERE id = $1)",
    )
    .bind(edge)
    .bind(&eid)
    .fetch_one(pool)
    .await
    .expect("read the retired edge back");
    assert_eq!(
        (factors, retracted),
        (0, true),
        "CALIBRATION: the retired edge is retracted and has no derived factor left"
    );
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    sqlx::query_scalar(
        "INSERT INTO match_candidates (claim_a, claim_b, score, features, status) \
         VALUES ($1, $2, 0.9, '{}'::jsonb, 'stale') RETURNING id",
    )
    .bind(lo)
    .bind(hi)
    .fetch_one(pool)
    .await
    .expect("the already-retired candidate")
}

/// The per-edge guard itself: a batch with a live promoted pair and an
/// already-retired pair (see [`already_retired_candidate`]) finds BOTH matcher
/// edges, but withdraws only from the live one. The retired pair's endpoints
/// have no BBA, so re-deriving them would CLEAR caches the run never fed.
#[sqlx::test(migrations = "../../migrations")]
async fn retire_apply_leaves_an_already_retired_pair_alone(pool: PgPool) {
    let operator = seed_agent(&pool).await;
    let a = viewer_fixture::seed_public_claim(&pool, operator, "u043 rerun a").await;
    let b = viewer_fixture::seed_public_claim(&pool, operator, "u043 rerun b").await;
    let c = viewer_fixture::seed_public_claim(&pool, operator, "u043 rerun c").await;
    let e = viewer_fixture::seed_public_claim(&pool, operator, "u043 rerun e").await;
    let live = promoted_candidate(&pool, a, b).await;
    let retired = already_retired_candidate(&pool, c, e).await;

    let d = seed_surviving_bba_and_derive(&pool, b, operator).await;
    for claim in [a, b, c, e] {
        poison_betp(&pool, claim).await;
    }

    let (code, stdout, stderr) = run_retire_apply(&pool, &[live, retired]).await;
    assert_eq!(code, Some(0), "{stdout}\n{stderr}");
    // Both edges reached the withdrawal loop, and only the live one withdrew.
    for line in [
        "Found 2 matcher edge(s) to delete.",
        "factors deleted:     1",
        "edges deleted:       1",
    ] {
        assert!(
            stdout.contains(line),
            "CALIBRATION: the retired edge is selected but withdraws nothing ({line:?}):\n{stdout}"
        );
    }
    let after = betp_of(&pool, b)
        .await
        .unwrap_or_else(|| panic!("b keeps a cache: a BBA backs it\n{stdout}"));
    assert!(
        (after - d).abs() < 1e-9,
        "CALIBRATION: the live pair is re-derived (expected {d}, found {after})\n{stdout}"
    );
    for claim in [c, e] {
        assert_eq!(
            betp_of(&pool, claim).await,
            Some(POISONED_BETP),
            "the already-retired pair withdrew nothing, so its endpoint {claim} must keep \
             its cache\n{stdout}"
        );
    }
    assert!(
        stdout.contains("Belief re-derived on the 2 affected endpoint(s)"),
        "only the live pair's two endpoints are re-derived:\n{stdout}"
    );
}
