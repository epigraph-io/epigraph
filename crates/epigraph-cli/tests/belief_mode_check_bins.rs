//! The CLI wave bins check their own belief modes against the API's `/health`
//! before a writing run (SPEC §10.2 flip runbook, gate G0).
//!
//! Every belief-mode flag is read at startup by each process. A flip is a
//! restart window, and a bin started from a shell whose environment was not
//! updated (or was updated early) would write under a different fold than the
//! API serves. So a WRITING run of a wave bin reads the API's `/health` →
//! `belief_modes` and refuses when any mode differs. A dry run writes nothing
//! and is exempt, so a wave can be reviewed under its target fold
//! (`--dry-run --target-fold <mode>`) before the server's flag flips.
//!
//! The bins run as real processes, with a cleared environment, against a
//! fixture `/health` served from a plain thread (the bin is a separate
//! process, so the fixture must keep serving while the test blocks on it).
//! The writing-run tests seed a claim whose cached BetP is a stale sentinel
//! that a real `recompute_betp` run rewrites; "writes nothing" is checked on
//! that sentinel and on every BBA and combined-belief row, and the control
//! (`matching_modes_*`) proves the same run DOES write when the modes agree,
//! so a refusal is the mode check's doing and not a broken fixture.

#[path = "viewer_fixture.rs"]
mod fixture;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;

use sqlx::PgPool;
use uuid::Uuid;

const RECOMPUTE_BETP: &str = env!("CARGO_BIN_EXE_recompute_betp");
const BACKFILL_FACTORS: &str = env!("CARGO_BIN_EXE_backfill_factors");
const DECOMPOSE_CLAIMS: &str = env!("CARGO_BIN_EXE_decompose_claims");

/// The modes a server with no belief flag set reports (SPEC §10.2 defaults).
fn legacy_modes() -> serde_json::Value {
    serde_json::json!({
        "atom_fold": "legacy",
        "compound_belief": "legacy",
        "compound_write_guard": "warn",
        "compound_source_edges": "frozen",
        "atom_cache_mode": "display",
        "inference": "off",
        "bp_apply": "off",
    })
}

/// Serve `body` as the JSON answer to every request, forever, on a loopback
/// port. Returns the base URL.
fn fixture_health(body: serde_json::Value) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
    let addr = listener.local_addr().expect("fixture address");
    let payload = body.to_string();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            // Read the request head; the fixture answers every path alike.
            let mut buf = [0u8; 4096];
            let mut head = Vec::new();
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => head.extend_from_slice(&buf[..n]),
                }
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{}",
                payload.len(),
                payload
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    format!("http://{addr}")
}

/// A `/health` body as the API returns it, with the given modes.
fn health_with(modes: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "status": "healthy",
        "version": "0.0.0-fixture",
        "timestamp": "2026-01-01T00:00:00Z",
        "belief_modes": modes,
    })
}

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// Run `bin` with ONLY the given environment (plus `PATH`), so no
/// `EPIGRAPH_*` flag of the host running the tests can leak in.
fn run(bin: &str, args: &[&str], env: &[(&str, &str)]) -> Run {
    let mut cmd = Command::new(bin);
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("RUST_LOG", "warn")
        .args(args)
        .current_dir(std::env::temp_dir());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("run the binary");
    Run {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'belief-mode-check', 'system', \
                 ARRAY['test']) RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

/// A two-source hub on a binary frame whose cached BetP is the sentinel 0.5,
/// far from what its BBAs combine to (> .9): a real `recompute_betp` run
/// rewrites it, a refused or dry run leaves it.
async fn seed_stale_hub(pool: &PgPool) -> Uuid {
    let owner = seed_agent(pool).await;
    let frame: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, description, hypotheses) \
         VALUES ('belief_mode_check_binary_' || gen_random_uuid(), 'test binary frame', \
                 ARRAY['TRUE', 'FALSE']) RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed frame");
    let claim: Uuid = sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, pignistic_prob) \
         VALUES ('belief mode check hub ' || gen_random_uuid(), \
                 sha256(gen_random_uuid()::text::bytea), 0.5, $1, 0.5) RETURNING id",
    )
    .bind(owner)
    .fetch_one(pool)
    .await
    .expect("seed claim");
    for masses in [
        serde_json::json!({"0": 0.9, "0,1": 0.1}),
        serde_json::json!({"0": 0.85, "0,1": 0.15}),
    ] {
        let source = seed_agent(pool).await;
        sqlx::query(
            "INSERT INTO mass_functions (claim_id, frame_id, source_agent_id, masses, locality_tag) \
             VALUES ($1, $2, $3, $4, 'unknown')",
        )
        .bind(claim)
        .bind(frame)
        .bind(source)
        .bind(masses)
        .execute(pool)
        .await
        .expect("seed BBA");
    }
    claim
}

async fn cached_betp(pool: &PgPool, claim: Uuid) -> Option<f64> {
    sqlx::query_scalar("SELECT pignistic_prob FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("read the cache")
}

/// Every belief-bearing row a wave bin could write: claim cache columns, BBA
/// rows and per-frame combined beliefs.
async fn belief_state(pool: &PgPool) -> (String, String, String) {
    let one = |sql: &'static str| async move {
        sqlx::query_scalar::<_, Option<String>>(sql)
            .fetch_one(pool)
            .await
            .unwrap_or_else(|e| panic!("{sql}: {e}"))
            .unwrap_or_default()
    };
    (
        one(
            "SELECT md5(string_agg(concat_ws('|', id, belief, plausibility, mass_on_empty, \
             pignistic_prob, mass_on_missing, open_world_mass, belief_frame_id), ',' \
             ORDER BY id)) FROM claims",
        )
        .await,
        one("SELECT md5(string_agg(t::text, ',' ORDER BY t::text)) FROM mass_functions t").await,
        one("SELECT md5(string_agg(t::text, ',' ORDER BY t::text)) FROM ds_combined_beliefs t")
            .await,
    )
}

fn assert_refused_for_atom_fold(r: &Run, what: &str) {
    assert!(
        r.code.is_some_and(|c| c != 0),
        "{what}: a writing run whose modes differ from the server's must exit non-zero; \
         got {:?}\nstdout: {}\nstderr: {}",
        r.code,
        r.stdout,
        r.stderr
    );
    for needle in ["atom_fold", "legacy", "aef_standalone"] {
        assert!(
            r.stderr.contains(needle),
            "{what}: the refusal must name the differing mode and both values \
             (missing {needle:?})\nstderr: {}",
            r.stderr
        );
    }
}

// ── recompute_betp ──────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn a_writing_run_refuses_when_its_atom_fold_differs_from_the_server(pool: PgPool) {
    let hub = seed_stale_hub(&pool).await;
    let before = belief_state(&pool).await;
    let db = fixture::database_url_for(&pool).await;
    let api = fixture_health(health_with(legacy_modes()));

    let r = run(
        RECOMPUTE_BETP,
        &[],
        &[
            ("DATABASE_URL", &db),
            ("EPIGRAPH_API_URL", &api),
            ("EPIGRAPH_ATOM_FOLD", "aef_standalone"),
        ],
    );

    assert_refused_for_atom_fold(&r, "recompute_betp");
    assert_eq!(cached_betp(&pool, hub).await, Some(0.5), "the sentinel");
    assert_eq!(
        belief_state(&pool).await,
        before,
        "a refused run writes nothing"
    );
}

/// Control for the refusal above: the same bin, the same fixture server, the
/// same seeded claim, with modes that agree. It must run and rewrite the
/// sentinel; otherwise the refusal test could pass on a broken fixture.
#[sqlx::test(migrations = "../../migrations")]
async fn matching_modes_let_the_same_writing_run_proceed_and_write(pool: PgPool) {
    let hub = seed_stale_hub(&pool).await;
    let db = fixture::database_url_for(&pool).await;
    let api = fixture_health(health_with(legacy_modes()));

    let r = run(
        RECOMPUTE_BETP,
        &[],
        &[("DATABASE_URL", &db), ("EPIGRAPH_API_URL", &api)],
    );

    assert_eq!(
        r.code,
        Some(0),
        "matching modes must not refuse\nstdout: {}\nstderr: {}",
        r.stdout,
        r.stderr
    );
    let after = cached_betp(&pool, hub)
        .await
        .expect("a cache after the run");
    assert!(
        (after - 0.5).abs() > 0.05,
        "a real run must rewrite the stale sentinel; got {after}"
    );
}

/// The W0/W1 review shape (SPEC §10.3 O4/O7): the server still runs `legacy`
/// and the bin is asked for the fold the server will flip to. The bin's own
/// environment is ALSO skewed (`aef`), the worst case; a dry run is exempt
/// all the same, and writes nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn a_dry_run_with_a_target_fold_proceeds_under_a_legacy_server_and_writes_nothing(
    pool: PgPool,
) {
    let hub = seed_stale_hub(&pool).await;
    let before = belief_state(&pool).await;
    let db = fixture::database_url_for(&pool).await;
    let api = fixture_health(health_with(legacy_modes()));

    let r = run(
        RECOMPUTE_BETP,
        &["--dry-run", "--target-fold", "aef"],
        &[
            ("DATABASE_URL", &db),
            ("EPIGRAPH_API_URL", &api),
            ("EPIGRAPH_ATOM_FOLD", "aef"),
        ],
    );

    assert_eq!(
        r.code,
        Some(0),
        "a dry run is exempt from the mode check\nstdout: {}\nstderr: {}",
        r.stdout,
        r.stderr
    );
    assert_eq!(cached_betp(&pool, hub).await, Some(0.5), "the sentinel");
    assert_eq!(
        belief_state(&pool).await,
        before,
        "a dry run writes nothing"
    );
}

/// The check fails CLOSED: a writing run that cannot read the server's modes
/// (nothing listening) does not proceed on the assumption that they agree.
#[sqlx::test(migrations = "../../migrations")]
async fn a_writing_run_refuses_when_the_server_modes_cannot_be_read(pool: PgPool) {
    let hub = seed_stale_hub(&pool).await;
    let db = fixture::database_url_for(&pool).await;
    // A port that was free a moment ago and has no listener now.
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", l.local_addr().unwrap())
    };

    let r = run(
        RECOMPUTE_BETP,
        &[],
        &[("DATABASE_URL", &db), ("EPIGRAPH_API_URL", &dead)],
    );

    assert!(
        r.code.is_some_and(|c| c != 0),
        "an unreachable API must refuse a writing run; got {:?}\nstderr: {}",
        r.code,
        r.stderr
    );
    assert!(
        r.stderr.contains("belief_modes"),
        "the refusal must say the server's belief_modes could not be read\nstderr: {}",
        r.stderr
    );
    assert_eq!(cached_betp(&pool, hub).await, Some(0.5), "the sentinel");
}

/// A server built before `/health` reported its modes cannot be compared, so
/// a writing run refuses rather than treat "no report" as "the same modes".
#[sqlx::test(migrations = "../../migrations")]
async fn a_writing_run_refuses_a_server_that_does_not_report_belief_modes(pool: PgPool) {
    let hub = seed_stale_hub(&pool).await;
    let db = fixture::database_url_for(&pool).await;
    let api = fixture_health(serde_json::json!({
        "status": "healthy",
        "version": "0.0.0-fixture",
        "timestamp": "2026-01-01T00:00:00Z",
    }));

    let r = run(
        RECOMPUTE_BETP,
        &[],
        &[("DATABASE_URL", &db), ("EPIGRAPH_API_URL", &api)],
    );

    assert!(
        r.code.is_some_and(|c| c != 0),
        "a server without belief_modes must refuse a writing run; got {:?}\nstderr: {}",
        r.code,
        r.stderr
    );
    assert!(
        r.stderr.contains("belief_modes"),
        "the refusal must name the missing report\nstderr: {}",
        r.stderr
    );
    assert_eq!(cached_betp(&pool, hub).await, Some(0.5), "the sentinel");
}

/// `--target-fold` names the fold a REVIEW is for; a writing run under it
/// would write that fold while the server serves another, so clap refuses it
/// without `--dry-run`, before anything runs.
#[sqlx::test(migrations = "../../migrations")]
async fn a_target_fold_without_dry_run_is_refused_and_writes_nothing(pool: PgPool) {
    let hub = seed_stale_hub(&pool).await;
    let before = belief_state(&pool).await;
    let db = fixture::database_url_for(&pool).await;
    let api = fixture_health(health_with(legacy_modes()));

    let r = run(
        RECOMPUTE_BETP,
        &["--target-fold", "legacy"],
        &[("DATABASE_URL", &db), ("EPIGRAPH_API_URL", &api)],
    );

    assert!(
        r.code.is_some_and(|c| c != 0),
        "--target-fold needs --dry-run; got {:?}\nstderr: {}",
        r.code,
        r.stderr
    );
    assert!(r.stderr.contains("--dry-run"), "stderr: {}", r.stderr);
    assert_eq!(cached_betp(&pool, hub).await, Some(0.5), "the sentinel");
    assert_eq!(
        belief_state(&pool).await,
        before,
        "a refused run writes nothing"
    );
}

/// The override: the same skewed writing run as the refusal test, with
/// `--allow-mode-skew`, proceeds and writes, and says so on stderr.
#[sqlx::test(migrations = "../../migrations")]
async fn allow_mode_skew_lets_a_skewed_writing_run_proceed_loudly(pool: PgPool) {
    let hub = seed_stale_hub(&pool).await;
    let db = fixture::database_url_for(&pool).await;
    let api = fixture_health(health_with(legacy_modes()));

    let r = run(
        RECOMPUTE_BETP,
        &["--allow-mode-skew"],
        &[
            ("DATABASE_URL", &db),
            ("EPIGRAPH_API_URL", &api),
            ("EPIGRAPH_ATOM_FOLD", "aef_standalone"),
        ],
    );

    assert_eq!(r.code, Some(0), "stderr: {}", r.stderr);
    assert!(
        r.stderr.contains("--allow-mode-skew") && r.stderr.contains("atom_fold"),
        "the override must name what it overrode\nstderr: {}",
        r.stderr
    );
    let after = cached_betp(&pool, hub).await.expect("a cache");
    assert!((after - 0.5).abs() > 0.05, "the run wrote; got {after}");
}

// ── backfill_factors and decompose_claims --retarget ───────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn backfill_factors_refuses_a_writing_run_on_mode_skew(pool: PgPool) {
    let _hub = seed_stale_hub(&pool).await;
    let before = belief_state(&pool).await;
    let db = fixture::database_url_for(&pool).await;
    let api = fixture_health(health_with(legacy_modes()));

    let r = run(
        BACKFILL_FACTORS,
        &["--phase", "edges"],
        &[
            ("DATABASE_URL", &db),
            ("EPIGRAPH_API_URL", &api),
            ("EPIGRAPH_ATOM_FOLD", "aef_standalone"),
        ],
    );

    assert_refused_for_atom_fold(&r, "backfill_factors");
    assert_eq!(
        belief_state(&pool).await,
        before,
        "a refused run writes nothing"
    );
}

/// `--retarget --apply-plan` writes edges through the API: a writing run. It
/// refuses on skew before it opens the database or mints a token, so this
/// run is given neither.
#[test]
fn retarget_apply_plan_refuses_on_mode_skew_before_touching_the_database() {
    let api = fixture_health(health_with(legacy_modes()));
    let manifest = std::env::temp_dir().join(format!("belief-mode-{}.jsonl", Uuid::new_v4()));

    let r = run(
        DECOMPOSE_CLAIMS,
        &[
            "--retarget",
            "--apply-plan",
            manifest.to_str().expect("utf-8 temp path"),
        ],
        &[
            ("EPIGRAPH_API_URL", &api),
            ("EPIGRAPH_ATOM_FOLD", "aef_standalone"),
        ],
    );

    assert_refused_for_atom_fold(&r, "decompose_claims --retarget --apply-plan");
}
