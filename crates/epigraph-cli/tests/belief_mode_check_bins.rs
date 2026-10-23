//! The CLI wave bins check their own belief modes against the API's `/health`
//! before a writing run (SPEC §10.2 flip runbook).
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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

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

/// [`legacy_modes`] with `atom_fold` set to `fold`.
fn modes_with_atom_fold(fold: &str) -> serde_json::Value {
    let mut modes = legacy_modes();
    modes["atom_fold"] = serde_json::json!(fold);
    modes
}

/// Serve `body` as the JSON answer to every request, forever, on a loopback
/// port. Returns the base URL.
fn fixture_health(body: serde_json::Value) -> String {
    fixture_health_counted(body).0
}

/// [`fixture_health`], also returning how many connections it has accepted, so
/// a test can show a run never contacted the API at all.
fn fixture_health_counted(body: serde_json::Value) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
    let addr = listener.local_addr().expect("fixture address");
    let payload = body.to_string();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            counter.fetch_add(1, Ordering::SeqCst);
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
    (format!("http://{addr}"), hits)
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

/// The exit status of a mode-check refusal, which an operator script keys on
/// to tell a refusal from a crash. A literal on purpose: the contract is the
/// number, not whatever the constant says.
const REFUSED: Option<i32> = Some(3);

fn assert_refused_for_atom_fold(r: &Run, what: &str) {
    assert_eq!(
        r.code, REFUSED,
        "{what}: a writing run whose modes differ from the server's must exit 3; \
         got {:?}\nstdout: {}\nstderr: {}",
        r.code, r.stdout, r.stderr
    );
    // "differ from the API's" pins the SKEW refusal, not the build's own fold
    // refusal, whose text also names `atom_fold` and `legacy`.
    for needle in [
        "differ from the API's",
        "atom_fold",
        "legacy",
        "aef_standalone",
    ] {
        assert!(
            r.stderr.contains(needle),
            "{what}: the refusal must be the skew refusal, naming the differing mode and \
             both values (missing {needle:?})\nstderr: {}",
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
    // The server is the one ahead: this process runs `legacy`, so the build's
    // own fold refusal cannot fire and only the skew check can refuse.
    let api = fixture_health(health_with(modes_with_atom_fold("aef_standalone")));

    let r = run(
        RECOMPUTE_BETP,
        &[],
        &[("DATABASE_URL", &db), ("EPIGRAPH_API_URL", &api)],
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

/// The wave-review shape (SPEC §10.3): the server still runs `legacy`
/// and the bin is asked for the fold the server will flip to. The bin's own
/// environment is ALSO skewed (`aef`), the worst case; a dry run is exempt
/// all the same, never contacts the API (so it runs on a host with no API),
/// and writes nothing. This build has no AEF fold, so the preview must not
/// print a per-claim row: those would be legacy numbers under an AEF label.
#[sqlx::test(migrations = "../../migrations")]
async fn a_dry_run_with_a_target_fold_proceeds_under_a_legacy_server_and_writes_nothing(
    pool: PgPool,
) {
    let hub = seed_stale_hub(&pool).await;
    let before = belief_state(&pool).await;
    let db = fixture::database_url_for(&pool).await;
    let (api, hits) = fixture_health_counted(health_with(legacy_modes()));

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
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "a dry run must not contact the API"
    );
    assert!(
        r.stdout.contains("cannot compute the aef fold"),
        "an AEF preview must say this build cannot compute it\nstdout: {}",
        r.stdout
    );
    assert!(
        !r.stdout.contains(&hub.to_string()),
        "an AEF preview must print no per-claim row (they would be legacy numbers)\nstdout: {}",
        r.stdout
    );
    assert_eq!(cached_betp(&pool, hub).await, Some(0.5), "the sentinel");
    assert_eq!(
        belief_state(&pool).await,
        before,
        "a dry run writes nothing"
    );
}

/// Control for the AEF preview above: the same seed under `--target-fold
/// legacy` DOES print the hub's per-claim row, so the AEF test's "no row"
/// check is not passing on an empty cohort. Also exempt, and also silent
/// towards the API, with a skewed environment.
#[sqlx::test(migrations = "../../migrations")]
async fn a_legacy_target_dry_run_previews_the_seeded_claim_without_contacting_the_api(
    pool: PgPool,
) {
    let hub = seed_stale_hub(&pool).await;
    let before = belief_state(&pool).await;
    let db = fixture::database_url_for(&pool).await;
    let (api, hits) = fixture_health_counted(health_with(legacy_modes()));

    let r = run(
        RECOMPUTE_BETP,
        &["--dry-run", "--target-fold", "legacy"],
        &[
            ("DATABASE_URL", &db),
            ("EPIGRAPH_API_URL", &api),
            ("EPIGRAPH_ATOM_FOLD", "aef"),
        ],
    );

    assert_eq!(
        r.code,
        Some(0),
        "stdout: {}\nstderr: {}",
        r.stdout,
        r.stderr
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "a dry run must not contact the API"
    );
    assert!(
        r.stdout.contains(&hub.to_string()),
        "a legacy preview prints the hub's row\nstdout: {}",
        r.stdout
    );
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
    // Port 1 is privileged and unbound: nothing a parallel test binds can
    // land on it, unlike a just-released ephemeral port.
    let dead = "http://127.0.0.1:1";

    let r = run(
        RECOMPUTE_BETP,
        &[],
        &[("DATABASE_URL", &db), ("EPIGRAPH_API_URL", dead)],
    );

    assert_eq!(
        r.code, REFUSED,
        "an unreachable API must refuse a writing run with exit 3; got {:?}\nstderr: {}",
        r.code, r.stderr
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

    assert_eq!(
        r.code, REFUSED,
        "a server without belief_modes must refuse a writing run with exit 3; got {:?}\nstderr: {}",
        r.code, r.stderr
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

/// The override: a skewed writing run with `--allow-mode-skew` proceeds and
/// writes, and says so on stderr. The skew is on a mode the run does not act
/// on (`compound_write_guard`): an `atom_fold` skew would also meet the
/// build's own fold refusal, which the override does not lift (see
/// `a_writing_run_under_a_fold_this_build_cannot_write_refuses_even_when_the_server_agrees`).
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
            ("EPIGRAPH_COMPOUND_WRITE_GUARD", "refuse"),
        ],
    );

    assert_eq!(r.code, Some(0), "stderr: {}", r.stderr);
    assert!(
        r.stderr.contains("--allow-mode-skew") && r.stderr.contains("compound_write_guard"),
        "the override must name what it overrode\nstderr: {}",
        r.stderr
    );
    let after = cached_betp(&pool, hub).await.expect("a cache");
    assert!((after - 0.5).abs() > 0.05, "the run wrote; got {after}");
}

/// This build's cache writers implement only the legacy fold. A writing run
/// whose `EPIGRAPH_ATOM_FOLD` names another fold must refuse even when the
/// server agrees: agreement compares flag values, not what the build can do,
/// so a binary older than the server's fold would otherwise write
/// legacy-fold caches under an AEF label. Not lifted by `--allow-mode-skew`,
/// which overrides a skew, not this.
#[sqlx::test(migrations = "../../migrations")]
async fn a_writing_run_under_a_fold_this_build_cannot_write_refuses_even_when_the_server_agrees(
    pool: PgPool,
) {
    let hub = seed_stale_hub(&pool).await;
    let before = belief_state(&pool).await;
    let db = fixture::database_url_for(&pool).await;
    let api = fixture_health(health_with(modes_with_atom_fold("aef_standalone")));

    for args in [&[][..], &["--allow-mode-skew"][..]] {
        let r = run(
            RECOMPUTE_BETP,
            args,
            &[
                ("DATABASE_URL", &db),
                ("EPIGRAPH_API_URL", &api),
                ("EPIGRAPH_ATOM_FOLD", "aef_standalone"),
            ],
        );
        assert_eq!(
            r.code, REFUSED,
            "recompute_betp {args:?}: a writing run under a fold this build cannot write \
             must exit 3\nstdout: {}\nstderr: {}",
            r.stdout, r.stderr
        );
        assert!(
            r.stderr.contains("writes only the legacy fold") && r.stderr.contains("aef_standalone"),
            "recompute_betp {args:?}: the refusal must name the fold and what this build \
             writes\nstderr: {}",
            r.stderr
        );
    }
    assert_eq!(cached_betp(&pool, hub).await, Some(0.5), "the sentinel");
    assert_eq!(
        belief_state(&pool).await,
        before,
        "a refused run writes nothing"
    );
}

// ── backfill_factors and decompose_claims --retarget ───────────────────────

/// A source with a cached interval `supports` a factorless target: exactly
/// what `backfill_factors --phase edges` selects and wires, writing the
/// target's first BBA. Returns the target.
async fn seed_unwired_edge(pool: &PgPool) -> Uuid {
    let author = seed_agent(pool).await;
    let claim = |content: &'static str, interval: Option<(f64, f64)>| async move {
        let (bel, pl) = interval.unzip();
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id, belief, \
                                 plausibility, pignistic_prob) \
             VALUES ($1 || gen_random_uuid(), sha256(gen_random_uuid()::text::bytea), 0.5, $2, \
                     $3, $4, $3) RETURNING id",
        )
        .bind(content)
        .bind(author)
        .bind(bel)
        .bind(pl)
        .fetch_one(pool)
        .await
        .expect("seed claim")
    };
    let source = claim("belief mode check edge source ", Some((0.8, 0.95))).await;
    let target = claim("belief mode check edge target ", None).await;
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'supports')",
    )
    .bind(source)
    .bind(target)
    .execute(pool)
    .await
    .expect("seed edge");
    target
}

async fn bba_rows(pool: &PgPool, claim: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM mass_functions WHERE claim_id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("count BBA rows")
}

#[sqlx::test(migrations = "../../migrations")]
async fn backfill_factors_refuses_a_writing_run_on_mode_skew(pool: PgPool) {
    let target = seed_unwired_edge(&pool).await;
    let before = belief_state(&pool).await;
    let db = fixture::database_url_for(&pool).await;
    // The server is the one ahead: this process runs `legacy`, so the build's
    // own fold refusal cannot fire and only the skew check can refuse.
    let api = fixture_health(health_with(modes_with_atom_fold("aef_standalone")));

    let r = run(
        BACKFILL_FACTORS,
        &["--phase", "edges"],
        &[("DATABASE_URL", &db), ("EPIGRAPH_API_URL", &api)],
    );

    assert_refused_for_atom_fold(&r, "backfill_factors");
    assert_eq!(bba_rows(&pool, target).await, 0, "the edge was not wired");
    assert_eq!(
        belief_state(&pool).await,
        before,
        "a refused run writes nothing"
    );
}

/// Control for the backfill refusal above: the same run with matching modes
/// wires the edge, so that refusal's "writes nothing" bites.
#[sqlx::test(migrations = "../../migrations")]
async fn backfill_factors_with_matching_modes_wires_the_same_edge(pool: PgPool) {
    let target = seed_unwired_edge(&pool).await;
    let db = fixture::database_url_for(&pool).await;
    let api = fixture_health(health_with(legacy_modes()));

    let r = run(
        BACKFILL_FACTORS,
        &["--phase", "edges"],
        &[("DATABASE_URL", &db), ("EPIGRAPH_API_URL", &api)],
    );

    assert_eq!(
        r.code,
        Some(0),
        "stdout: {}\nstderr: {}",
        r.stdout,
        r.stderr
    );
    assert_eq!(
        bba_rows(&pool, target).await,
        1,
        "a real edge phase wires the edge's factor onto the target\nstdout: {}",
        r.stdout
    );
}

/// `backfill_factors` folds the targets it wires through the same legacy
/// fold, so it too refuses a writing run under another fold, even when the
/// server agrees.
#[sqlx::test(migrations = "../../migrations")]
async fn backfill_factors_refuses_a_writing_run_under_a_fold_this_build_cannot_write(pool: PgPool) {
    let target = seed_unwired_edge(&pool).await;
    let before = belief_state(&pool).await;
    let db = fixture::database_url_for(&pool).await;
    let api = fixture_health(health_with(modes_with_atom_fold("aef")));

    let r = run(
        BACKFILL_FACTORS,
        &["--phase", "edges"],
        &[
            ("DATABASE_URL", &db),
            ("EPIGRAPH_API_URL", &api),
            ("EPIGRAPH_ATOM_FOLD", "aef"),
        ],
    );

    assert_eq!(
        r.code, REFUSED,
        "backfill_factors: must exit 3\nstdout: {}\nstderr: {}",
        r.stdout, r.stderr
    );
    assert!(
        r.stderr.contains("writes only the legacy fold"),
        "stderr: {}",
        r.stderr
    );
    assert_eq!(bba_rows(&pool, target).await, 0, "the edge was not wired");
    assert_eq!(
        belief_state(&pool).await,
        before,
        "a refused run writes nothing"
    );
}

/// `backfill_factors --dry-run` writes nothing, so it is exempt: a skewed
/// environment proceeds, and the API is never contacted.
#[sqlx::test(migrations = "../../migrations")]
async fn backfill_factors_dry_run_is_exempt_and_never_contacts_the_api(pool: PgPool) {
    let target = seed_unwired_edge(&pool).await;
    let before = belief_state(&pool).await;
    let db = fixture::database_url_for(&pool).await;
    let (api, hits) = fixture_health_counted(health_with(legacy_modes()));

    let r = run(
        BACKFILL_FACTORS,
        &["--phase", "edges", "--dry-run"],
        &[
            ("DATABASE_URL", &db),
            ("EPIGRAPH_API_URL", &api),
            ("EPIGRAPH_ATOM_FOLD", "aef_standalone"),
        ],
    );

    assert_eq!(
        r.code,
        Some(0),
        "stdout: {}\nstderr: {}",
        r.stdout,
        r.stderr
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "a dry run must not contact the API"
    );
    assert!(
        r.stdout.contains(&target.to_string()),
        "the dry run lists the edge it would wire\nstdout: {}",
        r.stdout
    );
    assert_eq!(
        belief_state(&pool).await,
        before,
        "a dry run writes nothing"
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

/// A typo in this process's own flag runs the default (SPEC §10.2), so a
/// refusal that blames "this process runs legacy" without saying why sends
/// the operator to the wrong fix. The refusal must name the unrecognised
/// value. `decompose_claims` installs no log subscriber, so stderr is the
/// only place the typo can surface.
#[test]
fn a_refusal_names_this_process_s_unrecognised_flag_value() {
    let api = fixture_health(health_with(modes_with_atom_fold("aef_standalone")));
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
            ("EPIGRAPH_ATOM_FOLD", "aef-standalone"),
        ],
    );

    assert_eq!(r.code, REFUSED, "stderr: {}", r.stderr);
    for needle in ["EPIGRAPH_ATOM_FOLD", "aef-standalone"] {
        assert!(
            r.stderr.contains(needle),
            "the refusal must name the unrecognised value (missing {needle:?})\nstderr: {}",
            r.stderr
        );
    }
}
