//! `epigraph-operator delete-frames` (drain U048, backlog 34b3175c), driven
//! through the real binary against a `#[sqlx::test]` database migrated
//! 001 -> head.
//!
//! What is pinned: a listed frame carrying ANY frame-keyed row (BBA, frame
//! assignment, cached belief, divergence) of a claim outside the companion set
//! is refused and nothing is written, so no real claim's belief changes; a
//! frame that is an edge endpoint is refused (edges have no foreign key to
//! `frames`, so nothing else would stop them dangling); `--apply` needs the
//! exact planned count; a dry run prints the cascade counts and writes
//! nothing, audit included; an apply removes exactly the listed frames and
//! their companion rows, leaves every other frame and claim row alone, skips
//! an id that is not a frame, and writes one `security_events` row; and the
//! same apply works as a real NOSUPERUSER maintenance login.

mod viewer_fixture;

use sqlx::PgPool;
use std::io::Write as _;
use std::process::Command;
use uuid::Uuid;
use viewer_fixture as fixture;

const BIN: &str = env!("CARGO_BIN_EXE_epigraph-operator");
const DSN_ENV: &str = "EPIGRAPH_OPERATOR_MAINTENANCE_DSN";
const EVENT: &str = "operator.frames_deleted";

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

fn run_with_dsn(args: &[&str], dsn: &str) -> Run {
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

async fn run_op(pool: &PgPool, args: &[&str]) -> Run {
    let url = fixture::database_url_for(pool).await;
    run_with_dsn(args, &url)
}

/// Write one UUID per line (after a `#` comment) to a fresh scratch file and
/// return its path.
fn ids_file(ids: &[Uuid]) -> String {
    let p = std::env::temp_dir().join(format!("operator-delete-frames-{}.txt", Uuid::new_v4()));
    let mut f = std::fs::File::create(&p).expect("scratch file");
    writeln!(f, "# delete-frames test ids").expect("write");
    for id in ids {
        writeln!(f, "{id}").expect("write");
    }
    f.sync_all().expect("sync");
    p.to_str().expect("utf-8 path").to_string()
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'delete-frames-test', 'system', \
                 ARRAY['test']) RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

async fn seed_frame(pool: &PgPool, name: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO frames (name, description, hypotheses) \
         VALUES ($1, 'delete-frames test frame', ARRAY['TRUE', 'FALSE']) RETURNING id",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .expect("seed frame")
}

async fn seed_claim(pool: &PgPool, agent: Uuid, content: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id) \
         VALUES ($1, sha256($1::bytea), 0.5, $2) RETURNING id",
    )
    .bind(content)
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

async fn seed_bba(pool: &PgPool, claim: Uuid, frame: Uuid, agent: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO mass_functions (claim_id, frame_id, source_agent_id, masses) \
         VALUES ($1, $2, $3, '{\"0\": 0.7, \"0,1\": 0.3}'::jsonb) RETURNING id",
    )
    .bind(claim)
    .bind(frame)
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seed BBA")
}

async fn assign(pool: &PgPool, claim: Uuid, frame: Uuid) {
    sqlx::query(
        "INSERT INTO claim_frames (claim_id, frame_id, hypothesis_index) VALUES ($1, $2, 0)",
    )
    .bind(claim)
    .bind(frame)
    .execute(pool)
    .await
    .expect("seed claim_frames");
}

async fn frame_exists(pool: &PgPool, id: Uuid) -> bool {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM frames WHERE id = $1)")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("frame exists")
}

async fn count(pool: &PgPool, sql: &str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(pool).await.expect(sql)
}

async fn bbas_on(pool: &PgPool, claim: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM mass_functions WHERE claim_id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("bbas")
}

async fn audit_rows(pool: &PgPool) -> Vec<serde_json::Value> {
    sqlx::query_scalar(
        "SELECT details FROM security_events WHERE event_type = $1 ORDER BY created_at, id",
    )
    .bind(EVENT)
    .fetch_all(pool)
    .await
    .expect("audit rows")
}

/// A test frame `T` carries a BBA from its companion test claim `tc` AND one
/// from a real claim `rc`. Listing `tc` as a companion must not license `rc`'s
/// row: the run refuses `T`, names `rc`, and writes nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn delete_frames_refuses_a_frame_carrying_a_bba_on_a_real_claim(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let t = seed_frame(&pool, &format!("test-frame-all-{}", Uuid::new_v4())).await;
    let tc = seed_claim(
        &pool,
        agent,
        &format!("test-mass-frame-1-{}", Uuid::new_v4()),
    )
    .await;
    let rc = seed_claim(
        &pool,
        agent,
        "a real claim whose belief rests on this frame",
    )
    .await;
    seed_bba(&pool, tc, t, agent).await;
    let real_bba = seed_bba(&pool, rc, t, agent).await;

    let ids = ids_file(&[t]);
    let companions = ids_file(&[tc]);
    let r = run_op(
        &pool,
        &[
            "delete-frames",
            "--ids-file",
            &ids,
            "--companion-claims-file",
            &companions,
            "--apply",
            "--confirm-delete",
            "1",
            "--reason",
            "u048 test",
        ],
    )
    .await;

    assert_eq!(r.code, 3, "a refused frame must exit 3\n{}", r.show());
    let refused: Vec<&str> = r
        .stdout
        .lines()
        .filter(|l| l.starts_with(&format!("REFUSED\t{t}\t")))
        .collect();
    assert!(
        refused
            .iter()
            .any(|l| l.contains("mass_functions") && l.contains(&rc.to_string())),
        "the refusal must name the real claim's BBA\n{}",
        r.show()
    );
    assert!(
        !refused.iter().any(|l| l.contains(&tc.to_string())),
        "the companion claim is not a reason to refuse\n{}",
        r.show()
    );
    assert!(
        frame_exists(&pool, t).await,
        "the refused frame was deleted"
    );
    assert_eq!(bbas_on(&pool, rc).await, 1, "the real claim lost its BBA");
    assert_eq!(bbas_on(&pool, tc).await, 1, "a refused run removed a row");
    let still: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM mass_functions WHERE id = $1)")
            .bind(real_bba)
            .fetch_one(&pool)
            .await
            .expect("bba");
    assert!(still);
    assert!(
        audit_rows(&pool).await.is_empty(),
        "a refused run wrote an audit row"
    );
}

/// Edges carry no foreign key to `frames` (055's existence trigger fires on
/// INSERT only), so nothing in the schema stops a frame delete leaving an edge
/// dangling. The tool must refuse it.
#[sqlx::test(migrations = "../../migrations")]
async fn delete_frames_refuses_a_frame_that_is_an_edge_endpoint(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let t = seed_frame(&pool, "e2e-test-frame").await;
    let c = seed_claim(&pool, agent, "a claim linked to the frame by an edge").await;
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'frame', 'IN_FRAME')",
    )
    .bind(c)
    .bind(t)
    .execute(&pool)
    .await
    .expect("seed edge");

    let ids = ids_file(&[t]);
    let r = run_op(
        &pool,
        &[
            "delete-frames",
            "--ids-file",
            &ids,
            "--apply",
            "--confirm-delete",
            "1",
            "--reason",
            "u048 test",
        ],
    )
    .await;
    assert_eq!(r.code, 3, "{}", r.show());
    assert!(
        r.stdout
            .lines()
            .any(|l| l.starts_with(&format!("REFUSED\t{t}\t")) && l.contains("edges")),
        "{}",
        r.show()
    );
    assert!(frame_exists(&pool, t).await);
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM edges WHERE target_type = 'frame'"
        )
        .await,
        1
    );
    assert!(audit_rows(&pool).await.is_empty());
}

/// The fixture both apply tests share: `t1` carries its companion test claim's
/// BBA and frame assignment, `t2` is unreferenced, and `k` (NOT listed) carries
/// a real claim's BBA. Returns `(t1, t2, k, tc, rc)`.
async fn seed_sweep(pool: &PgPool) -> (Uuid, Uuid, Uuid, Uuid, Uuid) {
    let agent = seed_agent(pool).await;
    let t1 = seed_frame(pool, &format!("test-frame-all-{}", Uuid::new_v4())).await;
    let t2 = seed_frame(pool, "e2e-40-1777590762 frame").await;
    let k = seed_frame(pool, "claim_validity_like").await;
    let tc = seed_claim(
        pool,
        agent,
        &format!("test-mass-frame-1-{}", Uuid::new_v4()),
    )
    .await;
    let rc = seed_claim(pool, agent, "a real claim on a real frame").await;
    seed_bba(pool, tc, t1, agent).await;
    assign(pool, tc, t1).await;
    seed_bba(pool, rc, k, agent).await;
    (t1, t2, k, tc, rc)
}

/// Without `--apply` nothing is written, the audit row included, and the plan
/// prints what WOULD cascade.
#[sqlx::test(migrations = "../../migrations")]
async fn delete_frames_dry_run_writes_nothing(pool: PgPool) {
    let (t1, t2, _k, tc, _rc) = seed_sweep(&pool).await;
    let frames_before = count(&pool, "SELECT count(*) FROM frames").await;
    let mf_before = count(&pool, "SELECT count(*) FROM mass_functions").await;
    let cf_before = count(&pool, "SELECT count(*) FROM claim_frames").await;
    let se_before = count(&pool, "SELECT count(*) FROM security_events").await;

    let ids = ids_file(&[t1, t2]);
    let companions = ids_file(&[tc]);
    let r = run_op(
        &pool,
        &[
            "delete-frames",
            "--ids-file",
            &ids,
            "--companion-claims-file",
            &companions,
            "--reason",
            "u048 test",
        ],
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert!(r.stdout.contains("DELETE-PLAN: 2 frame(s)"), "{}", r.show());
    assert!(
        r.stdout.lines().any(|l| l == "CASCADE\tmass_functions\t1"),
        "{}",
        r.show()
    );
    assert!(
        r.stdout.lines().any(|l| l == "CASCADE\tclaim_frames\t1"),
        "{}",
        r.show()
    );
    assert!(r.stdout.contains("DRY RUN"), "{}", r.show());
    assert_eq!(
        count(&pool, "SELECT count(*) FROM frames").await,
        frames_before
    );
    assert_eq!(
        count(&pool, "SELECT count(*) FROM mass_functions").await,
        mf_before
    );
    assert_eq!(
        count(&pool, "SELECT count(*) FROM claim_frames").await,
        cf_before
    );
    assert_eq!(
        count(&pool, "SELECT count(*) FROM security_events").await,
        se_before
    );
}

/// `--apply` without the count, or with the wrong one, is refused before any
/// write.
#[sqlx::test(migrations = "../../migrations")]
async fn delete_frames_apply_needs_the_exact_planned_count(pool: PgPool) {
    let (t1, t2, _k, tc, _rc) = seed_sweep(&pool).await;
    let ids = ids_file(&[t1, t2]);
    let companions = ids_file(&[tc]);
    for confirm in [None, Some("1"), Some("3")] {
        let mut args = vec![
            "delete-frames".to_string(),
            "--ids-file".into(),
            ids.clone(),
            "--companion-claims-file".into(),
            companions.clone(),
            "--apply".into(),
            "--reason".into(),
            "u048 test".into(),
        ];
        if let Some(n) = confirm {
            args.push("--confirm-delete".into());
            args.push(n.into());
        }
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        let r = run_op(&pool, &a).await;
        assert_eq!(r.code, 1, "confirm {confirm:?}\n{}", r.show());
        assert!(
            r.stderr.contains("--confirm-delete 2"),
            "the refusal names the planned count\n{}",
            r.show()
        );
        assert!(frame_exists(&pool, t1).await && frame_exists(&pool, t2).await);
        assert_eq!(bbas_on(&pool, tc).await, 1);
        assert!(audit_rows(&pool).await.is_empty());
    }
}

/// Assert the state after a successful apply over `seed_sweep`'s fixture.
async fn assert_swept(pool: &PgPool, r: &Run, ids: (Uuid, Uuid, Uuid, Uuid, Uuid), missing: Uuid) {
    let (t1, t2, k, tc, rc) = ids;
    assert_eq!(r.code, 0, "{}", r.show());
    assert!(!frame_exists(pool, t1).await, "t1 survived\n{}", r.show());
    assert!(!frame_exists(pool, t2).await, "t2 survived\n{}", r.show());
    assert!(frame_exists(pool, k).await, "an unlisted frame was deleted");
    assert_eq!(
        bbas_on(pool, tc).await,
        0,
        "the companion BBA was not removed"
    );
    assert_eq!(
        count(
            pool,
            &format!("SELECT count(*) FROM claim_frames WHERE claim_id = '{tc}'")
        )
        .await,
        0
    );
    assert_eq!(
        bbas_on(pool, rc).await,
        1,
        "a real claim on an unlisted frame lost its BBA"
    );
    assert!(
        r.stdout
            .lines()
            .any(|l| l.starts_with(&format!("MISSING\t{missing}\t"))),
        "{}",
        r.show()
    );
    let audit = audit_rows(pool).await;
    assert_eq!(audit.len(), 1, "exactly one audit row\n{}", r.show());
    let d = &audit[0];
    let mut got: Vec<String> = d["frames"]
        .as_array()
        .expect("details.frames")
        .iter()
        .map(|f| f["id"].as_str().expect("frame id").to_string())
        .collect();
    got.sort();
    let mut want = vec![t1.to_string(), t2.to_string()];
    want.sort();
    assert_eq!(got, want, "{d}");
    assert_eq!(d["cascade"]["mass_functions"], 1, "{d}");
    assert_eq!(d["cascade"]["claim_frames"], 1, "{d}");
    assert_eq!(d["reason"], "u048 test", "{d}");
}

/// The happy path: the listed frames and their companion rows go, an unlisted
/// frame and a real claim's BBA stay, an id that is not a frame is skipped,
/// and one audit row records the frames and the cascade counts.
#[sqlx::test(migrations = "../../migrations")]
async fn delete_frames_apply_removes_only_listed_frames_and_their_companion_rows(pool: PgPool) {
    let s = seed_sweep(&pool).await;
    let missing = Uuid::new_v4();
    let ids = ids_file(&[s.0, s.1, missing]);
    let companions = ids_file(&[s.3]);
    let r = run_op(
        &pool,
        &[
            "delete-frames",
            "--ids-file",
            &ids,
            "--companion-claims-file",
            &companions,
            "--apply",
            "--confirm-delete",
            "2",
            "--reason",
            "u048 test",
        ],
    )
    .await;
    assert_swept(&pool, &r, s, missing).await;
}

/// The same apply as a REAL maintenance login (`NOSUPERUSER`, a member of
/// `epigraph_maintenance`), the shape the runbook uses. Every other test here
/// connects as the cluster superuser, which no row-security policy filters; a
/// plan read filtered to nothing would let the frame's ON DELETE CASCADE take
/// rows the plan never counted.
#[sqlx::test(migrations = "../../migrations")]
async fn delete_frames_applies_as_a_non_superuser_maintenance_login(pool: PgPool) {
    let s = seed_sweep(&pool).await;
    let missing = Uuid::new_v4();
    let url = fixture::database_url_for(&pool).await;
    let role = format!("u048_maint_{}", Uuid::new_v4().simple());
    sqlx::query(&format!(
        "CREATE ROLE {role} LOGIN PASSWORD 'probe-only' NOSUPERUSER IN ROLE epigraph_maintenance"
    ))
    .execute(&pool)
    .await
    .expect("create role");
    let (scheme, rest) = url.split_once("://").expect("scheme");
    let (_, host) = rest.split_once('@').expect("credentials");
    let dsn = format!("{scheme}://{role}:probe-only@{host}");
    let ids = ids_file(&[s.0, s.1, missing]);
    let companions = ids_file(&[s.3]);
    let r = run_with_dsn(
        &[
            "delete-frames",
            "--ids-file",
            &ids,
            "--companion-claims-file",
            &companions,
            "--apply",
            "--confirm-delete",
            "2",
            "--reason",
            "u048 test",
        ],
        &dsn,
    );
    // Drop the cluster-global role BEFORE asserting, so a failure cannot leak it.
    sqlx::query(&format!("DROP ROLE {role}"))
        .execute(&pool)
        .await
        .expect("drop role");
    assert_swept(&pool, &r, s, missing).await;
}
