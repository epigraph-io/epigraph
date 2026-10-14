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
    assert!(
        r.stdout.contains(COMPANION_HINT) && !r.stdout.contains(REFERENCE_HINT),
        "a cascade-table refusal gets the companion hint and only that\n{}",
        r.show()
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
    assert!(
        r.stdout.contains(REFERENCE_HINT) && !r.stdout.contains(COMPANION_HINT),
        "companions cannot clear an edge, so the hint must not suggest them\n{}",
        r.show()
    );
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
/// except the group-private refusal below connects as the cluster superuser.
/// What this pins is that the login can carry the whole apply: DELETE on
/// `frames` (migration 158), the cascade, the census and the audit row. Every
/// fixture row here is public, so it does NOT pin that the plan sees
/// non-public rows; `delete_frames_refuses_a_group_private_claims_bba_as_a_
/// non_superuser_maintenance_login` does.
#[sqlx::test(migrations = "../../migrations")]
async fn delete_frames_applies_as_a_non_superuser_maintenance_login(pool: PgPool) {
    let s = seed_sweep(&pool).await;
    let missing = Uuid::new_v4();
    let (role, dsn) = maintenance_login(&pool).await;
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

/// The two refusal hints `run` prints after the REFUSED lines. A row of one
/// of the four cascade tables can be licensed by naming its (test) claim a
/// companion; every other reason cannot, and the hint must not send the
/// operator to a remedy that does nothing.
const COMPANION_HINT: &str = "list that claim in --companion-claims-file";
const REFERENCE_HINT: &str = "not affected by --companion-claims-file";

/// `REFUSED\t<id>\t...` lines for one frame.
fn refused_lines(r: &Run, id: Uuid) -> Vec<String> {
    let p = format!("REFUSED\t{id}\t");
    r.stdout
        .lines()
        .filter(|l| l.starts_with(&p))
        .map(|l| l[p.len()..].to_string())
        .collect()
}

async fn table_rows(pool: &PgPool, table: &str) -> i64 {
    count(pool, &format!("SELECT count(*) FROM {table}")).await
}

/// Every refusal reason other than a companion-less BBA and an edge, one frame
/// per reason: a `factors` row, a child frame, a claim whose cached belief is
/// the frame's, and a non-companion row in each of `claim_frames`,
/// `ds_combined_beliefs` and `ds_bayesian_divergence`. Three of these are FK
/// RESTRICT / NO ACTION references that would fail the DELETE anyway; the tool
/// must name them as a refusal (exit 3) instead of surfacing a raw FK error,
/// and the three cascade tables must refuse like `mass_functions` does or a
/// real claim's frame assignment or cached belief would cascade away.
///
/// Listing a parent AND its child refuses the parent (the child row still
/// exists when the plan is read): the child itself is not refused.
///
/// A refusal exits 3 on a dry run too, before the DRY RUN line, and under
/// `--apply` writes nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn delete_frames_refuses_every_blocker_kind_on_a_dry_run_and_under_apply(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let rc = seed_claim(&pool, agent, "a real claim several frames depend on").await;

    let f_factor = seed_frame(&pool, "blocker-factor").await;
    sqlx::query(
        "INSERT INTO factors (factor_type, variable_ids, frame_id) \
         VALUES ('evidential_support', ARRAY[gen_random_uuid(), gen_random_uuid()], $1)",
    )
    .bind(f_factor)
    .execute(&pool)
    .await
    .expect("seed factor");

    let f_parent = seed_frame(&pool, "blocker-parent").await;
    let child = seed_frame(&pool, "blocker-child (not listed)").await;
    let p2 = seed_frame(&pool, "listed-parent").await;
    let c2 = seed_frame(&pool, "listed-child").await;
    for (c, p) in [(child, f_parent), (c2, p2)] {
        sqlx::query("UPDATE frames SET parent_frame_id = $2 WHERE id = $1")
            .bind(c)
            .bind(p)
            .execute(&pool)
            .await
            .expect("seed child frame");
    }

    let f_belief = seed_frame(&pool, "blocker-belief").await;
    let believer = seed_claim(&pool, agent, "a claim whose cached belief is this frame's").await;
    sqlx::query("UPDATE claims SET belief_frame_id = $2 WHERE id = $1")
        .bind(believer)
        .bind(f_belief)
        .execute(&pool)
        .await
        .expect("seed belief_frame_id");

    let f_cf = seed_frame(&pool, "blocker-claim-frames").await;
    assign(&pool, rc, f_cf).await;

    let f_dcb = seed_frame(&pool, "blocker-combined-belief").await;
    sqlx::query(
        "INSERT INTO ds_combined_beliefs (frame_id, claim_id, scope_type, belief, plausibility) \
         VALUES ($1, $2, 'global', 0.6, 0.9)",
    )
    .bind(f_dcb)
    .bind(rc)
    .execute(&pool)
    .await
    .expect("seed ds_combined_beliefs");

    let f_dbd = seed_frame(&pool, "blocker-divergence").await;
    sqlx::query(
        "INSERT INTO ds_bayesian_divergence \
             (claim_id, frame_id, pignistic_prob, bayesian_posterior, kl_divergence) \
         VALUES ($1, $2, 0.6, 0.5, 0.01)",
    )
    .bind(rc)
    .bind(f_dbd)
    .execute(&pool)
    .await
    .expect("seed ds_bayesian_divergence");

    // (frame, the start of its one expected reason)
    let expected: Vec<(Uuid, String)> = vec![
        (f_factor, "factors: 1 row(s)".into()),
        (
            f_parent,
            "frames.parent_frame_id (child frames): 1 row(s)".into(),
        ),
        (
            f_belief,
            "claims.belief_frame_id (claims whose cached belief is this frame's): 1 row(s)".into(),
        ),
        (f_cf, format!("claim_frames: 1 row(s) of claim {rc}")),
        (
            f_dcb,
            format!("ds_combined_beliefs: 1 row(s) of claim {rc}"),
        ),
        (
            f_dbd,
            format!("ds_bayesian_divergence: 1 row(s) of claim {rc}"),
        ),
        (p2, "frames.parent_frame_id (child frames): 1 row(s)".into()),
    ];
    let mut listed: Vec<Uuid> = expected.iter().map(|(f, _)| *f).collect();
    listed.push(c2);
    let ids = ids_file(&listed);

    let tables = [
        "frames",
        "factors",
        "claim_frames",
        "ds_combined_beliefs",
        "ds_bayesian_divergence",
        "security_events",
    ];
    let mut before = Vec::new();
    for t in tables {
        before.push(table_rows(&pool, t).await);
    }

    let dry = run_op(
        &pool,
        &["delete-frames", "--ids-file", &ids, "--reason", "u048 test"],
    )
    .await;
    let apply = run_op(
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

    for (label, r) in [("dry run", &dry), ("apply", &apply)] {
        assert_eq!(
            r.code,
            3,
            "{label}: a refused frame must exit 3\n{}",
            r.show()
        );
        assert!(
            !r.stdout.contains("DRY RUN"),
            "{label}: a refusal stops before the dry-run line\n{}",
            r.show()
        );
        for (frame, want) in &expected {
            let got = refused_lines(r, *frame);
            assert!(
                got.len() == 1 && got[0].starts_with(want.as_str()),
                "{label}: frame {frame} must be refused for exactly `{want}`, got {got:?}\n{}",
                r.show()
            );
        }
        assert!(
            refused_lines(r, c2).is_empty(),
            "{label}: the listed child frame is not itself refused\n{}",
            r.show()
        );
        assert!(
            r.stdout
                .lines()
                .any(|l| l.starts_with(&format!("FRAME\t{c2}\t"))),
            "{label}: the listed child stays in the plan\n{}",
            r.show()
        );
        assert!(
            r.stdout.contains(COMPANION_HINT) && r.stdout.contains(REFERENCE_HINT),
            "{label}: both kinds of reason are present, so both hints must be\n{}",
            r.show()
        );
    }
    for (t, b) in tables.iter().zip(before) {
        assert_eq!(table_rows(&pool, t).await, b, "a refused run changed {t}");
    }
    assert!(audit_rows(&pool).await.is_empty());
}

/// The census is the only accounting for the ON DELETE CASCADE: the tool
/// deletes `frames` alone and trusts `pg_stat_xact_user_tables` to prove that
/// exactly the planned companion rows went with them. A fixture-only trigger
/// makes the frame delete also remove a REAL claim's BBA on an UNLISTED frame,
/// a write the plan cannot see; the run must roll back, real BBA included.
#[sqlx::test(migrations = "../../migrations")]
async fn delete_frames_rolls_back_when_the_census_finds_an_unplanned_change(pool: PgPool) {
    let s = seed_sweep(&pool).await;
    let (t1, t2, k, tc, rc) = s;
    sqlx::query(&format!(
        "CREATE FUNCTION u048_unplanned_delete() RETURNS trigger LANGUAGE plpgsql AS $f$ \
         BEGIN DELETE FROM mass_functions WHERE frame_id = '{k}'; RETURN NULL; END $f$"
    ))
    .execute(&pool)
    .await
    .expect("create trigger function");
    sqlx::query(
        "CREATE TRIGGER u048_unplanned_delete AFTER DELETE ON frames \
         FOR EACH STATEMENT EXECUTE FUNCTION u048_unplanned_delete()",
    )
    .execute(&pool)
    .await
    .expect("create trigger");

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
            "--apply",
            "--confirm-delete",
            "2",
            "--reason",
            "u048 test",
        ],
    )
    .await;
    assert_eq!(
        r.code,
        1,
        "an unplanned change must fail the run\n{}",
        r.show()
    );
    assert!(
        r.stderr.contains("census found changes outside the plan"),
        "{}",
        r.show()
    );
    assert!(
        frame_exists(&pool, t1).await && frame_exists(&pool, t2).await,
        "the frame delete was not rolled back\n{}",
        r.show()
    );
    assert_eq!(
        bbas_on(&pool, tc).await,
        1,
        "the companion BBA was not rolled back"
    );
    assert_eq!(bbas_on(&pool, rc).await, 1, "the real claim lost its BBA");
    assert!(
        audit_rows(&pool).await.is_empty(),
        "a rolled-back run wrote an audit row"
    );
}

/// Create a NOSUPERUSER login in `epigraph_maintenance` and return
/// `(role, dsn)`. The caller drops the role.
async fn maintenance_login(pool: &PgPool) -> (String, String) {
    let url = fixture::database_url_for(pool).await;
    let role = format!("u048_maint_{}", Uuid::new_v4().simple());
    sqlx::query(&format!(
        "CREATE ROLE {role} LOGIN PASSWORD 'probe-only' NOSUPERUSER IN ROLE epigraph_maintenance"
    ))
    .execute(pool)
    .await
    .expect("create role");
    let (scheme, rest) = url.split_once("://").expect("scheme");
    let (_, host) = rest.split_once('@').expect("credentials");
    let dsn = format!("{scheme}://{role}:probe-only@{host}");
    (role, dsn)
}

/// The refusal as a REAL maintenance login, over a real claim that is NOT
/// public: `rc` and its BBA on the listed frame belong to a group the login is
/// no member of. The plan's reads must see that row through
/// `epigraph_bypass()`; a plan read that row security filtered to public rows
/// would miss it and plan the frame as deletable, and the frame's ON DELETE
/// CASCADE (which runs without row security) would then take the hidden BBA.
#[sqlx::test(migrations = "../../migrations")]
async fn delete_frames_refuses_a_group_private_claims_bba_as_a_non_superuser_maintenance_login(
    pool: PgPool,
) {
    let agent = seed_agent(&pool).await;
    let (owner, group) = fixture::seed_agent_with_group(&pool, "u048-private").await;
    let t = seed_frame(&pool, &format!("test-frame-all-{}", Uuid::new_v4())).await;
    let tc = seed_claim(
        &pool,
        agent,
        &format!("test-mass-frame-1-{}", Uuid::new_v4()),
    )
    .await;
    let rc =
        fixture::seed_group_claim(&pool, owner, group, "a private real claim on this frame").await;
    seed_bba(&pool, tc, t, agent).await;
    let real_bba = seed_bba(&pool, rc, t, owner).await;
    // Precondition: the row the plan must see is not public, or this test
    // would pass the same way a superuser run does.
    let (vis, og): (String, Uuid) =
        sqlx::query_as("SELECT visibility::text, owner_group_id FROM mass_functions WHERE id = $1")
            .bind(real_bba)
            .fetch_one(&pool)
            .await
            .expect("bba tenancy");
    assert_eq!(
        (vis.as_str(), og),
        ("group", group),
        "fixture: the real BBA must be group-private"
    );

    let (role, dsn) = maintenance_login(&pool).await;
    let ids = ids_file(&[t]);
    let companions = ids_file(&[tc]);
    let r = run_with_dsn(
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
        &dsn,
    );
    sqlx::query(&format!("DROP ROLE {role}"))
        .execute(&pool)
        .await
        .expect("drop role");

    assert_eq!(
        r.code,
        3,
        "the private claim's BBA must refuse the frame\n{}",
        r.show()
    );
    assert!(
        refused_lines(&r, t)
            .iter()
            .any(|l| l.starts_with(&format!("mass_functions: 1 row(s) of claim {rc}"))),
        "the refusal must name the private claim\n{}",
        r.show()
    );
    assert!(
        frame_exists(&pool, t).await,
        "the refused frame was deleted"
    );
    assert_eq!(
        bbas_on(&pool, rc).await,
        1,
        "the private claim lost its BBA"
    );
    assert!(audit_rows(&pool).await.is_empty());
}
