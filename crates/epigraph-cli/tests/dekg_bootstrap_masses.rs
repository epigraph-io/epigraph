//! `dekg migrate bootstrap-masses`, driven through the real binary against a
//! `#[sqlx::test]` database migrated 001 -> head (backlog 8013cd91).
//!
//! What is pinned:
//! * a claim on a THREE-hypothesis frame gets one mass function whose Theta
//!   key names all three hypotheses (`"0,1,2"`), not a binary `"0,1"`;
//! * the printed count is the number of rows actually written: an INSERT the
//!   database turned into a no-op is not counted.

mod viewer_fixture;

use sqlx::PgPool;
use std::process::Command;
use uuid::Uuid;
use viewer_fixture as fixture;

const BIN: &str = env!("CARGO_BIN_EXE_dekg");

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

async fn bootstrap(pool: &PgPool) -> Run {
    let url = fixture::database_url_for(pool).await;
    let out = Command::new(BIN)
        .args(["migrate", "bootstrap-masses", "--db-url", &url])
        .env("RUST_LOG", "warn")
        // `dekg` refuses to start without a token, though `migrate` talks to
        // the database only.
        .env("EPIGRAPH_TOKEN", "unused-by-migrate")
        .env_remove("DATABASE_URL")
        .output()
        .expect("spawn dekg");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// A public claim assigned to a fresh frame with `hypotheses`.
async fn claim_on_frame(pool: &PgPool, hypotheses: &[&str]) -> (Uuid, Uuid) {
    let (agent, _) = fixture::seed_agent_with_group(pool, "bootstrap").await;
    let claim = fixture::seed_public_claim(pool, agent, "bootstrap-masses subject").await;
    let hyps: Vec<String> = hypotheses.iter().map(|s| (*s).to_string()).collect();
    let frame: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses, owner_group_id, visibility) \
         VALUES ($1, $2, $3, 'public') RETURNING id",
    )
    .bind(format!("bootstrap-frame-{}", Uuid::new_v4().simple()))
    .bind(&hyps)
    .bind(Uuid::nil())
    .fetch_one(pool)
    .await
    .expect("seed frame");
    sqlx::query(
        "INSERT INTO claim_frames (claim_id, frame_id, hypothesis_index) VALUES ($1, $2, 0)",
    )
    .bind(claim)
    .bind(frame)
    .execute(pool)
    .await
    .expect("seed claim_frames");
    (claim, frame)
}

async fn masses_of(pool: &PgPool, claim: Uuid, frame: Uuid) -> Vec<serde_json::Value> {
    sqlx::query_scalar("SELECT masses FROM mass_functions WHERE claim_id = $1 AND frame_id = $2")
        .bind(claim)
        .bind(frame)
        .fetch_all(pool)
        .await
        .expect("read mass_functions")
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_three_hypothesis_frame_gets_a_theta_key_of_all_three(pool: PgPool) {
    let (claim, frame) = claim_on_frame(&pool, &["a", "b", "c"]).await;
    let r = bootstrap(&pool).await;
    assert_eq!(r.code, 0, "{}", r.show());
    let rows = masses_of(&pool, claim, frame).await;
    assert_eq!(rows.len(), 1, "one bootstrap row: {}", r.show());
    let keys: Vec<&str> = rows[0]
        .as_object()
        .expect("masses is an object")
        .keys()
        .map(String::as_str)
        .collect();
    assert!(
        keys.contains(&"0,1,2"),
        "Theta covers all three hypotheses, got keys {keys:?}"
    );
    assert!(!keys.contains(&"0,1"), "not a binary Theta: {keys:?}");
    assert!(
        r.stdout.contains("Created 1 mass functions"),
        "{}",
        r.show()
    );
}

/// The NOT EXISTS in the selection already excludes a pair that has a row,
/// so a concurrent writer is the only natural way an INSERT writes nothing.
/// A test-only `BEFORE INSERT ... RETURN NULL` trigger produces the same
/// outcome deterministically: the statement succeeds and writes 0 rows.
#[sqlx::test(migrations = "../../migrations")]
async fn an_insert_that_writes_nothing_is_not_counted(pool: PgPool) {
    let (claim, frame) = claim_on_frame(&pool, &["yes", "no"]).await;
    for sql in [
        "CREATE FUNCTION test_swallow_mass_insert() RETURNS trigger LANGUAGE plpgsql AS \
         $$ BEGIN RETURN NULL; END $$",
        "CREATE TRIGGER test_swallow_mass_insert BEFORE INSERT ON mass_functions \
         FOR EACH ROW EXECUTE FUNCTION test_swallow_mass_insert()",
    ] {
        sqlx::query(sql).execute(&pool).await.expect(sql);
    }
    let r = bootstrap(&pool).await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert!(masses_of(&pool, claim, frame).await.is_empty());
    assert!(
        r.stdout.contains("Created 0 mass functions"),
        "a row the database did not write is not counted: {}",
        r.show()
    );
}
