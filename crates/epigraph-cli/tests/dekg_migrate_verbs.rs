//! `dekg migrate create-frames` and `dekg migrate validate`, driven through the
//! real `dekg` binary against a `#[sqlx::test]` database migrated 001 -> head
//! (backlog 06385b31).
//!
//! `frames.hypotheses` is `text[]` (migration 001, never altered). Both verbs
//! used to treat it as `jsonb`: `create-frames` bound a `serde_json::Value`
//! into the insert and `validate` called `jsonb_array_length(hypotheses)`, so
//! Postgres refused each with a datatype error and neither verb could finish
//! on any database. `create-frames` also read the claim embeddings with
//! `embedding::text::float4[]`, which Postgres refuses as well (pgvector prints
//! `[..]`, and array input reads a leading `[` as a dimension decoration), so
//! the command stopped before it reached the frame insert at all.
//!
//! What is pinned:
//!
//! * `create-frames` on two well-separated clusters of three claims exits 0,
//!   writes exactly two `Auto-frame-*` frames whose `hypotheses` array holds
//!   the cluster's three members, binds all six claims, and says so;
//! * `validate` exits 0 on that database and reports the frames check as
//!   PASS with zero violations. (`frames_not_empty`, a CHECK of at least two
//!   hypotheses, means the violation count cannot be non-zero on a migrated
//!   database; what this pins is that the check RUNS instead of being refused.)
//!
//! # Verified to fail
//!
//! On the code before the fix: `create_frames_then_validate_end_to_end` fails
//! at the create-frames exit code (the embedding read is refused). With only
//! the embedding cast fixed it still fails there, on the frame insert's
//! `jsonb` bind; with only the insert fixed (validate unchanged) it fails at
//! the validate exit code with the `jsonb_array_length` refusal.

mod viewer_fixture;

use sqlx::PgPool;
use std::process::Command;
use uuid::Uuid;
use viewer_fixture as fixture;

const BIN: &str = env!("CARGO_BIN_EXE_dekg");
/// `claims.embedding` is `vector(1536)` (migration 001).
const DIM: usize = 1536;

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

/// Run `dekg` with `--db-url` pointing at the test database. The DSN
/// variables are removed so the binary connects to that database and no
/// other (`MAINTENANCE_DATABASE_URL` would otherwise win over `--db-url`).
///
/// `main` refuses to start without an API token before it dispatches any
/// subcommand, `migrate` included, although the migrate verbs never call the
/// API; a placeholder satisfies that check and is never sent anywhere.
fn dekg(args: &[&str]) -> Run {
    let out = Command::new(BIN)
        .args(args)
        .env("RUST_LOG", "warn")
        .env("EPIGRAPH_TOKEN", "unused-by-migrate-verbs")
        .env("EPIGRAPH_API_URL", "http://127.0.0.1:9")
        .env_remove("DATABASE_URL")
        .env_remove("MAINTENANCE_DATABASE_URL")
        .output()
        .expect("spawn dekg");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'dekg-migrate-verbs-test', 'system', \
                 ARRAY['test']) RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

/// A pgvector literal: `axis` set to 1.0, a small `jitter` on the next
/// coordinate, every other coordinate 0.
fn embedding(axis: usize, jitter: f32) -> String {
    let mut v = vec![0.0f32; DIM];
    v[axis] = 1.0;
    v[axis + 1] = jitter;
    let body: Vec<String> = v.iter().map(f32::to_string).collect();
    format!("[{}]", body.join(","))
}

async fn seed_claim(pool: &PgPool, agent: Uuid, content: &str, emb: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, embedding) \
         VALUES ($1, sha256($1::bytea), 0.5, $2, $3::vector) RETURNING id",
    )
    .bind(content)
    .bind(agent)
    .bind(emb)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

#[sqlx::test(migrations = "../../migrations")]
async fn create_frames_then_validate_end_to_end(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let mut seeded = Vec::new();
    for (axis, label) in [(0usize, "alpha"), (10usize, "beta")] {
        for j in 0..3u8 {
            let content = format!("dekg verbs cluster {label} member {j}");
            let emb = embedding(axis, f32::from(j) * 0.01);
            seeded.push(seed_claim(&pool, agent, &content, &emb).await);
        }
    }
    let url = fixture::database_url_for(&pool).await;

    let created = dekg(&[
        "migrate",
        "create-frames",
        "--db-url",
        &url,
        "--k-min",
        "2",
        "--k-max",
        "2",
        "--min-claims",
        "3",
    ]);
    assert_eq!(created.code, 0, "create-frames must finish\n{}", created.show());
    assert!(
        created.stdout.contains("Created 2 frames, assigned 6 claims"),
        "create-frames reports what it wrote\n{}",
        created.show()
    );

    // Migrations seed frames of their own; count only this command's.
    let frames: Vec<(Uuid, Vec<String>)> = sqlx::query_as(
        "SELECT id, hypotheses FROM frames WHERE name LIKE 'Auto-frame-%' ORDER BY name",
    )
    .fetch_all(&pool)
    .await
    .expect("read auto frames");
    assert_eq!(frames.len(), 2, "one frame per cluster: {frames:?}");
    for (id, hypotheses) in &frames {
        assert_eq!(
            hypotheses.len(),
            3,
            "frame {id} names its cluster's three members as text[] hypotheses: {hypotheses:?}"
        );
        assert!(
            hypotheses
                .iter()
                .all(|h| h.starts_with("dekg verbs cluster ")),
            "the hypotheses are the members' contents, not a JSON rendering: {hypotheses:?}"
        );
        let clusters: std::collections::BTreeSet<&str> = hypotheses
            .iter()
            .map(|h| h.split_whitespace().nth(3).unwrap_or_default())
            .collect();
        assert_eq!(
            clusters.len(),
            1,
            "a frame's hypotheses come from one cluster: {hypotheses:?}"
        );
    }

    let bound: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM claim_frames cf JOIN frames f ON f.id = cf.frame_id \
         WHERE f.name LIKE 'Auto-frame-%' AND cf.claim_id = ANY($1)",
    )
    .bind(&seeded)
    .fetch_one(&pool)
    .await
    .expect("count bindings");
    assert_eq!(bound, 6, "every seeded claim is bound to its cluster's frame");

    let validated = dekg(&["migrate", "validate", "--db-url", &url]);
    assert_eq!(
        validated.code,
        0,
        "validate must run every check and pass\n{}",
        validated.show()
    );
    assert!(
        validated
            .stdout
            .contains("Frames have hypotheses: PASS (0 violations)"),
        "the frames check ran\n{}",
        validated.show()
    );
    assert!(
        validated.stdout.contains("ALL CHECKS PASSED"),
        "{}",
        validated.show()
    );
}
