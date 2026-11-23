//! The frame-assignment write of `dekg migrate create-frames`
//! (`epigraph_cli::dekg_frames::assign_claims_to_frame`), driven with a fixed
//! cluster assignment on a `#[sqlx::test]` database migrated 001 -> head, so
//! no embeddings or clustering are needed (backlog 02612a76).
//!
//! What is pinned:
//!
//! * the returned count is rows written: a claim already bound to the frame
//!   (`ON CONFLICT DO NOTHING`) is not counted, and its existing binding is
//!   left as it was;
//! * a failing insert is an error, not a skip: a frame id that does not exist
//!   fails the call, and a bad row in the middle of a cluster stops the loop
//!   there (the rows before it stay written, the rows after it are never
//!   attempted);
//! * a frame with no hypotheses is refused before anything is written;
//! * the one call site in `src/bin/dekg.rs` adds the returned count to the
//!   command's `claims_assigned` and propagates the error with `.await?`
//!   (a source check, since the whole command cannot run end to end today).
//!
//! # Verified to fail
//!
//! Run against three mutations of the function (PR for backlog 02612a76):
//! counting each attempted row (`+= 1` instead of `rows_affected()`) fails
//! `conflicting_binding_is_not_counted`; discarding a failed insert and
//! continuing fails `missing_frame_aborts` and `bad_row_mid_cluster_stops_the_loop`;
//! finishing the loop and only then returning the first error fails
//! `bad_row_mid_cluster_stops_the_loop` alone (on the row-after assertion);
//! keeping only the last row's count (`=` instead of `+=`) fails
//! `conflicting_binding_is_not_counted`. Swallowing the error at the call site
//! (`.await.unwrap_or(0)`) or dropping the count there (`let _n = ...`) fails
//! `create_frames_call_site_counts_and_propagates`.

use epigraph_cli::dekg_frames::assign_claims_to_frame;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'dekg-create-frames-test', 'system', \
                 ARRAY['test']) RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

async fn seed_frame(pool: &PgPool, name: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO frames (name, description, hypotheses) \
         VALUES ($1, 'dekg create-frames test frame', ARRAY['H0', 'H1']) RETURNING id",
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

/// The stored `hypothesis_index` of `(claim, frame)`, or `None` when the
/// binding does not exist.
async fn binding(pool: &PgPool, claim: Uuid, frame: Uuid) -> Option<Option<i32>> {
    sqlx::query_scalar(
        "SELECT hypothesis_index FROM claim_frames WHERE claim_id = $1 AND frame_id = $2",
    )
    .bind(claim)
    .bind(frame)
    .fetch_optional(pool)
    .await
    .expect("read claim_frames")
}

async fn bindings_of_frame(pool: &PgPool, frame: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM claim_frames WHERE frame_id = $1")
        .bind(frame)
        .fetch_one(pool)
        .await
        .expect("count claim_frames")
}

/// (a) A claim already bound to the frame is not counted, and its binding is
/// not overwritten; the new claims are written with `row_index % hypotheses`
/// and counted across the whole loop (two new rows, so a count that keeps only
/// the last row's `rows_affected()` is caught too).
#[sqlx::test(migrations = "../../migrations")]
async fn conflicting_binding_is_not_counted(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let frame = seed_frame(&pool, "dekg-assign-conflict").await;
    let a = seed_claim(&pool, agent, "dekg assign claim A").await;
    let b = seed_claim(&pool, agent, "dekg assign claim B").await;
    let c = seed_claim(&pool, agent, "dekg assign claim C").await;

    // A is already bound, with an index the call would never write.
    sqlx::query(
        "INSERT INTO claim_frames (claim_id, frame_id, hypothesis_index) VALUES ($1, $2, 7)",
    )
    .bind(a)
    .bind(frame)
    .execute(&pool)
    .await
    .expect("pre-bind A");

    let written = assign_claims_to_frame(&pool, frame, &[(0, a), (5, b), (2, c)], 2)
        .await
        .expect("assign");

    assert_eq!(
        written, 2,
        "B and C were written; the conflicting A binding must not be counted"
    );
    assert_eq!(
        binding(&pool, a, frame).await,
        Some(Some(7)),
        "A's existing binding is left as it was"
    );
    assert_eq!(
        binding(&pool, b, frame).await,
        Some(Some(1)),
        "B is bound with hypothesis_index = 5 % 2"
    );
    assert_eq!(
        binding(&pool, c, frame).await,
        Some(Some(0)),
        "C is bound with hypothesis_index = 2 % 2"
    );
    assert_eq!(bindings_of_frame(&pool, frame).await, 3);
}

/// (b) A frame id that does not exist fails the call; nothing is written.
#[sqlx::test(migrations = "../../migrations")]
async fn missing_frame_aborts(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let a = seed_claim(&pool, agent, "dekg assign missing-frame A").await;
    let b = seed_claim(&pool, agent, "dekg assign missing-frame B").await;
    let missing = Uuid::new_v4();

    let got = assign_claims_to_frame(&pool, missing, &[(0, a), (1, b)], 2).await;

    match got {
        Err(e) => assert!(
            format!("{e:#}").contains("insert claim_frames assignment"),
            "the error names the failed write: {e:#}"
        ),
        Ok(n) => panic!("a frame id that does not exist must fail the call, got Ok({n})"),
    }
    assert_eq!(bindings_of_frame(&pool, missing).await, 0);
}

/// (c) A bad row in the middle of a cluster stops the loop: the row before it
/// stays written and the row after it is never attempted. Distinguishes
/// "abort at once" from "keep looping and return the first error at the end",
/// which (b) cannot (there every row fails, so both shapes write nothing).
#[sqlx::test(migrations = "../../migrations")]
async fn bad_row_mid_cluster_stops_the_loop(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let frame = seed_frame(&pool, "dekg-assign-mid-cluster").await;
    let a = seed_claim(&pool, agent, "dekg assign mid-cluster A").await;
    let c = seed_claim(&pool, agent, "dekg assign mid-cluster C").await;
    let no_such_claim = Uuid::new_v4();

    let got = assign_claims_to_frame(&pool, frame, &[(0, a), (1, no_such_claim), (2, c)], 2).await;

    assert!(
        got.is_err(),
        "a claim id that does not exist must fail the call, got {got:?}"
    );
    assert_eq!(
        binding(&pool, a, frame).await,
        Some(Some(0)),
        "the row before the failure stays written"
    );
    assert_eq!(
        binding(&pool, c, frame).await,
        None,
        "the row after the failure is never attempted"
    );
    assert_eq!(bindings_of_frame(&pool, frame).await, 1);
}

/// A frame with no hypotheses is refused before any insert (no `% 0`).
#[sqlx::test(migrations = "../../migrations")]
async fn zero_hypotheses_is_refused(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let frame = seed_frame(&pool, "dekg-assign-zero-hypotheses").await;
    let a = seed_claim(&pool, agent, "dekg assign zero-hypotheses A").await;

    let got = assign_claims_to_frame(&pool, frame, &[(0, a)], 0).await;

    assert!(got.is_err(), "zero hypotheses must be refused, got {got:?}");
    assert_eq!(bindings_of_frame(&pool, frame).await, 0);
}

/// The binary's one call of `assign_claims_to_frame` must add the returned
/// count to `claims_assigned` and propagate the error with `?` to `main`
/// (which returns `Result`, so the command exits non-zero). The tests above pin
/// the library function; this pins the call site, which they cannot reach: the
/// command needs the clustering pipeline's embeddings to get there. A source
/// check, so it runs without a database.
#[test]
fn create_frames_call_site_counts_and_propagates() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bin/dekg.rs"))
        .expect("read src/bin/dekg.rs");
    let needle = "assign_claims_to_frame(";
    let starts: Vec<usize> = src.match_indices(needle).map(|(i, _)| i).collect();
    assert_eq!(
        starts.len(),
        1,
        "dekg.rs calls assign_claims_to_frame exactly once; update this check if that changes"
    );
    let start = starts[0];

    // The statement head: from the previous statement boundary to the call.
    let head_from = src[..start].rfind([';', '{', '}']).map_or(0, |i| i + 1);
    let head: String = src[head_from..start]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    assert_eq!(
        head, "claims_assigned+=epigraph_cli::dekg_frames::",
        "the returned count must be added to claims_assigned"
    );

    // The statement tail: after the call's matching `)` up to the `;`.
    let open = start + needle.len() - 1;
    let mut depth = 0usize;
    let mut close = None;
    for (i, ch) in src[open..].char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(open + i);
                    break;
                }
            }
            _ => {}
        }
    }
    let close = close.expect("matching ) of the assign_claims_to_frame call");
    let end = close + src[close..].find(';').expect("; ending the call statement");
    let tail: String = src[close + 1..end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    assert_eq!(
        tail, ".await?",
        "the insert error must propagate with `?`, not be swallowed or defaulted"
    );
}
