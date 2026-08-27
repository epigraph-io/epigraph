//! REGRESSION. `backfill_canonical_hash --max-chunks N` must make progress
//! across successive windows (backlog e09986c2).
//!
//! # The defect this pins
//!
//! Once the backfill gained an ELIGIBILITY filter — only a row whose
//! `content_hash` is the plain BLAKE3 of its `content` gets a canonical twin —
//! `WHERE canonical_hash IS NULL` stopped being self-consuming. An ineligible
//! row is read, deliberately not written, and is still NULL on the next scan.
//!
//! A drain that always restarts at the beginning therefore re-reads the whole
//! accumulated skip prefix on every invocation. With a chunk budget that is
//! smaller than that prefix, the budget is consumed entirely by re-skips and
//! no eligible row is ever reached — a permanent stall, not a slowdown. The
//! fixture below is exactly that shape: four ineligible rows sort first,
//! `--chunk-size 2 --max-chunks 2` reads only those four, and the single
//! eligible row sits just past the budget forever.
//!
//! # What the fix is
//!
//! [`drain`] takes a starting cursor and returns
//! [`CanonicalBackfillPass::resume_after`], which the binary surfaces as
//! `--after <uuid>`. `stalls_when_the_cursor_is_discarded` holds the defect
//! itself in place so the passing test cannot be read as "budgets happen to
//! work"; the two differ ONLY in whether the cursor is threaded.

use epigraph_cli::backfill_canonical_hash::drain;
use epigraph_crypto::ContentHasher;
use sqlx::PgPool;
use uuid::Uuid;

const ELIGIBLE_TEXT: &str = "Legacy row whose digest is the plain one.";
const SHARED_SPINE_TEXT: &str = "Introduction";

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, agent_type, created_at, updated_at) \
         VALUES ($1, sha256($1::text::bytea), 'system', NOW(), NOW())",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("seed agent");
    id
}

/// Four rows carrying a NAMESPACED digest (ids forced low so `ORDER BY id`
/// puts them first) and one eligible legacy row (id forced high). Returns the
/// eligible row's id.
///
/// The namespacing mirrors `epigraph_ingest::common::ids::compound_content_hash`
/// — BLAKE3 over the plain digest concatenated with a per-artifact seed — so
/// all four share `content` yet none is the plain digest of it.
async fn seed_skip_prefix_then_one_eligible(pool: &PgPool, agent: Uuid) -> Uuid {
    let namespaced = |seed: &str| -> Vec<u8> {
        let mut material = Vec::new();
        material.extend_from_slice(ContentHasher::hash(SHARED_SPINE_TEXT.as_bytes()).as_slice());
        material.extend_from_slice(seed.as_bytes());
        blake3::hash(&material).as_bytes().to_vec()
    };

    let insert = |id: Uuid, content: &'static str, hash: Vec<u8>| async move {
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, truth_value, agent_id) \
             VALUES ($1, $2, $3, 0.5, $4)",
        )
        .bind(id)
        .bind(content)
        .bind(hash)
        .bind(agent)
        .execute(pool)
        .await
        .expect("seed claim");
    };

    for n in 1..=4u8 {
        let id = Uuid::parse_str(&format!("00000000-0000-4000-8000-00000000000{n}")).unwrap();
        insert(id, SHARED_SPINE_TEXT, namespaced(&format!("paper-{n}"))).await;
    }

    let eligible = Uuid::parse_str("ffffffff-0000-4000-8000-00000000000e").unwrap();
    insert(
        eligible,
        ELIGIBLE_TEXT,
        ContentHasher::hash(ELIGIBLE_TEXT.as_bytes()).to_vec(),
    )
    .await;

    // Fixture assertion: the eligible row must actually be eligible, and the
    // four skips must actually be ineligible, or every assertion below is
    // vacuous.
    let null_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE canonical_hash IS NULL")
            .fetch_one(pool)
            .await
            .expect("count nulls");
    assert_eq!(null_rows, 5, "fixture: all five rows start NULL");

    eligible
}

async fn canonical_hash_of(pool: &PgPool, id: Uuid) -> Option<Vec<u8>> {
    sqlx::query_scalar("SELECT canonical_hash FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read canonical_hash")
}

/// A budgeted drain that threads its cursor forward reaches the eligible row.
#[sqlx::test(migrations = "../../migrations")]
async fn windowed_drain_reaches_rows_past_the_skip_prefix(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let eligible = seed_skip_prefix_then_one_eligible(&pool, agent).await;

    // Window 1: the budget is spent entirely on the four ineligible rows.
    let first = drain(&pool, 2, 2, None).await.expect("window 1");
    assert_eq!(first.backfilled, 0, "window 1 reads only ineligible rows");
    assert_eq!(first.skipped_foreign_digest, 4);
    assert_eq!(first.chunks, 2);
    assert!(
        !first.is_complete(),
        "the budget cut the scan short, so a resume point must be reported"
    );
    let resume = first
        .resume_after
        .expect("budgeted pass must expose a cursor");

    // Window 2 resumes STRICTLY AFTER the skip prefix and finds the row.
    let second = drain(&pool, 2, 2, Some(resume)).await.expect("window 2");
    assert_eq!(
        second.backfilled, 1,
        "resuming past the skip prefix must reach the eligible row"
    );
    assert_eq!(second.skipped_foreign_digest, 0);
    assert!(
        second.is_complete(),
        "the second window reaches end of scan"
    );
    assert_eq!(
        second.resume_after, None,
        "a completed pass reports no resume point"
    );

    assert_eq!(
        canonical_hash_of(&pool, eligible).await,
        Some(ContentHasher::hash_canonical_text(ELIGIBLE_TEXT).to_vec()),
        "the backfilled digest must be the one the write path computes"
    );

    // The four namespaced rows are still NULL — resumability must not have
    // been bought by relaxing the eligibility guard.
    let still_null: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE canonical_hash IS NULL")
            .fetch_one(&pool)
            .await
            .expect("count nulls");
    assert_eq!(
        still_null, 4,
        "namespaced rows stay NULL; only the eligible row was filled"
    );
}

/// The defect itself, held in place: discarding the cursor stalls forever.
///
/// This is the pre-fix binary's behaviour — it started every invocation at
/// `None` and exposed no `--after`. Five successive windows write nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn windowed_drain_stalls_when_the_cursor_is_discarded(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let eligible = seed_skip_prefix_then_one_eligible(&pool, agent).await;

    for window in 1..=5 {
        let pass = drain(&pool, 2, 2, None).await.expect("window");
        assert_eq!(
            (pass.backfilled, pass.skipped_foreign_digest, pass.chunks),
            (0, 4, 2),
            "window {window}: restarting from None re-reads the same skip \
             prefix, so the budget never reaches the eligible row"
        );
    }

    assert_eq!(
        canonical_hash_of(&pool, eligible).await,
        None,
        "no amount of cursor-less repetition fills the eligible row — this is \
         why drain() takes an `after` and the binary exposes --after"
    );
}

/// An UNBUDGETED run needs no cursor: it always runs to end of scan, so the
/// stateless restart the module docs promise for `--max-chunks 0` holds.
#[sqlx::test(migrations = "../../migrations")]
async fn unbudgeted_drain_completes_in_one_pass_from_none(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let eligible = seed_skip_prefix_then_one_eligible(&pool, agent).await;

    let pass = drain(&pool, 2, 0, None).await.expect("full drain");
    assert_eq!(pass.backfilled, 1);
    assert_eq!(pass.skipped_foreign_digest, 4);
    assert!(pass.is_complete(), "an unbudgeted run reaches end of scan");
    assert!(
        canonical_hash_of(&pool, eligible).await.is_some(),
        "the eligible row is filled without any cursor being threaded"
    );

    // Re-running a completed backfill writes nothing.
    let again = drain(&pool, 2, 0, None).await.expect("second full drain");
    assert_eq!(again.backfilled, 0, "a completed run is a no-op");
    assert_eq!(
        again.skipped_foreign_digest, 4,
        "it still re-reads the skips"
    );
}
