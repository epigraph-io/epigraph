//! REGRESSION SUITE for backlog e09986c2 — canonicalized dedup lookup.
//!
//! # The defect these tests pin
//!
//! `content_hash` is BLAKE3 over the raw UTF-8 bytes of `claims.content`, with
//! no canonicalization of the hash INPUT. Consequence: two submissions that are
//! the *same text* to any human reader — differing only in Unicode
//! normalization form, invisible zero-width characters, or whitespace runs —
//! hash differently, miss the `(content_hash, agent_id)` dedup lookup, and land
//! as two separate rows for the same agent.
//!
//! `create_or_get` is the canonical find-or-insert entry point
//! (`crates/epigraph-db/src/repos/claim.rs`), reached from MCP `submit_claim`
//! and `POST /api/v1/claims` / `POST /api/v1/submit/packet`.
//!
//! # The fix these tests pin
//!
//! ADDITIVE. `claims.content_hash` keeps its value byte-for-byte — it still
//! carries `uq_claims_content_hash_agent`, still backs the client-supplied hash
//! override, and is still what MCP signs. Migration 061 adds a SECOND column,
//! `claims.canonical_hash`, holding BLAKE3 over the canonicalized text, and
//! `create_or_get` consults it as a FALLBACK after the exact lookup misses.
//!
//! `submitted_text_is_stored_verbatim` is the load-bearing test of the whole
//! design: canonicalization applies to the hash INPUT only, never to what the
//! graph stores.

use epigraph_core::{AgentId, Claim, ClaimId, TruthValue};
use epigraph_crypto::ContentHasher;
use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

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

fn make_claim(content: &str, agent_id: Uuid) -> Claim {
    Claim::new(
        content.to_string(),
        AgentId::from_uuid(agent_id),
        [0u8; 32],
        TruthValue::new(0.5).unwrap(),
    )
}

/// Submit `first`, then `second`, from the same agent, through the canonical
/// find-or-insert path. Returns `(second_was_created, first_id, second_id,
/// rows_for_agent)`.
async fn submit_pair(
    pool: &PgPool,
    agent: Uuid,
    first: &str,
    second: &str,
) -> (bool, Uuid, Uuid, i64) {
    let mut conn = pool.acquire().await.expect("acquire");

    let (stored_a, created_a) =
        ClaimRepository::create_or_get(&mut conn, &make_claim(first, agent))
            .await
            .expect("create_or_get first");
    assert!(created_a, "fixture: first submission must insert");

    let (stored_b, created_b) =
        ClaimRepository::create_or_get(&mut conn, &make_claim(second, agent))
            .await
            .expect("create_or_get second");

    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE agent_id = $1")
        .bind(agent)
        .fetch_one(pool)
        .await
        .expect("count");

    (created_b, stored_a.id.into(), stored_b.id.into(), rows)
}

/// CONTROL. Byte-identical resubmission dedups through stage 1 (the exact
/// `content_hash` lookup), before canonicalization is consulted at all. If this
/// ever fails, the fixture is broken and the tests below prove nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn byte_identical_content_dedups(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let text = "Mitochondrial density predicts endurance capacity.";

    let (created_second, id_a, id_b, rows) = submit_pair(&pool, agent, text, text).await;

    assert!(!created_second, "byte-identical resubmit must not insert");
    assert_eq!(id_a, id_b);
    assert_eq!(rows, 1);
}

/// NFC vs NFD. "café" written with U+00E9 versus "cafe" + U+0301. Identical
/// on every screen; different bytes; different BLAKE3.
#[sqlx::test(migrations = "../../migrations")]
async fn nfd_variant_of_existing_nfc_claim_dedups(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let nfc = "The caf\u{00e9} protocol raises yield.";
    let nfd = "The cafe\u{0301} protocol raises yield.";
    assert_ne!(nfc, nfd, "fixture: the two forms must be byte-distinct");

    let (created_second, id_a, id_b, rows) = submit_pair(&pool, agent, nfc, nfd).await;

    assert!(
        !created_second,
        "NFD variant of an already-stored NFC claim must dedup to it, \
         but create_or_get inserted a second row"
    );
    assert_eq!(id_a, id_b, "both forms must resolve to one claim id");
    assert_eq!(rows, 1, "agent must own exactly one row for this text");
}

/// Invisible characters. A zero-width space (U+200B) pasted mid-word from a
/// word processor or a web page survives into `content` and forks the hash.
#[sqlx::test(migrations = "../../migrations")]
async fn zero_width_variant_of_existing_claim_dedups(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let plain = "Ribosome profiling resolves translation rates.";
    let zw = "Ribosome\u{200b} profiling resolves translation\u{feff} rates.";
    assert_ne!(plain, zw, "fixture: the two forms must be byte-distinct");

    let (created_second, id_a, id_b, rows) = submit_pair(&pool, agent, plain, zw).await;

    assert!(
        !created_second,
        "zero-width-padded variant of an already-stored claim must dedup to it, \
         but create_or_get inserted a second row"
    );
    assert_eq!(id_a, id_b, "both forms must resolve to one claim id");
    assert_eq!(rows, 1, "agent must own exactly one row for this text");
}

/// Whitespace. A trailing newline and a double space between words — the
/// classic difference between a claim typed by hand and the same claim
/// round-tripped through a template.
#[sqlx::test(migrations = "../../migrations")]
async fn whitespace_variant_of_existing_claim_dedups(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let tight = "CRISPR knockouts reduce tumour volume.";
    let loose = "CRISPR  knockouts reduce tumour volume.\n";
    assert_ne!(tight, loose, "fixture: the two forms must be byte-distinct");

    let (created_second, id_a, id_b, rows) = submit_pair(&pool, agent, tight, loose).await;

    assert!(
        !created_second,
        "whitespace-variant of an already-stored claim must dedup to it, \
         but create_or_get inserted a second row"
    );
    assert_eq!(id_a, id_b, "both forms must resolve to one claim id");
    assert_eq!(rows, 1, "agent must own exactly one row for this text");
}

/// REGRESSION GUARD for backlog 49c17386 — was `#[ignore]`d as a known-failing
/// reproduction, un-ignored 2026-08-29 when the defect it documents was fixed.
///
/// It began life refuting the round-1 blocker "verify_claim asserts computed ==
/// stored, so changing the hash input flips every existing claim to
/// hash_matches=false". That blocker was false, and the reason was worse than
/// the blocker: `ClaimRepository::get_by_id` never SELECTed `content_hash`, and
/// `claim_from_row` filled `Claim.content_hash` by RECOMPUTING
/// `ContentHasher::hash(content)`. The comparison was a value against itself —
/// a tautology that could never observe a divergence.
///
/// `get_by_id` now post-fixes the persisted digest, so this test passes. Keep
/// it: if anyone reverts that post-fix, or reintroduces a derivation of
/// content_hash from content on a read path, this fails and says why.
///
/// The blast radius the original note worried about is handled, not avoided:
/// rows written through `POST /api/v1/claims` with a client-supplied
/// `content_hash` override no longer silently report a match, but they land in
/// `verify_claim`'s `FOREIGN_DIGEST` tier rather than `DIVERGENT`, because they
/// carry no `canonical_hash` for the kernel to adjudicate against. Only
/// `DIVERGENT` asserts a problem.
///
/// The test persists a row whose stored `content_hash` is deliberately wrong
/// and asserts the check catches it.
#[sqlx::test(migrations = "../../migrations")]
async fn verify_claim_hash_check_reads_the_persisted_digest(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let id = Uuid::new_v4();
    let bogus_digest = vec![0xABu8; 32];

    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id) \
         VALUES ($1, $2, $3, 0.5, $4)",
    )
    .bind(id)
    .bind("a claim whose persisted digest does not match its text")
    .bind(&bogus_digest)
    .bind(agent)
    .execute(&pool)
    .await
    .expect("insert tampered row");

    let claim = ClaimRepository::get_by_id(&pool, ClaimId::from_uuid(id))
        .await
        .expect("get_by_id")
        .expect("row exists");

    // Verbatim the check in epigraph-mcp/src/tools/claims.rs::verify_claim.
    let computed_hash = ContentHasher::hash(claim.content.as_bytes());
    let hash_matches = computed_hash == claim.content_hash;

    assert!(
        !hash_matches,
        "verify_claim must report hash_matches=false when the PERSISTED \
         content_hash disagrees with the stored content; instead \
         claim_from_row recomputed the digest from `content`, so the check \
         compared a value against itself and reported a match"
    );
}

/// THE LOAD-BEARING INVARIANT of the whole design: canonicalization applies to
/// the hash INPUT, never to the stored text. An agent that writes a claim with
/// a deliberate double space, a trailing newline, or an NFD accent must read
/// back exactly those bytes — the graph is a record of what was said, and
/// silently rewriting it would corrupt provenance. Only the dedup KEY is
/// canonical.
#[sqlx::test(migrations = "../../migrations")]
async fn submitted_text_is_stored_verbatim(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let messy = "  Ribosome\u{200b}  profiling\tresolves cafe\u{0301} rates.\n";
    let mut conn = pool.acquire().await.expect("acquire");

    let (stored, created) = ClaimRepository::create_or_get(&mut conn, &make_claim(messy, agent))
        .await
        .expect("create_or_get");
    assert!(created, "fixture: first submission must insert");
    assert_eq!(
        stored.content, messy,
        "create_or_get must return the submitted bytes, not a canonical form"
    );

    let from_db: String = sqlx::query_scalar("SELECT content FROM claims WHERE id = $1")
        .bind(Uuid::from(stored.id))
        .fetch_one(&pool)
        .await
        .expect("read content back");
    assert_eq!(
        from_db, messy,
        "the persisted `content` column must hold the submitted bytes verbatim"
    );
}

/// The ADDITIVE invariant, asserted against the columns themselves:
/// `content_hash` is still raw BLAKE3 over the submitted bytes (so the 013
/// UNIQUE constraint, the MCP signature, and the revocation audit trail all
/// keep meaning exactly what they meant), while `canonical_hash` carries the
/// canonicalized digest alongside it.
#[sqlx::test(migrations = "../../migrations")]
async fn content_hash_stays_raw_while_canonical_hash_is_added(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let messy = "CRISPR  knockouts reduce tumour volume.\n";
    let mut conn = pool.acquire().await.expect("acquire");

    let (stored, _) = ClaimRepository::create_or_get(&mut conn, &make_claim(messy, agent))
        .await
        .expect("create_or_get");

    let (raw, canon): (Vec<u8>, Option<Vec<u8>>) =
        sqlx::query_as("SELECT content_hash, canonical_hash FROM claims WHERE id = $1")
            .bind(Uuid::from(stored.id))
            .fetch_one(&pool)
            .await
            .expect("read digests back");

    assert_eq!(
        raw,
        ContentHasher::hash(messy.as_bytes()).to_vec(),
        "content_hash must remain BLAKE3 over the SUBMITTED bytes"
    );
    assert_eq!(
        canon,
        Some(ContentHasher::hash_canonical_text(messy).to_vec()),
        "canonical_hash must be BLAKE3 over the CANONICALIZED text"
    );
    assert_ne!(
        Some(raw),
        canon,
        "fixture: for this non-canonical input the two digests must differ, \
         else the test cannot tell them apart"
    );
}

/// The legacy path, end to end. A row written before migration 061 has
/// `canonical_hash IS NULL`, so stage 2 of the lookup cannot see it and a
/// cosmetic variant still forks — which is EXACTLY the behaviour before this
/// change, never worse. Running `backfill_canonical_hash_chunk` fills the
/// column, and the same variant then dedups.
///
/// This is what makes the backfill claim testable rather than asserted.
#[sqlx::test(migrations = "../../migrations")]
async fn legacy_null_row_dedups_only_after_the_backfill(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let original = "Telomere length correlates with replicative capacity.";
    let variant = "Telomere  length correlates with replicative\u{200b} capacity.\n";

    // A pre-061 row: real content_hash, no canonical_hash.
    let legacy_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id) \
         VALUES ($1, $2, $3, 0.5, $4)",
    )
    .bind(legacy_id)
    .bind(original)
    .bind(ContentHasher::hash(original.as_bytes()).as_slice())
    .bind(agent)
    .execute(&pool)
    .await
    .expect("insert legacy row");

    assert_eq!(
        ClaimRepository::count_missing_canonical_hash(&pool)
            .await
            .expect("count"),
        1,
        "fixture: exactly the legacy row must be missing canonical_hash"
    );

    // Pre-backfill: the variant cannot find it. Not a regression — this is
    // precisely today's behaviour, which the fix promises never to worsen.
    let mut conn = pool.acquire().await.expect("acquire");
    let (_, created_pre) = ClaimRepository::create_or_get(&mut conn, &make_claim(variant, agent))
        .await
        .expect("create_or_get pre-backfill");
    assert!(
        created_pre,
        "fixture: an unbackfilled legacy row is invisible to the canonical lookup"
    );

    // Backfill, then assert it is complete and idempotent.
    let chunk = ClaimRepository::backfill_canonical_hash_chunk(&pool, 1000, None)
        .await
        .expect("backfill chunk");
    assert_eq!(chunk.updated, 1, "the one legacy row must be backfilled");
    assert_eq!(
        chunk.skipped_foreign_digest, 0,
        "the legacy row carries a PLAIN content_hash, so nothing is skipped"
    );
    assert_eq!(
        ClaimRepository::count_missing_canonical_hash(&pool)
            .await
            .expect("re-count"),
        0
    );
    assert_eq!(
        ClaimRepository::backfill_canonical_hash_chunk(&pool, 1000, None)
            .await
            .expect("second backfill chunk"),
        epigraph_db::CanonicalBackfillChunk::END,
        "a completed backfill must be a no-op on re-run"
    );

    // Post-backfill: a fresh cosmetic variant of the legacy text finds it.
    let variant2 = "Telomere length\u{feff} correlates  with replicative capacity. ";
    let (found, created_post) =
        ClaimRepository::create_or_get(&mut conn, &make_claim(variant2, agent))
            .await
            .expect("create_or_get post-backfill");
    assert!(
        !created_post,
        "after the backfill a cosmetic variant must dedup to the legacy row"
    );
    assert_eq!(
        Uuid::from(found.id),
        legacy_id,
        "and it must resolve to the LEGACY row, not to the pre-backfill fork"
    );
}

/// The over-folding guard. Canonicalization must collapse cosmetic difference
/// and nothing else: if it folded genuinely distinct text, one claim would
/// silently absorb another and the graph would lose a fact.
#[sqlx::test(migrations = "../../migrations")]
async fn genuinely_different_text_still_gets_its_own_row(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");

    for text in [
        "Yield rises under hypoxia.",
        "Yield falls under hypoxia.",
        // Word boundaries are load-bearing: collapsing a space to nothing
        // rather than to one space would merge the next two.
        "the rapist confession",
        "therapist confession",
        // Case is not folded.
        "Hypoxia",
        "hypoxia",
    ] {
        let (_, created) = ClaimRepository::create_or_get(&mut conn, &make_claim(text, agent))
            .await
            .expect("create_or_get");
        assert!(created, "{text:?} must land as its own row");
    }

    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE agent_id = $1")
        .bind(agent)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(rows, 6, "six distinct claims must remain six rows");
}

/// Cross-agent isolation survives. `(canonical_hash, agent_id)` is keyed on the
/// agent exactly as `(content_hash, agent_id)` is: two agents independently
/// asserting the same thing is two claims, not one, and the canonical fallback
/// must not quietly merge them.
#[sqlx::test(migrations = "../../migrations")]
async fn canonical_lookup_does_not_reach_across_agents(pool: PgPool) {
    let agent_a = seed_agent(&pool).await;
    let agent_b = seed_agent(&pool).await;
    let nfc = "The caf\u{00e9} protocol raises yield.";
    let nfd = "The cafe\u{0301} protocol raises yield.";
    let mut conn = pool.acquire().await.expect("acquire");

    let (a, created_a) = ClaimRepository::create_or_get(&mut conn, &make_claim(nfc, agent_a))
        .await
        .expect("agent A");
    assert!(created_a);

    let (b, created_b) = ClaimRepository::create_or_get(&mut conn, &make_claim(nfd, agent_b))
        .await
        .expect("agent B");
    assert!(
        created_b,
        "agent B's claim must be its own row even though it canonicalizes to \
         the same text as agent A's"
    );
    assert_ne!(a.id, b.id);
    assert_eq!(Uuid::from(b.agent_id), agent_b);
}

/// Stage ordering. When BOTH a byte-identical row and a cosmetic sibling of it
/// exist for one agent — the pre-fix era's legacy state — an exact resubmit
/// must resolve to the byte-identical row. That is what exact-first buys, and
/// a canonical-only lookup would return whichever row sorted first.
#[sqlx::test(migrations = "../../migrations")]
async fn exact_match_wins_over_a_cosmetic_sibling(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let sibling = "Ribosome  profiling resolves rates.\n"; // canonicalizes to `exact`
    let exact = "Ribosome profiling resolves rates.";

    // The cosmetic sibling was written FIRST, so it sorts first by created_at
    // and a canonical-only lookup would return it.
    for (id, text) in [(Uuid::new_v4(), sibling), (Uuid::new_v4(), exact)] {
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, canonical_hash, truth_value, agent_id) \
             VALUES ($1, $2, $3, $4, 0.5, $5)",
        )
        .bind(id)
        .bind(text)
        .bind(ContentHasher::hash(text.as_bytes()).as_slice())
        .bind(ContentHasher::hash_canonical_text(text).as_slice())
        .bind(agent)
        .execute(&pool)
        .await
        .expect("seed row");
    }

    let mut conn = pool.acquire().await.expect("acquire");
    let (found, created) = ClaimRepository::create_or_get(&mut conn, &make_claim(exact, agent))
        .await
        .expect("create_or_get");

    assert!(!created, "an exact resubmit must never insert");
    assert_eq!(
        found.content, exact,
        "the exact lookup must win over the cosmetic sibling that was stored first"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// SCOPE GUARDS on the stage-2 lookup.
//
// Stage 2 widened what `create_or_get` can resolve a submission onto. Two rows
// it must NOT reach, each pinned below:
//
//   1. a TOMBSTONE (`is_current = false`). Stage 1 has always been able to
//      return one — that is pre-existing, and `submit.rs`'s dead-node guard
//      turns it into a deliberate 409. Stage 2 reaching one is NOT pre-existing:
//      a cosmetic variant of a superseded claim used to miss the lookup
//      entirely and land a fresh LIVE row (201 Created). Letting stage 2 find
//      the tombstone converts that 201 into a 409 — a user-visible regression.
//
//   2. a DOCUMENT-SCOPED (compound) row, whose `content_hash` is namespaced by
//      its host artifact (`epigraph_ingest::common::ids::compound_content_hash`)
//      precisely so paper A's "Introduction" and paper B's "Introduction" stay
//      distinguishable. A `canonical_hash` over the text ALONE would re-open
//      that collision in the lookup dimension and let a plain claim submission
//      resolve onto a spine node.
// ─────────────────────────────────────────────────────────────────────────────

/// REGRESSION (defect 1). A cosmetic variant of a SUPERSEDED claim must still
/// start a fresh live row.
///
/// Before stage 2 existed, the variant's `content_hash` differed from the
/// tombstone's, so the lookup missed and `create_or_get` inserted — the
/// submitter got a new live claim. A stage 2 with no `is_current` predicate
/// resolves the variant onto the tombstone instead, and every caller that
/// guards against dead nodes (`routes/submit.rs`) then rejects the submission
/// with 409 `DuplicateNotCurrent`. Dedup must never resurrect a tombstone.
#[sqlx::test(migrations = "../../migrations")]
async fn cosmetic_variant_of_a_superseded_claim_starts_a_fresh_live_row(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let original = "Mitochondrial density predicts endurance.";
    // Same text to a reader: collapsed whitespace run + a zero-width space.
    let variant = "Mitochondrial  density predicts\u{200b} endurance.";

    let mut conn = pool.acquire().await.expect("acquire");
    let (stored, created) = ClaimRepository::create_or_get(&mut conn, &make_claim(original, agent))
        .await
        .expect("create_or_get original");
    assert!(created, "fixture: the original must insert");

    // Retire it. Different content, so the ORIGINAL row keeps its digests and
    // merely flips to `is_current = false` — a tombstone.
    ClaimRepository::supersede(
        &pool,
        stored.id,
        "Mitochondrial density predicts endurance only in trained subjects.",
        TruthValue::new(0.6).unwrap(),
        "test: retire the original to create a tombstone",
    )
    .await
    .expect("supersede");

    let tombstoned: bool = sqlx::query_scalar("SELECT is_current FROM claims WHERE id = $1")
        .bind(Uuid::from(stored.id))
        .fetch_one(&pool)
        .await
        .expect("read is_current");
    assert!(!tombstoned, "fixture: the original must now be a tombstone");

    let (found, created_variant) =
        ClaimRepository::create_or_get(&mut conn, &make_claim(variant, agent))
            .await
            .expect("create_or_get variant");

    assert!(
        created_variant,
        "a cosmetic variant of a SUPERSEDED claim must insert a fresh live row, \
         exactly as it did before the canonical lookup existed — instead it \
         resolved onto claim {}",
        Uuid::from(found.id)
    );
    assert_ne!(
        found.id, stored.id,
        "the variant must never be handed back the tombstone's id"
    );
    let live: bool = sqlx::query_scalar("SELECT is_current FROM claims WHERE id = $1")
        .bind(Uuid::from(found.id))
        .fetch_one(&pool)
        .await
        .expect("read is_current of the new row");
    assert!(live, "the freshly created row must be live");
}

/// The other half of defect 1: excluding tombstones must not cost a LIVE hit.
/// With a tombstone and a live row sharing one canonical digest — the state a
/// supersede-then-resubmit leaves behind — a third cosmetic variant must
/// resolve onto the LIVE row, not fork and not resurrect the dead one.
///
/// The tombstone is seeded FIRST so it sorts first under the lookup's
/// `ORDER BY created_at, id`: a predicate-free stage 2 would return it.
#[sqlx::test(migrations = "../../migrations")]
async fn canonical_lookup_prefers_the_live_row_over_a_tombstone_sibling(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let dead = "Chaperone  binding stabilises the fold.\n"; // canonicalizes to `live`
    let live = "Chaperone binding stabilises the fold.";
    let third = "Chaperone binding stabilises\u{feff} the  fold."; // same canonical form

    let dead_id = Uuid::new_v4();
    let live_id = Uuid::new_v4();
    for (id, text, is_current) in [(dead_id, dead, false), (live_id, live, true)] {
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, canonical_hash, truth_value, \
                                 agent_id, is_current) \
             VALUES ($1, $2, $3, $4, 0.5, $5, $6)",
        )
        .bind(id)
        .bind(text)
        .bind(ContentHasher::hash(text.as_bytes()).as_slice())
        .bind(ContentHasher::hash_canonical_text(text).as_slice())
        .bind(agent)
        .bind(is_current)
        .execute(&pool)
        .await
        .expect("seed row");
    }

    let mut conn = pool.acquire().await.expect("acquire");
    let (found, created) = ClaimRepository::create_or_get(&mut conn, &make_claim(third, agent))
        .await
        .expect("create_or_get third variant");

    assert!(
        !created,
        "a cosmetic variant of a LIVE row must still dedup onto it"
    );
    assert_eq!(
        Uuid::from(found.id),
        live_id,
        "stage 2 must resolve onto the LIVE sibling, not the tombstone that \
         sorts ahead of it"
    );
}

/// REGRESSION (defect 2). A row whose `content_hash` is NAMESPACED must not
/// advertise a `canonical_hash` over its text alone.
///
/// `epigraph_ingest::common::ids::compound_content_hash` derives a structural
/// node's digest over `(plain text hash ‖ artifact seed)` so that paper A's
/// "Introduction" and paper B's "Introduction" stay distinct rows. Deriving
/// `canonical_hash` from the text alone hands both of them the SAME lookup key
/// and makes either reachable by a plain `create_or_get("Introduction")`.
///
/// `create_with_id_if_absent` cannot know the namespace — the caller folded it
/// into `content_hash` before calling — so the only safe rule is: derive
/// `canonical_hash` only when `content_hash` IS the plain digest of `content`.
#[sqlx::test(migrations = "../../migrations")]
async fn namespaced_content_hash_row_gets_no_canonical_hash(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let shared_text = "Introduction";

    // Mirrors `compound_content_hash`: blake3(plain_hash ‖ artifact_seed).
    // Reconstructed here rather than imported because `epigraph-db` sits below
    // `epigraph-ingest`; `spine_node_identity_test.rs` pins the real function.
    let namespaced = |seed: &str| -> [u8; 32] {
        let mut material = Vec::new();
        material.extend_from_slice(ContentHasher::hash(shared_text.as_bytes()).as_slice());
        material.extend_from_slice(seed.as_bytes());
        *blake3::hash(&material).as_bytes()
    };

    let paper_a = Uuid::new_v4();
    let paper_b = Uuid::new_v4();
    for (id, seed) in [(paper_a, "paper-a"), (paper_b, "paper-b")] {
        assert!(
            ClaimRepository::create_with_id_if_absent(
                &pool,
                id,
                shared_text,
                &namespaced(seed),
                agent,
                TruthValue::new(0.5).unwrap(),
                &[],
            )
            .await
            .expect("insert spine node"),
            "fixture: each spine node must insert"
        );
    }

    let distinct_content_hashes: i64 =
        sqlx::query_scalar("SELECT COUNT(DISTINCT content_hash) FROM claims WHERE id = ANY($1)")
            .bind(vec![paper_a, paper_b])
            .fetch_one(&pool)
            .await
            .expect("count distinct content_hash");
    assert_eq!(
        distinct_content_hashes, 2,
        "fixture: the two spine nodes must carry DISTINCT namespaced content_hash"
    );

    let with_canonical: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM claims WHERE id = ANY($1) AND canonical_hash IS NOT NULL",
    )
    .bind(vec![paper_a, paper_b])
    .fetch_one(&pool)
    .await
    .expect("count canonical_hash");
    assert_eq!(
        with_canonical, 0,
        "a namespaced (document-scoped) row must leave canonical_hash NULL — \
         a text-only digest would collapse both papers onto one lookup key"
    );

    // The consequence that matters: a plain claim submission must not be
    // resolved onto a document's structural node.
    let mut conn = pool.acquire().await.expect("acquire");
    let (found, created) =
        ClaimRepository::create_or_get(&mut conn, &make_claim(shared_text, agent))
            .await
            .expect("create_or_get plain claim");
    assert!(
        created,
        "a plain claim must never be resolved onto a document-scoped spine \
         node — it resolved onto {}",
        Uuid::from(found.id)
    );
    assert_ne!(Uuid::from(found.id), paper_a);
    assert_ne!(Uuid::from(found.id), paper_b);
}

/// The complement of the guard above: an ATOM — whose `content_hash` IS the
/// plain digest of its text, because global convergence across documents is
/// exactly its point — must still get a `canonical_hash`. The scope guard
/// narrows the namespaced case only; it must not switch the feature off for
/// every `create_with_id_if_absent` caller.
#[sqlx::test(migrations = "../../migrations")]
async fn plain_content_hash_row_still_gets_its_canonical_hash(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let text = "Kinesin  steps along the microtubule.\n";
    let id = Uuid::new_v4();

    assert!(
        ClaimRepository::create_with_id_if_absent(
            &pool,
            id,
            text,
            &ContentHasher::hash(text.as_bytes()),
            agent,
            TruthValue::new(0.5).unwrap(),
            &[],
        )
        .await
        .expect("insert atom"),
        "fixture: the atom must insert"
    );

    let canon: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT canonical_hash FROM claims WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("read canonical_hash");
    assert_eq!(
        canon,
        Some(ContentHasher::hash_canonical_text(text).to_vec()),
        "a row whose content_hash is the PLAIN digest must still carry the \
         canonical twin — this is the atom/global-convergence case"
    );
}

/// REGRESSION. The BACKFILL must honour the same scope rule as the write path.
///
/// `backfill_canonical_hash_chunk` fills every row where `canonical_hash IS
/// NULL`. Left unqualified, one run would UNDO the guard above on every row
/// the write path ever protected — re-fusing two documents' "Introduction",
/// and giving every `fully_private` claim of one agent the digest of the
/// literal placeholder `"[private]"` they all store as `content`.
///
/// This also pins the paging hazard that eligibility introduces: `WHERE
/// canonical_hash IS NULL` stops being self-consuming once rows are skipped,
/// so a chunk that writes NOTHING must still advance and must not be read as
/// end-of-scan. The eligible row here sorts AFTER both skipped rows under
/// `ORDER BY id`, and `chunk_size = 1` forces each into its own chunk, so a
/// run that terminated on "wrote nothing" would stop before ever reaching it.
#[sqlx::test(migrations = "../../migrations")]
async fn backfill_skips_foreign_digests_without_truncating_the_scan(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let shared_text = "Introduction";
    let eligible_text = "Legacy row whose digest is the plain one.";

    // Two namespaced rows (ids forced low) and one eligible legacy row (id
    // forced high) so `ORDER BY id` puts the skips first.
    let skip_a = Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap();
    let skip_b = Uuid::parse_str("00000000-0000-4000-8000-000000000002").unwrap();
    let eligible = Uuid::parse_str("ffffffff-0000-4000-8000-000000000003").unwrap();

    let namespaced = |seed: &str| -> Vec<u8> {
        let mut material = Vec::new();
        material.extend_from_slice(ContentHasher::hash(shared_text.as_bytes()).as_slice());
        material.extend_from_slice(seed.as_bytes());
        blake3::hash(&material).as_bytes().to_vec()
    };

    for (id, text, hash) in [
        (skip_a, shared_text, namespaced("paper-a")),
        (skip_b, shared_text, namespaced("paper-b")),
        (
            eligible,
            eligible_text,
            ContentHasher::hash(eligible_text.as_bytes()).to_vec(),
        ),
    ] {
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, truth_value, agent_id) \
             VALUES ($1, $2, $3, 0.5, $4)",
        )
        .bind(id)
        .bind(text)
        .bind(hash)
        .bind(agent)
        .execute(&pool)
        .await
        .expect("seed row");
    }

    // Drive the loop the CLI drives: one row per chunk, terminating ONLY on
    // end-of-scan (`next_after == None`), never on "this chunk wrote nothing".
    let mut after: Option<Uuid> = None;
    let (mut updated, mut skipped, mut chunks) = (0_u64, 0_u64, 0_u32);
    loop {
        let chunk = ClaimRepository::backfill_canonical_hash_chunk(&pool, 1, after)
            .await
            .expect("backfill chunk");
        let Some(next) = chunk.next_after else { break };
        after = Some(next);
        updated += chunk.updated;
        skipped += chunk.skipped_foreign_digest;
        chunks += 1;
        assert!(
            chunks < 10,
            "cursor failed to advance — the scan is looping"
        );
    }

    assert_eq!(chunks, 3, "every row must be scanned, skips included");
    assert_eq!(
        updated, 1,
        "exactly the one plain-digest row may be backfilled"
    );
    assert_eq!(skipped, 2, "both namespaced rows must be skipped");

    let still_null: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM claims WHERE canonical_hash IS NULL ORDER BY id")
            .fetch_all(&pool)
            .await
            .expect("read remaining NULLs");
    assert_eq!(
        still_null,
        vec![skip_a, skip_b],
        "the namespaced rows must remain NULL after a COMPLETE backfill pass"
    );

    // And the guard still holds end-to-end: a plain submission of the spine
    // text must not be resolved onto either document's node.
    let mut conn = pool.acquire().await.expect("acquire");
    let (found, created) =
        ClaimRepository::create_or_get(&mut conn, &make_claim(shared_text, agent))
            .await
            .expect("create_or_get after backfill");
    assert!(
        created,
        "after a full backfill a plain claim must still not resolve onto a \
         document-scoped node — it resolved onto {}",
        Uuid::from(found.id)
    );
}
