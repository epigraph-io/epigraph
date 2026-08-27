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

/// KNOWN-FAILING, AND DELIBERATELY NOT FIXED HERE — a SEPARATE defect that
/// happens to be provable with this fixture. `#[ignore]`d so it does not fail
/// the suite; run it with `--ignored` to watch it fail.
///
/// It began life refuting the round-1 blocker "verify_claim asserts computed ==
/// stored, so changing the hash input flips every existing claim to
/// hash_matches=false". That blocker is false, and this is why: MCP
/// `verify_claim` compares `ContentHasher::hash(claim.content)` against
/// `claim.content_hash`, but `ClaimRepository::get_by_id` never SELECTs
/// `content_hash` — its `SELECT` lists id, content, truth_value, agent_id,
/// trace_id, created_at, updated_at, is_current, supersedes — and
/// `claim_from_row` then fills `Claim.content_hash` by RECOMPUTING
/// `ContentHasher::hash(content)`. The comparison is a value against itself.
/// The persisted digest is never read, so the check is a tautology that can
/// never observe a divergence, and a hash-input change cannot break it.
///
/// That tautology is its own bug with its own blast radius: fixing it means
/// `get_by_id` selecting the stored digest, which would start reporting
/// `hash_matches = false` for every row written through the
/// `POST /api/v1/claims` client-supplied `content_hash` override. It needs its
/// own change, its own review, and its own commit. (`signature_valid` is
/// likewise unconditionally false, since `claim_from_row` hardcodes
/// `public_key = [0u8; 32]` and `signature = None`.)
///
/// The test persists a row whose stored `content_hash` is deliberately wrong
/// and asserts the check catches it.
#[ignore = "separate defect: verify_claim's hash check is a tautology because \
            claim_from_row recomputes the digest instead of get_by_id \
            selecting it — needs its own commit"]
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
    let n = ClaimRepository::backfill_canonical_hash_chunk(&pool, 1000)
        .await
        .expect("backfill chunk");
    assert_eq!(n, 1, "the one legacy row must be backfilled");
    assert_eq!(
        ClaimRepository::count_missing_canonical_hash(&pool)
            .await
            .expect("re-count"),
        0
    );
    assert_eq!(
        ClaimRepository::backfill_canonical_hash_chunk(&pool, 1000)
            .await
            .expect("second backfill chunk"),
        0,
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
