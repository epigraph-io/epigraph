//! PR-21: does `seal` actually seal, and does it leave a shadow?
//!
//! # Why this file is corpus-wide and not column-by-column
//!
//! FINAL-PLAN §6.5.4 records a previous revision of seal-commit that wrote a
//! ciphertext row, replaced `claims.content` with a sentinel, nulled
//! `claims.embedding` — and stopped. It passed its own audit, because the audit
//! was written over `claims` alone. What it left behind is the reason this file
//! exists, and the shape of the test is the lesson: **one assertion is taken
//! against a dump of the WHOLE database rather than against a list of columns
//! somebody remembered to name.** A per-column suite can only ever be as
//! complete as the list its author was working from, and the failure being
//! guarded against is precisely an incomplete list.
//!
//! The per-column assertions are still here, because a dump grep says *nothing
//! survived* and not *the right thing happened*, and because they name the
//! side channels — length, token count, ciphertext modulus — that survive a
//! dump grep by construction.
//!
//! # The dump assertion carries a positive control, and that is not optional
//!
//! `pg_dump … | grep -c <nonce>` returning `0` is also what you get from a
//! `pg_dump` that failed, from a dump of the wrong database, and from a grep
//! whose pattern never matched anything. So the test seeds TWO nonces, seals
//! one claim and leaves the other alone, and asserts against the SAME dump that
//! the sealed nonce is absent and the unsealed one is present. It also asserts
//! `pg_dump`'s exit status explicitly, and FAILS rather than skipping when the
//! binary is missing: a side-channel test that silently does not run is worse
//! than no test, because it reports green.
//!
//! # The client half is played with the real crates
//!
//! Sealing is client-driven and the server never holds a key, so a test of the
//! server half has to produce ciphertext the way the client does — padded by
//! `epigraph_privacy::pad`, bound to `entity_id || epoch || field_tag`. Hand
//! rolling those bytes here would assert this file's idea of the wire format
//! rather than the one `epigraph-privatize` writes.

mod viewer_fixture;

use epigraph_db::repos::privatization::{
    PrivatizationRepository, SealCommitEvidence, SealCommitItem, SealCommitVersion,
    UnsealCommitEvidence, UnsealCommitItem, UnsealCommitVersion,
};
use epigraph_privacy::{encryptor::FieldTag, pad, unpad};
use sqlx::PgPool;
use std::process::Command;
use uuid::Uuid;

/// The bucket every fixture in this file seals at. FINAL-PLAN §6.5.4's default
/// and `docs/tenancy/progress.json`'s `Q5_pad_to`.
const PAD_TO: u32 = 256;

/// The epoch key the fixture "unwraps". A real client derives it with
/// `epigraph_crypto::derive_epoch_key` from a KMS handle or a wrapped share;
/// the server never sees either, so for the server's half a fixed 32 bytes is
/// the same input.
const EPOCH_KEY: [u8; 32] = [0x5a; 32];

/// The group key epoch every fixture seals under.
const EPOCH: i32 = 0;

/// The derived-extraction tables a seal empties.
///
/// One list, used BOTH to calibrate the fixture and to assert the result, so a
/// table can never be asserted-about without also being seeded. Keeping them
/// separate is how an assertion goes vacuous: `count(*) = 0` over a table the
/// fixture never wrote is true before the seal as well as after it.
const DERIVED_TABLES: &[&str] = &[
    "triples",
    "entity_mentions",
    "experiment_entity_mentions",
    "reasoning_traces",
    "challenges",
    "experiment_triples",
];

// =========================================================================
// Fixture
// =========================================================================

/// A keyed `team` group old enough and admin'd enough to be a seal target,
/// plus its author agent.
///
/// Backdated 48 h and given three admins because migration 081's
/// `epigraph_privatization_plan_guard` requires both of a plan's target group,
/// and `kind='team'` with an active key epoch because its `mode='seal'` arm
/// requires those too. The seal MUTATION does not consult the guard — but a
/// group this test could seal into and the production surface could not would
/// make every assertion here true of a state that can never occur.
struct World {
    author: Uuid,
    group: Uuid,
}

async fn seed_world(pool: &PgPool) -> World {
    let (author, _) = viewer_fixture::seed_agent_with_group(pool, "seal-author").await;
    let (admin_b, _) = viewer_fixture::seed_agent_with_group(pool, "seal-admin-b").await;
    let (admin_c, _) = viewer_fixture::seed_agent_with_group(pool, "seal-admin-c").await;

    let group: Uuid = sqlx::query_scalar(
        "INSERT INTO groups (display_name, did_key, public_key, kind, status, \
                             created_by_agent_id, created_at) \
         VALUES ('seal target', 'did:epigraph:team:' || gen_random_uuid()::text, \
                 $2, 'team', 'active', $1, now() - interval '48 hours') \
         RETURNING id",
    )
    .bind(author)
    .bind(vec![0x11u8; 32])
    .fetch_one(pool)
    .await
    .expect("seed team group");

    for agent in [author, admin_b, admin_c] {
        sqlx::query(
            "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
             VALUES ($1, $2, ''::bytea, 0, 'admin')",
        )
        .bind(group)
        .bind(agent)
        .execute(pool)
        .await
        .expect("seed admin membership");
    }

    sqlx::query("INSERT INTO group_key_epochs (group_id, epoch, status) VALUES ($1, $2, 'active')")
        .bind(group)
        .bind(EPOCH)
        .execute(pool)
        .await
        .expect("seed active key epoch");

    World { author, group }
}

/// A `pgvector` literal: `[v,v,…]` with `dims` entries.
fn vector_literal(dims: usize, value: f32) -> String {
    let mut s = String::with_capacity(dims * 4 + 2);
    s.push('[');
    for i in 0..dims {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&value.to_string());
    }
    s.push(']');
    s
}

/// A `visibility='group'` claim owned by the seal target, with one
/// `claim_versions` row, one `evidence` row, and one row in each derived
/// extraction table the seal DELETEs.
///
/// Group-visible rather than public because migration 081's
/// `claim_encryption_no_public_sealed` refuses to seal a claim that is still
/// public: restrict first, then seal.
async fn seed_sealable_claim(pool: &PgPool, world: &World, content: &str) -> Uuid {
    seed_sealable_claim_as(pool, world, world.author, content).await
}

/// [`seed_sealable_claim`] with an explicit author.
///
/// Needed because `uq_claims_content_hash_agent` is unique on
/// `(content_hash, agent_id)`: two claims with IDENTICAL plaintext — the
/// fixture the `[private]` collision regression requires — cannot share an
/// author before they are sealed.
async fn seed_sealable_claim_as(pool: &PgPool, world: &World, author: Uuid, content: &str) -> Uuid {
    let claim = viewer_fixture::seed_group_claim(pool, author, world.group, content).await;

    sqlx::query(
        "INSERT INTO claim_versions (claim_id, version_number, content, truth_value, \
                                     created_by, visibility, owner_group_id) \
         VALUES ($1, 1, $2, 0.8, $3, 'group', $4)",
    )
    .bind(claim)
    .bind(content)
    .bind(author)
    .bind(world.group)
    .execute(pool)
    .await
    .expect("seed claim version");

    let evidence = viewer_fixture::seed_evidence(pool, claim, "document").await;
    sqlx::query("UPDATE evidence SET raw_content = $2, properties = $3 WHERE id = $1")
        .bind(evidence)
        .bind(content)
        .bind(serde_json::json!({ "source": content }))
        .execute(pool)
        .await
        .expect("give the evidence plaintext");

    // The trace's own `explanation` carries the CONTENT, not the fixture's
    // fixed string. `reasoning_traces.explanation` is a §6.5.4 leak surface, and
    // a trace seeded with boilerplate would satisfy the row-count assertion
    // while telling the `pg_dump` grep nothing.
    let trace = viewer_fixture::seed_reasoning_trace(pool, claim, "deductive").await;
    sqlx::query("UPDATE reasoning_traces SET explanation = $2 WHERE id = $1")
        .bind(trace)
        .bind(content)
        .execute(pool)
        .await
        .expect("give the trace the content");

    let entity: Uuid = sqlx::query_scalar(
        "INSERT INTO entities (canonical_name, type_top) VALUES ($1, 'Concept') RETURNING id",
    )
    .bind(format!("entity for {claim}"))
    .fetch_one(pool)
    .await
    .expect("seed entity");

    sqlx::query(
        "INSERT INTO triples (claim_id, subject_id, predicate, object_literal, confidence, \
                              extractor) \
         VALUES ($1, $2, 'mentions', $3, 0.9, 'test')",
    )
    .bind(claim)
    .bind(entity)
    .bind(content)
    .execute(pool)
    .await
    .expect("seed triple");

    // Both mention tables. `experiment_entity_mentions` is the one FINAL-PLAN
    // §6.5.4's DELETE list omits, and it carries the same `surface_form` the
    // list's `entity_mentions` does.
    sqlx::query(
        "INSERT INTO entity_mentions (claim_id, entity_id, surface_form, mention_role, \
                                      confidence, extractor) \
         VALUES ($1, $2, $3, 'subject', 0.9, 'test')",
    )
    .bind(claim)
    .bind(entity)
    .bind(content)
    .execute(pool)
    .await
    .expect("seed entity mention");

    let experiment_entity: Uuid = sqlx::query_scalar(
        "INSERT INTO experiment_entities (canonical_name, entity_type) \
         VALUES ($1, 'concept') RETURNING id",
    )
    .bind(format!("experiment entity for {claim}"))
    .fetch_one(pool)
    .await
    .expect("seed experiment entity");

    sqlx::query(
        "INSERT INTO experiment_entity_mentions (claim_id, entity_id, surface_form, \
                                                 mention_role, confidence) \
         VALUES ($1, $2, $3, 'subject', 0.9)",
    )
    .bind(claim)
    .bind(experiment_entity)
    .bind(content)
    .execute(pool)
    .await
    .expect("seed experiment entity mention");

    sqlx::query(
        "INSERT INTO challenges (claim_id, challenge_type, explanation, challenger_id, \
                                 visibility, owner_group_id) \
         VALUES ($1, 'methodological', $2, $3, 'group', $4)",
    )
    .bind(claim)
    .bind(content)
    .bind(author)
    .bind(world.group)
    .execute(pool)
    .await
    .expect("seed challenge");

    sqlx::query(
        "INSERT INTO experiment_triples (claim_id, subject_entity_id, predicate, \
                                         object_entity_id, confidence, visibility, \
                                         owner_group_id) \
         VALUES ($1, $2, $3, $2, 0.9, 'group', $4)",
    )
    .bind(claim)
    .bind(experiment_entity)
    .bind(content)
    .bind(world.group)
    .execute(pool)
    .await
    .expect("seed experiment triple");

    // HARVESTER SOURCE TEXT, through the provenance join. Statement 8 of
    // `seal_claims_conn` is the only one whose target is reached by a join
    // rather than by an id list, so a fixture without these two rows executes it
    // against nothing and the join could be wrong in either direction unnoticed.
    let source: Uuid = sqlx::query_scalar(
        "INSERT INTO harvester_sources (content_hash, modality, status) \
         VALUES ($1, 'text', 'completed') RETURNING id",
    )
    .bind(
        claim
            .as_bytes()
            .iter()
            .copied()
            .cycle()
            .take(32)
            .collect::<Vec<u8>>(),
    )
    .fetch_one(pool)
    .await
    .expect("seed harvester source");
    let fragment: Uuid = sqlx::query_scalar(
        "INSERT INTO harvester_fragments (source_id, content_hash, content_text, \
                                          context_window, status, visibility, owner_group_id) \
         VALUES ($1, $2, $3, $3, 'completed', 'group', $4) RETURNING id",
    )
    .bind(source)
    .bind(
        claim
            .as_bytes()
            .iter()
            .rev()
            .copied()
            .cycle()
            .take(32)
            .collect::<Vec<u8>>(),
    )
    .bind(content)
    .bind(world.group)
    .fetch_one(pool)
    .await
    .expect("seed harvester fragment");
    sqlx::query(
        "INSERT INTO harvester_claim_provenance (claim_id, fragment_id, visibility, \
                                                 owner_group_id) \
         VALUES ($1, $2, 'group', $3)",
    )
    .bind(claim)
    .bind(fragment)
    .bind(world.group)
    .execute(pool)
    .await
    .expect("seed harvester provenance");

    // A plaintext-derived ANN vector on BOTH vector columns, on both the claim
    // and its evidence. `embedding_3072` is absent from §6.5.4's TCB table and
    // is live in this schema; a seal that nulls one and not the other keeps a
    // plaintext-derived vector on a sealed row.
    for (table, id) in [("claims", claim), ("evidence", evidence)] {
        sqlx::query(&format!(
            "UPDATE {table} SET embedding = $2::vector, embedding_3072 = $3::vector \
              WHERE id = $1"
        ))
        .bind(id)
        .bind(vector_literal(1536, 0.5))
        .bind(vector_literal(3072, 0.25))
        .execute(pool)
        .await
        .expect("seed embeddings");
    }

    claim
}

/// Encrypt one claim's whole TCB, exactly as the CLI does.
async fn seal_payload(pool: &PgPool, claim: Uuid) -> SealCommitItem {
    let (content, labels, properties): (String, Vec<String>, serde_json::Value) =
        sqlx::query_as("SELECT content, labels, properties FROM claims WHERE id = $1")
            .bind(claim)
            .fetch_one(pool)
            .await
            .expect("read the plaintext");

    let ct = |bytes: &[u8], entity: Uuid, tag: FieldTag| -> Vec<u8> {
        let padded = pad(bytes, PAD_TO).expect("pad");
        epigraph_privacy::encrypt_content(&padded, &EPOCH_KEY, entity, EPOCH as u32, tag)
            .expect("encrypt")
            .to_bytes()
    };

    let content_ct = ct(content.as_bytes(), claim, FieldTag::Content);
    let content_hash = blake3::hash(&content_ct).as_bytes().to_vec();

    let versions: Vec<(Uuid, String)> =
        sqlx::query_as("SELECT id, content FROM claim_versions WHERE claim_id = $1 ORDER BY id")
            .bind(claim)
            .fetch_all(pool)
            .await
            .expect("read versions");

    let evidence: Vec<(Uuid, Option<String>, serde_json::Value)> = sqlx::query_as(
        "SELECT id, raw_content, properties FROM evidence WHERE claim_id = $1 ORDER BY id",
    )
    .bind(claim)
    .fetch_all(pool)
    .await
    .expect("read evidence");

    SealCommitItem {
        claim_id: claim,
        content_ct,
        labels_ct: ct(
            serde_json::to_string(&labels).unwrap().as_bytes(),
            claim,
            FieldTag::Labels,
        ),
        properties_ct: ct(
            properties.to_string().as_bytes(),
            claim,
            FieldTag::Properties,
        ),
        content_hash,
        versions: versions
            .into_iter()
            .map(|(id, content)| SealCommitVersion {
                content_ct: ct(content.as_bytes(), id, FieldTag::VersionContent),
                id,
            })
            .collect(),
        evidence: evidence
            .into_iter()
            .map(|(id, raw, props)| SealCommitEvidence {
                content_ct: ct(
                    raw.unwrap_or_default().as_bytes(),
                    id,
                    FieldTag::EvidenceContent,
                ),
                properties_ct: ct(
                    props.to_string().as_bytes(),
                    id,
                    FieldTag::EvidenceProperties,
                ),
                id,
            })
            .collect(),
    }
}

/// Run the seal mutation for `items` on a bypass connection.
async fn commit_seal(pool: &PgPool, world: &World, items: &[SealCommitItem]) -> Vec<Uuid> {
    let (scoped, _viewer) = viewer_fixture::bypass(pool).await;
    let (mut conn, _lease) = scoped
        .unscoped_for_maintenance(epigraph_db::visibility::SystemReason::PrivatizationApply)
        .await
        .expect("maintenance connection");
    let mut tx = sqlx::Connection::begin(&mut *conn)
        .await
        .expect("begin seal tx");
    let sealed = PrivatizationRepository::seal_claims_conn(&mut tx, world.group, EPOCH, items)
        .await
        .expect("seal");
    tx.commit().await.expect("commit seal");
    sealed
}

// =========================================================================
// Tests
// =========================================================================

/// Every per-column side channel §6.5.4 names, on one sealed claim.
#[sqlx::test(migrations = "../../migrations")]
async fn a_sealed_claim_keeps_no_plaintext_derived_column(pool: PgPool) {
    let world = seed_world(&pool).await;
    let claim = seed_sealable_claim(&pool, &world, "a confidential finding about a molecule").await;

    // CALIBRATION, BEFORE THE SEAL. Every table the loop below asserts is empty
    // must be NON-empty first. This is the exact failure the file's own thesis
    // names: an assertion list longer than the fixture's list passes trivially
    // for the difference, and the tables that go uncovered that way are the ones
    // nobody remembered to seed — which is the same set nobody remembered to
    // delete.
    for table in DERIVED_TABLES {
        let n: i64 =
            sqlx::query_scalar(&format!("SELECT count(*) FROM {table} WHERE claim_id = $1"))
                .bind(claim)
                .fetch_one(&pool)
                .await
                .expect("calibrate derived rows");
        assert_eq!(n, 1, "the fixture must seed a {table} row before the seal");
    }

    let payload = seal_payload(&pool, claim).await;
    let sealed = commit_seal(&pool, &world, std::slice::from_ref(&payload)).await;
    assert_eq!(sealed, vec![claim], "the seal reported the claim it sealed");

    let (content, n_tokens, embedding_present, embedding_3072_present, hash): (
        String,
        Option<i32>,
        bool,
        bool,
        Vec<u8>,
    ) = sqlx::query_as(
        "SELECT content, array_length(tsvector_to_array(content_tsv), 1), \
                embedding IS NOT NULL, embedding_3072 IS NOT NULL, content_hash \
           FROM claims WHERE id = $1",
    )
    .bind(claim)
    .fetch_one(&pool)
    .await
    .expect("read the sealed claim");

    assert_eq!(content, format!("[sealed:x{}]", claim.simple()));
    // The lexical side channel, and it is measured as a CONSTANT rather than as
    // a bound. `<= 2` is the plan's phrasing; the property is that the token
    // count does not vary with the id, because a count that did would be a
    // per-row signal in the GIN index. `assert_eq!` is what catches a sentinel
    // format whose token count is merely usually two — which is what the
    // hyphen-stripped-but-unprefixed spelling turned out to be.
    assert_eq!(
        n_tokens,
        Some(2),
        "the sentinel must lex to exactly two tokens, got {n_tokens:?} for {content}"
    );
    assert!(!embedding_present, "a sealed claim keeps no ANN vector");
    assert!(
        !embedding_3072_present,
        "a sealed claim keeps no 3072-d ANN vector either — the column §6.5.4's TCB table omits"
    );
    assert_eq!(
        hash,
        blake3::hash(&payload.content_ct).as_bytes().to_vec(),
        "content_hash is BLAKE3 over the ciphertext"
    );

    let (labels, properties): (Vec<String>, serde_json::Value) =
        sqlx::query_as("SELECT labels, properties FROM claims WHERE id = $1")
            .bind(claim)
            .fetch_one(&pool)
            .await
            .expect("read labels and properties");
    assert!(labels.is_empty(), "labels are emptied, not merely hidden");
    assert_eq!(properties, serde_json::json!({}));

    // `claim_versions` — the survivor §6.5.4 names first, and the one a
    // column-by-column suite written from the claims table alone would miss.
    let versions: Vec<String> =
        sqlx::query_scalar("SELECT content FROM claim_versions WHERE claim_id = $1")
            .bind(claim)
            .fetch_all(&pool)
            .await
            .expect("read versions");
    assert!(!versions.is_empty(), "the fixture seeded a version row");
    for v in &versions {
        assert_eq!(v, &format!("[sealed:x{}]", claim.simple()));
    }

    // Evidence, on both vector columns.
    let evidence: Vec<(Option<String>, bool, bool, serde_json::Value)> = sqlx::query_as(
        "SELECT raw_content, embedding IS NOT NULL, embedding_3072 IS NOT NULL, properties \
           FROM evidence WHERE claim_id = $1",
    )
    .bind(claim)
    .fetch_all(&pool)
    .await
    .expect("read evidence");
    assert!(!evidence.is_empty(), "the fixture seeded an evidence row");
    for (raw, emb, emb3072, props) in &evidence {
        assert_eq!(raw.as_deref(), Some("[sealed]"));
        assert!(!emb, "sealed evidence keeps no ANN vector");
        assert!(!emb3072, "sealed evidence keeps no 3072-d ANN vector");
        assert_eq!(props, &serde_json::json!({}));
    }

    // The derived extractions are gone, INCLUDING the table §6.5.4's list omits.
    for table in DERIVED_TABLES {
        let n: i64 =
            sqlx::query_scalar(&format!("SELECT count(*) FROM {table} WHERE claim_id = $1"))
                .bind(claim)
                .fetch_one(&pool)
                .await
                .expect("count derived rows");
        assert_eq!(
            n, 0,
            "{table} still carries a derived row for a sealed claim"
        );
    }

    // Harvester source text, through the provenance join. Not recoverable on
    // unseal, and stated in the preview before the admin clicks.
    let fragments: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT f.content_text, f.context_window \
           FROM harvester_fragments f \
           JOIN harvester_claim_provenance p ON p.fragment_id = f.id \
          WHERE p.claim_id = $1",
    )
    .bind(claim)
    .fetch_all(&pool)
    .await
    .expect("read harvester fragments");
    assert_eq!(fragments.len(), 1, "the fixture must seed a fragment");
    assert_eq!(fragments[0].0, "[sealed]");
    assert!(fragments[0].1.is_none());
}

/// The audit clause the previous revision got wrong: zero on BOTH tables.
#[sqlx::test(migrations = "../../migrations")]
async fn sealed_with_embedding_is_zero_on_claims_and_on_evidence(pool: PgPool) {
    let world = seed_world(&pool).await;
    let claim = seed_sealable_claim(&pool, &world, "an embedded confidential finding").await;

    // CALIBRATION. Before the seal both clauses must be NON-zero, or a green
    // result after it proves only that the fixture never embedded anything.
    let before_claims: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM claims c WHERE c.id = $1 \
           AND (c.embedding IS NOT NULL OR c.embedding_3072 IS NOT NULL)",
    )
    .bind(claim)
    .fetch_one(&pool)
    .await
    .expect("calibrate claims");
    let before_evidence: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM evidence e WHERE e.claim_id = $1 \
           AND (e.embedding IS NOT NULL OR e.embedding_3072 IS NOT NULL)",
    )
    .bind(claim)
    .fetch_one(&pool)
    .await
    .expect("calibrate evidence");
    assert_eq!(before_claims, 1, "the fixture must embed the claim");
    assert_eq!(before_evidence, 1, "the fixture must embed the evidence");

    let payload = seal_payload(&pool, claim).await;
    commit_seal(&pool, &world, &[payload]).await;

    // The CLAUDE.md clause, both halves, both vector columns.
    let claims_gap: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM claims c \
          WHERE (c.embedding IS NOT NULL OR c.embedding_3072 IS NOT NULL) \
            AND EXISTS (SELECT 1 FROM claim_encryption ce WHERE ce.claim_id = c.id)",
    )
    .fetch_one(&pool)
    .await
    .expect("sealed_with_embedding over claims");
    let evidence_gap: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM evidence e \
          WHERE (e.embedding IS NOT NULL OR e.embedding_3072 IS NOT NULL) \
            AND EXISTS (SELECT 1 FROM claim_encryption ce WHERE ce.claim_id = e.claim_id)",
    )
    .fetch_one(&pool)
    .await
    .expect("sealed_with_embedding over evidence");

    assert_eq!(claims_gap, 0);
    assert_eq!(evidence_gap, 0);
}

/// Length and hash: the two properties the sentinel format exists to give.
#[sqlx::test(migrations = "../../migrations")]
async fn ciphertext_length_and_content_hash_leak_nothing_about_the_plaintext(pool: PgPool) {
    let world = seed_world(&pool).await;

    // Two claims of wildly different length, and two whose plaintext is
    // IDENTICAL. The identical pair is the `[private]` collision regression:
    // a hash taken over a fixed sentinel would make them collide on
    // `uq_claims_content_hash_agent`.
    let short = seed_sealable_claim(&pool, &world, "x").await;
    let long = seed_sealable_claim(&pool, &world, &"y".repeat(200)).await;
    let (twin_author, _) = viewer_fixture::seed_agent_with_group(&pool, "seal-twin").await;
    let twin_a = seed_sealable_claim(&pool, &world, "the very same words").await;
    let twin_b = seed_sealable_claim_as(&pool, &world, twin_author, "the very same words").await;

    let mut payloads = Vec::new();
    for claim in [short, long, twin_a, twin_b] {
        payloads.push(seal_payload(&pool, claim).await);
    }
    let sealed = commit_seal(&pool, &world, &payloads).await;
    assert_eq!(sealed.len(), 4);

    let lengths: Vec<(Uuid, i32)> = sqlx::query_as(
        "SELECT claim_id, octet_length(encrypted_content) FROM claim_encryption \
          WHERE claim_id = ANY($1) ORDER BY claim_id",
    )
    .bind(&sealed)
    .fetch_all(&pool)
    .await
    .expect("read ciphertext lengths");
    assert_eq!(lengths.len(), 4);
    for (id, len) in &lengths {
        assert_eq!(
            len % PAD_TO as i32,
            0,
            "octet_length(encrypted_content) % pad_to must be 0 for {id}, got {len}"
        );
    }
    let by_id = |want: Uuid| lengths.iter().find(|(id, _)| *id == want).unwrap().1;
    assert_eq!(
        by_id(short),
        by_id(long),
        "a 1-byte and a 200-byte plaintext must store the same ciphertext length at pad_to=256"
    );

    // `length(content)` is constant modulo the uuid, and the uuid is fixed
    // width, so it is constant outright.
    let content_lengths: Vec<i32> =
        sqlx::query_scalar("SELECT length(content) FROM claims WHERE id = ANY($1)")
            .bind(&sealed)
            .fetch_all(&pool)
            .await
            .expect("read sentinel lengths");
    assert_eq!(
        content_lengths
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        1
    );

    let hashes: Vec<Vec<u8>> =
        sqlx::query_scalar("SELECT content_hash FROM claims WHERE id = ANY($1)")
            .bind(vec![twin_a, twin_b])
            .fetch_all(&pool)
            .await
            .expect("read twin hashes");
    assert_eq!(hashes.len(), 2);
    assert_ne!(
        hashes[0], hashes[1],
        "two sealed claims with identical plaintext must not share a content_hash"
    );
}

/// The corpus-wide regression: nothing of the sealed plaintext survives
/// anywhere in the database.
#[sqlx::test(migrations = "../../migrations")]
async fn no_trace_of_a_sealed_claim_survives_a_full_data_dump(pool: PgPool) {
    let world = seed_world(&pool).await;

    // Two distinct 32-byte nonces. One claim is sealed; the other is the
    // POSITIVE CONTROL, and without it a broken `pg_dump` invocation would pass
    // this test.
    let sealed_nonce = format!("nonce{}", Uuid::new_v4().simple());
    let control_nonce = format!("nonce{}", Uuid::new_v4().simple());
    let sealed_claim =
        seed_sealable_claim(&pool, &world, &format!("secret text {sealed_nonce} ends")).await;
    let _control =
        seed_sealable_claim(&pool, &world, &format!("public text {control_nonce} ends")).await;

    let payload = seal_payload(&pool, sealed_claim).await;
    commit_seal(&pool, &world, &[payload]).await;

    let url = viewer_fixture::database_url_for(&pool).await;
    let out = Command::new("pg_dump")
        .arg("--data-only")
        .arg("--no-owner")
        .arg(&url)
        .output()
        .expect(
            "pg_dump must be on PATH. This assertion is the only corpus-wide control in the \
             suite; skipping it when the binary is absent would report green over an untested \
             seal.",
        );
    assert!(
        out.status.success(),
        "pg_dump failed ({}): {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let dump = String::from_utf8_lossy(&out.stdout);
    assert!(
        dump.len() > 1024,
        "the dump is {} bytes, which is too small to have contained the fixture — the grep below \
         would pass vacuously",
        dump.len()
    );

    assert!(
        dump.matches(&control_nonce).count() > 0,
        "the POSITIVE CONTROL is missing from the dump: the instrument cannot detect plaintext, \
         so its silence about the sealed nonce means nothing"
    );
    assert_eq!(
        dump.matches(&sealed_nonce).count(),
        0,
        "the sealed claim's plaintext survives somewhere in the dump"
    );
}

/// Unseal restores the row, regenerates `content_tsv` with no code, and drops
/// the ciphertext.
#[sqlx::test(migrations = "../../migrations")]
async fn unseal_restores_the_row_and_the_generated_tsvector(pool: PgPool) {
    let world = seed_world(&pool).await;
    let plaintext = "a reversible confidential finding";
    let claim = seed_sealable_claim(&pool, &world, plaintext).await;
    let payload = seal_payload(&pool, claim).await;
    commit_seal(&pool, &world, std::slice::from_ref(&payload)).await;

    // The client's half of unseal: read the manifest, decrypt, unpad.
    let (scoped, _viewer) = viewer_fixture::bypass(&pool).await;
    let (mut conn, _lease) = scoped
        .unscoped_for_maintenance(epigraph_db::visibility::SystemReason::PrivatizationApply)
        .await
        .expect("maintenance connection");

    let recovered = {
        let decrypted = epigraph_privacy::decrypt_content(
            &epigraph_crypto::EncryptedPayload::from_bytes(&payload.content_ct).unwrap(),
            &EPOCH_KEY,
            claim,
            EPOCH as u32,
            FieldTag::Content,
        )
        .expect("decrypt");
        String::from_utf8(unpad(&decrypted, PAD_TO).expect("unpad")).expect("utf8")
    };
    assert_eq!(recovered, plaintext, "the ceremony round-trips");

    let versions: Vec<UnsealCommitVersion> = payload
        .versions
        .iter()
        .map(|v| UnsealCommitVersion {
            id: v.id,
            content: plaintext.to_string(),
        })
        .collect();
    let evidence: Vec<UnsealCommitEvidence> = payload
        .evidence
        .iter()
        .map(|e| UnsealCommitEvidence {
            id: e.id,
            raw_content: Some(plaintext.to_string()),
            properties: serde_json::json!({ "source": plaintext }),
        })
        .collect();

    let mut tx = sqlx::Connection::begin(&mut *conn)
        .await
        .expect("begin unseal tx");
    let restored = PrivatizationRepository::unseal_claims_conn(
        &mut tx,
        world.group,
        &[UnsealCommitItem {
            claim_id: claim,
            content: recovered.clone(),
            content_hash: blake3::hash(recovered.as_bytes()).as_bytes().to_vec(),
            labels: vec!["restored".to_string()],
            properties: serde_json::json!({ "back": true }),
            versions,
            evidence,
        }],
    )
    .await
    .expect("unseal");
    tx.commit().await.expect("commit unseal");
    assert_eq!(restored, vec![claim]);
    drop(conn);

    let (content, tokens, labels, properties): (
        String,
        Option<i32>,
        Vec<String>,
        serde_json::Value,
    ) = sqlx::query_as(
        "SELECT content, array_length(tsvector_to_array(content_tsv), 1), labels, properties \
               FROM claims WHERE id = $1",
    )
    .bind(claim)
    .fetch_one(&pool)
    .await
    .expect("read the unsealed claim");
    assert_eq!(content, plaintext);
    assert!(
        tokens.unwrap_or(0) > 2,
        "content_tsv must regenerate from the restored content with no bespoke code, got {tokens:?}"
    );
    assert_eq!(labels, vec!["restored".to_string()]);
    assert_eq!(properties, serde_json::json!({ "back": true }));

    let ciphertext_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM claim_encryption WHERE claim_id = $1")
            .bind(claim)
            .fetch_one(&pool)
            .await
            .expect("count ciphertext rows");
    assert_eq!(ciphertext_rows, 0, "unseal drops the ciphertext row");

    // The embedding is NOT restored: the vector was destroyed, not stashed, and
    // the caller enqueues an embedding job. Asserted so nobody later reads the
    // NULL as a bug and "fixes" it by retaining the vector through a seal.
    let embedding_present: bool =
        sqlx::query_scalar("SELECT embedding IS NOT NULL FROM claims WHERE id = $1")
            .bind(claim)
            .fetch_one(&pool)
            .await
            .expect("read embedding");
    assert!(!embedding_present);
}

/// A commit that omits a version or an evidence row is REFUSED, not applied to
/// the rest.
///
/// The refusal itself is the route's; what this asserts is the fact the route
/// refuses ON — that the database, not the manifest, is the authority on what
/// the TCB contains for a claim at commit time.
#[sqlx::test(migrations = "../../migrations")]
async fn the_tcb_shape_is_read_from_the_database_not_from_the_manifest(pool: PgPool) {
    let world = seed_world(&pool).await;
    let claim = seed_sealable_claim(&pool, &world, "a claim that grows a version").await;
    let payload = seal_payload(&pool, claim).await;
    assert_eq!(payload.versions.len(), 1);
    assert_eq!(payload.evidence.len(), 1);

    // A row inserted AFTER the manifest was served. A commit checked against
    // the manifest would call itself complete; a commit checked against the
    // database sees two versions and one covered.
    sqlx::query(
        "INSERT INTO claim_versions (claim_id, version_number, content, truth_value, \
                                     created_by, visibility, owner_group_id) \
         VALUES ($1, 2, 'a later revision', 0.8, $2, 'group', $3)",
    )
    .bind(claim)
    .bind(world.author)
    .bind(world.group)
    .execute(&pool)
    .await
    .expect("seed a late version");

    let (scoped, _viewer) = viewer_fixture::bypass(&pool).await;
    let (mut conn, _lease) = scoped
        .unscoped_for_maintenance(epigraph_db::visibility::SystemReason::PrivatizationSelection)
        .await
        .expect("maintenance connection");
    let shape = PrivatizationRepository::seal_tcb_shape_conn(&mut conn, &[claim])
        .await
        .expect("tcb shape");
    assert_eq!(shape.len(), 1);
    assert_eq!(
        shape[0].version_ids.len(),
        2,
        "the shape must see the row inserted after the manifest was served"
    );
    let covered: std::collections::BTreeSet<Uuid> = payload.versions.iter().map(|v| v.id).collect();
    assert!(
        shape[0].version_ids.iter().any(|id| !covered.contains(id)),
        "an uncovered TCB member must be visible to the commit's completeness check"
    );
}

/// Seal-then-declassify is refused unconditionally, and no GUC reaches it.
///
/// Migration 074's `epigraph_claims_block_widening` arm (a) already ships this
/// and `tenancy_required.rs` already covers the guard on its own terms. It is
/// re-asserted here against a claim sealed by THIS module's mutation, because
/// the property PR-21 owns is that its seal produces a row the guard actually
/// refuses — not that the guard exists.
#[sqlx::test(migrations = "../../migrations")]
async fn a_claim_sealed_by_this_path_can_never_be_declassified(pool: PgPool) {
    let world = seed_world(&pool).await;
    let claim = seed_sealable_claim(&pool, &world, "sealed and staying that way").await;
    let payload = seal_payload(&pool, claim).await;
    commit_seal(&pool, &world, &[payload]).await;

    let world_group = viewer_fixture::world_group(&pool).await;
    let mut tx = pool.begin().await.expect("begin");
    // The GUC is set, and set in the same transaction, so the assertion is
    // about arm (a) having NO override rather than about the override being
    // absent from the test.
    sqlx::query("SET LOCAL epigraph.allow_declassify = 'yes'")
        .execute(&mut *tx)
        .await
        .expect("arm the declassification GUC");
    let err = sqlx::query(
        "UPDATE claims SET visibility = 'public', owner_group_id = $2 \
                            WHERE id = $1",
    )
    .bind(claim)
    .bind(world_group)
    .execute(&mut *tx)
    .await
    .expect_err("declassifying a sealed claim must be refused");

    let code = err
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(std::borrow::Cow::into_owned);
    assert_eq!(
        code.as_deref(),
        Some("42501"),
        "expected an insufficient-privilege refusal, got {err}"
    );
}

/// Re-delivering a commit is a no-op, not a second seal under a fresh key.
#[sqlx::test(migrations = "../../migrations")]
async fn a_redelivered_seal_commit_changes_nothing(pool: PgPool) {
    let world = seed_world(&pool).await;
    let claim = seed_sealable_claim(&pool, &world, "delivered twice").await;
    let payload = seal_payload(&pool, claim).await;

    let first = commit_seal(&pool, &world, std::slice::from_ref(&payload)).await;
    assert_eq!(first, vec![claim]);
    let hash_after_first: Vec<u8> =
        sqlx::query_scalar("SELECT content_hash FROM claims WHERE id = $1")
            .bind(claim)
            .fetch_one(&pool)
            .await
            .expect("read hash");

    let second = commit_seal(&pool, &world, std::slice::from_ref(&payload)).await;
    assert!(
        second.is_empty(),
        "a claim that already carries a ciphertext row is skipped whole"
    );
    let hash_after_second: Vec<u8> =
        sqlx::query_scalar("SELECT content_hash FROM claims WHERE id = $1")
            .bind(claim)
            .fetch_one(&pool)
            .await
            .expect("read hash");
    assert_eq!(hash_after_first, hash_after_second);
}

/// The reseal completion test: a rotation leaves every ciphertext row bound to
/// the retired epoch, and only a real re-seal clears the flag.
#[sqlx::test(migrations = "../../migrations")]
async fn a_rotation_does_not_move_a_ciphertext_row_and_the_count_says_so(pool: PgPool) {
    let world = seed_world(&pool).await;
    let claim = seed_sealable_claim(&pool, &world, "sealed under epoch zero").await;
    let payload = seal_payload(&pool, claim).await;
    commit_seal(&pool, &world, &[payload]).await;

    let (scoped, _viewer) = viewer_fixture::bypass(&pool).await;
    let (mut conn, _lease) = scoped
        .unscoped_for_maintenance(epigraph_db::visibility::SystemReason::PrivatizationReseal)
        .await
        .expect("maintenance connection");

    assert_eq!(
        PrivatizationRepository::stale_epoch_seal_count_conn(&mut conn, world.group)
            .await
            .expect("count"),
        0,
        "nothing is stale before a rotation"
    );

    sqlx::query(
        "UPDATE group_key_epochs SET status = 'retired', retired_at = now() \
                  WHERE group_id = $1 AND epoch = $2",
    )
    .bind(world.group)
    .bind(EPOCH)
    .execute(&mut *conn)
    .await
    .expect("retire the epoch");
    sqlx::query("INSERT INTO group_key_epochs (group_id, epoch, status) VALUES ($1, $2, 'active')")
        .bind(world.group)
        .bind(EPOCH + 1)
        .execute(&mut *conn)
        .await
        .expect("create the next epoch");
    sqlx::query("UPDATE groups SET reseal_required_at = now() WHERE id = $1")
        .bind(world.group)
        .execute(&mut *conn)
        .await
        .expect("mark reseal required");

    let stale = PrivatizationRepository::stale_epoch_seal_count_conn(&mut conn, world.group)
        .await
        .expect("count");
    assert!(
        stale > 0,
        "rotation gates only future ciphertext: every row sealed under the retired epoch is \
         still bound to it, and the count is what says so out loud"
    );

    // The flag stays set while anything is stale — the handler's precondition.
    let flagged: bool =
        sqlx::query_scalar("SELECT reseal_required_at IS NOT NULL FROM groups WHERE id = $1")
            .bind(world.group)
            .fetch_one(&mut *conn)
            .await
            .expect("read the flag");
    assert!(flagged);
}

/// The fixture's list of derived tables IS the mutation's list.
///
/// Three hand-maintained lists now describe the same set: [`DERIVED_TABLES`]
/// (what this file seeds and asserts about),
/// `epigraph_db::repos::privatization::SEAL_DELETE_TABLES` (what the mutation
/// deletes) and `epigraph_api::routes::privatization::SEAL_DESTROYS` (what the
/// operator is told). `privatization_seal.rs` pins the last two to each other;
/// this pins the first two, so all three agree transitively.
///
/// Without it, a table added to the mutation and to the preview but not to this
/// fixture goes back to being asserted-about-but-unseeded — which is exactly the
/// vacuity the calibration loop exists to prevent, arriving through the one door
/// that loop cannot watch.
/// A source fragment cited by a claim outside the plan is blanked ANYWAY.
///
/// `harvester_claim_provenance` is keyed `(claim_id, fragment_id)`, so one
/// fragment can back several claims, and the blanking statement reaches it
/// through that join. The choice here is between two losses and there is no
/// third option: narrowing the statement to fragments cited only by sealed
/// claims would leave the SEALED claim's own source text in the corpus in
/// plaintext, which §6.5.4 calls worse than not sealing at all. So the fragment
/// goes, the other claim's provenance text goes with it, and the seal preview's
/// `unrecoverable` line says so before the admin clicks. This test exists so
/// that a later slice that "fixes" the over-reach has to argue with the
/// confidentiality direction first.
#[sqlx::test(migrations = "../../migrations")]
async fn a_shared_source_fragment_is_blanked_for_every_claim_that_cites_it(pool: PgPool) {
    let world = seed_world(&pool).await;
    let sealed = seed_sealable_claim(&pool, &world, "the claim this plan seals").await;
    let sharer_text = "a claim outside the plan, citing the same source";
    let sharer = seed_sealable_claim(&pool, &world, sharer_text).await;

    let fragment: Uuid = sqlx::query_scalar(
        "SELECT fragment_id FROM harvester_claim_provenance WHERE claim_id = $1",
    )
    .bind(sealed)
    .fetch_one(&pool)
    .await
    .expect("read the sealed claim's fragment");
    sqlx::query(
        "INSERT INTO harvester_claim_provenance (claim_id, fragment_id, visibility, \
                                                 owner_group_id) \
         VALUES ($1, $2, 'group', $3)",
    )
    .bind(sharer)
    .bind(fragment)
    .bind(world.group)
    .execute(&pool)
    .await
    .expect("share the fragment with a second claim");

    let payload = seal_payload(&pool, sealed).await;
    commit_seal(&pool, &world, std::slice::from_ref(&payload)).await;

    let (text, window): (String, Option<String>) = sqlx::query_as(
        "SELECT content_text, context_window FROM harvester_fragments WHERE id = $1",
    )
    .bind(fragment)
    .fetch_one(&pool)
    .await
    .expect("read the shared fragment");
    assert_eq!(
        text, "[sealed]",
        "the sealed claim's source text must not survive the seal in any row, shared or not"
    );
    assert!(window.is_none());

    // The out-of-plan claim itself is NOT touched: it keeps its content, and it
    // acquires no ciphertext row. The loss is its provenance text and nothing
    // else, which is the boundary the preview describes.
    let (content, ciphertext_rows): (String, i64) = sqlx::query_as(
        "SELECT c.content, \
                (SELECT count(*) FROM claim_encryption ce WHERE ce.claim_id = c.id) \
           FROM claims c WHERE c.id = $1",
    )
    .bind(sharer)
    .fetch_one(&pool)
    .await
    .expect("read the out-of-plan claim");
    assert_eq!(content, sharer_text);
    assert_eq!(ciphertext_rows, 0);
}

/// The restore write applies the READ's population rules, `is_current` included.
///
/// The pair exists because the read and the write are separated by a provider
/// round trip. `claim_text_for_embedding` declines a superseded claim; if the
/// write did not, a supersede landing inside that window would put the vector
/// back on the row the supersede had just nulled — `stale_present` in CLAUDE.md's
/// audit, with nothing downstream to clean it up.
#[sqlx::test(migrations = "../../migrations")]
async fn the_restore_write_refuses_a_claim_superseded_since_the_text_was_read(pool: PgPool) {
    let world = seed_world(&pool).await;
    let current = seed_sealable_claim(&pool, &world, "still the current revision").await;
    let stale = seed_sealable_claim(&pool, &world, "superseded mid-flight").await;

    let (_scoped, bypass) = viewer_fixture::bypass(&pool).await;
    let vector = vector_literal(1536, 0.375);
    let mut conn = pool.acquire().await.expect("acquire");

    let wrote = epigraph_db::ClaimRepository::store_embedding_if_unsealed(
        &mut conn, &bypass, current, &vector,
    )
    .await
    .expect("store a vector on a current claim");
    assert!(
        wrote,
        "a current, unsealed claim must still be embeddable by the restore write"
    );

    // What `ClaimRepository::supersede` does to the loser, reduced to the one
    // column this write consults.
    sqlx::query("UPDATE claims SET is_current = false, embedding = NULL WHERE id = $1")
        .bind(stale)
        .execute(&pool)
        .await
        .expect("supersede the claim out from under the in-flight job");

    let refused = epigraph_db::ClaimRepository::store_embedding_if_unsealed(
        &mut conn, &bypass, stale, &vector,
    )
    .await
    .expect("the refusal is a zero-row UPDATE, not an error");
    assert!(
        !refused,
        "the restore write must report no row for a superseded claim"
    );

    let after: Option<bool> =
        sqlx::query_scalar("SELECT embedding IS NULL FROM claims WHERE id = $1")
            .bind(stale)
            .fetch_one(&pool)
            .await
            .expect("re-read the superseded claim's vector column");
    assert_eq!(
        after,
        Some(true),
        "every claim with is_current = false should have embedding = NULL"
    );
}

#[test]
fn the_fixture_seeds_exactly_the_tables_the_seal_deletes() {
    assert_eq!(
        DERIVED_TABLES,
        epigraph_db::repos::privatization::SEAL_DELETE_TABLES,
        "the fixture's derived-table list and the seal mutation's DELETE list disagree"
    );
}
