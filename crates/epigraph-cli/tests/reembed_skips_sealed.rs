//! `reembed` must never select a sealed row, on either table.
//!
//! # Why this is worth a test of its own
//!
//! `reembed` is the documented recovery path for the 3072-d column a
//! privatization unseal does not restore, so it is deliberately run over
//! corpora that contain sealed rows. A seal nulls `embedding_3072` and replaces
//! the text column with a constant-shaped sentinel — which is exactly the shape
//! `embedding_3072 IS NULL AND length(<text>) > 0` selects. The tool's selection
//! rule and the seal's output agree unless something says otherwise.
//!
//! What a missing exclusion costs is not a failed run: it is a successful one
//! that writes a vector into a live ANN column on every sealed row, permanently
//! (the column is no longer NULL, so no later run revisits it) and silently.
//!
//! # The fixture seals the two tables SEPARATELY, and that is the point
//!
//! A claim is sealed iff `claim_encryption` holds its id; an evidence row is
//! sealed iff `evidence_encryption` holds ITS OWN id. The fixture therefore
//! seeds an unsealed evidence row under a SEALED claim and asserts it is still
//! re-embedded: the two predicates are not the same set, and an exclusion keyed
//! on the parent claim would skip rows whose plaintext is real.

use std::sync::Arc;

use sqlx::PgPool;
use uuid::Uuid;

use epigraph_cli::reembed::{run, ReembedConfig, ReembedTarget};
use epigraph_embeddings::{EmbeddingConfig, MockProvider};

const EPOCH: i32 = 0;

struct Corpus {
    plain_claim: Uuid,
    sealed_claim: Uuid,
    /// An unsealed evidence row hanging off the SEALED claim.
    plain_evidence: Uuid,
    sealed_evidence: Uuid,
}

async fn seed_claim(pool: &PgPool, agent: Uuid, group: Uuid, content: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, \
                             visibility, owner_group_id, embedding_3072) \
         VALUES ($1, sha256($1::bytea), 0.5, $2, 'group', $3, NULL) \
         RETURNING id",
    )
    .bind(content)
    .bind(agent)
    .bind(group)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

async fn seed_evidence(pool: &PgPool, claim_id: Uuid, raw: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO evidence (claim_id, evidence_type, content_hash, raw_content, \
                               embedding_3072) \
         VALUES ($1, 'document', sha256($2::bytea), $2, NULL) \
         RETURNING id",
    )
    .bind(claim_id)
    .bind(raw)
    .fetch_one(pool)
    .await
    .expect("seed evidence")
}

async fn seed(pool: &PgPool) -> Corpus {
    let agent: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'reembed-seal-test', 'system', \
                 ARRAY['test']) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent");

    // A `personal` group carries an empty `public_key` (only `kind='team'` may
    // carry 32 bytes, per `groups_public_key_shape`). Nothing here exercises the
    // key ceremony; the group and its epoch exist because `claim_encryption`
    // and `evidence_encryption` have foreign keys onto them.
    let group: Uuid = sqlx::query_scalar(
        "INSERT INTO groups (display_name, did_key, public_key, kind, created_by_agent_id) \
         VALUES ('reembed seal target', 'did:epigraph:personal:' || $1::text, ''::bytea, \
                 'personal', $1) \
         RETURNING id",
    )
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seed group");

    sqlx::query("INSERT INTO group_key_epochs (group_id, epoch, status) VALUES ($1, $2, 'active')")
        .bind(group)
        .bind(EPOCH)
        .execute(pool)
        .await
        .expect("seed active key epoch");

    let plain_claim = seed_claim(pool, agent, group, "reembed-seal-test plaintext claim").await;
    let sealed_claim = seed_claim(
        pool,
        agent,
        group,
        "reembed-seal-test claim about to be sealed",
    )
    .await;

    // The sentinel the seal actually writes, so the `length(content) > 0` guard
    // is exercised against the real shape rather than against a string this
    // test invented.
    sqlx::query("UPDATE claims SET content = $2 WHERE id = $1")
        .bind(sealed_claim)
        .bind(format!(
            "[sealed:x{}]",
            sealed_claim.to_string().replace('-', "")
        ))
        .execute(pool)
        .await
        .expect("write the seal sentinel");

    sqlx::query(
        "INSERT INTO claim_encryption (claim_id, group_id, epoch, privacy_tier, \
                                       encrypted_content) \
         VALUES ($1, $2, $3, 'fully_private', ''::bytea)",
    )
    .bind(sealed_claim)
    .bind(group)
    .bind(EPOCH)
    .execute(pool)
    .await
    .expect("seal the claim");

    // Deliberately hung off the SEALED claim: this row is NOT sealed and its
    // text is real, so it must still be re-embedded.
    let plain_evidence =
        seed_evidence(pool, sealed_claim, "reembed-seal-test evidence plaintext").await;
    let sealed_evidence = seed_evidence(pool, plain_claim, "[sealed]").await;

    sqlx::query(
        "INSERT INTO evidence_encryption (evidence_id, group_id, epoch, privacy_tier, \
                                          encrypted_content) \
         VALUES ($1, $2, $3, 'fully_private', ''::bytea)",
    )
    .bind(sealed_evidence)
    .bind(group)
    .bind(EPOCH)
    .execute(pool)
    .await
    .expect("seal the evidence row");

    Corpus {
        plain_claim,
        sealed_claim,
        plain_evidence,
        sealed_evidence,
    }
}

async fn has_vector(pool: &PgPool, table: &str, id: Uuid) -> bool {
    let present: bool = sqlx::query_scalar(&format!(
        "SELECT embedding_3072 IS NOT NULL FROM {table} WHERE id = $1"
    ))
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("read embedding_3072");
    present
}

async fn reembed(pool: &PgPool, target: ReembedTarget) {
    run(
        pool,
        ReembedConfig {
            target,
            batch_size: 16,
            embedding_provider: Arc::new(MockProvider::new(EmbeddingConfig::openai(3072))),
            checkpoint_path: None,
        },
    )
    .await
    .expect("reembed run");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_reembed_run_writes_no_vector_onto_a_sealed_row(pool: PgPool) {
    let corpus = seed(&pool).await;

    reembed(&pool, ReembedTarget::Claims).await;
    reembed(&pool, ReembedTarget::Evidence).await;

    // POSITIVE ARM FIRST. An exclusion that selected nothing would satisfy
    // every assertion below it, and the observable result — a corpus that is
    // never re-embedded — is the failure this tool exists to prevent.
    assert!(
        has_vector(&pool, "claims", corpus.plain_claim).await,
        "an unsealed claim must still be re-embedded"
    );
    assert!(
        has_vector(&pool, "evidence", corpus.plain_evidence).await,
        "an unsealed evidence row must still be re-embedded, even under a sealed claim"
    );

    assert!(
        !has_vector(&pool, "claims", corpus.sealed_claim).await,
        "a sealed claim must not be given a vector derived from its seal sentinel"
    );
    assert!(
        !has_vector(&pool, "evidence", corpus.sealed_evidence).await,
        "a sealed evidence row must not be given a vector derived from its seal sentinel"
    );
}
