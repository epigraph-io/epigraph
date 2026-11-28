//! Backlog aa366aa6: the seal re-signs the sealed form with the server's key
//! and keeps the pre-seal signature in the ciphertext row (migration 357).
//!
//! Before 357 the seal replaced `claims.content_hash` with BLAKE3 of the
//! ciphertext and left `claims.signature` (a v1 signature over BLAKE3 of the
//! PLAINTEXT) on the row, and left `evidence.signature` beside a sentinel
//! digest. Neither verified over its row any more, and both let anyone who can
//! read the row confirm a guessed plaintext against the signer's public key.
//!
//! What these tests pin, each against REAL signatures (a claim signed by its
//! author over BLAKE3 of its content, an evidence row over BLAKE3 of its
//! body), so "verifies" means a verification ran:
//!
//! * after a seal, the claim's signature verifies under the SERVER key over
//!   the ciphertext digest, `signer_id` is the server's signer agent, the
//!   evidence row is unsigned, and the ciphertext rows hold the originals;
//! * a member of the sealing group reads the stash on the application role,
//!   and a non-member reads no row (with the member read as the positive
//!   control);
//! * seal then unseal restores `signature` and `signer_id` byte for byte, and
//!   the original verifies over the restored plaintext digest;
//! * an unsigned original comes back unsigned, a seal with no key leaves the
//!   sealed row unsigned, a re-delivered seal keeps the first stash, and a row
//!   sealed WITHOUT the stash (before 357) keeps its signature through unseal;
//! * `docs/runbooks/357-undo.sql` puts the originals back and drops the
//!   columns, twice.

mod viewer_fixture;

use epigraph_crypto::{AgentSigner, SignatureScheme, SignatureVerifier, SignedEntity};
use epigraph_db::repos::privatization::{
    PrivatizationRepository, SealCommitEvidence, SealCommitItem, UnsealCommitEvidence,
    UnsealCommitItem,
};
use epigraph_db::repos::EdgeSigningKey;
use sqlx::PgPool;
use uuid::Uuid;

const EPOCH: i32 = 0;

// =========================================================================
// Fixture
// =========================================================================

/// A keyed `team` group (the seal target), its author, an outsider in a group
/// of its own, and the server's signer agent.
struct World {
    group: Uuid,
    author: Uuid,
    author_key: AgentSigner,
    outsider: Uuid,
    server: AgentSigner,
    server_id: Uuid,
}

/// A real agent row whose `public_key` is `signer`'s.
async fn agent_for(pool: &PgPool, signer: &AgentSigner) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system') RETURNING id",
    )
    .bind(Uuid::new_v4())
    .bind(signer.public_key().to_vec())
    .fetch_one(pool)
    .await
    .expect("seed a keyed agent")
}

async fn seed_world(pool: &PgPool) -> World {
    let author_key = AgentSigner::generate();
    let author = agent_for(pool, &author_key).await;
    let (outsider, _) = viewer_fixture::seed_agent_with_group(pool, "resign-outsider").await;
    let server = AgentSigner::generate();
    let server_id = agent_for(pool, &server).await;

    let group: Uuid = sqlx::query_scalar(
        "INSERT INTO groups (display_name, did_key, public_key, kind, status, \
                             created_by_agent_id, created_at) \
         VALUES ('resign target', 'did:epigraph:team:' || gen_random_uuid()::text, \
                 $2, 'team', 'active', $1, now() - interval '48 hours') \
         RETURNING id",
    )
    .bind(author)
    .bind(vec![0x22u8; 32])
    .fetch_one(pool)
    .await
    .expect("seed team group");
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'admin')",
    )
    .bind(group)
    .bind(author)
    .execute(pool)
    .await
    .expect("seed membership");
    sqlx::query("INSERT INTO group_key_epochs (group_id, epoch, status) VALUES ($1, $2, 'active')")
        .bind(group)
        .bind(EPOCH)
        .execute(pool)
        .await
        .expect("seed active key epoch");

    World {
        group,
        author,
        author_key,
        outsider,
        server,
        server_id,
    }
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

/// A group claim with one evidence row. When `signed`, both carry the
/// author's real v1 signature over their plaintext digest, as a signed write
/// stores them; otherwise both are unsigned.
async fn seed_claim(pool: &PgPool, world: &World, content: &str, signed: bool) -> (Uuid, Uuid) {
    let claim = viewer_fixture::seed_group_claim(pool, world.author, world.group, content).await;
    let claim_digest = digest(content.as_bytes());
    let claim_sig = signed.then(|| {
        world
            .author_key
            .sign_entity(SignedEntity::Claim, &claim_digest)
            .to_vec()
    });
    sqlx::query(
        "UPDATE claims SET content_hash = $2, signature = $3, signer_id = $4 WHERE id = $1",
    )
    .bind(claim)
    .bind(claim_digest.to_vec())
    .bind(&claim_sig)
    .bind(signed.then_some(world.author))
    .execute(pool)
    .await
    .expect("sign the claim");

    let evidence = viewer_fixture::seed_evidence(pool, claim, "document").await;
    let body = format!("the body behind {content}");
    let body_digest = digest(body.as_bytes());
    let evidence_sig = signed.then(|| {
        world
            .author_key
            .sign_entity(SignedEntity::Evidence, &body_digest)
            .to_vec()
    });
    sqlx::query(
        "UPDATE evidence SET raw_content = $2, content_hash = $3, signature = $4, signer_id = $5 \
          WHERE id = $1",
    )
    .bind(evidence)
    .bind(&body)
    .bind(body_digest.to_vec())
    .bind(&evidence_sig)
    .bind(signed.then_some(world.author))
    .execute(pool)
    .await
    .expect("sign the evidence");
    (claim, evidence)
}

/// The seal's input for one claim. The mutation does not read the ciphertext,
/// so opaque bytes stand in for it; the digest is BLAKE3 over them, as the
/// route requires.
fn seal_item(claim: Uuid, evidence: Uuid) -> SealCommitItem {
    let content_ct = format!("ciphertext of {claim}").into_bytes();
    SealCommitItem {
        claim_id: claim,
        content_hash: digest(&content_ct).to_vec(),
        content_ct,
        labels_ct: b"labels ct".to_vec(),
        properties_ct: b"properties ct".to_vec(),
        versions: Vec::new(),
        evidence: vec![SealCommitEvidence {
            id: evidence,
            content_ct: b"evidence ct".to_vec(),
            properties_ct: b"evidence properties ct".to_vec(),
        }],
    }
}

fn unseal_item(claim: Uuid, evidence: Uuid, content: &str) -> UnsealCommitItem {
    UnsealCommitItem {
        claim_id: claim,
        content: content.to_string(),
        content_hash: digest(content.as_bytes()).to_vec(),
        labels: Vec::new(),
        properties: serde_json::json!({}),
        versions: Vec::new(),
        evidence: vec![UnsealCommitEvidence {
            id: evidence,
            raw_content: Some(format!("the body behind {content}")),
            properties: serde_json::json!({}),
        }],
    }
}

/// Run the seal on a maintenance connection, as the route does.
async fn seal(
    pool: &PgPool,
    world: &World,
    items: &[SealCommitItem],
    attest: Option<EdgeSigningKey<'_>>,
) -> Vec<Uuid> {
    let (scoped, _viewer) = viewer_fixture::bypass(pool).await;
    let (mut conn, _lease) = scoped
        .unscoped_for_maintenance(epigraph_db::visibility::SystemReason::PrivatizationApply)
        .await
        .expect("maintenance connection");
    let mut tx = sqlx::Connection::begin(&mut *conn).await.expect("begin");
    let sealed =
        PrivatizationRepository::seal_claims_conn(&mut tx, world.group, EPOCH, items, attest)
            .await
            .expect("seal");
    tx.commit().await.expect("commit seal");
    sealed
}

async fn unseal(pool: &PgPool, world: &World, items: &[UnsealCommitItem]) -> Vec<Uuid> {
    let (scoped, _viewer) = viewer_fixture::bypass(pool).await;
    let (mut conn, _lease) = scoped
        .unscoped_for_maintenance(epigraph_db::visibility::SystemReason::PrivatizationApply)
        .await
        .expect("maintenance connection");
    let mut tx = sqlx::Connection::begin(&mut *conn).await.expect("begin");
    let restored = PrivatizationRepository::unseal_claims_conn(&mut tx, world.group, items)
        .await
        .expect("unseal");
    tx.commit().await.expect("commit unseal");
    restored
}

fn server_key(world: &World) -> EdgeSigningKey<'_> {
    EdgeSigningKey {
        signer: &world.server,
        signer_id: world.server_id,
    }
}

type Signed = (Option<Vec<u8>>, Option<Uuid>);

async fn claim_signature(pool: &PgPool, claim: Uuid) -> (Vec<u8>, Option<Vec<u8>>, Option<Uuid>) {
    sqlx::query_as("SELECT content_hash, signature, signer_id FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("read the claim's signature")
}

async fn evidence_signature(pool: &PgPool, evidence: Uuid) -> Signed {
    sqlx::query_as("SELECT signature, signer_id FROM evidence WHERE id = $1")
        .bind(evidence)
        .fetch_one(pool)
        .await
        .expect("read the evidence signature")
}

/// `(pre_seal_signature, pre_seal_signer_id, pre_seal_stashed)` on the
/// superuser pool.
async fn claim_stash(pool: &PgPool, claim: Uuid) -> (Option<Vec<u8>>, Option<Uuid>, bool) {
    sqlx::query_as(
        "SELECT pre_seal_signature, pre_seal_signer_id, pre_seal_stashed \
           FROM claim_encryption WHERE claim_id = $1",
    )
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("read the claim stash")
}

async fn evidence_stash(pool: &PgPool, evidence: Uuid) -> (Option<Vec<u8>>, Option<Uuid>, bool) {
    sqlx::query_as(
        "SELECT pre_seal_signature, pre_seal_signer_id, pre_seal_stashed \
           FROM evidence_encryption WHERE evidence_id = $1",
    )
    .bind(evidence)
    .fetch_one(pool)
    .await
    .expect("read the evidence stash")
}

fn verifies(
    key: &AgentSigner,
    kind: SignedEntity,
    digest: &[u8],
    signature: Option<&Vec<u8>>,
) -> bool {
    let digest: [u8; 32] = digest.try_into().expect("a 32-byte digest");
    let Some(signature) = signature else {
        return false;
    };
    let signature: [u8; 64] = signature
        .as_slice()
        .try_into()
        .expect("a 64-byte signature");
    SignatureVerifier::verify_entity(&key.public_key(), kind, &digest, &signature)
        .expect("a valid public key")
        == Some(SignatureScheme::V1)
}

/// A downgraded `epigraph_app` connection stamped as `principal`, with its
/// live groups in `epigraph.group_ids` (the GUC 077's encryption-table policy
/// reads), as a request's connection is.
async fn app_conn_as(pool: &PgPool, principal: Uuid) -> sqlx::pool::PoolConnection<sqlx::Postgres> {
    let groups: Vec<Uuid> = sqlx::query_scalar(
        "SELECT group_id FROM group_memberships WHERE agent_id = $1 AND revoked_at IS NULL",
    )
    .bind(principal)
    .fetch_all(pool)
    .await
    .expect("read live memberships");
    let app = viewer_fixture::downgraded_pool(pool, "epigraph_app").await;
    let mut conn = app.acquire().await.expect("acquire an app connection");
    let joined = groups
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    sqlx::query(
        "SELECT set_config('epigraph.principal_id', $1::text, false), \
                set_config('epigraph.group_ids', $2, false)",
    )
    .bind(principal)
    .bind(&joined)
    .execute(&mut *conn)
    .await
    .expect("stamp the session");
    let (role, bypassrls, stamped): (String, bool, Vec<Uuid>) = sqlx::query_as(
        "SELECT session_user::text, \
                (SELECT r.rolbypassrls FROM pg_roles r WHERE r.rolname = session_user), \
                public.epigraph_session_groups()",
    )
    .fetch_one(&mut *conn)
    .await
    .expect("session probe");
    assert_eq!(role, "epigraph_app", "CALIBRATION: really downgraded");
    assert!(!bypassrls, "CALIBRATION: epigraph_app must not bypass RLS");
    assert_eq!(stamped.len(), groups.len(), "CALIBRATION: groups stamped");
    conn
}

/// Both stash columns' signature for `claim` / `evidence`, as the caller's
/// connection reads them.
async fn read_stash(
    conn: &mut sqlx::PgConnection,
    claim: Uuid,
    evidence: Uuid,
) -> (Vec<Option<Vec<u8>>>, Vec<Option<Vec<u8>>>) {
    let c: Vec<Option<Vec<u8>>> =
        sqlx::query_scalar("SELECT pre_seal_signature FROM claim_encryption WHERE claim_id = $1")
            .bind(claim)
            .fetch_all(&mut *conn)
            .await
            .expect("read claim_encryption as the app role");
    let e: Vec<Option<Vec<u8>>> = sqlx::query_scalar(
        "SELECT pre_seal_signature FROM evidence_encryption WHERE evidence_id = $1",
    )
    .bind(evidence)
    .fetch_all(&mut *conn)
    .await
    .expect("read evidence_encryption as the app role");
    (c, e)
}

// =========================================================================
// Tests
// =========================================================================

/// The seal re-signs the claim over the ciphertext digest, unsigns the
/// evidence row, and moves both originals into the ciphertext rows.
#[sqlx::test(migrations = "../../migrations")]
async fn a_seal_resigns_the_claim_and_stashes_both_originals(pool: PgPool) {
    let world = seed_world(&pool).await;
    let (claim, evidence) = seed_claim(&pool, &world, "a finding about a solvent", true).await;
    let (plain_hash, original, original_signer) = claim_signature(&pool, claim).await;
    let (ev_original, ev_signer) = evidence_signature(&pool, evidence).await;
    assert!(
        verifies(
            &world.author_key,
            SignedEntity::Claim,
            &plain_hash,
            original.as_ref()
        ),
        "CALIBRATION: the seeded claim signature verifies over the plaintext digest"
    );
    assert_eq!(original_signer, Some(world.author));
    assert!(ev_original.is_some() && ev_signer == Some(world.author));

    let item = seal_item(claim, evidence);
    let sealed = seal(
        &pool,
        &world,
        std::slice::from_ref(&item),
        Some(server_key(&world)),
    )
    .await;
    assert_eq!(sealed, vec![claim]);

    let (hash, signature, signer) = claim_signature(&pool, claim).await;
    assert_eq!(hash, item.content_hash, "the digest is the ciphertext's");
    assert!(
        verifies(
            &world.server,
            SignedEntity::Claim,
            &hash,
            signature.as_ref()
        ),
        "the sealed claim's signature must verify under the server key over the ciphertext \
         digest"
    );
    assert_eq!(signer, Some(world.server_id), "signed as the server signer");
    assert_ne!(signature, original, "the original is off the row");
    assert!(
        !verifies(
            &world.author_key,
            SignedEntity::Claim,
            &plain_hash,
            signature.as_ref()
        ),
        "the row no longer confirms the plaintext digest"
    );

    assert_eq!(
        claim_stash(&pool, claim).await,
        (original.clone(), original_signer, true),
        "the claim's ciphertext row holds the original signature and signer"
    );
    assert_eq!(
        evidence_signature(&pool, evidence).await,
        (None, None),
        "the sealed evidence row carries no signature over its plaintext digest"
    );
    assert_eq!(
        evidence_stash(&pool, evidence).await,
        (ev_original, ev_signer, true),
        "the evidence's ciphertext row holds its original signature and signer"
    );
}

/// The stash is readable on the application role by a member of the sealing
/// group and by nobody else.
#[sqlx::test(migrations = "../../migrations")]
async fn only_a_member_of_the_sealing_group_reads_the_stash(pool: PgPool) {
    let world = seed_world(&pool).await;
    let (claim, evidence) = seed_claim(&pool, &world, "a finding about a membrane", true).await;
    let (_, original, _) = claim_signature(&pool, claim).await;
    let (ev_original, _) = evidence_signature(&pool, evidence).await;
    seal(
        &pool,
        &world,
        &[seal_item(claim, evidence)],
        Some(server_key(&world)),
    )
    .await;

    let mut member = app_conn_as(&pool, world.author).await;
    let (c, e) = read_stash(&mut member, claim, evidence).await;
    assert_eq!(
        (c, e),
        (vec![original], vec![ev_original]),
        "POSITIVE CONTROL: a member of the sealing group reads the stash"
    );

    let mut outsider = app_conn_as(&pool, world.outsider).await;
    let (c, e) = read_stash(&mut outsider, claim, evidence).await;
    assert!(
        c.is_empty() && e.is_empty(),
        "a non-member must read no stash row: claim {c:?}, evidence {e:?}"
    );
}

/// Seal then unseal restores the claim's and the evidence's signature and
/// signer byte for byte, and the originals verify over the restored digests.
#[sqlx::test(migrations = "../../migrations")]
async fn seal_then_unseal_restores_the_original_signatures_byte_for_byte(pool: PgPool) {
    let world = seed_world(&pool).await;
    let content = "a finding about a ligand";
    let (claim, evidence) = seed_claim(&pool, &world, content, true).await;
    let before = claim_signature(&pool, claim).await;
    let ev_before = evidence_signature(&pool, evidence).await;

    seal(
        &pool,
        &world,
        &[seal_item(claim, evidence)],
        Some(server_key(&world)),
    )
    .await;
    assert_ne!(
        claim_signature(&pool, claim).await,
        before,
        "CALIBRATION: the seal changed the row"
    );

    let restored = unseal(&pool, &world, &[unseal_item(claim, evidence, content)]).await;
    assert_eq!(restored, vec![claim]);

    let after = claim_signature(&pool, claim).await;
    assert_eq!(
        after, before,
        "content_hash, signature and signer_id are byte-identical"
    );
    assert!(verifies(
        &world.author_key,
        SignedEntity::Claim,
        &after.0,
        after.1.as_ref()
    ));
    let ev_after = evidence_signature(&pool, evidence).await;
    assert_eq!(ev_after, ev_before, "the evidence signature is back");
    let ev_hash: Vec<u8> = sqlx::query_scalar("SELECT content_hash FROM evidence WHERE id = $1")
        .bind(evidence)
        .fetch_one(&pool)
        .await
        .expect("read the evidence digest");
    assert!(verifies(
        &world.author_key,
        SignedEntity::Evidence,
        &ev_hash,
        ev_after.0.as_ref()
    ));

    let left: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM claim_encryption WHERE claim_id = $1) \
              + (SELECT count(*) FROM evidence_encryption WHERE evidence_id = $2)",
    )
    .bind(claim)
    .bind(evidence)
    .fetch_one(&pool)
    .await
    .expect("count ciphertext rows");
    assert_eq!(left, 0, "the ciphertext rows, stash and all, are gone");
}

/// An original that was unsigned comes back unsigned: the server's signature
/// over the ciphertext digest must not survive the unseal.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unsigned_original_comes_back_unsigned(pool: PgPool) {
    let world = seed_world(&pool).await;
    let content = "an unsigned finding";
    let (claim, evidence) = seed_claim(&pool, &world, content, false).await;

    seal(
        &pool,
        &world,
        &[seal_item(claim, evidence)],
        Some(server_key(&world)),
    )
    .await;
    let (_, sealed_sig, sealed_signer) = claim_signature(&pool, claim).await;
    assert!(
        sealed_sig.is_some() && sealed_signer == Some(world.server_id),
        "CALIBRATION: the sealed row carries the server signature"
    );
    assert_eq!(claim_stash(&pool, claim).await, (None, None, true));

    unseal(&pool, &world, &[unseal_item(claim, evidence, content)]).await;
    let (_, signature, signer) = claim_signature(&pool, claim).await;
    assert_eq!((signature, signer), (None, None));
    assert_eq!(evidence_signature(&pool, evidence).await, (None, None));
}

/// With no key configured the sealed claim is left unsigned (not carrying
/// its plaintext-digest signature), and unseal restores the original.
#[sqlx::test(migrations = "../../migrations")]
async fn a_seal_without_a_key_leaves_the_sealed_claim_unsigned(pool: PgPool) {
    let world = seed_world(&pool).await;
    let content = "a finding sealed with no server key";
    let (claim, evidence) = seed_claim(&pool, &world, content, true).await;
    let before = claim_signature(&pool, claim).await;

    seal(&pool, &world, &[seal_item(claim, evidence)], None).await;
    let (_, signature, signer) = claim_signature(&pool, claim).await;
    assert_eq!(
        (signature, signer),
        (None, None),
        "no key: the sealed row is unsigned"
    );
    assert_eq!(
        claim_stash(&pool, claim).await,
        (before.1.clone(), before.2, true)
    );

    unseal(&pool, &world, &[unseal_item(claim, evidence, content)]).await;
    assert_eq!(claim_signature(&pool, claim).await, before);
}

/// A re-delivered seal-commit is a no-op: the stash keeps the ORIGINAL, not
/// the server signature the first delivery wrote.
#[sqlx::test(migrations = "../../migrations")]
async fn a_redelivered_seal_keeps_the_first_stash(pool: PgPool) {
    let world = seed_world(&pool).await;
    let content = "a finding sealed twice";
    let (claim, evidence) = seed_claim(&pool, &world, content, true).await;
    let before = claim_signature(&pool, claim).await;
    let item = seal_item(claim, evidence);

    assert_eq!(
        seal(
            &pool,
            &world,
            std::slice::from_ref(&item),
            Some(server_key(&world))
        )
        .await,
        vec![claim]
    );
    let first = claim_signature(&pool, claim).await;
    assert!(
        seal(
            &pool,
            &world,
            std::slice::from_ref(&item),
            Some(server_key(&world))
        )
        .await
        .is_empty(),
        "the second delivery seals nothing"
    );
    assert_eq!(claim_signature(&pool, claim).await, first);
    assert_eq!(
        claim_stash(&pool, claim).await,
        (before.1.clone(), before.2, true)
    );

    unseal(&pool, &world, &[unseal_item(claim, evidence, content)]).await;
    assert_eq!(claim_signature(&pool, claim).await, before);
}

/// A row sealed WITHOUT the stash (before 357, or by an older binary) still
/// carries its original signature; unseal must leave it there rather than
/// restore the empty stash over it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_row_sealed_without_the_stash_keeps_its_signature_through_unseal(pool: PgPool) {
    let world = seed_world(&pool).await;
    let content = "a finding sealed before the stash";
    let (claim, evidence) = seed_claim(&pool, &world, content, true).await;
    let before = claim_signature(&pool, claim).await;
    let ev_before = evidence_signature(&pool, evidence).await;

    seal(&pool, &world, &[seal_item(claim, evidence)], None).await;
    // The shape a pre-357 seal leaves: no stash, the signature on the rows.
    sqlx::query(
        "UPDATE claim_encryption SET pre_seal_signature = NULL, pre_seal_signer_id = NULL, \
                pre_seal_stashed = false WHERE claim_id = $1",
    )
    .bind(claim)
    .execute(&pool)
    .await
    .expect("drop the claim stash");
    sqlx::query(
        "UPDATE evidence_encryption SET pre_seal_signature = NULL, pre_seal_signer_id = NULL, \
                pre_seal_stashed = false WHERE evidence_id = $1",
    )
    .bind(evidence)
    .execute(&pool)
    .await
    .expect("drop the evidence stash");
    sqlx::query("UPDATE claims SET signature = $2, signer_id = $3 WHERE id = $1")
        .bind(claim)
        .bind(&before.1)
        .bind(before.2)
        .execute(&pool)
        .await
        .expect("put the original back on the claim");
    sqlx::query("UPDATE evidence SET signature = $2, signer_id = $3 WHERE id = $1")
        .bind(evidence)
        .bind(&ev_before.0)
        .bind(ev_before.1)
        .execute(&pool)
        .await
        .expect("put the original back on the evidence");

    unseal(&pool, &world, &[unseal_item(claim, evidence, content)]).await;
    assert_eq!(claim_signature(&pool, claim).await, before);
    assert_eq!(evidence_signature(&pool, evidence).await, ev_before);
}

/// `docs/runbooks/357-undo.sql` copies every stashed original back onto its
/// row and drops the columns; a second run changes nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn the_357_undo_puts_the_originals_back_and_drops_the_columns(pool: PgPool) {
    let world = seed_world(&pool).await;
    let (claim, evidence) = seed_claim(&pool, &world, "a finding sealed before undo", true).await;
    let before = claim_signature(&pool, claim).await;
    let ev_before = evidence_signature(&pool, evidence).await;
    seal(
        &pool,
        &world,
        &[seal_item(claim, evidence)],
        Some(server_key(&world)),
    )
    .await;
    assert_eq!(
        claim_signature(&pool, claim).await.2,
        Some(world.server_id),
        "CALIBRATION: the seal re-signed the claim"
    );

    let undo = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/runbooks/357-undo.sql"
    ))
    .expect("read the undo runbook");
    for run in ["first", "second"] {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the {run} run of the undo applies: {e}"));
    }

    let (hash, signature, signer) = claim_signature(&pool, claim).await;
    assert_eq!(
        (signature.clone(), signer),
        (before.1, before.2),
        "the original signature is back on the sealed claim"
    );
    assert_ne!(hash, before.0, "the claim is still sealed");
    assert_eq!(evidence_signature(&pool, evidence).await, ev_before);
    let columns: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.columns \
          WHERE table_schema = 'public' \
            AND table_name IN ('claim_encryption', 'evidence_encryption') \
            AND column_name LIKE 'pre_seal_%'",
    )
    .fetch_one(&pool)
    .await
    .expect("count stash columns");
    assert_eq!(columns, 0, "the undo drops all six columns");
}
