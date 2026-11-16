//! Every evidence write stores the evidence's edge to its claim, in the same
//! transaction (backlog 2d60f619).
//!
//! The Atlas leaf view draws stored `evidence -> claim` edges only (no derived
//! edge, by operator ruling), so the repository's evidence writers
//! (`create`, `create_with_source_url`, `batch_create`,
//! `record_derivation_conn`) each write it through
//! `EvidenceRepository::link_to_claims_signed_conn`. What each test pins:
//!
//! * the edge exists after each writer, with the canonical relationship of the
//!   direction it was given, and a tenancy never wider than the evidence row
//!   (on a group claim, on a public claim, and on the APPLICATION ROLE for a
//!   writer attaching to another group's public claim);
//! * a refused duplicate writes no edge;
//! * the helper refuses an empty claim list and writes nothing;
//! * it is idempotent across spellings: a legacy upper-case `SUPPORTS` edge is
//!   found, not duplicated, and a retracted edge is never resurrected;
//! * a writer with a key attests the edge.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_core::{AgentId, ClaimId, Evidence, EvidenceType};
use epigraph_crypto::AgentSigner;
use epigraph_db::repos::edge_signature::{EdgeSignatureRepository, EdgeSigningKey};
use epigraph_db::visibility::Viewer;
use epigraph_db::{
    DbError, DerivationEvidence, EvidenceDirection, EvidenceEdge, EvidenceRepository,
};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

fn digest(body: &str) -> [u8; 32] {
    *blake3::hash(body.as_bytes()).as_bytes()
}

fn document(agent: Uuid, claim: Uuid, body: &str) -> Evidence {
    Evidence::new(
        AgentId::from_uuid(agent),
        [0u8; 32],
        digest(body),
        EvidenceType::Document {
            source_url: None,
            mime_type: "text/plain".to_string(),
            checksum: None,
        },
        Some(body.to_string()),
        ClaimId::from_uuid(claim),
    )
}

/// One stored edge out of an evidence row:
/// `(target_id, relationship, owner_group_id, visibility, co_owner_group_id)`.
type EdgeShape = (Uuid, String, Uuid, String, Option<Uuid>);

/// Every edge (any relationship, any state) from `evidence` to a claim.
async fn edges_from(pool: &PgPool, evidence: Uuid) -> Vec<EdgeShape> {
    sqlx::query_as(
        "SELECT target_id, relationship, owner_group_id, visibility::text, co_owner_group_id \
           FROM edges \
          WHERE source_type = 'evidence' AND source_id = $1 AND target_type = 'claim' \
          ORDER BY target_id, relationship",
    )
    .bind(evidence)
    .fetch_all(pool)
    .await
    .expect("read the evidence's edges")
}

/// `(owner_group_id, visibility)` of an evidence row.
async fn evidence_tenancy(pool: &PgPool, evidence: Uuid) -> (Uuid, String) {
    sqlx::query_as("SELECT owner_group_id, visibility::text FROM evidence WHERE id = $1")
        .bind(evidence)
        .fetch_one(pool)
        .await
        .expect("read the evidence's tenancy")
}

/// Assert `evidence` has exactly one edge, to `claim`, with `relationship`,
/// and the evidence row's own tenancy (never wider).
async fn assert_one_edge(pool: &PgPool, evidence: Uuid, claim: Uuid, relationship: &str) {
    let edges = edges_from(pool, evidence).await;
    let (owner, visibility) = evidence_tenancy(pool, evidence).await;
    assert_eq!(
        edges,
        vec![(claim, relationship.to_string(), owner, visibility, None)],
        "exactly one evidence -> claim `{relationship}` edge, with the evidence row's tenancy"
    );
}

/// Stamp `conn` with `agent`'s real viewer, the way `ScopedPool` does.
async fn stamp(conn: &mut PgConnection, pool: &PgPool, agent: Uuid) {
    let v = Viewer::resolve(pool, agent).await.expect("resolve viewer");
    let csv = |ids: &[Uuid]| {
        ids.iter()
            .map(Uuid::to_string)
            .collect::<Vec<_>>()
            .join(",")
    };
    sqlx::query(
        "SELECT set_config('epigraph.group_ids', $1, false), \
                set_config('epigraph.writable_group_ids', $2, false), \
                set_config('epigraph.principal_id', $3, false)",
    )
    .bind(csv(v.group_bind().expect("a scoped viewer")))
    .bind(csv(v.writable_groups()))
    .bind(agent.to_string())
    .execute(&mut *conn)
    .await
    .expect("stamp session gucs");
}

async fn edge_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM edges WHERE source_type = 'evidence'")
        .fetch_one(pool)
        .await
        .expect("count edges")
}

#[sqlx::test(migrations = "../../migrations")]
async fn create_writes_one_supports_edge_with_the_evidence_tenancy(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "ev-edge-group").await;
    let private = fixture::seed_group_claim(&pool, agent, group, "a group claim").await;
    let public = fixture::seed_public_claim(&pool, agent, "a public claim").await;

    let on_private = EvidenceRepository::create(
        &pool,
        &document(agent, private, "evidence on a group claim"),
        EvidenceEdge::supports(None),
    )
    .await
    .expect("evidence on the group claim");
    assert_one_edge(&pool, on_private.id.as_uuid(), private, "supports").await;
    assert_eq!(
        evidence_tenancy(&pool, on_private.id.as_uuid()).await,
        (group, "group".to_string()),
        "control: the evidence inherits its group claim's tenancy"
    );

    let on_public = EvidenceRepository::create_with_source_url(
        &pool,
        &document(agent, public, "evidence on a public claim"),
        Some("https://example.org/source"),
        EvidenceEdge::supports(None),
    )
    .await
    .expect("evidence on the public claim");
    assert_one_edge(&pool, on_public.id.as_uuid(), public, "supports").await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn refutes_direction_is_stored_as_refutes(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "ev-edge-refutes").await;
    let claim = fixture::seed_public_claim(&pool, agent, "a refuted claim").await;
    let ev = EvidenceRepository::create(
        &pool,
        &document(agent, claim, "evidence against"),
        EvidenceEdge::new(None, false),
    )
    .await
    .expect("evidence against the claim");
    assert_one_edge(&pool, ev.id.as_uuid(), claim, "refutes").await;
    assert_eq!(
        EvidenceDirection::from_supports(true).relationship(),
        "supports"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn batch_create_writes_an_edge_per_row(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "ev-edge-batch").await;
    let a = fixture::seed_group_claim(&pool, agent, group, "batch claim a").await;
    let b = fixture::seed_public_claim(&pool, agent, "batch claim b").await;
    let rows = EvidenceRepository::batch_create(
        &pool,
        &[
            document(agent, a, "batch one"),
            document(agent, a, "batch two"),
            document(agent, b, "batch three"),
        ],
        EvidenceEdge::supports(None),
    )
    .await
    .expect("the batch lands");
    assert_eq!(rows.len(), 3);
    for row in rows {
        assert_one_edge(&pool, row.id.as_uuid(), row.claim_id.as_uuid(), "supports").await;
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn derivation_provenance_writes_a_supports_edge(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "ev-edge-derivation").await;
    let parent = fixture::seed_public_claim(&pool, agent, "the parent states the atom").await;
    let atom = fixture::seed_public_claim(&pool, agent, "the atom").await;
    let viewer = fixture::public_viewer(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let recorded =
        EvidenceRepository::record_derivation_conn(&mut conn, &viewer, None, atom, parent, "t")
            .await
            .expect("the derivation write");
    let DerivationEvidence::Recorded(id) = recorded else {
        panic!("expected a recorded derivation row, got {recorded:?}");
    };
    assert_one_edge(&pool, id, atom, "supports").await;

    // A re-applied derivation writes neither a row nor a second edge.
    let again =
        EvidenceRepository::record_derivation_conn(&mut conn, &viewer, None, atom, parent, "t")
            .await
            .expect("the re-applied derivation");
    assert_eq!(again, DerivationEvidence::AlreadyPresent);
    assert_one_edge(&pool, id, atom, "supports").await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_refused_duplicate_writes_no_edge(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "ev-edge-dup").await;
    let claim = fixture::seed_public_claim(&pool, agent, "a claim").await;
    EvidenceRepository::create(
        &pool,
        &document(agent, claim, "the same body"),
        EvidenceEdge::supports(None),
    )
    .await
    .expect("the first write");
    let before = edge_count(&pool).await;
    let dup = EvidenceRepository::create(
        &pool,
        &document(agent, claim, "the same body"),
        EvidenceEdge::supports(None),
    )
    .await;
    assert!(
        matches!(dup, Err(DbError::DuplicateKey { .. })),
        "a same-tenancy duplicate is refused: {dup:?}"
    );
    assert_eq!(edge_count(&pool).await, before, "and writes no edge");
}

#[sqlx::test(migrations = "../../migrations")]
async fn no_claim_is_refused_and_writes_nothing(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "ev-edge-noclaim").await;
    let claim = fixture::seed_public_claim(&pool, agent, "a claim").await;
    let evidence = fixture::seed_evidence(&pool, claim, "document").await;
    let before = edge_count(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let refused = EvidenceRepository::link_to_claims_signed_conn(
        &mut conn,
        None,
        evidence,
        &[],
        EvidenceDirection::Supports,
    )
    .await;
    assert!(
        matches!(&refused, Err(DbError::InvalidData { reason }) if reason.contains("no claim")),
        "evidence that applies to no claim is refused: {refused:?}"
    );
    assert_eq!(edge_count(&pool).await, before, "nothing was written");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_legacy_upper_case_edge_is_not_duplicated_and_a_retracted_one_stays_retracted(
    pool: PgPool,
) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "ev-edge-legacy").await;
    let claim = fixture::seed_public_claim(&pool, agent, "a claim").await;
    // Raw rows, as a writer before this change left them: no edge, or a legacy
    // upper-case one.
    let legacy = fixture::seed_evidence(&pool, claim, "document").await;
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'evidence', $2, 'claim', 'SUPPORTS')",
    )
    .bind(legacy)
    .bind(claim)
    .execute(&pool)
    .await
    .expect("seed a legacy SUPPORTS edge");
    let retracted = fixture::seed_evidence(&pool, claim, "observation").await;
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            valid_to) \
         VALUES ($1, 'evidence', $2, 'claim', 'supports', now() - interval '1 day')",
    )
    .bind(retracted)
    .bind(claim)
    .execute(&pool)
    .await
    .expect("seed a retracted edge");

    let mut conn = pool.acquire().await.expect("acquire");
    for evidence in [legacy, retracted] {
        for _ in 0..2 {
            let links = EvidenceRepository::link_to_claims_signed_conn(
                &mut conn,
                None,
                evidence,
                &[claim, claim],
                EvidenceDirection::Supports,
            )
            .await
            .expect("link");
            assert_eq!(links.len(), 1, "one link per distinct claim");
            assert!(
                !links[0].created,
                "the existing edge is found, not duplicated"
            );
        }
    }
    assert_eq!(
        edges_from(&pool, legacy).await.len(),
        1,
        "the legacy edge is the only one"
    );
    let still_retracted: bool = sqlx::query_scalar(
        "SELECT valid_to IS NOT NULL AND valid_to <= now() FROM edges WHERE source_id = $1",
    )
    .bind(retracted)
    .fetch_one(&pool)
    .await
    .expect("read the retracted edge");
    assert!(still_retracted, "a retracted edge is never resurrected");
    assert_eq!(edges_from(&pool, retracted).await.len(), 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_signed_writer_attests_the_edge(pool: PgPool) {
    let signer = AgentSigner::from_bytes(&[0x2d; 32]).expect("signer");
    let (s, _) = fixture::seed_agent_with_group(&pool, "ev-edge-signer").await;
    sqlx::query("UPDATE agents SET public_key = $2 WHERE id = $1")
        .bind(s)
        .bind(signer.public_key().as_slice())
        .execute(&pool)
        .await
        .expect("register the signer's key");
    let claim = fixture::seed_public_claim(&pool, s, "a signed claim").await;
    let ev = EvidenceRepository::create(
        &pool,
        &document(s, claim, "signed evidence"),
        EvidenceEdge::supports(Some(EdgeSigningKey {
            signer: &signer,
            signer_id: s,
        })),
    )
    .await
    .expect("signed evidence");
    let edge: Uuid = sqlx::query_scalar("SELECT id FROM edges WHERE source_id = $1")
        .bind(ev.id.as_uuid())
        .fetch_one(&pool)
        .await
        .expect("the edge");
    let viewer = fixture::public_viewer(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let check = EdgeSignatureRepository::verify_conn(&mut conn, &viewer, edge)
        .await
        .expect("verify")
        .expect("readable");
    assert!(
        check.signed && check.signature_valid,
        "the evidence's edge is attested by its writer: {check:?}"
    );
}

/// On the APPLICATION ROLE with real stamps, the edge lands wherever the
/// evidence does: on the writer's own group claim, and on another group's
/// PUBLIC claim (migration 114's attach: the evidence is the writer's), and it
/// is never wider than the evidence row.
#[sqlx::test(migrations = "../../migrations")]
async fn on_the_app_role_the_edge_lands_with_the_evidence_and_is_never_wider(pool: PgPool) {
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "ev-edge-owner").await;
    let (writer, writer_group) = fixture::seed_agent_with_group(&pool, "ev-edge-writer").await;
    let own = fixture::seed_group_claim(&pool, writer, writer_group, "the writer's claim").await;
    let foreign = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES (gen_random_uuid(), 'another group''s public claim', $1, 0.5, $2, true, \
                 'public', $3) RETURNING id",
    )
    .bind(digest("foreign").as_slice())
    .bind(owner)
    .bind(owner_group)
    .fetch_one(&pool)
    .await
    .expect("seed a public claim of another group");

    let p = pool.clone();
    let (on_own, on_foreign) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, writer).await;
        let a = EvidenceRepository::create(
            &mut *conn,
            &document(writer, own, "on my own group claim"),
            EvidenceEdge::supports(None),
        )
        .await;
        let b = EvidenceRepository::create(
            &mut *conn,
            &document(writer, foreign, "on another group's public claim"),
            EvidenceEdge::refutes(None),
        )
        .await;
        (conn, (a, b))
    })
    .await;
    let on_own = on_own.expect("the writer's evidence on its own claim lands");
    let on_foreign = on_foreign.expect("the writer's evidence on a public claim lands");
    assert_one_edge(&pool, on_own.id.as_uuid(), own, "supports").await;
    assert_one_edge(&pool, on_foreign.id.as_uuid(), foreign, "refutes").await;
    let (ev_owner, _) = evidence_tenancy(&pool, on_foreign.id.as_uuid()).await;
    assert_eq!(
        ev_owner, writer_group,
        "control: the attached evidence is the writer's"
    );
}
