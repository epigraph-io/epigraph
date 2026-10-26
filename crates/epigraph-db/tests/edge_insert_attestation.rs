//! Ruling R-50: structural verb-edges are signed AT INSERT. The insert
//! primitives take the writer's key (`EdgeSigningKey`), the writer chooses the
//! edge's `id` and `created_at`, and the row carries its attestation digest,
//! the v1 edge signature and `signer_id` from the INSERT on.
//!
//! Why INSERT time: a world-owned structural edge (an `agent` endpoint is
//! outside migration 120's writer scope) cannot be UPDATEd by an application
//! session (migration 117), so signing it after the fact
//! (`EdgeSignatureRepository::sign_created_edge_conn`) signs nothing. The
//! first test pins that contrast on the non-bypassing `epigraph_app` role,
//! stamped as `ScopedPool::begin_as` stamps a session.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_crypto::{AgentSigner, SignatureScheme};
use epigraph_db::repos::edge::EdgeRepository;
use epigraph_db::repos::edge_signature::{
    EdgeSignOutcome, EdgeSignatureCheck, EdgeSignatureRepository, EdgeSigningKey,
};
use epigraph_db::visibility::Viewer;
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

const WORLD: Uuid = Uuid::nil();

fn csv(ids: &[Uuid]) -> String {
    ids.iter()
        .map(Uuid::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// Stamp `conn` for `agent` exactly as `ScopedPool::begin_as` would.
async fn stamp(conn: &mut PgConnection, pool: &PgPool, agent: Uuid) {
    let v = Viewer::resolve(pool, agent).await.expect("resolve viewer");
    let groups = csv(v.group_bind().expect("scoped viewer"));
    let writable = csv(v.writable_groups());
    sqlx::query(
        "SELECT set_config('epigraph.group_ids', $1, false), \
                set_config('epigraph.writable_group_ids', $2, false), \
                set_config('epigraph.principal_id', $3, false)",
    )
    .bind(groups)
    .bind(writable)
    .bind(agent.to_string())
    .execute(&mut *conn)
    .await
    .expect("stamp");
}

/// An agent with a personal group whose registered key IS `signer`'s.
async fn seed_signer_agent(pool: &PgPool, label: &str, signer: &AgentSigner) -> Uuid {
    let (agent, _) = fixture::seed_agent_with_group(pool, label).await;
    sqlx::query("UPDATE agents SET public_key = $2 WHERE id = $1")
        .bind(agent)
        .bind(signer.public_key().as_slice())
        .execute(pool)
        .await
        .expect("register the signer's key");
    agent
}

async fn verify(pool: &PgPool, edge: Uuid) -> EdgeSignatureCheck {
    let viewer = fixture::public_viewer(pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    EdgeSignatureRepository::verify_conn(&mut conn, &viewer, edge)
        .await
        .expect("verify")
        .expect("the edge is readable")
}

/// Signed, valid as v1, the row matches its digest, and attested by `signer`.
fn assert_attested(check: &EdgeSignatureCheck, signer: Uuid, what: &str) {
    assert!(check.signed && check.signature_valid, "{what}: {check:?}");
    assert_eq!(
        check.signature_scheme,
        Some(SignatureScheme::V1),
        "{what}: {check:?}"
    );
    assert_eq!(check.content_matches, Some(true), "{what}: {check:?}");
    assert_eq!(check.signer_id, Some(signer), "{what}: {check:?}");
    assert!(!check.pre_attestation, "{what}: {check:?}");
}

async fn stored_attestation(pool: &PgPool, edge: Uuid) -> (Option<Vec<u8>>, Option<Uuid>) {
    sqlx::query_as("SELECT signature, signer_id FROM edges WHERE id = $1")
        .bind(edge)
        .fetch_one(pool)
        .await
        .expect("edge row")
}

/// A world-owned structural edge (`agent -AUTHORED-> claim`) written on an
/// application session: signing it afterwards is refused by row security
/// (`NotSignable`, nothing written), and the same edge written through the
/// signed primitive carries a verifying v1 attestation by the writer's key.
#[sqlx::test(migrations = "../../migrations")]
async fn a_world_owned_structural_edge_is_signed_at_insert_and_only_there(pool: PgPool) {
    let key = AgentSigner::from_bytes(&[0x51; 32]).expect("signer");
    let w = seed_signer_agent(&pool, "r50-world", &key).await;
    let claim = fixture::seed_public_claim(&pool, w, "R-50: a claim W authored").await;

    let p = pool.clone();
    let w_viewer = Viewer::resolve(&pool, w).await.expect("W's viewer");
    let k = AgentSigner::from_bytes(&[0x51; 32]).expect("signer");
    let (after_the_fact, outcome, at_insert) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            stamp(&mut conn, &p, w).await;
            let after_the_fact = EdgeRepository::create_signed_conn(
                &mut conn, None, w, "agent", claim, "claim", "AUTHORED", None, None, None,
            )
            .await
            .expect("W writes the structural edge");
            let outcome = EdgeSignatureRepository::sign_created_edge_conn(
                &mut conn,
                &w_viewer,
                after_the_fact,
                &k,
                w,
            )
            .await
            .expect("sign after the fact");
            let at_insert = EdgeRepository::create_signed_conn(
                &mut conn,
                Some(EdgeSigningKey {
                    signer: &k,
                    signer_id: w,
                }),
                w,
                "agent",
                claim,
                "claim",
                "AUTHORED",
                Some(serde_json::json!({"tool": "r50"})),
                None,
                None,
            )
            .await
            .expect("W writes the structural edge, attested at INSERT");
            (conn, (after_the_fact, outcome, at_insert))
        })
        .await;

    let owner: Uuid = sqlx::query_scalar("SELECT owner_group_id FROM edges WHERE id = $1")
        .bind(at_insert)
        .fetch_one(&pool)
        .await
        .expect("owner");
    assert_eq!(
        owner, WORLD,
        "calibration: the structural edge is world-owned"
    );
    assert_eq!(
        outcome,
        EdgeSignOutcome::NotSignable,
        "calibration: a world-owned edge cannot be signed after its INSERT"
    );
    assert_eq!(
        stored_attestation(&pool, after_the_fact).await,
        (None, None)
    );
    assert_attested(&verify(&pool, at_insert).await, w, "signed at INSERT");
}

/// Every signed twin attests the edge it INSERTS, and a dedup hit returns the
/// existing row without writing onto it.
#[sqlx::test(migrations = "../../migrations")]
async fn every_signed_primitive_attests_its_insert_and_not_a_dedup_hit(pool: PgPool) {
    let signer = AgentSigner::from_bytes(&[0x52; 32]).expect("signer");
    let s = seed_signer_agent(&pool, "r50-primitives", &signer).await;
    let key = Some(EdgeSigningKey {
        signer: &signer,
        signer_id: s,
    });
    let c: Vec<Uuid> = {
        let mut v = Vec::new();
        for i in 0..8 {
            v.push(fixture::seed_public_claim(&pool, s, &format!("R-50 primitive {i}")).await);
        }
        v
    };
    let paper: Uuid = sqlx::query_scalar(
        "INSERT INTO papers (doi, title) VALUES ('10.9999/r50', 'R-50') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("seed paper");
    let mut conn = pool.acquire().await.expect("conn");

    // create_if_not_exists_signed_conn, then a dedup hit.
    let (row, created) = EdgeRepository::create_if_not_exists_signed_conn(
        &mut conn,
        key,
        c[0],
        "claim",
        c[1],
        "claim",
        "supports",
        Some(serde_json::json!({"n": 1})),
        None,
        None,
    )
    .await
    .expect("insert");
    assert!(created);
    assert_attested(&verify(&pool, row.id).await, s, "create_if_not_exists");
    let before = stored_attestation(&pool, row.id).await;
    let (again, created) = EdgeRepository::create_if_not_exists_signed_conn(
        &mut conn, key, c[0], "claim", c[1], "claim", "supports", None, None, None,
    )
    .await
    .expect("dedup");
    assert!(!created && again.id == row.id);
    assert_eq!(stored_attestation(&pool, row.id).await, before);

    // create_if_absent_including_retracted_signed_conn.
    let (row, created) = EdgeRepository::create_if_absent_including_retracted_signed_conn(
        &mut conn,
        key,
        c[2],
        "claim",
        c[3],
        "claim",
        "decomposes_to",
        None,
        Some(chrono::Utc::now()),
        None,
    )
    .await
    .expect("insert");
    assert!(created);
    assert_attested(
        &verify(&pool, row.id).await,
        s,
        "create_if_absent_including_retracted (with valid_from)",
    );

    // create_processed_by_stamp_if_absent_signed_conn.
    assert!(
        EdgeRepository::create_processed_by_stamp_if_absent_signed_conn(
            &mut conn, key, paper, s, "r50:v1", "r50",
        )
        .await
        .expect("stamp")
    );
    let stamp_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM edges WHERE source_id = $1 AND relationship = 'processed_by'",
    )
    .bind(paper)
    .fetch_one(&pool)
    .await
    .expect("stamp row");
    assert_attested(&verify(&pool, stamp_id).await, s, "processed_by stamp");

    // The symmetric family: returning, oriented, row; each then deduped from
    // the reverse direction.
    let (id, created) = EdgeRepository::create_symmetric_if_absent_returning_signed_conn(
        &mut conn,
        key,
        c[4],
        c[5],
        "alternative_of",
        serde_json::json!({}),
    )
    .await
    .expect("returning");
    assert!(created);
    assert_attested(&verify(&pool, id).await, s, "symmetric returning");
    let before = stored_attestation(&pool, id).await;
    let (again, created) = EdgeRepository::create_symmetric_if_absent_returning_signed_conn(
        &mut conn,
        key,
        c[5],
        c[4],
        "alternative_of",
        serde_json::json!({}),
    )
    .await
    .expect("returning dedup");
    assert!(!created && again == id);
    assert_eq!(stored_attestation(&pool, id).await, before);

    let up = EdgeRepository::create_symmetric_if_absent_oriented_signed_conn(
        &mut conn,
        key,
        c[6],
        c[7],
        "contradicts",
        serde_json::json!({"strength": 0.5}),
    )
    .await
    .expect("oriented");
    assert!(up.was_created && up.source_id == c[6] && up.target_id == c[7]);
    assert_attested(&verify(&pool, up.edge_id).await, s, "symmetric oriented");
    let reverse = EdgeRepository::create_symmetric_if_absent_oriented_signed_conn(
        &mut conn,
        key,
        c[7],
        c[6],
        "contradicts",
        serde_json::json!({}),
    )
    .await
    .expect("oriented dedup");
    assert!(!reverse.was_created && reverse.edge_id == up.edge_id);
    assert_eq!(
        (reverse.source_id, reverse.target_id),
        (c[6], c[7]),
        "the stored orientation"
    );

    let (row, created) = EdgeRepository::create_symmetric_if_absent_row_signed_conn(
        &mut conn,
        key,
        c[1],
        c[2],
        "corroborates",
        Some(serde_json::json!({"via": "http"})),
        Some(chrono::Utc::now() - chrono::Duration::days(1)),
        None,
    )
    .await
    .expect("row");
    assert!(created);
    assert_attested(&verify(&pool, row.id).await, s, "symmetric row");
}

/// The signature is over the row AS STORED. A database that rewrites a column
/// on INSERT (here a test trigger that lower-cases `relationship`, as a
/// canonical-spelling rule would) still gets an edge whose signature verifies
/// AND whose row recomputes to its digest; the INSERT is re-made over the
/// stored values rather than leaving a signature over what was sent.
#[sqlx::test(migrations = "../../migrations")]
async fn an_edge_the_database_rewrites_is_signed_over_what_it_stores(pool: PgPool) {
    sqlx::query(
        "CREATE FUNCTION test_lower_relationship() RETURNS trigger LANGUAGE plpgsql AS \
         $$ BEGIN NEW.relationship := lower(NEW.relationship); RETURN NEW; END $$",
    )
    .execute(&pool)
    .await
    .expect("trigger fn");
    sqlx::query(
        "CREATE TRIGGER test_lower_relationship BEFORE INSERT ON edges \
         FOR EACH ROW EXECUTE FUNCTION test_lower_relationship()",
    )
    .execute(&pool)
    .await
    .expect("trigger");

    let signer = AgentSigner::from_bytes(&[0x53; 32]).expect("signer");
    let s = seed_signer_agent(&pool, "r50-normalised", &signer).await;
    let a = fixture::seed_public_claim(&pool, s, "R-50 normalised A").await;
    let b = fixture::seed_public_claim(&pool, s, "R-50 normalised B").await;
    let mut conn = pool.acquire().await.expect("conn");
    let id = EdgeRepository::create_signed_conn(
        &mut conn,
        Some(EdgeSigningKey {
            signer: &signer,
            signer_id: s,
        }),
        a,
        "claim",
        b,
        "claim",
        "Supports",
        Some(serde_json::json!({"x": -0.0, "big": 1e300})),
        None,
        None,
    )
    .await
    .expect("insert");
    let rel: String = sqlx::query_scalar("SELECT relationship::text FROM edges WHERE id = $1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .expect("relationship");
    assert_eq!(rel, "supports", "calibration: the trigger rewrote the row");
    assert_attested(&verify(&pool, id).await, s, "rewritten on INSERT");
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM edges WHERE source_id = $1")
        .bind(a)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(n, 1, "the first attempt was rolled back, not left behind");
}
