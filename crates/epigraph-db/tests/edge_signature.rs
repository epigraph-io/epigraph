//! Edge attestation (backlog `dae795f8`): an edge's writer signs the stored
//! assertion under the v1 EDGE message, and the verifier checks it.
//!
//! The writer arms run on the non-bypassing `epigraph_app` role, stamped the way
//! `ScopedPool::begin_as` stamps a session, because the harness connection is a
//! superuser that bypasses migration 117's owner-scoped UPDATE policy, and "a
//! stranger cannot sign the writer's edge" would pass vacuously on it.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_crypto::{AgentSigner, SignatureScheme, SignedEntity};
use epigraph_db::repos::edge::EdgeRepository;
use epigraph_db::repos::edge_signature::{
    edge_attestation_digest, EdgeSignOutcome, EdgeSignatureRepository,
};
use epigraph_db::visibility::Viewer;
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

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
    assert!(!writable.is_empty(), "a writer with no writable group");
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

/// A writer agent with a personal group whose registered key IS `signer`'s.
async fn seed_signing_writer(pool: &PgPool, label: &str, signer: &AgentSigner) -> Uuid {
    let (agent, _) = fixture::seed_agent_with_group(pool, label).await;
    sqlx::query("UPDATE agents SET public_key = $2 WHERE id = $1")
        .bind(agent)
        .bind(signer.public_key().as_slice())
        .execute(pool)
        .await
        .expect("register the signer's key");
    agent
}

async fn verify(
    pool: &PgPool,
    edge: Uuid,
) -> epigraph_db::repos::edge_signature::EdgeSignatureCheck {
    let viewer = fixture::public_viewer(pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    EdgeSignatureRepository::verify_conn(&mut conn, &viewer, edge)
        .await
        .expect("verify")
        .expect("the edge is readable")
}

/// The writer creates an edge on its stamped app-role session and signs it in
/// the same act. The stored digest is the attestation digest of the stored row,
/// the signature verifies as a v1 EDGE signature, and the row matches.
#[sqlx::test(migrations = "../../migrations")]
async fn a_writer_signs_its_new_edge_and_it_verifies_as_v1(pool: PgPool) {
    let signer = AgentSigner::from_bytes(&[0x71; 32]).expect("signer");
    let w = seed_signing_writer(&pool, "edge-signer-w", &signer).await;
    let a = fixture::seed_public_claim(&pool, w, "attested A").await;
    let b = fixture::seed_public_claim(&pool, w, "attested B").await;

    let p = pool.clone();
    let s = AgentSigner::from_bytes(&[0x71; 32]).expect("signer");
    let w_viewer = Viewer::resolve(&pool, w).await.expect("W's viewer");
    let (edge, outcome) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, w).await;
        let (row, created) = EdgeRepository::create_if_not_exists_conn(
            &mut conn,
            a,
            "claim",
            b,
            "claim",
            "supports",
            Some(serde_json::json!({"run": "2026-10-26", "n": 2})),
            None,
            None,
        )
        .await
        .expect("W writes the edge");
        assert!(created);
        let outcome =
            EdgeSignatureRepository::sign_created_edge_conn(&mut conn, &w_viewer, row.id, &s, w)
                .await
                .expect("sign");
        (conn, (row.id, outcome))
    })
    .await;

    let EdgeSignOutcome::Signed { digest } = outcome else {
        panic!("the writer could not sign its own new edge: {outcome:?}");
    };
    let (stored_hash, signer_id): (Option<Vec<u8>>, Option<Uuid>) =
        sqlx::query_as("SELECT content_hash, signer_id FROM edges WHERE id = $1")
            .bind(edge)
            .fetch_one(&pool)
            .await
            .expect("row");
    assert_eq!(stored_hash.as_deref(), Some(digest.as_slice()));
    assert_eq!(signer_id, Some(w));

    let check = verify(&pool, edge).await;
    assert!(check.signed && check.signature_valid, "{check:?}");
    assert_eq!(
        check.signature_scheme,
        Some(SignatureScheme::V1),
        "{check:?}"
    );
    assert_eq!(check.content_matches, Some(true), "{check:?}");
    assert_eq!(check.key_kind, Some("unattested"), "{check:?}");
}

/// What the attestation binds. After signing, a properties patch and a
/// relationship rewrite each leave the signature valid over the digest it
/// signed and report `content_matches: false`; a retraction (`valid_to`) does
/// not disturb either.
#[sqlx::test(migrations = "../../migrations")]
async fn a_changed_edge_no_longer_matches_its_attestation_and_a_retraction_still_does(
    pool: PgPool,
) {
    // The harness connection is a superuser; sign as the maintenance path does.
    let (_scoped, bypass) = fixture::bypass(&pool).await;
    let signer = AgentSigner::from_bytes(&[0x72; 32]).expect("signer");
    let w = seed_signing_writer(&pool, "edge-signer-t", &signer).await;
    let a = fixture::seed_public_claim(&pool, w, "tamper A").await;
    let b = fixture::seed_public_claim(&pool, w, "tamper B").await;
    let c = fixture::seed_public_claim(&pool, w, "tamper C").await;

    let mut edges = Vec::new();
    for target in [b, c] {
        let mut conn = pool.acquire().await.expect("acquire");
        let id = EdgeRepository::create(
            &mut *conn,
            a,
            "claim",
            target,
            "claim",
            "supports",
            Some(serde_json::json!({"k": "v"})),
            None,
            None,
        )
        .await
        .expect("edge");
        let out =
            EdgeSignatureRepository::sign_created_edge_conn(&mut conn, &bypass, id, &signer, w)
                .await
                .expect("sign");
        assert!(matches!(out, EdgeSignOutcome::Signed { .. }), "{out:?}");
        edges.push(id);
    }

    sqlx::query("UPDATE edges SET valid_to = now() WHERE id = $1")
        .bind(edges[0])
        .execute(&pool)
        .await
        .unwrap();
    let retracted = verify(&pool, edges[0]).await;
    assert_eq!(
        (retracted.signature_valid, retracted.content_matches),
        (true, Some(true)),
        "a retraction is not a change to the attested assertion: {retracted:?}"
    );

    for sql in [
        "UPDATE edges SET properties = '{\"k\": \"w\"}'::jsonb WHERE id = $1",
        "UPDATE edges SET relationship = 'refutes' WHERE id = $1",
    ] {
        sqlx::query("UPDATE edges SET properties = '{\"k\": \"v\"}'::jsonb, relationship = 'supports' WHERE id = $1")
            .bind(edges[1])
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(verify(&pool, edges[1]).await.content_matches, Some(true));
        sqlx::query(sql)
            .bind(edges[1])
            .execute(&pool)
            .await
            .unwrap();
        let check = verify(&pool, edges[1]).await;
        assert_eq!(
            (check.signature_valid, check.content_matches),
            (true, Some(false)),
            "after `{sql}` the row must no longer match what was signed: {check:?}"
        );
    }
}

/// Domain separation at the edge verifier (ruling R-34): a claim- or
/// evidence-tagged signature over the edge's digest is no edge signature; the
/// edge-tagged one verifies as `v1`, and a bare-digest one as `legacy`.
#[sqlx::test(migrations = "../../migrations")]
async fn only_an_edge_tagged_or_legacy_signature_verifies_an_edge(pool: PgPool) {
    // The harness connection is a superuser; sign as the maintenance path does.
    let (_scoped, bypass) = fixture::bypass(&pool).await;
    let signer = AgentSigner::from_bytes(&[0x73; 32]).expect("signer");
    let w = seed_signing_writer(&pool, "edge-signer-x", &signer).await;
    let a = fixture::seed_public_claim(&pool, w, "cross A").await;
    let b = fixture::seed_public_claim(&pool, w, "cross B").await;
    let id = EdgeRepository::create(&pool, a, "claim", b, "claim", "supports", None, None, None)
        .await
        .expect("edge");
    let mut conn = pool.acquire().await.expect("acquire");
    let EdgeSignOutcome::Signed { digest } =
        EdgeSignatureRepository::sign_created_edge_conn(&mut conn, &bypass, id, &signer, w)
            .await
            .expect("sign")
    else {
        panic!("not signed");
    };
    drop(conn);

    for (sig, want) in [
        (signer.sign_entity(SignedEntity::Claim, &digest), None),
        (signer.sign_entity(SignedEntity::Evidence, &digest), None),
        (signer.sign(&digest), Some(SignatureScheme::Legacy)),
        (
            signer.sign_entity(SignedEntity::Edge, &digest),
            Some(SignatureScheme::V1),
        ),
    ] {
        sqlx::query("UPDATE edges SET signature = $2 WHERE id = $1")
            .bind(id)
            .bind(sig.as_slice())
            .execute(&pool)
            .await
            .unwrap();
        let check = verify(&pool, id).await;
        assert_eq!(check.signature_scheme, want, "{check:?}");
        assert_eq!(check.signature_valid, want.is_some(), "{check:?}");
    }
}

/// A LEGACY (bare-digest) edge signature binds no entity type, so it counts
/// only over the row's own attestation digest. A bare-digest signature over
/// some claim's content hash, stored here together with that hash, is refused
/// (security review of this module, finding 2).
#[sqlx::test(migrations = "../../migrations")]
async fn a_legacy_signature_counts_only_over_the_rows_own_digest(pool: PgPool) {
    let signer = AgentSigner::from_bytes(&[0x77; 32]).expect("signer");
    let w = seed_signing_writer(&pool, "edge-legacy", &signer).await;
    let a = fixture::seed_public_claim(&pool, w, "legacy A").await;
    let b = fixture::seed_public_claim(&pool, w, "legacy B").await;
    let id = EdgeRepository::create(&pool, a, "claim", b, "claim", "supports", None, None, None)
        .await
        .expect("edge");
    let claim_hash = epigraph_crypto::ContentHasher::hash(b"some claim's body");
    sqlx::query("UPDATE edges SET content_hash = $2, signature = $3, signer_id = $4 WHERE id = $1")
        .bind(id)
        .bind(claim_hash.as_slice())
        .bind(signer.sign(&claim_hash).as_slice())
        .bind(w)
        .execute(&pool)
        .await
        .unwrap();
    let check = verify(&pool, id).await;
    assert_eq!(check.content_matches, Some(false), "{check:?}");
    assert!(
        !check.signature_valid && check.signature_scheme.is_none(),
        "a bare-digest signature over a claim's hash verified an edge: {check:?}"
    );
}

/// The signer's key must be ADMITTED when the edge was created, by the rule
/// the claim verifier uses (`key_window_admits`): an active or closed-window
/// rotated key verifies; a revoked, pending, not-yet-valid or expired one does
/// not, and a key whose `agent_keys` row refuses it does not come back in as
/// the bare `agents.public_key` (security review of this module, finding 1).
#[sqlx::test(migrations = "../../migrations")]
async fn only_a_key_admitted_at_the_edges_creation_verifies_it(pool: PgPool) {
    // The harness connection is a superuser; sign as the maintenance path does.
    let (_scoped, bypass) = fixture::bypass(&pool).await;
    use chrono::{Duration, Utc};
    let hour = Duration::hours(1);
    let now = Utc::now();
    // (label, status, valid_from, valid_until, key is also agents.public_key, verifies)
    type Case = (
        &'static str,
        &'static str,
        chrono::DateTime<Utc>,
        Option<chrono::DateTime<Utc>>,
        bool,
        bool,
    );
    let cases: [Case; 7] = [
        ("active", "active", now - hour, None, false, true),
        (
            "rotated-closed",
            "rotated",
            now - hour * 2,
            Some(now + hour),
            false,
            true,
        ),
        ("revoked", "revoked", now - hour, None, false, false),
        ("pending", "pending", now - hour, None, false, false),
        ("not-yet-valid", "active", now + hour, None, false, false),
        (
            "expired-before",
            "expired",
            now - hour * 3,
            Some(now - hour * 2),
            false,
            false,
        ),
        (
            "revoked-agent-key",
            "revoked",
            now - hour,
            None,
            true,
            false,
        ),
    ];
    for (i, (label, status, from, until, as_agent_key, want)) in cases.into_iter().enumerate() {
        let key = AgentSigner::from_bytes(&[0x90 + u8::try_from(i).unwrap(); 32]).expect("key");
        let (w, _) = fixture::seed_agent_with_group(&pool, &format!("edge-key-{label}")).await;
        if as_agent_key {
            sqlx::query("UPDATE agents SET public_key = $2 WHERE id = $1")
                .bind(w)
                .bind(key.public_key().as_slice())
                .execute(&pool)
                .await
                .unwrap();
        }
        sqlx::query(
            "INSERT INTO agent_keys (agent_id, public_key, key_type, status, valid_from, valid_until) \
             VALUES ($1, $2, 'signing', $3, $4, $5)",
        )
        .bind(w)
        .bind(key.public_key().as_slice())
        .bind(status)
        .bind(from)
        .bind(until)
        .execute(&pool)
        .await
        .unwrap_or_else(|e| panic!("{label}: seed agent key: {e}"));
        let a = fixture::seed_public_claim(&pool, w, &format!("{label} A")).await;
        let b = fixture::seed_public_claim(&pool, w, &format!("{label} B")).await;
        let id =
            EdgeRepository::create(&pool, a, "claim", b, "claim", "supports", None, None, None)
                .await
                .expect("edge");
        let mut conn = pool.acquire().await.expect("acquire");
        let out = EdgeSignatureRepository::sign_created_edge_conn(&mut conn, &bypass, id, &key, w)
            .await
            .expect("sign");
        assert!(
            matches!(out, EdgeSignOutcome::Signed { .. }),
            "{label}: {out:?}"
        );
        drop(conn);

        let check = verify(&pool, id).await;
        assert_eq!(check.content_matches, Some(true), "{label}: {check:?}");
        assert_eq!(check.signature_valid, want, "{label}: {check:?}");
        assert_eq!(
            check.key_kind,
            want.then_some("signing"),
            "{label}: {check:?}"
        );
    }
}

/// An attestation is never overwritten, and a stranger cannot sign another
/// writer's edge: on the app role the owner-scoped UPDATE policy hides the row
/// from the stranger's `FOR UPDATE`, so it signs nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn a_stranger_cannot_sign_and_a_signature_is_never_overwritten(pool: PgPool) {
    let w_key = AgentSigner::from_bytes(&[0x74; 32]).expect("w");
    let z_key = AgentSigner::from_bytes(&[0x75; 32]).expect("z");
    let w = seed_signing_writer(&pool, "edge-owner-w", &w_key).await;
    let z = seed_signing_writer(&pool, "edge-stranger-z", &z_key).await;
    let a = fixture::seed_public_claim(&pool, w, "owned A").await;
    let b = fixture::seed_public_claim(&pool, w, "owned B").await;

    let p = pool.clone();
    let w_viewer = Viewer::resolve(&pool, w).await.expect("W's viewer");
    let z_viewer = Viewer::resolve(&pool, z).await.expect("Z's viewer");
    let (z_try, z_with_ws_viewer, w_first, w_again) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            stamp(&mut conn, &p, w).await;
            let id = EdgeRepository::create(
                &mut *conn, a, "claim", b, "claim", "supports", None, None, None,
            )
            .await
            .expect("W writes");
            stamp(&mut conn, &p, z).await;
            let z_try = EdgeSignatureRepository::sign_created_edge_conn(
                &mut conn, &z_viewer, id, &z_key, z,
            )
            .await
            .expect("Z's attempt runs");
            // A caller that passes a viewer its session does not hold: the
            // write predicate admits W's group, and row security on Z's
            // stamped session still refuses (defence in depth).
            let z_with_ws_viewer = EdgeSignatureRepository::sign_created_edge_conn(
                &mut conn, &w_viewer, id, &z_key, z,
            )
            .await
            .expect("Z's second attempt runs");
            stamp(&mut conn, &p, w).await;
            let w_first = EdgeSignatureRepository::sign_created_edge_conn(
                &mut conn, &w_viewer, id, &w_key, w,
            )
            .await
            .expect("W signs");
            let w_again = EdgeSignatureRepository::sign_created_edge_conn(
                &mut conn, &w_viewer, id, &w_key, w,
            )
            .await
            .expect("W re-signs");
            (conn, (z_try, z_with_ws_viewer, w_first, w_again))
        })
        .await;

    assert_eq!(
        z_with_ws_viewer,
        EdgeSignOutcome::NotSignable,
        "row security let a stranger's session attest W's edge"
    );
    assert_eq!(
        z_try,
        EdgeSignOutcome::NotSignable,
        "a stranger signed W's edge"
    );
    assert!(
        matches!(w_first, EdgeSignOutcome::Signed { .. }),
        "{w_first:?}"
    );
    assert_eq!(w_again, EdgeSignOutcome::AlreadySigned);
}

/// The unsigned-edge metric counts what the rows say.
#[sqlx::test(migrations = "../../migrations")]
async fn coverage_counts_signed_and_unsigned_edges(pool: PgPool) {
    // The harness connection is a superuser; sign as the maintenance path does.
    let (_scoped, bypass) = fixture::bypass(&pool).await;
    let signer = AgentSigner::from_bytes(&[0x76; 32]).expect("signer");
    let w = seed_signing_writer(&pool, "edge-metric", &signer).await;
    let viewer = fixture::public_viewer(&pool).await;
    let before = EdgeSignatureRepository::coverage(&pool, &viewer)
        .await
        .expect("coverage");
    let a = fixture::seed_public_claim(&pool, w, "metric A").await;
    let b = fixture::seed_public_claim(&pool, w, "metric B").await;
    let c = fixture::seed_public_claim(&pool, w, "metric C").await;
    let signed =
        EdgeRepository::create(&pool, a, "claim", b, "claim", "supports", None, None, None)
            .await
            .unwrap();
    EdgeRepository::create(&pool, a, "claim", c, "claim", "supports", None, None, None)
        .await
        .unwrap();
    let mut conn = pool.acquire().await.unwrap();
    EdgeSignatureRepository::sign_created_edge_conn(&mut conn, &bypass, signed, &signer, w)
        .await
        .unwrap();
    drop(conn);

    let after = EdgeSignatureRepository::coverage(&pool, &viewer)
        .await
        .expect("coverage");
    assert_eq!(after.total - before.total, 2);
    assert_eq!(after.signed - before.signed, 1);
    assert_eq!(after.unsigned - before.unsigned, 1);
    assert_eq!(after.total, after.signed + after.unsigned);

    // Viewer-scoped: an edge onto W's group-private claim (the tenancy trigger
    // gives it the meet) is counted for W and not for the public reader.
    let w_group: Uuid = sqlx::query_scalar(
        "SELECT id FROM groups WHERE kind = 'personal' AND created_by_agent_id = $1",
    )
    .bind(w)
    .fetch_one(&pool)
    .await
    .expect("W's personal group");
    let private = fixture::seed_group_claim(&pool, w, w_group, "metric private").await;
    EdgeRepository::create(
        &pool, a, "claim", private, "claim", "supports", None, None, None,
    )
    .await
    .unwrap();
    let public_again = EdgeSignatureRepository::coverage(&pool, &viewer)
        .await
        .expect("coverage");
    assert_eq!(
        public_again, after,
        "a group-private edge leaked into the public count"
    );
    let w_viewer = Viewer::resolve(&pool, w).await.expect("W's viewer");
    let w_sees = EdgeSignatureRepository::coverage(&pool, &w_viewer)
        .await
        .expect("coverage");
    assert_eq!(
        w_sees.unsigned,
        after.unsigned + 1,
        "{w_sees:?} vs {after:?}"
    );

    // And the digest the repository stored is the public function's.
    let row: (Vec<u8>,) = sqlx::query_as("SELECT content_hash FROM edges WHERE id = $1")
        .bind(signed)
        .fetch_one(&pool)
        .await
        .unwrap();
    let att: (Uuid, Uuid, Uuid, chrono::DateTime<chrono::Utc>) =
        sqlx::query_as("SELECT id, source_id, target_id, created_at FROM edges WHERE id = $1")
            .bind(signed)
            .fetch_one(&pool)
            .await
            .unwrap();
    let digest = edge_attestation_digest(&epigraph_db::repos::edge_signature::EdgeAttestation {
        id: att.0,
        source_id: att.1,
        source_type: "claim".into(),
        target_id: att.2,
        target_type: "claim".into(),
        relationship: "supports".into(),
        properties: serde_json::json!({}),
        valid_from: None,
        created_at: att.3,
    })
    .unwrap();
    assert_eq!(row.0, digest.to_vec());
}
