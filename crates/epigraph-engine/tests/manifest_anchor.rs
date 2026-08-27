//! `anchor_manifest` / `verify_manifest` against a real database.
//!
//! The load-bearing test in this file is
//! [`label_churn_does_not_break_the_root`]. Backlog 6e2364b8 named exactly one
//! blocker — "a manifest over whole rows breaks on ordinary label churn" — and
//! that test mutates every field the leaf deliberately excludes, then asserts
//! the manifest is still fully green. Everything else here pins the other side:
//! that dropping, deleting, or rewriting something the leaf DOES cover is
//! caught, and caught with the right flag.

use epigraph_core::{ClaimId, TruthValue};
use epigraph_crypto::{verify_inclusion, AgentSigner, ContentHasher, ManifestRowKind};
use epigraph_db::ClaimRepository;
use epigraph_engine::export::manifest::{
    anchor_manifest, verify_manifest, EntryVerdict, ManifestError,
};
use sqlx::PgPool;
use uuid::Uuid;

// ── Fixtures ──────────────────────────────────────────────────────────────

fn signer() -> AgentSigner {
    AgentSigner::from_bytes(&[0x5A; 32]).expect("signer")
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key, display_name) VALUES ($1, $2, 'anchor-test')")
        .bind(id)
        .bind(&pk)
        .execute(pool)
        .await
        .expect("seed agent");
    id
}

async fn seed_claim(pool: &PgPool, agent: Uuid, content: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value)
         VALUES ($1, $2, sha256($1::text::bytea), $3, 0.6)",
    )
    .bind(id)
    .bind(content)
    .bind(agent)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

async fn seed_edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship)
         VALUES ($1, $2, 'claim', $3, 'claim', $4)",
    )
    .bind(id)
    .bind(source)
    .bind(target)
    .bind(relationship)
    .execute(pool)
    .await
    .expect("seed edge");
    id
}

fn subject() -> serde_json::Value {
    serde_json::json!({"kind": "test_export"})
}

/// Three claims and the two edges between them.
async fn seed_subgraph(pool: &PgPool) -> (Uuid, Vec<Uuid>, Vec<Uuid>) {
    let agent = seed_agent(pool).await;
    let a = seed_claim(pool, agent, "claim A").await;
    let b = seed_claim(pool, agent, "claim B").await;
    let c = seed_claim(pool, agent, "claim C").await;
    let ab = seed_edge(pool, a, b, "derived_from").await;
    let bc = seed_edge(pool, b, c, "derived_from").await;
    (agent, vec![a, b, c], vec![ab, bc])
}

// ── The blocker ───────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn label_churn_does_not_break_the_root(pool: PgPool) {
    // THE test that proves the backlog item's stated blocker is solved. A
    // manifest over WHOLE rows would go red on every one of these mutations —
    // all of which are ordinary, sanctioned maintenance.
    let (agent, claims, edges) = seed_subgraph(&pool).await;

    let anchored = anchor_manifest(&pool, &signer(), agent, subject(), &claims, &edges)
        .await
        .expect("anchor");
    assert_eq!(anchored.entry_count, 5);

    // Real FK targets for the two mutable id columns.
    let theme: Uuid = sqlx::query_scalar(
        "INSERT INTO claim_themes (label, description) VALUES ('churn', '') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let trace: Uuid = sqlx::query_scalar(
        "INSERT INTO reasoning_traces (claim_id, reasoning_type, explanation)
         VALUES ($1, 'deductive', 'churn trace') RETURNING id",
    )
    .bind(claims[0])
    .fetch_one(&pool)
    .await
    .unwrap();

    // Every column the leaf deliberately EXCLUDES, mutated at once:
    // labels/properties (update_labels, patch_claim, resolve_backlog_item),
    // theme_id (theme_cluster), the whole Dempster-Shafer block (every belief
    // recompute), embedding (nulled on supersede), trace_id, updated_at.
    sqlx::query(
        "UPDATE claims SET
             labels          = ARRAY['backlog','resolved'],
             properties      = '{\"churned\": true}'::jsonb,
             theme_id        = $2,
             trace_id        = $3,
             truth_value     = 0.99,
             belief          = 0.10,
             plausibility    = 0.90,
             pignistic_prob  = 0.42,
             beta_alpha      = 7.0,
             beta_beta       = 3.0,
             mass_on_empty   = 0.05,
             mass_on_missing = 0.05,
             open_world_mass = 0.05,
             classification  = 'contradicted',
             embedding       = NULL,
             updated_at      = NOW()
         WHERE id = ANY($1)",
    )
    .bind(&claims)
    .bind(theme)
    .bind(trace)
    .execute(&pool)
    .await
    .expect("churn every excluded claim column");

    // The edge equivalents: labels, properties, valid_to
    // (EdgeRepository::update_valid_to_and_properties).
    sqlx::query(
        "UPDATE edges SET labels = ARRAY['reviewed'],
                          properties = '{\"weight\": 0.3}'::jsonb,
                          valid_to = NOW()
         WHERE id = ANY($1)",
    )
    .bind(&edges)
    .execute(&pool)
    .await
    .expect("churn every excluded edge column");

    let report = verify_manifest(&pool, anchored.id, None)
        .await
        .expect("verify");

    assert!(
        report.entries.iter().all(|e| e.status == EntryVerdict::Ok),
        "every entry must still be Ok after label churn, got: {:?}",
        report.entries
    );
    assert!(report.live_root_matches, "live root must still match");
    assert!(report.stored_root_intact);
    assert!(report.entry_count_matches);
    assert!(report.header_consistent);
    assert!(report.signature_valid);
    assert_eq!(
        report.signer_key_current,
        Some(false),
        "the test signer's key is not the seeded agent's key"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn superseding_a_committed_claim_does_not_break_the_root(pool: PgPool) {
    // supersede() flips is_current, sets `supersedes`, and NULLs the embedding
    // (CLAUDE.md's cleanup contract). None of those are in the leaf.
    let (agent, claims, edges) = seed_subgraph(&pool).await;
    let anchored = anchor_manifest(&pool, &signer(), agent, subject(), &claims, &edges)
        .await
        .expect("anchor");

    ClaimRepository::supersede(
        &pool,
        ClaimId::from_uuid(claims[0]),
        "claim A, revised",
        TruthValue::new(0.8).unwrap(),
        "test supersession",
    )
    .await
    .expect("supersede");

    let is_current: bool = sqlx::query_scalar("SELECT is_current FROM claims WHERE id = $1")
        .bind(claims[0])
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        !is_current,
        "fixture precondition: the claim was superseded"
    );

    let report = verify_manifest(&pool, anchored.id, None).await.unwrap();
    assert!(
        report.entries.iter().all(|e| e.status == EntryVerdict::Ok),
        "supersession must not disturb any leaf: {:?}",
        report.entries
    );
    assert!(report.live_root_matches);
    assert!(report.signature_valid);
}

#[sqlx::test(migrations = "../../migrations")]
async fn edge_endpoint_rewrite_does_not_break_the_root(pool: PgPool) {
    // This is the test that JUSTIFIES excluding endpoints. Dedup re-sourcing
    // (mark_duplicate_with_repair, consolidate_claims) and the retraction
    // cascade all rewrite edges.target_id; a leaf that bound the endpoints
    // would break on every manifest that ever touched a deduped edge.
    let (agent, claims, edges) = seed_subgraph(&pool).await;
    let anchored = anchor_manifest(&pool, &signer(), agent, subject(), &claims, &edges)
        .await
        .expect("anchor");

    sqlx::query("UPDATE edges SET target_id = $2 WHERE id = $1")
        .bind(edges[0])
        .bind(claims[2])
        .execute(&pool)
        .await
        .expect("re-source the edge, as dedup does");

    let report = verify_manifest(&pool, anchored.id, None).await.unwrap();
    let edge_entry = report
        .entries
        .iter()
        .find(|e| e.row_id == edges[0])
        .expect("edge entry");
    assert_eq!(
        edge_entry.status,
        EntryVerdict::Ok,
        "an edge leaf binds (id, relationship, created_at) and NOT its endpoints"
    );
    assert!(report.live_root_matches);
}

// ── The purpose ───────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn omitting_a_row_changes_the_root(pool: PgPool) {
    // THE test that proves the feature's purpose: a set with one claim quietly
    // dropped is a DIFFERENT set, and the root says so.
    let (agent, claims, edges) = seed_subgraph(&pool).await;

    let full = anchor_manifest(&pool, &signer(), agent, subject(), &claims, &edges)
        .await
        .expect("anchor full set");
    let short = anchor_manifest(&pool, &signer(), agent, subject(), &claims[..2], &edges)
        .await
        .expect("anchor set minus one claim");

    assert_ne!(
        ContentHasher::to_hex(&full.root),
        ContentHasher::to_hex(&short.root),
        "dropping a row MUST change the root"
    );
    assert_eq!(full.entry_count, 5);
    assert_eq!(short.entry_count, 4);
}

#[sqlx::test(migrations = "../../migrations")]
async fn two_anchors_of_the_same_set_produce_the_same_root(pool: PgPool) {
    // Canonical ordering, not export order: otherwise two honest exports of the
    // same set produce different roots and set-equality stops being provable.
    let (agent, claims, edges) = seed_subgraph(&pool).await;

    let first = anchor_manifest(&pool, &signer(), agent, subject(), &claims, &edges)
        .await
        .expect("first anchor");

    let mut reversed_claims = claims.clone();
    reversed_claims.reverse();
    let mut reversed_edges = edges.clone();
    reversed_edges.reverse();
    let second = anchor_manifest(
        &pool,
        &signer(),
        agent,
        subject(),
        &reversed_claims,
        &reversed_edges,
    )
    .await
    .expect("second anchor, reversed input order");

    assert_eq!(first.root, second.root, "the root is a function of the SET");
    assert_ne!(first.id, second.id, "but each anchoring is its own record");
}

// ── Failure detection, flag by flag ───────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn deleting_a_committed_claim_is_reported_missing(pool: PgPool) {
    // The four flags MUST disagree here — which is exactly why they are
    // reported separately rather than collapsed into one boolean. The manifest
    // is honest; the graph moved on.
    let (agent, claims, edges) = seed_subgraph(&pool).await;
    let anchored = anchor_manifest(&pool, &signer(), agent, subject(), &claims, &edges)
        .await
        .expect("anchor");

    sqlx::query("DELETE FROM edges WHERE source_id = $1 OR target_id = $1")
        .bind(claims[2])
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM claims WHERE id = $1")
        .bind(claims[2])
        .execute(&pool)
        .await
        .expect("delete a committed claim");

    let report = verify_manifest(&pool, anchored.id, None).await.unwrap();
    let gone = report
        .entries
        .iter()
        .find(|e| e.row_id == claims[2])
        .expect("the entry row survives the claim — it is not a foreign key");
    assert_eq!(gone.status, EntryVerdict::Missing);
    assert!(gone.live_leaf.is_none());

    assert!(
        !report.live_root_matches,
        "the live graph no longer folds to the root"
    );
    assert!(report.stored_root_intact, "the stored leaves are untouched");
    assert!(
        report.signature_valid,
        "the manifest itself was not tampered with"
    );
    assert!(report.entry_count_matches, "no entry row was removed");
}

#[sqlx::test(migrations = "../../migrations")]
async fn content_hash_change_is_reported_mismatch(pool: PgPool) {
    let (agent, claims, edges) = seed_subgraph(&pool).await;
    let anchored = anchor_manifest(&pool, &signer(), agent, subject(), &claims, &edges)
        .await
        .expect("anchor");

    sqlx::query("UPDATE claims SET content_hash = sha256('something else') WHERE id = $1")
        .bind(claims[1])
        .execute(&pool)
        .await
        .expect("rewrite a committed content_hash");

    let report = verify_manifest(&pool, anchored.id, None).await.unwrap();
    let changed = report
        .entries
        .iter()
        .find(|e| e.row_id == claims[1])
        .expect("entry");
    assert_eq!(changed.status, EntryVerdict::Mismatch);
    assert!(
        changed.live_leaf.is_some() && changed.live_leaf != Some(changed.stored_leaf.clone()),
        "a mismatch reports BOTH leaves so the difference is inspectable"
    );
    assert!(!report.live_root_matches);
    assert!(
        report.signature_valid,
        "the manifest was not tampered with — the row was"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn tampered_root_column_fails_the_header_crosscheck(pool: PgPool) {
    // The gap that storing `signed_header` verbatim opens, and the cross-check
    // that closes it: the stored bytes still carry a cryptographically valid
    // signature, but over a DIFFERENT root than the column now claims.
    let (agent, claims, edges) = seed_subgraph(&pool).await;
    let anchored = anchor_manifest(&pool, &signer(), agent, subject(), &claims, &edges)
        .await
        .expect("anchor");

    sqlx::query("UPDATE manifests SET root = sha256('forged') WHERE id = $1")
        .bind(anchored.id)
        .execute(&pool)
        .await
        .expect("rewrite the root column");

    let report = verify_manifest(&pool, anchored.id, None).await.unwrap();
    assert!(
        !report.header_consistent,
        "the header still names the real root"
    );
    assert!(
        !report.signature_valid,
        "so the signature does not attest to this row"
    );
    assert!(
        report.signature_bytes_valid,
        "the stored bytes ARE validly signed — that is precisely why the \
         header/column cross-check is mandatory rather than optional"
    );
    assert!(
        !report.stored_root_intact,
        "the leaves no longer fold to the column"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn deleted_entry_row_is_caught_by_entry_count(pool: PgPool) {
    let (agent, claims, edges) = seed_subgraph(&pool).await;
    let anchored = anchor_manifest(&pool, &signer(), agent, subject(), &claims, &edges)
        .await
        .expect("anchor");

    sqlx::query("DELETE FROM manifest_entries WHERE manifest_id = $1 AND position = 0")
        .bind(anchored.id)
        .execute(&pool)
        .await
        .expect("delete one leaf row");

    let report = verify_manifest(&pool, anchored.id, None).await.unwrap();
    assert!(
        !report.entry_count_matches,
        "COUNT(manifest_entries) must be checked against the SIGNED entry_count"
    );
    assert!(
        !report.stored_root_intact,
        "the surviving leaves fold to something, but not to the signed root"
    );
    assert_eq!(report.entries.len(), 4);
}

// ── Fail-closed anchoring ─────────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn anchor_rejects_an_unknown_row_id(pool: PgPool) {
    let (agent, claims, edges) = seed_subgraph(&pool).await;
    let ghost = Uuid::new_v4();
    let mut with_ghost = claims.clone();
    with_ghost.push(ghost);

    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM manifests")
        .fetch_one(&pool)
        .await
        .unwrap();

    let err = anchor_manifest(&pool, &signer(), agent, subject(), &with_ghost, &edges)
        .await
        .unwrap_err();
    match err {
        ManifestError::UnknownRow { kind, id } => {
            assert_eq!(kind, ManifestRowKind::Claim);
            assert_eq!(id, ghost);
        }
        other => panic!("expected UnknownRow, got {other:?}"),
    }

    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM manifests")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(before, after, "fail closed: NO manifest row may be written");

    // Same rule for edges.
    let ghost_edge = Uuid::new_v4();
    let err = anchor_manifest(
        &pool,
        &signer(),
        agent,
        subject(),
        &claims,
        &[edges[0], ghost_edge],
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, ManifestError::UnknownRow { kind: ManifestRowKind::Edge, id } if id == ghost_edge),
        "got {err:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn anchor_rejects_an_empty_set(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let err = anchor_manifest(&pool, &signer(), agent, subject(), &[], &[])
        .await
        .unwrap_err();
    assert!(matches!(err, ManifestError::Empty), "got {err:?}");

    // And a non-object subject is refused BEFORE anything is signed.
    let claim = seed_claim(&pool, agent, "subject guard").await;
    let err = anchor_manifest(
        &pool,
        &signer(),
        agent,
        serde_json::json!("bare string"),
        &[claim],
        &[],
    )
    .await
    .unwrap_err();
    assert!(matches!(err, ManifestError::Invalid { .. }), "got {err:?}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn anchor_dedups_a_repeated_id(pool: PgPool) {
    // A set with a repeated member is the same set. The crypto layer rejects
    // duplicate leaves outright, so anchoring must dedup its inputs first
    // rather than surfacing a confusing DuplicateEntry to the caller.
    let (agent, claims, edges) = seed_subgraph(&pool).await;
    let repeated: Vec<Uuid> = vec![claims[0], claims[1], claims[0], claims[2], claims[0]];

    let anchored = anchor_manifest(&pool, &signer(), agent, subject(), &repeated, &edges)
        .await
        .expect("repeats must not be an error");
    assert_eq!(anchored.entry_count, 5, "3 distinct claims + 2 edges");

    let clean = anchor_manifest(&pool, &signer(), agent, subject(), &claims, &edges)
        .await
        .expect("anchor");
    assert_eq!(
        anchored.root, clean.root,
        "the deduped set folds to the same root as the set itself"
    );
}

// ── Inclusion proofs on a live path ───────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn inclusion_proof_verifies_for_every_entry_of_a_real_manifest(pool: PgPool) {
    let (agent, claims, edges) = seed_subgraph(&pool).await;
    let anchored = anchor_manifest(&pool, &signer(), agent, subject(), &claims, &edges)
        .await
        .expect("anchor");

    for entry in &anchored.entries {
        let kind = if entry.kind == "claim" {
            ManifestRowKind::Claim
        } else {
            ManifestRowKind::Edge
        };
        let report = verify_manifest(&pool, anchored.id, Some((kind, entry.id)))
            .await
            .expect("verify with proof");
        let proof = report
            .inclusion_proof
            .unwrap_or_else(|| panic!("no proof returned for {} {}", entry.kind, entry.id));

        assert!(
            proof.verified,
            "proof for position {} must verify",
            proof.position
        );
        assert_eq!(proof.position, entry.position);
        assert_eq!(proof.leaf, entry.leaf);
        assert_eq!(proof.tree_size, 5);

        // Re-verify independently, through the crypto primitive, from the hex
        // the tool returned — no shared state with the engine's own check.
        let leaf = ContentHasher::from_hex(&proof.leaf).unwrap();
        let root = ContentHasher::from_hex(&report.root).unwrap();
        let steps: Vec<epigraph_crypto::ProofStep> = proof
            .path
            .iter()
            .map(|s| epigraph_crypto::ProofStep {
                sibling: ContentHasher::from_hex(&s.sibling).unwrap(),
                sibling_is_right: s.sibling_is_right,
            })
            .collect();
        assert!(verify_inclusion(
            leaf,
            usize::try_from(proof.position).unwrap(),
            proof.tree_size,
            &steps,
            root
        ));
    }

    // A row that is not in the manifest gets no proof, not a bogus one.
    let outsider = seed_claim(&pool, agent, "never committed").await;
    let report = verify_manifest(&pool, anchored.id, Some((ManifestRowKind::Claim, outsider)))
        .await
        .unwrap();
    assert!(report.inclusion_proof.is_none());
}

#[sqlx::test(migrations = "../../migrations")]
async fn verify_reports_not_found_for_an_unknown_manifest(pool: PgPool) {
    let id = Uuid::new_v4();
    let err = verify_manifest(&pool, id, None).await.unwrap_err();
    assert!(
        matches!(err, ManifestError::NotFound(got) if got == id),
        "got {err:?}"
    );
}
