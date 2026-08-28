//! `AnchorService` end to end against real Postgres and the real mock ledger.
//!
//! Nothing here is stubbed at the storage layer: commitments are the actual
//! deterministic CBOR, they are published to `anchor_mock_chain` through
//! `MockAnchorBackend`, and verification reads them back OUT of that table to
//! compare against `anchors.commitment_bytes`. Two stores must agree, and one
//! of them refuses UPDATE and DELETE outright.
//!
//! HONESTY NOTE, repeated from the module docs because it is easy to forget
//! when the tests are green: the mock ledger is in the SAME Postgres. These
//! tests prove the MECHANISM, not the trust property. `trust_basis` is
//! asserted as `"operator-held"` throughout for exactly that reason.
//!
//! The manifest fixtures build a real `manifests` + `manifest_entries` pair via
//! `epigraph_crypto`'s leaf/fold primitives, so `ManifestRootSource` — the only
//! file coupled to the manifest track — is exercised rather than stubbed.

use std::sync::Arc;

use epigraph_crypto::{claim_leaf, merkle_root, ContentHasher, ManifestRowKind, HASH_SIZE};
use epigraph_db::anchor::{
    AnchorService, AnchorVerdict, CardanoBlockfrostBackend, ManifestRootSource, MockAnchorBackend,
    TRUST_OPERATOR_HELD, TRUST_THIRD_PARTY,
};
use epigraph_db::{AnchorRepository, NewAnchor, ROOT_TYPE_MANIFEST};
use epigraph_interfaces::anchor::{AnchorBackend, AnchorCommitment};
use sqlx::PgPool;
use uuid::Uuid;

// ── Fixtures ──────────────────────────────────────────────────────────────

fn service(pool: &PgPool) -> AnchorService {
    AnchorService::new(
        Arc::new(MockAnchorBackend::new(pool.clone())),
        Arc::new(ManifestRootSource),
    )
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key, display_name) VALUES ($1, $2, 'anchor-e2e')")
        .bind(id)
        .bind(&pk)
        .execute(pool)
        .await
        .expect("seed agent");
    id
}

/// A real manifest over `n` real claims, folded with the same primitives the
/// exporter uses, so the root this test anchors is a root the production path
/// would produce.
async fn seed_manifest(pool: &PgPool, n: usize) -> (Uuid, Vec<Uuid>) {
    let agent = seed_agent(pool).await;
    let mut claim_ids = Vec::with_capacity(n);
    for i in 0..n {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, agent_id, truth_value)
             VALUES ($1, $2, sha256($1::text::bytea), $3, 0.6)",
        )
        .bind(id)
        .bind(format!("anchor e2e claim {i}"))
        .bind(agent)
        .execute(pool)
        .await
        .expect("seed claim");
        claim_ids.push(id);
    }

    // Canonical order is (kind tag, row id bytes); one kind here, so sort by id.
    claim_ids.sort_by_key(|id| *id.as_bytes());

    // Build the leaves from the repository's OWN projection, not a hand-rolled
    // SELECT: `ManifestRootSource::live_root` will read the same rows through
    // the same function, so a fixture that read `created_at` any other way
    // could disagree on microseconds and fake a drift.
    let inputs = epigraph_db::ManifestRepository::load_claim_leaf_inputs(pool, &claim_ids)
        .await
        .expect("leaf inputs");
    let mut by_id: std::collections::HashMap<Uuid, [u8; HASH_SIZE]> =
        std::collections::HashMap::new();
    for row in &inputs {
        let ch = <[u8; HASH_SIZE]>::try_from(row.content_hash.as_slice()).expect("32-byte hash");
        by_id.insert(
            row.id,
            claim_leaf(
                *row.id.as_bytes(),
                &ch,
                row.agent_id.as_bytes(),
                row.created_at.timestamp_micros(),
            )
            .hash(),
        );
    }
    let leaves: Vec<[u8; HASH_SIZE]> = claim_ids.iter().map(|id| by_id[id]).collect();
    let root = merkle_root(&leaves).expect("fold");

    let manifest_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO manifests (id, root, entry_count, subject, signed_header, signature,
                                signer_id, signer_public_key)
         VALUES ($1, $2, $3, '{\"kind\":\"anchor_e2e\"}'::jsonb, decode('7b7d', 'hex'),
                 decode(repeat('00', 64), 'hex'), $4, decode(repeat('11', 32), 'hex'))",
    )
    .bind(manifest_id)
    .bind(root.to_vec())
    .bind(i32::try_from(n).unwrap())
    .bind(agent)
    .execute(pool)
    .await
    .expect("seed manifest");

    for (pos, id) in claim_ids.iter().enumerate() {
        sqlx::query(
            "INSERT INTO manifest_entries (manifest_id, position, row_kind, row_id, leaf_hash)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(manifest_id)
        .bind(i32::try_from(pos).unwrap())
        .bind(ManifestRowKind::Claim.as_str())
        .bind(id)
        .bind(by_id[id].to_vec())
        .execute(pool)
        .await
        .expect("seed manifest entry");
    }

    (manifest_id, claim_ids)
}

async fn mock_chain_rows(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM anchor_mock_chain")
        .fetch_one(pool)
        .await
        .expect("count mock chain")
}

// ── Tests ─────────────────────────────────────────────────────────────────

/// THE END-TO-END MECHANISM: the bytes we recorded and the bytes the ledger
/// holds must be identical, and both must decode to the root we anchored.
#[sqlx::test(migrations = "../../migrations")]
async fn anchor_writes_commitment_to_mock_chain_and_confirms(pool: PgPool) {
    let (manifest_id, _) = seed_manifest(&pool, 4).await;

    let row = service(&pool)
        .anchor(&pool, ROOT_TYPE_MANIFEST, manifest_id)
        .await
        .expect("anchor");

    assert_eq!(row.status, "confirmed", "the mock confirms synchronously");
    assert_eq!(row.backend, "mock");
    assert_eq!(row.network, "mock");
    let tx_id = row.tx_id.clone().expect("a confirmed anchor has a tx_id");
    assert_eq!(tx_id.len(), 64, "shaped like a Cardano tx hash");
    assert!(row.block_height.is_some());
    assert!(row.block_time.is_some());
    assert!(row.confirmed_at.is_some());

    // The ledger's own copy.
    let (label, published): (i64, Vec<u8>) = sqlx::query_as(
        "SELECT metadata_label, metadata_cbor FROM anchor_mock_chain WHERE tx_id = $1",
    )
    .bind(&tx_id)
    .fetch_one(&pool)
    .await
    .expect("the ledger row must exist");

    assert_eq!(label, 40961, "published under the reserved metadatum label");
    assert_eq!(
        published, row.commitment_bytes,
        "the ledger's bytes and ours must be identical, byte for byte"
    );

    // And they decode to the manifest's actual root.
    let decoded = AnchorCommitment::from_cbor(&published).expect("decode published bytes");
    let manifest_root: Vec<u8> = sqlx::query_scalar("SELECT root FROM manifests WHERE id = $1")
        .bind(manifest_id)
        .fetch_one(&pool)
        .await
        .expect("manifest root");
    assert_eq!(decoded.root_hash.to_vec(), manifest_root);
    assert_eq!(decoded.root_id, *manifest_id.as_bytes());
    assert_eq!(decoded.kind, ROOT_TYPE_MANIFEST);
    assert_eq!(decoded.leaf_count, 4);
}

#[sqlx::test(migrations = "../../migrations")]
async fn verify_reports_verified_for_an_untouched_root(pool: PgPool) {
    let (manifest_id, _) = seed_manifest(&pool, 3).await;
    let svc = service(&pool);
    svc.anchor(&pool, ROOT_TYPE_MANIFEST, manifest_id)
        .await
        .expect("anchor");

    let report = svc
        .verify(&pool, ROOT_TYPE_MANIFEST, manifest_id)
        .await
        .expect("verify");

    assert_eq!(report.verdict, AnchorVerdict::Verified, "{report:?}");
    assert_eq!(
        report.trust_basis, TRUST_OPERATOR_HELD,
        "the mock is the operator's own ledger and the report must say so"
    );
    assert_eq!(
        report.anchored_root, report.live_root,
        "an untouched root re-derives to what was anchored"
    );
    assert_eq!(report.anchored_root.as_ref().map(String::len), Some(64));
    assert_eq!(
        report.sealed_after_block,
        Some(false),
        "the seal cannot postdate the block that proves it"
    );
    assert!(report.block_height.is_some());
}

/// Mutate a row the root covers and the two roots must diverge — reported with
/// BOTH hashes, and judged by nobody here.
#[sqlx::test(migrations = "../../migrations")]
async fn verify_reports_drift_when_a_member_row_changes(pool: PgPool) {
    let (manifest_id, claim_ids) = seed_manifest(&pool, 3).await;
    let svc = service(&pool);
    svc.anchor(&pool, ROOT_TYPE_MANIFEST, manifest_id)
        .await
        .expect("anchor");

    // `content_hash` is inside the leaf, so rewriting it moves the live root.
    sqlx::query("UPDATE claims SET content_hash = decode(repeat('ab', 32), 'hex') WHERE id = $1")
        .bind(claim_ids[0])
        .execute(&pool)
        .await
        .expect("mutate a covered row");

    let report = svc
        .verify(&pool, ROOT_TYPE_MANIFEST, manifest_id)
        .await
        .expect("verify");

    assert_eq!(report.verdict, AnchorVerdict::Drift, "{report:?}");
    let anchored = report.anchored_root.expect("anchored root is reported");
    let live = report.live_root.expect("live root is reported");
    assert_eq!(anchored.len(), 64);
    assert_eq!(live.len(), 64);
    assert_ne!(anchored, live, "drift means the two roots differ");
    assert!(
        report.detail.unwrap().contains("does not judge it"),
        "drift is reported, not judged"
    );
}

/// An anchor whose `root_hash` column disagrees with its published bytes.
///
/// The UPDATE trigger makes this state unreachable by editing an existing row —
/// which is itself the point — so it is constructed at INSERT time. Verification
/// must catch it from the BYTES, never from the column.
#[sqlx::test(migrations = "../../migrations")]
async fn verify_reports_commitment_tampered_when_root_hash_disagrees_with_bytes(pool: PgPool) {
    let (manifest_id, _) = seed_manifest(&pool, 2).await;

    // A commitment over the honest root...
    let real_root: Vec<u8> = sqlx::query_scalar("SELECT root FROM manifests WHERE id = $1")
        .bind(manifest_id)
        .fetch_one(&pool)
        .await
        .expect("root");
    let commitment = AnchorCommitment::new(
        ROOT_TYPE_MANIFEST,
        *manifest_id.as_bytes(),
        <[u8; 32]>::try_from(real_root.as_slice()).unwrap(),
        2,
        1_700_000_000,
    );
    let bytes = commitment.to_cbor().expect("encode");

    // ...stored beside a root_hash column that says something else.
    AnchorRepository::insert_pending(
        &pool,
        &NewAnchor {
            root_type: ROOT_TYPE_MANIFEST.to_string(),
            root_id: manifest_id,
            root_hash: vec![0xcc; 32],
            commitment_version: 1,
            commitment_hash: ContentHasher::hash(&bytes).to_vec(),
            commitment_bytes: bytes,
            backend: "mock".to_string(),
            network: "mock".to_string(),
            sealed_at: chrono::Utc::now(),
        },
    )
    .await
    .expect("insert the tampered anchor");

    let report = service(&pool)
        .verify(&pool, ROOT_TYPE_MANIFEST, manifest_id)
        .await
        .expect("verify");

    assert_eq!(
        report.verdict,
        AnchorVerdict::CommitmentTampered,
        "{report:?}"
    );
    let detail = report.detail.expect("detail");
    assert!(
        detail.contains("anchors.root_hash says"),
        "the report must name the disagreement: {detail}"
    );
    assert_eq!(
        report.anchored_root.expect("root from the BYTES"),
        ContentHasher::to_hex(&<[u8; 32]>::try_from(real_root.as_slice()).unwrap()),
        "the anchored root is re-derived from the payload, never read off the column"
    );

    // A payload that does not hash to commitment_hash is caught even earlier.
    let other = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO anchors (root_type, root_id, root_hash, commitment_hash, commitment_bytes,
                              backend, network, status, sealed_at)
         VALUES ('manifest', $1, decode(repeat('cc', 32), 'hex'),
                 decode(repeat('00', 32), 'hex'), decode('a701', 'hex'),
                 'mock', 'mock', 'pending', NOW())",
    )
    .bind(other)
    .execute(&pool)
    .await
    .expect("insert a payload/digest mismatch");

    let report = service(&pool)
        .verify(&pool, ROOT_TYPE_MANIFEST, other)
        .await
        .expect("verify");
    assert_eq!(report.verdict, AnchorVerdict::CommitmentTampered);
    assert!(report
        .detail
        .unwrap()
        .contains("blake3(commitment_bytes) is"));
}

/// THE CASE THE TRACK EXISTS FOR: the ledger's copy and ours disagree.
#[sqlx::test(migrations = "../../migrations")]
async fn verify_reports_ledger_mismatch_when_chain_bytes_differ(pool: PgPool) {
    let (manifest_id, _) = seed_manifest(&pool, 3).await;
    let svc = service(&pool);
    let row = svc
        .anchor(&pool, ROOT_TYPE_MANIFEST, manifest_id)
        .await
        .expect("anchor");
    assert_eq!(
        svc.verify(&pool, ROOT_TYPE_MANIFEST, manifest_id)
            .await
            .expect("verify")
            .verdict,
        AnchorVerdict::Verified,
        "precondition: it verifies before the swap"
    );

    // The ledger cannot be edited (that is the whole design), so point the
    // anchor at a DIFFERENT ledger transaction carrying different bytes — the
    // shape a lying operator would actually have to produce.
    let decoy = AnchorCommitment::new(
        ROOT_TYPE_MANIFEST,
        *manifest_id.as_bytes(),
        [0x77; 32],
        3,
        1,
    )
    .to_cbor()
    .expect("encode decoy");
    sqlx::query(
        "INSERT INTO anchor_mock_chain (tx_id, metadata_label, metadata_cbor, block_height)
         VALUES ('decoy-tx', 40961, $1, 9999)",
    )
    .bind(&decoy)
    .execute(&pool)
    .await
    .expect("publish the decoy");
    // tx_id is NOT a guarded column: the guard protects what was committed to,
    // and repointing the transaction id is exactly what this check must catch.
    sqlx::query("UPDATE anchors SET tx_id = 'decoy-tx' WHERE id = $1")
        .bind(row.id)
        .execute(&pool)
        .await
        .expect("repoint the anchor");

    let report = svc
        .verify(&pool, ROOT_TYPE_MANIFEST, manifest_id)
        .await
        .expect("verify");
    assert_eq!(report.verdict, AnchorVerdict::LedgerMismatch, "{report:?}");
    assert!(report.detail.unwrap().contains("differ from"));

    // And a transaction the ledger never issued is a different verdict again.
    sqlx::query("UPDATE anchors SET tx_id = 'never-published' WHERE id = $1")
        .bind(row.id)
        .execute(&pool)
        .await
        .expect("repoint at nothing");
    assert_eq!(
        svc.verify(&pool, ROOT_TYPE_MANIFEST, manifest_id)
            .await
            .expect("verify")
            .verdict,
        AnchorVerdict::LedgerMissing
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn verify_reports_missing_when_root_was_never_anchored(pool: PgPool) {
    let (manifest_id, _) = seed_manifest(&pool, 2).await;

    let report = service(&pool)
        .verify(&pool, ROOT_TYPE_MANIFEST, manifest_id)
        .await
        .expect("verify must not panic on an unanchored root");

    assert_eq!(report.verdict, AnchorVerdict::Missing);
    assert!(report.anchor_id.is_none());
    assert_eq!(report.trust_basis, TRUST_OPERATOR_HELD);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM anchors")
            .fetch_one(&pool)
            .await
            .expect("count"),
        0,
        "verification writes nothing"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn anchor_is_idempotent_for_an_already_anchored_root(pool: PgPool) {
    let (manifest_id, _) = seed_manifest(&pool, 3).await;
    let svc = service(&pool);

    let first = svc
        .anchor(&pool, ROOT_TYPE_MANIFEST, manifest_id)
        .await
        .expect("first anchor");
    assert_eq!(mock_chain_rows(&pool).await, 1);

    let second = svc
        .anchor(&pool, ROOT_TYPE_MANIFEST, manifest_id)
        .await
        .expect("second anchor");

    assert_eq!(first.id, second.id, "the same anchor row comes back");
    assert_eq!(first.tx_id, second.tx_id, "and the same transaction");
    assert_eq!(
        mock_chain_rows(&pool).await,
        1,
        "re-anchoring must publish nothing — two live commitments over one root \
         would let an operator present whichever suited them"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM anchors WHERE root_id = $1")
            .bind(manifest_id)
            .fetch_one(&pool)
            .await
            .expect("count"),
        1
    );
}

/// The unconfigured chain must not be able to break a seal — and must not
/// pretend to have published anything.
#[sqlx::test(migrations = "../../migrations")]
async fn cardano_stub_records_a_failed_anchor_without_network_access(pool: PgPool) {
    let (manifest_id, _) = seed_manifest(&pool, 2).await;

    let svc = AnchorService::new(
        Arc::new(CardanoBlockfrostBackend::with_project_id(None)),
        Arc::new(ManifestRootSource),
    );
    assert_eq!(svc.trust_basis(), TRUST_THIRD_PARTY);

    let row = svc
        .anchor(&pool, ROOT_TYPE_MANIFEST, manifest_id)
        .await
        .expect("an unconfigured backend must not make anchoring return Err");

    assert_eq!(row.status, "failed");
    let reason = row.failure_reason.expect("a reason is recorded");
    assert!(
        reason.contains("BLOCKFROST_PROJECT_ID"),
        "the reason must name the missing configuration: {reason}"
    );
    assert_eq!(row.backend, "cardano");
    assert_eq!(
        mock_chain_rows(&pool).await,
        0,
        "a cardano attempt must never touch the mock ledger"
    );

    // The verdict is Missing, not Verified: a failed anchor is not live.
    assert_eq!(
        svc.verify(&pool, ROOT_TYPE_MANIFEST, manifest_id)
            .await
            .expect("verify")
            .verdict,
        AnchorVerdict::Missing
    );

    // And because the failed row is outside the partial index, a retry on a
    // working backend still succeeds.
    let mock = service(&pool);
    assert_eq!(
        mock.anchor(&pool, ROOT_TYPE_MANIFEST, manifest_id)
            .await
            .expect("retry on the mock")
            .status,
        "confirmed"
    );
}

/// `fetch` is the real-backend confirmation path, not test-only scaffolding.
#[sqlx::test(migrations = "../../migrations")]
async fn poll_pending_confirms_a_submitted_anchor(pool: PgPool) {
    let (manifest_id, _) = seed_manifest(&pool, 2).await;
    let svc = service(&pool);
    let backend = MockAnchorBackend::new(pool.clone());

    // Publish to the ledger by hand and leave the anchor `submitted`, the state
    // a real chain leaves a row in between inclusion and confirmation.
    let root: Vec<u8> = sqlx::query_scalar("SELECT root FROM manifests WHERE id = $1")
        .bind(manifest_id)
        .fetch_one(&pool)
        .await
        .expect("root");
    let sealed_at = chrono::Utc::now();
    let commitment = AnchorCommitment::new(
        ROOT_TYPE_MANIFEST,
        *manifest_id.as_bytes(),
        <[u8; 32]>::try_from(root.as_slice()).unwrap(),
        2,
        u64::try_from(sealed_at.timestamp()).unwrap(),
    );
    let bytes = commitment.to_cbor().expect("encode");
    let receipt = backend.submit(&commitment).await.expect("publish");

    let row = AnchorRepository::insert_pending(
        &pool,
        &NewAnchor {
            root_type: ROOT_TYPE_MANIFEST.to_string(),
            root_id: manifest_id,
            root_hash: root.clone(),
            commitment_version: 1,
            commitment_hash: ContentHasher::hash(&bytes).to_vec(),
            commitment_bytes: bytes,
            backend: "mock".to_string(),
            network: "mock".to_string(),
            sealed_at,
        },
    )
    .await
    .expect("insert");
    AnchorRepository::mark_submitted(&pool, row.id, &receipt.tx_id)
        .await
        .expect("submit");

    assert_eq!(
        svc.verify(&pool, ROOT_TYPE_MANIFEST, manifest_id)
            .await
            .expect("verify")
            .verdict,
        AnchorVerdict::Unconfirmed,
        "nothing below confirmation is meaningful yet"
    );

    let advanced = svc.poll_pending(&pool, 100).await.expect("poll");
    assert_eq!(advanced, 1, "the straggler must be advanced");

    let confirmed = AnchorRepository::get_by_id(&pool, row.id)
        .await
        .expect("get")
        .expect("exists");
    assert_eq!(confirmed.status, "confirmed");
    assert_eq!(
        confirmed.block_height, receipt.block_height,
        "the ledger's height, not ours"
    );
    assert!(confirmed.block_time.is_some());

    assert_eq!(
        svc.verify(&pool, ROOT_TYPE_MANIFEST, manifest_id)
            .await
            .expect("verify")
            .verdict,
        AnchorVerdict::Verified
    );

    // A second poll finds nothing left open.
    assert_eq!(svc.poll_pending(&pool, 100).await.expect("poll again"), 0);
}

/// An unknown root kind is a hard error, never a silent skip — silently not
/// anchoring is the failure mode this whole design is built against.
#[sqlx::test(migrations = "../../migrations")]
async fn unknown_root_type_is_an_error_not_a_skip(pool: PgPool) {
    let (manifest_id, _) = seed_manifest(&pool, 2).await;
    let svc = service(&pool);

    let err = svc
        .anchor(&pool, "checkpoint", manifest_id)
        .await
        .expect_err("a reserved-but-unimplemented kind must not silently pass");
    assert!(err.to_string().contains("unknown anchor root type"));

    let err = svc
        .anchor(&pool, ROOT_TYPE_MANIFEST, Uuid::new_v4())
        .await
        .expect_err("there is no root to anchor");
    assert!(err.to_string().contains("does not exist"));

    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM anchors")
            .fetch_one(&pool)
            .await
            .expect("count"),
        0,
        "and nothing was written on either path"
    );
}

/// `verify_all` is what `anchor_verify --all` sweeps, and what a cron job turns
/// into an exit code.
#[sqlx::test(migrations = "../../migrations")]
async fn verify_all_sweeps_every_anchor_and_flags_the_broken_one(pool: PgPool) {
    let svc = service(&pool);
    let (good, _) = seed_manifest(&pool, 2).await;
    let (bad, bad_claims) = seed_manifest(&pool, 2).await;

    svc.anchor(&pool, ROOT_TYPE_MANIFEST, good)
        .await
        .expect("anchor good");
    svc.anchor(&pool, ROOT_TYPE_MANIFEST, bad)
        .await
        .expect("anchor bad");

    sqlx::query("UPDATE claims SET content_hash = decode(repeat('99', 32), 'hex') WHERE id = $1")
        .bind(bad_claims[0])
        .execute(&pool)
        .await
        .expect("drift the second manifest");

    let reports = svc.verify_all(&pool, 50).await.expect("verify_all");
    assert_eq!(reports.len(), 2);

    let problems: Vec<_> = reports.iter().filter(|r| r.verdict.is_problem()).collect();
    assert_eq!(problems.len(), 1, "exactly one anchor is broken");
    assert_eq!(problems[0].root_id, bad);
    assert_eq!(problems[0].verdict, AnchorVerdict::Drift);
    assert!(reports
        .iter()
        .any(|r| r.root_id == good && r.verdict == AnchorVerdict::Verified));
}

/// `trust_basis` is an HONESTY guard, and `verify_all` sweeps `list_all` —
/// which is NOT filtered by backend. So a process configured for one ledger
/// routinely verifies rows recorded under another (the ordinary dev-mock ->
/// prod-chain migration leaves exactly that mixture behind). The label must
/// describe the LEDGER THE ROW WAS ANCHORED TO, not the one this process
/// happens to be holding.
#[sqlx::test(migrations = "../../migrations")]
async fn trust_basis_describes_the_rows_backend_not_the_process(pool: PgPool) {
    let (mock_root, _) = seed_manifest(&pool, 2).await;
    let (chain_root, _) = seed_manifest(&pool, 2).await;

    // A real, confirmed, operator-held anchor on the in-Postgres mock ledger.
    service(&pool)
        .anchor(&pool, ROOT_TYPE_MANIFEST, mock_root)
        .await
        .expect("anchor on the mock ledger");

    // A row recorded under cardano. The stub refuses to submit, so this lands
    // `failed` with backend = "cardano" — still an anchors row, still swept.
    let chain_svc = AnchorService::new(
        Arc::new(CardanoBlockfrostBackend::with_project_id(None)),
        Arc::new(ManifestRootSource),
    );
    let chain_row = chain_svc
        .anchor(&pool, ROOT_TYPE_MANIFEST, chain_root)
        .await
        .expect("a refused submit is recorded, not raised");
    assert_eq!(chain_row.backend, "cardano");

    fn basis_for(reports: &[epigraph_db::anchor::AnchorVerification], root: Uuid) -> &'static str {
        reports
            .iter()
            .find(|r| r.root_id == root)
            .unwrap_or_else(|| panic!("no report for {root}"))
            .trust_basis
    }

    // (a) Swept by a MOCK-configured process. Both rows are returned.
    let reports = service(&pool).verify_all(&pool, 50).await.expect("sweep");
    assert_eq!(reports.len(), 2, "list_all is not filtered by backend");
    assert_eq!(
        basis_for(&reports, mock_root),
        TRUST_OPERATOR_HELD,
        "the mock row is operator-held"
    );
    assert_eq!(
        basis_for(&reports, chain_root),
        TRUST_THIRD_PARTY,
        "a row anchored to cardano is third-party however this process is configured"
    );

    // (b) The reciprocal, and the DANGEROUS direction: a chain-configured
    // process must not stamp third-party proof onto the operator's own ledger.
    let reports = chain_svc.verify_all(&pool, 50).await.expect("sweep");
    assert_eq!(
        basis_for(&reports, mock_root),
        TRUST_OPERATOR_HELD,
        "the mock ledger is in THIS Postgres — calling it third-party is the honesty \
         guard lying about itself"
    );
    assert_eq!(basis_for(&reports, chain_root), TRUST_THIRD_PARTY);
}
