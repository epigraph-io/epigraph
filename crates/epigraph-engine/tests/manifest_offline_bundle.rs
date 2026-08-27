//! The recipient's side of the story: an exported bundle, written to a real
//! file on a real filesystem, verified with NO database access at all.
//!
//! This is what makes the omission attack detectable by the RECIPIENT rather
//! than only by the origin instance. The bundle carries every leaf's own
//! material, the exact bytes that were signed, and the signature — so a
//! consumer recomputes every leaf, folds the root, compares it to the root
//! inside the signed header, and Ed25519-verifies. No trust in the exporter is
//! required at any step.
//!
//! Nothing below reads the pool after the export returns.

use epigraph_crypto::{
    canonical_order, claim_leaf, edge_leaf, merkle_root, ContentHasher, ManifestLeaf,
    SignatureVerifier,
};
use epigraph_engine::export::prov::export_provenance_prov_o;
use sqlx::PgPool;
use uuid::Uuid;

// ── Fixtures ──────────────────────────────────────────────────────────────

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key, display_name) VALUES ($1, $2, 'bundle-test')")
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
         VALUES ($1, $2, sha256($1::text::bytea), $3, 0.7)",
    )
    .bind(id)
    .bind(content)
    .bind(agent)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

async fn seed_edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) {
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship)
         VALUES ($1, 'claim', $2, 'claim', $3)",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .execute(pool)
    .await
    .expect("seed edge");
}

/// Where the run's real bytes go. `EPIGRAPH_TEST_BLOB_DIR` when the harness
/// provides one, else the platform temp dir — never a path inside the checkout.
fn bundle_path() -> std::path::PathBuf {
    let dir = std::env::var("EPIGRAPH_TEST_BLOB_DIR")
        .map_or_else(|_| std::env::temp_dir(), std::path::PathBuf::from);
    std::fs::create_dir_all(&dir).expect("bundle directory");
    dir.join(format!("manifest_bundle_{}.json", Uuid::new_v4()))
}

// ── The off-platform verifier ─────────────────────────────────────────────

/// Rebuild one leaf purely from the JSON the bundle carries.
///
/// Deliberately hand-rolled from the bundle's own fields rather than reusing an
/// engine helper: a consumer in another language has exactly this much to work
/// with, and if this function needed anything more the bundle would be
/// incomplete.
fn leaf_from_bundle_entry(entry: &serde_json::Value) -> ManifestLeaf {
    let row_id = Uuid::parse_str(entry["id"].as_str().expect("id")).expect("uuid");
    let micros = entry["created_at_micros"]
        .as_i64()
        .expect("created_at_micros");
    match entry["kind"].as_str().expect("kind") {
        "claim" => {
            let content_hash =
                ContentHasher::from_hex(entry["content_hash"].as_str().expect("content_hash"))
                    .expect("32-byte hex");
            let agent_id =
                Uuid::parse_str(entry["agent_id"].as_str().expect("agent_id")).expect("uuid");
            claim_leaf(
                *row_id.as_bytes(),
                &content_hash,
                agent_id.as_bytes(),
                micros,
            )
        }
        "edge" => edge_leaf(
            *row_id.as_bytes(),
            entry["relationship"].as_str().expect("relationship"),
            micros,
        ),
        other => panic!("unknown entry kind {other}"),
    }
}

/// Fold the bundle's entries into a root, with no database and no trust in the
/// order they arrived in.
fn recompute_root(manifest: &serde_json::Value) -> [u8; 32] {
    let leaves: Vec<ManifestLeaf> = manifest["entries"]
        .as_array()
        .expect("entries array")
        .iter()
        .map(leaf_from_bundle_entry)
        .collect();
    let ordered = canonical_order(leaves).expect("canonical order");
    merkle_root(&ordered.iter().map(ManifestLeaf::hash).collect::<Vec<_>>()).expect("root")
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn exported_bundle_verifies_off_platform_from_disk(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let root_claim = seed_claim(&pool, agent, "bundle root").await;
    let ancestor = seed_claim(&pool, agent, "bundle ancestor").await;
    let prior = seed_claim(&pool, agent, "bundle prior").await;
    seed_edge(&pool, ancestor, root_claim, "derived_from").await;
    seed_edge(&pool, root_claim, prior, "supersedes").await;

    let signer = epigraph_crypto::AgentSigner::from_bytes(&[0x2B; 32]).unwrap();
    let export = export_provenance_prov_o(&pool, root_claim, Some(5), &signer, agent)
        .await
        .expect("export");

    // --- write real bytes to a real path -------------------------------
    let path = bundle_path();
    let pretty = serde_json::to_vec_pretty(&export.document).expect("serialize");
    std::fs::write(&path, &pretty).expect("write bundle");
    let on_disk_len = std::fs::metadata(&path).expect("stat bundle").len();
    assert!(on_disk_len > 0, "the bundle must actually be on disk");

    let read_back = std::fs::read(&path).expect("read bundle");
    assert_eq!(read_back.len() as u64, on_disk_len);
    let document: serde_json::Value = serde_json::from_slice(&read_back).expect("parse bundle");

    // --- from here on: NO database access ------------------------------

    let manifest = &document["manifest"];
    let signed_header_bytes = manifest["signed_header"]
        .as_str()
        .expect("signed_header is the canonical JSON string as signed")
        .as_bytes()
        .to_vec();
    let header: serde_json::Value =
        serde_json::from_slice(&signed_header_bytes).expect("parse signed header");

    // 1. Every leaf recomputes, and they fold to the root the header names.
    let recomputed = recompute_root(manifest);
    assert_eq!(
        ContentHasher::to_hex(&recomputed),
        header["root"].as_str().expect("header root"),
        "the bundle's own entry material must reproduce the SIGNED root"
    );
    assert_eq!(
        manifest["root"].as_str().unwrap(),
        header["root"].as_str().unwrap(),
        "and the convenience field must agree with the header"
    );
    assert_eq!(
        header["entry_count"].as_u64().unwrap(),
        manifest["entries"].as_array().unwrap().len() as u64
    );
    assert_eq!(
        header["entry_count"].as_u64().unwrap() as usize,
        export.claim_ids.len() + export.edge_ids.len()
    );

    // 2. The signature verifies over those exact bytes, against the key the
    //    bundle carries.
    let public_key: [u8; 32] = ContentHasher::from_hex(
        manifest["signer_public_key"]
            .as_str()
            .expect("signer_public_key"),
    )
    .expect("32-byte key");
    let sig_hex = manifest["signature"].as_str().expect("signature");
    assert_eq!(sig_hex.len(), 128, "64-byte Ed25519 signature as hex");
    let mut signature = [0u8; 64];
    for (i, byte) in signature.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&sig_hex[i * 2..i * 2 + 2], 16).expect("hex");
    }
    assert!(
        SignatureVerifier::verify(&public_key, &signed_header_bytes, &signature).unwrap(),
        "the bundle must be self-verifying with no access to the origin instance"
    );

    // 3. The subject rides inside the signature, so the export cannot be
    //    re-labelled after the fact.
    assert_eq!(header["subject"]["kind"], "provenance_export");
    assert_eq!(
        header["subject"]["root_claim_id"].as_str().unwrap(),
        root_claim.to_string()
    );

    std::fs::remove_file(&path).expect("clean up bundle");
}

#[sqlx::test(migrations = "../../migrations")]
async fn dropping_an_entry_from_the_bundle_on_disk_breaks_the_root(pool: PgPool) {
    // THE omission attack, caught by the recipient, from bytes on disk.
    let agent = seed_agent(&pool).await;
    let root_claim = seed_claim(&pool, agent, "omission root").await;
    let ancestor = seed_claim(&pool, agent, "omission ancestor").await;
    seed_edge(&pool, ancestor, root_claim, "derived_from").await;

    let signer = epigraph_crypto::AgentSigner::from_bytes(&[0x2B; 32]).unwrap();
    let export = export_provenance_prov_o(&pool, root_claim, Some(5), &signer, agent)
        .await
        .expect("export");

    let path = bundle_path();
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&export.document).expect("serialize"),
    )
    .expect("write bundle");

    // A hostile intermediary edits the file: one entry quietly removed.
    let mut document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("parse");
    let entries = document["manifest"]["entries"]
        .as_array_mut()
        .expect("entries");
    assert!(entries.len() >= 2, "need at least two entries to drop one");
    let dropped = entries.remove(0);
    let remaining = entries.len();
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&document).expect("re-serialize"),
    )
    .expect("rewrite bundle");

    // The recipient re-reads the tampered bytes and checks them.
    let tampered: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("re-read")).expect("parse");
    let manifest = &tampered["manifest"];
    let header: serde_json::Value = serde_json::from_slice(
        manifest["signed_header"]
            .as_str()
            .expect("header")
            .as_bytes(),
    )
    .expect("parse header");

    let recomputed = recompute_root(manifest);
    assert_ne!(
        ContentHasher::to_hex(&recomputed),
        header["root"].as_str().unwrap(),
        "dropping entry {} must break the root",
        dropped["id"]
    );
    assert_ne!(
        header["entry_count"].as_u64().unwrap() as usize,
        remaining,
        "and the signed entry_count no longer matches what was delivered"
    );

    // The signature itself is still perfectly valid — which is exactly why the
    // recipient must recompute the root rather than trust a green signature.
    let public_key: [u8; 32] =
        ContentHasher::from_hex(manifest["signer_public_key"].as_str().unwrap()).unwrap();
    let sig_hex = manifest["signature"].as_str().unwrap();
    let mut signature = [0u8; 64];
    for (i, byte) in signature.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&sig_hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    assert!(
        SignatureVerifier::verify(
            &public_key,
            manifest["signed_header"].as_str().unwrap().as_bytes(),
            &signature
        )
        .unwrap(),
        "the signature covers the header, not the entry list — the root is what catches the drop"
    );

    std::fs::remove_file(&path).expect("clean up bundle");
}
