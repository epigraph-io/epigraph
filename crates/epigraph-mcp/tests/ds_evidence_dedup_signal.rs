//! `submit_ds_evidence` says what its write did to the caller's BBA slot
//! (backlog bcbe34b2).
//!
//! # What was wrong, measured at origin/main before this file
//!
//! The BBA is upserted on `(claim, frame, agent, perspective)` and the tool
//! returned only the row id. An identical resubmission answered exactly like a
//! first submission (same `mass_function_id`, `bba_count` unchanged) with no
//! signal that nothing new was combined, so a multi-round caller believed N
//! updates applied when one did. Worse, a resubmission with DIFFERENT masses on
//! the same key silently REPLACED the earlier BBA under the same id.
//!
//! Now every response carries `write_outcome` (`inserted` | `unchanged` |
//! `replaced`) and `deduplicated` (true iff `unchanged`), and the two
//! non-insert outcomes add a warning. Assertions read JSON keys, so this file
//! compiles against the pre-fix response type and fails on the assertions.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_crypto::AgentSigner;
use epigraph_mcp::tools::ds_auto::ensure_binary_frame;
use epigraph_mcp::types::SubmitDsEvidenceParams;
use epigraph_mcp::{embed::McpEmbedder, tools, EpiGraphMcpFull};
use sqlx::PgPool;
use uuid::Uuid;

async fn make_server(pool: PgPool) -> EpiGraphMcpFull {
    let signer = AgentSigner::from_bytes(&[0x6bu8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None);
    let scoped = fixture::scoped_pool(&pool).await;
    EpiGraphMcpFull::new(pool, signer, embedder, false).with_scoped_pool(scoped)
}

async fn insert_claim(pool: &PgPool, content: &str) -> Uuid {
    let agent: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, labels)
         VALUES (sha256(gen_random_uuid()::text::bytea), 'dedup-agent', 'system', ARRAY['test'])
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current)
         VALUES ($1, sha256($1::bytea), 0.5, $2, true) RETURNING id",
    )
    .bind(content)
    .bind(agent)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn submit(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    claim: Uuid,
    frame: Uuid,
    masses: serde_json::Value,
    perspective: Option<&str>,
) -> serde_json::Value {
    let mut v = serde_json::json!({
        "claim_id": claim.to_string(),
        "frame_id": frame.to_string(),
        "hypothesis_index": 0,
        "masses": masses,
    });
    if let Some(p) = perspective {
        v["perspective_id"] = serde_json::json!(p);
    }
    let params: SubmitDsEvidenceParams = serde_json::from_value(v).expect("params");
    first_text(
        &tools::ds::submit_ds_evidence(server, viewer, params, None)
            .await
            .expect("submit_ds_evidence"),
    )
}

fn warnings(out: &serde_json::Value) -> Vec<String> {
    out.get("warnings")
        .and_then(serde_json::Value::as_array)
        .map(|a| {
            a.iter()
                .map(|w| w.as_str().unwrap_or_default().to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// The claim's cached belief columns, as the recompute wrote them.
async fn cached_belief(pool: &PgPool, claim: Uuid) -> (Option<f64>, Option<f64>, Option<f64>) {
    sqlx::query_as("SELECT belief, plausibility, pignistic_prob FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("read cached belief")
}

fn assert_same_belief(a: &serde_json::Value, b: &serde_json::Value) {
    for k in ["belief", "plausibility", "pignistic_prob"] {
        let (x, y) = (
            a[k].as_f64().unwrap_or(f64::NAN),
            b[k].as_f64().unwrap_or(f64::NAN),
        );
        assert!(
            (x - y).abs() <= 1e-12,
            "{k} moved on an `unchanged` write: {x} -> {y} ({a} vs {b})"
        );
    }
}

async fn stored_masses(pool: &PgPool, id: &str) -> serde_json::Value {
    sqlx::query_scalar("SELECT masses FROM mass_functions WHERE id = $1::uuid")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read stored masses")
}

#[sqlx::test(migrations = "../../migrations")]
async fn each_write_reports_whether_it_inserted_deduplicated_or_replaced(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    let frame = ensure_binary_frame(&mut pool.acquire().await.unwrap(), &viewer)
        .await
        .unwrap();
    let claim = insert_claim(&pool, "bcbe34b2: dedup signal").await;
    let masses = serde_json::json!({"0": 0.7, "0,1": 0.3});

    // First submission: a new row.
    let first = submit(&server, &viewer, claim, frame, masses.clone(), None).await;
    assert_eq!(first["write_outcome"], "inserted", "{first}");
    assert_eq!(first["deduplicated"], false, "{first}");
    assert!(
        warnings(&first).is_empty(),
        "a first submission carries no warning: {first}"
    );
    let id = first["mass_function_id"].as_str().expect("id").to_string();
    let cache_after_first = cached_belief(&pool, claim).await;
    assert!(
        cache_after_first.0.is_some(),
        "CALIBRATION: the first submission wrote the claim's cached belief"
    );

    // (a) Byte-identical resubmission: folded once, and SAID so.
    let again = submit(&server, &viewer, claim, frame, masses.clone(), None).await;
    assert_eq!(again["mass_function_id"], id.as_str(), "{again}");
    assert_eq!(again["bba_count"], 1, "{again}");
    assert_eq!(again["write_outcome"], "unchanged", "{again}");
    assert_eq!(again["deduplicated"], true, "{again}");
    let w = warnings(&again);
    assert_eq!(w.len(), 1, "{again}");
    assert!(
        w[0].contains("identical") && w[0].contains("not combined again"),
        "the dedup warning must say the resubmission was not combined again: {w:?}"
    );
    // ... and what it says holds: the belief did not move on its account,
    // neither in the response nor in the claim's cache.
    assert_same_belief(&first, &again);
    assert_eq!(
        cached_belief(&pool, claim).await,
        cache_after_first,
        "an `unchanged` write must leave the claim's cached belief as it was"
    );

    // (b) Different masses on the same (claim, frame, agent, perspective) key:
    // the earlier BBA is REPLACED in place, and that is said too.
    let changed = serde_json::json!({"0": 0.4, "1": 0.2, "0,1": 0.4});
    let replaced = submit(&server, &viewer, claim, frame, changed.clone(), None).await;
    assert_eq!(replaced["mass_function_id"], id.as_str(), "{replaced}");
    assert_eq!(replaced["bba_count"], 1, "{replaced}");
    assert_eq!(replaced["write_outcome"], "replaced", "{replaced}");
    assert_eq!(replaced["deduplicated"], false, "{replaced}");
    let w = warnings(&replaced);
    assert_eq!(w.len(), 1, "{replaced}");
    assert!(
        w[0].contains("REPLACED") && w[0].contains("perspective_id"),
        "the replace warning must name the overwrite and the way to add evidence: {w:?}"
    );
    let stored = stored_masses(&pool, &id).await;
    for (k, want) in changed.as_object().unwrap() {
        let got = stored[k].as_f64().unwrap_or(f64::NAN);
        assert!(
            (got - want.as_f64().unwrap()).abs() < 1e-12,
            "stored {k}: {got} vs {want} ({stored})"
        );
    }

    // (b2) The SAME masses on the same key with a different evidence_type is
    // not a restatement: the upsert overwrites evidence_type, which changes
    // the calibrated weight the combine applies, so it is `replaced`.
    let typed = serde_json::json!({
        "claim_id": claim.to_string(),
        "frame_id": frame.to_string(),
        "hypothesis_index": 0,
        "masses": changed.clone(),
        "evidence_type": "empirical",
    });
    let retyped = first_text(
        &tools::ds::submit_ds_evidence(
            &server,
            &viewer,
            serde_json::from_value(typed).expect("params"),
            None,
        )
        .await
        .expect("submit_ds_evidence (typed)"),
    );
    assert_eq!(retyped["mass_function_id"], id.as_str(), "{retyped}");
    assert_eq!(retyped["write_outcome"], "replaced", "{retyped}");
    assert_eq!(retyped["deduplicated"], false, "{retyped}");
    let stored_type: Option<String> =
        sqlx::query_scalar("SELECT evidence_type FROM mass_functions WHERE id = $1::uuid")
            .bind(&id)
            .fetch_one(&pool)
            .await
            .expect("read stored evidence_type");
    assert_eq!(
        stored_type.as_deref(),
        Some("empirical"),
        "the retyped BBA replaced the untyped one in place"
    );

    // (c) A distinct perspective adds an independent BBA.
    let created = first_text(
        &tools::perspectives::create_perspective(
            &server,
            &viewer,
            serde_json::from_value(serde_json::json!({"name": "bcbe34b2 lens"})).unwrap(),
            None,
        )
        .await
        .expect("create perspective"),
    );
    let pid = created["perspective_id"].as_str().unwrap().to_string();
    let other = submit(&server, &viewer, claim, frame, masses, Some(&pid)).await;
    assert_ne!(other["mass_function_id"], id.as_str(), "{other}");
    assert_eq!(other["bba_count"], 2, "{other}");
    assert_eq!(other["write_outcome"], "inserted", "{other}");
    assert_eq!(other["deduplicated"], false, "{other}");
}

/// The contract an agent reads names the new fields, so a caller knows to
/// look for them.
#[test]
fn submit_ds_evidence_description_names_the_write_outcome() {
    let d = epigraph_mcp::server::EpiGraphMcpFull::static_tools()
        .iter()
        .find(|t| t.name == "submit_ds_evidence")
        .and_then(|t| t.description.as_deref().map(str::to_string))
        .expect("submit_ds_evidence is in the manifest and has a description");
    for needle in [
        "write_outcome says which happened (inserted, unchanged",
        "deduplicated is true exactly when it is unchanged",
    ] {
        assert!(d.contains(needle), "description lacks {needle:?}: {d}");
    }
}
