//! `submit_ds_evidence`'s `combination_method` and `gamma` are deprecated —
//! accepted, no effect on belief — and a caller who sends a non-default value
//! is TOLD so in the response (backlog 82dcff9d, G5).
//!
//! Default taken from the brief: deprecate rather than honour. Honouring a
//! per-call method would re-introduce the second, divergent combine that
//! backlog 2bffdfdc removed in favour of the shared adaptive recompute.
//!
//! Params are built from JSON so this file compiles against the pre-fix types
//! and the revert run FAILS on the assertions, not on the build.

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
    let signer = AgentSigner::from_bytes(&[0x5du8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None);
    let scoped = fixture::scoped_pool(&pool).await;
    EpiGraphMcpFull::new(pool, signer, embedder, false).with_scoped_pool(scoped)
}

async fn insert_claim(pool: &PgPool, content: &str) -> Uuid {
    let agent: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, labels)
         VALUES (sha256(gen_random_uuid()::text::bytea), 'g5-agent', 'system', ARRAY['test'])
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

fn params(claim: Uuid, frame: Uuid, extra: serde_json::Value) -> SubmitDsEvidenceParams {
    let mut v = serde_json::json!({
        "claim_id": claim.to_string(),
        "frame_id": frame.to_string(),
        "hypothesis_index": 0,
        "masses": {"0": 0.7, "0,1": 0.3},
    });
    for (k, val) in extra.as_object().expect("object") {
        v[k] = val.clone();
    }
    serde_json::from_value(v).expect("params")
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_non_default_method_and_any_gamma_are_warned_about_and_change_nothing(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    let frame = ensure_binary_frame(&mut pool.acquire().await.unwrap(), &viewer)
        .await
        .unwrap();

    let plain_claim = insert_claim(&pool, "g5: plain submission").await;
    let plain = first_text(
        &tools::ds::submit_ds_evidence(
            &server,
            &viewer,
            params(plain_claim, frame, serde_json::json!({})),
            None,
        )
        .await
        .expect("plain submit"),
    );
    assert!(
        plain.get("warnings").is_none(),
        "a call with no deprecated parameter must carry no warnings: {plain}"
    );

    let dempster_claim = insert_claim(&pool, "g5: explicit Dempster").await;
    let dempster = first_text(
        &tools::ds::submit_ds_evidence(
            &server,
            &viewer,
            params(
                dempster_claim,
                frame,
                serde_json::json!({"combination_method": "Dempster"}),
            ),
            None,
        )
        .await
        .unwrap(),
    );
    assert!(
        dempster.get("warnings").is_none(),
        "Dempster is the default and must not warn: {dempster}"
    );

    let yager_claim = insert_claim(&pool, "g5: YagerOpen with gamma").await;
    let yager = first_text(
        &tools::ds::submit_ds_evidence(
            &server,
            &viewer,
            params(
                yager_claim,
                frame,
                serde_json::json!({"combination_method": "YagerOpen", "gamma": 0.4}),
            ),
            None,
        )
        .await
        .expect("yager submit is accepted, not refused"),
    );
    let warnings: Vec<String> = yager
        .get("warnings")
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| panic!("no warnings for a non-default method + gamma: {yager}"))
        .iter()
        .map(|w| w.as_str().unwrap().to_string())
        .collect();
    assert_eq!(warnings.len(), 2, "{warnings:?}");
    assert!(
        warnings[0].contains("combination_method=YagerOpen") && warnings[0].contains("deprecated"),
        "{warnings:?}"
    );
    assert!(
        warnings[1].contains("gamma=0.4") && warnings[1].contains("not change"),
        "{warnings:?}"
    );

    // The warning is TRUE: same masses, same frame, the same belief.
    assert_eq!(yager["method_used"], "YagerOpen", "still stored and echoed");
    for f in ["belief", "plausibility", "pignistic_prob"] {
        let (a, b) = (plain[f].as_f64().unwrap(), yager[f].as_f64().unwrap());
        assert!(
            (a - b).abs() < 1e-12,
            "{f} differs ({a} vs {b}): the method DID change the belief"
        );
    }
}
