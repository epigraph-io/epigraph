//! Backlog a2b71568: `submit_ds_evidence`'s reliability handling was a bare
//! caller-supplied float with zero connection to per-source-class calibration
//! (`epigraph_engine::edge_factor::effective_source_strength`,
//! `calibration.toml [evidence_type_weights]`) — the sophisticated recompute-time
//! discount chain that `auto_wire_ds_update` (issue #197 Phase 2/4) already uses.
//!
//! `submit_ds_evidence` unconditionally stored `evidence_type = NULL` and
//! `locality_tag = 'unknown'` on every BBA row (see `ds.rs`
//! `store_with_perspective` call), so a subsequent recompute could never key
//! off evidence-type calibration for evidence submitted through this entry
//! point — regardless of what the caller believed `reliability` meant.
//!
//! Fix: `SubmitDsEvidenceParams` gains two new OPTIONAL fields,
//! `evidence_type` and `locality_tag`. When `evidence_type` is supplied, the
//! BBA is stored with that metadata (raw, undiscounted masses — same as
//! today) so the *existing* recompute path
//! (`recompute_claim_belief_on_frame` -> `recompute_combined_belief` ->
//! `effective_source_strength`), which `submit_ds_evidence` already
//! delegates to for its returned belief, discounts by the calibrated
//! per-source-class weight instead of falling through to the 0.5
//! unknown-evidence-type fallback. When `evidence_type` is omitted (the
//! default), storage and discounting are byte-for-byte identical to
//! pre-change behavior: `evidence_type = NULL`, `locality_tag = 'unknown'`,
//! raw `reliability` float pre-discount as before.
//!
//! IMPORTANT: because `submit_ds_evidence` reads its returned belief back
//! from the `claims` row *after* delegating to the shared recompute path
//! (backlog 2bffdfdc), the no-`evidence_type` baseline is NOT "undiscounted" —
//! `effective_source_strength` on a row with `evidence_type = NULL` AND
//! `source_strength = NULL` falls through its tier chain to the 0.5
//! unknown-key fallback (see `edge_factor.rs` step 5). So this test compares
//! the *calibrated* testimonial weight (0.6, `calibration.toml`) against the
//! *0.5 fallback*, not against a fictitious "no discount" baseline.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_crypto::AgentSigner;
use epigraph_db::MassFunctionRepository;
use epigraph_mcp::tools::ds_auto::ensure_binary_frame;
use epigraph_mcp::types::SubmitDsEvidenceParams;
use epigraph_mcp::{embed::McpEmbedder, tools, EpiGraphMcpFull};
use rmcp::model::RawContent;
use sqlx::PgPool;
use uuid::Uuid;

/// Scoped, because `submit_ds_evidence` now runs its `claim_frames` assignment
/// and its `mass_functions` BBA in ONE transaction stamped from the author's
/// viewer, and `ScopedPool::begin_as` is the only thing that can open one. Both
/// tables carry migration 077's strict `WITH CHECK` with no orphan `*_privacy`
/// policy to fall back on, so a server with no `ScopedPool` REFUSES the tool by
/// name rather than writing on the unstamped pool — which is what this fixture
/// used to do, and what made the tool return `42501` in production.
async fn make_server(pool: PgPool) -> EpiGraphMcpFull {
    let signer = AgentSigner::from_bytes(&[0x5du8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None);
    let scoped = fixture::scoped_pool(&pool).await;
    EpiGraphMcpFull::new(pool, signer, embedder, false).with_scoped_pool(scoped)
}

fn result_json(out: rmcp::model::CallToolResult) -> serde_json::Value {
    let first = out.content.first().cloned().expect("first content");
    let text = match first.raw {
        RawContent::Text(t) => t.text,
        other => panic!("expected text content, got {other:?}"),
    };
    serde_json::from_str(&text).expect("result is JSON")
}

async fn insert_agent(pool: &PgPool, name: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO agents (public_key, display_name, agent_type, labels)
         VALUES (sha256(gen_random_uuid()::text::bytea), $1, 'system', ARRAY['test'])
         RETURNING id",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn insert_claim(pool: &PgPool, agent: Uuid, content: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current)
         VALUES ($1, sha256($1::bytea), 0.5, $2, true) RETURNING id",
    )
    .bind(content)
    .bind(agent)
    .fetch_one(pool)
    .await
    .unwrap()
}

fn base_params(claim_id: Uuid, frame_id: Uuid) -> SubmitDsEvidenceParams {
    SubmitDsEvidenceParams {
        claim_id: claim_id.to_string(),
        frame_id: frame_id.to_string(),
        hypothesis_index: 0,
        masses: serde_json::json!({"0": 0.8, "~": 0.2}),
        reliability: None,
        combination_method: None,
        gamma: None,
        perspective_id: None,
        evidence_type: None,
        locality_tag: None,
    }
}

/// A call with `evidence_type = "testimonial"` (calibrated weight 0.6 per
/// `calibration.toml [evidence_type_weights]`) must produce a DIFFERENT
/// pignistic_prob than the same masses submitted with no `evidence_type` at
/// all (which falls to the 0.5 unknown-key fallback in
/// `effective_source_strength`). Same input masses, same frame, same
/// hypothesis — the only variable is the calibration key, and it must reach
/// the belief computation.
#[sqlx::test(migrations = "../../migrations")]
async fn evidence_type_testimonial_diverges_from_no_evidence_type(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    let agent = insert_agent(&pool, "ds-calibrated-testimonial").await;
    let frame_id = ensure_binary_frame(&mut pool.acquire().await.expect("acquire"), &viewer)
        .await
        .expect("binary frame");

    let claim_a = insert_claim(&pool, agent, &format!("calib-a-{}", Uuid::new_v4())).await;
    let out_a =
        tools::ds::submit_ds_evidence(&server, &viewer, base_params(claim_a, frame_id), None)
            .await
            .expect("submit_ds_evidence (no evidence_type)");
    let pignistic_a = result_json(out_a)["pignistic_prob"]
        .as_f64()
        .expect("pignistic_prob is a number");

    let claim_b = insert_claim(&pool, agent, &format!("calib-b-{}", Uuid::new_v4())).await;
    let mut params_b = base_params(claim_b, frame_id);
    params_b.evidence_type = Some("testimonial".to_string());
    let out_b = tools::ds::submit_ds_evidence(&server, &viewer, params_b, None)
        .await
        .expect("submit_ds_evidence (evidence_type=testimonial)");
    let pignistic_b = result_json(out_b)["pignistic_prob"]
        .as_f64()
        .expect("pignistic_prob is a number");

    assert!(
        (pignistic_a - pignistic_b).abs() > 1e-6,
        "expected evidence_type=testimonial (calibrated weight 0.6) to produce a different \
         pignistic_prob than no evidence_type (0.5 fallback), got a={pignistic_a} b={pignistic_b}"
    );

    // Confirm the row actually landed with the resolved evidence_type
    // (not silently dropped), so future recomputes see consistent metadata.
    let rows = MassFunctionRepository::get_for_claim_frame(&pool, &viewer, claim_b, frame_id)
        .await
        .expect("get_for_claim_frame");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].evidence_type.as_deref(), Some("testimonial"));
}

/// Backward-compatibility: a call using ONLY the pre-existing params (no
/// `evidence_type`/`locality_tag`) must be byte-for-byte identical to
/// pre-change behavior — both in the returned belief numbers and in the
/// stored row's metadata columns (`evidence_type = NULL`,
/// `locality_tag = 'unknown'`, raw-`reliability`-based `source_strength`
/// semantics unchanged).
#[sqlx::test(migrations = "../../migrations")]
async fn omitting_evidence_type_is_byte_identical_to_legacy_behavior(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    let agent = insert_agent(&pool, "ds-calibrated-backcompat").await;
    let frame_id = ensure_binary_frame(&mut pool.acquire().await.expect("acquire"), &viewer)
        .await
        .expect("binary frame");
    let claim = insert_claim(&pool, agent, &format!("calib-compat-{}", Uuid::new_v4())).await;

    let mut params = base_params(claim, frame_id);
    params.reliability = Some(0.8);
    let out = tools::ds::submit_ds_evidence(&server, &viewer, params, None)
        .await
        .expect("submit_ds_evidence");
    let json = result_json(out);

    // Pinned legacy numbers: masses {"0": 0.8, "~": 0.2}, reliability 0.8,
    // no evidence_type => stored evidence_type=NULL/source_strength=NULL =>
    // effective_source_strength's step-5 unknown fallback (0.5) is what the
    // shared recompute path applies — the same value pre-change code path
    // already produced for this exact input (see
    // ds_evidence_recompute_belief_match.rs, which established that
    // submit_ds_evidence's returned value always equals recompute_beliefs's).
    // We assert the response is well-formed and internally consistent rather
    // than a hardcoded literal, since the literal is itself an emergent
    // property of effective_source_strength + combination::discount, not a
    // constant this test should duplicate by hand.
    // Pinned literal, captured from this exact input (masses {"0": 0.8,
    // "~": 0.2}, reliability 0.8, no evidence_type) against BOTH this
    // change's None-branch (which is textually identical to the
    // pre-change code — see `ds.rs`'s `if calibrated_evidence_type.is_none()`
    // gate) and independently verified equal to `origin/main`'s
    // unconditional pre-discount path for the same input. A future edit
    // that changes this value for a no-`evidence_type` call is a real
    // backward-compat regression, not test flake.
    // RE-BASELINED for backlog 0183a294: 0.6739130434782611 -> 0.62.
    //
    // The delta is exactly the open-world renormalizer this input carries and
    // `pignistic_probability` no longer applies:
    //     0.62 / (1 - 0.08) = 0.6739130434782611
    // where 0.08 is the post-discount mass on "~" (0.2 discounted by the step-5
    // unknown fallback). There is NO conflict mass in this input, so the conflict
    // factor — which all three measures still share — is 1.0 and contributes
    // nothing. The whole change here is the open-world half.
    //
    // That half is the licensed one: `scripts/lib/scifact_conformal.py`, against
    // which the 0.948-F1 conformal quantiles were fit, computes
    // `betp_sup = m_sup + m_theta/2` and EXCLUDES open-world mass without
    // renormalising. 0.62 is the calibration-consistent value; 0.6739 was not.
    //
    // The backward-compat intent of this assertion is preserved: a future edit
    // that moves this value for a no-`evidence_type` call is still a real
    // regression, not flake.
    let pignistic = json["pignistic_prob"].as_f64().expect("pignistic_prob");
    assert!(
        (pignistic - 0.62).abs() < 1e-9,
        "no-evidence_type call must reproduce the pinned pignistic_prob for this \
         input; got {pignistic}, expected 0.62 (masses {{\"0\":0.8,\"~\":0.2}}, \
         reliability=0.8, evidence_type=None -> effective_source_strength's step-5 \
         unknown fallback of 0.5). Pre-0183a294 this was 0.6739130434782611, which \
         differs by exactly the removed open-world renormalizer 1/(1-0.08)."
    );

    let rows = MassFunctionRepository::get_for_claim_frame(&pool, &viewer, claim, frame_id)
        .await
        .expect("get_for_claim_frame");
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].evidence_type, None,
        "legacy no-evidence_type call must still store evidence_type=NULL"
    );
    assert_eq!(
        rows[0].locality_tag, "unknown",
        "legacy no-evidence_type call must still store locality_tag='unknown'"
    );
    assert_eq!(
        rows[0].source_strength, None,
        "legacy no-evidence_type call must still store source_strength=NULL \
         (the raw `reliability` float is applied by pre-discounting the stored \
         masses, not by caching it as source_strength — matches pre-change behavior)"
    );
}
