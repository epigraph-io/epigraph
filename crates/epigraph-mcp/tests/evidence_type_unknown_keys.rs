//! Unknown evidence-type keys are REPORTED, not silently defaulted and not
//! refused (backlog 86ee2d30, G12).
//!
//! `submit_ds_evidence` accepted any `evidence_type` and `set_source_reliability`
//! any tag key; a key outside the vocabulary the belief engine resolves fell
//! back to the default weight with no signal, and the engine's own vocabulary
//! check (`warn_on_unknown_evidence_type_keys`) was private and only logged.
//!
//! Params are built from JSON so the file compiles against the pre-fix types
//! and the revert run fails on the assertions.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_crypto::AgentSigner;
use epigraph_mcp::tools::ds_auto::ensure_binary_frame;
use epigraph_mcp::{embed::McpEmbedder, tools, EpiGraphMcpFull};
use sqlx::PgPool;
use uuid::Uuid;

async fn make_server(pool: PgPool) -> EpiGraphMcpFull {
    let signer = AgentSigner::from_bytes(&[0x5eu8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None);
    let scoped = fixture::scoped_pool(&pool).await;
    EpiGraphMcpFull::new(pool, signer, embedder, false).with_scoped_pool(scoped)
}

async fn insert_claim(pool: &PgPool, content: &str) -> Uuid {
    let agent: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, labels)
         VALUES (sha256(gen_random_uuid()::text::bytea), 'g12-agent', 'system', ARRAY['test'])
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
    evidence_type: &str,
) -> serde_json::Value {
    let p = serde_json::from_value(serde_json::json!({
        "claim_id": claim.to_string(),
        "frame_id": frame.to_string(),
        "hypothesis_index": 0,
        "masses": {"0": 0.7, "0,1": 0.3},
        "evidence_type": evidence_type,
    }))
    .unwrap();
    first_text(
        &tools::ds::submit_ds_evidence(server, viewer, p, None)
            .await
            .expect("an unknown evidence_type is accepted, not refused"),
    )
}

#[sqlx::test(migrations = "../../migrations")]
async fn submit_ds_evidence_reports_an_unknown_evidence_type(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    let frame = ensure_binary_frame(&mut pool.acquire().await.unwrap(), &viewer)
        .await
        .unwrap();

    // Known keys: a canonical key, an alias, and a different case.
    for et in ["testimonial", "observation", "Empirical"] {
        let c = insert_claim(&pool, &format!("g12 known {et}")).await;
        let out = submit(&server, &viewer, c, frame, et).await;
        assert!(out.get("unknown_keys").is_none(), "{et}: {out}");
        assert!(out.get("warnings").is_none(), "{et}: {out}");
    }

    let c = insert_claim(&pool, "g12 unknown anecdote").await;
    let out = submit(&server, &viewer, c, frame, "anecdote").await;
    assert_eq!(
        out["unknown_keys"],
        serde_json::json!(["anecdote"]),
        "{out}"
    );
    let w = out["warnings"][0].as_str().unwrap_or_default();
    assert!(
        w.contains("\"anecdote\"") && w.contains("0.5 unknown-type") && w.contains("empirical"),
        "the warning must name the key, the consequence and the known keys: {w}"
    );

    // MEASURED: the BBA really was stored with the tag (a warning, not a refusal).
    let (n,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM mass_functions WHERE claim_id = $1 AND evidence_type = 'anecdote'",
    )
    .bind(c)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(n, 1);
}

/// The frame's own strict-key override (Tier 1 of `effective_source_strength`)
/// DOES resolve a key calibration does not know, so it must not be reported.
#[sqlx::test(migrations = "../../migrations")]
async fn a_frame_override_key_is_not_reported_unknown(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    let frame = ensure_binary_frame(&mut pool.acquire().await.unwrap(), &viewer)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE frames SET properties = COALESCE(properties, '{}'::jsonb) \
         || '{\"evidence_type_weights\": {\"anecdote\": 0.8}}'::jsonb WHERE id = $1",
    )
    .bind(frame)
    .execute(&pool)
    .await
    .unwrap();

    let c = insert_claim(&pool, "g12 override anecdote").await;
    let out = submit(&server, &viewer, c, frame, "anecdote").await;
    assert!(out.get("unknown_keys").is_none(), "{out}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn set_source_reliability_reports_keys_the_lens_can_never_match(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;

    let created = first_text(
        &tools::perspectives::create_perspective(
            &server,
            &viewer,
            serde_json::from_value(serde_json::json!({"name": "g12 lens"})).unwrap(),
            None,
        )
        .await
        .expect("create perspective"),
    );
    let pid = created["perspective_id"].as_str().unwrap().to_string();

    let clean = first_text(
        &tools::perspectives::set_source_reliability(
            &server,
            &viewer,
            serde_json::from_value(serde_json::json!({
                "perspective_id": pid,
                "source_reliability": {"empirical": 0.9, "supports": 0.7},
            }))
            .unwrap(),
            None,
        )
        .await
        .unwrap(),
    );
    assert!(clean.get("unknown_keys").is_none(), "{clean}");

    let dirty = first_text(
        &tools::perspectives::set_source_reliability(
            &server,
            &viewer,
            serde_json::from_value(serde_json::json!({
                "perspective_id": pid,
                "source_reliability": {"empirical": 0.9, "Testimonial": 0.4, "made_up": 0.5},
            }))
            .unwrap(),
            None,
        )
        .await
        .expect("unknown keys are a warning, not a refusal"),
    );
    assert_eq!(dirty["status"], "set", "{dirty}");
    assert_eq!(
        dirty["unknown_keys"],
        serde_json::json!(["Testimonial", "made_up"]),
        "{dirty}"
    );
    let warnings = dirty["warnings"].as_array().expect("warnings");
    assert_eq!(warnings.len(), 2, "{dirty}");
    assert!(
        warnings[0].as_str().unwrap().contains("\"testimonial\""),
        "the case warning must give the lowercase spelling: {dirty}"
    );

    // MEASURED: the mixed-case key really is dead — stored verbatim, and the
    // lens matches BBAs by LOWERCASED evidence_type, so it can never equal one.
    let (stored,): (serde_json::Value,) = sqlx::query_as(
        "SELECT properties->'source_reliability' FROM perspectives WHERE id = $1::uuid",
    )
    .bind(&pid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        stored.get("Testimonial").is_some(),
        "stored verbatim: {stored}"
    );
    assert!(
        stored.get("testimonial").is_none(),
        "not normalised: {stored}"
    );
}

/// G12 review: a LOWERCASE unknown key is reported, but it is not inert. It
/// weights every BBA submit_ds_evidence stored under that same unrecognised
/// evidence_type, so the tool description may not say it "can change no
/// belief". Pins the reviewer's measurement: the perspective's belief follows
/// the unknown key's alpha.
#[sqlx::test(migrations = "../../migrations")]
async fn a_lowercase_unknown_key_still_weights_a_bba_carrying_it(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    let frame = ensure_binary_frame(&mut pool.acquire().await.unwrap(), &viewer)
        .await
        .unwrap();
    let c = insert_claim(&pool, "g12 review: anecdote is weighted").await;
    let out = submit(&server, &viewer, c, frame, "anecdote").await;
    assert_eq!(
        out["unknown_keys"],
        serde_json::json!(["anecdote"]),
        "{out}"
    );

    let created = first_text(
        &tools::perspectives::create_perspective(
            &server,
            &viewer,
            serde_json::from_value(serde_json::json!({"name": "g12 review lens"})).unwrap(),
            None,
        )
        .await
        .expect("create perspective"),
    );
    let pid = created["perspective_id"].as_str().unwrap().to_string();

    let mut beliefs = Vec::new();
    for alpha in [0.05, 0.95] {
        let set = first_text(
            &tools::perspectives::set_source_reliability(
                &server,
                &viewer,
                serde_json::from_value(serde_json::json!({
                    "perspective_id": pid,
                    "source_reliability": {"anecdote": alpha},
                }))
                .unwrap(),
                None,
            )
            .await
            .unwrap(),
        );
        assert_eq!(
            set["unknown_keys"],
            serde_json::json!(["anecdote"]),
            "{set}"
        );
        let scoped = first_text(
            &tools::ds::scoped_belief(
                &server,
                &viewer,
                serde_json::from_value(serde_json::json!({
                    "claim_id": c.to_string(),
                    "scope_type": "perspective",
                    "scope_id": pid,
                    "frame_id": frame.to_string(),
                }))
                .unwrap(),
            )
            .await
            .expect("scoped_belief"),
        );
        beliefs.push(scoped["belief"].as_f64().expect("belief"));
    }
    // masses {0: 0.7}: belief = alpha * 0.7 under the lens.
    assert!(
        (beliefs[0] - 0.035).abs() < 1e-6 && (beliefs[1] - 0.665).abs() < 1e-6,
        "the unknown key's alpha must move the belief: {beliefs:?}"
    );
}

async fn submit_with_locality(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    claim: Uuid,
    frame: Uuid,
    evidence_type: Option<&str>,
    locality_tag: &str,
) -> serde_json::Value {
    let mut body = serde_json::json!({
        "claim_id": claim.to_string(),
        "frame_id": frame.to_string(),
        "hypothesis_index": 0,
        "masses": {"0": 0.7, "0,1": 0.3},
        "locality_tag": locality_tag,
    });
    if let Some(et) = evidence_type {
        body["evidence_type"] = serde_json::json!(et);
    }
    first_text(
        &tools::ds::submit_ds_evidence(server, viewer, serde_json::from_value(body).unwrap(), None)
            .await
            .expect("a locality_tag is never refused"),
    )
}

async fn stored_locality(pool: &PgPool, claim: Uuid) -> String {
    sqlx::query_scalar("SELECT locality_tag FROM mass_functions WHERE claim_id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// The `locality_tag` half of backlog 86ee2d30: "The same applies to
/// locality_tag". A misspelt intra tag was stored and folded as cross (no
/// discount) with no signal, and a tag sent without `evidence_type` was
/// dropped silently. Both now come back as warnings; known tags stay quiet.
#[sqlx::test(migrations = "../../migrations")]
async fn submit_ds_evidence_reports_an_unknown_or_ignored_locality_tag(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    let frame = ensure_binary_frame(&mut pool.acquire().await.unwrap(), &viewer)
        .await
        .unwrap();

    let mut intra_belief = None;
    for tag in ["intra_self_cite", "intra", "cross", "unknown"] {
        let c = insert_claim(&pool, &format!("86ee2d30 known locality {tag}")).await;
        let out = submit_with_locality(&server, &viewer, c, frame, Some("empirical"), tag).await;
        assert!(out.get("warnings").is_none(), "{tag}: {out}");
        assert!(out.get("unknown_locality_tag").is_none(), "{tag}: {out}");
        if tag == "intra_self_cite" {
            intra_belief = out["belief"].as_f64();
        }
    }

    // A misspelt intra tag: stored as given, warned, and MEASURED to get no
    // discount (its belief differs from the intra_self_cite one above).
    let c = insert_claim(&pool, "86ee2d30 misspelt locality").await;
    let out =
        submit_with_locality(&server, &viewer, c, frame, Some("empirical"), "self-cite").await;
    let w = out["warnings"][0].as_str().unwrap_or_default();
    assert!(
        w.contains("\"self-cite\"") && w.contains("NO locality discount"),
        "the warning must name the tag and the consequence: {out}"
    );
    assert_eq!(stored_locality(&pool, c).await, "self-cite");
    assert_eq!(
        out["unknown_locality_tag"], "self-cite",
        "the unknown tag must also come back machine-readable: {out}"
    );
    assert_ne!(
        out["belief"].as_f64(),
        intra_belief,
        "a misspelt intra tag is folded without the intra discount: {out}"
    );

    // A tag without evidence_type: dropped, stored "unknown", and warned.
    let c = insert_claim(&pool, "86ee2d30 dropped locality").await;
    let out = submit_with_locality(&server, &viewer, c, frame, None, "intra_self_cite").await;
    let w = out["warnings"][0].as_str().unwrap_or_default();
    assert!(w.contains("ignored"), "{out}");
    assert!(out.get("unknown_locality_tag").is_none(), "{out}");
    assert_eq!(stored_locality(&pool, c).await, "unknown");
}

/// A stored `locality_tag` longer than the `varchar(20)` column used to reach
/// the INSERT and fail as a redacted internal error. It is now refused as a
/// parameter error before anything is written; the same tag sent without
/// `evidence_type` is dropped, not stored, so it still succeeds.
#[sqlx::test(migrations = "../../migrations")]
async fn an_over_long_stored_locality_tag_is_a_parameter_error(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    let frame = ensure_binary_frame(&mut pool.acquire().await.unwrap(), &viewer)
        .await
        .unwrap();

    let c = insert_claim(&pool, "86ee2d30 over-long locality").await;
    let p = serde_json::from_value(serde_json::json!({
        "claim_id": c.to_string(),
        "frame_id": frame.to_string(),
        "hypothesis_index": 0,
        "masses": {"0": 0.7, "0,1": 0.3},
        "evidence_type": "empirical",
        "locality_tag": "intra_methodological_overlap",
    }))
    .unwrap();
    let err = tools::ds::submit_ds_evidence(&server, &viewer, p, None)
        .await
        .expect_err("a 28-character stored tag cannot fit varchar(20)");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS, "{err:?}");
    assert!(err.message.contains("20"), "{err:?}");
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM mass_functions WHERE claim_id = $1")
        .bind(c)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 0, "a refusal writes nothing");

    let out = submit_with_locality(
        &server,
        &viewer,
        c,
        frame,
        None,
        "intra_methodological_overlap",
    )
    .await;
    assert_eq!(stored_locality(&pool, c).await, "unknown", "{out}");
}
