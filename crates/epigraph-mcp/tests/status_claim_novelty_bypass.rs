//! Templated status reports must not collapse into the PRIOR run's claim
//! (backlog a3e63a12, 0a97ba24; operator ruling R-35).
//!
//! A scheduled reporter writes one status claim per run from a fixed template:
//! only the run tag, the dates and the counts change. Under a real embedder
//! those runs sit well inside the novelty gate's default 0.05 cosine band, so
//! `submit_claim` answered run N+1 with run N's claim id and wrote nothing: the
//! norcal-rfp generator status for 2026-07-19 came back as the 2026-06-29 claim,
//! and the roster of cycles that the generators rebuild from
//! `query_claims_by_label(["norcal-rfp-gen-status"])` lost that week.
//!
//! # How the gate is made to fire in a test process
//!
//! `McpEmbedder::with_generator` replaces the provider, so no request leaves the
//! process. The generator here ([`template_vector`]) derives the vector from the
//! text with every ASCII digit removed. Two runs of the same template therefore
//! embed to the SAME vector (cosine distance 0, inside every band), which is the
//! geometry a real embedder produces for them; two different templates embed to
//! unrelated pseudo-random vectors (distance near 1, outside every band). The
//! distance itself is computed by Postgres/pgvector, and the decision runs
//! through the real `submit_claim` / `memorize` / `batch_submit_claims` paths.
//!
//! Every test pairs a status arm with a CONTROL arm on the same transport: the
//! same shape of templated report carrying only TOPIC labels must still be
//! suppressed into the prior run (`deduplicated.by == "novelty_gate"`). The
//! control is what proves the gate fires in this harness at all, so the status
//! arm cannot pass vacuously; it also pins that the bypass is keyed on status
//! labels, not a blanket off-switch.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_crypto::AgentSigner;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::types::{BatchSubmitClaimsParams, MemorizeParams, SubmitClaimParams};
use epigraph_mcp::{tools, EpiGraphMcpFull};
use sqlx::PgPool;
use uuid::Uuid;

/// The status labels the scheduled writers in epiclaw-host `deploy/` attach to
/// their per-run summary claims (norcal-rfp and grant-monitor generators,
/// reviewers, revisers, cross-generator dedup, the grant run summary), plus
/// `telemetry` (per-run observations such as url-discovery and A/E filter
/// drops) and the bare forms the same reporters used before their labels were
/// prefixed.
const STATUS_LABELS_IN_USE: [&str; 13] = [
    "telemetry",
    "gen-status",
    "generator-summary",
    "review-status",
    "revise-status",
    "research-scan",
    "norcal-rfp-gen-status",
    "norcal-rfp-review-status",
    "norcal-rfp-revise-status",
    "norcal-rfp-dedup-status",
    "grant-gen-status",
    "grant-run-status",
    "grant-dedup-status",
];

/// Labels that co-occur with status claims but say what a claim is ABOUT, not
/// that it is a periodic report. They must leave the gate armed.
const TOPIC_LABELS: [&str; 4] = ["graph-integrity", "maintenance", "daily-journal", "rfp"];

const DIM: usize = 1536;

/// A deterministic vector for `text` that ignores every ASCII digit (see the
/// module docs). FNV-1a over the digit-stripped bytes seeds an xorshift64
/// stream; each component is the stream's top 16 bits, centred on zero.
fn template_vector(text: &str) -> Vec<f32> {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in text.bytes().filter(|b| !b.is_ascii_digit()) {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    let mut out = Vec::with_capacity(DIM);
    for _ in 0..DIM {
        h ^= h << 13;
        h ^= h >> 7;
        h ^= h << 17;
        let top = u16::try_from(h >> 48).expect("the top 16 bits fit a u16");
        out.push(f32::from(top) - 32_768.0);
    }
    out
}

/// A write-capable server whose embedder answers with [`template_vector`], and
/// the viewer of its own agent (the author of every claim below, so the gate's
/// nearest-neighbour read sees them).
async fn server_with_template_embedder(
    pool: &PgPool,
) -> (EpiGraphMcpFull, epigraph_db::visibility::Viewer) {
    let scoped = fixture::scoped_pool(pool).await;
    let embedder = McpEmbedder::new(pool.clone(), None)
        .with_scoped_pool(scoped.clone())
        .with_generator(std::sync::Arc::new(|text: &str| Ok(template_vector(text))));
    let server = EpiGraphMcpFull::new(
        pool.clone(),
        AgentSigner::from_bytes(&[0xB3u8; 32]).expect("signer"),
        embedder,
        false,
    )
    .with_scoped_pool(scoped);
    let agent = server.server_agent_id().await.expect("server agent");
    let viewer = epigraph_db::visibility::Viewer::resolve(pool, agent)
        .await
        .expect("viewer");
    (server, viewer)
}

/// Week `week` of a templated report whose template is identified by `kind`.
/// Only digits differ between weeks of the same kind.
fn weekly_report(kind: &str, week: u32) -> String {
    let day = 5 + 7 * week;
    let sources = 40 + week;
    let found = 3 * week + 1;
    format!(
        "Run 2026-07-{day:02} {kind}: generator completed; {sources} sources scanned, \
         {found} new solicitations, 0 errors."
    )
}

fn submit(content: &str, labels: &[&str]) -> SubmitClaimParams {
    SubmitClaimParams {
        content: content.to_string(),
        methodology: "direct_observation".to_string(),
        evidence_data: format!("run log for: {content}"),
        evidence_type: "empirical".to_string(),
        confidence: 0.9,
        source_url: None,
        reasoning: None,
        labels: labels.iter().map(|s| (*s).to_string()).collect(),
        novelty_threshold: None,
    }
}

async fn labels_of(pool: &PgPool, id: &str) -> Vec<String> {
    sqlx::query_scalar("SELECT labels FROM claims WHERE id = $1")
        .bind(Uuid::parse_str(id).expect("claim_id is a uuid"))
        .fetch_one(pool)
        .await
        .expect("the claim row exists")
}

/// `submit_claim`: week 2 of a status-labelled report inserts as its own claim
/// (still soft-flagged `near-duplicate`), for every status label the scheduled
/// writers use; the same report with topic labels only is still suppressed.
#[sqlx::test(migrations = "../../migrations")]
async fn submit_claim_keeps_every_run_of_a_status_labelled_report(pool: PgPool) {
    let (server, viewer) = server_with_template_embedder(&pool).await;

    // Control: topic labels only. Week 2 must come back as week 1.
    let kind = "graph-integrity maintenance summary";
    let w1 = first_text(
        &tools::claims::submit_claim(
            &server,
            &viewer,
            submit(&weekly_report(kind, 1), &TOPIC_LABELS),
            None,
        )
        .await
        .expect("control week 1"),
    );
    assert_eq!(
        w1["embedded"], true,
        "fixture: week 1 must be embedded or the gate cannot see it: {w1}"
    );
    let w2 = first_text(
        &tools::claims::submit_claim(
            &server,
            &viewer,
            submit(&weekly_report(kind, 2), &TOPIC_LABELS),
            None,
        )
        .await
        .expect("control week 2"),
    );
    assert_eq!(
        w2["deduplicated"]["by"], "novelty_gate",
        "control: a topic-labelled templated report must still be suppressed: {w2}"
    );
    assert_eq!(w2["claim_id"], w1["claim_id"], "{w2}");

    for label in STATUS_LABELS_IN_USE {
        let kind = format!("{label} bucket-aggregators status");
        let labels = [label, "bucket-aggregators"];
        let w1 = first_text(
            &tools::claims::submit_claim(
                &server,
                &viewer,
                submit(&weekly_report(&kind, 1), &labels),
                None,
            )
            .await
            .unwrap_or_else(|e| panic!("`{label}` week 1: {e:?}")),
        );
        assert_eq!(w1["embedded"], true, "fixture (`{label}`): {w1}");
        let w2 = first_text(
            &tools::claims::submit_claim(
                &server,
                &viewer,
                submit(&weekly_report(&kind, 2), &labels),
                None,
            )
            .await
            .unwrap_or_else(|e| panic!("`{label}` week 2: {e:?}")),
        );
        assert!(
            w2.get("deduplicated").is_none(),
            "a run labelled `{label}` must insert as its own claim, not collapse into the \
             prior run: {w2}"
        );
        assert_ne!(w2["claim_id"], w1["claim_id"], "`{label}`: {w2}");
        let w2_id = w2["claim_id"].as_str().expect("claim_id");
        let stored = labels_of(&pool, w2_id).await;
        assert!(
            stored.iter().any(|l| l == label),
            "`{label}` week 2 is stored with its own labels: {stored:?}"
        );
        assert!(
            stored.iter().any(|l| l == "near-duplicate"),
            "`{label}`: the bypass lifts suppression only; the near-duplicate soft-flag stays: \
             {stored:?}"
        );
    }
}

/// `memorize`: its tags are its labels, so a status-tagged memory gets the same
/// bypass; an untagged one is still suppressed.
#[sqlx::test(migrations = "../../migrations")]
async fn memorize_keeps_every_run_of_a_status_tagged_memory(pool: PgPool) {
    let (server, viewer) = server_with_template_embedder(&pool).await;

    let memorize = |content: String, tags: Option<Vec<String>>| MemorizeParams {
        content,
        confidence: Some(0.8),
        tags,
        novelty_threshold: None,
    };

    // Control: no tags.
    let kind = "daily maintenance memory";
    let c1 = first_text(
        &tools::memory::memorize(
            &server,
            &viewer,
            memorize(weekly_report(kind, 1), None),
            None,
        )
        .await
        .expect("control week 1"),
    );
    assert_eq!(c1["embedded"], true, "fixture: {c1}");
    let c2 = first_text(
        &tools::memory::memorize(
            &server,
            &viewer,
            memorize(weekly_report(kind, 2), None),
            None,
        )
        .await
        .expect("control week 2"),
    );
    assert_eq!(c2["deduplicated"]["by"], "novelty_gate", "control: {c2}");
    assert_eq!(c2["claim_id"], c1["claim_id"], "{c2}");

    let kind = "norcal-rfp generator status memory";
    let tags = || Some(vec!["norcal-rfp-gen-status".to_string()]);
    let s1 = first_text(
        &tools::memory::memorize(
            &server,
            &viewer,
            memorize(weekly_report(kind, 1), tags()),
            None,
        )
        .await
        .expect("status week 1"),
    );
    assert_eq!(s1["embedded"], true, "fixture: {s1}");
    let s2 = first_text(
        &tools::memory::memorize(
            &server,
            &viewer,
            memorize(weekly_report(kind, 2), tags()),
            None,
        )
        .await
        .expect("status week 2"),
    );
    assert!(
        s2.get("deduplicated").is_none(),
        "a status-tagged memory must insert as its own claim: {s2}"
    );
    assert_ne!(s2["claim_id"], s1["claim_id"], "{s2}");
}

/// `batch_submit_claims`: each entry reaches the gate with its own labels. In
/// one batch, the status pair both insert and the topic pair collapses.
#[sqlx::test(migrations = "../../migrations")]
async fn batch_submit_claims_keeps_every_run_of_a_status_labelled_entry(pool: PgPool) {
    let (server, viewer) = server_with_template_embedder(&pool).await;

    let status = "grant-monitor run summary";
    let topic = "grant-monitor topic note";
    let entry = |content: String, labels: &[&str]| {
        serde_json::json!({
            "content": content,
            "evidence_data": format!("run log for: {content}"),
            "evidence_type": "empirical",
            "labels": labels,
        })
    };
    let params: BatchSubmitClaimsParams = serde_json::from_value(serde_json::json!({
        "claims": [
            entry(weekly_report(status, 1), &["grant-run-status"]),
            entry(weekly_report(status, 2), &["grant-run-status"]),
            entry(weekly_report(topic, 1), &["grant-pipeline"]),
            entry(weekly_report(topic, 2), &["grant-pipeline"]),
        ]
    }))
    .expect("batch params");
    let json = first_text(
        &tools::batch::batch_submit_claims(&server, &viewer, params, None)
            .await
            .expect("batch"),
    );
    let r = &json["results"];
    assert_eq!(json["submitted"], 4, "{json}");
    assert_eq!(r[0]["embedded"], true, "fixture: {json}");
    assert_eq!(r[2]["embedded"], true, "fixture: {json}");

    // Control: the topic pair collapses.
    assert_eq!(
        r[3]["deduplicated"]["by"], "novelty_gate",
        "control: {json}"
    );
    assert_eq!(r[3]["claim_id"], r[2]["claim_id"], "control: {json}");

    // Status pair: both persist.
    assert!(
        r[1].get("deduplicated").is_none(),
        "a status-labelled batch entry must insert as its own claim: {json}"
    );
    assert_ne!(r[1]["claim_id"], r[0]["claim_id"], "{json}");
}
