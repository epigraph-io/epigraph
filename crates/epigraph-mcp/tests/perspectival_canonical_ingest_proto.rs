//! PROTOTYPE (perspectival demo · option ii): ingest a practitioner interview through
//! the REAL claim-write path (`update_with_evidence` → `ds_auto` → frame function)
//! by mapping the demo's source-PROVENANCE types onto the kernel's canonical
//! `evidence_type` vocabulary, instead of the bespoke repo-tier write the
//! `perspectival_interview_merge.rs` harness uses.
//!
//! Provenance → canonical mapping (kept 4-way distinct, no collapse):
//!   source_practitioner → testimonial
//!   source_clinical     → empirical
//!   source_survey       → statistical
//!   source_tradition    → regulatory   (tradition canon as authoritative source)
//!
//! WHAT THIS PROVES (the part that holds up):
//!   - canonical evidence_type survives ingestion (no normalize-drop), and
//!   - the per-perspective frame function discounts each BBA by the asking
//!     lens's reliability for that canonical type — so the tradition_observer (high
//!     testimonial) moves a lot while the skeptic (≈0 testimonial) stays put,
//!     exactly the demo's behaviour — all through the real API tool.
//!
//! WHAT THIS EXPOSES (the part that flattens — see eprintln + the doc on C2):
//!   `update_with_evidence`/`ds_auto` write a ONE-SIDED simple-support BBA on a
//!   SHARED BINARY {TRUE,FALSE} frame (`build_binary_bba`: m({TRUE|FALSE}) =
//!   conf*weight, m(Θ) = rest). The demo's TWO-SIDED, TYPED-frame BBAs
//!   ({efficacious,no_effect}, {safe,harmful}) cannot ride this path: e.g.
//!   treatment-d safety {safe 0.20, harmful 0.55, θ 0.25} can only be expressed as
//!   `supports=false, strength≈0.55`, losing the explicit 0.20 safe mass and
//!   the typed frame. Faithful typed-frame full-BBA ingestion still needs the
//!   repo tier (today) or a kernel feature (the filed request).

mod common;
use common::*;

use std::collections::HashMap;

use epigraph_db::PerspectiveRepository;
use epigraph_engine::belief_query::get_perspective_belief;
use epigraph_mcp::tools::claims::update_with_evidence;
use epigraph_mcp::tools::ds_auto::ensure_binary_frame;
use epigraph_mcp::types::UpdateWithEvidenceParams;
use uuid::Uuid;

async fn add_evidence(
    server: &epigraph_mcp::EpiGraphMcpFull,
    claim: Uuid,
    evidence_type: &str,
    supports: bool,
    strength: f64,
    note: &str,
) {
    update_with_evidence(
        server,
        UpdateWithEvidenceParams {
            claim_id: claim.to_string(),
            evidence_type: evidence_type.to_string(),
            evidence_data: note.to_string(),
            source_url: None,
            supports,
            strength,
        },
    )
    .await
    .expect("update_with_evidence");
}

#[sqlx::test(migrations = "../../migrations")]
async fn canonical_ingest_preserves_per_lens_discount(pool: sqlx::PgPool) {
    let server = build_test_server(pool.clone());

    // ── 4 observer lenses, reliability keyed on the CANONICAL vocabulary ──
    let lenses: [(&str, HashMap<String, f64>); 4] = [
        (
            "tradition_observer",
            HashMap::from([
                ("testimonial".into(), 0.85),
                ("regulatory".into(), 0.70),
                ("empirical".into(), 0.30),
                ("statistical".into(), 0.25),
            ]),
        ),
        (
            "clinical_observer",
            HashMap::from([
                ("empirical".into(), 0.90),
                ("statistical".into(), 0.85),
                ("testimonial".into(), 0.10),
                ("regulatory".into(), 0.20),
            ]),
        ),
        (
            "regulatory_observer",
            HashMap::from([
                ("regulatory".into(), 0.80),
                ("statistical".into(), 0.60),
                ("empirical".into(), 0.50),
                ("testimonial".into(), 0.35),
            ]),
        ),
        (
            "skeptic_observer",
            HashMap::from([
                ("statistical".into(), 0.40),
                ("empirical".into(), 0.30),
                ("regulatory".into(), 0.05),
                ("testimonial".into(), 0.02),
            ]),
        ),
    ];
    let mut persp: Vec<(String, Uuid)> = Vec::new();
    for (name, rel) in &lenses {
        let row = PerspectiveRepository::create(
            &pool,
            name,
            None,
            None,
            Some("observer"),
            &[],
            None,
            None,
        )
        .await
        .expect("create perspective");
        PerspectiveRepository::set_source_reliability(&pool, row.id, rel)
            .await
            .expect("set reliability");
        persp.push(((*name).to_string(), row.id));
    }

    let frame = ensure_binary_frame(&pool).await.expect("binary frame");

    let read = |claim: Uuid| {
        let pool = pool.clone();
        let persp = persp.clone();
        async move {
            let mut out: Vec<(String, f64)> = Vec::new();
            for (k, id) in &persp {
                let b = get_perspective_belief(&pool, claim, frame, *id)
                    .await
                    .expect("belief");
                out.push((k.clone(), b.pignistic_prob));
            }
            out
        }
    };

    // ── representative claims ──
    let c_eff = seed_claim(&pool, "treatment-e is efficacious for symptom-5.", 0.5).await;
    let c_saf = seed_claim(
        &pool,
        "treatment-d is safe at therapeutic dose for chronic use.",
        0.5,
    )
    .await;
    let c_novel = seed_claim(&pool, "treatment-a is efficacious for symptom-6.", 0.5).await;

    // ── prior (discovery) evidence, mapped to canonical types ──
    add_evidence(
        &server,
        c_eff,
        "empirical",
        true,
        0.55,
        "source_clinical: modest RCT signal",
    )
    .await; // source_clinical→empirical
    add_evidence(
        &server,
        c_saf,
        "statistical",
        true,
        0.60,
        "source_survey: largely safe in practice",
    )
    .await; // source_survey→statistical
            // c_novel: no prior evidence (practitioner-only signal)

    let before_eff = read(c_eff).await;
    let before_saf = read(c_saf).await;
    let before_novel = read(c_novel).await;

    // ── the INTERVIEW, ingested via the real path as canonical `testimonial` ──
    add_evidence(
        &server,
        c_eff,
        "testimonial",
        true,
        0.82,
        "practitioner: foremost treatment, strong in symptom-5",
    )
    .await;
    // treatment-d: two-sided {safe 0.20, harmful 0.55} → can only be one-sided refutation
    add_evidence(
        &server,
        c_saf,
        "testimonial",
        false,
        0.55,
        "practitioner: caution in chronic use of the condition cluster",
    )
    .await;
    add_evidence(
        &server,
        c_novel,
        "testimonial",
        true,
        0.80,
        "practitioner: calms symptom-6",
    )
    .await;

    let after_eff = read(c_eff).await;
    let after_saf = read(c_saf).await;
    let after_novel = read(c_novel).await;

    let show = |label: &str, before: &[(String, f64)], after: &[(String, f64)]| {
        eprintln!("\n  {label}");
        for ((k, b), (_, a)) in before.iter().zip(after.iter()) {
            eprintln!("    {k:24} {b:.3} -> {a:.3}   Δ {:+.3}", a - b);
        }
    };
    eprintln!("\n=== option ii: interview ingested via update_with_evidence (canonical types), per-lens BetP ===");
    show(
        "treatment-e efficacious (practitioner=testimonial, supports)",
        &before_eff,
        &after_eff,
    );
    show("treatment-d safe (practitioner=testimonial, REFUTES — one-sided collapse of {safe .20, harmful .55})", &before_saf, &after_saf);
    show(
        "treatment-a efficacious — NOVEL practitioner-only",
        &before_novel,
        &after_novel,
    );

    // ── core (ii) claim: the per-lens discount survives the canonical mapping ──
    let d = |rows_b: &[(String, f64)], rows_a: &[(String, f64)], lens: &str| -> f64 {
        let b = rows_b.iter().find(|(k, _)| k == lens).unwrap().1;
        let a = rows_a.iter().find(|(k, _)| k == lens).unwrap().1;
        a - b
    };
    let tradition = d(&before_eff, &after_eff, "tradition_observer");
    let skeptic = d(&before_eff, &after_eff, "skeptic_observer");
    eprintln!("\n  efficacy lift — tradition {tradition:+.3} vs skeptic {skeptic:+.3}");
    assert!(
        tradition > skeptic + 0.10,
        "per-lens discount must survive canonical mapping: tradition ({tradition:+.3}) should outrun skeptic ({skeptic:+.3})"
    );
    // safety must fall (or at least not rise) for the trusting lens on a refutation
    let tradition_saf = d(&before_saf, &after_saf, "tradition_observer");
    eprintln!("  treatment-d safety — tradition Δ {tradition_saf:+.3} (refutation; one-sided)");
    assert!(
        tradition_saf < 0.0,
        "practitioner caution must lower safety for the trusting lens"
    );
}
