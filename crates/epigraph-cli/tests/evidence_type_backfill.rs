//! The legacy evidence-type backfill (backlog bc06ec6f), on a fixture with one
//! or more rows from every writer class measured on production
//! (`combination_method` NULL, discount, auto_wire, Dempster, auto_cdst,
//! propagated_from_parent / _neighbor, interview_extraction, dempster, test,
//! adaptive, truth_value_seed, error_derived, memory_reinforcement, none, and
//! prior) plus the cached-combination labels the full cached-combination
//! predicate names (`cautious+…`, `cached_unfolded`) and the writer shapes
//! whose masses already carry their weight (the assess input and its fold,
//! agent-bearing combination-labelled inputs, the truth_value seed).
//!
//! What is pinned:
//! * each row is typed, or left NULL for its stated reason (a decision table,
//!   so a rule that types an ambiguous row fails on THAT row);
//! * a type the calibration cannot weigh is left NULL;
//! * a dry run writes nothing; an apply writes exactly the decided rows and
//!   only their `evidence_type`, and touches no claim or cached belief;
//! * cached combination rows and ambiguous rows are untouched;
//! * a second run writes nothing; a bounded run resumes after its `last_id`;
//! * the only belief effect is the documented lens effect: a typed row's
//!   `effective_source_strength` becomes its type's calibrated weight times the
//!   locality factor, a perspective's reliability for its type now applies to
//!   it, and every other row's weight (global and through the lens) is
//!   unchanged;
//! * the binary refuses an unset maintenance DSN, an application login as the
//!   maintenance DSN, and a calibration that does not load or weighs no type;
//!   on a real `epigraph_maintenance` login it writes.

#[path = "viewer_fixture.rs"]
mod viewer_fixture;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use epigraph_cli::evidence_type_backfill::{decide, run, Decision, LeaveNull, Options, Rule};
use epigraph_db::repos::mass_function::{MassFunctionRepository, MassFunctionRow};
use epigraph_engine::calibration::CalibrationConfig;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

const BIN: &str = env!("CARGO_BIN_EXE_backfill_evidence_type");

fn calibration_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../calibration.toml")
        .canonicalize()
        .expect("the workspace calibration.toml")
}

fn calibration() -> CalibrationConfig {
    CalibrationConfig::load(&calibration_path()).expect("load calibration.toml")
}

/// A copy of the workspace calibration.toml with every `[evidence_type_weights]`
/// line for which `keep` is false removed, written to a fresh temp file.
fn calibration_variant(keep: impl Fn(&str) -> bool) -> PathBuf {
    let src = std::fs::read_to_string(calibration_path()).expect("read calibration.toml");
    let mut in_weights = false;
    let mut out = String::new();
    for line in src.lines() {
        if line.trim_start().starts_with('[') {
            in_weights = line.trim() == "[evidence_type_weights]";
        } else if in_weights && !keep(line) {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    let path = std::env::temp_dir().join(format!("bc06-calibration-{}.toml", Uuid::new_v4()));
    std::fs::write(&path, out).expect("write the calibration variant");
    path
}

/// Every claim and every cached combined belief, whole: the backfill must not
/// touch either (it writes `mass_functions.evidence_type` only and recomputes
/// nothing).
async fn belief_snapshot(pool: &PgPool) -> (Vec<serde_json::Value>, Vec<serde_json::Value>) {
    let claims: Vec<serde_json::Value> =
        sqlx::query_scalar("SELECT to_jsonb(c) FROM claims c ORDER BY c.id")
            .fetch_all(pool)
            .await
            .expect("claims snapshot");
    let combined: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT to_jsonb(b) FROM ds_combined_beliefs b ORDER BY to_jsonb(b)::text",
    )
    .fetch_all(pool)
    .await
    .expect("combined-belief snapshot");
    (claims, combined)
}

async fn seed_agent(pool: &PgPool, name: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), $1, 'system', ARRAY['test']) \
         RETURNING id",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

async fn seed_frame(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ('bc06-' || gen_random_uuid(), \
         ARRAY['TRUE','FALSE']) RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed frame")
}

/// A frame with a given name (get-or-create: `frames.name` is UNIQUE).
async fn seed_frame_named(pool: &PgPool, name: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['supported','unsupported']) \
         ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .expect("seed named frame")
}

async fn seed_claim(pool: &PgPool, agent: Uuid, props: serde_json::Value, labels: &[&str]) -> Uuid {
    let labels: Vec<String> = labels.iter().map(ToString::to_string).collect();
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, properties, labels) \
         VALUES ('bc06 ' || gen_random_uuid(), sha256(gen_random_uuid()::text::bytea), 0.5, \
                 $1, $2, $3) RETURNING id",
    )
    .bind(agent)
    .bind(props)
    .bind(labels)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

async fn seed_evidence(pool: &PgPool, claim: Uuid, tag: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO evidence (claim_id, evidence_type, content_hash, raw_content) \
         VALUES ($1, $2, sha256(gen_random_uuid()::text::bytea), 'bc06 evidence') RETURNING id",
    )
    .bind(claim)
    .bind(tag)
    .fetch_one(pool)
    .await
    .expect("seed evidence")
}

/// One BBA row as a legacy writer left it.
struct Bba<'a> {
    method: Option<&'a str>,
    agent: Option<Uuid>,
    evidence: Option<Uuid>,
    evidence_type: Option<&'a str>,
    source_strength: Option<f64>,
    locality: &'a str,
}

impl Default for Bba<'_> {
    fn default() -> Self {
        Self {
            method: None,
            agent: None,
            evidence: None,
            evidence_type: None,
            source_strength: Some(0.3),
            locality: "unknown",
        }
    }
}

async fn seed_bba(pool: &PgPool, claim: Uuid, frame: Uuid, b: Bba<'_>) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO mass_functions (claim_id, frame_id, source_agent_id, masses, \
             combination_method, evidence_id, evidence_type, source_strength, locality_tag) \
         VALUES ($1, $2, $3, '{\"0\": 0.6, \"0,1\": 0.4}'::jsonb, $4, $5, $6, $7, $8) \
         RETURNING id",
    )
    .bind(claim)
    .bind(frame)
    .bind(b.agent)
    .bind(b.method)
    .bind(b.evidence)
    .bind(b.evidence_type)
    .bind(b.source_strength)
    .bind(b.locality)
    .fetch_one(pool)
    .await
    .expect("seed bba")
}

fn typed(t: &str, rule: Rule) -> Decision {
    Decision::Type {
        evidence_type: t.to_string(),
        rule,
    }
}

const fn null(reason: LeaveNull) -> Decision {
    Decision::LeaveNull(reason)
}

/// The fixture: every row, the writer class it stands for, and its expected
/// decision. `already_typed` is a row the backfill must never even scan.
struct Fixture {
    expected: Vec<(Uuid, &'static str, Decision)>,
    already_typed: Uuid,
    intra_typed: Uuid,
    truth_value_seed: Uuid,
}

#[allow(clippy::too_many_lines)]
async fn seed_fixture(pool: &PgPool) -> Fixture {
    let ext = seed_agent(pool, "paper-extractor:some-paper").await;
    let openstax = seed_agent(pool, "textbook-extractor:openstax_biology").await;
    let mut expected = Vec::new();

    // A fresh (claim, frame) slot for one row; the unique key is
    // (claim, frame, agent, perspective) NULLS NOT DISTINCT.
    macro_rules! slot {
        ($props:expr, $labels:expr) => {{
            let c = seed_claim(pool, ext, $props, $labels).await;
            let f = seed_frame(pool).await;
            (c, f)
        }};
    }

    // ── <null>: a lone legacy input with a `reference` evidence row -> logical.
    let (c, f) = slot!(json!({}), &[]);
    let e = seed_evidence(pool, c, "reference").await;
    let id = seed_bba(
        pool,
        c,
        f,
        Bba {
            evidence: Some(e),
            ..Bba::default()
        },
    )
    .await;
    expected.push((id, "<null>", typed("logical", Rule::LinkedReference)));

    // ── <null> sharing its slot with an input: the pre-b5cb3efb single-input
    // cache copy shape. Left NULL even though its evidence says `reference`;
    // the discount input beside it IS typed.
    let (c, f) = slot!(json!({}), &[]);
    let e = seed_evidence(pool, c, "reference").await;
    let copy = seed_bba(
        pool,
        c,
        f,
        Bba {
            evidence: Some(e),
            ..Bba::default()
        },
    )
    .await;
    expected.push((copy, "<null>", null(LeaveNull::UnlabelledSharedSlot)));
    let input = seed_bba(
        pool,
        c,
        f,
        Bba {
            method: Some("discount"),
            agent: Some(ext),
            evidence: Some(e),
            ..Bba::default()
        },
    )
    .await;
    expected.push((input, "discount", typed("logical", Rule::LinkedReference)));

    // ── <null>, OpenStax extractor claim, nothing but the agent's name.
    let c = seed_claim(pool, openstax, json!({}), &[]).await;
    let f = seed_frame(pool).await;
    let id = seed_bba(pool, c, f, Bba::default()).await;
    expected.push((id, "<null>", null(LeaveNull::OpenstaxAgentNameOnly)));

    // ── <null>, a regulatory hint (provisional rule) and a claim source_type.
    let (c, f) = slot!(json!({"source_doi": "CBC-2022-1604"}), &[]);
    let id = seed_bba(pool, c, f, Bba::default()).await;
    expected.push((id, "<null>", null(LeaveNull::RegulatoryProvisional)));
    let (c, f) = slot!(json!({"source_type": "Textbook"}), &[]);
    let id = seed_bba(pool, c, f, Bba::default()).await;
    expected.push((id, "<null>", null(LeaveNull::SourceTypeProvisional)));

    // ── <null>, a backlog item: not evidence.
    let (c, f) = slot!(json!({"evidence_type": "empirical"}), &["backlog"]);
    let id = seed_bba(pool, c, f, Bba::default()).await;
    expected.push((id, "<null>", null(LeaveNull::NotEvidence)));

    // ── <null> with an empty-string type counts as untyped.
    let (c, f) = slot!(json!({}), &[]);
    let e = seed_evidence(pool, c, "reference").await;
    let id = seed_bba(
        pool,
        c,
        f,
        Bba {
            evidence: Some(e),
            evidence_type: Some(""),
            ..Bba::default()
        },
    )
    .await;
    expected.push((id, "<null>", typed("logical", Rule::LinkedReference)));

    // ── discount: the claim's declared type, any case -> its key.
    let (c, f) = slot!(json!({"evidence_type": " Empirical "}), &[]);
    let id = seed_bba(
        pool,
        c,
        f,
        Bba {
            method: Some("discount"),
            agent: Some(ext),
            ..Bba::default()
        },
    )
    .await;
    expected.push((id, "discount", typed("empirical", Rule::DeclaredType)));

    // ── auto_wire: an alias is not a declarable key; a deciding methodology
    // makes a declared type ambiguous; a non-deciding one does not; a
    // methodology alone decides nothing here; a generic declared type is not
    // copied; a linked `reference` with intra locality.
    let (c, f) = slot!(json!({"evidence_type": "observation"}), &[]);
    let aw = Bba {
        method: Some("auto_wire"),
        agent: Some(ext),
        ..Bba::default()
    };
    let id = seed_bba(pool, c, f, aw).await;
    expected.push((id, "auto_wire", null(LeaveNull::DeclaredTypeNotDeclarable)));

    let (c, f) = slot!(
        json!({"evidence_type": "statistical", "methodology": "computational"}),
        &[]
    );
    let id = seed_bba(
        pool,
        c,
        f,
        Bba {
            method: Some("auto_wire"),
            agent: Some(ext),
            ..Bba::default()
        },
    )
    .await;
    expected.push((
        id,
        "auto_wire",
        null(LeaveNull::DeclaredTypeWithMethodology),
    ));

    let (c, f) = slot!(
        json!({"evidence_type": "logical", "methodology": "extraction"}),
        &[]
    );
    let id = seed_bba(
        pool,
        c,
        f,
        Bba {
            method: Some("auto_wire"),
            agent: Some(ext),
            ..Bba::default()
        },
    )
    .await;
    expected.push((id, "auto_wire", typed("logical", Rule::DeclaredType)));

    let (c, f) = slot!(json!({"methodology": "instrumental"}), &[]);
    let e = seed_evidence(pool, c, "reference").await;
    let id = seed_bba(
        pool,
        c,
        f,
        Bba {
            method: Some("auto_wire"),
            agent: Some(ext),
            evidence: Some(e),
            ..Bba::default()
        },
    )
    .await;
    expected.push((id, "auto_wire", null(LeaveNull::MethodologyOnly)));

    let (c, f) = slot!(json!({"evidence_type": "reference"}), &[]);
    let id = seed_bba(
        pool,
        c,
        f,
        Bba {
            method: Some("auto_wire"),
            agent: Some(ext),
            ..Bba::default()
        },
    )
    .await;
    expected.push((id, "auto_wire", null(LeaveNull::GenericDeclaredType)));

    let (c, f) = slot!(json!({}), &[]);
    let e = seed_evidence(pool, c, "reference").await;
    let intra_typed = seed_bba(
        pool,
        c,
        f,
        Bba {
            method: Some("auto_wire"),
            agent: Some(ext),
            evidence: Some(e),
            locality: "intra_self_cite",
            ..Bba::default()
        },
    )
    .await;
    expected.push((
        intra_typed,
        "auto_wire",
        typed("logical", Rule::LinkedReference),
    ));

    // A row #573's writer already typed: never scanned, never changed.
    let (c, f) = slot!(json!({"evidence_type": "logical"}), &[]);
    let already_typed = seed_bba(
        pool,
        c,
        f,
        Bba {
            method: Some("auto_wire"),
            agent: Some(ext),
            evidence_type: Some("statistical"),
            ..Bba::default()
        },
    )
    .await;

    // ── Dempster: agent-less = a cached combination; with an agent = a
    // submit_ds_evidence input stored without a caller type, whose masses that
    // writer pre-discounted by the caller's reliability (#573 stores RAW masses
    // only when it is given a type): typing it would weigh it twice.
    let (c, f) = slot!(json!({"evidence_type": "empirical"}), &[]);
    let e = seed_evidence(pool, c, "reference").await;
    let id = seed_bba(
        pool,
        c,
        f,
        Bba {
            method: Some("Dempster"),
            evidence: Some(e),
            ..Bba::default()
        },
    )
    .await;
    expected.push((id, "Dempster", null(LeaveNull::CachedCombination)));
    let (c, f) = slot!(json!({}), &[]);
    let e = seed_evidence(pool, c, "reference").await;
    let id = seed_bba(
        pool,
        c,
        f,
        Bba {
            method: Some("Dempster"),
            agent: Some(ext),
            evidence: Some(e),
            ..Bba::default()
        },
    )
    .await;
    expected.push((id, "Dempster", null(LeaveNull::CombinationLabelledInput)));

    // ── the rest of the cached-combination family.
    for label in ["cautious+Dempster", "cached_unfolded", "YagerOpen"] {
        let (c, f) = slot!(json!({"evidence_type": "logical"}), &[]);
        let id = seed_bba(
            pool,
            c,
            f,
            Bba {
                method: Some(label),
                ..Bba::default()
            },
        )
        .await;
        expected.push((id, label, null(LeaveNull::CachedCombination)));
    }

    // ── auto_cdst: the stored `observation` / `testimony` tags are wrong too
    // often to copy.
    for tag in ["observation", "testimony"] {
        let (c, f) = slot!(json!({}), &[]);
        let e = seed_evidence(pool, c, tag).await;
        let id = seed_bba(
            pool,
            c,
            f,
            Bba {
                method: Some("auto_cdst"),
                agent: Some(ext),
                evidence: Some(e),
                ..Bba::default()
            },
        )
        .await;
        expected.push((id, "auto_cdst", null(LeaveNull::LinkedTagUnreliable)));
    }

    // ── propagated_*: the relationship was never stored.
    for m in ["propagated_from_parent", "propagated_from_neighbor"] {
        let (c, f) = slot!(json!({"evidence_type": "logical"}), &[]);
        let e = seed_evidence(pool, c, "reference").await;
        let id = seed_bba(
            pool,
            c,
            f,
            Bba {
                method: Some(m),
                agent: Some(ext),
                evidence: Some(e),
                ..Bba::default()
            },
        )
        .await;
        expected.push((id, m, null(LeaveNull::RelationshipNotStored)));
    }

    // ── interview_extraction -> testimonial (the value #573 names).
    let (c, f) = slot!(json!({}), &[]);
    let id = seed_bba(
        pool,
        c,
        f,
        Bba {
            method: Some("interview_extraction"),
            agent: Some(ext),
            ..Bba::default()
        },
    )
    .await;
    expected.push((
        id,
        "interview_extraction",
        typed("testimonial", Rule::InterviewExtraction),
    ));

    // ── dempster (lower case, an out-of-repo writer): a combination label on an
    // input with an agent. No #573 writer types such a row; left NULL even
    // though its claim declares a type.
    let (c, f) = slot!(json!({"evidence_type": "testimonial"}), &[]);
    let id = seed_bba(
        pool,
        c,
        f,
        Bba {
            method: Some("dempster"),
            agent: Some(ext),
            ..Bba::default()
        },
    )
    .await;
    expected.push((id, "dempster", null(LeaveNull::CombinationLabelledInput)));

    // ── test: a fixture, not evidence.
    let (c, f) = slot!(json!({"evidence_type": "empirical"}), &[]);
    let id = seed_bba(
        pool,
        c,
        f,
        Bba {
            method: Some("test"),
            agent: Some(ext),
            ..Bba::default()
        },
    )
    .await;
    expected.push((id, "test", null(LeaveNull::NotEvidence)));

    // ── adaptive with a `computation` tag; none with a `document` tag.
    for (m, tag) in [("adaptive", "computation"), ("none", "document")] {
        let (c, f) = slot!(json!({}), &[]);
        let e = seed_evidence(pool, c, tag).await;
        let id = seed_bba(
            pool,
            c,
            f,
            Bba {
                method: Some(m),
                agent: Some(ext),
                evidence: Some(e),
                ..Bba::default()
            },
        )
        .await;
        expected.push((id, m, null(LeaveNull::LinkedTagUnreliable)));
    }

    // ── memory_reinforcement: nothing that decides.
    let (c, f) = slot!(json!({}), &["claude-memory"]);
    let id = seed_bba(
        pool,
        c,
        f,
        Bba {
            method: Some("memory_reinforcement"),
            agent: Some(ext),
            ..Bba::default()
        },
    )
    .await;
    expected.push((
        id,
        "memory_reinforcement",
        null(LeaveNull::NoDeterminingField),
    ));

    // ── truth_value_seed, as `ds_auto.rs::auto_wire_ds_update` writes it: the
    // author's agent, source_strength 1.0, evidence_type NULL ON PURPOSE (the
    // exempt arm keys on its absence, so the seed's BetP stays the claim's
    // truth_value). A declared type on its claim must not type it.
    let (c, f) = slot!(json!({"evidence_type": "testimonial"}), &[]);
    let seed = seed_bba(
        pool,
        c,
        f,
        Bba {
            method: Some("truth_value_seed"),
            agent: Some(ext),
            source_strength: Some(1.0),
            ..Bba::default()
        },
    )
    .await;
    expected.push((seed, "truth_value_seed", null(LeaveNull::UntypedByDesign)));

    // ── prior: a vacuous hypothesis prior, not evidence; untyped by design.
    let (c, f) = slot!(json!({"evidence_type": "empirical"}), &[]);
    let id = seed_bba(
        pool,
        c,
        f,
        Bba {
            method: Some("prior"),
            agent: Some(ext),
            ..Bba::default()
        },
    )
    .await;
    expected.push((id, "prior", null(LeaveNull::UntypedByDesign)));

    // ── the assess shape: `routes/assess.rs::assess_claim` stores an agent-less,
    // perspective-less `discount` input whose masses `build_bba_directed`
    // already sized with the type weight. Anonymous REST inputs share the
    // shape. Typing it would apply the type weight a second time.
    let (c, f) = slot!(json!({"evidence_type": "empirical"}), &[]);
    let id = seed_bba(
        pool,
        c,
        f,
        Bba {
            method: Some("discount"),
            ..Bba::default()
        },
    )
    .await;
    expected.push((id, "discount", null(LeaveNull::MassesAlreadyWeighted)));

    // ── a lone agent-less `<null>` row on an assess auto-frame: the single-input
    // fold that replaced its (already type-weighted) assess input in the
    // shared slot. Left NULL whatever its claim declares.
    for frame_name in [
        "research_validity".to_string(),
        format!("paper_validity_bc06_{}", Uuid::new_v4().simple()),
    ] {
        let c = seed_claim(pool, ext, json!({"evidence_type": "logical"}), &[]).await;
        let f = seed_frame_named(pool, &frame_name).await;
        let id = seed_bba(pool, c, f, Bba::default()).await;
        expected.push((id, "<null>", null(LeaveNull::MassesAlreadyWeighted)));
    }

    // ── a declared type beside a linked `observation` tag: the claim's own
    // declared type wins (it is checked first), the tag is not consulted.
    let (c, f) = slot!(json!({"evidence_type": "empirical"}), &[]);
    let e = seed_evidence(pool, c, "observation").await;
    let id = seed_bba(
        pool,
        c,
        f,
        Bba {
            method: Some("auto_wire"),
            agent: Some(ext),
            evidence: Some(e),
            ..Bba::default()
        },
    )
    .await;
    expected.push((id, "auto_wire", typed("empirical", Rule::DeclaredType)));

    // ── error_derived: #573 keeps it untyped on purpose; a declared type on
    // the claim must not lift it.
    let (c, f) = slot!(json!({"evidence_type": "empirical"}), &[]);
    let e = seed_evidence(pool, c, "reference").await;
    let id = seed_bba(
        pool,
        c,
        f,
        Bba {
            method: Some("error_derived"),
            agent: Some(ext),
            evidence: Some(e),
            ..Bba::default()
        },
    )
    .await;
    expected.push((id, "error_derived", null(LeaveNull::UntypedByDesign)));

    Fixture {
        expected,
        already_typed,
        intra_typed,
        truth_value_seed: seed,
    }
}

/// Every mass_functions row: (evidence_type, every other column as JSON).
async fn snapshot(pool: &PgPool) -> BTreeMap<Uuid, (Option<String>, serde_json::Value)> {
    let rows: Vec<(Uuid, Option<String>, serde_json::Value)> = sqlx::query_as(
        "SELECT id, evidence_type, to_jsonb(m) - 'evidence_type' FROM mass_functions m",
    )
    .fetch_all(pool)
    .await
    .expect("snapshot");
    rows.into_iter()
        .map(|(id, t, rest)| (id, (t, rest)))
        .collect()
}

async fn mf_row(pool: &PgPool, id: Uuid) -> MassFunctionRow {
    sqlx::query_as(
        "SELECT id, claim_id, frame_id, source_agent_id, perspective_id, masses, conflict_k, \
                combination_method, source_strength, evidence_type, locality_tag, evidence_id, \
                created_at FROM mass_functions WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("mass_functions row")
}

fn expected_writer_counts(fx: &Fixture) -> BTreeMap<String, (u64, u64, u64)> {
    let mut m: BTreeMap<String, (u64, u64, u64)> = BTreeMap::new();
    for (_, writer, d) in &fx.expected {
        let e = m.entry((*writer).to_string()).or_default();
        e.0 += 1;
        match d {
            Decision::Type { .. } => e.1 += 1,
            Decision::LeaveNull(_) => e.2 += 1,
        }
    }
    m
}

fn opts(apply: bool, batch: i64) -> Options {
    Options {
        apply,
        batch,
        after: None,
        max_batches: None,
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn each_writer_class_is_typed_or_left_null_for_its_stored_reason(pool: PgPool) {
    let cal = calibration();
    let fx = seed_fixture(&pool).await;

    let page = MassFunctionRepository::untyped_provenance_page(&pool, None, 10_000)
        .await
        .expect("page");
    let decided: BTreeMap<Uuid, Decision> = page.iter().map(|r| (r.id, decide(r, &cal))).collect();
    assert!(
        !decided.contains_key(&fx.already_typed),
        "a row #573's writer typed was scanned"
    );
    let mut wrong = Vec::new();
    for (id, writer, want) in &fx.expected {
        let got = decided.get(id);
        if got != Some(want) {
            wrong.push(format!("{writer} {id}: want {want:?}, got {got:?}"));
        }
    }
    assert!(wrong.is_empty(), "decisions differ:\n{}", wrong.join("\n"));
    assert_eq!(
        decided.len(),
        fx.expected.len(),
        "scanned rows outside the fixture"
    );

    // A dry run reports the same per-writer counts and writes nothing.
    let before = snapshot(&pool).await;
    let mut conn = pool.acquire().await.expect("conn");
    let report = run(&mut conn, &cal, &opts(false, 7))
        .await
        .expect("dry run");
    drop(conn);
    assert_eq!(snapshot(&pool).await, before, "a dry run wrote");
    assert_eq!(report.written, 0);
    assert!(report.complete);
    let got: BTreeMap<String, (u64, u64, u64)> = report
        .per_writer
        .iter()
        .map(|(w, c)| {
            (
                w.clone(),
                (
                    c.scanned,
                    c.typed.values().sum::<u64>(),
                    c.left_null.values().sum::<u64>(),
                ),
            )
        })
        .collect();
    assert_eq!(got, expected_writer_counts(&fx));
    assert_eq!(
        report.per_writer["Dempster"]
            .left_null
            .get(&LeaveNull::CachedCombination),
        Some(&1)
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn apply_types_exactly_the_decided_rows_and_a_second_run_is_a_no_op(pool: PgPool) {
    let cal = calibration();
    let fx = seed_fixture(&pool).await;
    let before = snapshot(&pool).await;
    let beliefs_before = belief_snapshot(&pool).await;
    assert!(
        !beliefs_before.0.is_empty(),
        "CALIBRATION: the fixture has claims"
    );

    let mut conn = pool.acquire().await.expect("conn");
    let first = run(&mut conn, &cal, &opts(true, 4)).await.expect("apply");
    let after = snapshot(&pool).await;
    assert_eq!(
        belief_snapshot(&pool).await,
        beliefs_before,
        "the apply changed a claim or a cached combined belief"
    );

    let want_typed: BTreeMap<Uuid, String> = fx
        .expected
        .iter()
        .filter_map(|(id, _, d)| match d {
            Decision::Type { evidence_type, .. } => Some((*id, evidence_type.clone())),
            Decision::LeaveNull(_) => None,
        })
        .collect();
    assert!(want_typed.len() >= 8, "CALIBRATION: the fixture types rows");
    assert_eq!(first.written, want_typed.len() as u64, "{first:?}");
    assert!(first.batches > 1, "CALIBRATION: the run paged");

    assert_eq!(before.len(), after.len());
    for (id, (t_before, rest_before)) in &before {
        let (t_after, rest_after) = &after[id];
        assert_eq!(
            rest_after, rest_before,
            "row {id}: a column other than evidence_type changed"
        );
        match want_typed.get(id) {
            Some(t) => assert_eq!(t_after.as_deref(), Some(t.as_str()), "row {id}"),
            None => assert_eq!(t_after, t_before, "row {id} was left-null but changed"),
        }
    }

    // Second run: scans only what is still untyped and writes nothing.
    let second = run(&mut conn, &cal, &opts(true, 4))
        .await
        .expect("re-apply");
    assert_eq!(second.written, 0, "{second:?}");
    assert_eq!(second.decided_typed, 0, "{second:?}");
    assert_eq!(second.left_null, first.left_null);
    assert_eq!(snapshot(&pool).await, after, "a second run changed rows");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_bounded_run_resumes_from_its_last_id(pool: PgPool) {
    let cal = calibration();
    let fx = seed_fixture(&pool).await;
    let mut conn = pool.acquire().await.expect("conn");

    // Dry runs: nothing leaves the untyped set, so a resume that ignored
    // `--after` would rescan the first batch and over-count.
    let part = run(
        &mut conn,
        &cal,
        &Options {
            apply: false,
            batch: 5,
            after: None,
            max_batches: Some(1),
        },
    )
    .await
    .expect("first batch");
    assert!(!part.complete);
    assert_eq!(part.scanned, 5);
    let last = part.last_id.expect("a bounded run reports its last id");
    let rest = run(
        &mut conn,
        &cal,
        &Options {
            apply: false,
            batch: 5,
            after: part.last_id,
            max_batches: None,
        },
    )
    .await
    .expect("the rest");
    assert!(rest.complete);
    assert_eq!(part.scanned + rest.scanned, fx.expected.len() as u64);
    let typed = fx
        .expected
        .iter()
        .filter(|(_, _, d)| matches!(d, Decision::Type { .. }))
        .count() as u64;
    assert_eq!(part.decided_typed + rest.decided_typed, typed);
    let resumed = MassFunctionRepository::untyped_provenance_page(&mut *conn, Some(last), 10_000)
        .await
        .expect("resumed page");
    assert_eq!(resumed.len() as u64, rest.scanned);
    assert!(
        resumed.iter().all(|r| r.id > last),
        "the resumed page starts at or before the cursor"
    );

    // Applied in the same two parts, every decided row is written once.
    let a = run(
        &mut conn,
        &cal,
        &Options {
            apply: true,
            batch: 5,
            after: None,
            max_batches: Some(1),
        },
    )
    .await
    .expect("first applied batch");
    let b = run(
        &mut conn,
        &cal,
        &Options {
            apply: true,
            batch: 5,
            after: a.last_id,
            max_batches: None,
        },
    )
    .await
    .expect("the applied rest");
    assert_eq!(a.written + b.written, typed);
}

#[sqlx::test(migrations = "../../migrations")]
async fn typing_changes_only_the_documented_lens_weight(pool: PgPool) {
    let cal = calibration();
    let fx = seed_fixture(&pool).await;
    let ids: Vec<Uuid> = fx.expected.iter().map(|(id, _, _)| *id).collect();
    // A perspective whose reliability for every canonical type the fixture
    // can be typed with differs from calibration: the lens bc06ec6f is about.
    const LENS: f64 = 0.42;
    let mut lens = epigraph_engine::edge_factor::PerspectiveReliability::default();
    for t in [
        "empirical",
        "statistical",
        "logical",
        "testimonial",
        "circumstantial",
    ] {
        assert!(
            (cal.evidence_type_weights[t] - LENS).abs() > 1e-6,
            "CALIBRATION: {t}'s calibrated weight equals the lens value"
        );
        lens.source_reliability.insert(t.to_string(), LENS);
    }
    let with_lens = |row: &MassFunctionRow| {
        epigraph_engine::edge_factor::effective_source_strength_with_perspective(
            row, None, None, &cal, &lens,
        )
    };
    let mut weight_before = BTreeMap::new();
    let mut lens_before = BTreeMap::new();
    for id in &ids {
        let row = mf_row(&pool, *id).await;
        let global =
            epigraph_engine::edge_factor::effective_source_strength(&row, None, None, &cal);
        // Untyped, the row is invisible to the lens: it reads the global value.
        assert!(
            (with_lens(&row) - global).abs() < 1e-12,
            "row {id}: the lens saw an untyped row"
        );
        weight_before.insert(*id, global);
        lens_before.insert(*id, with_lens(&row));
    }

    let mut conn = pool.acquire().await.expect("conn");
    run(&mut conn, &cal, &opts(true, 1000))
        .await
        .expect("apply");

    let intra = cal.evidence_locality.intra_evidence_locality_factor;
    let mut moved = 0;
    for (id, _, d) in &fx.expected {
        let row = mf_row(&pool, *id).await;
        let w = epigraph_engine::edge_factor::effective_source_strength(&row, None, None, &cal);
        let lw = with_lens(&row);
        let locality = if row.locality_tag.starts_with("intra") {
            intra
        } else {
            1.0
        };
        match d {
            Decision::Type { evidence_type, .. } => {
                let want = cal.evidence_type_weights[evidence_type.as_str()] * locality;
                assert!(
                    (w - want).abs() < 1e-12,
                    "row {id}: weight {w}, documented {want}"
                );
                if (w - weight_before[id]).abs() > 1e-9 {
                    moved += 1;
                }
                // Typed, the row is visible to the lens: it reads the
                // perspective's reliability for its type, which it did not
                // before.
                assert!(
                    (lw - LENS * locality).abs() < 1e-12,
                    "row {id}: lens weight {lw}, want {}",
                    LENS * locality
                );
                assert!(
                    (lens_before[id] - LENS * locality).abs() > 1e-9,
                    "CALIBRATION: row {id} already read the lens value before the apply"
                );
            }
            Decision::LeaveNull(_) => {
                assert!(
                    (w - weight_before[id]).abs() < 1e-12,
                    "row {id} was left NULL but its weight moved"
                );
                assert!(
                    (lw - lens_before[id]).abs() < 1e-12,
                    "row {id} was left NULL but its lens weight moved"
                );
            }
        }
    }
    assert!(
        moved > 0,
        "CALIBRATION: typing moved no weight, so this test proves nothing"
    );
    let row = mf_row(&pool, fx.intra_typed).await;
    let w = epigraph_engine::edge_factor::effective_source_strength(&row, None, None, &cal);
    assert!(
        (w - cal.evidence_type_weights["logical"] * intra).abs() < 1e-12,
        "the intra locality discount must compose with the typed weight"
    );
    // The truth_value seed keeps its exempt (undiscounted) reliability, so its
    // BetP stays the claim's truth_value.
    let row = mf_row(&pool, fx.truth_value_seed).await;
    let w = epigraph_engine::edge_factor::effective_source_strength(&row, None, None, &cal);
    assert!(
        (w - 1.0).abs() < 1e-12,
        "the truth_value seed's reliability moved to {w}; it must stay 1.0"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_type_a_writer_stored_after_the_read_is_kept(pool: PgPool) {
    let fx = seed_fixture(&pool).await;
    let (id, _, _) = fx.expected[0];
    sqlx::query("UPDATE mass_functions SET evidence_type = 'statistical' WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .expect("a writer types the row");
    let n = MassFunctionRepository::backfill_evidence_type_where_untyped(
        &pool,
        &[id],
        &["logical".to_string()],
    )
    .await
    .expect("backfill");
    assert_eq!(n, 0);
    let t: Option<String> =
        sqlx::query_scalar("SELECT evidence_type FROM mass_functions WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("read");
    assert_eq!(t.as_deref(), Some("statistical"));
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_type_the_calibration_cannot_weigh_is_left_null(pool: PgPool) {
    let fx = seed_fixture(&pool).await;
    let path = calibration_variant(|line| !line.trim_start().starts_with("logical"));
    let cal = CalibrationConfig::load(&path).expect("load the variant");
    let _ = std::fs::remove_file(&path);
    assert!(
        !cal.evidence_type_weight_present("logical"),
        "CALIBRATION: the variant still weighs logical"
    );
    let page = MassFunctionRepository::untyped_provenance_page(&pool, None, 10_000)
        .await
        .expect("page");
    let decided: BTreeMap<Uuid, Decision> = page.iter().map(|r| (r.id, decide(r, &cal))).collect();
    let mut uncalibrated = 0;
    for (id, writer, want) in &fx.expected {
        let want = match want {
            Decision::Type { evidence_type, .. } if evidence_type == "logical" => {
                uncalibrated += 1;
                null(LeaveNull::Uncalibrated)
            }
            other => other.clone(),
        };
        assert_eq!(decided.get(id), Some(&want), "{writer} {id}");
    }
    assert!(
        uncalibrated > 0,
        "CALIBRATION: no fixture row is typed logical"
    );
}

// ── the binary, as a real process on real LOGIN roles ──────────────────────

async fn create_login(pool: &PgPool, parent: &str) -> (String, String) {
    let role = format!("bc06_{}_{}", parent, Uuid::new_v4().simple());
    let password = Uuid::new_v4().simple().to_string();
    sqlx::query(&format!(
        "CREATE ROLE {role} LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '{password}' IN ROLE {parent}"
    ))
    .execute(pool)
    .await
    .expect("create the login");
    let base = viewer_fixture::database_url_for(pool).await;
    let scheme_end = base.find("://").expect("a scheme") + 3;
    let host_path = &base[base.find('@').expect("credentials in the DSN") + 1..];
    let url = format!("{}{role}:{password}@{host_path}", &base[..scheme_end]);
    (role, url)
}

async fn drop_login(pool: &PgPool, role: &str) {
    let _ = sqlx::query(&format!("DROP ROLE IF EXISTS {role}"))
        .execute(pool)
        .await;
}

struct Out {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run_bin(args: &[&str], database_url: &str, maintenance_url: Option<&str>) -> Out {
    let mut cmd = Command::new(BIN);
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("DATABASE_URL", database_url)
        .env("RUST_LOG", "warn")
        .args(args)
        .current_dir(std::env::temp_dir());
    if let Some(m) = maintenance_url {
        cmd.env("MAINTENANCE_DATABASE_URL", m);
    }
    let out = cmd.output().expect("run the binary");
    Out {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_binary_refuses_the_application_dsn_and_writes_on_the_maintenance_login(pool: PgPool) {
    let fx = seed_fixture(&pool).await;
    let (app_role, app_url) = create_login(&pool, "epigraph_app").await;
    let (maint_role, maint_url) = create_login(&pool, "epigraph_maintenance").await;
    let cal = calibration_path();
    let cal = cal.to_str().expect("utf-8 path");
    let before = snapshot(&pool).await;

    // No configured maintenance DSN: refused, nothing written.
    let r = run_bin(&["--calibration", cal, "--apply"], &maint_url, None);
    assert_ne!(r.code, Some(0), "{}", r.stderr);
    assert!(
        r.stderr
            .contains("runs only on an explicitly configured MAINTENANCE_DATABASE_URL"),
        "{}",
        r.stderr
    );
    // A calibration that does not load: refused before any connection.
    let r = run_bin(
        &["--calibration", "/nonexistent/calibration.toml", "--apply"],
        &app_url,
        Some(&maint_url),
    );
    assert_ne!(r.code, Some(0), "{}", r.stderr);
    assert!(r.stderr.contains("--calibration"), "{}", r.stderr);
    // A calibration that loads but weighs no type: refused.
    let empty = calibration_variant(|_| false);
    let r = run_bin(
        &["--calibration", empty.to_str().expect("utf-8"), "--apply"],
        &app_url,
        Some(&maint_url),
    );
    let _ = std::fs::remove_file(&empty);
    assert_ne!(r.code, Some(0), "{}", r.stderr);
    assert!(
        r.stderr.contains("has no [evidence_type_weights]"),
        "{}",
        r.stderr
    );
    // An application login configured AS the maintenance DSN: it cannot
    // bypass row security, so the maintenance pool refuses it at connect.
    let r = run_bin(&["--calibration", cal, "--apply"], &app_url, Some(&app_url));
    assert_ne!(r.code, Some(0), "{}", r.stderr);
    assert!(
        r.stderr.contains("does not satisfy epigraph_bypass()"),
        "{}",
        r.stderr
    );
    assert_eq!(snapshot(&pool).await, before, "a refused run wrote");

    // Dry run (the default): the report, and nothing written.
    let r = run_bin(&["--calibration", cal], &app_url, Some(&maint_url));
    assert_eq!(r.code, Some(0), "{}", r.stderr);
    let dry: serde_json::Value = serde_json::from_str(&r.stdout).expect("JSON report");
    assert_eq!(snapshot(&pool).await, before, "a dry run wrote");
    let typed = fx
        .expected
        .iter()
        .filter(|(_, _, d)| matches!(d, Decision::Type { .. }))
        .count() as u64;
    assert_eq!(dry["decided_typed"], typed, "{dry}");
    assert_eq!(dry["written"], 0, "{dry}");

    // --apply on the maintenance login writes, and a second apply writes nothing.
    let r = run_bin(
        &["--calibration", cal, "--apply", "--batch", "3"],
        &app_url,
        Some(&maint_url),
    );
    assert_eq!(r.code, Some(0), "{}", r.stderr);
    let applied: serde_json::Value = serde_json::from_str(&r.stdout).expect("JSON report");
    assert_eq!(applied["written"], typed, "{applied}");
    assert_eq!(
        applied["per_writer"]["Dempster"]["left_null"]["cached_combination"], 1,
        "{applied}"
    );
    let r = run_bin(
        &["--calibration", cal, "--apply"],
        &app_url,
        Some(&maint_url),
    );
    assert_eq!(r.code, Some(0), "{}", r.stderr);
    let again: serde_json::Value = serde_json::from_str(&r.stdout).expect("JSON report");
    assert_eq!(again["written"], 0, "{again}");

    drop_login(&pool, &app_role).await;
    drop_login(&pool, &maint_role).await;
}
