//! The profile: schema, pinning, template validation and reads.

use epigraph_engine::label_dedup::profile::profile_hash;
use epigraph_engine::label_dedup::{LabelDedupProfile, ReadPurpose, Section};

use crate::fixtures::{self as f, bytes, profile_value};

fn schema_error(v: &serde_json::Value) -> String {
    match LabelDedupProfile::from_json_bytes(&bytes(v)) {
        Ok(_) => panic!("profile must be refused: {v}"),
        Err(e) => {
            assert_eq!(e.code(), "PROFILE_SCHEMA_INVALID", "{e}");
            e.to_string()
        }
    }
}

#[test]
fn the_hash_is_blake3_of_the_exact_bytes() {
    let b = bytes(&profile_value());
    let h = profile_hash(&b);
    assert_eq!(h.len(), 64);
    assert!(
        h.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "{h}"
    );
    assert_eq!(
        h,
        epigraph_crypto::ContentHasher::to_hex(&epigraph_crypto::ContentHasher::hash(&b))
    );
    // One byte of whitespace is a different profile.
    let mut spaced = b.clone();
    spaced.push(b' ');
    assert_ne!(profile_hash(&spaced), h);
}

#[test]
fn a_pinned_load_refuses_a_hash_mismatch_before_parsing() {
    let b = bytes(&profile_value());
    let (p, h) = LabelDedupProfile::load_pinned(&b, &profile_hash(&b)).expect("pinned load");
    assert_eq!(p.pass.family_label, "notice");
    assert_eq!(h, profile_hash(&b));
    let wrong = "0".repeat(64);
    let err = LabelDedupProfile::load_pinned(&b, &wrong).expect_err("mismatch");
    assert_eq!(err.code(), "PROFILE_HASH_MISMATCH", "{err}");
    // The hash is checked first: garbage under a wrong pin is a mismatch,
    // never a parse error that echoes the bytes.
    let err = LabelDedupProfile::load_pinned(b"not json", &wrong).expect_err("mismatch");
    assert_eq!(err.code(), "PROFILE_HASH_MISMATCH", "{err}");
}

#[test]
fn unknown_keys_and_a_wrong_schema_are_refused() {
    let mut v = profile_value();
    v["family_lable"] = "notice".into();
    assert!(schema_error(&v).contains("family_lable"));
    let mut v = profile_value();
    v["fields"]["deadline"]["markers"] = serde_json::json!(["due "]);
    schema_error(&v);
    let mut v = profile_value();
    // The previous schema (loser relabelling, carried values) is refused.
    v["schema"] = "label-dedup-profile/v1".into();
    schema_error(&v);
    let mut v = profile_value();
    v.as_object_mut().expect("object").remove("family_label");
    schema_error(&v);
    let mut v = profile_value();
    v["ids"]["strong_patterns"] = serde_json::json!(["(unclosed"]);
    schema_error(&v);
    // Control: the fixture itself is valid.
    LabelDedupProfile::from_json_bytes(&bytes(&profile_value())).expect("valid");
}

#[test]
fn a_minimal_profile_has_empty_defaults() {
    let v = serde_json::json!({
        "schema": "label-dedup-profile/v2",
        "family_label": "notice",
        "family_kind": "index"
    });
    let p = LabelDedupProfile::from_json_bytes(&bytes(&v)).expect("minimal profile");
    assert!(p.pass.retired_labels.is_empty());
    assert!(p.pass.entity_match.aliases.is_empty());
    assert!(p.pass.title_match.stopwords.is_empty());
    assert!(p.pass.ids.reject.is_empty());
    assert!(p.pass.precedence.rank_label_groups.is_empty());
    assert!(p.pass.closed_label.is_none());
    assert!(p.closeout.is_none() && p.lifecycle.is_none());
    // With no reject rules nothing is rejected: there is no built-in date list.
    let ids = epigraph_engine::label_dedup::extract_ids(&p.pass.ids, "due 2026-07-15 ref 20260715");
    assert!(ids.iter().any(|i| i.norm == "20260715"), "{ids:?}");
    // Writes are not defaulted: a section without its template is refused.
    let err = p.reads(&[Section::Dedup]).expect_err("no merge template");
    assert_eq!(err.code(), "SECTION_NOT_CONFIGURED");
    let err = p
        .reads(&[Section::Hygiene])
        .expect_err("no hygiene template");
    assert_eq!(err.code(), "SECTION_NOT_CONFIGURED");
}

#[test]
fn a_retirement_that_does_not_leave_the_family_is_refused() {
    // Otherwise an applied plan re-plans the same writes forever.
    let mut v = profile_value();
    v["hygiene_write"] = serde_json::json!({"add": ["{run_tag}"], "remove": []});
    assert!(schema_error(&v).contains("hygiene_write"));
    let mut v = profile_value();
    v["closeout"]["add"] = serde_json::json!(["closed-past-due", "{run_tag}"]);
    assert!(schema_error(&v).contains("closeout"));
    let mut v = profile_value();
    v["lifecycle"]["age_out_add"] = serde_json::json!(["aged-out"]);
    assert!(schema_error(&v).contains("age_out_add"));
    // Control: the literal family label works as well as `{family}`.
    let mut v = profile_value();
    v["hygiene_write"] = serde_json::json!({"add": ["{run_tag}"], "remove": ["notice"]});
    f::load(&v);
}

#[test]
fn placeholders_are_bound_only_where_they_have_a_value() {
    // `{survivor}` is bound in no write a profile declares (losers are marked,
    // not relabelled); in a survivor write it would expand to the claim's own
    // id, so it is refused.
    let mut v = profile_value();
    v["merge"]["survivor_add"] = serde_json::json!(["dup-of:{survivor}"]);
    assert!(schema_error(&v).contains("{survivor}"));
    let mut v = profile_value();
    v["hygiene_write"]["add"] = serde_json::json!(["{target}"]);
    schema_error(&v);
    let mut v = profile_value();
    v["merge"]["survivor_add"] = serde_json::json!(["{oops}", "{run_tag}"]);
    schema_error(&v);
    // A literal that the write path refuses is refused at load time.
    let mut v = profile_value();
    v["merge"]["survivor_add"] = serde_json::json!(["cost$"]);
    schema_error(&v);
    // Control: `{target}` is bound in a graduation write.
    f::load(&profile_value());
}

#[test]
fn reads_name_every_input_a_plan_needs() {
    let p = f::profile();
    let reads = p.reads(&[Section::Dedup, Section::Hygiene]).expect("reads");
    assert_eq!(reads.len(), 1);
    assert_eq!(reads[0].purpose, ReadPurpose::Members);
    assert_eq!(reads[0].include, vec!["notice".to_string()]);
    assert_eq!(
        reads[0].exclude,
        vec!["resolved".to_string()],
        "retired labels are LOADED, closed ones are not"
    );
    assert!(reads[0].current_only);

    let reads = p
        .reads(&[Section::Lifecycle, Section::Closeout])
        .expect("reads");
    let purposes: Vec<_> = reads.iter().map(|r| r.purpose).collect();
    assert_eq!(
        purposes,
        vec![
            ReadPurpose::Members,
            ReadPurpose::LifecycleSignals,
            ReadPurpose::LifecycleTargets
        ]
    );
    assert_eq!(reads[1].include, vec!["lead".to_string()]);
    assert_eq!(reads[1].exclude, vec!["resolved".to_string()]);
    assert_eq!(reads[2].include, vec!["notice".to_string()]);
    assert!(
        !reads[2].exclude.contains(&"resolved".to_string()),
        "the graduation index keeps closed members"
    );
    assert!(reads[2].exclude.contains(&"notice-duplicate".to_string()));

    // `matches` is the read's own filter.
    let labels = |l: &[&str]| l.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
    assert!(reads[0].matches(&labels(&["notice", "src-feed"])));
    assert!(!reads[0].matches(&labels(&["notice", "resolved"])));
    assert!(!reads[0].matches(&labels(&["lead"])));

    let probe = p.probe_reads(true).expect("probe reads");
    assert_eq!(probe.len(), 2);
    assert_eq!(probe[1].purpose, ReadPurpose::ClosedSignals);
    assert_eq!(
        probe[1].include,
        vec!["lead".to_string(), "resolved".to_string()]
    );
    assert_eq!(p.probe_reads(false).expect("probe reads").len(), 1);
}

#[test]
fn sections_normalize_before_hashing() {
    assert_eq!(
        Section::normalize(&[Section::Dedup, Section::Hygiene, Section::Dedup]),
        vec![Section::Hygiene, Section::Dedup]
    );
    assert_eq!(Section::normalize(&[]), Section::default_set());
}

// ── Knobs: each one changes an outcome, and the default is the control ─────

fn survivor_of(
    prof: &LabelDedupProfile,
    graph: &[epigraph_engine::label_dedup::DedupClaim],
) -> uuid::Uuid {
    let p = f::plan_graph(prof, graph, &f::dedup_sections(), None);
    assert_eq!(
        p.clusters.len(),
        1,
        "the pair must cluster: {:?}",
        p.clusters
    );
    p.clusters[0].survivor
}

/// A sparse claim (newer) and a complete one (older), same item.
fn sparse_and_full() -> Vec<epigraph_engine::label_dedup::DedupClaim> {
    vec![
        f::claim(
            1,
            f::WIDGET_SPARSE,
            &["notice", "src-direct-a"],
            "2026-07-20T00:00:00Z",
        ),
        f::claim(
            2,
            f::WIDGET_FULL,
            &["notice", "src-direct-a"],
            "2026-07-01T00:00:00Z",
        ),
    ]
}

#[test]
fn a_not_unknown_value_stops_counting_against_completeness() {
    // Control: `unknown` is missing, so the complete claim survives.
    assert_eq!(survivor_of(&f::profile(), &sparse_and_full()), f::id(2));
    // Listed in `not_unknown` too, it is a value: completeness ties and the
    // newer claim survives.
    let mut v = profile_value();
    v["unknown"]["not_unknown"] = serde_json::json!(["Unknown"]);
    assert_eq!(survivor_of(&f::load(&v), &sparse_and_full()), f::id(1));
}

#[test]
fn the_tie_break_order_comes_from_the_profile() {
    // Default order: fewest unknown, then newest.
    assert_eq!(survivor_of(&f::profile(), &sparse_and_full()), f::id(2));
    let mut v = profile_value();
    v["precedence"]["then"] =
        serde_json::json!(["newest_created_at", "fewest_unknown", "smallest_id"]);
    assert_eq!(survivor_of(&f::load(&v), &sparse_and_full()), f::id(1));
}

#[test]
fn index_exclude_labels_keep_claims_out_of_the_member_read() {
    let graph = vec![
        f::claim(
            1,
            f::WING_FEED,
            &["notice", "src-feed", "on-hold"],
            "2026-06-28T00:00:00Z",
        ),
        f::claim(
            2,
            f::WING_DIRECT,
            &["notice", "src-direct-c"],
            "2026-06-29T00:00:00Z",
        ),
    ];
    // Control: without the knob the pair clusters.
    let p = f::plan_graph(&f::profile(), &graph, &f::dedup_sections(), None);
    assert_eq!(p.clusters.len(), 1);
    let mut v = profile_value();
    v["index_exclude_labels"] = serde_json::json!(["on-hold"]);
    let prof = f::load(&v);
    let reads = prof.reads(&[Section::Dedup]).expect("reads");
    assert_eq!(
        reads[0].exclude,
        vec!["resolved".to_string(), "on-hold".to_string()]
    );
    let p = f::plan_graph(&prof, &graph, &f::dedup_sections(), None);
    assert!(p.clusters.is_empty() && p.hygiene.is_empty(), "{p:?}");
    assert_eq!(p.coverage.members, 1);
}

#[test]
fn match_thresholds_come_from_the_profile() {
    // Entity overlap 4/5 = 0.8: a match at the default threshold only.
    let pier = |tag: u32, side: &str| {
        f::claim(
            tag,
            &format!("[OPEN] Pier Lamp Swap | Acme Harbor Port Board {side} | sector:city | due unknown | est. unknown | lamps"),
            &["notice"],
            "2026-06-28T00:00:00Z",
        )
    };
    let piers = [pier(1, "North"), pier(2, "South")];
    let p = f::plan_graph(&f::profile(), &piers, &f::dedup_sections(), None);
    assert_eq!(p.clusters.len(), 1, "control: {:?}", p.review_pairs);
    let mut v = profile_value();
    v["entity_match"]["threshold"] = serde_json::json!(0.9);
    let p = f::plan_graph(&f::load(&v), &piers, &f::dedup_sections(), None);
    assert!(p.clusters.is_empty(), "{:?}", p.clusters);

    // A preference-track variant is queued for review by default...
    let murals = [
        f::claim(1, f::MURAL_STD, &["notice"], "2026-06-22T00:00:00Z"),
        f::claim(2, f::MURAL_MSB, &["notice"], "2026-06-22T00:00:00Z"),
    ];
    let p = f::plan_graph(&f::profile(), &murals, &f::dedup_sections(), None);
    assert_eq!(p.review_pairs.len(), 1, "control");
    // ...but not when its titles are shorter than the fuzzy minimum.
    let mut v = profile_value();
    v["title_match"]["fuzzy_min_tokens"] = serde_json::json!(12);
    let p = f::plan_graph(&f::load(&v), &murals, &f::dedup_sections(), None);
    assert!(p.review_pairs.is_empty(), "{:?}", p.review_pairs);
}
