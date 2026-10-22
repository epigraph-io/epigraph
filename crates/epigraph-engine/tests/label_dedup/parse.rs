//! The record parser and the comparison keys.

use epigraph_engine::label_dedup::record::{
    entities_match, entity_tokens, parse_content, title_tokens,
};

use crate::fixtures::{self as f, parsed, pass};

fn entities(a: &str, b: &str) -> bool {
    let p = pass();
    let ea = entity_tokens(&p, parse_content(&p, a).entity.as_deref());
    let eb = entity_tokens(&p, parse_content(&p, b).entity.as_deref());
    entities_match(&p, ea.as_ref(), eb.as_ref())
}

#[test]
fn parses_pipe_layout() {
    let facts = parse_content(&pass(), f::WING_FEED);
    assert_eq!(facts.title, "Kestrel Wing Refit TND 47310K");
    assert_eq!(facts.entity.as_deref(), Some("Acme Campus Lodging Office"));
    assert_eq!(facts.deadline.as_deref(), Some("2026-08-12"));
    assert_eq!(facts.value, None, "`est. unknown` is missing");
    assert_eq!(facts.class.as_deref(), Some("open"));
}

#[test]
fn parses_prose_layout_past_a_parenthetical() {
    let facts = parse_content(&pass(), f::AGREEMENT_Q23_OLD);
    assert_eq!(
        facts.entity.as_deref(),
        Some("Acme City Public Operations"),
        "the entity sits after the dash, past the `(Solicitation …)` in the title"
    );
    assert!(facts.title.contains("Q23"), "{}", facts.title);
    assert_eq!(facts.deadline.as_deref(), Some("2026-06-30"));
    assert_eq!(facts.value.as_deref(), Some("$2.4M"));
}

#[test]
fn prose_entity_stops_at_comma_and_paren_and_value_keeps_thousands() {
    let facts = parse_content(&pass(), f::AGREEMENT_Q23_NEW);
    assert_eq!(
        facts.entity.as_deref(),
        Some("AC Department of Public Operations")
    );
    assert_eq!(
        facts.value.as_deref(),
        Some("$2,400,000"),
        "thousands separators stay inside the value"
    );
}

#[test]
fn parses_header_dash_prose_and_keyed_pipe_layouts() {
    let trails = parse_content(&pass(), f::PATHS_HEADER);
    assert_eq!(trails.entity.as_deref(), Some("ACRB"));
    assert_eq!(
        trails.title,
        "Path Mapping Helpdesk Advisor Tender FY28-35-TND"
    );
    assert_eq!(trails.deadline.as_deref(), Some("2026-07-24"));

    let pool = parse_content(&pass(), f::BENCH_KEYED);
    assert_eq!(pool.entity.as_deref(), Some("Acme City School District"));
    assert!(
        pool.title.starts_with("TND Bench of Roofing"),
        "{}",
        pool.title
    );
    assert_eq!(pool.deadline, None, "`Due: TBD` is missing");
    assert_eq!(pool.value, None, "`Value: unknown` is missing");
}

#[test]
fn a_short_pipe_title_prefix_becomes_the_entity_when_none_is_keyed() {
    let facts = parse_content(
        &pass(),
        "ACSD: TND Bench of Roofing Firms | sector:school | due 2026-09-01 | est. unknown",
    );
    assert_eq!(facts.title, "TND Bench of Roofing Firms");
    assert_eq!(facts.entity.as_deref(), Some("ACSD"));
}

#[test]
fn flag_and_label_spellings_canonicalize_to_one_class() {
    let from_content = parse_content(&pass(), f::PANEL_NEW);
    assert_eq!(from_content.class.as_deref(), Some("listed-opportunity"));
    let from_label = parsed(
        1,
        f::PANEL_OLD,
        &["notice", "class:listed-opp"],
        "2026-06-14T00:00:00Z",
    );
    assert_eq!(
        from_label.facts.class, from_content.class,
        "the flag spelling and the label spelling are one class"
    );
    // The content flag wins over the label by default.
    let both = parsed(
        2,
        f::PANEL_NEW,
        &["notice", "class:review"],
        "2026-06-14T00:00:00Z",
    );
    assert_eq!(both.facts.class.as_deref(), Some("listed-opportunity"));
}

#[test]
fn a_label_first_field_reads_the_label_before_the_content() {
    let mut v = f::profile_value();
    v["fields"]["class"]["prefer_label"] = true.into();
    v["fields"]["extra"] = serde_json::json!({"kind": {"from_label_prefix": "kind:"}});
    let p = f::load(&v);
    let claim = f::claim(
        3,
        f::PANEL_NEW,
        &["notice", "class:review", "kind:framework"],
        "2026-06-14T00:00:00Z",
    );
    let rec = epigraph_engine::label_dedup::parse_record(&p.pass, &claim);
    assert_eq!(rec.facts.class.as_deref(), Some("review"));
    assert_eq!(rec.facts.field("kind"), Some("framework"));
    // Control: without the label the content flag is used.
    let bare = f::claim(4, f::PANEL_NEW, &["notice"], "2026-06-14T00:00:00Z");
    let rec = epigraph_engine::label_dedup::parse_record(&p.pass, &bare);
    assert_eq!(rec.facts.class.as_deref(), Some("listed-opportunity"));
    assert_eq!(rec.facts.field("kind"), None);
}

#[test]
fn entity_aliases_collapse_abbreviations() {
    assert!(
        entities(f::WEIR_LATE, f::WEIR_EARLY),
        "`Acme County PUA` must match `Acme County Public Utility Authority`"
    );
    assert!(
        entities(f::AGREEMENT_Q23_NEW, f::AGREEMENT_Q23_OLD),
        "`AC Department of Public Operations` must match `Acme City Public Operations`"
    );
}

#[test]
fn unrelated_entities_do_not_match() {
    assert!(!entities(f::AGREEMENT_Q23_NEW, f::PATHS_HEADER));
    // Control: the same entity matches itself.
    assert!(entities(f::AGREEMENT_Q23_NEW, f::AGREEMENT_Q22_NEW));
    // An unknown entity matches nothing, not even another unknown one.
    let p = pass();
    assert!(!entities_match(&p, None, None));
}

#[test]
fn match_keys_are_computed_at_parse_time() {
    // Pairing is O(n²): keys derived inside the comparison cost two orders of
    // magnitude on a large family, and a wrong cache is silently wrong.
    let p = pass();
    let r = parsed(
        5,
        f::WING_DIRECT,
        &["notice", "src-direct-c"],
        "2026-06-29T00:00:00Z",
    );
    assert_eq!(r.keys.title_tokens, title_tokens(&p, &r.facts.title));
    assert_eq!(
        r.keys.entity_tokens,
        entity_tokens(&p, r.facts.entity.as_deref())
    );
    assert_eq!(
        r.keys.strong_ids,
        r.facts
            .ids
            .iter()
            .filter(|i| i.strong)
            .map(|i| i.norm.clone())
            .collect()
    );
    assert_eq!(
        r.keys.all_ids,
        r.facts.ids.iter().map(|i| i.norm.clone()).collect()
    );
    assert!(r.keys.strong_ids.contains("47310K"));
    assert!(!r.keys.title_key.is_empty());
    assert!(
        !r.keys.title_tokens.contains("tnd"),
        "stopwords are dropped"
    );
}

#[test]
fn a_prose_deadline_never_panics_on_a_multibyte_boundary() {
    let facts = parse_content(&pass(), f::PROSE_DUE_MULTIBYTE);
    assert_eq!(facts.deadline.as_deref(), Some("late Oct — see notice"));
    assert_eq!(
        epigraph_engine::label_dedup::iso_prefix_date("late Oct — see notice"),
        None
    );
    assert_eq!(
        epigraph_engine::label_dedup::iso_prefix_date("2026-07-15 (extended)"),
        Some(f::date("2026-07-15"))
    );
}

#[test]
fn carried_ids_join_the_id_set() {
    let r = parsed(
        6,
        f::WING_FEED,
        &["notice", "also-id:ZZ9911"],
        "2026-06-29T00:00:00Z",
    );
    assert!(
        r.keys.strong_ids.contains("ZZ9911"),
        "{:?}",
        r.keys.strong_ids
    );
    assert!(r.keys.strong_ids.contains("47310K"));
    // The legacy profile has no carry prefix: the label is just a label.
    let legacy = epigraph_engine::label_dedup::parse_record(
        &f::legacy_profile().pass,
        &f::claim(
            6,
            f::WING_FEED,
            &["notice", "also-id:ZZ9911"],
            "2026-06-29T00:00:00Z",
        ),
    );
    assert!(!legacy.keys.strong_ids.contains("ZZ9911"));
}
