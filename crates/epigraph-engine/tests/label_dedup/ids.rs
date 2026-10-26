//! Id tokenization.

use epigraph_engine::label_dedup::extract_ids;

use crate::fixtures::{self as f, pass};

fn norms(content: &str) -> Vec<String> {
    extract_ids(&pass().ids, content)
        .into_iter()
        .map(|i| i.norm)
        .collect()
}

fn has_strong(content: &str, norm: &str) -> bool {
    extract_ids(&pass().ids, content)
        .iter()
        .any(|i| i.norm == norm && i.strong)
}

#[test]
fn ids_normalize_identically_across_layouts() {
    // Pipe and prose spellings of one id normalize to one key, which is
    // how the two layouts find each other.
    let key = "ACSDFACLCPFY29317";
    assert!(has_strong(f::PANEL_NEW, key), "{:?}", norms(f::PANEL_NEW));
    assert!(has_strong(f::PANEL_OLD, key), "{:?}", norms(f::PANEL_OLD));
    // Bare in one claim, parenthesized in the other.
    assert!(has_strong(f::WEIR_LATE, "KX4417"));
    assert!(has_strong(f::WEIR_EARLY, "KX4417"));
    assert!(has_strong(f::AGREEMENT_Q23_OLD, "0000081574"));
    assert!(has_strong(f::WING_FEED, "47310K"));
}

#[test]
fn dates_years_times_and_money_are_not_ids() {
    let ids = norms(f::WEIR_LATE);
    // Positive control: the real id and the weak bid number are found.
    assert!(ids.contains(&"KX4417".to_string()), "{ids:?}");
    assert!(ids.contains(&"5174".to_string()), "{ids:?}");
    for noise in ["20260715", "20260617", "200", "48M", "2026"] {
        assert!(
            !ids.contains(&noise.to_string()),
            "{noise} is not an id: {ids:?}"
        );
    }
    // Thousands separators never produce a digit run.
    let q23 = norms(f::AGREEMENT_Q23_NEW);
    assert!(q23.contains(&"0000081574".to_string()), "{q23:?}");
    assert!(!q23.iter().any(|i| i.contains("2400000")), "{q23:?}");
    // A year range is not an id.
    assert!(norms("2026-2031 Ten Year Upkeep Outline").is_empty());
}

#[test]
fn us_dates_and_fiscal_years_are_not_ids_but_numbering_schemes_are() {
    // `3/26/2026` would normalize to the 7-digit STRONG id `3262026`.
    for (text, noise) in [
        ("permit state:PENDING (recv 3/26/2026)", "3262026"),
        ("permit state:APPROVED 8/11/2025", "8112025"),
        ("update posted 10/1/2026; gutters", "1012026"),
        ("bids open 12/15/26 at the town office", "121526"),
    ] {
        assert!(
            !norms(text).contains(&noise.to_string()),
            "{text:?} must not yield {noise}"
        );
    }
    for text in [
        "Plan B items for the 2026-27 school year",
        "Allocation FY2026-27",
        "Outlay plan FY 2026/27",
    ] {
        assert!(
            norms(text).iter().all(|i| !i.contains("202627")),
            "{text:?}: {:?}",
            norms(text)
        );
    }
    for (text, noise) in [
        ("Allocation FY26-27 for the district", "FY2627"),
        ("Outlay plan FY25/26 upkeep", "FY2526"),
        ("Town plan FY2026 adds upkeep money", "FY2026"),
        ("Plan B outlay in FY26", "FY26"),
    ] {
        assert!(!norms(text).contains(&noise.to_string()), "{text:?}");
    }
    // Year-led numbering that is not a next-year pair stays an id.
    for (text, id) in [
        ("Advisor Tender FY28-35-TND, area", "FY2835TND"),
        ("Bid FY26-41 Gutter Swap", "FY2641"),
        ("Contract FY29_317 panel refresh", "FY29317"),
        ("TND 2026-15 Standby Drafting Support", "202615"),
        ("Contract No. 2026/045-ENG", "2026045ENG"),
    ] {
        assert!(
            has_strong(text, id),
            "{text:?} must yield strong {id}: {:?}",
            norms(text)
        );
    }
}

#[test]
fn short_ids_are_weak() {
    let ids = extract_ids(&pass().ids, "STANDING SUPPORT CONTRACT Q23 FIELD SURVEY");
    let q23 = ids.iter().find(|i| i.norm == "Q23").expect("Q23 extracted");
    assert!(!q23.strong, "a 3-char id must not merge on its own");
    // Control: the length rule promotes a 6-char, 2-digit id.
    assert!(has_strong("Agreement QX0023 general", "QX0023"));
}

#[test]
fn money_and_clock_times_are_rejected_before_trimming() {
    // Rejection runs before trimming; trimmed first, `$350K` reads as `350K`
    // and `2:00` as `200`.
    let hoist = norms(f::HOIST_LISTED);
    assert!(!hoist.contains(&"350K".to_string()), "{hoist:?}");
    let weir = norms(f::WEIR_LATE);
    assert!(
        !weir.contains(&"200".to_string()) && !weir.contains(&"48M".to_string()),
        "{weir:?}"
    );
    assert!(weir.contains(&"KX4417".to_string()), "control: {weir:?}");
}

#[test]
fn reject_and_strong_patterns_come_from_the_profile() {
    let mut v = f::profile_value();
    v["ids"]["reject_patterns"] = serde_json::json!(["^[0-9]{6}$"]);
    v["ids"]["strong_patterns"] = serde_json::json!(["^[0-9]{2}\\.[0-9]{3}$"]);
    let p = f::load(&v);
    let text = "industry code 541715, listing 47.041, ref ZQ-123456";
    let ids = extract_ids(&p.pass.ids, text);
    assert!(
        ids.iter().all(|i| i.norm != "541715"),
        "rejected by pattern: {ids:?}"
    );
    let listing = ids.iter().find(|i| i.norm == "47041").expect("listing id");
    assert!(
        listing.strong,
        "a 5-char id is strong only through the pattern"
    );
    assert!(
        ids.iter().any(|i| i.norm == "ZQ123456" && i.strong),
        "control: {ids:?}"
    );
    // Without the patterns the defaults apply.
    let plain = extract_ids(&pass().ids, text);
    assert!(plain.iter().any(|i| i.norm == "541715"), "{plain:?}");
    assert!(
        plain.iter().any(|i| i.norm == "47041" && !i.strong),
        "{plain:?}"
    );
}

#[test]
fn the_scan_cut_drops_ids_after_the_last_marker() {
    let text = "Lead: permit project Blk-C77 court | permit 01-323022 | notes:New court Blk-D88 per Code-31";
    let cut = norms(text);
    assert!(cut.contains(&"BLKC77".to_string()), "{cut:?}");
    assert!(cut.contains(&"01323022".to_string()), "{cut:?}");
    assert!(
        !cut.contains(&"BLKD88".to_string()) && !cut.contains(&"CODE31".to_string()),
        "{cut:?}"
    );
    // The legacy profile has no cut: everything is scanned.
    let all: Vec<String> = extract_ids(&f::legacy_profile().pass.ids, text)
        .into_iter()
        .map(|i| i.norm)
        .collect();
    assert!(all.contains(&"BLKD88".to_string()), "{all:?}");
}
