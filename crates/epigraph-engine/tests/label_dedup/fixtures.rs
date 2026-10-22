//! Neutral fixtures for the label-dedup engine.
//!
//! Every entity, place, id and label below is synthetic. The contents are
//! shaped like real family records (a pipe layout, two prose layouts, a keyed
//! layout with a header) so the parser and the tokenizer meet the same
//! structures they meet in production, without any production text.

#![allow(dead_code)]

use chrono::{DateTime, NaiveDate, Utc};
use epigraph_engine::label_dedup::{
    plan, DedupClaim, LabelDedupProfile, ParsedRecord, PassProfile, Plan, PlanInputs, PlanRequest,
    ReadPurpose, Section, Snapshot, WriteUnit,
};
use uuid::Uuid;

// ── Ids ─────────────────────────────────────────────────────────────────────

/// A claim id whose first 8 hex digits are `tag`, so a `revision-of-<8 hex>`
/// or `distinct-from:<8 hex>` label names exactly one fixture, and id order is
/// tag order.
pub fn id(tag: u32) -> Uuid {
    Uuid::from_u128(u128::from(tag) << 96 | u128::from(tag))
}

/// The 8-hex prefix of [`id`].
pub fn prefix(tag: u32) -> String {
    format!("{tag:08x}")
}

pub fn ts(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .expect("fixture timestamp")
        .with_timezone(&Utc)
}

pub fn date(d: &str) -> NaiveDate {
    NaiveDate::parse_from_str(d, "%Y-%m-%d").expect("fixture date")
}

pub fn claim(tag: u32, content: &str, labels: &[&str], created: &str) -> DedupClaim {
    DedupClaim {
        id: id(tag),
        content: content.to_string(),
        labels: labels.iter().map(|s| (*s).to_string()).collect(),
        created_at: Some(ts(created)),
        duplicates: Vec::new(),
    }
}

// ── Profiles ────────────────────────────────────────────────────────────────

pub const RUN_TAG: &str = "notice-dedup-2026-10-05";

/// The full test profile: every feature on.
pub fn profile_value() -> serde_json::Value {
    serde_json::json!({
        "schema": "label-dedup-profile/v2",
        "family_label": "notice",
        "family_kind": "index",
        "closed_label": "resolved",
        "retired_labels": ["notice-dropped", "notice-duplicate", "listed-final"],
        "content_retired_flags": ["DROPPED"],
        "non_member": {
            "labels_any": ["notice-run-status", "lead"],
            "body_prefixes": ["notice monitor"],
            "body_contains": ["sweep finished"],
            "completion_report": {
                "prefixes": ["collector ", "review ", "rerun "],
                "requires_any": ["complete"]
            }
        },
        "hygiene_write": {"add": ["{run_tag}"], "remove": ["{family}"]},
        "flag": {"canonical": {"listed-opp": "listed-opportunity", "listed-only": "listed-final"}},
        "fields": {
            "title": {
                "header_tokens": ["tender", "tnd", "active"],
                "prose_header_tokens": ["open", "active"]
            },
            "entity": {"pipe_position": 1, "keys": ["agency:"]},
            "deadline": {
                "keys": ["due:", "due "],
                "prose_markers": ["due:", "due ", "open through ", "closes ", "deadline "]
            },
            "value": {
                "keys": ["est.", "value:"],
                "prose_markers": ["est. ", "est ", "value:", "estimated value"]
            },
            "class": {"from_flag": true, "from_label_prefix": "class:"},
            "ignored_keys": ["sector:", "trade:", "lane:", "notes:", "contact:", "source:"]
        },
        "unknown": {
            "tokens": ["unknown", "tbd", "n a", "none", "not stated", "unconfirmed"],
            "count_fields": ["entity", "deadline", "value", "class"]
        },
        "ids": {
            "scan_cut_at_last": "| notes:",
            "reject": ["iso_date", "us_date", "bare_year", "year_range", "fiscal_year",
                       "clock_time", "money", "percent"],
            "carry_label_prefix": "also-id:"
        },
        "entity_match": {
            "aliases": [
                ["ac", "acme city"],
                ["dpo", "department public operations"],
                ["pua", "public utility authority"],
                ["sd", "school district"],
                ["axu", "acme state university"]
            ],
            "stopwords": ["of", "the", "and", "for", "a", "at"]
        },
        "title_match": {
            "stopwords": ["tender", "tnd", "bid", "call", "for", "the", "and", "of", "at", "to", "work", "works", "support", "no"]
        },
        "revision_label_prefix": "revision-of-",
        "distinct_label_prefix": "distinct-from:",
        "precedence": {
            "rank_label_groups": [["src-direct-a", "src-direct-b", "src-direct-c"], ["src-feed"]]
        },
        "merge": {
            "survivor_add": ["notice-survivor", "{run_tag}"],
            "carry_ids": true
        },
        "closeout": {"date_field": "deadline", "add": ["resolved", "closed-past-due", "{run_tag}"]},
        "lifecycle": {
            "signal_family_label": "lead",
            "signal_family_kind": "index",
            "signal_exclude_labels": ["resolved"],
            "target_exclude_labels": ["notice-dropped", "notice-duplicate", "listed-final"],
            "umbrella": {
                "strip_prefix": "lead ",
                "body_prefixes": ["fund signal", "program office"],
                "tokens": ["batch", "umbrella", "legislation", "budget"],
                "phrases": ["bond program", "bond measure"]
            },
            "age_key": [{"after_keywords": ["received", "recv"]},
                        {"after_keywords": ["approved"]},
                        "created_at"],
            "max_age_days": 120,
            "graduate_add": ["resolved", "materialized", "graduated-to:{target}", "{run_tag}"],
            "age_out_add": ["resolved", "closed-past-due", "aged-out", "{run_tag}"]
        }
    })
}

/// The full profile with every feature that has no counterpart in a plain
/// union-find planner turned off: no scan cut, no carried ids or values, no
/// distinct-from rulings. The parity baseline.
pub fn legacy_profile_value() -> serde_json::Value {
    let mut v = profile_value();
    let o = v.as_object_mut().expect("object");
    o.remove("distinct_label_prefix");
    let ids = o["ids"].as_object_mut().expect("ids");
    ids.remove("scan_cut_at_last");
    ids.remove("carry_label_prefix");
    let merge = o["merge"].as_object_mut().expect("merge");
    merge.insert("carry_ids".into(), false.into());
    v
}

pub fn bytes(v: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(v).expect("serialize profile")
}

pub fn load(v: &serde_json::Value) -> LabelDedupProfile {
    LabelDedupProfile::from_json_bytes(&bytes(v)).expect("fixture profile is valid")
}

pub fn profile() -> LabelDedupProfile {
    load(&profile_value())
}

pub fn legacy_profile() -> LabelDedupProfile {
    load(&legacy_profile_value())
}

pub fn pass() -> PassProfile {
    profile().pass
}

pub fn parsed(tag: u32, content: &str, labels: &[&str], created: &str) -> ParsedRecord {
    epigraph_engine::label_dedup::parse_record(&pass(), &claim(tag, content, labels, created))
}

// ── Planning over an in-memory graph ────────────────────────────────────────

/// Perform the profile's reads over `graph` (every claim of every family), as
/// the tool performs them over the database, and plan.
pub fn plan_graph(
    profile: &LabelDedupProfile,
    graph: &[DedupClaim],
    sections: &[Section],
    as_of: Option<NaiveDate>,
) -> Plan {
    try_plan_graph(profile, graph, sections, as_of, 5000).expect("plan")
}

pub fn try_plan_graph(
    profile: &LabelDedupProfile,
    graph: &[DedupClaim],
    sections: &[Section],
    as_of: Option<NaiveDate>,
    cap: usize,
) -> Result<Plan, epigraph_engine::label_dedup::LabelDedupError> {
    let mut inputs = PlanInputs::default();
    for read in profile.reads(sections)? {
        let rows: Vec<DedupClaim> = graph
            .iter()
            .filter(|c| read.matches(&c.labels))
            .cloned()
            .collect();
        let snap = Snapshot::from_capped(rows, cap);
        match read.purpose {
            ReadPurpose::Members => inputs.members = snap,
            ReadPurpose::LifecycleSignals => inputs.lifecycle_signals = Some(snap),
            ReadPurpose::LifecycleTargets => inputs.lifecycle_targets = Some(snap),
            ReadPurpose::SignalMembers => inputs.signal_members = Some(snap),
            ReadPurpose::ClosedSignals => {}
        }
    }
    let req = PlanRequest {
        profile,
        profile_hash: "0000000000000000000000000000000000000000000000000000000000000000",
        run_tag: RUN_TAG,
        as_of,
        sections,
    };
    plan(&req, &inputs)
}

/// Like [`plan_graph`], but every read keeps `graph`'s row order and each
/// claim's label order: nothing is sorted on the way in, so the engine alone
/// is responsible for being order-independent.
pub fn plan_graph_as_given(
    profile: &LabelDedupProfile,
    graph: &[DedupClaim],
    sections: &[Section],
    as_of: Option<NaiveDate>,
) -> Plan {
    let mut inputs = PlanInputs::default();
    for read in profile.reads(sections).expect("reads") {
        let snap = Snapshot {
            claims: graph
                .iter()
                .filter(|c| read.matches(&c.labels))
                .cloned()
                .collect(),
            truncated: false,
        };
        match read.purpose {
            ReadPurpose::Members => inputs.members = snap,
            ReadPurpose::LifecycleSignals => inputs.lifecycle_signals = Some(snap),
            ReadPurpose::LifecycleTargets => inputs.lifecycle_targets = Some(snap),
            ReadPurpose::SignalMembers => inputs.signal_members = Some(snap),
            ReadPurpose::ClosedSignals => {}
        }
    }
    let req = PlanRequest {
        profile,
        profile_hash: "0000000000000000000000000000000000000000000000000000000000000000",
        run_tag: RUN_TAG,
        as_of,
        sections,
    };
    plan(&req, &inputs).expect("plan")
}

/// Apply write units to an in-memory graph as the apply tool does: each mark
/// first (the duplicate becomes non-current, so it leaves every current-only
/// read, and it is read through its canonical as `index_view` returns it:
/// under the canonical's `duplicates`, with the duplicates it had itself),
/// then the label writes (set union for `add`, set difference for `remove`,
/// content untouched).
pub fn apply_units(graph: &[DedupClaim], units: &[WriteUnit]) -> Vec<DedupClaim> {
    let mut out = graph.to_vec();
    for unit in units {
        for m in &unit.marks {
            let pos = out
                .iter()
                .position(|c| c.id == m.dup)
                .unwrap_or_else(|| panic!("a mark names a claim outside the graph: {m:?}"));
            let mut dup = out.remove(pos);
            let mut inherited = std::mem::take(&mut dup.duplicates);
            let canonical = out
                .iter_mut()
                .find(|c| c.id == m.canonical)
                .unwrap_or_else(|| panic!("a mark's canonical is outside the graph: {m:?}"));
            canonical.duplicates.push(dup);
            canonical.duplicates.append(&mut inherited);
        }
    }
    for unit in units {
        for w in &unit.writes {
            let c = out
                .iter_mut()
                .find(|c| c.id == w.claim_id)
                .unwrap_or_else(|| panic!("write targets a claim outside the graph: {w:?}"));
            c.labels.retain(|l| !w.remove.contains(l));
            for a in &w.add {
                if !c.labels.contains(a) {
                    c.labels.push(a.clone());
                }
            }
        }
    }
    out
}

pub fn all_sections() -> Vec<Section> {
    vec![
        Section::Hygiene,
        Section::Dedup,
        Section::Closeout,
        Section::Lifecycle,
    ]
}

pub fn dedup_sections() -> Vec<Section> {
    vec![Section::Hygiene, Section::Dedup]
}

/// `(survivor, sorted losers)` per cluster, sorted.
pub fn cluster_shape(p: &Plan) -> Vec<(Uuid, Vec<Uuid>)> {
    let mut v: Vec<(Uuid, Vec<Uuid>)> = p
        .clusters
        .iter()
        .map(|c| {
            let mut l: Vec<Uuid> = c.members.iter().map(|m| m.id).collect();
            l.sort();
            (c.survivor, l)
        })
        .collect();
    v.sort();
    v
}

// ── Content ─────────────────────────────────────────────────────────────────

/// Pipe layout, found by a feed source.
pub const WING_FEED: &str = "[OPEN] Kestrel Wing Refit TND 47310K | Acme Campus Lodging Office | sector:univ | trade:arch | due 2026-08-12 | est. unknown | Design work to refit the Kestrel wing at the Acme campus; open call";
/// The same record, found again by a direct source in the same run.
pub const WING_DIRECT: &str = WING_FEED;

/// Prose layout, later run: the deadline was extended.
pub const WEIR_LATE: &str = "Tender: GWX KX-4417 Granite Weir Channel Upgrade — Acme County PUA, due 2026-07-15, est. $48M. Moved out from the first 2026-06-17 date; responses due 2:00 PM through the portal, ref no 5174.";
/// Prose layout with a `&` type prefix and the id in parentheses.
pub const WEIR_EARLY: &str = "Bid&Q: GWX Granite Weir Channel Upgrade (KX-4417) — Acme County Public Utility Authority, due 2026-06-17, est. $48M build cost. Channel design work.";

pub const AGREEMENT_Q23_NEW: &str = "Tender: STANDING SUPPORT CONTRACT Q23 FIELD SURVEY WORK — AC Department of Public Operations (ID 0000081574), due 2026-06-30, est. $2,400,000, on-call survey crews for AC DPO sites";
pub const AGREEMENT_Q23_OLD: &str = "Bid: AC DPO Standing Field Survey Contract Q23 (Solicitation 0000081574) — Acme City Public Operations, open through 2026-06-30, est. $2.4M. On-call survey crews.";
pub const AGREEMENT_Q22_NEW: &str = "Tender: STANDING SUPPORT CONTRACT Q22 FIELD SAMPLING WORK — AC Department of Public Operations (ID 0000081573), due 2026-06-30, est. $2,400,000, on-call sampling crews for AC DPO sites";

pub const PANEL_OLD: &str = "Tender: TND Lighting Control Panel Refresh ACSD-FAC-LCP-FY29_317 — Acme City School District, due 2026-07-21, est. TBD, statement of interest for a panel refresh; covers an outside reviewer for commissioning";
pub const PANEL_NEW: &str = "[LISTED-OPP] Lighting Control Panel Refresh TND ACSD-FAC-LCP-FY29_317 | Acme City School District | sector:school | trade:trade-adjacent | due 2026-07-21 | est. unknown | Call to form a bench of outside lighting control reviewers for district sites";

pub const HOIST_LISTED: &str = "[LISTED-OPP] AXU Hoist Inspection Advice BOA | Acme State University | sector:univ | trade:trade-adjacent | due 2026-07-15 | est. $350K cap per call-off | Call-off agreement for hoist inspection advice: surveys, specs and site checks across campus buildings";
pub const HOIST_REVIEW: &str = "[REVIEW] AXU Hoist Inspection Advice BOA | Acme State University | sector:univ | trade:trade-adjacent | due 2026-07-15 | est. $350K cap per call-off | Call-off agreement for hoist inspection advice: surveys, specs and site checks across campus buildings";

pub const MURAL_MSB: &str = "[LISTED-OPP] TND Standby Mural Conservation Support 2026 MSB | AC Department of Public Operations | sector:city | trade:trade-adjacent | due unknown | est. unknown | Standby mural conservation for AC DPO sites, small-firm track";
pub const MURAL_STD: &str = "[LISTED-OPP] TND Standby Mural Conservation Support 2026 | AC Department of Public Operations | sector:city | trade:trade-adjacent | due unknown | est. unknown | Standby mural conservation for AC DPO sites, open track";

pub const KIOSK_UNIT: &str = "Tender: G2 KIOSK FITOUT UNIT 1 SFS — Acme Field Board (Ref AFEV-0000071206), due 2026-09-17, est. TBD, fit-out design for the gate 2 kiosk unit at Acme Field under the small firm scheme";
pub const KIOSK_CAFE: &str = "Tender: G2 KIOSK FITOUT CAFE SFS — Acme Field Board (Ref AFEV-0000071219), due 2026-11-23, est. TBD, fit-out design for the gate 2 kiosk cafe at Acme Field under the small firm scheme";

pub const COUNTY_DEPOT: &str = "Bid: Acme County Depot Block No. 9 — Acme County Public Operations Department, active call. Design work for a new depot block.";
pub const COUNTY_STANDBY: &str = "Bid: Acme County Standby Drafting and Survey Support — Acme County Public Operations Department, active call. Standby drafting help for county sites.";

/// `<HEADER> — <entity>: <title>; …` prose.
pub const PATHS_HEADER: &str = "Tender OPEN — ACRB: Path Mapping Helpdesk Advisor Tender FY28-35-TND, Acme area; due 2026-07-24; lane: city; notes: helpdesk for path mapping";
/// Keyed pipe layout with a leading header field and a short title prefix.
pub const BENCH_KEYED: &str = "ACTIVE TND — SCHOOL | ACSD: TND Bench of Roofing Firms for Gutter & Drain Repair | Agency: Acme City School District | Due: TBD | Lane: school | Notes: Forms a bench of roofing firms for gutter repair at district sites. | Value: unknown";

pub const DROPPED_SEATING: &str = "[DROPPED] CAP 52D3812 Acme Civic Hall Bench Seating Swap — out of range: seating supply only, no design work";
pub const RUN_STATUS: &str =
    "notice-monitor sweep finished 2026-08-02 (cycle 31, feed B). 4 new notices logged.";
pub const REVIEW_STATUS: &str =
    "Review src-direct-a for notice-2026-08-02 complete. Flagged: 1 item. Kept: 6 items.";

pub const STEAM_A: &str = "[OPEN] Quad Steam Line Swap | Acme Polytechnic | ref TND 90001A | sector:univ | trade:eng | due 2026-09-01 | est. unknown | scope";
pub const STEAM_B: &str = "[OPEN] Quad Steam Line Swap | Acme Polytechnic | ref TND 90002B | sector:univ | trade:eng | due 2026-09-01 | est. unknown | scope";

pub const WIDGET_SPARSE: &str = "[OPEN] Footpath Lighting Study | City of Acmeton | sector:city | trade:planning | due unknown | est. unknown | scope";
pub const WIDGET_FULL: &str = "[OPEN] Footpath Lighting Study | City of Acmeton | sector:city | trade:planning | due 2026-09-01 | est. $180,000 | scope";

/// The deadline text puts a multi-byte dash across byte 10.
pub const PROSE_DUE_MULTIBYTE: &str = "[OPEN] Boathouse Reuse Options Review | City of Acmeton | sector:city | trade:planning | due late Oct — see notice | est. unknown | Options review for the old boathouse";

pub const FENDER_DIRECT_NO_DUE: &str = "[OPEN] Dock 4 Fender Rebuild TND 0000029912 | Acme Port Authority | sector:city | trade:civil | due unknown | est. unknown | Fender rebuild design for dock 4";
pub const FENDER_DIRECT_HELD: &str = "[OPEN] Dock 4 Fender Rebuild TND 0000029912 | Acme Port Authority | sector:city | trade:civil | due 2026-07-01 | est. unknown | Fender rebuild design for dock 4";
pub const FENDER_FEED: &str = "Bid: Acme Port Authority Dock 4 Fender Rebuild (Solicitation 0000029912) — Acme Port Authority, due 2026-06-01, est. $1,600,000. Fender rebuild design.";

// Signals (the `lead` family).
pub const LEAD_CHILLER: &str = "LEAD: Acme Med Center Cold Room 2nd Level Chiller Swap PRJ-007731 | Acme Medical Center | sector:univ | due unknown | est. $2.9M | early-design signal";
pub const LEAD_PERMIT_OLD: &str = "Lead: permit project Yard Fence and Gate Rework at Acme Primary, Acme SD | sector:school | permit App 02-310082 | Est $2,700,000 | permit state:PENDING (recv 3/26/2026) | notes: fence and gate rework";
pub const LEAD_PERMIT_YOUNG: &str = "Lead: permit project Window Reglaze at Ridge Academy, Acme SD | sector:school | permit App 02-310245 | Est $1,100,000 | permit state:PENDING (recv 6/10/2026) | notes: window reglaze";
pub const LEAD_FUND: &str = "Lead: FUND signal — Board note: allocation cycle 12 shut | sector:school | source: example.org";
pub const NOTICE_CHILLER: &str = "[OPEN] Cold Room Chiller Swap PRJ-007731 | AMC | sector:univ | trade:eng | due 2026-11-01 | est. unknown | chiller swap design work";
/// Shares no id with any lead; it only repeats a lead's received date.
pub const NOTICE_SAME_US_DATE: &str = "[OPEN] Acmeton Depot Gutter Swap TND DEP-2026-07 | City of Acmeton | sector:city | trade:arch | due 2026-11-15 | est. unknown | update posted 3/26/2026; gutter design";

// ── The corpus ──────────────────────────────────────────────────────────────

/// Tags of the corpus claims. Within each known pair, the survivor is listed
/// first.
pub mod t {
    pub const WING_DIRECT: u32 = 0x1100_0001;
    pub const WING_FEED: u32 = 0x1100_0002;
    pub const WEIR_LATE: u32 = 0x1200_0001;
    pub const WEIR_EARLY: u32 = 0x1200_0002;
    pub const Q23_NEW: u32 = 0x1300_0001;
    pub const Q23_OLD: u32 = 0x1300_0002;
    pub const Q22_NEW: u32 = 0x1300_0003;
    pub const PANEL_OLD: u32 = 0x1400_0001;
    pub const PANEL_NEW: u32 = 0x1400_0002;
    pub const HOIST_LISTED: u32 = 0x1500_0002;
    pub const HOIST_REVIEW: u32 = 0x1500_0001;
    pub const MURAL_MSB: u32 = 0x1600_0002;
    pub const MURAL_STD: u32 = 0x1600_0001;
    pub const KIOSK_UNIT: u32 = 0x1700_0001;
    pub const KIOSK_CAFE: u32 = 0x1700_0002;
    pub const COUNTY_DEPOT: u32 = 0x1800_0001;
    pub const COUNTY_STANDBY: u32 = 0x1800_0002;
    pub const PATHS: u32 = 0x1900_0001;
    pub const BENCH: u32 = 0x1a00_0001;
    pub const DROPPED: u32 = 0x1b00_0002;
    pub const STATUS: u32 = 0x1b00_0001;
}

/// 21 family claims: five true duplicate pairs, one review pair, two hygiene
/// claims, and the close calls the matcher must keep apart.
pub fn corpus() -> Vec<DedupClaim> {
    vec![
        claim(
            t::WING_FEED,
            WING_FEED,
            &["notice", "src-feed", "class:open"],
            "2026-06-28T00:00:00Z",
        ),
        claim(
            t::WING_DIRECT,
            WING_DIRECT,
            &["notice", "src-direct-c", "class:open"],
            "2026-06-29T00:00:00Z",
        ),
        claim(
            t::WEIR_EARLY,
            WEIR_EARLY,
            &["notice"],
            "2026-04-27T00:00:00Z",
        ),
        claim(
            t::WEIR_LATE,
            WEIR_LATE,
            &["notice", "class:review"],
            "2026-06-20T00:00:00Z",
        ),
        claim(
            t::Q23_NEW,
            AGREEMENT_Q23_NEW,
            &["notice", "src-direct-a", "class:listed-opportunity"],
            "2026-07-19T00:00:00Z",
        ),
        claim(
            t::Q23_OLD,
            AGREEMENT_Q23_OLD,
            &["notice"],
            "2026-04-27T00:00:00Z",
        ),
        claim(
            t::Q22_NEW,
            AGREEMENT_Q22_NEW,
            &["notice", "src-direct-a"],
            "2026-06-14T00:00:00Z",
        ),
        claim(
            t::PANEL_OLD,
            PANEL_OLD,
            &["notice", "src-direct-b"],
            "2026-06-14T00:00:00Z",
        ),
        claim(
            t::PANEL_NEW,
            PANEL_NEW,
            &[
                "notice",
                "src-direct-b",
                &format!("revision-of-{}", prefix(t::PANEL_OLD)),
            ],
            "2026-07-05T00:00:00Z",
        ),
        claim(
            t::HOIST_LISTED,
            HOIST_LISTED,
            &["notice", "src-direct-c", "class:listed-opportunity"],
            "2026-06-28T00:00:00Z",
        ),
        claim(
            t::HOIST_REVIEW,
            HOIST_REVIEW,
            &["notice", "src-direct-c", "class:review"],
            "2026-06-28T00:00:00Z",
        ),
        claim(
            t::MURAL_MSB,
            MURAL_MSB,
            &["notice", "src-direct-a"],
            "2026-06-22T00:00:00Z",
        ),
        claim(
            t::MURAL_STD,
            MURAL_STD,
            &["notice", "src-direct-a"],
            "2026-06-22T00:00:00Z",
        ),
        claim(
            t::KIOSK_UNIT,
            KIOSK_UNIT,
            &["notice", "src-direct-a"],
            "2026-06-14T00:00:00Z",
        ),
        claim(
            t::KIOSK_CAFE,
            KIOSK_CAFE,
            &["notice", "src-direct-a"],
            "2026-06-14T00:00:00Z",
        ),
        claim(
            t::COUNTY_DEPOT,
            COUNTY_DEPOT,
            &["notice"],
            "2026-04-27T00:00:00Z",
        ),
        claim(
            t::COUNTY_STANDBY,
            COUNTY_STANDBY,
            &["notice"],
            "2026-04-27T00:00:00Z",
        ),
        claim(t::PATHS, PATHS_HEADER, &["notice"], "2026-05-19T00:00:00Z"),
        claim(t::BENCH, BENCH_KEYED, &["notice"], "2026-05-19T00:00:00Z"),
        claim(
            t::DROPPED,
            DROPPED_SEATING,
            &["notice", "notice-dropped", "src-feed"],
            "2026-06-28T00:00:00Z",
        ),
        claim(
            t::STATUS,
            RUN_STATUS,
            &["notice", "src-direct-b"],
            "2026-06-21T00:00:00Z",
        ),
    ]
}
