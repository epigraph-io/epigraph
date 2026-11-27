//! Every refusal code the migrated schema raises is accounted for (backlog
//! 25619697, split from the refusal-encoding review ad2c7b0e).
//!
//! A refusal code is a literal in a plpgsql body that opens with `CODE:` (two
//! to five capitals and two digits: a RAISE message, a DETAIL, a `format()`
//! template) or a custom SQLSTATE (`ERRCODE = 'ELV03'`, `RAISE SQLSTATE`, three
//! capitals and two digits; no standard SQLSTATE class opens with three
//! letters). The scan reads `pg_proc.prosrc` on a database migrated from
//! empty, so each function is read in its CURRENT definition: a code a later
//! migration replaced away is not counted, and a migration-time `DO` block
//! (a preflight, never reachable by a caller) is not a function.
//!
//! Each code must be in exactly one of:
//! * the registry, `epigraph_db`'s reviewed lists ([`CALLER_REFUSAL_CODES`],
//!   [`SUPERSEDE_REFUSAL_CODES`]) and the custom SQLSTATEs
//!   `From<sqlx::Error> for DbError` maps to typed variants;
//! * [`RECOGNISED`]: a Rust arm outside the registry names it (each entry's
//!   recognising expression is checked to still be in its source);
//! * [`REDACTED`]: no Rust arm names it, with the reason. Such a code reaches
//!   a caller as its SQLSTATE and `DbError` variant decide: for
//!   `DbError::QueryFailed` the redacted 500 over HTTP, the coded text over
//!   MCP.
//!
//! The lists ratchet: a NEW code fails until it is registered, recognised or
//! listed here with a reason, and a listed code that no function raises any
//! more fails until its entry is removed.
//!
//! Uses the non-macro `sqlx::query*` forms so the offline `.sqlx/` cache is
//! not extended.
//!
//! [`CALLER_REFUSAL_CODES`]: epigraph_db::CALLER_REFUSAL_CODES
//! [`SUPERSEDE_REFUSAL_CODES`]: epigraph_db::SUPERSEDE_REFUSAL_CODES

use sqlx::PgPool;
use std::collections::{BTreeMap, BTreeSet};

/// A Rust arm outside the registry that recognises raised codes by name.
struct Recognised {
    codes: &'static [&'static str],
    /// Repo-relative, for the failure message.
    path: &'static str,
    source: &'static str,
    /// The recognising expressions; each must still be in `source`.
    needles: &'static [&'static str],
}

const RECOGNISED: &[Recognised] = &[
    Recognised {
        codes: &["VIS01", "VIS02", "VIS03", "VIS04", "VIS05", "VIS06"],
        path: "crates/epigraph-db/src/repos/claim_visibility.rs",
        source: include_str!("../src/repos/claim_visibility.rs"),
        needles: &[
            r#"msg.starts_with("VIS01") || msg.starts_with("VIS02") || msg.starts_with("VIS05")"#,
            r#"msg.starts_with("VIS03")"#,
            r#"msg.starts_with("VIS04") || msg.starts_with("VIS06")"#,
        ],
    },
    Recognised {
        codes: &["CSG01", "CSG02"],
        path: "crates/epigraph-db/src/repos/countersign.rs",
        source: include_str!("../src/repos/countersign.rs"),
        needles: &[r#"d.message().starts_with("CSG01") || d.message().starts_with("CSG02")"#],
    },
    Recognised {
        codes: &[
            "TGP01", "TGP02", "TGP03", "TGP04", "TGP05", "TGP06", "TGP07", "TGP08", "TGP09",
        ],
        path: "crates/epigraph-db/src/repos/person_team_group.rs",
        source: include_str!("../src/repos/person_team_group.rs"),
        needles: &[
            r#"Some("TGP01" | "TGP02")"#,
            r#"Some("TGP03" | "TGP09")"#,
            r#"Some("TGP04" | "TGP05" | "TGP06" | "TGP07")"#,
            r#"Some("TGP08")"#,
        ],
    },
    Recognised {
        // Every `BUGnn:` message: the named ones by kind, the rest Authority.
        codes: &[
            "BUG01", "BUG02", "BUG03", "BUG04", "BUG05", "BUG06", "BUG07", "BUG08",
        ],
        path: "crates/epigraph-db/src/repos/bug_report.rs",
        source: include_str!("../src/repos/bug_report.rs"),
        needles: &[
            r#"!b.starts_with(b"BUG")"#,
            r#""BUG04" | "BUG05" => RefusalKind::Input"#,
            r#""BUG03" | "BUG08" => RefusalKind::State"#,
            "_ => RefusalKind::Authority",
        ],
    },
    Recognised {
        codes: &["PVS01", "PVS02", "PVS04", "PVS05"],
        path: "crates/epigraph-db/src/repos/agent.rs",
        source: include_str!("../src/repos/agent.rs"),
        needles: &[
            r#"msg.starts_with("PVS01") || msg.starts_with("PVS05")"#,
            r#"msg.starts_with("PVS02")"#,
            r#"msg.starts_with("PVS04")"#,
        ],
    },
    Recognised {
        codes: &["RT07"],
        path: "crates/epigraph-db/src/errors.rs",
        source: include_str!("../src/errors.rs"),
        needles: &[
            r#"RETRACTED_BBA_REWRITE_PREFIX: &str = "RT07: ""#,
            "starts_with(RETRACTED_BBA_REWRITE_PREFIX)",
        ],
    },
    Recognised {
        codes: &["CX03"],
        path: "crates/epigraph-auth/src/claim_act.rs",
        source: include_str!("../../epigraph-auth/src/claim_act.rs"),
        needles: &[
            r#"CASCADE_DEFERRAL_REFUSAL_CODE: &str = "CX03""#,
            ".strip_prefix(CASCADE_DEFERRAL_REFUSAL_CODE)",
        ],
    },
    Recognised {
        codes: &["ELV01", "ELV03", "ELV04", "ELV06", "ELV08"],
        path: "crates/epigraph-api/src/routes/elevate.rs",
        source: include_str!("../../epigraph-api/src/routes/elevate.rs"),
        needles: &[
            r#"Some("ELV01") =>"#,
            r#"Some("ELV08" | "ELV03")"#,
            r#"== Some("ELV04")"#,
            r#"== Some("ELV06")"#,
        ],
    },
    Recognised {
        codes: &["ELV02"],
        path: "crates/epigraph-api/src/routes/elevation.rs",
        source: include_str!("../../epigraph-api/src/routes/elevation.rs"),
        needles: &[r#"code == "ELV02""#],
    },
    Recognised {
        codes: &["ELV07"],
        path: "crates/epigraph-api/src/routes/admin_acts.rs",
        source: include_str!("../../epigraph-api/src/routes/admin_acts.rs"),
        needles: &[r#"code == "ELV07""#],
    },
    Recognised {
        codes: &["ADM02", "AK02", "AK03"],
        path: "crates/epigraph-api/src/routes/agent_keys.rs",
        source: include_str!("../../epigraph-api/src/routes/agent_keys.rs"),
        needles: &[
            r#"contains("ADM02:")"#,
            r#"message.contains("AK02:")"#,
            r#"message.contains("AK03:")"#,
        ],
    },
    Recognised {
        codes: &["CUS04"],
        path: "crates/epigraph-api/src/routes/privatization.rs",
        source: include_str!("../../epigraph-api/src/routes/privatization.rs"),
        needles: &[r#"== Some("CUS04")"#],
    },
];

/// Raised codes no Rust arm names, by the surface that raises them. Seeded
/// with every such code at the time this test was written; a code leaves
/// this list when a reviewed mapping takes it.
const REDACTED: &[(&[&str], &str)] = &[
    (
        &["ADM01", "ADM03", "ADM04", "ADM05"],
        "the admin act definers (audit write, claim patch, workflow-row deprecate); only ADM02 is mapped",
    ),
    (
        &["ADS01", "ADS02", "ADS03"],
        "the admin scope-enforcement switch, its guard and its would-strip record",
    ),
    (&["AG01"], "the agents competence guard trigger"),
    (
        &["AID03", "AID05", "AID06", "AID07", "AID08"],
        "agent identity registration and prompt history; repos/agent_identity.rs names them \
         as SQLSTATE constants but no arm maps them (DbError::QueryFailed)",
    ),
    (
        &["AID09", "AID10"],
        "agent identity registration and legacy succession record",
    ),
    (
        &["AK01", "AK04"],
        "agent key rotation and status; only AK02 and AK03 are mapped",
    ),
    (
        &["AN01", "AN02", "AN03", "AN04"],
        "the OAuth assertion nonce consumer",
    ),
    (&["AT01"], "the OAuth access-token revoke"),
    (
        &["BPF01", "BPF02", "BPF03"],
        "the hypothesis factor promotion definer",
    ),
    (&["CD01", "CD02"], "the edge-BBA cascade delete"),
    (
        &[
            "CR01", "CR02", "CR03", "CR04", "CR05", "CR06", "CR07", "CR08", "CR09",
        ],
        "challenge resolution and its guard (CR03 is a DETAIL)",
    ),
    (
        &["CUS01", "CUS02", "CUS03", "CUS05", "CUS06"],
        "the custodial role guards (role assignments, platform roles, instance admins, \
         operator links); only CUS04 is mapped",
    ),
    (
        &["CX01", "CX02"],
        "the cascade deferral record; only CX03 is mapped",
    ),
    (
        &["ELV09", "ELV10"],
        "the custodial act, admin act consume and role assignment elevation checks",
    ),
    (&["EVP01"], "the evidence passage licence guard"),
    (
        &["FA01", "FA02", "FA03", "FA04", "FA05", "FA06", "FA07", "FA08"],
        "the foreign aggregate, belief cache, claim frame and dedup BBA-move guards \
         (FA06 is a DETAIL); repos/claim.rs authors its own FA04/FA07 pre-check \
         refusals, but no arm maps the database's",
    ),
    (&["FCT01"], "the factor triggers on edges"),
    (
        &["GRA01", "GRA02", "GRA03"],
        "the group reseal-required mark",
    ),
    (
        &["GRB01", "GRB02", "GRB03"],
        "group role bindings and role definition",
    ),
    (
        &["GRP01", "GRP02", "GRP03", "GRP04", "GRP05", "GRP06"],
        "the agent-facing team group verbs",
    ),
    (&["HEV01"], "the OAuth client human-evidence guard"),
    (&["IWE01", "IWE02"], "the ingest-written edges guard"),
    (
        &["LIC01", "LIC02", "LIC03", "LIC04"],
        "the paper licence setter",
    ),
    (&["MC01"], "the match candidates stale guard"),
    (
        &["OC01", "OC02"],
        "OAuth client agent link and reactivation",
    ),
    (&["OCC05"], "the role projection edges guard"),
    (
        &["OLR01", "OLR02", "OLR03", "OLR04", "OLR05"],
        "operator link retirement and its retire-only guard",
    ),
    (
        &["RDR01", "RDR02"],
        "the unauthenticated reader key and membership reservations",
    ),
    (&["RLE01"], "the legacy edge re-owner"),
    (
        &["ROL02", "ROL03", "ROL04"],
        "role agent guards, attach and successor restore; only ROL01 is mapped",
    ),
    (
        &["RT01", "RT02", "RT03", "RT04", "RT05", "RT06"],
        "two surfaces share the prefix: refresh-token rotate/revoke (RT01-RT03) and BBA \
         retract/unretract and its guard (RT01-RT06); only RT07 is mapped",
    ),
    (
        &["WFO01", "WFO02", "WFO03", "WFO04"],
        "the workflow outcome record, workflow lock and admin deprecate",
    ),
];

/// The registry: the reviewed message-code lists and the custom SQLSTATEs
/// `From<sqlx::Error> for DbError` maps.
fn registry() -> BTreeSet<&'static str> {
    epigraph_db::CALLER_REFUSAL_CODES
        .iter()
        .chain(epigraph_db::SUPERSEDE_REFUSAL_CODES)
        .copied()
        .chain([
            epigraph_db::PERSONAL_MEMBERSHIP_REVOKED,
            epigraph_db::PERSONAL_GROUP_NOT_OWNED,
            epigraph_db::OPERATOR_LINK_REQUIRED,
            epigraph_db::OPERATOR_SCOPE_REFUSED,
            epigraph_db::ROLE_HOLDER_REQUIRED,
        ])
        .collect()
}

fn recognised() -> BTreeSet<&'static str> {
    RECOGNISED
        .iter()
        .flat_map(|r| r.codes.iter().copied())
        .collect()
}

fn redacted() -> BTreeSet<&'static str> {
    REDACTED
        .iter()
        .flat_map(|(c, _)| c.iter().copied())
        .collect()
}

/// The text with `--` and `/* */` comments removed, string literals kept, so
/// a commented-out RAISE does not count.
fn strip_comments(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    let mut last = 0;
    while i < b.len() {
        match b[i] {
            b'\'' => {
                i += 1;
                while i < b.len() {
                    if b[i] == b'\'' {
                        if b.get(i + 1) == Some(&b'\'') {
                            i += 2;
                            continue;
                        }
                        break;
                    }
                    i += 1;
                }
                i += 1;
            }
            b'-' if b.get(i + 1) == Some(&b'-') => {
                out.push_str(&src[last..i]);
                i = src[i..].find('\n').map_or(b.len(), |n| i + n);
                last = i;
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                out.push_str(&src[last..i]);
                i = src[i + 2..].find("*/").map_or(b.len(), |n| i + 2 + n + 2);
                out.push(' ');
                last = i;
            }
            _ => i += 1,
        }
    }
    out.push_str(&src[last.min(b.len())..]);
    out
}

/// Every single-quoted literal in `src` with the byte offset of its opening
/// quote, `''` unescaped.
fn literals(src: &str) -> Vec<(usize, String)> {
    let b = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'\'' {
            i += 1;
            continue;
        }
        let start = i;
        let mut lit = Vec::new();
        i += 1;
        while i < b.len() {
            if b[i] == b'\'' {
                if b.get(i + 1) == Some(&b'\'') {
                    lit.push(b'\'');
                    i += 2;
                    continue;
                }
                break;
            }
            lit.push(b[i]);
            i += 1;
        }
        i += 1;
        out.push((start, String::from_utf8_lossy(&lit).into_owned()));
    }
    out
}

/// `CODE` when `lit` opens with `CODE:` (two to five capitals, two digits),
/// the shape `caller_refusal_codes_restatement.rs`'s `code_of` reads.
fn message_code(lit: &str) -> Option<&str> {
    let caps = lit.bytes().take_while(u8::is_ascii_uppercase).count();
    let digits = lit[caps..].bytes().take_while(u8::is_ascii_digit).count();
    ((2..=5).contains(&caps) && digits == 2 && lit[caps + 2..].starts_with(':'))
        .then(|| &lit[..caps + 2])
}

/// Whether `lit` has a custom SQLSTATE's shape: three capitals, two digits.
fn custom_sqlstate(lit: &str) -> bool {
    let b = lit.as_bytes();
    b.len() == 5
        && b[..3].iter().all(u8::is_ascii_uppercase)
        && b[3..].iter().all(u8::is_ascii_digit)
}

/// Whether the literal at `at` is the value of an `ERRCODE =` or follows
/// `SQLSTATE` (`RAISE SQLSTATE '...'`, `WHEN SQLSTATE '...'`).
fn after_sqlstate_keyword(src: &str, at: usize) -> bool {
    let before = src[..at].trim_end();
    let before = before.strip_suffix('=').map_or(before, str::trim_end);
    let upper = before.to_ascii_uppercase();
    upper.ends_with("ERRCODE") || upper.ends_with("SQLSTATE")
}

/// Every refusal code a plpgsql `body` names.
fn codes_in(body: &str) -> BTreeSet<String> {
    let src = strip_comments(body);
    let mut out = BTreeSet::new();
    for (at, lit) in literals(&src) {
        if let Some(code) = message_code(&lit) {
            out.insert(code.to_string());
        } else if custom_sqlstate(&lit) && after_sqlstate_keyword(&src, at) {
            out.insert(lit);
        }
    }
    out
}

/// Code -> the plpgsql functions whose current definition names it.
async fn raised(pool: &PgPool) -> BTreeMap<String, BTreeSet<String>> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT n.nspname || '.' || p.proname, p.prosrc \
           FROM pg_proc p \
           JOIN pg_namespace n ON n.oid = p.pronamespace \
           JOIN pg_language l ON l.oid = p.prolang \
          WHERE l.lanname = 'plpgsql' \
            AND n.nspname NOT IN ('pg_catalog', 'information_schema')",
    )
    .fetch_all(pool)
    .await
    .expect("read pg_proc");
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (name, body) in rows {
        for code in codes_in(&body) {
            out.entry(code).or_default().insert(name.clone());
        }
    }
    out
}

/// `CODE(function, ...)` for every raised code in no list.
fn unaccounted(raised: &BTreeMap<String, BTreeSet<String>>) -> Vec<String> {
    let known: BTreeSet<&str> = registry()
        .into_iter()
        .chain(recognised())
        .chain(redacted())
        .collect();
    raised
        .iter()
        .filter(|(code, _)| !known.contains(code.as_str()))
        .map(|(code, fns)| {
            let fns: Vec<&str> = fns.iter().map(String::as_str).collect();
            format!("{code}({})", fns.join(","))
        })
        .collect()
}

#[test]
fn the_scanner_reads_codes_and_skips_comments() {
    let body = "BEGIN\n\
                -- RAISE EXCEPTION 'ZZA01: commented out';\n\
                /* RAISE EXCEPTION 'ZZB01: block comment'; */\n\
                x := 'not a code: ZZC01';\n\
                y := '--ZZD01: in a literal, not a comment';\n\
                RAISE EXCEPTION 'AB01: it''s refused; really' USING ERRCODE = 'ZZE02';\n\
                RAISE EXCEPTION USING MESSAGE = format('CDEFG12: %s', v), DETAIL = 'HIJ03: why';\n\
                RAISE SQLSTATE 'KLM04';\n\
                z := 'NOP05';\n\
                RAISE EXCEPTION 'ABCDEF01: six capitals' USING ERRCODE = '22023';\n\
                END";
    let got: Vec<String> = codes_in(body).into_iter().collect();
    assert_eq!(got, ["AB01", "CDEFG12", "HIJ03", "KLM04", "ZZE02"]);
    assert_eq!(message_code("SR09: x"), Some("SR09"));
    assert_eq!(message_code("SR9: x"), None);
    assert_eq!(message_code("SR091: x"), None);
    assert_eq!(message_code("S01: x"), None);
    assert!(custom_sqlstate("ELV03"));
    assert!(!custom_sqlstate("22023"));
    assert!(!custom_sqlstate("P0001"));
    assert!(!custom_sqlstate("HV00B"));
}

#[test]
fn the_lists_are_disjoint_and_each_recognising_arm_is_still_there() {
    let (reg, rec, red) = (registry(), recognised(), redacted());
    let both: Vec<&str> = rec.intersection(&reg).copied().collect();
    assert!(both.is_empty(), "registered AND recognised: {both:?}");
    let mapped: BTreeSet<&str> = reg.union(&rec).copied().collect();
    let both: Vec<&str> = red.intersection(&mapped).copied().collect();
    assert!(
        both.is_empty(),
        "a code in REDACTED is mapped (registered or recognised); remove it from REDACTED: {both:?}"
    );
    let listed: usize = REDACTED.iter().map(|(c, _)| c.len()).sum::<usize>()
        + RECOGNISED.iter().map(|r| r.codes.len()).sum::<usize>();
    assert_eq!(listed, red.len() + rec.len(), "a code is listed twice");
    for r in RECOGNISED {
        for needle in r.needles {
            assert!(
                r.source.contains(needle),
                "{} no longer holds `{needle}`, which RECOGNISED cites for {:?}: \
                 move the codes it mapped to REDACTED or cite the new arm",
                r.path,
                r.codes
            );
        }
    }
    for (codes, reason) in REDACTED {
        assert!(!reason.trim().is_empty(), "{codes:?} has no reason");
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn every_raised_refusal_code_is_registered_recognised_or_listed(pool: PgPool) {
    let raised = raised(&pool).await;
    assert!(
        raised.len() > 100,
        "PREMISE: the scan finds the schema's coded refusals ({} found)",
        raised.len()
    );
    let missing = unaccounted(&raised);
    assert!(
        missing.is_empty(),
        "UNACCOUNTED_REFUSAL_CODES: {}. Each is raised by the function(s) named but \
         is in no list: add it to a reviewed registry in src/refusal_codes.rs (or map \
         its SQLSTATE in errors.rs), cite the Rust arm that recognises it in RECOGNISED, \
         or list it in REDACTED with a reason",
        missing.join(" ")
    );
    let stale: Vec<&str> = recognised()
        .into_iter()
        .chain(redacted())
        .filter(|c| !raised.contains_key(*c))
        .collect();
    assert!(
        stale.is_empty(),
        "STALE_REFUSAL_CODES: {stale:?} are listed here but no function raises them \
         any more; remove them"
    );
}

/// The ratchet bites: a function a later migration adds with an unlisted
/// message code or custom SQLSTATE is reported, and a code its replacement
/// drops is not (the scan reads current definitions only).
#[sqlx::test(migrations = "../../migrations")]
async fn a_new_unlisted_code_is_reported(pool: PgPool) {
    for sql in [
        "CREATE FUNCTION public.zz_fixture_message() RETURNS void LANGUAGE plpgsql AS $$ \
         BEGIN RAISE EXCEPTION 'ZZZ01: a new refusal' USING ERRCODE = '42501'; END $$",
        "CREATE FUNCTION public.zz_fixture_sqlstate() RETURNS void LANGUAGE plpgsql AS $$ \
         BEGIN RAISE EXCEPTION 'a new refusal' USING ERRCODE = 'ZZZ02'; END $$",
        "CREATE FUNCTION public.zz_fixture_replaced() RETURNS void LANGUAGE plpgsql AS $$ \
         BEGIN RAISE EXCEPTION 'ZZZ03: replaced away'; END $$",
        "CREATE OR REPLACE FUNCTION public.zz_fixture_replaced() RETURNS void LANGUAGE plpgsql AS $$ \
         BEGIN -- RAISE EXCEPTION 'ZZZ04: commented out';\n RETURN; END $$",
    ] {
        sqlx::query(sql).execute(&pool).await.expect(sql);
    }
    let missing = unaccounted(&raised(&pool).await);
    assert_eq!(
        missing,
        [
            "ZZZ01(public.zz_fixture_message)",
            "ZZZ02(public.zz_fixture_sqlstate)"
        ],
        "only the fixture's two live, unlisted codes are reported"
    );
}
