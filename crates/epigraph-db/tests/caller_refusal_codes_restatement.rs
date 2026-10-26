//! Migration 176 (backlog e2c22c7c, ruling R-25) restates twelve functions to
//! give their caller-reachable refusals a code. This pins that it changed
//! NOTHING ELSE: a database migrated to 175 and the same database after 176
//! hold the same owner, ACL, SECURITY mode, `proconfig` (search_path) and
//! volatility for each function, and the same body once every
//! `RAISE EXCEPTION` statement is masked out. Each RAISE that does differ is
//! the old statement with a refusal code prefixed to its message and nothing
//! else changed (AGK01, which moves the role to DETAIL, is the one declared
//! exception), keeps its SQLSTATE, and the codes introduced are exactly
//! `epigraph_db::CALLER_REFUSAL_CODES`.
//!
//! Uses the non-macro `sqlx::query` forms so the offline `.sqlx/` cache is not
//! extended for one test.

use sqlx::migrate::Migrator;
use sqlx::PgPool;
use std::borrow::Cow;
use std::collections::BTreeMap;

static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");

const MIGRATION_176: &str = include_str!("../../../migrations/176_caller_refusal_codes.sql");

/// The functions 176 restates, by identity signature.
const RESTATED: &[&str] = &[
    "epigraph_admin_act_args(p_kind text, p_args jsonb)",
    "epigraph_propose_admin_act(p_kind text, p_args jsonb, p_reason text, p_jti text)",
    "epigraph_owner_immutable_guard()",
    "epigraph_writer_owner_guard()",
    "epigraph_group_memberships_identity_immutable()",
    "epigraph_group_memberships_no_retired_writer()",
    "epigraph_groups_identity_immutable()",
    "epigraph_groups_personal_identity_names_creator()",
    "epigraph_team_group_roster_verbs_only()",
    "epigraph_team_group_row_verbs_only()",
    "epigraph_no_public_sealed()",
    "epigraph_agents_refuse_registered_system_key()",
];

fn up_to(max: i64) -> Migrator {
    Migrator {
        migrations: Cow::Owned(
            MIGRATOR
                .migrations
                .iter()
                .filter(|m| m.version <= max)
                .cloned()
                .collect(),
        ),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    }
}

/// Run `migrator` on one connection and reset it: 001's pg_dump header leaves
/// session-level SETs behind.
async fn migrate(pool: &PgPool, migrator: &Migrator) {
    let mut conn = pool.acquire().await.expect("acquire");
    migrator.run(&mut *conn).await.expect("migrate");
    sqlx::query("RESET ALL")
        .execute(&mut *conn)
        .await
        .expect("RESET ALL");
}

#[derive(Debug, PartialEq, Eq)]
struct Fact {
    /// owner, ACL, SECURITY DEFINER, proconfig, volatility.
    attributes: String,
    body: String,
}

async fn facts(pool: &PgPool) -> BTreeMap<String, Fact> {
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')', \
                format('owner=%s acl=%s definer=%s config=%s volatile=%s', \
                       pg_get_userbyid(p.proowner), coalesce(p.proacl::text, '-'), \
                       p.prosecdef, coalesce(p.proconfig::text, '-'), p.provolatile), \
                p.prosrc \
           FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace",
    )
    .fetch_all(pool)
    .await
    .expect("read pg_proc");
    rows.into_iter()
        .filter(|(sig, _, _)| RESTATED.contains(&sig.as_str()))
        .map(|(sig, attributes, body)| (sig, Fact { attributes, body }))
        .collect()
}

/// Byte spans of every `RAISE EXCEPTION ... ;` statement in a plpgsql body,
/// skipping string literals and comments, so a `;` inside a message does not
/// end the statement.
fn raise_spans(src: &str) -> Vec<(usize, usize)> {
    let b = src.as_bytes();
    let mut spans = Vec::new();
    let mut i = 0;
    let skip_string = |mut j: usize| -> usize {
        j += 1;
        while j < b.len() {
            if b[j] == b'\'' {
                if j + 1 < b.len() && b[j + 1] == b'\'' {
                    j += 2;
                    continue;
                }
                return j + 1;
            }
            j += 1;
        }
        j
    };
    while i < b.len() {
        match b[i] {
            b'\'' => i = skip_string(i),
            b'-' if b.get(i + 1) == Some(&b'-') => {
                i = src[i..].find('\n').map_or(b.len(), |n| i + n + 1);
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                i = src[i + 2..].find("*/").map_or(b.len(), |n| i + 2 + n + 2);
            }
            _ => {
                // Bytes only: `i` may sit inside a multi-byte character.
                let starts_word = i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_');
                let after = i + 5;
                let mut k = after;
                while k < b.len() && b[k].is_ascii_whitespace() {
                    k += 1;
                }
                let is_raise = starts_word
                    && b.len() >= after
                    && b[i..after].eq_ignore_ascii_case(b"raise")
                    && k > after
                    && b.len() >= k + 9
                    && b[k..k + 9].eq_ignore_ascii_case(b"exception");
                if !is_raise {
                    i += 1;
                    continue;
                }
                let start = i;
                let mut j = i;
                while j < b.len() && b[j] != b';' {
                    j = if b[j] == b'\'' { skip_string(j) } else { j + 1 };
                }
                spans.push((start, (j + 1).min(b.len())));
                i = j + 1;
            }
        }
    }
    spans
}

fn raises(src: &str) -> Vec<&str> {
    raise_spans(src)
        .into_iter()
        .map(|(s, e)| &src[s..e])
        .collect()
}

fn masked(src: &str) -> String {
    let mut out = String::new();
    let mut last = 0;
    for (s, e) in raise_spans(src) {
        out.push_str(&src[last..s]);
        out.push_str("<RAISE>");
        last = e;
    }
    out.push_str(&src[last..]);
    out
}

/// The text after `RAISE EXCEPTION '` up to the first `:` if it is a refusal
/// code (two to five capitals, two digits).
fn code_of(raise: &str) -> Option<&str> {
    let lit = &raise[raise.find('\'')? + 1..];
    let code = &lit[..lit.find(':')?];
    let caps = code.bytes().take_while(u8::is_ascii_uppercase).count();
    ((2..=5).contains(&caps)
        && code.len() == caps + 2
        && code[caps..].bytes().all(|c| c.is_ascii_digit()))
    .then_some(code)
}

fn errcode_of(raise: &str) -> Option<&str> {
    let i = raise.find("ERRCODE")?;
    let rest = &raise[i..];
    let q = rest.find('\'')? + 1;
    Some(&rest[q..q + rest[q..].find('\'')?])
}

/// The one declared exception to "a code prefix and nothing else": AGK01
/// moves the system agent's role out of the message into DETAIL.
const AGK01: &str = "AGK01";

/// `raise` with `<code>: ` inserted after the opening quote of its message.
fn with_code(raise: &str, code: &str) -> String {
    let q = raise.find('\'').expect("a RAISE with a message") + 1;
    format!("{}{code}: {}", &raise[..q], &raise[q..])
}

/// AGK01's old RAISE interpolated the role (`the % system agent`, `v_role`);
/// the new one names no role in its message, keeps the rest of the sentence,
/// and carries the role in DETAIL.
fn assert_agk01_moves_only_the_role_to_detail(old: &str, new: &str) {
    assert!(
        old.contains("registered for the % system agent") && old.contains(", v_role"),
        "PREMISE: 148's message interpolated the role: {old}"
    );
    let message_end = new.find("USING").expect("AGK01 has a USING clause");
    let message = &new[..message_end];
    assert!(
        !message.contains('%') && !message.contains("v_role"),
        "AGK01's message interpolates nothing: {new}"
    );
    for kept in [
        "this public key was registered for a system agent",
        "(migration 148); no other agent may hold it. Nothing was written",
    ] {
        assert!(message.contains(kept), "AGK01 keeps {kept:?}: {new}");
    }
    assert!(
        new.contains("DETAIL = format('system agent role: %s', v_role)"),
        "AGK01 carries the role in DETAIL: {new}"
    );
}

#[test]
fn the_raise_scanner_masks_whole_statements_and_only_them() {
    let body = "BEGIN\n  -- RAISE EXCEPTION 'in a comment';\n  x := 'raise exception';\n  \
                RAISE EXCEPTION 'AB01: a; b', v USING ERRCODE = '42501';\n  y := 1;\nEND";
    assert_eq!(
        raises(body),
        vec!["RAISE EXCEPTION 'AB01: a; b', v USING ERRCODE = '42501';"]
    );
    assert_eq!(
        masked(body),
        "BEGIN\n  -- RAISE EXCEPTION 'in a comment';\n  x := 'raise exception';\n  <RAISE>\n  y := 1;\nEND"
    );
    assert_eq!(code_of(raises(body)[0]), Some("AB01"));
    assert_eq!(code_of("RAISE EXCEPTION 'epigraph tenancy: x'"), None);
    assert_eq!(errcode_of(raises(body)[0]), Some("42501"));
}

#[test]
fn the_migration_restates_exactly_the_listed_functions() {
    let restated = MIGRATION_176
        .matches("CREATE OR REPLACE FUNCTION public.")
        .count();
    assert_eq!(restated, RESTATED.len(), "one CREATE per listed function");
    for sig in RESTATED {
        let name = &sig[..sig.find('(').unwrap()];
        assert!(
            MIGRATION_176.contains(&format!("CREATE OR REPLACE FUNCTION public.{name}(")),
            "176 restates {name}"
        );
    }
}

#[sqlx::test(migrations = false)]
async fn migration_176_changes_only_raise_statements(pool: PgPool) {
    migrate(&pool, &up_to(175)).await;
    let before = facts(&pool).await;
    assert_eq!(before.len(), RESTATED.len(), "every function exists at 175");
    // Up to 176, not head: this pins what 176 itself did, so a later
    // migration that restates one of these functions (from 176's body, as the
    // README asks) is judged by its own test, not by this one.
    migrate(&pool, &up_to(176)).await;
    let after = facts(&pool).await;
    assert_eq!(after.len(), RESTATED.len());

    let mut introduced: Vec<String> = Vec::new();
    for sig in RESTATED {
        let (old, new) = (&before[*sig], &after[*sig]);
        assert_eq!(
            old.attributes, new.attributes,
            "{sig}: owner, ACL, SECURITY mode, search_path or volatility changed"
        );
        assert_ne!(
            old.body, new.body,
            "{sig}: 176 restated it, so a RAISE changed"
        );
        assert_eq!(
            masked(&old.body),
            masked(&new.body),
            "{sig}: the body changed outside its RAISE statements"
        );
        let (old_r, new_r) = (raises(&old.body), raises(&new.body));
        assert_eq!(old_r.len(), new_r.len(), "{sig}: RAISE count changed");
        for (o, n) in old_r.iter().zip(&new_r) {
            if o == n {
                continue;
            }
            assert_eq!(
                code_of(o),
                None,
                "{sig}: a changed RAISE was already coded: {o}"
            );
            let code = code_of(n).unwrap_or_else(|| panic!("{sig}: changed but uncoded: {n}"));
            assert_eq!(
                errcode_of(o),
                errcode_of(n),
                "{sig}: the SQLSTATE of a coded refusal changed: {n}"
            );
            if code == AGK01 {
                assert_agk01_moves_only_the_role_to_detail(o, n);
            } else {
                assert_eq!(
                    *n,
                    with_code(o, code),
                    "{sig}: a changed RAISE is the old one with `{code}: ` prefixed and \
                     nothing else changed (wording, arguments, HINT, DETAIL)"
                );
            }
            introduced.push(code.to_string());
        }
    }
    let mut expected: Vec<String> = epigraph_db::CALLER_REFUSAL_CODES
        .iter()
        .map(|c| (*c).to_string())
        .collect();
    expected.sort();
    let mut got = introduced.clone();
    got.sort();
    assert_eq!(
        got, expected,
        "176 introduces exactly CALLER_REFUSAL_CODES, each once"
    );
}
