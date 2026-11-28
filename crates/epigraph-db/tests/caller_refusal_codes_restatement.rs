//! Migration 176 (backlog e2c22c7c, ruling R-25) restates twelve functions to
//! give their caller-reachable refusals a code. This pins that it changed
//! NOTHING ELSE: a database migrated to 175 and the same database after 176
//! hold the same owner, ACL, SECURITY mode, `proconfig` (search_path) and
//! volatility for each function, and the same body once every
//! `RAISE EXCEPTION` statement is masked out. Each RAISE that does differ is
//! the old statement with a refusal code prefixed to its message and nothing
//! else changed (AGK01, which moves the role to DETAIL, is the one declared
//! exception), keeps its SQLSTATE, and the codes introduced are exactly
//! `epigraph_db::CALLER_REFUSAL_CODES` less the ones a later restatement adds.
//!
//! Migration 362 (backlog baac4c90) restates the three `*_require_tenancy`
//! bodies 176 left out, from 216's text, the same way: the same before/after
//! catalog comparison pins that only four RAISE statements change, each to
//! its declared new form, and that the codes it introduces are
//! [`MIGRATION_362_CODES`].
//!
//! Uses the non-macro `sqlx::query` forms so the offline `.sqlx/` cache is not
//! extended for one test.

use sqlx::migrate::Migrator;
use sqlx::PgPool;
use std::borrow::Cow;
use std::collections::BTreeMap;

static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");

const MIGRATION_176: &str = include_str!("../../../migrations/176_caller_refusal_codes.sql");

/// The restatement of the three `*_require_tenancy` bodies.
const MIGRATION_362_VERSION: i64 = 362;
const MIGRATION_362: &str =
    include_str!("../../../migrations/362_require_tenancy_refusal_codes.sql");

/// The codes 362 introduces, each also in `epigraph_db::CALLER_REFUSAL_CODES`.
const MIGRATION_362_CODES: &[&str] = &["TEN03", "TEN04", "TEN05", "TEN06"];

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
    facts_of(pool, RESTATED).await
}

async fn facts_of(pool: &PgPool, restated: &[&str]) -> BTreeMap<String, Fact> {
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
        .filter(|(sig, _, _)| restated.contains(&sig.as_str()))
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
        .filter(|c| !MIGRATION_362_CODES.contains(c))
        .map(|c| (*c).to_string())
        .collect();
    expected.sort();
    let mut got = introduced.clone();
    got.sort();
    assert_eq!(
        got, expected,
        "176 introduces exactly CALLER_REFUSAL_CODES less 362's, each once"
    );
}

// =============================================================================
// Migration 362: the three *_require_tenancy bodies, from 216's text.
// =============================================================================

/// The three functions 362 restates, by identity signature.
const RESTATED_362: &[&str] = &[
    "epigraph_claims_require_tenancy()",
    "epigraph_derived_require_tenancy()",
    "epigraph_root_require_tenancy()",
];

/// The RAISE statements 362 changes, per function, in body order: the code,
/// and the declared edits beyond the prefix, as `(old text, new text)` pairs
/// applied to the old statement once the code is prefixed. Every pair's old
/// text must be in the old statement, so an edit cannot be declared vacuously.
/// The two non-empty lists move row ids out of the MESSAGE into DETAIL.
type Change = (&'static str, &'static [(&'static str, &'static str)]);
const CHANGES_362: &[(&str, &[Change])] = &[
    (
        "epigraph_claims_require_tenancy()",
        &[(
            "TEN03",
            &[(
                "'or set claims.supersedes. id=%, agent_id=%', NEW.id, NEW.agent_id\n        \
                 USING ERRCODE = '23502',\n",
                "'or set claims.supersedes.'\n        USING ERRCODE = '23502',\n              \
                 DETAIL = format('id=%s, agent_id=%s', NEW.id, NEW.agent_id),\n",
            )],
        )],
    ),
    (
        "epigraph_derived_require_tenancy()",
        &[
            (
                "TEN04",
                &[
                    (
                        "%.claim_id=% references a nonexistent claim'",
                        "%.claim_id references a nonexistent claim'",
                    ),
                    (
                        "TG_TABLE_NAME, NEW.claim_id USING ERRCODE = '23503';",
                        "TG_TABLE_NAME USING ERRCODE = '23503',\n            \
                         DETAIL = format('claim_id=%s', NEW.claim_id);",
                    ),
                ],
            ),
            ("TEN05", &[]),
        ],
    ),
    ("epigraph_root_require_tenancy()", &[("TEN06", &[])]),
];

#[test]
fn migration_362_restates_exactly_the_three_tenancy_bodies() {
    assert_eq!(
        MIGRATION_362
            .matches("CREATE OR REPLACE FUNCTION public.")
            .count(),
        RESTATED_362.len(),
        "one CREATE per listed function"
    );
    for sig in RESTATED_362 {
        let name = &sig[..sig.find('(').unwrap()];
        assert!(
            MIGRATION_362.contains(&format!("CREATE OR REPLACE FUNCTION public.{name}(")),
            "362 restates {name}"
        );
    }
    assert_eq!(
        CHANGES_362.iter().map(|(sig, _)| *sig).collect::<Vec<_>>(),
        RESTATED_362,
        "every restated function declares its changes"
    );
}

#[test]
fn migration_362_codes_are_caller_refusal_codes() {
    for code in MIGRATION_362_CODES {
        assert_eq!(
            epigraph_db::caller_refusal_code(&format!("{code}: x")),
            Some(*code),
            "{code} is a listed caller-refusal code, so the HTTP mapper sends its text"
        );
    }
}

#[sqlx::test(migrations = false)]
async fn migration_362_changes_only_the_declared_raise_statements(pool: PgPool) {
    migrate(&pool, &up_to(MIGRATION_362_VERSION - 1)).await;
    let before = facts_of(&pool, RESTATED_362).await;
    assert_eq!(
        before.len(),
        RESTATED_362.len(),
        "every function exists before 362"
    );
    // Up to 362, not head, for the reason 176's test gives.
    migrate(&pool, &up_to(MIGRATION_362_VERSION)).await;
    let after = facts_of(&pool, RESTATED_362).await;
    assert_eq!(after.len(), RESTATED_362.len());

    let mut introduced: Vec<&str> = Vec::new();
    for (sig, changes) in CHANGES_362 {
        let (old, new) = (&before[*sig], &after[*sig]);
        assert_eq!(
            old.attributes, new.attributes,
            "{sig}: owner, ACL, SECURITY mode, search_path or volatility changed"
        );
        assert_eq!(
            masked(&old.body),
            masked(&new.body),
            "{sig}: the body changed outside its RAISE statements"
        );
        let (old_r, new_r) = (raises(&old.body), raises(&new.body));
        assert_eq!(old_r.len(), new_r.len(), "{sig}: RAISE count changed");
        let mut pending = changes.iter();
        for (o, n) in old_r.iter().zip(&new_r) {
            if o == n {
                assert_eq!(
                    code_of(n),
                    None,
                    "{sig}: an unchanged RAISE is uncoded: {n}"
                );
                continue;
            }
            let (code, edits) = pending
                .next()
                .unwrap_or_else(|| panic!("{sig}: an undeclared RAISE changed: {n}"));
            assert_eq!(
                code_of(o),
                None,
                "{sig}: a changed RAISE was already coded: {o}"
            );
            assert_eq!(code_of(n), Some(*code), "{sig}: expected {code}: {n}");
            assert_eq!(
                errcode_of(o),
                errcode_of(n),
                "{sig}: the SQLSTATE of a coded refusal changed: {n}"
            );
            let mut expected = with_code(o, code);
            for (from, to) in *edits {
                assert_eq!(
                    expected.matches(from).count(),
                    1,
                    "{sig}: PREMISE: 216's {code} statement holds {from:?} once: {o}"
                );
                expected = expected.replace(from, to);
            }
            assert_eq!(
                *n, expected,
                "{sig}: {code} is 216's statement with `{code}: ` prefixed and only its \
                 declared edits"
            );
            introduced.push(*code);
        }
        assert!(
            pending.next().is_none(),
            "{sig}: a declared change did not happen"
        );
    }
    assert_eq!(
        introduced, MIGRATION_362_CODES,
        "362 introduces exactly its codes, each once"
    );
}

fn undo_362() -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/runbooks/362-undo.sql"),
    )
    .expect("read the 362 undo runbook")
}

/// `docs/runbooks/362-undo.sql` returns the three bodies to their definition
/// below 362 (216's, owner, ACL, SECURITY mode and search_path included), and
/// a second run changes nothing.
#[sqlx::test(migrations = false)]
async fn the_362_undo_returns_the_bodies_below_362(pool: PgPool) {
    migrate(&pool, &up_to(MIGRATION_362_VERSION - 1)).await;
    let before = facts_of(&pool, RESTATED_362).await;
    migrate(&pool, &up_to(MIGRATION_362_VERSION)).await;
    assert_ne!(
        facts_of(&pool, RESTATED_362).await,
        before,
        "CALIBRATION: 362 changed the bodies"
    );
    let undo = undo_362();
    for run in ["first", "second"] {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the {run} run of the undo applies: {e}"));
        assert_eq!(
            facts_of(&pool, RESTATED_362).await,
            before,
            "after the {run} run the three bodies are exactly as below 362"
        );
    }
}

/// The undo refuses (55000, nothing changed) over a body a later migration
/// re-stated, rather than reverting it.
#[sqlx::test(migrations = false)]
async fn the_362_undo_refuses_over_a_body_restated_after_362(pool: PgPool) {
    migrate(&pool, &up_to(MIGRATION_362_VERSION)).await;
    sqlx::raw_sql(
        "CREATE OR REPLACE FUNCTION public.epigraph_root_require_tenancy() RETURNS trigger \
         LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp \
         AS $$ BEGIN RETURN NEW; END $$",
    )
    .execute(&pool)
    .await
    .expect("a later re-statement");
    let at = facts_of(&pool, RESTATED_362).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let e = sqlx::raw_sql(&undo_362())
        .execute(&mut *conn)
        .await
        .expect_err("the undo refuses over a foreign body");
    // The failed script leaves its transaction open on that connection: close
    // it rather than return it to the pool.
    drop(conn.detach());
    assert_eq!(
        e.as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref(),
        Some("55000"),
        "{e}"
    );
    assert_eq!(
        facts_of(&pool, RESTATED_362).await,
        at,
        "nothing was changed"
    );
}
