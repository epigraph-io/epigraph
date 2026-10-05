//! `epigraph-operator --act`: executing a CONFIRMED admin act (migration 130)
//! through the real binary, against a `#[sqlx::test]` database migrated 001 ->
//! head, on the dedicated maintenance DSN variable only.
//!
//! Once the acting custodian holds a live passkey the database refuses the
//! write without a confirmed act (ELV10). The verb recomputes the act's
//! canonical args from its own flags and refuses BEFORE writing when they are
//! not the confirmed act's (exit 1, nothing written, the act unspent); the
//! database consumes the act inside the write, so a dry run spends nothing.
//!
//! A confirmed act is stood in for by the shared fixture
//! (`viewer_fixture::confirmed_act`: the row written as the superuser with
//! triggers off): the proposal and its passkey ceremony are the database's and
//! the API's, driven in `epigraph-db/tests/pending_admin_acts.rs`; what is
//! under test here is the verb. Each test names the mutation it was verified
//! against in its doc.

mod viewer_fixture;

use sqlx::PgPool;
use std::process::Command;
use uuid::Uuid;
use viewer_fixture as fixture;

const BIN: &str = env!("CARGO_BIN_EXE_epigraph-operator");
const DSN_ENV: &str = "EPIGRAPH_OPERATOR_MAINTENANCE_DSN";
const AUDITOR: &str = "role:auditor";

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Run {
    fn show(&self) -> String {
        format!(
            "exit={}\n--- stdout\n{}\n--- stderr\n{}",
            self.code, self.stdout, self.stderr
        )
    }
}

async fn run_op(pool: &PgPool, args: &[&str]) -> Run {
    let url = fixture::database_url_for(pool).await;
    let out = Command::new(BIN)
        .args(args)
        .env("RUST_LOG", "warn")
        .env_remove("DATABASE_URL")
        .env_remove("MAINTENANCE_DATABASE_URL")
        .env(DSN_ENV, url)
        .output()
        .expect("spawn");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// A live passkey for `person` through 124's definers (maintenance opens,
/// the unstamped application completes); its first one only.
async fn live_passkey(pool: &PgPool, person: Uuid, n: u8) {
    let e: Uuid = fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let e = sqlx::query_scalar(
            "SELECT public.epigraph_create_passkey_enrollment($1, 'act cli test', 'key')",
        )
        .bind(person)
        .fetch_one(&mut *conn)
        .await
        .expect("enroll");
        (conn, e)
    })
    .await;
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        sqlx::query(
            "SELECT public.epigraph_set_passkey_enrollment_challenge($1, '{\"rs\": 1}'::jsonb)",
        )
        .bind(e)
        .execute(&mut *conn)
        .await
        .expect("enrollment challenge");
        let mut cred = vec![0x3C_u8; 16];
        cred[0] = n;
        sqlx::query(
            "SELECT public.epigraph_complete_passkey_enrollment($1, $2, '{\"cred\": 1}'::jsonb, \
                    '00000000-0000-0000-0000-000000000000'::uuid, 'none', true, false)",
        )
        .bind(e)
        .bind(cred)
        .execute(&mut *conn)
        .await
        .expect("complete the enrollment");
        (conn, ())
    })
    .await;
}

/// A live custodian holding a passkey: `(person, assignment)`.
async fn custodian_with_passkey(pool: &PgPool, label: &str, n: u8) -> (Uuid, Uuid) {
    let (person, _) = fixture::seed_human_operator(pool, label).await;
    let assignment = fixture::make_custodian(pool, person).await;
    live_passkey(pool, person, n).await;
    (person, assignment)
}

async fn assignments(pool: &PgPool, holder: Uuid) -> Vec<(Uuid, Option<Uuid>)> {
    sqlx::query_as(
        "SELECT id, grant_act_id FROM role_assignments WHERE holder_person_id = $1 \
          ORDER BY created_at",
    )
    .bind(holder)
    .fetch_all(pool)
    .await
    .expect("assignments")
}

async fn consumed(pool: &PgPool, act: Uuid) -> bool {
    sqlx::query_scalar("SELECT consumed_at IS NOT NULL FROM pending_admin_acts WHERE id = $1")
        .bind(act)
        .fetch_one(pool)
        .await
        .expect("the act")
}

fn grant_json(holder: Uuid, valid_to: &str, reason: &str) -> String {
    format!(
        "{{\"role\": \"{AUDITOR}\", \"holder\": \"{holder}\", \"valid_from\": null, \
         \"valid_to\": \"{valid_to}\", \"reason\": \"{reason}\"}}"
    )
}

/// The custodian holding a passkey cannot grant without an act: `grant-role`
/// with no `--act` is refused by the database (ELV10, exit 1, nothing
/// written). On its confirmed act, with exactly the act's args, the grant
/// lands, names the act and spends it; a second run on the spent act is
/// refused before writing.
///
/// Verified to fail: the verb dropping `--act` (calling the 123 definer) ->
/// the confirmed run is refused ELV10; the verb's spent-act check removed
/// from `refusal_for` -> the second run reaches the database (ELV08), and
/// stderr names no "already executed".
#[sqlx::test(migrations = "../../migrations")]
async fn grant_role_needs_the_confirmed_act_once_the_grantor_holds_a_passkey(pool: PgPool) {
    let (g, _) = custodian_with_passkey(&pool, "grantor", 1).await;
    let (x, _) = fixture::seed_human_operator(&pool, "holder").await;
    let (gs, xs) = (g.to_string(), x.to_string());
    let base = [
        "grant-role",
        "--role",
        AUDITOR,
        "--holder",
        &xs,
        "--valid-to",
        "2099-01-01T00:00:00Z",
        "--granted-by",
        &gs,
        "--reason",
        "audit",
        "--apply",
    ];
    let bare = run_op(&pool, &base).await;
    assert_eq!(bare.code, 1, "no act: {}", bare.show());
    assert!(bare.stderr.contains("ELV10"), "{}", bare.show());
    assert!(
        assignments(&pool, x).await.is_empty(),
        "nothing was granted"
    );

    let act = fixture::confirmed_act(
        &pool,
        "role.grant",
        &grant_json(x, "2099-01-01T00:00:00Z", "audit"),
        g,
    )
    .await;
    let acts = act.to_string();
    let mut with_act = base.to_vec();
    with_act.extend(["--act", &acts]);
    let run = run_op(&pool, &with_act).await;
    assert_eq!(run.code, 0, "{}", run.show());
    assert!(run.stdout.contains(&format!("act={act}")), "{}", run.show());
    assert_eq!(assignments(&pool, x).await.len(), 1);
    assert_eq!(assignments(&pool, x).await[0].1, Some(act));
    assert!(consumed(&pool, act).await, "the act is spent");

    let again = run_op(&pool, &with_act).await;
    assert_eq!(again.code, 1, "{}", again.show());
    assert!(
        again.stderr.contains("REFUSED") && again.stderr.contains("already executed"),
        "{}",
        again.show()
    );
    assert_eq!(assignments(&pool, x).await.len(), 1, "nothing more");
}

/// The verb refuses BEFORE writing, naming both forms, when its flags are not
/// the act's args: a `--valid-to` one day off, another `--granted-by` than the
/// proposer, no `--granted-by` at all. A DRY RUN with the exact args spends
/// nothing (the consumption rolls back with the grant); `--apply` then spends
/// it.
///
/// Verified to fail: the verb's args comparison removed from `refusal_for` ->
/// the one-field-different run reaches the database (ELV09) and stderr carries
/// no "the flags say"; `custodian::grant` committing a dry run -> the act is
/// spent by the dry run.
#[sqlx::test(migrations = "../../migrations")]
async fn grant_role_on_an_act_refuses_flags_that_are_not_the_acts(pool: PgPool) {
    let (g, _) = custodian_with_passkey(&pool, "grantor", 1).await;
    let (q, _) = custodian_with_passkey(&pool, "other custodian", 2).await;
    let (x, _) = fixture::seed_human_operator(&pool, "holder").await;
    let act = fixture::confirmed_act(
        &pool,
        "role.grant",
        &grant_json(x, "2099-01-01T00:00:00Z", "audit"),
        g,
    )
    .await;
    let (gs, qs, xs, acts) = (g.to_string(), q.to_string(), x.to_string(), act.to_string());
    let run_with = |valid_to: &'static str, by: Option<&str>, apply: bool| {
        let mut args = vec![
            "grant-role".to_string(),
            "--role".to_string(),
            AUDITOR.to_string(),
            "--holder".to_string(),
            xs.clone(),
            "--valid-to".to_string(),
            valid_to.to_string(),
            "--reason".to_string(),
            "audit".to_string(),
            "--act".to_string(),
            acts.clone(),
        ];
        if let Some(by) = by {
            args.extend(["--granted-by".to_string(), by.to_string()]);
        }
        if apply {
            args.push("--apply".to_string());
        }
        args
    };
    for (args, what) in [
        (
            run_with("2099-01-02T00:00:00Z", Some(&gs), true),
            "valid_to one day off",
        ),
        (
            run_with("2099-01-01T00:00:00Z", Some(&qs), true),
            "another grantor",
        ),
        (run_with("2099-01-01T00:00:00Z", None, true), "no grantor"),
    ] {
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let run = run_op(&pool, &refs).await;
        assert_eq!(run.code, 1, "{what}: {}", run.show());
        assert!(run.stderr.contains("REFUSED"), "{what}: {}", run.show());
        assert!(!consumed(&pool, act).await, "{what}: the act is unspent");
    }
    let off = run_with("2099-01-02T00:00:00Z", Some(&gs), true);
    let refs: Vec<&str> = off.iter().map(String::as_str).collect();
    let run = run_op(&pool, &refs).await;
    assert!(
        run.stderr.contains("the flags say") && run.stderr.contains("2099-01-02T00:00:00.000000Z"),
        "the refusal shows both forms: {}",
        run.show()
    );
    assert!(
        assignments(&pool, x).await.is_empty(),
        "nothing was granted"
    );

    let dry = run_with("2099-01-01T00:00:00Z", Some(&gs), false);
    let refs: Vec<&str> = dry.iter().map(String::as_str).collect();
    let run = run_op(&pool, &refs).await;
    assert_eq!(run.code, 0, "{}", run.show());
    assert!(run.stdout.contains("WOULD BE GRANTED"), "{}", run.show());
    assert!(!consumed(&pool, act).await, "a dry run spends nothing");
    assert!(assignments(&pool, x).await.is_empty());

    let apply = run_with("2099-01-01T00:00:00Z", Some(&gs), true);
    let refs: Vec<&str> = apply.iter().map(String::as_str).collect();
    let run = run_op(&pool, &refs).await;
    assert_eq!(run.code, 0, "{}", run.show());
    assert!(consumed(&pool, act).await);
}

/// `end-role-assignment` while a custodian holds a passkey: with no act the
/// database refuses (ELV10); on an act over another reason the verb refuses
/// before writing; on the exact act it ends the assignment, names the act, and
/// the end's audit row says `confirmation = 'passkey'`.
///
/// Verified to fail: the verb dropping `--act` on an end (calling the 123
/// definer) -> the confirmed end is refused ELV10.
#[sqlx::test(migrations = "../../migrations")]
async fn end_role_assignment_needs_the_confirmed_act(pool: PgPool) {
    let (g, _) = custodian_with_passkey(&pool, "custodian", 1).await;
    let (x, _) = fixture::seed_human_operator(&pool, "holder").await;
    let grant = fixture::confirmed_act(
        &pool,
        "role.grant",
        &grant_json(x, "2099-01-01T00:00:00Z", "audit"),
        g,
    )
    .await;
    let a: Uuid = sqlx::query_scalar(
        "SELECT public.epigraph_grant_role('role:auditor', $1, NULL, '2099-01-01T00:00:00Z', \
                                          $2, 'audit', $3)",
    )
    .bind(x)
    .bind(g)
    .bind(grant)
    .fetch_one(&pool)
    .await
    .expect("an auditor");
    let a_s = a.to_string();
    let bare = run_op(
        &pool,
        &[
            "end-role-assignment",
            "--assignment",
            &a_s,
            "--reason",
            "done",
            "--apply",
        ],
    )
    .await;
    assert_eq!(bare.code, 1, "{}", bare.show());
    assert!(bare.stderr.contains("ELV10"), "{}", bare.show());

    let other = fixture::confirmed_act(
        &pool,
        "role.end",
        &format!("{{\"assignment\": \"{a}\", \"reason\": \"another reason\"}}"),
        g,
    )
    .await;
    let other_s = other.to_string();
    let run = run_op(
        &pool,
        &[
            "end-role-assignment",
            "--assignment",
            &a_s,
            "--reason",
            "done",
            "--act",
            &other_s,
            "--apply",
        ],
    )
    .await;
    assert_eq!(run.code, 1, "{}", run.show());
    assert!(run.stderr.contains("REFUSED"), "{}", run.show());

    let act = fixture::confirmed_act(
        &pool,
        "role.end",
        &format!("{{\"assignment\": \"{a}\", \"reason\": \"done\"}}"),
        g,
    )
    .await;
    let act_s = act.to_string();
    let run = run_op(
        &pool,
        &[
            "end-role-assignment",
            "--assignment",
            &a_s,
            "--reason",
            "done",
            "--act",
            &act_s,
            "--apply",
        ],
    )
    .await;
    assert_eq!(run.code, 0, "{}", run.show());
    assert!(
        run.stdout.contains("ENDED") && run.stdout.contains(&format!("act={act}")),
        "{}",
        run.show()
    );
    let confirmation: String = sqlx::query_scalar(
        "SELECT details->>'confirmation' FROM security_events \
          WHERE event_type = 'platform.role_ended' AND details->>'assignment_id' = $1",
    )
    .bind(a_s.as_str())
    .fetch_one(&pool)
    .await
    .expect("the end's audit row");
    assert_eq!(confirmation, "passkey");
}

/// A current, world-owned (platform corpus) claim by a fresh unbound author.
async fn corpus_claim(pool: &PgPool) -> Uuid {
    let (author, _) = fixture::seed_agent_with_group(pool, "legacy author").await;
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5)",
    )
    .bind(id)
    .bind(format!("corpus claim {id}"))
    .bind(id.as_bytes().repeat(2))
    .bind(author)
    .bind(Uuid::nil())
    .execute(pool)
    .await
    .expect("claim");
    id
}

async fn is_current(pool: &PgPool, claim: Uuid) -> bool {
    sqlx::query_scalar("SELECT COALESCE(is_current, true) FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("claim")
}

/// `custodial-supersede` by a custodian holding a passkey: with no act the
/// database refuses the record (ELV10) and the whole supersede rolls back;
/// on an act confirmed for truth 0.7, flags saying 0.8 are refused before any
/// write; with the act's exact args (the content hashed by the DATABASE in
/// this test, so the verb's own hash is checked against it) the claim is
/// revised, the act spent, and the `platform.custodial_act` row names the
/// act with `confirmation = 'passkey'`.
///
/// Verified to fail: the verb recording without the act (the six-parameter
/// recorder) -> the confirmed run is refused ELV10; the verb hashing the
/// content trimmed -> the confirmed run is refused (the flags are not the
/// act's).
#[sqlx::test(migrations = "../../migrations")]
async fn custodial_supersede_executes_its_confirmed_act(pool: PgPool) {
    let (c, a) = custodian_with_passkey(&pool, "custodian", 1).await;
    let claim = corpus_claim(&pool).await;
    let content = "  the custodian's revision, with \"quotes\" and a trailing newline\n";
    let (cs, as_, claims) = (c.to_string(), a.to_string(), claim.to_string());
    let args_for = |truth: &str, act: Option<&str>| {
        let mut v: Vec<String> = [
            "custodial-supersede",
            "--claim",
            &claims,
            "--content",
            content,
            "--truth",
            truth,
            "--assignment",
            &as_,
            "--actor",
            &cs,
            "--reason",
            "custodial revision",
            "--apply",
        ]
        .iter()
        .map(ToString::to_string)
        .collect();
        if let Some(act) = act {
            v.extend(["--act".to_string(), act.to_string()]);
        }
        v
    };
    let run = |args: Vec<String>| {
        let pool = pool.clone();
        async move {
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            run_op(&pool, &refs).await
        }
    };
    let bare = run(args_for("0.7", None)).await;
    assert_eq!(bare.code, 1, "{}", bare.show());
    assert!(bare.stderr.contains("ELV10"), "{}", bare.show());
    assert!(is_current(&pool, claim).await, "the supersede rolled back");

    let hash: String = sqlx::query_scalar("SELECT encode(sha256(convert_to($1, 'UTF8')), 'hex')")
        .bind(content)
        .fetch_one(&pool)
        .await
        .expect("sha256");
    let act = fixture::confirmed_act(
        &pool,
        "claim.custodial_supersede",
        &format!(
            "{{\"claim\": \"{claim}\", \"content_sha256\": \"{hash}\", \"truth\": 0.7, \
             \"reason\": \"custodial revision\", \"allow_owned\": false}}"
        ),
        c,
    )
    .await;
    let act_s = act.to_string();
    let off = run(args_for("0.8", Some(&act_s))).await;
    assert_eq!(off.code, 1, "{}", off.show());
    assert!(off.stderr.contains("REFUSED"), "{}", off.show());
    assert!(is_current(&pool, claim).await, "nothing was changed");

    let done = run(args_for("0.7", Some(&act_s))).await;
    assert_eq!(done.code, 0, "{}", done.show());
    assert!(
        done.stdout.contains(&format!("act={act}")),
        "{}",
        done.show()
    );
    assert!(!is_current(&pool, claim).await, "the claim was revised");
    let (act_id, confirmation): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT details->>'act_id', details->>'confirmation' FROM security_events \
          WHERE event_type = 'platform.custodial_act' AND details->>'target' = $1",
    )
    .bind(claims.as_str())
    .fetch_one(&pool)
    .await
    .expect("the custodial act record");
    assert_eq!(act_id.as_deref(), Some(act_s.as_str()));
    assert_eq!(confirmation.as_deref(), Some("passkey"));
    let spent: bool =
        sqlx::query_scalar("SELECT consumed_at IS NOT NULL FROM pending_admin_acts WHERE id = $1")
            .bind(act)
            .fetch_one(&pool)
            .await
            .expect("the act");
    assert!(spent, "the act is spent");
}

/// A LATER passkey: `passkey-enroll` for a person who already holds a live
/// passkey is refused by the database (ELV10, no ticket); on a confirmed
/// `passkey.register` act whose label differs from the flags the verb refuses
/// before writing; on the exact act the ticket opens `confirmed_act` and the
/// act is spent. The break-glass: once the person's only passkey is revoked,
/// a maintenance enrollment opens again with no act.
///
/// Verified to fail: the enroll verb dropping `--act` (the 124 definer) ->
/// the confirmed run is refused ELV10.
#[sqlx::test(migrations = "../../migrations")]
async fn passkey_enroll_a_later_passkey_needs_the_confirmed_act(pool: PgPool) {
    let (p, _) = custodian_with_passkey(&pool, "custodian", 1).await;
    let ps = p.to_string();
    let enroll = |extra: &[&str]| {
        let mut args: Vec<String> = [
            "passkey-enroll",
            "--person",
            &ps,
            "--reason",
            "a second key",
            "--label",
            "laptop",
            "--apply",
        ]
        .iter()
        .map(ToString::to_string)
        .collect();
        args.extend(extra.iter().map(ToString::to_string));
        let pool = pool.clone();
        async move {
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            run_op(&pool, &refs).await
        }
    };
    let tickets = |pool: PgPool| async move {
        let n: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM passkey_enrollments WHERE person_agent_id = $1",
        )
        .bind(p)
        .fetch_one(&pool)
        .await
        .expect("tickets");
        n
    };
    let before = tickets(pool.clone()).await;
    let bare = enroll(&[]).await;
    assert_eq!(bare.code, 1, "{}", bare.show());
    assert!(bare.stderr.contains("ELV10"), "{}", bare.show());
    assert_eq!(tickets(pool.clone()).await, before, "no ticket");

    let other = fixture::confirmed_act(
        &pool,
        "passkey.register",
        &format!("{{\"person\": \"{p}\", \"label\": \"phone\", \"reason\": \"a second key\"}}"),
        p,
    )
    .await;
    let other_s = other.to_string();
    let run = enroll(&["--act", &other_s]).await;
    assert_eq!(run.code, 1, "{}", run.show());
    assert!(run.stderr.contains("REFUSED"), "{}", run.show());

    let act = fixture::confirmed_act(
        &pool,
        "passkey.register",
        &format!("{{\"person\": \"{p}\", \"label\": \"laptop\", \"reason\": \"a second key\"}}"),
        p,
    )
    .await;
    let act_s = act.to_string();
    let run = enroll(&["--act", &act_s]).await;
    assert_eq!(run.code, 0, "{}", run.show());
    let (via, spent): (String, bool) = sqlx::query_as(
        "SELECT e.created_via, a.consumed_at IS NOT NULL FROM passkey_enrollments e \
           JOIN pending_admin_acts a ON a.id = e.act_id WHERE e.act_id = $1",
    )
    .bind(act)
    .fetch_one(&pool)
    .await
    .expect("the enrollment");
    assert_eq!((via.as_str(), spent), ("confirmed_act", true));

    fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        sqlx::query(
            "SELECT public.epigraph_revoke_passkey(k.id, 'lost') FROM person_authenticators k \
              WHERE k.person_agent_id = $1 AND k.revoked_at IS NULL",
        )
        .bind(p)
        .execute(&mut *conn)
        .await
        .expect("revoke");
        (conn, ())
    })
    .await;
    let again = enroll(&[]).await;
    assert_eq!(again.code, 0, "the break-glass: {}", again.show());
}
