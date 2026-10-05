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

// =====================================================================
// EL-12b: the whole act, end to end: proposed and confirmed over HTTP,
// executed by the real binary
// =====================================================================

#[path = "../../epigraph-passkey/tests/support/soft_authenticator.rs"]
mod soft_authenticator;

/// The real API router on an application-role pool that declares the
/// per-access recorder, with a software-attestation relying party: its
/// address and its token signer.
async fn api(
    pool: &PgPool,
) -> (
    std::net::SocketAddr,
    std::sync::Arc<epigraph_auth::JwtConfig>,
) {
    let scoped = epigraph_db::ScopedPool::connect_with_access_recorder_for_tests(
        &fixture::database_url_for(pool).await,
        epigraph_db::SessionGucMode::Session,
        epigraph_db::ScopedPoolOptions::default(),
        Some("epigraph_app"),
    )
    .await
    .expect("app-role pool");
    let rp = epigraph_passkey::Passkeys::new(epigraph_passkey::PasskeyConfig {
        rp_id: soft_authenticator::RP_ID.into(),
        origin: soft_authenticator::ORIGIN.parse().unwrap(),
        policy: epigraph_passkey::AttestationPolicy::SoftwareAllowed,
    })
    .expect("relying party");
    let state =
        epigraph_api::AppState::with_scoped_pool(scoped, epigraph_api::ApiConfig::default())
            .with_passkeys(Some(std::sync::Arc::new(rp)));
    let jwt = state.jwt_config.clone();
    let app = epigraph_api::create_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });
    (addr, jwt)
}

async fn post(
    addr: std::net::SocketAddr,
    path: &str,
    token: Option<&str>,
    body: &serde_json::Value,
) -> (u16, serde_json::Value) {
    let mut req = reqwest::Client::new()
        .post(format!("http://{addr}{path}"))
        .json(body);
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    let resp = req.send().await.expect("POST");
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(serde_json::Value::Null))
}

/// [`run_op`] over owned arguments.
async fn run_strings(pool: &PgPool, args: &[String]) -> Run {
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run_op(pool, &refs).await
}

/// A human token for `person` on `client`, naming `family` and `elv`.
fn token(
    jwt: &epigraph_auth::JwtConfig,
    person: Uuid,
    client: Uuid,
    family: Uuid,
    elv: Option<Uuid>,
) -> String {
    jwt.issue_access_token(
        client,
        vec!["claims:read".into(), "platform:admin".into()],
        "human",
        None,
        Some(person),
        chrono::Duration::minutes(15),
        epigraph_auth::AccessTokenBinding {
            family_id: Some(family),
            elevation_id: elv,
        },
    )
    .expect("mint")
    .0
}

/// THE ACCEPTANCE PASS for one `role.end` (elevation plan EL-12b), every
/// step on its production path: the custodian P registers a passkey through
/// the enrollment ceremony, elevates through the ticket ceremony, PROPOSES the
/// end of a test assignment over `POST /api/v1/admin/acts`, CONFIRMS it at
/// `/elevate/act/<id>` with that passkey (the challenge committing to the
/// act), and the real `epigraph-operator end-role-assignment --act` EXECUTES
/// it: the assignment ends, names the act, the act is spent, and the end's
/// audit row says `confirmation = 'passkey'` with the act and the elevation
/// it was proposed under. Calibration: the same verb without `--act` is
/// refused ELV10 (P holds a passkey), and before the confirmation the act is
/// refused by the verb.
///
/// Verified to fail with the act's challenge started without the content
/// binding (the assertion is refused `challenge_not_bound`, so the act is
/// never confirmed and the verb refuses it).
#[sqlx::test(migrations = "../../migrations")]
async fn a_role_end_is_proposed_confirmed_and_executed_end_to_end(pool: PgPool) {
    use soft_authenticator::{ClientUv, SoftAuthenticator, ORIGIN};
    let (p, _) = fixture::seed_human_operator(&pool, "custodian").await;
    fixture::make_custodian(&pool, p).await;
    let (x, _) = fixture::seed_human_operator(&pool, "auditor").await;
    // A bootstrap grant by P: no custodian holds a passkey yet.
    let assignment: Uuid = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let a = sqlx::query_scalar(
            "SELECT public.epigraph_grant_role('role:auditor', $1, NULL, NULL, $2, 'test')",
        )
        .bind(x)
        .bind(p)
        .fetch_one(&mut *conn)
        .await
        .expect("a test assignment");
        (conn, a)
    })
    .await;
    let (addr, jwt) = api(&pool).await;
    let mut auth = SoftAuthenticator::new(Uuid::from_u128(0x5eed));

    // 1. The passkey, through the enrollment ceremony.
    let enrollment: Uuid = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let e = sqlx::query_scalar(
            "SELECT public.epigraph_create_passkey_enrollment($1, 'e2e', 'key')",
        )
        .bind(p)
        .fetch_one(&mut *conn)
        .await
        .expect("an enrollment");
        (conn, e)
    })
    .await;
    let base = format!("/elevate/enroll/{enrollment}");
    let (status, options) = post(
        addr,
        &format!("{base}/challenge"),
        None,
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(status, 200, "{options}");
    let registration = auth.register(ORIGIN, options, ClientUv::AsRequested).await;
    let (status, body) = post(addr, &format!("{base}/finish"), None, &registration).await;
    assert_eq!(status, 200, "enrollment: {body}");

    // 2. The elevation, through the ticket ceremony.
    let client: Uuid = sqlx::query_scalar(
        "SELECT id FROM oauth_clients WHERE agent_id = $1 AND client_type = 'human'",
    )
    .bind(p)
    .fetch_one(&pool)
    .await
    .expect("P's client");
    let hash: Vec<u8> = [
        Uuid::new_v4().as_bytes().to_vec(),
        Uuid::new_v4().as_bytes().to_vec(),
    ]
    .concat();
    let family: Uuid = sqlx::query_scalar(
        "INSERT INTO refresh_tokens (token_hash, client_id, scopes, expires_at) \
         VALUES ($1, $2, ARRAY['claims:read'], now() + interval '1 day') RETURNING id",
    )
    .bind(&hash)
    .bind(client)
    .fetch_one(&pool)
    .await
    .expect("a family");
    let plain = token(&jwt, p, client, family, None);
    let (status, ticket) = post(
        addr,
        "/api/v1/elevation/tickets",
        Some(&plain),
        &serde_json::json!({"reason": "end a test assignment"}),
    )
    .await;
    assert_eq!(status, 201, "{ticket}");
    let ticket = ticket["ticket_id"].as_str().unwrap().to_string();
    let (_, options) = post(
        addr,
        &format!("/elevate/{ticket}/challenge"),
        None,
        &serde_json::json!({}),
    )
    .await;
    let assertion = auth.authenticate(ORIGIN, options).await;
    let (status, body) = post(addr, &format!("/elevate/{ticket}/assert"), None, &assertion).await;
    assert_eq!(status, 200, "elevation: {body}");
    let session: Uuid =
        sqlx::query_scalar("SELECT session_id FROM elevation_tickets WHERE id = $1::uuid")
            .bind(&ticket)
            .fetch_one(&pool)
            .await
            .expect("the session");
    let elevated = token(&jwt, p, client, family, Some(session));

    // 3. The proposal.
    let (status, proposed) = post(
        addr,
        "/api/v1/admin/acts",
        Some(&elevated),
        &serde_json::json!({"kind": "role.end",
                            "args": {"assignment": assignment.to_string(), "reason": "done"},
                            "reason": "the test assignment is no longer needed"}),
    )
    .await;
    assert_eq!(status, 201, "{proposed}");
    let act: Uuid = proposed["act_id"].as_str().unwrap().parse().unwrap();
    let (a_s, act_s) = (assignment.to_string(), act.to_string());
    let end = |with_act: bool| {
        let mut args = vec![
            "end-role-assignment",
            "--assignment",
            &a_s,
            "--reason",
            "done",
        ];
        if with_act {
            args.extend(["--act", &act_s]);
        }
        args.push("--apply");
        args.into_iter().map(str::to_string).collect::<Vec<_>>()
    };
    let early = run_strings(&pool, &end(true)).await;
    assert_eq!(
        early.code,
        1,
        "an unconfirmed act is refused: {}",
        early.show()
    );

    // 4. The confirmation, with the passkey, over the act's own challenge.
    let (status, options) = post(
        addr,
        &format!("/elevate/act/{act}/challenge"),
        None,
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(status, 200, "{options}");
    let assertion = auth.authenticate(ORIGIN, options).await;
    let (status, body) = post(
        addr,
        &format!("/elevate/act/{act}/assert"),
        None,
        &assertion,
    )
    .await;
    assert_eq!(status, 200, "confirmation: {body}");

    // 5. The execution.
    let bare = run_strings(&pool, &end(false)).await;
    assert_eq!(bare.code, 1, "{}", bare.show());
    assert!(
        bare.stderr.contains("ELV10"),
        "CALIBRATION: P holds a passkey: {}",
        bare.show()
    );
    let done = run_strings(&pool, &end(true)).await;
    assert_eq!(done.code, 0, "{}", done.show());
    let (revoked, revoke_act): (bool, Option<Uuid>) = sqlx::query_as(
        "SELECT revoked_at IS NOT NULL, revoke_act_id FROM role_assignments WHERE id = $1",
    )
    .bind(assignment)
    .fetch_one(&pool)
    .await
    .expect("the assignment");
    assert_eq!(
        (revoked, revoke_act),
        (true, Some(act)),
        "ended, naming the act"
    );
    assert!(consumed(&pool, act).await, "the act is spent");
    let (confirmation, act_id, elevation): (Option<String>, Option<String>, Option<String>) =
        sqlx::query_as(
            "SELECT details->>'confirmation', details->>'act_id', details->>'elevation_id' \
               FROM security_events \
              WHERE event_type = 'platform.role_ended' AND details->>'assignment_id' = $1",
        )
        .bind(assignment.to_string())
        .fetch_one(&pool)
        .await
        .expect("the end's audit row");
    assert_eq!(
        (confirmation.as_deref(), act_id, elevation),
        (
            Some("passkey"),
            Some(act.to_string()),
            Some(session.to_string())
        )
    );
}

// =====================================================================
// EL-13: `verify-confirmations`, the offline confirmation verifier
// =====================================================================

/// A custodian P elevated through the real ceremonies, with two bootstrap
/// test assignments (granted before P held a passkey) an act can end.
struct Elevated {
    addr: std::net::SocketAddr,
    jwt: std::sync::Arc<epigraph_auth::JwtConfig>,
    auth: soft_authenticator::SoftAuthenticator,
    person: Uuid,
    client: Uuid,
    ticket: Uuid,
    elevated: String,
    assignments: [Uuid; 2],
    credential: Vec<u8>,
}

/// A fresh refresh family of `client` (one live elevation per family).
async fn fresh_family(pool: &PgPool, client: Uuid) -> Uuid {
    let hash: Vec<u8> = [
        Uuid::new_v4().as_bytes().to_vec(),
        Uuid::new_v4().as_bytes().to_vec(),
    ]
    .concat();
    sqlx::query_scalar(
        "INSERT INTO refresh_tokens (token_hash, client_id, scopes, expires_at) \
         VALUES ($1, $2, ARRAY['claims:read'], now() + interval '1 day') RETURNING id",
    )
    .bind(&hash)
    .bind(client)
    .fetch_one(pool)
    .await
    .expect("a family")
}

/// A grant-mode ticket of P's on a fresh family, its ceremony started:
/// `(ticket, the assertion options)`.
async fn started_ticket(pool: &PgPool, e: &Elevated) -> (Uuid, serde_json::Value) {
    let family = fresh_family(pool, e.client).await;
    let plain = token(&e.jwt, e.person, e.client, family, None);
    let (status, ticket) = post(
        e.addr,
        "/api/v1/elevation/tickets",
        Some(&plain),
        &serde_json::json!({"reason": "verify-confirmations test"}),
    )
    .await;
    assert_eq!(status, 201, "{ticket}");
    let ticket: Uuid = ticket["ticket_id"].as_str().unwrap().parse().unwrap();
    let (status, options) = post(
        e.addr,
        &format!("/elevate/{ticket}/challenge"),
        None,
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(status, 200, "{options}");
    (ticket, options)
}

/// A custodian P holding a passkey of `auth`'s, enrolled through the real
/// ceremony (its registration passed through `wrap` on the way), NOT yet
/// elevated (`ticket` and `elevated` are empty).
async fn enrolled_custodian(
    pool: &PgPool,
    auth: soft_authenticator::SoftAuthenticator,
    wrap: fn(&serde_json::Value) -> serde_json::Value,
) -> Elevated {
    use soft_authenticator::{ClientUv, ORIGIN};
    let (p, _) = fixture::seed_human_operator(pool, "custodian").await;
    fixture::make_custodian(pool, p).await;
    let mut assignments = [Uuid::nil(); 2];
    for (i, a) in assignments.iter_mut().enumerate() {
        let (x, _) = fixture::seed_human_operator(pool, &format!("auditor {i}")).await;
        *a = fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
            let a = sqlx::query_scalar(
                "SELECT public.epigraph_grant_role('role:auditor', $1, NULL, NULL, $2, 'test')",
            )
            .bind(x)
            .bind(p)
            .fetch_one(&mut *conn)
            .await
            .expect("a test assignment");
            (conn, a)
        })
        .await;
    }
    let (addr, jwt) = api(pool).await;
    let mut auth = auth;
    let enrollment: Uuid = fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let e = sqlx::query_scalar(
            "SELECT public.epigraph_create_passkey_enrollment($1, 'verify', 'key')",
        )
        .bind(p)
        .fetch_one(&mut *conn)
        .await
        .expect("an enrollment");
        (conn, e)
    })
    .await;
    let base = format!("/elevate/enroll/{enrollment}");
    let (_, options) = post(
        addr,
        &format!("{base}/challenge"),
        None,
        &serde_json::json!({}),
    )
    .await;
    let registration = wrap(&auth.register(ORIGIN, options, ClientUv::AsRequested).await);
    let (status, body) = post(addr, &format!("{base}/finish"), None, &registration).await;
    assert_eq!(status, 200, "enrollment: {body}");
    let client: Uuid = sqlx::query_scalar(
        "SELECT id FROM oauth_clients WHERE agent_id = $1 AND client_type = 'human'",
    )
    .bind(p)
    .fetch_one(pool)
    .await
    .expect("P's client");
    let credential: Vec<u8> = sqlx::query_scalar(
        "SELECT credential_id FROM person_authenticators WHERE person_agent_id = $1",
    )
    .bind(p)
    .fetch_one(pool)
    .await
    .expect("P's passkey");
    Elevated {
        addr,
        jwt,
        auth,
        person: p,
        client,
        ticket: Uuid::nil(),
        elevated: String::new(),
        assignments,
        credential,
    }
}

/// [`enrolled_custodian`] with a synced passkey, then ELEVATED through the
/// real ticket ceremony (`ticket`, and the elevated token in `elevated`).
async fn elevated_custodian(pool: &PgPool) -> Elevated {
    let mut e = enrolled_custodian(
        pool,
        soft_authenticator::SoftAuthenticator::new(Uuid::from_u128(0x5eed)),
        Clone::clone,
    )
    .await;
    let (ticket, options) = started_ticket(pool, &e).await;
    let assertion = e
        .auth
        .authenticate(soft_authenticator::ORIGIN, options)
        .await;
    let (status, body) = post(
        e.addr,
        &format!("/elevate/{ticket}/assert"),
        None,
        &assertion,
    )
    .await;
    assert_eq!(status, 200, "elevation: {body}");
    let (session, family): (Uuid, Uuid) =
        sqlx::query_as("SELECT session_id, family_id FROM elevation_tickets WHERE id = $1")
            .bind(ticket)
            .fetch_one(pool)
            .await
            .expect("the session");
    e.ticket = ticket;
    e.elevated = token(&e.jwt, e.person, e.client, family, Some(session));
    e
}

/// Propose `role.end` of `assignment` over HTTP, elevated: the act id.
async fn propose_end(e: &Elevated, assignment: Uuid) -> Uuid {
    let (status, proposed) = post(
        e.addr,
        "/api/v1/admin/acts",
        Some(&e.elevated),
        &serde_json::json!({"kind": "role.end",
                            "args": {"assignment": assignment.to_string(), "reason": "done"},
                            "reason": "verify-confirmations test"}),
    )
    .await;
    assert_eq!(status, 201, "{proposed}");
    proposed["act_id"].as_str().unwrap().parse().unwrap()
}

/// The stored ceremony challenge of a ticket (b64url).
async fn ticket_challenge(pool: &PgPool, ticket: Uuid) -> String {
    sqlx::query_scalar(
        "SELECT challenge_state->'library'->'ast'->>'challenge' FROM elevation_tickets \
          WHERE id = $1",
    )
    .bind(ticket)
    .fetch_one(pool)
    .await
    .expect("the ticket's challenge")
}

/// `response` with one bit of its signature flipped.
fn tampered(mut response: serde_json::Value) -> serde_json::Value {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut sig = b64
        .decode(response["response"]["signature"].as_str().unwrap())
        .unwrap();
    sig[4] ^= 0x01;
    response["response"]["signature"] = serde_json::Value::from(b64.encode(sig));
    response
}

/// `epigraph_confirm_elevation` called as `epigraph_app` (the definer is
/// ticket-keyed and takes the caller's word for the assertion): its outcome.
async fn app_confirm_elevation(
    pool: &PgPool,
    ticket: Uuid,
    credential: Vec<u8>,
    backup_eligible: bool,
    evidence: serde_json::Value,
) -> String {
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        let o = sqlx::query_scalar(
            "SELECT outcome FROM public.epigraph_confirm_elevation($1, $2, 0, $3, $4)",
        )
        .bind(ticket)
        .bind(credential)
        .bind(backup_eligible)
        .bind(evidence)
        .fetch_one(&mut *conn)
        .await
        .expect("the confirm definer");
        (conn, o)
    })
    .await
}

/// THE APPLICATION-DSN FORGERY: a ticket of P's confirmed by calling 125's
/// ticket-keyed confirm definer as `epigraph_app` with evidence that is right
/// in every respect a row can show (P's credential, the ticket's own stored
/// challenge, a well-formed response of P's authenticator) except that its
/// signature does not verify. The database cannot tell: CALIBRATION, it
/// confirms the ticket and opens a session. Returns the ticket.
async fn forged_elevation(pool: &PgPool, e: &mut Elevated) -> Uuid {
    let (ticket, options) = started_ticket(pool, e).await;
    let response = tampered(
        e.auth
            .authenticate(soft_authenticator::ORIGIN, options)
            .await,
    );
    let evidence = serde_json::json!({
        "v": 1,
        "challenge": ticket_challenge(pool, ticket).await,
        "response": response,
    });
    let outcome = app_confirm_elevation(pool, ticket, e.credential.clone(), false, evidence).await;
    assert_eq!(outcome, "confirmed", "CALIBRATION: the database accepts it");
    ticket
}

/// Run `verify-confirmations` with the test relying party (`origin`
/// overridable; `None` leaves the relying party unset).
async fn run_verify(pool: &PgPool, args: &[&str], origin: Option<&str>) -> Run {
    let url = fixture::database_url_for(pool).await;
    let mut cmd = Command::new(BIN);
    cmd.arg("verify-confirmations")
        .args(args)
        .env("RUST_LOG", "warn")
        .env_remove("DATABASE_URL")
        .env_remove("MAINTENANCE_DATABASE_URL")
        .env_remove("EPIGRAPH_WEBAUTHN_RP_ID")
        .env_remove("EPIGRAPH_WEBAUTHN_ORIGIN")
        .env(DSN_ENV, url);
    if let Some(origin) = origin {
        cmd.env("EPIGRAPH_WEBAUTHN_RP_ID", soft_authenticator::RP_ID)
            .env("EPIGRAPH_WEBAUTHN_ORIGIN", origin);
    }
    let out = cmd.output().expect("spawn");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn report_of(run: &Run) -> serde_json::Value {
    serde_json::from_str(run.stdout.trim()).unwrap_or_else(|e| panic!("{e}: {}", run.show()))
}

/// `(subject, id, reason)` of every finding.
fn findings_of(report: &serde_json::Value) -> Vec<(String, Uuid, String)> {
    report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["subject"].as_str().unwrap().to_string(),
                f["id"].as_str().unwrap().parse().unwrap(),
                f["reason"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

/// `(agent_id, subject, id, reason)` of every recorded finding.
async fn recorded(pool: &PgPool) -> Vec<(Option<Uuid>, String, String, String)> {
    sqlx::query_as(
        "SELECT agent_id, details->>'subject', details->>'id', details->>'reason' \
           FROM security_events WHERE event_type = 'platform.confirmation_unverified' \
          ORDER BY created_at, id",
    )
    .fetch_all(pool)
    .await
    .expect("the recorded findings")
}

/// Every genuine confirmation verifies: an elevation and an admin act, both
/// through the real ceremonies, are checked (1 and 1), nothing is flagged,
/// nothing recorded, exit 0. A REFUSED assertion (an unknown credential, the
/// API's audited path, whose evidence by design does not verify) granted
/// nothing and is counted, not flagged. CALIBRATIONS that the evidence is really
/// re-verified: under another origin both are flagged
/// `assertion_does_not_verify` (exit 2); with no relying party configured
/// the verb refuses to run (exit 1, nothing recorded), since a run that
/// verified nothing must not exit 0.
#[sqlx::test(migrations = "../../migrations")]
async fn verify_confirmations_passes_every_genuine_confirmation(pool: PgPool) {
    let mut e = elevated_custodian(&pool).await;
    let act = propose_end(&e, e.assignments[0]).await;
    let (_, options) = post(
        e.addr,
        &format!("/elevate/act/{act}/challenge"),
        None,
        &serde_json::json!({}),
    )
    .await;
    let assertion = e
        .auth
        .authenticate(soft_authenticator::ORIGIN, options)
        .await;
    let (status, body) = post(
        e.addr,
        &format!("/elevate/act/{act}/assert"),
        None,
        &assertion,
    )
    .await;
    assert_eq!(status, 200, "the act confirmation: {body}");
    let (burned, _) = started_ticket(&pool, &e).await;
    let unverified = serde_json::json!({
        "v": 1,
        "challenge": ticket_challenge(&pool, burned).await,
        "response": {},
        "verified": false,
        "unverified_reason": "the credential is not one of the ticket person's live passkeys",
    });
    let outcome = app_confirm_elevation(&pool, burned, vec![0xEE; 16], false, unverified).await;
    assert_eq!(
        outcome, "refused",
        "CALIBRATION: an unknown credential is refused"
    );

    let unset = run_verify(&pool, &["--json"], None).await;
    assert_eq!(unset.code, 1, "{}", unset.show());
    assert!(
        unset.stderr.contains("EPIGRAPH_WEBAUTHN_RP_ID"),
        "{}",
        unset.show()
    );

    let ok = run_verify(&pool, &["--json"], Some(soft_authenticator::ORIGIN)).await;
    assert_eq!(ok.code, 0, "{}", ok.show());
    let report = report_of(&ok);
    assert_eq!(
        (
            &report["elevations_checked"],
            &report["acts_checked"],
            &report["refused_seen"]
        ),
        (
            &serde_json::json!(1),
            &serde_json::json!(1),
            &serde_json::json!(1)
        ),
        "{report}"
    );
    assert!(findings_of(&report).is_empty(), "{report}");
    assert!(recorded(&pool).await.is_empty());

    let elsewhere = run_verify(&pool, &["--json"], Some("https://auth.example.com:8443")).await;
    assert_eq!(elsewhere.code, 2, "{}", elsewhere.show());
    let mut got = findings_of(&report_of(&elsewhere));
    got.sort();
    let mut want = vec![
        (
            "admin_act".to_string(),
            act,
            "assertion_does_not_verify".to_string(),
        ),
        (
            "elevation_ticket".to_string(),
            e.ticket,
            "assertion_does_not_verify".to_string(),
        ),
    ];
    want.sort();
    assert_eq!(got, want);
}

/// THE APPLICATION-DSN FORGERY IS FLAGGED (elevation plan EL-13): a ticket
/// confirmed through the definer with evidence that does not verify is
/// reported `assertion_does_not_verify` (exit 2), the genuine elevation
/// beside it is not, and the finding is recorded ONCE, attributed to P: a
/// second run reports it again (exit 2) and records nothing more. `--since`
/// after both leaves nothing to check (exit 0).
///
/// Verified to fail with the re-verification skipped (a verifier that only
/// checks the row's shape: the forgery passes, exit 0).
#[sqlx::test(migrations = "../../migrations")]
async fn an_app_dsn_forged_elevation_is_flagged_and_recorded_once(pool: PgPool) {
    let mut e = elevated_custodian(&pool).await;
    let forged = forged_elevation(&pool, &mut e).await;

    let first = run_verify(&pool, &["--json"], Some(soft_authenticator::ORIGIN)).await;
    assert_eq!(first.code, 2, "{}", first.show());
    let report = report_of(&first);
    assert_eq!(
        report["elevations_checked"],
        serde_json::json!(2),
        "{report}"
    );
    assert_eq!(
        findings_of(&report),
        vec![(
            "elevation_ticket".to_string(),
            forged,
            "assertion_does_not_verify".to_string()
        )]
    );
    assert_eq!(report["recorded"], serde_json::json!(1));
    let rows = recorded(&pool).await;
    assert_eq!(
        rows,
        vec![(
            Some(e.person),
            "elevation_ticket".to_string(),
            forged.to_string(),
            "assertion_does_not_verify".to_string()
        )]
    );

    let again = run_verify(&pool, &[], Some(soft_authenticator::ORIGIN)).await;
    assert_eq!(again.code, 2, "{}", again.show());
    assert!(
        again
            .stdout
            .contains(&format!("UNVERIFIED\televation_ticket\t{forged}")),
        "{}",
        again.show()
    );
    assert!(again.stdout.contains("recorded=0"), "{}", again.show());
    assert_eq!(recorded(&pool).await.len(), 1, "recorded once");

    let later = (chrono::Utc::now() + chrono::Duration::minutes(5)).to_rfc3339();
    let none = run_verify(
        &pool,
        &["--json", "--since", &later],
        Some(soft_authenticator::ORIGIN),
    )
    .await;
    assert_eq!(none.code, 0, "{}", none.show());
    assert_eq!(report_of(&none)["elevations_checked"], serde_json::json!(0));
}

/// A VALID SIGNATURE OVER ANOTHER ACT'S CHALLENGE CONFIRMS NOTHING: act B's
/// started ceremony is copied onto act A through the app-callable
/// `epigraph_set_admin_act_challenge`, P's authenticator signs B's options,
/// and A is confirmed with that evidence by the definer, as `epigraph_app`
/// (CALIBRATION: the database confirms it). The evidence re-verifies and
/// matches A's stored ceremony; only the act binding (A's id, args digest
/// and nonce) refuses it: `challenge_not_bound`, exit 2. B, never
/// confirmed, is not checked; the genuine elevation is not flagged.
///
/// Verified to fail with the act challenge not recomputed.
#[sqlx::test(migrations = "../../migrations")]
async fn an_act_confirmed_with_another_acts_signature_is_flagged(pool: PgPool) {
    let mut e = elevated_custodian(&pool).await;
    let a = propose_end(&e, e.assignments[0]).await;
    let b = propose_end(&e, e.assignments[1]).await;
    let (status, options) = post(
        e.addr,
        &format!("/elevate/act/{b}/challenge"),
        None,
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(status, 200, "{options}");
    let response = e
        .auth
        .authenticate(soft_authenticator::ORIGIN, options)
        .await;
    let (state, challenge): (serde_json::Value, String) = sqlx::query_as(
        "SELECT challenge_state, challenge_state->'ceremony'->'library'->'ast'->>'challenge' \
           FROM pending_admin_acts WHERE id = $1",
    )
    .bind(b)
    .fetch_one(&pool)
    .await
    .expect("B's ceremony");
    let evidence = serde_json::json!({"v": 1, "challenge": challenge, "response": response});
    let cred = e.credential.clone();
    let outcome: String = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        sqlx::query("SELECT public.epigraph_set_admin_act_challenge($1, $2)")
            .bind(a)
            .bind(state)
            .execute(&mut *conn)
            .await
            .expect("B's ceremony onto A");
        let o = sqlx::query_scalar(
            "SELECT outcome FROM public.epigraph_confirm_admin_act($1, $2, 0, false, $3)",
        )
        .bind(a)
        .bind(cred)
        .bind(evidence)
        .fetch_one(&mut *conn)
        .await
        .expect("the confirm definer");
        (conn, o)
    })
    .await;
    assert_eq!(outcome, "confirmed", "CALIBRATION: the database accepts it");

    let run = run_verify(&pool, &["--json"], Some(soft_authenticator::ORIGIN)).await;
    assert_eq!(run.code, 2, "{}", run.show());
    let report = report_of(&run);
    assert_eq!(
        (&report["elevations_checked"], &report["acts_checked"]),
        (&serde_json::json!(1), &serde_json::json!(1)),
        "{report}"
    );
    assert_eq!(
        findings_of(&report),
        vec![(
            "admin_act".to_string(),
            a,
            "challenge_not_bound".to_string()
        )]
    );
}

/// On a REAL maintenance login (not the superuser the binary tests connect
/// as), the verifier reads every row it needs through the policies and its
/// audit row lands: 123's `security_events_platform_privileged` admits a
/// `platform.` row from a privileged session only with `created_at = now()`.
/// A second record of the same finding adds nothing. On a database without
/// migration 130's act table (the rollout verifies elevations before 130),
/// the acts are skipped, not an error.
///
/// Verified to fail with `created_at` bound from the client clock (the
/// policy refuses the row: invisible to the superuser tests above).
#[sqlx::test(migrations = "../../migrations")]
async fn the_verifier_reads_and_records_on_a_maintenance_login(pool: PgPool) {
    use epigraph_cli::operator::confirmations;
    let mut e = elevated_custodian(&pool).await;
    let forged = forged_elevation(&pool, &mut e).await;
    let verifier = || {
        epigraph_passkey::Verifier::new(epigraph_passkey::RelyingParty {
            rp_id: soft_authenticator::RP_ID.into(),
            origin: soft_authenticator::ORIGIN.parse().unwrap(),
        })
        .unwrap()
    };
    let (report, added, again) =
        fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
            let v = verifier();
            let report = confirmations::verify(&mut conn, &v, None)
                .await
                .expect("verify");
            let added = confirmations::record(&mut conn, &report.findings)
                .await
                .expect("record");
            let again = confirmations::record(&mut conn, &report.findings)
                .await
                .expect("record again");
            (conn, (report, added, again))
        })
        .await;
    assert_eq!(report.elevations_checked, 2);
    assert_eq!(
        report
            .findings
            .iter()
            .map(|f| (f.id, f.reason))
            .collect::<Vec<_>>(),
        vec![(forged, "assertion_does_not_verify")]
    );
    assert_eq!((added, again), (1, 0));
    assert_eq!(recorded(&pool).await.len(), 1);

    sqlx::query("ALTER TABLE pending_admin_acts RENAME TO pending_admin_acts_absent")
        .execute(&pool)
        .await
        .expect("a database without 130's table");
    let report = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let v = verifier();
        let r = confirmations::verify(&mut conn, &v, None)
            .await
            .expect("verify without acts");
        (conn, r)
    })
    .await;
    assert_eq!((report.elevations_checked, report.acts_checked), (2, 0));
}

/// A DEVICE-BOUND PASSKEY THAT ASSERTS AS BACKUP-ELIGIBLE: P's passkey was
/// registered device-bound (BE clear); its authenticator now asserts BE
/// without BS, which the library's passkey path accepts, and which the
/// confirm definer refuses only when the caller passes the flag on. An
/// application-DSN caller passes `false`: CALIBRATION, the database confirms
/// it. The evidence re-verifies (the signature is genuine) but asserts the
/// flag: `backup_eligibility_changed`, exit 2.
///
/// Verified to fail with the backup-eligible comparison removed.
#[sqlx::test(migrations = "../../migrations")]
async fn a_device_bound_passkey_confirming_as_backup_eligible_is_flagged(pool: PgPool) {
    let mut e = enrolled_custodian(
        &pool,
        soft_authenticator::SoftAuthenticator::new(Uuid::from_u128(0x5eed))
            .eligible_not_backed_up(),
        soft_authenticator::hardware_bound,
    )
    .await;
    let stored_be: bool = sqlx::query_scalar(
        "SELECT backup_eligible FROM person_authenticators WHERE person_agent_id = $1",
    )
    .bind(e.person)
    .fetch_one(&pool)
    .await
    .expect("P's passkey");
    assert!(!stored_be, "CALIBRATION: registered device-bound");
    let (ticket, options) = started_ticket(&pool, &e).await;
    let response = e
        .auth
        .authenticate(soft_authenticator::ORIGIN, options)
        .await;
    let evidence = serde_json::json!({
        "v": 1,
        "challenge": ticket_challenge(&pool, ticket).await,
        "response": response,
    });
    let outcome = app_confirm_elevation(&pool, ticket, e.credential.clone(), false, evidence).await;
    assert_eq!(outcome, "confirmed", "CALIBRATION: the database accepts it");

    let run = run_verify(&pool, &["--json"], Some(soft_authenticator::ORIGIN)).await;
    assert_eq!(run.code, 2, "{}", run.show());
    assert_eq!(
        findings_of(&report_of(&run)),
        vec![(
            "elevation_ticket".to_string(),
            ticket,
            "backup_eligibility_changed".to_string()
        )]
    );
}

/// A REPLAYED CONFIRMATION: the genuine elevation's stored ceremony and its
/// stored evidence are copied onto a second ticket of P's (through the
/// app-callable `epigraph_set_elevation_ticket_challenge`, then the confirm
/// definer as `epigraph_app`; CALIBRATION, the database confirms it). Every
/// per-row check passes: the signature is genuine, made over the challenge
/// the second ticket now stores. Only the repetition gives it away: the
/// LATER assertion is flagged `challenge_reused`, the original is not.
///
/// Verified to fail with the repetition check removed (exit 0), and with
/// the original flagged instead of the replay.
#[sqlx::test(migrations = "../../migrations")]
async fn a_replayed_confirmation_is_flagged(pool: PgPool) {
    let e = elevated_custodian(&pool).await;
    let (state, evidence): (serde_json::Value, serde_json::Value) = sqlx::query_as(
        "SELECT challenge_state, assertion_evidence FROM elevation_tickets WHERE id = $1",
    )
    .bind(e.ticket)
    .fetch_one(&pool)
    .await
    .expect("the genuine ticket");
    let (replay, _) = started_ticket(&pool, &e).await;
    fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        sqlx::query("SELECT public.epigraph_set_elevation_ticket_challenge($1, $2)")
            .bind(replay)
            .bind(state)
            .execute(&mut *conn)
            .await
            .expect("the genuine ceremony onto the replay");
        (conn, ())
    })
    .await;
    let outcome = app_confirm_elevation(&pool, replay, e.credential.clone(), false, evidence).await;
    assert_eq!(outcome, "confirmed", "CALIBRATION: the database accepts it");

    let run = run_verify(&pool, &["--json"], Some(soft_authenticator::ORIGIN)).await;
    assert_eq!(run.code, 2, "{}", run.show());
    let report = report_of(&run);
    assert_eq!(
        report["elevations_checked"],
        serde_json::json!(2),
        "{report}"
    );
    assert_eq!(
        findings_of(&report),
        vec![(
            "elevation_ticket".to_string(),
            replay,
            "challenge_reused".to_string()
        )]
    );
}

/// A SESSION WITH NO CONFIRMATION: a privileged login writes an elevation
/// session directly beside a live, started ticket of P's that is never
/// confirmed (125's session guard admits it: the ticket is live, the
/// assignment and the passkey are P's). The session liveness test never
/// reads the ticket, so CALIBRATION: the session is live to P's application
/// connection. It carries no evidence at all, so no per-row check sees it;
/// the session check flags it `session_unconfirmed`. The genuine session is
/// not flagged.
///
/// Verified to fail with the session check removed (exit 0).
#[sqlx::test(migrations = "../../migrations")]
async fn a_session_without_a_confirmation_is_flagged(pool: PgPool) {
    let e = elevated_custodian(&pool).await;
    let (ticket, _) = started_ticket(&pool, &e).await;
    let (session, family): (Uuid, Uuid) = sqlx::query_as(
        "INSERT INTO elevation_sessions (person_agent_id, assignment_id, client_id, family_id, \
                                         mode, reason, ticket_id, authenticator_id, expires_at) \
         SELECT t.person_agent_id, \
                public.epigraph_live_elevating_assignment(t.person_agent_id, now()), \
                t.client_id, t.family_id, t.mode, t.reason, t.id, a.id, \
                now() + interval '10 minutes' \
           FROM elevation_tickets t \
           JOIN person_authenticators a ON a.person_agent_id = t.person_agent_id \
          WHERE t.id = $1 \
         RETURNING id, family_id",
    )
    .bind(ticket)
    .fetch_one(&pool)
    .await
    .expect("a session written directly");
    let person = e.person;
    let live: i64 = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', $1, false), \
                    set_config('epigraph.access_recorder', 'on', false)",
        )
        .bind(person.to_string())
        .execute(&mut *conn)
        .await
        .expect("stamp P");
        let n = sqlx::query_scalar("SELECT count(*) FROM public.epigraph_elevation_live($1, $2)")
            .bind(session)
            .bind(family)
            .fetch_one(&mut *conn)
            .await
            .expect("liveness");
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', '', false), \
                    set_config('epigraph.access_recorder', '', false)",
        )
        .execute(&mut *conn)
        .await
        .expect("unstamp");
        (conn, n)
    })
    .await;
    assert_eq!(live, 1, "CALIBRATION: the unconfirmed session is live");

    let run = run_verify(&pool, &["--json"], Some(soft_authenticator::ORIGIN)).await;
    assert_eq!(run.code, 2, "{}", run.show());
    let report = report_of(&run);
    assert_eq!(
        (&report["elevations_checked"], &report["sessions_checked"]),
        (&serde_json::json!(1), &serde_json::json!(2)),
        "{report}"
    );
    assert_eq!(
        findings_of(&report),
        vec![(
            "elevation_session".to_string(),
            session,
            "session_unconfirmed".to_string()
        )]
    );
}
