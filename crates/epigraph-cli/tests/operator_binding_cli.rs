//! `epigraph-operator` operator-binding commands (migration 122), driven through
//! the real binary against a `#[sqlx::test]` database migrated 001 -> head, on
//! the dedicated maintenance DSN variable only.
//!
//! * `link`: a LIVE link for one agent, by id or by the `(model, prompt hash)`
//!   identity a stdio `epigraph-mcp` derives, refusing a non-human operator and
//!   an agent that is an OAuth principal.
//!
//! Each test names the mutation it was verified against in its doc.

mod viewer_fixture;

use sqlx::PgPool;
use std::process::Command;
use uuid::Uuid;
use viewer_fixture as fixture;

const BIN: &str = env!("CARGO_BIN_EXE_epigraph-operator");
const DSN_ENV: &str = "EPIGRAPH_OPERATOR_MAINTENANCE_DSN";

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
        .env_remove("EPIGRAPH_OPERATOR_LINK_ENFORCEMENT")
        .env(DSN_ENV, url)
        .output()
        .expect("spawn epigraph-operator");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// A registered HUMAN OPERATOR (active human client + registry row).
async fn make_human(pool: &PgPool, agent: Uuid) {
    fixture::make_human_operator(pool, agent).await;
}

async fn link_row(pool: &PgPool, agent: Uuid) -> Option<(Uuid, bool)> {
    sqlx::query_as("SELECT operator_id, retired FROM operator_links WHERE agent_id = $1")
        .bind(agent)
        .fetch_optional(pool)
        .await
        .expect("link row")
}

// ─────────────────────────────────────────────────────────────────────────────
// link
// ─────────────────────────────────────────────────────────────────────────────

/// A host links a fleet identity BEFORE its first start: the dry run writes
/// nothing (not even the agent row), `--apply` creates the agent exactly as
/// `epigraph-mcp` would (same public key, `mcp-agent`, LLM provenance) and
/// records a live link, and a re-run is an idempotent success.
///
/// Verified to fail: the dry run committing its transaction -> the "nothing
/// written" assertions fail.
#[sqlx::test(migrations = "../../migrations")]
async fn link_binds_an_llm_identity_before_its_first_start(pool: PgPool) {
    let (human, _) = fixture::seed_agent_with_group(&pool, "human").await;
    make_human(&pool, human).await;
    let model = "binding-cli-model";
    let hash = "ef".repeat(32);
    let key = epigraph_crypto::keypair_from_llm_agent_prehashed(model, &hash).public_key();
    let agent_of_key = || {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, Uuid>("SELECT id FROM agents WHERE public_key = $1")
                .bind(key.to_vec())
                .fetch_optional(&pool)
                .await
                .expect("agent by key")
        }
    };
    let human_s = human.to_string();
    let args = [
        "link",
        "--agent-model",
        model,
        "--agent-system-prompt-hash",
        hash.as_str(),
        "--operator",
        human_s.as_str(),
    ];

    let dry = run_op(&pool, &args).await;
    assert_eq!(dry.code, 0, "{}", dry.show());
    assert!(
        dry.stdout.contains("WOULD BE LINKED-LIVE"),
        "{}",
        dry.show()
    );
    assert!(
        agent_of_key().await.is_none(),
        "a dry run must not create the agent:\n{}",
        dry.show()
    );

    let mut apply_args = args.to_vec();
    apply_args.push("--apply");
    let applied = run_op(&pool, &apply_args).await;
    assert_eq!(applied.code, 0, "{}", applied.show());
    assert!(applied.stdout.contains("LINKED-LIVE"), "{}", applied.show());
    let agent = agent_of_key()
        .await
        .expect("--apply creates the agent under the derived key");
    assert_eq!(link_row(&pool, agent).await, Some((human, false)));
    let (name, llm_model): (Option<String>, Option<String>) =
        sqlx::query_as("SELECT display_name, properties->>'llm_model' FROM agents WHERE id = $1")
            .bind(agent)
            .fetch_one(&pool)
            .await
            .expect("agent row");
    assert_eq!(name.as_deref(), Some("mcp-agent"));
    assert_eq!(llm_model.as_deref(), Some(model));
    let binding: Option<String> = sqlx::query_scalar("SELECT public.epigraph_author_binding($1)")
        .bind(agent)
        .fetch_one(&pool)
        .await
        .expect("binding");
    assert_eq!(binding.as_deref(), Some("live_link"));

    let again = run_op(&pool, &apply_args).await;
    assert_eq!(again.code, 0, "a re-run is idempotent: {}", again.show());
}

/// The operator must be a HUMAN operator; a live link to anything else binds
/// nobody to a human. Nothing is written.
///
/// Verified to fail: the human-operator refusal removed -> the link is recorded
/// and the command exits 0.
#[sqlx::test(migrations = "../../migrations")]
async fn link_refuses_an_operator_that_is_not_human(pool: PgPool) {
    let (not_human, _) = fixture::seed_agent_with_group(&pool, "not-human").await;
    let (agent, _) = fixture::seed_agent_with_group(&pool, "agent").await;
    let r = run_op(
        &pool,
        &[
            "link",
            "--agent",
            &agent.to_string(),
            "--operator",
            &not_human.to_string(),
            "--apply",
        ],
    )
    .await;
    assert_eq!(r.code, 1, "{}", r.show());
    assert!(r.stderr.contains("is not a human operator"), "{}", r.show());
    assert_eq!(link_row(&pool, agent).await, None, "nothing may be linked");
}

/// An agent that is an OAuth principal is refused: any link would cost it its
/// HTTP tokens (operated agents are stdio-only), which is an operator decision.
///
/// Verified to fail: the OAuth-principal refusal removed -> linked, exit 0.
#[sqlx::test(migrations = "../../migrations")]
async fn link_refuses_an_agent_that_is_an_oauth_principal(pool: PgPool) {
    let (human, _) = fixture::seed_agent_with_group(&pool, "human").await;
    make_human(&pool, human).await;
    let (service, _) = fixture::seed_agent_with_group(&pool, "service").await;
    sqlx::query(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    status, agent_id, legal_entity_name, legal_contact_email) \
         VALUES ($1, 'binding cli service', 'service', ARRAY['claims:write'], 'active', $2, \
                 'Example', 'ops@example.invalid')",
    )
    .bind(format!("service-{service}"))
    .bind(service)
    .execute(&pool)
    .await
    .expect("service client");
    let r = run_op(
        &pool,
        &[
            "link",
            "--agent",
            &service.to_string(),
            "--operator",
            &human.to_string(),
            "--apply",
        ],
    )
    .await;
    assert_eq!(r.code, 1, "{}", r.show());
    assert!(r.stderr.contains("OAuth client"), "{}", r.show());
    assert_eq!(
        link_row(&pool, service).await,
        None,
        "nothing may be linked"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// arm-operator-binding
// ─────────────────────────────────────────────────────────────────────────────

async fn armed(pool: &PgPool) -> bool {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM operator_binding_arming)")
        .fetch_one(pool)
        .await
        .expect("armed read")
}

/// A `('public', group)` claim by `agent`, straight into the table.
async fn insert_claim(pool: &PgPool, agent: Uuid, group: Uuid) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5)",
    )
    .bind(id)
    .bind(format!("binding cli probe {id}"))
    .bind(id.as_bytes().repeat(2))
    .bind(agent)
    .bind(group)
    .execute(pool)
    .await?;
    Ok(id)
}

/// Arming is one-way, so the census comes first: a dry run lists the unbound
/// recent writer and arms nothing; `--apply` REFUSES (exit 1, nothing armed)
/// while one exists; `--allow-unbound-writers` arms, after which that writer is
/// refused OPL01; a re-run reports ALREADY-ARMED.
///
/// Verified to fail: the unbound-writer refusal removed from `arm::run` ->
/// the plain `--apply` arms and the test fails.
#[sqlx::test(migrations = "../../migrations")]
async fn arm_refuses_while_an_unbound_agent_wrote_recently(pool: PgPool) {
    let (unbound, group) = fixture::seed_agent_with_group(&pool, "unbound").await;
    insert_claim(&pool, unbound, group)
        .await
        .expect("unarmed: an unbound author still writes");
    let unbound_s = unbound.to_string();

    let dry = run_op(&pool, &["arm-operator-binding"]).await;
    assert_eq!(dry.code, 0, "{}", dry.show());
    assert!(
        dry.stdout
            .contains(&format!("UNBOUND\t{unbound_s}\t1 claim(s)")),
        "{}",
        dry.show()
    );
    assert!(dry.stdout.contains("DRY RUN"), "{}", dry.show());
    assert!(!armed(&pool).await, "a dry run must not arm");

    let refused = run_op(&pool, &["arm-operator-binding", "--apply"]).await;
    assert_eq!(refused.code, 1, "{}", refused.show());
    assert!(refused.stdout.contains("REFUSED"), "{}", refused.show());
    assert!(!armed(&pool).await, "a refused --apply must not arm");

    let forced = run_op(
        &pool,
        &["arm-operator-binding", "--apply", "--allow-unbound-writers"],
    )
    .await;
    assert_eq!(forced.code, 0, "{}", forced.show());
    assert!(forced.stdout.contains("ARMED"), "{}", forced.show());
    assert!(armed(&pool).await);
    let e = insert_claim(&pool, unbound, group)
        .await
        .expect_err("armed: the unbound writer is refused");
    assert_eq!(
        e.as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref(),
        Some("OPL01"),
        "{e}"
    );

    let again = run_op(&pool, &["arm-operator-binding", "--apply"]).await;
    assert_eq!(again.code, 0, "{}", again.show());
    assert!(again.stdout.contains("ALREADY-ARMED"), "{}", again.show());
}

/// With every recent writer bound, `--apply` arms without an override.
#[sqlx::test(migrations = "../../migrations")]
async fn arm_arms_when_every_recent_writer_is_bound(pool: PgPool) {
    let (human, group) = fixture::seed_agent_with_group(&pool, "human").await;
    make_human(&pool, human).await;
    insert_claim(&pool, human, group)
        .await
        .expect("the human writes");
    let r = run_op(&pool, &["arm-operator-binding", "--apply"]).await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert!(
        r.stdout.contains("UNBOUND-RECENT-WRITERS\t0"),
        "{}",
        r.show()
    );
    assert!(armed(&pool).await);
    insert_claim(&pool, human, group)
        .await
        .expect("armed: the human still writes");
}

// ─────────────────────────────────────────────────────────────────────────────
// link-legacy-authors
// ─────────────────────────────────────────────────────────────────────────────

/// Every shape the legacy tie must link or skip, around one human operator.
#[allow(dead_code)]
struct Legacy {
    human: Uuid,
    human_group: Uuid,
    old_author: Uuid,
    recent_author: Uuid,
    evidence_signer: Uuid,
    oauth_principal: Uuid,
    already_linked: Uuid,
    other_human: Uuid,
    excluded: Uuid,
    shared_signer: Uuid,
    writer_in_group: Uuid,
    no_rows: Uuid,
}

async fn legacy_fixture(pool: &PgPool) -> Legacy {
    let (human, human_group) = fixture::seed_agent_with_group(pool, "human").await;
    make_human(pool, human).await;
    let mut authors = Vec::new();
    for label in [
        "old", "recent", "signer", "oauth", "linked", "human2", "excluded", "shared", "writer",
        "none",
    ] {
        authors.push(fixture::seed_agent_with_group(pool, label).await);
    }
    let [old, recent, signer, oauth, linked, human2, excluded, shared, writer, none]: [(Uuid, Uuid);
        10] = authors.try_into().expect("ten");

    // Claims (unarmed, so every author may still write), all but one OLD.
    for (a, g) in [old, recent, oauth, linked, human2, excluded, shared, writer] {
        insert_claim(pool, a, g).await.expect("seed claim");
    }
    sqlx::query("UPDATE claims SET created_at = now() - interval '90 days' WHERE agent_id <> $1")
        .bind(recent.0)
        .execute(pool)
        .await
        .expect("age the claims");
    // An author through `evidence.signer_id` only.
    let c = insert_claim(pool, old.0, old.1).await.expect("claim");
    sqlx::query("UPDATE claims SET created_at = now() - interval '90 days' WHERE id = $1")
        .bind(c)
        .execute(pool)
        .await
        .expect("age");
    let ev = fixture::seed_evidence(pool, c, "testimony").await;
    sqlx::query("UPDATE evidence SET signer_id = $2, signature = $3 WHERE id = $1")
        .bind(ev)
        .bind(signer.0)
        .bind(vec![7u8; 64])
        .execute(pool)
        .await
        .expect("signer");
    // An HTTP service principal.
    sqlx::query(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    status, agent_id, legal_entity_name, legal_contact_email) \
         VALUES ($1, 'legacy service', 'service', ARRAY['claims:write'], 'active', $2, \
                 'Example', 'ops@example.invalid')",
    )
    .bind(format!("service-{}", oauth.0))
    .bind(oauth.0)
    .execute(pool)
    .await
    .expect("service client");
    // Already linked (live): not a candidate at all.
    {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_db::AgentRepository::link_operator(&mut conn, linked.0, human)
            .await
            .expect("live link");
    }
    make_human(pool, human2.0).await;
    // 107's shared-signer fingerprint: lineage to two principals.
    for target in [human, human2.0] {
        sqlx::query(
            "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
             VALUES ($1, 'agent', $2, 'agent', 'OPERATED_BY')",
        )
        .bind(shared.0)
        .bind(target)
        .execute(pool)
        .await
        .expect("lineage edge");
    }
    // A live writer row in the operator's group, with no link.
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'writer')",
    )
    .bind(human_group)
    .bind(writer.0)
    .execute(pool)
    .await
    .expect("writer row");

    Legacy {
        human,
        human_group,
        old_author: old.0,
        recent_author: recent.0,
        evidence_signer: signer.0,
        oauth_principal: oauth.0,
        already_linked: linked.0,
        other_human: human2.0,
        excluded: excluded.0,
        shared_signer: shared.0,
        writer_in_group: writer.0,
        no_rows: none.0,
    }
}

/// The legacy tie links exactly the quiet, non-principal, non-human authors
/// (through any author column) with RETIRED links and no membership, skips and
/// names every other shape, writes nothing on a dry run, audits each applied
/// run once, and is idempotent.
///
/// Verified to fail, each mutation of the definer applied alone:
/// * the `recent_writer` arm removed -> the recent author is linked;
/// * the `oauth_principal` arm removed -> the service principal is linked;
/// * the link inserted with `retired = false` -> the retired assertion fails.
#[sqlx::test(migrations = "../../migrations")]
async fn link_legacy_authors_ties_exactly_the_quiet_legacy_authors(pool: PgPool) {
    let fx = legacy_fixture(&pool).await;
    let excl = std::env::temp_dir().join(format!("legacy-exclude-{}", Uuid::new_v4()));
    std::fs::write(&excl, format!("# not this one\n{}\n", fx.excluded)).expect("exclude file");
    let human_s = fx.human.to_string();
    let excl_s = excl.display().to_string();
    let args = [
        "link-legacy-authors",
        "--operator",
        human_s.as_str(),
        "--exclude-agents-file",
        excl_s.as_str(),
    ];
    let links = || {
        let pool = pool.clone();
        async move {
            sqlx::query_as::<_, (Uuid, bool)>(
                "SELECT agent_id, retired FROM operator_links ORDER BY agent_id",
            )
            .fetch_all(&pool)
            .await
            .expect("links")
        }
    };
    let audits = || {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM security_events \
                  WHERE event_type = 'operator.legacy_authors_linked'",
            )
            .fetch_one(&pool)
            .await
            .expect("audits")
        }
    };
    let before = links().await;

    let dry = run_op(&pool, &args).await;
    assert_eq!(dry.code, 0, "{}", dry.show());
    for (tag, agent) in [
        ("LINKED-RETIRED", fx.old_author),
        ("LINKED-RETIRED", fx.evidence_signer),
        ("SKIPPED:recent_writer", fx.recent_author),
        ("SKIPPED:oauth_principal", fx.oauth_principal),
        ("SKIPPED:human_operator", fx.other_human),
        ("SKIPPED:excluded", fx.excluded),
        ("SKIPPED:shared_signer", fx.shared_signer),
        ("SKIPPED:write_authority", fx.writer_in_group),
    ] {
        assert!(
            dry.stdout.contains(&format!("{tag}\t{agent}")),
            "expected {tag} for {agent}:\n{}",
            dry.show()
        );
    }
    // Not candidates: already linked, authored nothing, the operator itself.
    // (The operator's id is on the header line, so look for a per-agent line.)
    for absent in [fx.already_linked, fx.no_rows, fx.human] {
        assert!(
            !dry.stdout.contains(&format!("\t{absent}")),
            "{absent} is not a candidate:\n{}",
            dry.show()
        );
    }
    assert_eq!(links().await, before, "a dry run must link nothing");
    assert_eq!(
        audits().await,
        0,
        "a dry run's audit row rolls back with it"
    );

    let mut apply = args.to_vec();
    apply.push("--apply");
    let applied = run_op(&pool, &apply).await;
    assert_eq!(applied.code, 0, "{}", applied.show());
    let mut expected = before.clone();
    expected.push((fx.old_author, true));
    expected.push((fx.evidence_signer, true));
    expected.sort();
    assert_eq!(
        links().await,
        expected,
        "exactly the two quiet legacy authors, RETIRED:\n{}",
        applied.show()
    );
    let memberships: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM group_memberships WHERE group_id = $1 AND agent_id = ANY($2)",
    )
    .bind(fx.human_group)
    .bind(vec![fx.old_author, fx.evidence_signer])
    .fetch_one(&pool)
    .await
    .expect("memberships");
    assert_eq!(memberships, 0, "a retired tie grants no membership");
    let details: serde_json::Value = sqlx::query_scalar(
        "SELECT details FROM security_events WHERE event_type = 'operator.legacy_authors_linked'",
    )
    .fetch_one(&pool)
    .await
    .expect("one audit row");
    assert_eq!(details["linked"], 2, "{details}");
    assert_eq!(details["candidates"], 8, "{details}");

    let again = run_op(&pool, &apply).await;
    assert_eq!(again.code, 0, "{}", again.show());
    assert!(
        !again.stdout.contains("LINKED-RETIRED"),
        "a re-run links nothing new:\n{}",
        again.show()
    );
    assert_eq!(links().await, expected);
    assert_eq!(audits().await, 2, "one audit row per applied run");
    let _ = std::fs::remove_file(excl);
}

/// The operator must be a HUMAN operator; nothing is tied otherwise.
#[sqlx::test(migrations = "../../migrations")]
async fn link_legacy_authors_refuses_a_non_human_operator(pool: PgPool) {
    let (not_human, _) = fixture::seed_agent_with_group(&pool, "not-human").await;
    let (author, group) = fixture::seed_agent_with_group(&pool, "author").await;
    insert_claim(&pool, author, group).await.expect("claim");
    let r = run_op(
        &pool,
        &[
            "link-legacy-authors",
            "--operator",
            &not_human.to_string(),
            "--no-quiet-window",
            "--apply",
        ],
    )
    .await;
    assert_eq!(r.code, 1, "{}", r.show());
    assert!(r.stderr.contains("is not a human operator"), "{}", r.show());
    assert_eq!(link_row(&pool, author).await, None);
}

// ─────────────────────────────────────────────────────────────────────────────
// reown-linked
// ─────────────────────────────────────────────────────────────────────────────

async fn owner_of(pool: &PgPool, table: &str, id: Uuid) -> Uuid {
    sqlx::query_scalar(&format!("SELECT owner_group_id FROM {table} WHERE id = $1"))
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("owner")
}

/// `reown-linked` moves exactly the claims a LINKED author's own personal group
/// owns into the operator's group, and their derived rows follow through
/// migration 070's arm (d) trigger (the evidence row below is never written by
/// the command itself). An unlinked author's claim and a linked author's claim
/// in a THIRD group stay put; a dry run moves nothing; a re-run finds nothing.
///
/// Verified to fail: the candidate query's personal-group predicate negated
/// (`g.kind <> 'personal'`) -> the linked author's claim is not moved.
#[sqlx::test(migrations = "../../migrations")]
async fn reown_linked_moves_a_linked_authors_personal_claims_and_their_derived_rows(pool: PgPool) {
    let (human, human_group) = fixture::seed_agent_with_group(&pool, "human").await;
    make_human(&pool, human).await;
    let (linked, linked_group) = fixture::seed_agent_with_group(&pool, "linked").await;
    let (unlinked, unlinked_group) = fixture::seed_agent_with_group(&pool, "unlinked").await;
    let third = fixture::seed_group(&pool).await;

    let mine = insert_claim(&pool, linked, linked_group)
        .await
        .expect("claim");
    let evidence = fixture::seed_evidence(&pool, mine, "testimony").await;
    assert_eq!(owner_of(&pool, "evidence", evidence).await, linked_group);
    let in_third = insert_claim(&pool, linked, third).await.expect("claim");
    let theirs = insert_claim(&pool, unlinked, unlinked_group)
        .await
        .expect("claim");
    {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_db::AgentRepository::link_retired_agent(&mut conn, linked, human)
            .await
            .expect("retired link");
    }
    let dir = std::env::temp_dir().join(format!("reown-linked-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("dir");
    let m1 = dir.join("m1.jsonl").display().to_string();
    let m2 = dir.join("m2.jsonl").display().to_string();
    let m3 = dir.join("m3.jsonl").display().to_string();
    let human_s = human.to_string();

    let dry = run_op(
        &pool,
        &[
            "reown-linked",
            "--operator",
            &human_s,
            "--legacy-owner",
            "operator",
            "--manifest-out",
            &m1,
        ],
    )
    .await;
    assert_eq!(dry.code, 0, "{}", dry.show());
    assert!(dry.stdout.contains("candidates=1"), "{}", dry.show());
    assert_eq!(
        owner_of(&pool, "claims", mine).await,
        linked_group,
        "dry run"
    );

    let applied = run_op(
        &pool,
        &[
            "reown-linked",
            "--operator",
            &human_s,
            "--legacy-owner",
            "operator",
            "--manifest-out",
            &m2,
            "--apply",
        ],
    )
    .await;
    assert_eq!(applied.code, 0, "{}", applied.show());
    assert_eq!(
        owner_of(&pool, "claims", mine).await,
        human_group,
        "{}",
        applied.show()
    );
    assert_eq!(
        owner_of(&pool, "evidence", evidence).await,
        human_group,
        "the derived row follows its claim (070 arm (d))"
    );
    assert_eq!(owner_of(&pool, "claims", in_third).await, third);
    assert_eq!(owner_of(&pool, "claims", theirs).await, unlinked_group);

    let again = run_op(
        &pool,
        &[
            "reown-linked",
            "--operator",
            &human_s,
            "--legacy-owner",
            "operator",
            "--manifest-out",
            &m3,
            "--apply",
        ],
    )
    .await;
    assert_eq!(again.code, 0, "{}", again.show());
    assert!(again.stdout.contains("candidates=0"), "{}", again.show());
    let _ = std::fs::remove_dir_all(dir);
}

/// Two humans (OB5): an agent is tied to ONE human for life. `link` to a second
/// human is refused (107's one-operator rule, surfaced by name), and the first
/// link is left exactly as it was, whether it is live or retired.
///
/// Verified to fail: 107's one-operator refusal in `epigraph_link_operator`
/// (`IF v_other IS NOT NULL`) disabled -> the live agent's `link` to the second
/// human no longer exits 1.
#[sqlx::test(migrations = "../../migrations")]
async fn link_refuses_a_second_human_live_or_retired(pool: PgPool) {
    let (a, _) = fixture::seed_agent_with_group(&pool, "human-a").await;
    let (b, _) = fixture::seed_agent_with_group(&pool, "human-b").await;
    make_human(&pool, a).await;
    make_human(&pool, b).await;
    let (live, _) = fixture::seed_agent_with_group(&pool, "live").await;
    let (retired, _) = fixture::seed_agent_with_group(&pool, "retired").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_db::AgentRepository::link_operator(&mut conn, live, a)
            .await
            .expect("live -> a");
        epigraph_db::AgentRepository::link_retired_agent(&mut conn, retired, a)
            .await
            .expect("retired -> a");
    }
    for agent in [live, retired] {
        let r = run_op(
            &pool,
            &[
                "link",
                "--agent",
                &agent.to_string(),
                "--operator",
                &b.to_string(),
                "--apply",
            ],
        )
        .await;
        assert_eq!(r.code, 1, "{}", r.show());
        assert!(
            r.stderr.contains("already has a link to operator"),
            "{}",
            r.show()
        );
    }
    assert_eq!(link_row(&pool, live).await, Some((a, false)));
    assert_eq!(link_row(&pool, retired).await, Some((a, true)));
}

// ─────────────────────────────────────────────────────────────────────────────
// register-human-operator / revoke-human-operator
// ─────────────────────────────────────────────────────────────────────────────

/// The registry through the real binary: a dry run registers nothing; `--apply`
/// registers the agent of an active human client (audited once), after which a
/// link to it succeeds; an agent without a human client is refused; revoking
/// stops the human binding at once.
///
/// Delta review SEC-D6 / DIS-D7: the client is NAMED (`--client`, required).
/// An application session may insert an ACTIVE `human` client naming the
/// person before the operator registers it; the registration records the
/// client the operator named, not the planted one, and a registration for a
/// different client than the recorded one is refused.
///
/// Verified to fail: `human::register` committing its dry-run transaction ->
/// the "nothing registered" assertion fails; `human::register` binding NULL
/// for the client (the pre-fix "the agent's one active human client") -> the
/// definer refuses the two-client person and the registration fails.
#[sqlx::test(migrations = "../../migrations")]
async fn register_and_revoke_a_human_operator(pool: PgPool) {
    let (person, _) = fixture::seed_agent_with_group(&pool, "person").await;
    let client_row = |label: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, Uuid>(
                "INSERT INTO oauth_clients (client_id, client_name, client_type, \
                                            allowed_scopes, status, agent_id) \
                 VALUES ($1, $2, 'human', ARRAY['claims:write'], 'active', $3) RETURNING id",
            )
            .bind(format!("{label}-{person}"))
            .bind(label)
            .bind(person)
            .fetch_one(&pool)
            .await
            .expect("human client")
        }
    };
    let real_client = client_row("person").await;
    // Planted by an application session (the app role holds INSERT on
    // oauth_clients), before the operator registers the person.
    let planted = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                        status, agent_id) \
             VALUES ($1, 'planted', 'human', ARRAY['claims:write'], 'active', $2) RETURNING id",
        )
        .bind(format!("planted-{person}"))
        .bind(person)
        .fetch_one(&mut *conn)
        .await
        .expect("the app role inserts a human client");
        (conn, id)
    })
    .await;
    let c = real_client.to_string();
    let (service, _) = fixture::seed_agent_with_group(&pool, "not-a-person").await;
    let registered = |agent: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, bool>("SELECT public.epigraph_is_human_operator($1)")
                .bind(agent)
                .fetch_one(&pool)
                .await
                .expect("human read")
        }
    };
    let p = person.to_string();

    let unnamed = run_op(
        &pool,
        &[
            "register-human-operator",
            "--agent",
            &p,
            "--reason",
            "test",
            "--apply",
        ],
    )
    .await;
    assert_ne!(
        unnamed.code,
        0,
        "the client must be named: {}",
        unnamed.show()
    );
    assert!(!registered(person).await);

    let dry = run_op(
        &pool,
        &[
            "register-human-operator",
            "--agent",
            &p,
            "--client",
            &c,
            "--reason",
            "test",
        ],
    )
    .await;
    assert_eq!(dry.code, 0, "{}", dry.show());
    assert!(dry.stdout.contains("WOULD BE REGISTERED"), "{}", dry.show());
    assert!(!registered(person).await, "a dry run must register nothing");

    let applied = run_op(
        &pool,
        &[
            "register-human-operator",
            "--agent",
            &p,
            "--client",
            &c,
            "--reason",
            "test",
            "--apply",
        ],
    )
    .await;
    assert_eq!(applied.code, 0, "{}", applied.show());
    assert!(registered(person).await);
    let recorded: Uuid =
        sqlx::query_scalar("SELECT client_id FROM human_operators WHERE agent_id = $1")
            .bind(person)
            .fetch_one(&pool)
            .await
            .expect("recorded client");
    assert_eq!(
        recorded, real_client,
        "the registration records the client the operator named, not the planted one"
    );
    let other = run_op(
        &pool,
        &[
            "register-human-operator",
            "--agent",
            &p,
            "--client",
            &planted.to_string(),
            "--reason",
            "test",
            "--apply",
        ],
    )
    .await;
    assert_eq!(
        other.code,
        1,
        "a registration for another client is refused: {}",
        other.show()
    );
    let audits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_events WHERE event_type = 'operator.human_registered' \
            AND agent_id = $1",
    )
    .bind(person)
    .fetch_one(&pool)
    .await
    .expect("audit");
    assert_eq!(audits, 1);
    let (agent, _) = fixture::seed_agent_with_group(&pool, "its-agent").await;
    let linked = run_op(
        &pool,
        &[
            "link",
            "--agent",
            &agent.to_string(),
            "--operator",
            &p,
            "--apply",
        ],
    )
    .await;
    assert_eq!(linked.code, 0, "{}", linked.show());

    let refused = run_op(
        &pool,
        &[
            "register-human-operator",
            "--agent",
            &service.to_string(),
            "--client",
            &c,
            "--reason",
            "test",
            "--apply",
        ],
    )
    .await;
    assert_eq!(refused.code, 1, "{}", refused.show());
    assert!(!registered(service).await);

    let revoked = run_op(
        &pool,
        &[
            "revoke-human-operator",
            "--agent",
            &p,
            "--reason",
            "left",
            "--apply",
        ],
    )
    .await;
    assert_eq!(revoked.code, 0, "{}", revoked.show());
    assert!(revoked.stdout.contains("REVOKED"), "{}", revoked.show());
    assert!(
        !registered(person).await,
        "a revoked human is no longer one"
    );
}

/// `reown-linked --legacy-owner platform` moves only a LIVE-linked author's
/// personal-group claims, and reports (never moves) a retired-linked author's.
///
/// Verified to fail: the candidate query's `($2 OR NOT l.retired)` reduced to
/// `TRUE` -> the retired-linked author's claim moves too.
#[sqlx::test(migrations = "../../migrations")]
async fn reown_linked_under_platform_moves_only_live_linked_authors(pool: PgPool) {
    let (human, human_group) = fixture::seed_human_operator(&pool, "human").await;
    let (live, live_group) = fixture::seed_agent_with_group(&pool, "live").await;
    let (retired, retired_group) = fixture::seed_agent_with_group(&pool, "retired").await;
    let c_live = insert_claim(&pool, live, live_group).await.expect("claim");
    let c_retired = insert_claim(&pool, retired, retired_group)
        .await
        .expect("claim");
    {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_db::AgentRepository::link_operator(&mut conn, live, human)
            .await
            .expect("live link");
        epigraph_db::AgentRepository::link_retired_agent(&mut conn, retired, human)
            .await
            .expect("retired link");
    }
    let m = std::env::temp_dir().join(format!("reown-platform-{}.jsonl", Uuid::new_v4()));
    let m_s = m.display().to_string();
    let r = run_op(
        &pool,
        &[
            "reown-linked",
            "--operator",
            &human.to_string(),
            "--legacy-owner",
            "platform",
            "--manifest-out",
            &m_s,
            "--apply",
        ],
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert!(r.stdout.contains("REPORT\t1 claim(s)"), "{}", r.show());
    assert_eq!(owner_of(&pool, "claims", c_live).await, human_group);
    assert_eq!(owner_of(&pool, "claims", c_retired).await, retired_group);
    let _ = std::fs::remove_file(m);
}

/// Review SEC-9: `link` lists every writer/admin row the agent already holds in
/// a group its new operator does not write (another human's group), keeps them
/// by default, and revokes them in the link's own transaction under
/// `--revoke-foreign-writes`. Never a refusal (any app session can enrol an
/// unlinked agent as a writer in its own group, so a refusal would strand it).
///
/// Verified to fail: the `UPDATE group_memberships ... revoked_at` statement in
/// `bind::run` removed -> the row in B's group stays live after `--apply`.
#[sqlx::test(migrations = "../../migrations")]
async fn link_lists_and_on_request_revokes_writer_rows_in_another_humans_group(pool: PgPool) {
    let (a, _) = fixture::seed_agent_with_group(&pool, "human-a").await;
    make_human(&pool, a).await;
    let (b, b_group) = fixture::seed_agent_with_group(&pool, "human-b").await;
    make_human(&pool, b).await;
    let (z, _) = fixture::seed_agent_with_group(&pool, "enrolled-by-b").await;
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'writer')",
    )
    .bind(b_group)
    .bind(z)
    .execute(&pool)
    .await
    .expect("B enrolled Z before any link");
    let live_in_b = || {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS (SELECT 1 FROM group_memberships WHERE group_id = $1 \
                   AND agent_id = $2 AND revoked_at IS NULL)",
            )
            .bind(b_group)
            .bind(z)
            .fetch_one(&pool)
            .await
            .expect("membership")
        }
    };
    let (z_s, a_s, g_s) = (z.to_string(), a.to_string(), b_group.to_string());

    let dry = run_op(&pool, &["link", "--agent", &z_s, "--operator", &a_s]).await;
    assert_eq!(dry.code, 0, "{}", dry.show());
    assert!(
        dry.stdout
            .lines()
            .any(|l| l.starts_with("FOREIGN-WRITE") && l.contains(&g_s) && l.contains("KEPT")),
        "{}",
        dry.show()
    );

    let applied = run_op(
        &pool,
        &[
            "link",
            "--agent",
            &z_s,
            "--operator",
            &a_s,
            "--revoke-foreign-writes",
            "--apply",
        ],
    )
    .await;
    assert_eq!(applied.code, 0, "{}", applied.show());
    assert!(
        applied
            .stdout
            .lines()
            .any(|l| l.starts_with("FOREIGN-WRITE") && l.contains(&g_s) && l.contains("REVOKED")),
        "{}",
        applied.show()
    );
    assert!(!live_in_b().await, "the row in B's group is revoked");
    assert_eq!(link_row(&pool, z).await, Some((a, false)));
}

/// Review C5: an LLM identity whose process created its own agent row on an
/// app DSN (where it could not record its LLM provenance) gets the provenance
/// when the host links it by `--agent-model` / `--agent-system-prompt-hash`,
/// the form the process's refusal now prints.
///
/// Verified to fail: `set_llm_properties` back under `if agent_created` ->
/// the pre-existing row's properties stay `{}`.
#[sqlx::test(migrations = "../../migrations")]
async fn link_records_the_llm_provenance_of_a_row_the_process_created(pool: PgPool) {
    let (human, _) = fixture::seed_agent_with_group(&pool, "human").await;
    make_human(&pool, human).await;
    let model = "provenance-model";
    let hash = "cd".repeat(32);
    let key = epigraph_crypto::keypair_from_llm_agent_prehashed(model, &hash).public_key();
    let agent: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name) VALUES ($1, 'mcp-agent') RETURNING id",
    )
    .bind(key.to_vec())
    .fetch_one(&pool)
    .await
    .expect("the row the process created");
    let human_s = human.to_string();
    let r = run_op(
        &pool,
        &[
            "link",
            "--agent-model",
            model,
            "--agent-system-prompt-hash",
            hash.as_str(),
            "--operator",
            human_s.as_str(),
            "--apply",
        ],
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    let (m, src): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT properties->>'llm_model', properties->>'source' FROM agents WHERE id = $1",
    )
    .bind(agent)
    .fetch_one(&pool)
    .await
    .expect("agent");
    assert_eq!(m.as_deref(), Some(model));
    assert_eq!(src.as_deref(), Some("mcp-llm-agent"));
    assert_eq!(link_row(&pool, agent).await, Some((human, false)));
}
