//! `epigraph-operator custodial-supersede` (migration 123), through the real
//! binary on the maintenance DSN variable, on an ARMED database: the
//! custodian's one edit path for the platform corpus, replacing the hand-run
//! SQL sequence the operator-binding runbook carried.

mod viewer_fixture;

use sqlx::PgPool;
use std::process::Command;
use uuid::Uuid;
use viewer_fixture as fixture;

const BIN: &str = env!("CARGO_BIN_EXE_epigraph-operator");
const DSN_ENV: &str = "EPIGRAPH_OPERATOR_MAINTENANCE_DSN";
const WORLD: Uuid = Uuid::nil();

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
        // No live embedder: the verb's `embedded=` field is deterministic.
        .env_remove("OPENAI_API_KEY")
        .env(DSN_ENV, url)
        .output()
        .expect("spawn epigraph-operator");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

async fn insert_claim(pool: &PgPool, author: Uuid, group: Uuid) -> Uuid {
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
    .bind(group)
    .execute(pool)
    .await
    .expect("claim");
    id
}

async fn edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            visibility, owner_group_id) \
         VALUES ($1, 'claim', $2, 'claim', $3, 'public', $4) RETURNING id",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .bind(WORLD)
    .fetch_one(pool)
    .await
    .expect("edge")
}

async fn current(pool: &PgPool, claim: Uuid) -> bool {
    sqlx::query_scalar("SELECT COALESCE(is_current, true) FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("claim")
}

async fn deferred_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM security_events \
          WHERE event_type = 'cascade.deferred' AND details->>'cause' = 'supersede'",
    )
    .fetch_one(pool)
    .await
    .expect("deferrals")
}

async fn acts(pool: &PgPool) -> Vec<(String, String)> {
    sqlx::query_as(
        "SELECT details->>'assignment_id', details->>'target' FROM security_events \
          WHERE event_type = 'platform.custodial_act' ORDER BY created_at, id",
    )
    .fetch_all(pool)
    .await
    .expect("acts")
}

/// The arguments of one `custodial-supersede`; the revised text names the
/// claim, so two revisions never share a content hash.
fn supersede_args(claim: &str, assignment: &str, actor: &str, apply: bool) -> Vec<String> {
    let mut args: Vec<String> = [
        "custodial-supersede",
        "--claim",
        claim,
        "--content",
        &format!("the custodian's revision of {claim}"),
        "--truth",
        "0.7",
        "--assignment",
        assignment,
        "--actor",
        actor,
        "--reason",
        "custodial revision test",
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    if apply {
        args.push("--apply".to_string());
    }
    args
}

async fn supersede(pool: &PgPool, claim: &str, assignment: &str, actor: &str, apply: bool) -> Run {
    let args = supersede_args(claim, assignment, actor, apply);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run_op(pool, &refs).await
}

/// Armed, on the maintenance DSN: a corpus claim by a RETIRED-linked author
/// and one by an UNLINKED author are each revised once. The successor is
/// world/public under the inherited author, one `supersedes` edge links it,
/// one `platform.custodial_act` names the assignment, and one `supersede`
/// cascade deferral is recorded per revision; once the deferred-cascade
/// replay has run (SPEC section 3.1: the custodial act's edge migration is
/// the supersede cascade's, run from its deferral), a strengthening edge
/// follows the successor while a `contradicts` edge stays on the
/// predecessor. A dry run writes nothing. An assignment of another holder, an ended one and one
/// not yet begun are CUS04 with nothing written; a claim the world group
/// does not own is refused (exit 1) without `--allow-owned` and revised, under
/// its own author and group, with it.
///
/// Verified to fail: the cascade deferral not recorded -> no deferral row,
/// and the replay leaves the strengthening edge on the predecessor; the act
/// committed before its audit record (the supersede committed on its own,
/// then the record attempted) -> the CUS04 run with another holder's
/// assignment leaves the predecessor retired; the assignment check skipped
/// (`record_custodial_act` not called) -> the other holder's assignment
/// revises the claim and no act is recorded; the `--allow-owned` check made
/// unconditional -> the owned claim is never revised.
#[sqlx::test(migrations = "../../migrations")]
async fn custodial_supersede_replaces_the_hand_sql(pool: PgPool) {
    let (a, a_group) = fixture::seed_human_operator(&pool, "custodian-a").await;
    let (b, _) = fixture::seed_human_operator(&pool, "custodian-b").await;
    let (legacy, _) = fixture::seed_agent_with_group(&pool, "legacy").await;
    let (unlinked, _) = fixture::seed_agent_with_group(&pool, "unlinked").await;
    let c_ret = insert_claim(&pool, legacy, WORLD).await;
    let c_unl = insert_claim(&pool, unlinked, WORLD).await;
    let c_own = insert_claim(&pool, a, a_group).await;
    let supporter = insert_claim(&pool, unlinked, WORLD).await;
    let critic = insert_claim(&pool, unlinked, WORLD).await;
    let c_more = insert_claim(&pool, unlinked, WORLD).await;
    let c_more2 = insert_claim(&pool, unlinked, WORLD).await;
    let (c_more_s, c_more2_s) = (c_more.to_string(), c_more2.to_string());
    let supports = edge(&pool, supporter, c_ret, "supports").await;
    let contradicts = edge(&pool, critic, c_ret, "contradicts").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_db::AgentRepository::link_retired_agent(&mut conn, legacy, a)
            .await
            .expect("the legacy author's retired tie to A");
    }
    let ia = fixture::make_custodian(&pool, a).await;
    let ib = fixture::make_custodian(&pool, b).await;
    fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        sqlx::query("SELECT * FROM public.epigraph_arm_operator_binding()")
            .execute(&mut *conn)
            .await
            .expect("arm");
        (conn, ())
    })
    .await;
    let (a_s, ia_s, ib_s) = (a.to_string(), ia.to_string(), ib.to_string());
    let (c_ret_s, c_unl_s, c_own_s) = (c_ret.to_string(), c_unl.to_string(), c_own.to_string());

    // Dry run: nothing.
    let dry = supersede(&pool, &c_ret_s, &ia_s, &a_s, false).await;
    assert_eq!(dry.code, 0, "{}", dry.show());
    assert!(dry.stdout.contains("WOULD BE SUPERSEDED"), "{}", dry.show());
    assert!(current(&pool, c_ret).await, "a dry run retires nothing");
    assert!(acts(&pool).await.is_empty(), "a dry run records nothing");
    assert_eq!(deferred_count(&pool).await, 0, "a dry run defers nothing");

    // Refused: another holder's assignment.
    let other = supersede(&pool, &c_ret_s, &ib_s, &a_s, true).await;
    assert_eq!(other.code, 1, "{}", other.show());
    assert!(other.stderr.contains("CUS04"), "{}", other.show());
    assert!(current(&pool, c_ret).await, "a refused run retires nothing");
    assert_eq!(
        deferred_count(&pool).await,
        0,
        "a refused run defers nothing"
    );

    // Applied, on the retired-linked author's corpus claim.
    let applied = supersede(&pool, &c_ret_s, &ia_s, &a_s, true).await;
    assert_eq!(applied.code, 0, "{}", applied.show());
    // Backlog 5fd3e2b4: the verb reports whether it embedded the successor.
    // With no OPENAI_API_KEY (the helper removes it) there is no embedder, so
    // `embedded=false` and the backfill note is printed; the dry run above
    // never embeds.
    assert!(
        applied.stdout.contains("\tembedded=false\n")
            && applied
                .stdout
                .contains("NOTE: the successor was not embedded"),
        "{}",
        applied.show()
    );
    assert!(dry.stdout.contains("\tembedded=false\n"), "{}", dry.show());
    let successor: (Uuid, Uuid, Uuid, String, bool) = sqlx::query_as(
        "SELECT id, agent_id, owner_group_id, visibility, COALESCE(is_current, true) \
           FROM claims WHERE supersedes = $1",
    )
    .bind(c_ret)
    .fetch_one(&pool)
    .await
    .expect("one successor");
    let new = successor.0;
    assert_eq!(
        (successor.1, successor.2, successor.3.as_str(), successor.4),
        (legacy, WORLD, "public", true),
        "world/public, the inherited author, current"
    );
    assert!(!current(&pool, c_ret).await, "the predecessor is retired");
    // Backlog 73085534 (ruling R-23): the custodian who restated the claim is
    // recorded as the successor's AUTHORED edge, in the act's transaction.
    let authored: Vec<(Uuid, serde_json::Value)> = sqlx::query_as(
        "SELECT source_id, COALESCE(properties, '{}'::jsonb) FROM edges \
          WHERE relationship = 'AUTHORED' AND source_type = 'agent' AND target_id = $1",
    )
    .bind(new)
    .fetch_all(&pool)
    .await
    .expect("AUTHORED edges");
    assert_eq!(
        authored,
        vec![(
            a,
            serde_json::json!({"tool": "custodial-supersede", "was_created": true, "supersede_act": "custodial-supersede"})
        )],
        "the acting custodian, not the inherited author, authored the restatement"
    );
    let supersedes_edges: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE relationship = 'supersedes' \
            AND source_id = $1 AND target_id = $2",
    )
    .bind(new)
    .bind(c_ret)
    .fetch_one(&pool)
    .await
    .expect("supersedes edge");
    assert_eq!(supersedes_edges, 1);
    assert_eq!(
        deferred_count(&pool).await,
        1,
        "the revision's cascade deferral"
    );
    // The edge migration is the cascade's: it runs from the deferral.
    let fixture_dsn = fixture::database_url_for(&pool).await;
    let r = replay(&fixture_dsn, &fixture_dsn);
    assert_eq!(r.code, 0, "{}", r.show());
    let targets: (Uuid, Uuid) = sqlx::query_as(
        "SELECT (SELECT target_id FROM edges WHERE id = $1), \
                (SELECT target_id FROM edges WHERE id = $2)",
    )
    .bind(supports)
    .bind(contradicts)
    .fetch_one(&pool)
    .await
    .expect("edge targets");
    assert_eq!(
        targets,
        (new, c_ret),
        "the strengthening edge follows; contradicts stays"
    );
    assert_eq!(
        acts(&pool).await,
        vec![(ia_s.clone(), c_ret_s.clone())],
        "one custodial act, naming the assignment"
    );

    // Applied, on the UNLINKED author's corpus claim.
    let unl = supersede(&pool, &c_unl_s, &ia_s, &a_s, true).await;
    assert_eq!(unl.code, 0, "{}", unl.show());
    assert!(!current(&pool, c_unl).await);
    let unl_successor: (Uuid, Uuid, String, bool) = sqlx::query_as(
        "SELECT agent_id, owner_group_id, visibility, COALESCE(is_current, true) \
           FROM claims WHERE supersedes = $1",
    )
    .bind(c_unl)
    .fetch_one(&pool)
    .await
    .expect("one successor of the unlinked author's claim");
    assert_eq!(
        (
            unl_successor.0,
            unl_successor.1,
            unl_successor.2.as_str(),
            unl_successor.3
        ),
        (unlinked, WORLD, "public", true),
        "the unlinked author's successor: its author, world/public, current"
    );

    // Not platform corpus: refused without --allow-owned, revised with it
    // (operator decision OQ-8's override; review TST-MTC-12).
    let owned = supersede(&pool, &c_own_s, &ia_s, &a_s, true).await;
    assert_eq!(owned.code, 1, "{}", owned.show());
    assert!(current(&pool, c_own).await);
    let mut args = supersede_args(&c_own_s, &ia_s, &a_s, true);
    args.push("--allow-owned".to_string());
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let allowed = run_op(&pool, &refs).await;
    assert_eq!(allowed.code, 0, "{}", allowed.show());
    assert!(!current(&pool, c_own).await, "the owned claim is retired");
    let own_successor: (Uuid, Uuid, bool) = sqlx::query_as(
        "SELECT agent_id, owner_group_id, COALESCE(is_current, true) \
           FROM claims WHERE supersedes = $1",
    )
    .bind(c_own)
    .fetch_one(&pool)
    .await
    .expect("one successor of the owned claim");
    assert_eq!(
        own_successor,
        (a, a_group, true),
        "the owned claim's successor keeps its author and its group"
    );

    // An ENDED assignment, and one not yet begun: CUS04, nothing written.
    let ended: bool =
        sqlx::query_scalar("SELECT public.epigraph_end_role_assignment($1, 'test end')")
            .bind(ib)
            .fetch_one(&pool)
            .await
            .expect("end B");
    assert!(ended);
    let b_s = b.to_string();
    let r = supersede(&pool, &c_more_s, &ib_s, &b_s, true).await;
    assert_eq!(r.code, 1, "an ended assignment: {}", r.show());
    assert!(r.stderr.contains("CUS04"), "{}", r.show());
    let future: Uuid = sqlx::query_scalar(
        "SELECT public.epigraph_grant_role('role:platform-custodian', $1, \
                now() + interval '1 day', NULL, $2, 'from tomorrow')",
    )
    .bind(b)
    .bind(a)
    .fetch_one(&pool)
    .await
    .expect("a future assignment for B");
    let future_s = future.to_string();
    let r = supersede(&pool, &c_more2_s, &future_s, &b_s, true).await;
    assert_eq!(r.code, 1, "an assignment not yet begun: {}", r.show());
    assert!(current(&pool, c_more).await && current(&pool, c_more2).await);
    assert_eq!(
        acts(&pool).await.len(),
        3,
        "only the three applied revisions (two corpus, one --allow-owned)"
    );
    assert_eq!(
        deferred_count(&pool).await,
        3,
        "one cascade deferral per applied revision, none for a refused one"
    );
    // OQ-8 (a): the override is RECORDED on the act, not only admitted.
    let overrides: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT details->>'target', details->'details'->>'allow_owned' FROM security_events \
          WHERE event_type = 'platform.custodial_act' ORDER BY created_at, id",
    )
    .fetch_all(&pool)
    .await
    .expect("acts");
    assert_eq!(
        overrides,
        vec![
            (c_ret_s.clone(), Some("false".to_string())),
            (c_unl_s.clone(), Some("false".to_string())),
            (c_own_s.clone(), Some("true".to_string())),
        ],
        "each act records whether --allow-owned admitted it"
    );
}

// ── K8: the custodial supersede runs the belief cascade (SPEC §3.1, §11 K8) ──

const REPLAY: &str = env!("CARGO_BIN_EXE_replay_deferred_cascades");

/// A per-test LOGIN role, `NOSUPERUSER NOBYPASSRLS`, member of `parent`, and
/// its DSN. Roles are cluster-global: the name is unique and the caller drops
/// it. The superuser fixture pool only seeds rows and reads results.
async fn create_login(pool: &PgPool, parent: &str) -> (String, String) {
    let role = format!("k8_{}_{}", parent, Uuid::new_v4().simple());
    let password = Uuid::new_v4().simple().to_string();
    sqlx::query(&format!(
        "CREATE ROLE {role} LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '{password}' IN ROLE {parent}"
    ))
    .execute(pool)
    .await
    .expect("create the login");
    let base = fixture::database_url_for(pool).await;
    let scheme_end = base.find("://").expect("a scheme") + 3;
    let host_path = &base[base.find('@').expect("credentials in the DSN") + 1..];
    let url = format!("{}{role}:{password}@{host_path}", &base[..scheme_end]);
    (role, url)
}

async fn drop_login(pool: &PgPool, role: &str) {
    let _ = sqlx::query(&format!("DROP ROLE IF EXISTS {role}"))
        .execute(pool)
        .await;
}

/// `epigraph-operator` on an explicit maintenance DSN (not the fixture's).
fn run_op_on(dsn: &str, args: &[&str]) -> Run {
    let out = Command::new(BIN)
        .args(args)
        .env("RUST_LOG", "warn")
        .env_remove("DATABASE_URL")
        .env_remove("MAINTENANCE_DATABASE_URL")
        .env_remove("EPIGRAPH_OPERATOR_LINK_ENFORCEMENT")
        .env_remove("OPENAI_API_KEY")
        .env(DSN_ENV, dsn)
        .output()
        .expect("spawn epigraph-operator");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// `replay_deferred_cascades`, the deferred-cascade replay the timer runs, on
/// the application and maintenance DSNs.
fn replay(app_dsn: &str, maint_dsn: &str) -> Run {
    let out = Command::new(REPLAY)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("DATABASE_URL", app_dsn)
        .env("MAINTENANCE_DATABASE_URL", maint_dsn)
        .env("RUST_LOG", "warn")
        .current_dir(std::env::temp_dir())
        .output()
        .expect("spawn replay_deferred_cascades");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// A world-owned corpus claim carrying a cached interval, so an edge out of it
/// wires a real edge-keyed BBA on its target.
async fn insert_claim_with_interval(pool: &PgPool, author: Uuid, bel: f64, pl: f64) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id, belief, plausibility) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5, $6, $7)",
    )
    .bind(id)
    .bind(format!("corpus claim with an interval {id}"))
    .bind(id.as_bytes().repeat(2))
    .bind(author)
    .bind(WORLD)
    .bind(bel)
    .bind(pl)
    .execute(pool)
    .await
    .expect("claim with an interval");
    id
}

/// Live BBAs on `claim` keyed on `edge` (edge-keyed: the edge's slot,
/// migration 267).
async fn edge_bbas(pool: &PgPool, claim: Uuid, edge: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM mass_functions WHERE claim_id = $1 AND slot_kind = 'edge' AND slot_id = $2 \
           AND retracted_at IS NULL",
    )
    .bind(claim)
    .bind(edge)
    .fetch_one(pool)
    .await
    .expect("edge-keyed BBAs")
}

/// Every `cascade.deferred` row, as `(id, agent_id, details)`.
async fn deferrals(pool: &PgPool) -> Vec<(Uuid, Option<Uuid>, serde_json::Value)> {
    sqlx::query_as(
        "SELECT id, agent_id, details FROM security_events \
          WHERE event_type = 'cascade.deferred' ORDER BY created_at, id",
    )
    .fetch_all(pool)
    .await
    .expect("deferrals")
}

/// SPEC §11 K8 (backlog D22, I18) and the phase-0 addendum: a custodial
/// supersede of a WORLD-owned corpus claim (the population the custodial path
/// exists for: custodial-only by I16), run by the real binary as a REAL
/// maintenance login (`NOSUPERUSER NOBYPASSRLS`, member of
/// `epigraph_maintenance`), records a `supersede` deferral through 120's
/// `epigraph_record_cascade_deferral` naming the custodian, in the act's own
/// transaction; the deferred-cascade replay then runs the whole supersede
/// cascade from it.
///
/// * The deferral passes 120's PRIVILEGED arm (`v_priv` = `epigraph_bypass()`,
///   session_user a member of `epigraph_maintenance`): the maintenance session
///   has no stamped principal, so the non-privileged arm would refuse CX02;
///   the control below shows exactly that refusal for the same act on an
///   application login. No CX02/CX03 on the custodial run.
/// * The deferral names the custodian (`agent_id`), the predecessor and the
///   successor, and the act record links it (`cascade_deferral_event_id`).
/// * A dry run and a CUS04-refused run leave no deferral (act and deferral
///   commit together or not at all).
/// * After the replay: one `cascade.admin_applied` row replaying that
///   deferral under the custodian's name, whose ids row lists the incoming
///   strengthening edge as retargeted and the outgoing one as resourced (the
///   migrated set the supersede cascade's factor regeneration keys on); the
///   edges have moved (`contradicts` stays); K3 re-minted both moved edges'
///   BP factors on the successor (the incoming edge is a `corroborates`, an
///   `evidential_support` factor, the outgoing a `supports`, a
///   `directional_support` one): a factor row per edge over the new pair, and
///   the applied row counts `factors_minted` = 2 (backlog d4810e69); and the
///   belief cascade ran: the
///   target's BBA frozen from the RETIRED claim's interval, keyed on the
///   outgoing edge, is invalidated, and the target's cache, which no row backs
///   any more, is cleared.
///
/// Verified to fail on the base: no deferral row (the custodial path recorded
/// none and ran no belief cascade; its inline edge migration left the replay
/// nothing to move). Verified to fail with K3 skipped in the replay
/// (`apply_after_supersede` minting no factors): no factor row on the
/// successor and `factors_minted` 0.
#[sqlx::test(migrations = "../../migrations")]
async fn custodial_supersede_of_world_corpus_defers_the_whole_cascade_to_the_replay(pool: PgPool) {
    let (a, _) = fixture::seed_human_operator(&pool, "k8-custodian-a").await;
    let (b, _) = fixture::seed_human_operator(&pool, "k8-custodian-b").await;
    let (legacy, _) = fixture::seed_agent_with_group(&pool, "k8-legacy").await;
    let old = insert_claim_with_interval(&pool, legacy, 0.8, 0.9).await;
    let target = insert_claim(&pool, legacy, WORLD).await;
    let supporter = insert_claim(&pool, legacy, WORLD).await;
    let critic = insert_claim(&pool, legacy, WORLD).await;
    let incoming = edge(&pool, supporter, old, "corroborates").await;
    let outgoing = edge(&pool, old, target, "supports").await;
    let contradicts = edge(&pool, critic, old, "contradicts").await;
    assert_eq!(
        (
            factors_on(&pool, incoming, supporter, old).await,
            factors_on(&pool, outgoing, old, target).await,
        ),
        (1, 1),
        "precondition: each strengthening edge carries its factor"
    );

    // The outgoing edge's BBA on the target, wired from the predecessor's
    // interval by the engine's own edge-factor path.
    {
        let (_scoped, viewer) = fixture::bypass(&pool).await;
        let mut conn = pool.acquire().await.expect("acquire");
        let wired = epigraph_engine::edge_factor::auto_wire_ds_for_edge(
            &mut conn, &viewer, outgoing, legacy, old, target, "supports",
        )
        .await
        .expect("wire the outgoing edge");
        assert!(
            matches!(
                wired,
                epigraph_engine::edge_factor::EdgeFactorOutcome::Wired
            ),
            "precondition: the outgoing edge carries a BBA ({wired:?})"
        );
    }
    assert_eq!(edge_bbas(&pool, target, outgoing).await, 1, "precondition");
    let target_belief: Option<f64> = sqlx::query_scalar("SELECT belief FROM claims WHERE id = $1")
        .bind(target)
        .fetch_one(&pool)
        .await
        .expect("target cache");
    assert!(
        target_belief.is_some(),
        "precondition: the target's cache is backed by that BBA"
    );

    let ia = fixture::make_custodian(&pool, a).await;
    let ib = fixture::make_custodian(&pool, b).await;
    fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        sqlx::query("SELECT * FROM public.epigraph_arm_operator_binding()")
            .execute(&mut *conn)
            .await
            .expect("arm");
        (conn, ())
    })
    .await;

    let (maint_role, maint_dsn) = create_login(&pool, "epigraph_maintenance").await;
    let (app_role, app_dsn) = create_login(&pool, "epigraph_app").await;
    let attrs: (bool, bool) =
        sqlx::query_as("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = $1")
            .bind(&maint_role)
            .fetch_one(&pool)
            .await
            .expect("the login's attributes");
    assert_eq!(
        attrs,
        (false, false),
        "the custodial run must exercise epigraph_bypass(), not a superuser short-circuit"
    );

    let (a_s, ia_s, ib_s, old_s) = (
        a.to_string(),
        ia.to_string(),
        ib.to_string(),
        old.to_string(),
    );
    let run = |assignment: &str, apply: bool| {
        let args = supersede_args(&old_s, assignment, &a_s, apply);
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        run_op_on(&maint_dsn, &refs)
    };

    // A dry run and a refused run leave no deferral.
    let dry = run(&ia_s, false);
    assert_eq!(dry.code, 0, "{}", dry.show());
    let refused = run(&ib_s, true);
    assert_eq!(refused.code, 1, "{}", refused.show());
    assert!(refused.stderr.contains("CUS04"), "{}", refused.show());
    assert!(
        deferrals(&pool).await.is_empty(),
        "a rolled-back act leaves no deferral"
    );

    // The custodial supersede: committed, with its deferral.
    let applied = run(&ia_s, true);
    assert_eq!(applied.code, 0, "{}", applied.show());
    assert!(
        !applied.stderr.contains("CX02") && !applied.stderr.contains("CX03"),
        "{}",
        applied.show()
    );
    let new: Uuid = sqlx::query_scalar("SELECT id FROM claims WHERE supersedes = $1")
        .bind(old)
        .fetch_one(&pool)
        .await
        .expect("one successor");
    let rows = deferrals(&pool).await;
    assert_eq!(rows.len(), 1, "one deferral for the one act: {rows:?}");
    let (deferral_id, deferral_agent, d) = &rows[0];
    assert_eq!(*deferral_agent, Some(a), "the deferral names the custodian");
    assert_eq!(d["cause"], "supersede", "{d}");
    assert_eq!(d["recorded_by"], "epigraph_record_cascade_deferral", "{d}");
    assert_eq!(
        d["session_user"], maint_role,
        "recorded on the maintenance login's own session: {d}"
    );
    assert_eq!(d["trigger"]["agent_id"], a.to_string(), "{d}");
    assert_eq!(d["trigger"]["subject_id"], old.to_string(), "{d}");
    assert_eq!(d["trigger"]["object_id"], new.to_string(), "{d}");
    let act_link: Option<String> = sqlx::query_scalar(
        "SELECT details->'details'->>'cascade_deferral_event_id' FROM security_events \
          WHERE event_type = 'platform.custodial_act' AND details->>'target' = $1",
    )
    .bind(&old_s)
    .fetch_one(&pool)
    .await
    .expect("the custodial act");
    assert_eq!(
        act_link,
        Some(deferral_id.to_string()),
        "the custodial act record names the cascade it owes"
    );

    // Control (120's non-privileged arm): the same act's deferral asked for on
    // an APPLICATION login, which carries no stamped principal, is CX02. So it
    // is the privileged arm that admitted the custodial run's.
    {
        let mut app = <sqlx::PgConnection as sqlx::Connection>::connect(&app_dsn)
            .await
            .expect("connect as the application login");
        let err = sqlx::query_scalar::<_, Uuid>(
            "SELECT public.epigraph_record_cascade_deferral('supersede', $1, $2, $3, \
                    ARRAY[]::uuid[], NULL, 'k8 control')",
        )
        .bind(a)
        .bind(old)
        .bind(new)
        .fetch_one(&mut app)
        .await
        .expect_err("an unstamped application session cannot record it");
        assert!(err.to_string().contains("CX02"), "{err}");
    }

    // The replay runs the cascade the deferral names.
    let r = replay(&app_dsn, &maint_dsn);
    assert_eq!(r.code, 0, "{}", r.show());
    let report: serde_json::Value = serde_json::from_str(r.stdout.trim()).expect("replay JSON");
    assert_eq!(report["applied"], 1, "{report}");
    let applied_rows: Vec<(Uuid, Option<Uuid>, serde_json::Value)> = sqlx::query_as(
        "SELECT id, agent_id, details FROM security_events \
          WHERE event_type = 'cascade.admin_applied' AND details->>'cause' = 'supersede' \
            AND details->'trigger'->>'subject_id' = $1",
    )
    .bind(&old_s)
    .fetch_all(&pool)
    .await
    .expect("applied rows");
    assert_eq!(applied_rows.len(), 1, "{applied_rows:?}");
    let (applied_id, applied_agent, ad) = &applied_rows[0];
    assert_eq!(
        *applied_agent,
        Some(a),
        "the cascade is the custodian's: {ad}"
    );
    assert_eq!(
        ad["replay_of"]["deferred_event_id"],
        deferral_id.to_string(),
        "it replays the custodial run's deferral: {ad}"
    );
    let touched: serde_json::Value = sqlx::query_scalar(
        "SELECT details->'touched' FROM security_events \
          WHERE event_type = 'cascade.admin_applied_ids' \
            AND details->>'applied_event_id' = $1",
    )
    .bind(applied_id.to_string())
    .fetch_one(&pool)
    .await
    .expect("the applied ids row");
    assert_eq!(
        touched["edges_retargeted"],
        serde_json::json!([incoming]),
        "the cascade migrated the incoming strengthening edge: {touched}"
    );
    assert_eq!(
        touched["edges_resourced"],
        serde_json::json!([outgoing]),
        "the cascade migrated the outgoing strengthening edge: {touched}"
    );
    // K3 (backlog d4810e69): the retirement deleted the predecessor's
    // factors and the migration's re-points are UPDATEs the INSERT-only
    // factor trigger never sees, so these rows exist only if the replay's
    // regeneration minted them.
    assert_eq!(
        ad["touched"]["factors_minted"],
        serde_json::json!(2),
        "the replay minted the two moved edges' factors: {ad}"
    );
    assert_eq!(
        touched["factors_minted"].as_array().map(Vec::len),
        Some(2),
        "the ids row lists the two minted slots: {touched}"
    );
    assert_eq!(
        (
            factors_on(&pool, incoming, supporter, new).await,
            factors_on(&pool, outgoing, new, target).await,
            factors_on(&pool, incoming, supporter, old).await,
            factors_on(&pool, outgoing, old, target).await,
        ),
        (1, 1, 0, 0),
        "each moved edge's factor is over the successor, none over the retired claim"
    );
    let ends: (Uuid, Uuid, Uuid) = sqlx::query_as(
        "SELECT (SELECT target_id FROM edges WHERE id = $1), \
                (SELECT source_id FROM edges WHERE id = $2), \
                (SELECT target_id FROM edges WHERE id = $3)",
    )
    .bind(incoming)
    .bind(outgoing)
    .bind(contradicts)
    .fetch_one(&pool)
    .await
    .expect("edge ends");
    assert_eq!(
        ends,
        (new, new, old),
        "the strengthening edges follow the successor; contradicts stays"
    );
    assert_eq!(
        edge_bbas(&pool, target, outgoing).await,
        0,
        "the BBA frozen from the retired claim's interval is invalidated"
    );
    let target_belief: Option<f64> = sqlx::query_scalar("SELECT belief FROM claims WHERE id = $1")
        .bind(target)
        .fetch_one(&pool)
        .await
        .expect("target cache");
    assert_eq!(
        target_belief, None,
        "the target's cache, backed by nothing now, is re-derived (cleared)"
    );
    let pending: i64 = {
        let r = Command::new(REPLAY)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("DATABASE_URL", &app_dsn)
            .env("MAINTENANCE_DATABASE_URL", &maint_dsn)
            .env("RUST_LOG", "warn")
            .arg("--report-only")
            .current_dir(std::env::temp_dir())
            .output()
            .expect("spawn the report");
        assert_eq!(
            r.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&r.stderr)
        );
        let v: serde_json::Value =
            serde_json::from_str(String::from_utf8_lossy(&r.stdout).trim()).expect("JSON");
        v["pending"].as_i64().expect("pending count")
    };
    assert_eq!(pending, 0, "the custodial cascade is no longer pending");

    drop_login(&pool, &maint_role).await;
    drop_login(&pool, &app_role).await;
}

/// BP factors keyed on `edge` over exactly the pair `(a, b)`.
async fn factors_on(pool: &PgPool, edge: Uuid, a: Uuid, b: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM factors \
          WHERE properties->>'source_edge_id' = $1::text \
            AND variable_ids @> ARRAY[$2, $3]::uuid[] AND cardinality(variable_ids) = 2",
    )
    .bind(edge)
    .bind(a)
    .bind(b)
    .fetch_one(pool)
    .await
    .expect("count factors")
}

/// The `--report-only` pending count of the deferred-cascade replay.
fn pending_replays(dsn: &str) -> i64 {
    let r = Command::new(REPLAY)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("DATABASE_URL", dsn)
        .env("MAINTENANCE_DATABASE_URL", dsn)
        .env("RUST_LOG", "warn")
        .arg("--report-only")
        .current_dir(std::env::temp_dir())
        .output()
        .expect("spawn the report");
    assert_eq!(
        r.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&r.stderr)
    );
    let v: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&r.stdout).trim()).expect("JSON");
    v["pending"].as_i64().expect("pending count")
}

/// Backlog 6a670eab: a custodial supersede of a GROUP-owned claim
/// (`--allow-owned`) leaves a group-owned successor that a group writer can
/// supersede again before the custodial deferral replays. The replay then
/// moves the predecessor's edges onto the CURRENT head of the successor's
/// supersedes chain, not onto the successor it recorded (now retired, where
/// traversal and belief from the head would never reach them): the
/// strengthening edges land on the head with their BP factors on the head,
/// `contradicts` stays on the predecessor, the deferral still names the
/// recorded successor, and the replay's audit names the head (the applied
/// row counts the one later replacement it followed; its ids row names it).
///
/// The intermediate supersede (successor -> head) runs with its own edge
/// migration inline (`supersede_conn`), as a request path's applied cascade
/// does, so only the custodial deferral is pending when the replay runs. The
/// replay runs on real maintenance and application logins.
///
/// The belief cascade keys on the head too: the target's BBA frozen from the
/// predecessor's interval, keyed on the outgoing edge (which now leaves the
/// head), is invalidated by the replay.
///
/// Verified to fail on the base: the replay migrated onto the recorded
/// successor (`migrate_superseded_edges_conn(old, new)`), so the edges ended on
/// the retired successor, no factor was minted (the successor is not current)
/// and no audit row named the head. Verified to fail with the belief cascade
/// keyed on the recorded successor (`cascade_after_supersede(.., new_id)` in
/// `apply_after_supersede`): the frozen BBA stays live.
#[sqlx::test(migrations = "../../migrations")]
async fn a_replayed_custodial_cascade_lands_on_the_successors_current_head(pool: PgPool) {
    let (a, a_group) = fixture::seed_human_operator(&pool, "head-custodian-a").await;
    let (legacy, _) = fixture::seed_agent_with_group(&pool, "head-legacy").await;
    let owned = insert_claim(&pool, a, a_group).await;
    let supporter = insert_claim(&pool, legacy, WORLD).await;
    let target = insert_claim(&pool, legacy, WORLD).await;
    let critic = insert_claim(&pool, legacy, WORLD).await;
    let incoming = edge(&pool, supporter, owned, "supports").await;
    let outgoing = edge(&pool, owned, target, "corroborates").await;
    let contradicts = edge(&pool, critic, owned, "contradicts").await;
    // The outgoing edge's BBA on the target, frozen from the predecessor's
    // interval by the engine's own edge-factor path: only a belief cascade
    // keyed on the claim the edge now leaves from (the head) reaches it.
    sqlx::query("UPDATE claims SET belief = 0.8, plausibility = 0.9 WHERE id = $1")
        .bind(owned)
        .execute(&pool)
        .await
        .expect("the predecessor's interval");
    {
        let (_scoped, viewer) = fixture::bypass(&pool).await;
        let mut conn = pool.acquire().await.expect("acquire");
        let wired = epigraph_engine::edge_factor::auto_wire_ds_for_edge(
            &mut conn,
            &viewer,
            outgoing,
            a,
            owned,
            target,
            "corroborates",
        )
        .await
        .expect("wire the outgoing edge");
        assert!(
            matches!(
                wired,
                epigraph_engine::edge_factor::EdgeFactorOutcome::Wired
            ),
            "precondition: the outgoing edge carries a BBA ({wired:?})"
        );
    }
    let frozen_bba: Uuid = sqlx::query_scalar(
        "SELECT id FROM mass_functions WHERE claim_id = $1 AND slot_kind = 'edge' \
           AND slot_id = $2 AND retracted_at IS NULL",
    )
    .bind(target)
    .bind(outgoing)
    .fetch_one(&pool)
    .await
    .expect("precondition: one live BBA keyed on the outgoing edge");
    let ia = fixture::make_custodian(&pool, a).await;
    fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        sqlx::query("SELECT * FROM public.epigraph_arm_operator_binding()")
            .execute(&mut *conn)
            .await
            .expect("arm");
        (conn, ())
    })
    .await;

    // The custodial revision of the owned claim: its cascade is deferred.
    let mut args = supersede_args(&owned.to_string(), &ia.to_string(), &a.to_string(), true);
    args.push("--allow-owned".to_string());
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let run = run_op(&pool, &refs).await;
    assert_eq!(run.code, 0, "{}", run.show());
    let new: Uuid = sqlx::query_scalar("SELECT id FROM claims WHERE supersedes = $1")
        .bind(owned)
        .fetch_one(&pool)
        .await
        .expect("the custodial successor");

    // A group writer revises the group-owned successor before the replay,
    // with its own edge migration applied.
    let head = {
        let mut conn = pool.acquire().await.expect("acquire");
        let (head, _) = epigraph_db::ClaimRepository::supersede_conn(
            &mut conn,
            epigraph_core::ClaimId::from_uuid(new),
            "the group's later revision of the successor",
            epigraph_core::TruthValue::new(0.6).expect("truth"),
            "a later revision",
            epigraph_db::SupersedeActor::new(a, epigraph_db::SupersedeTool::SupersedeClaim),
        )
        .await
        .expect("supersede the successor");
        head
    };
    assert!(!current(&pool, new).await && current(&pool, head).await);
    let dsn = fixture::database_url_for(&pool).await;
    assert_eq!(
        pending_replays(&dsn),
        1,
        "precondition: only the custodial deferral is pending"
    );
    assert!(
        bba_live(&pool, frozen_bba).await,
        "precondition: the act and the later revision left the frozen BBA in place"
    );

    // The replay as production runs it: REAL maintenance and application
    // logins (`NOSUPERUSER NOBYPASSRLS`), so the chain walk reads the retired
    // successor through row security, not as a superuser.
    let (maint_role, maint_dsn) = create_login(&pool, "epigraph_maintenance").await;
    let (app_role, app_dsn) = create_login(&pool, "epigraph_app").await;
    let r = replay(&app_dsn, &maint_dsn);
    assert_eq!(r.code, 0, "{}", r.show());
    let report: serde_json::Value = serde_json::from_str(r.stdout.trim()).expect("replay JSON");
    assert_eq!(report["applied"], 1, "{report}");

    let ends: (Uuid, Uuid, Uuid) = sqlx::query_as(
        "SELECT (SELECT target_id FROM edges WHERE id = $1), \
                (SELECT source_id FROM edges WHERE id = $2), \
                (SELECT target_id FROM edges WHERE id = $3)",
    )
    .bind(incoming)
    .bind(outgoing)
    .bind(contradicts)
    .fetch_one(&pool)
    .await
    .expect("edge ends");
    assert_eq!(
        ends,
        (head, head, owned),
        "the strengthening edges land on the current head (not the retired successor {new}); \
         contradicts stays"
    );
    assert_eq!(
        (
            factors_on(&pool, incoming, supporter, head).await,
            factors_on(&pool, outgoing, head, target).await,
        ),
        (1, 1),
        "the moved edges' factors are minted on the head"
    );
    assert!(
        !bba_live(&pool, frozen_bba).await,
        "the belief cascade ran from the head: the BBA frozen from the retired predecessor's \
         interval, keyed on the edge that now leaves the head, is invalidated"
    );

    let (deferred_object,): (Option<String>,) = sqlx::query_as(
        "SELECT details->'trigger'->>'object_id' FROM security_events \
          WHERE event_type = 'cascade.deferred' AND details->'trigger'->>'subject_id' = $1",
    )
    .bind(owned.to_string())
    .fetch_one(&pool)
    .await
    .expect("the deferral");
    assert_eq!(
        deferred_object,
        Some(new.to_string()),
        "the deferral still names the successor it recorded"
    );
    let (applied_id, touched): (Uuid, serde_json::Value) = sqlx::query_as(
        "SELECT id, details->'touched' FROM security_events \
          WHERE event_type = 'cascade.admin_applied' AND details->>'cause' = 'supersede' \
            AND details->'trigger'->>'subject_id' = $1",
    )
    .bind(owned.to_string())
    .fetch_one(&pool)
    .await
    .expect("the applied row");
    assert_eq!(
        touched["superseded_onto"],
        serde_json::json!(1),
        "the applied row counts the later replacement it followed: {touched}"
    );
    let ids: serde_json::Value = sqlx::query_scalar(
        "SELECT details->'touched' FROM security_events \
          WHERE event_type = 'cascade.admin_applied_ids' \
            AND details->>'applied_event_id' = $1",
    )
    .bind(applied_id.to_string())
    .fetch_one(&pool)
    .await
    .expect("the applied ids row");
    assert_eq!(
        ids["superseded_onto"],
        serde_json::json!([head]),
        "the ids row names the head: {ids}"
    );

    drop_login(&pool, &maint_role).await;
    drop_login(&pool, &app_role).await;
}

/// Whether the `mass_functions` row `id` is live (not retracted, not deleted).
async fn bba_live(pool: &PgPool, id: Uuid) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM mass_functions WHERE id = $1 AND retracted_at IS NULL)",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("BBA")
}

/// Backlog 6a670eab, the refusal: when the recorded successor's supersedes
/// chain has no single current head (here the group-owned custodial successor
/// was deprecated, retired with no replacement, before the replay), the
/// replay does NOT fall back to the recorded successor. The cascade fails
/// with nothing moved: the strengthening edges stay on the predecessor, no
/// factor is minted on the retired successor, a `cascade.admin_failed` row is
/// recorded and the deferral stays pending (it is replayable, then stuck, for
/// an operator to read). Run on real maintenance and application logins.
///
/// The edge migration's own refusal reason is asserted on a direct call of
/// `migrate_superseded_edges_to_head_conn` (the replay logs it and records
/// only a generic reason).
///
/// Verified to fail with the chain-walk error mapped to the recorded successor
/// (`[new_id]`) instead of a refusal: the replay applies, and the edges land
/// on the deprecated successor.
#[sqlx::test(migrations = "../../migrations")]
async fn a_replay_refuses_a_successor_chain_with_no_current_head(pool: PgPool) {
    let (a, a_group) = fixture::seed_human_operator(&pool, "headless-custodian").await;
    let (legacy, _) = fixture::seed_agent_with_group(&pool, "headless-legacy").await;
    let owned = insert_claim(&pool, a, a_group).await;
    let supporter = insert_claim(&pool, legacy, WORLD).await;
    let target = insert_claim(&pool, legacy, WORLD).await;
    let incoming = edge(&pool, supporter, owned, "supports").await;
    let outgoing = edge(&pool, owned, target, "corroborates").await;
    let ia = fixture::make_custodian(&pool, a).await;
    fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        sqlx::query("SELECT * FROM public.epigraph_arm_operator_binding()")
            .execute(&mut *conn)
            .await
            .expect("arm");
        (conn, ())
    })
    .await;

    let mut args = supersede_args(&owned.to_string(), &ia.to_string(), &a.to_string(), true);
    args.push("--allow-owned".to_string());
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let run = run_op(&pool, &refs).await;
    assert_eq!(run.code, 0, "{}", run.show());
    let new: Uuid = sqlx::query_scalar("SELECT id FROM claims WHERE supersedes = $1")
        .bind(owned)
        .fetch_one(&pool)
        .await
        .expect("the custodial successor");

    // The group deprecates the successor before the replay: retired, with no
    // replacement.
    assert_eq!(
        epigraph_db::ClaimRepository::deprecate_claim(
            &pool,
            epigraph_core::ClaimId::from_uuid(new)
        )
        .await
        .expect("deprecate the successor"),
        1
    );
    assert!(!current(&pool, new).await);

    let (maint_role, maint_dsn) = create_login(&pool, "epigraph_maintenance").await;
    let (app_role, app_dsn) = create_login(&pool, "epigraph_app").await;
    let r = replay(&app_dsn, &maint_dsn);
    assert_eq!(r.code, 1, "a failed replay exits non-zero: {}", r.show());
    let report: serde_json::Value = r
        .stdout
        .find('{')
        .and_then(|i| serde_json::from_str(r.stdout[i..].trim()).ok())
        .unwrap_or_else(|| panic!("replay JSON: {}", r.show()));
    assert_eq!(
        (report["applied"].as_i64(), report["failed"].as_i64()),
        (Some(0), Some(1)),
        "{report}"
    );

    let ends: (Uuid, Uuid) = sqlx::query_as(
        "SELECT (SELECT target_id FROM edges WHERE id = $1), \
                (SELECT source_id FROM edges WHERE id = $2)",
    )
    .bind(incoming)
    .bind(outgoing)
    .fetch_one(&pool)
    .await
    .expect("edge ends");
    assert_eq!(
        ends,
        (owned, owned),
        "nothing moved: not onto the deprecated successor {new}"
    );
    assert_eq!(
        (
            factors_on(&pool, incoming, supporter, new).await,
            factors_on(&pool, outgoing, new, target).await,
        ),
        (0, 0),
        "no factor on the deprecated successor"
    );
    let rows: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT event_type, details->>'outcome' FROM security_events \
          WHERE event_type IN ('cascade.admin_applied', 'cascade.admin_failed') \
            AND details->'trigger'->>'subject_id' = $1",
    )
    .bind(owned.to_string())
    .fetch_all(&pool)
    .await
    .expect("cascade rows");
    assert_eq!(
        rows,
        vec![(
            "cascade.admin_failed".to_string(),
            Some("failed".to_string())
        )],
        "one failure recorded, nothing applied"
    );
    // The edge migration itself refuses, naming why (the replay records only a
    // generic reason), with nothing moved.
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let v = &viewer;
    let refusal = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r = epigraph_db::ClaimRepository::migrate_superseded_edges_to_head_conn(
            &mut conn, v, owned, new,
        )
        .await
        .map(|_| ());
        (conn, r)
    })
    .await;
    let e = refusal.expect_err("no single current head: the migration refuses");
    assert!(e.to_string().contains("no single current head"), "{e}");

    let dsn = fixture::database_url_for(&pool).await;
    assert_eq!(pending_replays(&dsn), 1, "the cascade stays pending");

    drop_login(&pool, &maint_role).await;
    drop_login(&pool, &app_role).await;
}

/// Whether `claim` carries an embedding.
async fn embedded(pool: &PgPool, claim: Uuid) -> bool {
    sqlx::query_scalar("SELECT embedding IS NOT NULL FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("claim")
}

/// Backlog 5fd3e2b4: the custodial supersede embeds the successor it
/// committed, on the maintenance session's bypass viewer, so the revised claim
/// stays recallable (the retirement nulled the predecessor's vector). With an
/// embedder, the applied run's successor has an embedding and the report says
/// so; a dry run embeds nothing (there is no successor); with no embedder
/// configured the act still commits and reports `embedded: false`, leaving the
/// row to the backfill.
///
/// The session is opened on a real maintenance login, so the store is
/// exercised under row security, not as a superuser.
///
/// Verified to fail on the base: the verb never embedded, so the applied run's
/// successor kept `embedding IS NULL`; and with the post-commit store removed
/// from `custodial_supersede`, `embedded` is false and the vector NULL.
#[sqlx::test(migrations = "../../migrations")]
async fn a_custodial_supersede_embeds_its_successor(pool: PgPool) {
    use epigraph_cli::operator::custodian;
    use epigraph_embeddings::{EmbeddingConfig, EmbeddingService, MockProvider};

    let (a, _) = fixture::seed_human_operator(&pool, "embed-custodian").await;
    let (legacy, _) = fixture::seed_agent_with_group(&pool, "embed-legacy").await;
    let with = insert_claim(&pool, legacy, WORLD).await;
    let without = insert_claim(&pool, legacy, WORLD).await;
    let ia = fixture::make_custodian(&pool, a).await;
    fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        sqlx::query("SELECT * FROM public.epigraph_arm_operator_binding()")
            .execute(&mut *conn)
            .await
            .expect("arm");
        (conn, ())
    })
    .await;

    // The session the verb opens, on a REAL maintenance login (`NOSUPERUSER
    // NOBYPASSRLS`), so the store runs under row security on a world-owned
    // claim, as in production.
    let (maint_role, maint_dsn) = create_login(&pool, "epigraph_maintenance").await;
    let scoped = epigraph_db::ScopedPool::connect(&maint_dsn, epigraph_db::SessionGucMode::Session)
        .await
        .expect("connect as the maintenance login");
    // As `operator::connect` does: the whole pool is the maintenance login, so
    // it is attached as the maintenance pool (an unattached pool refuses).
    let maintenance = scoped.inner().clone();
    let scoped = scoped.with_maintenance_pool(maintenance);
    let mut session = scoped
        .maintenance_session(epigraph_db::visibility::SystemReason::EmbeddingBackfill)
        .await
        .expect("a maintenance session");
    let (conn, viewer) = session.split();
    let mock = MockProvider::new(EmbeddingConfig::openai(1536));
    let request = |claim: Uuid, apply: bool| custodian::SupersedeRequest {
        claim,
        content: format!("the custodian's revision of {claim}"),
        truth: 0.7,
        assignment: ia,
        actor: a,
        reason: "custodial embedding test".to_string(),
        allow_owned: false,
        act: None,
        apply,
    };
    let done = |o: custodian::SupersedeOutcome| match o {
        custodian::SupersedeOutcome::Done(r) => r,
        other => panic!("the supersede did not complete: {other:?}"),
    };

    // A dry run: rolled back, nothing to embed.
    let dry = done(
        custodian::custodial_supersede(
            &mut *conn,
            viewer,
            Some(&mock as &dyn EmbeddingService),
            &request(with, false),
        )
        .await
        .expect("dry run"),
    );
    assert!(!dry.applied && !dry.embedded, "a dry run embeds nothing");
    assert!(current(&pool, with).await, "a dry run retires nothing");

    // Applied, with an embedder: the successor is embedded.
    let r = done(
        custodian::custodial_supersede(
            &mut *conn,
            viewer,
            Some(&mock as &dyn EmbeddingService),
            &request(with, true),
        )
        .await
        .expect("applied run"),
    );
    assert!(r.applied, "{r:?}");
    assert!(!current(&pool, with).await, "the predecessor is retired");
    assert!(
        r.embedded,
        "the report says the successor was embedded: {r:?}"
    );
    assert!(
        embedded(&pool, r.new).await,
        "the committed successor carries an embedding"
    );

    // Applied, with no embedder: the act stands, the successor waits for the
    // backfill.
    let r = done(
        custodian::custodial_supersede(&mut *conn, viewer, None, &request(without, true))
            .await
            .expect("applied run without an embedder"),
    );
    assert!(r.applied && !r.embedded, "{r:?}");
    assert!(!current(&pool, without).await, "the act committed");
    assert!(
        !embedded(&pool, r.new).await,
        "no embedder: no vector (the control)"
    );

    drop(session);
    scoped.inner().close().await;
    drop_login(&pool, &maint_role).await;
}
