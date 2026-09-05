//! PR-16 / plan §8.2 — **D1 acceptance: tenancy is REQUIRED.**
//!
//! Migration 074 drops migration 062's `DEFAULT`s on all 25 tier-A tables and
//! replaces 070's transition trigger bodies with the final, `RAISE`-terminated
//! forms. This file is the acceptance suite for that: §8.2's five SQL queries,
//! plus the behavioural assertions the PR-16 *Acceptance* line names.
//!
//! `tenancy_triggers.rs` is PR-12's file and pins the TRANSITION behaviour;
//! this is PR-16's and pins the END STATE. Where the two disagree, PR-12's has
//! been inverted in place with a comment naming this file.
//!
//! # The one thing that makes every assertion here non-vacuous
//!
//! Migration 074's escape hatch is
//! `pg_has_role(session_user, 'epigraph_seed', 'MEMBER')`. The test harness
//! connects as a **superuser**, and a superuser satisfies `pg_has_role` for
//! every role — so on the default connection every undeclared write takes arm
//! 4 and succeeds. A file that only ever wrote on the default connection could
//! not observe the `23502` this migration exists to raise, and would pass on a
//! tree where 074 had never been applied.
//!
//! So the refusal assertions run inside
//! [`fixture::as_role`]`(pool, "epigraph_app", …)`, which issues
//! **`SET SESSION AUTHORIZATION`** — not `SET ROLE`. `SET ROLE` changes only
//! `current_user`; the trigger reads `session_user`, so under `SET ROLE` the
//! session is still the superuser and arm 4 still fires. That was measured, not
//! assumed, and it is the single easiest way to write a green vacuous version
//! of this file.
//!
//! # And the corollary for anyone running the suite as a non-superuser
//!
//! The ~180 test fixtures across this workspace that insert claims without
//! naming the tenancy columns survive 074 **because the harness role is a
//! superuser**, not because of any grant. The plan's *Files* line says
//! "`epigraph_seed` granted to the test harness pools"; on this host and in CI
//! (`POSTGRES_USER: epigraph` on a stock `pgvector/pgvector:pg16`) that grant
//! is implied and no `pg_auth_members` row exists. A harness that connects as a
//! non-superuser needs `GRANT epigraph_seed TO <role>` or those fixtures start
//! raising `23502`. [`the_harness_role_can_take_the_seed_escape_hatch`] asserts
//! the precondition so the failure names itself.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{ClaimRepository, ConsolidateMode};
use sqlx::{Executor, PgPool, Row};
use uuid::Uuid;

const WORLD: Uuid = Uuid::from_bytes([0u8; 16]);

/// A `('group', G)` claim, inserted on the ambient (superuser) connection.
async fn group_claim(pool: &PgPool, agent: Uuid, group: Uuid, content: &str) -> Uuid {
    fixture::seed_group_claim(pool, agent, group, content).await
}

/// `(owner_group_id, visibility)` of one row.
async fn tenancy_of(pool: &PgPool, table: &str, id: Uuid) -> (Uuid, String) {
    let row = sqlx::query(&format!(
        "SELECT owner_group_id, visibility FROM {table} WHERE id = $1"
    ))
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("read tenancy");
    (row.get(0), row.get(1))
}

// =============================================================================
// §8.2 A1 — no tier-A tenancy column carries a default, and none is nullable
// =============================================================================

/// A1, read from `information_schema` rather than inferred from an error.
///
/// The query is deliberately **table-agnostic** — it filters on
/// `column_name IN ('visibility','owner_group_id')` and names no table — so a
/// tier-A table added by a later migration that forgets to drop its default is
/// caught here without anyone editing a list.
///
/// It is also why `agents.profile_visibility` is NOT covered: that column has a
/// different name and A1 cannot see it. Migration 074's section 5 records why
/// its default is deliberately retained, and
/// [`agents_profile_visibility_keeps_its_default_deliberately`] pins the
/// decision so it reads as a choice rather than an oversight.
#[sqlx::test(migrations = "../../migrations")]
async fn a1_no_tier_a_tenancy_column_has_a_default_or_is_nullable(pool: PgPool) {
    let offenders: Vec<(String, String, Option<String>, String)> = sqlx::query_as(
        "SELECT c.table_name, c.column_name, c.column_default, c.is_nullable \
           FROM information_schema.columns c \
          WHERE c.table_schema = 'public' \
            AND c.column_name IN ('visibility','owner_group_id') \
            AND (c.column_default IS NOT NULL OR c.is_nullable = 'YES') \
          ORDER BY c.table_name, c.column_name",
    )
    .fetch_all(&pool)
    .await
    .expect("A1 probe");

    assert!(
        offenders.is_empty(),
        "plan §8.2 A1: no tier-A visibility/owner_group_id column may carry a \
         column_default or be nullable after migration 074. Offenders: {offenders:?}. \
         A DEFAULT here is 'public by omission' one layer below the code — the same \
         defect D1 names — and it is what makes the require-tenancy triggers \
         unreachable, because the column is never NULL inside a BEFORE trigger."
    );

    // Not vacuous: the query must actually be looking at columns that exist.
    // Without this, dropping every tier-A table would make A1 pass.
    let covered: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM information_schema.columns \
          WHERE table_schema = 'public' AND column_name = 'owner_group_id'",
    )
    .fetch_one(&pool)
    .await
    .expect("coverage probe");
    assert_eq!(
        covered, 25,
        "expected the 25 tier-A tables from migration 062's tier_a array to carry \
         owner_group_id; found {covered}. A different number means the tier-A set \
         moved, which is a D1 change and needs a decision, not a silent edit — and \
         it means A1 above was measured over the wrong population."
    );
}

/// The deliberate exception to A1's spirit, recorded as a decision.
///
/// Plan §3's 074 body drops `agents.profile_visibility`'s default too. This
/// tree does not, for three measured reasons stated in migration 074 section 5;
/// the load-bearing one is that **no trigger fills it**. `agents` is tier B and
/// carries a `tenancy_exempt` row precisely because identity has to render
/// authorship on a public claim, so it has no `owner_group_id`, no inheritance
/// arm and no seed arm. Dropping the default would turn every
/// `INSERT INTO agents` in the tree into a bare `23502` with no recovery path
/// and no security gain.
///
/// This test asserts the CURRENT state so that a later PR which does the work
/// properly — a `agents_require_profile_visibility` trigger, then the drop —
/// has to come here and say so.
#[sqlx::test(migrations = "../../migrations")]
async fn agents_profile_visibility_keeps_its_default_deliberately(pool: PgPool) {
    let default: Option<String> = sqlx::query_scalar(
        "SELECT column_default FROM information_schema.columns \
          WHERE table_schema='public' AND table_name='agents' \
            AND column_name='profile_visibility'",
    )
    .fetch_one(&pool)
    .await
    .expect("profile_visibility probe");

    assert!(
        default.is_some(),
        "agents.profile_visibility lost its DEFAULT. That is not covered by §8.2 A1 \
         (which filters on column_name IN ('visibility','owner_group_id')), and no \
         trigger fills the column — so dropping it makes every INSERT INTO agents \
         raise 23502. If this was intentional, ship the filling trigger in the same \
         migration and rewrite this test to assert the end state."
    );

    // But the vocabulary IS enforced: 076 validates the CHECK, so an
    // out-of-vocabulary value cannot be stored even while the default stands.
    let validated: bool = sqlx::query_scalar(
        "SELECT convalidated FROM pg_constraint \
          WHERE conrelid = 'public.agents'::regclass \
            AND conname = 'agents_profile_visibility_check'",
    )
    .fetch_one(&pool)
    .await
    .expect("agents CHECK probe");
    assert!(
        validated,
        "migration 076 must VALIDATE agents_profile_visibility_check. Retaining the \
         DEFAULT is only defensible while the vocabulary is enforced."
    );
}

// =============================================================================
// §8.2 A3 / A4 — no black holes, and no world-owned claims
// =============================================================================

/// A3 and A4 together, and the reason they are one test.
///
/// * **A3** — `('group', world)` is a black hole: the world group is memberless
///   by design, so `owner_group_id = ANY(<viewer groups>)` can never match and
///   nobody, including the author, can read the row back.
/// * **A4** — no claim is world-OWNED at all, in either visibility. This is
///   achievable only because migration 074 arm 4 stamps the **seed** group
///   rather than world; with the plan's earlier world-stamping arm the count
///   would grow on every test fixture insert and A4 could never be true.
///
/// The insert below is the exact write A4 is about: undeclared, on the harness
/// role, taking the escape hatch. Asserting A4 over an EMPTY table would pass
/// on any tree at all.
#[sqlx::test(migrations = "../../migrations")]
async fn a3_and_a4_no_black_holes_and_no_world_owned_claims(pool: PgPool) {
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "a34").await;
    let seed = fixture::seed_group(&pool).await;

    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current) \
         VALUES ($1, 'undeclared', $2, 0.7, $3, true)",
    )
    .bind(id)
    .bind(vec![7u8; 32])
    .bind(agent)
    .execute(&pool)
    .await
    .expect("the seed escape hatch must accept an undeclared insert on the harness role");

    assert_eq!(
        tenancy_of(&pool, "claims", id).await,
        (seed, "public".to_string()),
        "arm 4 must stamp ('public', <seed group>). Stamping world would make §8.2 A4 \
         unsatisfiable and would make the deferred strong CHECK (owner_group_id <> \
         world) permanently unshippable."
    );

    let black_holes: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM public.claims \
          WHERE visibility = 'group' AND owner_group_id = $1",
    )
    .bind(WORLD)
    .fetch_one(&pool)
    .await
    .expect("A3 probe");
    assert_eq!(
        black_holes, 0,
        "plan §8.2 A3: no ('group', world) black holes"
    );

    let world_owned: i64 =
        sqlx::query_scalar("SELECT count(*)::bigint FROM public.claims WHERE owner_group_id = $1")
            .bind(WORLD)
            .fetch_one(&pool)
            .await
            .expect("A4 probe");
    assert_eq!(
        world_owned, 0,
        "plan §8.2 A4: no claim may be world-owned. The escape-hatch row written \
         above is the case this is testing, and it must have landed on the seed group."
    );
}

// =============================================================================
// §8.2 A5 — every tenancy trigger is armed
// =============================================================================

/// A5, extended to migration 074's 23 new `*_require_tenancy` triggers and to
/// `claims_block_widening`.
///
/// `ALTER TABLE … DISABLE TRIGGER` reverts D1's whole write-side enforcement in
/// one line, with no diff and no migration. The counts are pinned as well as
/// the enabled-ness, because "no tenancy trigger is disabled" passes vacuously
/// on a database that has none — which is exactly what a partially-applied 074
/// looks like.
#[sqlx::test(migrations = "../../migrations")]
async fn a5_every_tenancy_trigger_is_enabled(pool: PgPool) {
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT c.relname, t.tgname, t.tgenabled::text \
           FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid \
          WHERE NOT t.tgisinternal \
            AND (t.tgname LIKE '%\\_require\\_tenancy' \
                 OR t.tgname LIKE '%\\_inherit\\_tenancy' \
                 OR t.tgname IN ('edges_tenancy','claims_propagate_tenancy', \
                                 'claims_block_widening')) \
          ORDER BY c.relname, t.tgname",
    )
    .fetch_all(&pool)
    .await
    .expect("pg_trigger probe");

    let require: Vec<&(String, String, String)> = rows
        .iter()
        .filter(|(_, n, _)| n.ends_with("_require_tenancy"))
        .collect();
    assert_eq!(
        require.len(),
        24,
        "expected 24 *_require_tenancy triggers after migration 074: claims (from \
         070) plus the 17 claim-derived tables plus the 6 parentless roots. Found \
         {}: {require:?}. `edges` is deliberately absent — edges_tenancy is already \
         BEFORE ROW and 072's body assigns both columns on every branch.",
        require.len()
    );

    assert!(
        rows.iter().any(|(_, n, _)| n == "claims_block_widening"),
        "migration 074 must create claims_block_widening. Without it a group→public \
         UPDATE is unguarded, and so is declassifying a SEALED claim."
    );

    let disabled: Vec<&(String, String, String)> =
        rows.iter().filter(|(_, _, e)| e != "O").collect();
    assert!(
        disabled.is_empty(),
        "plan §8.2 A5: every tenancy trigger must be ENABLED (tgenabled = 'O'). \
         These are not: {disabled:?}"
    );
}

// =============================================================================
// The PR-16 *Acceptance* line, behaviourally
// =============================================================================

/// The precondition every refusal assertion in this file rests on.
///
/// If this fails, the ~180 undeclared fixture inserts across the workspace are
/// about to fail too, and they will fail with the same `23502` — but scattered
/// across a hundred unrelated test names. Asserting it once, here, is what
/// makes that diagnosable.
#[sqlx::test(migrations = "../../migrations")]
async fn the_harness_role_can_take_the_seed_escape_hatch(pool: PgPool) {
    let ok: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_seed') \
            AND pg_has_role(session_user, 'epigraph_seed', 'MEMBER')",
    )
    .fetch_one(&pool)
    .await
    .expect("seed membership probe");

    assert!(
        ok,
        "the test harness role must satisfy migration 074 arm 4, or every fixture in \
         this workspace that inserts a claim without naming (visibility, \
         owner_group_id) starts raising 23502. On a superuser connection this holds \
         implicitly; on a non-superuser harness run `GRANT epigraph_seed TO <role>`."
    );
}

/// An undeclared `INSERT INTO claims` as `epigraph_app` raises `23502` **and
/// points at the documentation**.
///
/// The HINT is asserted, not just the SQLSTATE. A bare `null value in column
/// "visibility"` is a true statement and a useless one: the person reading it
/// is a developer whose write path needs a `TenancyDecl`, and the only thing
/// that tells them so is the hint text. `docs/tenancy.md` gained the
/// `#declaring-visibility-on-write` section in this PR for exactly this
/// reference to resolve.
#[sqlx::test(migrations = "../../migrations")]
async fn an_undeclared_claim_insert_by_the_app_role_raises_23502_with_the_hint(pool: PgPool) {
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "app").await;
    fixture::grant_app_privileges(&pool, "epigraph_app").await;

    let err = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        let e = sqlx::query(
            "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current) \
             VALUES (gen_random_uuid(), 'undeclared', $1, 0.7, $2, true)",
        )
        .bind(vec![11u8; 32])
        .bind(agent)
        .execute(&mut *conn)
        .await
        .expect_err("an undeclared insert by the app role must be refused");
        (conn, e)
    })
    .await;

    let db = err.as_database_error().expect("a database error");
    assert_eq!(
        db.code().as_deref(),
        Some("23502"),
        "the refusal must be a not-null violation, so existing client error \
         mapping treats it as a client fault: {err}"
    );
    assert!(
        db.message().contains("epigraph tenancy"),
        "the message must identify itself as a tenancy refusal, not a bare column \
         complaint: {}",
        db.message()
    );
    let hint = format!("{err:?}");
    assert!(
        hint.contains("docs/tenancy.md#declaring-visibility-on-write"),
        "the PR-16 acceptance line requires the docs/tenancy.md HINT. Without it \
         the error tells a developer what failed and not what to do. Got: {hint}"
    );
}

/// The same insert on the harness (seed-satisfying) role succeeds and lands on
/// `('public', <seed group>)`, **not** on the world group.
#[sqlx::test(migrations = "../../migrations")]
async fn the_same_insert_as_the_seed_role_succeeds_on_the_seed_group(pool: PgPool) {
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "seed").await;
    let seed = fixture::seed_group(&pool).await;

    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current) \
         VALUES ($1, 'undeclared', $2, 0.7, $3, true)",
    )
    .bind(id)
    .bind(vec![12u8; 32])
    .bind(agent)
    .execute(&pool)
    .await
    .expect("seed role insert");

    let (owner, vis) = tenancy_of(&pool, "claims", id).await;
    assert_eq!((owner, vis.as_str()), (seed, "public"));
    assert_ne!(
        owner, WORLD,
        "arm 4 must stamp the seed group, not world — that is what makes §8.2 A4 \
         achievable at all"
    );
}

/// The app role cannot DDL, so it cannot put the default back.
///
/// This is the residual migration 074's own header names: the trigger is
/// bypassable by `ALTER TABLE … DISABLE TRIGGER` and by
/// `session_replication_role`, both of which need table ownership. The control
/// is that the application role does not have it.
#[sqlx::test(migrations = "../../migrations")]
async fn the_app_role_cannot_restore_the_default(pool: PgPool) {
    fixture::grant_app_privileges(&pool, "epigraph_app").await;

    let err = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        let e = conn
            .execute("ALTER TABLE public.claims ALTER COLUMN visibility SET DEFAULT 'public'")
            .await
            .expect_err("the app role must not be able to reinstate the default");
        (conn, e)
    })
    .await;

    assert!(
        err.to_string().contains("must be owner"),
        "expected an ownership refusal; got {err}. If the app role has become the \
         table owner, every control in this file is advisory: it can DISABLE the \
         triggers and SET DEFAULT in two statements."
    );
}

// =============================================================================
// Inheritance: the arms that make "declare or bind a parent" true
// =============================================================================

/// Arm 1 — a successor inherits its predecessor's tenancy.
///
/// `ClaimRepository::supersede` is §4.6 site 4 and is deliberately UNCHANGED by
/// PR-16: it binds `supersedes`, so the database derives the answer. This is
/// the test the plan asks for in place of a call-site edit.
#[sqlx::test(migrations = "../../migrations")]
async fn a_successor_of_a_group_private_claim_is_group_private(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "sup").await;
    let old = group_claim(&pool, agent, group, "private original").await;

    let (_old, new) = ClaimRepository::supersede(
        &pool,
        epigraph_core::ClaimId::from_uuid(old),
        "private correction",
        epigraph_core::TruthValue::clamped(0.9),
        "test",
    )
    .await
    .expect("supersede");

    assert_eq!(
        tenancy_of(&pool, "claims", new).await,
        (group, "group".to_string()),
        "a supersede that did not inherit would DECLASSIFY its predecessor — the \
         successor becomes the current row and the private content is now public"
    );
}

/// Arm 1's refusal half: a declaration cannot widen past its predecessor.
///
/// **This is the arm-ordering correction.** Plan §3's 074 body puts "fully
/// declared by the writer" FIRST, which makes this insert SUCCEED — measured —
/// because the declared pair short-circuits before the predecessor is ever
/// read. That would be a one-statement declassification of any claim the writer
/// can name, and it would make this very acceptance criterion unsatisfiable.
/// Migration 074 runs the parent arms first for exactly this reason.
#[sqlx::test(migrations = "../../migrations")]
async fn an_explicitly_public_successor_over_a_private_predecessor_is_refused(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "widen").await;
    let old = group_claim(&pool, agent, group, "private original").await;

    let err = sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             supersedes, visibility, owner_group_id) \
         VALUES (gen_random_uuid(), 'now public', $1, 0.9, $2, true, $3, 'public', $4)",
    )
    .bind(vec![13u8; 32])
    .bind(agent)
    .bind(old)
    .bind(WORLD)
    .execute(&pool)
    .await
    .expect_err("declaring 'public' over a group-private predecessor must be refused");

    assert_eq!(
        err.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("42501"),
        "expected insufficient_privilege (42501); got {err}"
    );
}

/// Arm 2 — a step in a group-private lineage inherits, and cannot be declared
/// public. Symmetric with arm 1, and covers `evolve_step` /
/// `ingest-executor::add_step`.
#[sqlx::test(migrations = "../../migrations")]
async fn a_step_in_a_private_lineage_inherits_and_cannot_be_declared_public(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "lineage").await;
    let head = group_claim(&pool, agent, group, "step 1").await;
    let lineage = Uuid::new_v4();
    sqlx::query("UPDATE claims SET step_lineage_id = $1 WHERE id = $2")
        .bind(lineage)
        .bind(head)
        .execute(&pool)
        .await
        .expect("set lineage");

    let next = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             step_lineage_id) \
         VALUES ($1, 'step 2', $2, 0.8, $3, true, $4)",
    )
    .bind(next)
    .bind(vec![14u8; 32])
    .bind(agent)
    .bind(lineage)
    .execute(&pool)
    .await
    .expect("undeclared step must inherit");
    assert_eq!(
        tenancy_of(&pool, "claims", next).await,
        (group, "group".to_string())
    );

    let err = sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             step_lineage_id, visibility, owner_group_id) \
         VALUES (gen_random_uuid(), 'step 3', $1, 0.8, $2, true, $3, 'public', $4)",
    )
    .bind(vec![15u8; 32])
    .bind(agent)
    .bind(lineage)
    .bind(WORLD)
    .execute(&pool)
    .await
    .expect_err("a declared-public step in a private lineage must be refused");
    assert_eq!(
        err.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("42501")
    );
}

/// The claim-derived tables inherit at INSERT, on the **app** role.
///
/// Before migration 074 this worked through 070 arm (c), an AFTER STATEMENT
/// trigger. That is now too late: `NOT NULL` is checked at heap-insert, which
/// happens BEFORE any AFTER trigger fires, so the moment the defaults dropped
/// all 17 of these tables would have raised `23502` on every write. 074's
/// `epigraph_derived_require_tenancy` is the BEFORE ROW half that makes the row
/// insertable; arm (c) still runs after it and still has the last word.
///
/// Run as `epigraph_app` deliberately: on the harness role the seed arm would
/// mask a missing derived trigger by stamping `('public', seed)` — the row
/// would land, with the WRONG tenancy, and the test would pass.
#[sqlx::test(migrations = "../../migrations")]
async fn the_claim_derived_tables_inherit_at_insert_on_the_app_role(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "derived").await;
    let claim = group_claim(&pool, agent, group, "private parent").await;
    let frame: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses, visibility, owner_group_id) \
         VALUES ('tenancy-required-frame', ARRAY['a','b'], 'public', $1) RETURNING id",
    )
    .bind(WORLD)
    .fetch_one(&pool)
    .await
    .expect("seed frame");
    fixture::grant_app_privileges(&pool, "epigraph_app").await;

    // One row per §8.2's named tables, each inserted WITHOUT naming tenancy.
    let ids = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        let evidence: Uuid = sqlx::query_scalar(
            "INSERT INTO evidence (id, claim_id, content_hash, evidence_type) \
             VALUES (gen_random_uuid(), $1, $2, 'document') RETURNING id",
        )
        .bind(claim)
        .bind(vec![21u8; 32])
        .fetch_one(&mut *conn)
        .await
        .expect("evidence");

        let challenge: Uuid = sqlx::query_scalar(
            "INSERT INTO challenges (id, claim_id, challenger_id, challenge_type, explanation) \
             VALUES (gen_random_uuid(), $1, $2, 'evidence', 'why') RETURNING id",
        )
        .bind(claim)
        .bind(agent)
        .fetch_one(&mut *conn)
        .await
        .expect("challenge");

        let trace: Uuid = sqlx::query_scalar(
            "INSERT INTO reasoning_traces (id, claim_id, reasoning_type, confidence, explanation) \
             VALUES (gen_random_uuid(), $1, 'deductive', 0.9, 'why') RETURNING id",
        )
        .bind(claim)
        .fetch_one(&mut *conn)
        .await
        .expect("reasoning trace");

        // `claim_frames` is keyed on (claim_id, frame_id) and has no `id`
        // column, so it is asserted separately below rather than through the
        // id-keyed helper. Included at all because it is the highest-cardinality
        // derived table in the tree (9 production INSERT sites) and the one a
        // regression is most likely to reach.
        sqlx::query(
            "INSERT INTO claim_frames (claim_id, frame_id, hypothesis_index) \
             VALUES ($1, $2, 0)",
        )
        .bind(claim)
        .bind(frame)
        .execute(&mut *conn)
        .await
        .expect("claim_frames");

        (
            conn,
            [
                ("evidence", evidence),
                ("challenges", challenge),
                ("reasoning_traces", trace),
            ],
        )
    })
    .await;

    let cf: (Uuid, String) =
        sqlx::query_as("SELECT owner_group_id, visibility FROM claim_frames WHERE claim_id = $1")
            .bind(claim)
            .fetch_one(&pool)
            .await
            .expect("read claim_frames tenancy");
    assert_eq!(
        cf,
        (group, "group".to_string()),
        "claim_frames must inherit its parent claim's tenancy at INSERT"
    );

    for (table, id) in ids {
        assert_eq!(
            tenancy_of(&pool, table, id).await,
            (group, "group".to_string()),
            "{table} must inherit its parent claim's tenancy at INSERT. Stamped \
             public, its copy of the claim's content is readable by everyone — and \
             `evidence` is the sharp case, because evidence.raw_content plus \
             evidence.embedding are a full second copy WITH ITS OWN ANN VECTOR."
        );
    }
}

/// A derived row with no resolvable parent is refused, not defaulted.
#[sqlx::test(migrations = "../../migrations")]
async fn a_derived_row_with_no_parent_claim_is_refused_on_the_app_role(pool: PgPool) {
    fixture::grant_app_privileges(&pool, "epigraph_app").await;

    let err = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        let e = sqlx::query(
            "INSERT INTO evidence (id, claim_id, content_hash, evidence_type) \
             VALUES (gen_random_uuid(), gen_random_uuid(), $1, 'document')",
        )
        .bind(vec![22u8; 32])
        .execute(&mut *conn)
        .await
        .expect_err("an orphan derived row must be refused");
        (conn, e)
    })
    .await;

    // 23503 from the tenancy trigger, or from the FK if one is validated first
    // — either is a refusal, and both are client errors. What must NOT happen
    // is the row landing on a default.
    let code = err
        .as_database_error()
        .and_then(|e| e.code())
        .map(|c| c.to_string());
    assert!(
        matches!(code.as_deref(), Some("23503") | Some("23502")),
        "expected a foreign-key or not-null refusal; got {err}"
    );
}

/// The six parentless roots refuse an undeclared insert on the app role.
///
/// These are the tables the PR-16 *Files* line never mentions and that 070's
/// AFTER STATEMENT arm (c) never covered — they have no `claim_id`. Nine
/// production statements gained an explicit declaration in this PR because of
/// this test.
#[sqlx::test(migrations = "../../migrations")]
async fn the_parentless_root_tables_refuse_an_undeclared_insert(pool: PgPool) {
    fixture::grant_app_privileges(&pool, "epigraph_app").await;

    let statements: Vec<(&str, &str)> = vec![
        (
            "frames",
            "INSERT INTO frames (name, hypotheses) VALUES ('f-074', ARRAY['a','b'])",
        ),
        (
            "contexts",
            "INSERT INTO contexts (name, context_type) VALUES ('c-074', 'temporal')",
        ),
        (
            "perspectives",
            "INSERT INTO perspectives (name) VALUES ('p-074')",
        ),
        (
            "communities",
            "INSERT INTO communities (name) VALUES ('com-074')",
        ),
    ];

    for (table, sql) in statements {
        let err = fixture::as_role(&pool, "epigraph_app", |mut conn| {
            let sql = sql.to_string();
            async move {
                let e = sqlx::query(&sql).execute(&mut *conn).await.err();
                (conn, e)
            }
        })
        .await
        .unwrap_or_else(|| {
            panic!(
                "{table} accepted an undeclared INSERT on the app role. It has no parent \
                 to inherit from, so the only way that row got a tenancy is a DEFAULT \
                 migration 074 was supposed to have dropped."
            )
        });

        assert_eq!(
            err.as_database_error().and_then(|e| e.code()).as_deref(),
            Some("23502"),
            "{table}: expected 23502; got {err}"
        );
    }
}

// =============================================================================
// Widening — `claims_block_widening`
// =============================================================================

/// Declassification is refused unless the admin surface's GUC is set, and is
/// refused UNCONDITIONALLY for a sealed claim.
///
/// The sealed arm is the one with no override, and it is deliberate (sec F11):
/// the admin declassification surface sets `epigraph.allow_declassify` BY
/// DESIGN, so a guard that honoured the GUC would be no guard at all on the one
/// path that reaches it. Declassifying a sealed claim yields a public row whose
/// content is a `[sealed:uuid]` stub with ciphertext nobody is entitled to —
/// permanently unreadable, and with `content_hash` no longer agreeing with
/// `content`.
#[sqlx::test(migrations = "../../migrations")]
async fn declassification_is_gated_and_sealed_claims_can_never_be_widened(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "declass").await;
    let plain = group_claim(&pool, agent, group, "ordinary private").await;
    let sealed = group_claim(&pool, agent, group, "sealed private").await;

    // (a) no GUC → refused
    let err = sqlx::query("UPDATE claims SET visibility = 'public' WHERE id = $1")
        .bind(plain)
        .execute(&pool)
        .await
        .expect_err("declassification without the admin GUC must be refused");
    assert_eq!(
        err.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("42501")
    );

    // (b) with the GUC → allowed. Asserted so (a) is known to be testing the
    //     GUC and not some unrelated permission failure.
    let mut conn = pool.acquire().await.expect("acquire");
    conn.execute("SET epigraph.allow_declassify = 'yes'")
        .await
        .expect("set guc");
    sqlx::query("UPDATE claims SET visibility = 'public', owner_group_id = $2 WHERE id = $1")
        .bind(plain)
        .bind(WORLD)
        .execute(&mut *conn)
        .await
        .expect("declassification with the admin GUC must be allowed");

    // (c) sealed → refused EVEN WITH the GUC still set on this connection.
    let epoch: i32 = sqlx::query_scalar(
        "INSERT INTO group_key_epochs (group_id, epoch, wrapped_key, status) \
         VALUES ($1, 1, ''::bytea, 'active') \
         ON CONFLICT (group_id, epoch) DO UPDATE SET status = 'active' RETURNING epoch",
    )
    .bind(group)
    .fetch_one(&mut *conn)
    .await
    .expect("key epoch");
    sqlx::query(
        "INSERT INTO claim_encryption (claim_id, group_id, epoch, privacy_tier, encrypted_content) \
         VALUES ($1, $2, $3, 'fully_private', ''::bytea)",
    )
    .bind(sealed)
    .bind(group)
    .bind(epoch)
    .execute(&mut *conn)
    .await
    .expect("seal the claim");

    let err = sqlx::query("UPDATE claims SET visibility = 'public' WHERE id = $1")
        .bind(sealed)
        .execute(&mut *conn)
        .await
        .expect_err("a SEALED claim must never be widened, GUC or not");
    assert_eq!(
        err.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("42501")
    );
    assert!(
        err.to_string().contains("SEALED"),
        "the sealed refusal must be distinguishable from the ordinary \
         declassification refusal, or an operator will reach for the GUC that \
         cannot help them: {err}"
    );
}

/// **No sealed claim is `visibility = 'public'`.** A corpus invariant, and the
/// regression test for a real defect PR-16 introduced and then fixed.
///
/// # The defect, because the shape of it is the lesson
///
/// `POST /api/v1/claims` carries `privacy_tier` and `group_id`: with
/// `privacy_tier = "fully_private"` it verifies the caller's membership of
/// `group_id` against the AUTHENTICATED identity, writes the claim, and then
/// writes a `claim_encryption` row for it. Plan §4.6's table treats that
/// handler as one call site needing one declaration, and the first PR-16 draft
/// gave it one — `('public', <author's personal group>)` for both tiers.
///
/// On the private tier that is a disclosure: the row carries
/// `visibility = 'public'` while its content is a `[sealed:uuid]` stub, so
/// every authenticated agent can read its labels, properties and existence.
/// And it is **unfixable in place**. Migration 074's `claims_block_widening`
/// refuses to make a sealed claim public, but it is a `BEFORE UPDATE` trigger
/// and cannot see an INSERT that starts out public — the row would have to be
/// unsealed before it could be corrected.
///
/// # Why this is an invariant test and not an HTTP test
///
/// Driving the handler needs a group, an active key epoch, a live membership,
/// base64 ciphertext and a bearer token, and it would pin ONE writer. The
/// property is corpus-wide and belongs to every writer, including the ones
/// PR-21 adds. `ClaimEncryptionRepository::insert_conn` has exactly one
/// production caller today (`routes/claims.rs::create_claim`); when PR-21 adds
/// the seal/unseal protocol it will add more, and this is what they have to
/// keep true.
///
/// The INSERT-side enforcement — a trigger on `claim_encryption` refusing to
/// seal a public claim — is deliberately NOT added here. `claim_encryption`'s
/// writers are PR-21's to rewrite, and its acceptance line already owns
/// "seal-then-declassify raises 42501 unconditionally". This test is the
/// standing measurement until then.
#[sqlx::test(migrations = "../../migrations")]
async fn no_sealed_claim_is_publicly_visible(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "sealed").await;
    let sealed = group_claim(&pool, agent, group, "sealed content").await;

    let epoch: i32 = sqlx::query_scalar(
        "INSERT INTO group_key_epochs (group_id, epoch, wrapped_key, status) \
         VALUES ($1, 1, ''::bytea, 'active') \
         ON CONFLICT (group_id, epoch) DO UPDATE SET status = 'active' RETURNING epoch",
    )
    .bind(group)
    .fetch_one(&pool)
    .await
    .expect("key epoch");
    sqlx::query(
        "INSERT INTO claim_encryption (claim_id, group_id, epoch, privacy_tier, encrypted_content) \
         VALUES ($1, $2, $3, 'fully_private', ''::bytea)",
    )
    .bind(sealed)
    .bind(group)
    .bind(epoch)
    .execute(&pool)
    .await
    .expect("seal the claim");

    // NOT VACUOUS. The join must actually reach the sealed row — without this,
    // an empty `claim_encryption` would make the invariant below pass on any
    // tree at all, including one where every sealed claim was public.
    let sealed_count: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM claims c \
          WHERE EXISTS (SELECT 1 FROM claim_encryption e WHERE e.claim_id = c.id)",
    )
    .fetch_one(&pool)
    .await
    .expect("sealed census");
    assert_eq!(
        sealed_count, 1,
        "the fixture must have produced exactly one sealed claim for the invariant \
         below to be measuring anything"
    );

    let leaked: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM claims c \
          WHERE c.visibility = 'public' \
            AND EXISTS (SELECT 1 FROM claim_encryption e WHERE e.claim_id = c.id)",
    )
    .fetch_one(&pool)
    .await
    .expect("sealed-and-public probe");
    assert_eq!(
        leaked, 0,
        "a claim with a claim_encryption row must never be visibility='public'. \
         Its content is a [sealed:uuid] stub, so 'public' discloses the row's \
         existence, labels and properties to every authenticated agent while \
         disclosing nothing anyone can act on — and claims_block_widening cannot \
         repair it, because that trigger fires on UPDATE and this state is \
         reachable only by INSERT."
    );
}

// =============================================================================
// `consolidate` — the meet rule, end to end (plan §4.6)
// =============================================================================

async fn consolidate_sources(
    pool: &PgPool,
    agent: Uuid,
    a: (Option<Uuid>, &str),
    b: (Option<Uuid>, &str),
) -> Vec<Uuid> {
    let mut out = Vec::new();
    for (i, (grp, content)) in [a, b].into_iter().enumerate() {
        let id = match grp {
            Some(g) => fixture::seed_group_claim(pool, agent, g, content).await,
            None => fixture::seed_public_claim(pool, agent, content).await,
        };
        assert!(i < 2);
        out.push(id);
    }
    out
}

/// Same group in, same group out.
#[sqlx::test(migrations = "../../migrations")]
async fn consolidate_within_one_group_keeps_the_group(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "cons-same").await;
    let src = consolidate_sources(&pool, agent, (Some(group), "s1"), (Some(group), "s2")).await;

    let r = ClaimRepository::consolidate(
        &pool,
        &src,
        "merged",
        0.8,
        ConsolidateMode::Merge,
        "test",
        agent,
    )
    .await
    .expect("same-group merge");

    assert_eq!(
        tenancy_of(&pool, "claims", r.merged_id).await,
        (group, "group".to_string())
    );
}

/// Mixed visibility: ANY group source makes the merge group-visible.
///
/// The other direction would be a one-statement declassification — merge a
/// private claim with a public one and read the private content off the public
/// result.
#[sqlx::test(migrations = "../../migrations")]
async fn consolidate_of_a_public_and_a_private_source_is_private(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "cons-mixed").await;
    let src = consolidate_sources(
        &pool,
        agent,
        (None, "public source"),
        (Some(group), "private"),
    )
    .await;

    let r = ClaimRepository::consolidate(
        &pool,
        &src,
        "merged mixed",
        0.8,
        ConsolidateMode::Merge,
        "test",
        agent,
    )
    .await
    .expect("mixed merge");

    assert_eq!(
        tenancy_of(&pool, "claims", r.merged_id).await,
        (group, "group".to_string()),
        "a merge that inherited the PUBLIC side would publish the private source's \
         content under a new id, with no audit trail and no author consent"
    );
}

/// Two different owner groups: **REFUSED**, naming NEITHER group to the caller.
///
/// This is a deliberate behaviour change on a live MCP tool
/// (`consolidate_claims`): a call that succeeded before PR-16 now returns an
/// error. It is not a regression. Merging claims owned by two groups into one
/// row discloses each group's content to the other, and neither authorized it;
/// picking a winner and picking the world group are both disclosures, and
/// refusing is the only answer that is not.
#[sqlx::test(migrations = "../../migrations")]
async fn consolidate_across_two_groups_is_refused(pool: PgPool) {
    let (agent, g1) = fixture::seed_agent_with_group(&pool, "cons-a").await;
    let (_other, g2) = fixture::seed_agent_with_group(&pool, "cons-b").await;
    let src = consolidate_sources(&pool, agent, (Some(g1), "in g1"), (Some(g2), "in g2")).await;

    let err = ClaimRepository::consolidate(
        &pool,
        &src,
        "merged across groups",
        0.8,
        ConsolidateMode::Merge,
        "test",
        agent,
    )
    .await
    .expect_err("a cross-group merge must be refused");

    assert!(
        matches!(err, epigraph_db::DbError::Conflict { .. }),
        "the refusal must be a Conflict (HTTP 409), not a 500 or a validation error: \
         {err:?}"
    );
    // The message must name NEITHER group. `consolidate` refuses a cross-group
    // merge without requiring the caller to be a member of either group, so a
    // 409 carrying the owner UUIDs would be an oracle over the private
    // ownership graph: name two claim ids you cannot read, learn who owns them.
    // The pair is preserved on `ConsolidateTenancyError::CrossGroup` and logged
    // at `warn!` by the repo, which is where an operator reads it.
    let msg = err.to_string();
    assert!(
        !msg.contains(&g1.to_string()) && !msg.contains(&g2.to_string()),
        "the 409 must not disclose either owner group to a caller who may be \
         entitled to read neither source: {msg}"
    );
    assert!(
        msg.contains("owned by more than one group"),
        "the refusal must still say WHY, so the caller can act on it: {msg}"
    );

    // And nothing was written: the refusal happens inside the transaction, so a
    // partial merge cannot survive it.
    let leftovers: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM claims WHERE content = 'merged across groups'",
    )
    .fetch_one(&pool)
    .await
    .expect("leftover probe");
    assert_eq!(
        leftovers, 0,
        "a refused merge must leave no merged row behind"
    );
}

/// All-public sources merge public, owned by the ACTING agent's own group.
///
/// Not the world group: §8.2 A4 forbids world-owned claims, so the fallback
/// arm of the meet rule has to name a real group and the actor's personal one
/// is the only one in scope.
#[sqlx::test(migrations = "../../migrations")]
async fn consolidate_of_public_sources_lands_in_the_actors_own_group(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "cons-pub").await;
    let src = consolidate_sources(&pool, agent, (None, "p1"), (None, "p2")).await;

    let r = ClaimRepository::consolidate(
        &pool,
        &src,
        "merged public",
        0.8,
        ConsolidateMode::Merge,
        "test",
        agent,
    )
    .await
    .expect("public merge");

    let (owner, vis) = tenancy_of(&pool, "claims", r.merged_id).await;
    assert_eq!(vis, "public");
    assert_eq!(
        owner, group,
        "the merged row must be owned by the acting agent's personal group"
    );
    assert_ne!(owner, WORLD, "plan §8.2 A4: no claim may be world-owned");
}

// =============================================================================
// The validate migrations
// =============================================================================

/// 075 and 076 leave no tenancy constraint `NOT VALID`.
///
/// A `NOT VALID` constraint IS enforced on new rows; what it does not do is
/// certify the rows already there. Leaving `claims_owner_group_fkey` unvalidated
/// means the corpus may still contain an `owner_group_id` pointing at no group
/// — a row whose owner cannot be resolved, which every later policy and
/// privatization plan would silently skip.
#[sqlx::test(migrations = "../../migrations")]
async fn migrations_075_and_076_validate_every_tenancy_constraint(pool: PgPool) {
    let unvalidated: Vec<(String, String)> = sqlx::query_as(
        "SELECT c.relname, con.conname \
           FROM pg_constraint con \
           JOIN pg_class c ON c.oid = con.conrelid \
           JOIN pg_namespace n ON n.oid = c.relnamespace \
          WHERE n.nspname = 'public' AND NOT con.convalidated \
          ORDER BY 1, 2",
    )
    .fetch_all(&pool)
    .await
    .expect("NOT VALID probe");

    assert!(
        unvalidated.is_empty(),
        "migrations 075/076 must validate every constraint migrations 062/068/072 \
         added NOT VALID. Still unvalidated: {unvalidated:?}"
    );
}

/// 074, 075 and 076 are all idempotent — the property a `lock_timeout` abort
/// depends on.
///
/// sqlx records no `_sqlx_migrations` row for a failed migration, so a file
/// that aborted on `SET LOCAL lock_timeout = '3s'` is re-run on the next
/// restart. A migration that is not re-runnable turns a transient lock wait
/// into a permanent deploy outage.
#[sqlx::test(migrations = "../../migrations")]
async fn the_pr16_migrations_can_be_applied_twice(pool: PgPool) {
    for file in [
        "074_tenancy_required.sql",
        "075_validate_tenancy_claims.sql",
        "076_validate_tenancy_remaining.sql",
    ] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../migrations")
            .join(file);
        let sql = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        pool.execute(sql.as_str()).await.unwrap_or_else(|e| {
            panic!("{file} must be idempotent, but re-applying it failed: {e}")
        });
    }

    // And the re-application did not undo anything: A1 still holds.
    let offenders: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM information_schema.columns \
          WHERE table_schema='public' AND column_name IN ('visibility','owner_group_id') \
            AND (column_default IS NOT NULL OR is_nullable='YES')",
    )
    .fetch_one(&pool)
    .await
    .expect("A1 re-probe");
    assert_eq!(offenders, 0);
}

// ===========================================================================
// The declaration ROUND-TRIPS — the writers store what the caller declared
//
// Every one of the ~40 converted call sites in this workspace passes
// `TenancyDecl::Inherited`, which binds SQL NULL for BOTH columns. That makes
// the whole suite blind to the defect class this conversion is most exposed
// to: FOUR of the six converted `ClaimRepository` writers
// (`create_with_tx`, `create_strict`, `create_with_id_if_absent`,
// `batch_create`) build their INSERT with runtime `sqlx::query`/`query_as` and
// UNTYPED `.bind()`. Swapping `decl.visibility_bind()` for
// `decl.owner_group_bind()`, or dropping one of the two, compiles cleanly and
// passes every existing test — because with `Inherited` both binds are NULL
// and Postgres infers each parameter's type from its column.
//
// `batch_create` is the sharpest case: this PR rewrote its placeholder
// arithmetic from a hardcoded 8-tuple `format!` to a `PARAMS_PER_ROW = 10`
// loop and appended the two tenancy binds inside the per-row loop. A stride
// error there transposes or drops tenancy in production while all four gates
// stay green. So `batch_create` is exercised with THREE claims, to cross two
// row boundaries.
//
// These cases also answer the "is the suite's green partly the seed escape
// hatch?" question: a declaration of `group(G)` that reads back `(G, 'group')`
// is not satisfiable by migration 074's arm 4, which stamps
// `('public', <seed group>)`.
// ===========================================================================

/// A `Claim` for `agent`, not inserted.
fn unsaved_claim(agent: Uuid, content: &str) -> epigraph_core::Claim {
    epigraph_core::Claim::new(
        content.to_string(),
        epigraph_core::AgentId::from_uuid(agent),
        [0u8; 32],
        epigraph_core::TruthValue::new(0.7).expect("0.7 is in [0,1]"),
    )
}

#[sqlx::test(migrations = "../../migrations")]
async fn create_stores_the_declared_tenancy(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "rt-create").await;

    let private = ClaimRepository::create(
        &pool,
        &unsaved_claim(agent, "create declares group"),
        epigraph_core::TenancyDecl::group(group),
    )
    .await
    .expect("create with an explicit group declaration");
    assert_eq!(
        tenancy_of(&pool, "claims", private.id.into()).await,
        (group, "group".to_string())
    );

    let public = ClaimRepository::create(
        &pool,
        &unsaved_claim(agent, "create declares public"),
        epigraph_core::TenancyDecl::public(group),
    )
    .await
    .expect("create with an explicit public declaration");
    assert_eq!(
        tenancy_of(&pool, "claims", public.id.into()).await,
        (group, "public".to_string()),
        "`public(G)` means world-READABLE but G-OWNED; binding the visibility \
         into owner_group_id (or vice versa) would show up here"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn create_with_tx_stores_the_declared_tenancy(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "rt-withtx").await;
    let mut tx = pool.begin().await.expect("begin");

    let private = ClaimRepository::create_with_tx(
        &mut tx,
        &unsaved_claim(agent, "with_tx declares group"),
        epigraph_core::TenancyDecl::group(group),
    )
    .await
    .expect("create_with_tx group");
    let public = ClaimRepository::create_with_tx(
        &mut tx,
        &unsaved_claim(agent, "with_tx declares public"),
        epigraph_core::TenancyDecl::public(group),
    )
    .await
    .expect("create_with_tx public");
    tx.commit().await.expect("commit");

    assert_eq!(
        tenancy_of(&pool, "claims", private.id.into()).await,
        (group, "group".to_string())
    );
    assert_eq!(
        tenancy_of(&pool, "claims", public.id.into()).await,
        (group, "public".to_string())
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn create_strict_stores_the_declared_tenancy(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "rt-strict").await;
    let mut conn = pool.acquire().await.expect("acquire");

    let private = ClaimRepository::create_strict(
        &mut conn,
        &unsaved_claim(agent, "strict declares group"),
        epigraph_core::TenancyDecl::group(group),
    )
    .await
    .expect("create_strict group");
    let public = ClaimRepository::create_strict(
        &mut conn,
        &unsaved_claim(agent, "strict declares public"),
        epigraph_core::TenancyDecl::public(group),
    )
    .await
    .expect("create_strict public");
    drop(conn);

    assert_eq!(
        tenancy_of(&pool, "claims", private.id.into()).await,
        (group, "group".to_string())
    );
    assert_eq!(
        tenancy_of(&pool, "claims", public.id.into()).await,
        (group, "public".to_string())
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn create_or_get_stores_the_declared_tenancy_on_the_insert_arm(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "rt-orget").await;
    let viewer = fixture::public_viewer(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");

    let claim = unsaved_claim(agent, "or_get declares public");
    let (first, created) = ClaimRepository::create_or_get(
        &mut conn,
        &viewer,
        &claim,
        epigraph_core::TenancyDecl::public(group),
    )
    .await
    .expect("create_or_get insert arm");
    assert!(created, "precondition: the first call must INSERT");
    assert_eq!(
        tenancy_of(&pool, "claims", first.id.into()).await,
        (group, "public".to_string())
    );

    // And the GET arm does not re-declare: the row keeps the tenancy the
    // INSERT that created it decided, not whatever this caller passed.
    let (again, created_again) = ClaimRepository::create_or_get(
        &mut conn,
        &viewer,
        &claim,
        epigraph_core::TenancyDecl::group(group),
    )
    .await
    .expect("create_or_get get arm");
    assert!(!created_again, "the second call must take the GET arm");
    assert_eq!(
        tenancy_of(&pool, "claims", again.id.into()).await,
        (group, "public".to_string()),
        "a GET must not silently re-tenant a row an earlier, different request \
         declared"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn create_with_id_if_absent_stores_the_declared_tenancy(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "rt-ifabsent").await;

    for (visibility, decl) in [
        ("group", epigraph_core::TenancyDecl::group(group)),
        ("public", epigraph_core::TenancyDecl::public(group)),
    ] {
        let id = Uuid::new_v4();
        let content = format!("if_absent declares {visibility}");
        let hash = epigraph_crypto::ContentHasher::hash(content.as_bytes());
        let inserted = ClaimRepository::create_with_id_if_absent(
            &pool,
            id,
            &content,
            &hash,
            agent,
            epigraph_core::TruthValue::new(0.6).expect("0.6 is in [0,1]"),
            &[],
            decl,
        )
        .await
        .expect("create_with_id_if_absent");
        assert!(inserted, "precondition: a fresh id must INSERT");
        assert_eq!(
            tenancy_of(&pool, "claims", id).await,
            (group, visibility.to_string())
        );
    }
}

/// THREE claims, so the `PARAMS_PER_ROW = 10` stride crosses two boundaries.
///
/// With two rows an off-by-one stride can still land on a compatible type by
/// accident; with three, the third row's placeholders are wrong by twice the
/// error and the INSERT either raises or mis-tenants a row this reads back.
#[sqlx::test(migrations = "../../migrations")]
async fn batch_create_stores_the_declared_tenancy_across_row_boundaries(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "rt-batch").await;

    let claims: Vec<epigraph_core::Claim> = (0..3)
        .map(|i| unsaved_claim(agent, &format!("batch row {i}")))
        .collect();
    let created =
        ClaimRepository::batch_create(&pool, &claims, epigraph_core::TenancyDecl::group(group))
            .await
            .expect("batch_create group");
    assert_eq!(created.len(), 3);
    for c in &created {
        assert_eq!(
            tenancy_of(&pool, "claims", c.id.into()).await,
            (group, "group".to_string()),
            "every row of the batch must carry the declaration, not just the first"
        );
    }

    // And the content survived the same stride: a transposed bind would put a
    // uuid where the content goes, or shift each row's content by one.
    let mut contents: Vec<String> = created.iter().map(|c| c.content.clone()).collect();
    contents.sort();
    assert_eq!(
        contents,
        vec![
            "batch row 0".to_string(),
            "batch row 1".to_string(),
            "batch row 2".to_string()
        ]
    );

    let public = ClaimRepository::batch_create(
        &pool,
        &(0..2)
            .map(|i| unsaved_claim(agent, &format!("batch public {i}")))
            .collect::<Vec<_>>(),
        epigraph_core::TenancyDecl::public(group),
    )
    .await
    .expect("batch_create public");
    for c in &public {
        assert_eq!(
            tenancy_of(&pool, "claims", c.id.into()).await,
            (group, "public".to_string())
        );
    }
}

/// `consolidate` refuses to merge INTO a group the actor is not a member of.
///
/// The meet rule this PR adds is the right rule, but it changes the SHAPE of
/// `consolidate`'s missing authorization: before migration 074 a cross-tenant
/// merge landed on the world default and merely DISCLOSED; now the merged row
/// lands inside the owning group, so an unrelated caller would be writing its
/// own content into a foreign group's private corpus while retiring that
/// group's claims through the `supersedes` forwarding.
///
/// The full write-side gate is 16b. This is the narrow refusal that keeps 16a's
/// own rule from creating the primitive 16b would have to close.
#[sqlx::test(migrations = "../../migrations")]
async fn consolidate_into_a_group_the_actor_is_not_in_is_refused(pool: PgPool) {
    let (outsider, _own) = fixture::seed_agent_with_group(&pool, "cons-outsider").await;
    let (_member, foreign) = fixture::seed_agent_with_group(&pool, "cons-foreign").await;

    // Both sources are private to `foreign`, so the CROSS-group arm does not
    // fire — this isolates the membership refusal.
    let src = consolidate_sources(
        &pool,
        outsider,
        (Some(foreign), "foreign s1"),
        (Some(foreign), "foreign s2"),
    )
    .await;

    let err = ClaimRepository::consolidate(
        &pool,
        &src,
        "merged into a group I am not in",
        0.8,
        ConsolidateMode::Merge,
        "test",
        outsider,
    )
    .await
    .expect_err("a merge into a foreign group must be refused");

    assert!(
        matches!(err, epigraph_db::DbError::Conflict { .. }),
        "the refusal must be a Conflict (HTTP 409): {err:?}"
    );
    let msg = err.to_string();
    assert!(
        !msg.contains(&foreign.to_string()),
        "the 409 must not name the group: the caller cannot read either source, \
         so naming its owner would be an oracle over the ownership graph: {msg}"
    );

    let leftovers: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM claims WHERE content = 'merged into a group I am not in'",
    )
    .fetch_one(&pool)
    .await
    .expect("leftover probe");
    assert_eq!(leftovers, 0, "a refused merge must write nothing");

    // The sources are untouched: not retired, still current.
    let still_current: i64 =
        sqlx::query_scalar("SELECT count(*)::bigint FROM claims WHERE id = ANY($1) AND is_current")
            .bind(&src)
            .fetch_one(&pool)
            .await
            .expect("source probe");
    assert_eq!(
        still_current, 2,
        "a refused merge must not retire the foreign group's claims"
    );
}

/// A revoked membership is not a membership.
#[sqlx::test(migrations = "../../migrations")]
async fn consolidate_refuses_once_the_actors_membership_is_revoked(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "cons-revoked").await;
    let src = consolidate_sources(&pool, agent, (Some(group), "r1"), (Some(group), "r2")).await;

    sqlx::query("UPDATE group_memberships SET revoked_at = now() WHERE agent_id = $1")
        .bind(agent)
        .execute(&pool)
        .await
        .expect("revoke");

    let err = ClaimRepository::consolidate(
        &pool,
        &src,
        "merged after revocation",
        0.8,
        ConsolidateMode::Merge,
        "test",
        agent,
    )
    .await
    .expect_err("a revoked member must not merge into the group");
    assert!(
        matches!(err, epigraph_db::DbError::Conflict { .. }),
        "{err:?}"
    );
}
