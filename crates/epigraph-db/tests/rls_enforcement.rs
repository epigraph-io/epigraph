//! PR-17: does row-level security actually filter, and does the application
//! still work under it?
//!
//! # THE VACUITY PROBLEM, WHICH IS THE WHOLE DESIGN CONSTRAINT OF THIS FILE
//!
//! `DATABASE_URL` is `epigraph` in CI (`.github/workflows/ci.yml`) and on every
//! developer host. That role is `rolsuper` and `rolbypassrls`, and it OWNS every
//! protected table. In PostgreSQL a policy filters every role except the owner
//! and `BYPASSRLS` holders, so **a test that connects on `DATABASE_URL` and
//! asserts anything about row visibility passes vacuously** — a completely wrong
//! policy set, or none at all, is invisible to it.
//!
//! `epigraph_app` is `NOLOGIN` (migration 060) and there is no second
//! login-capable non-bypass role, so there is no second DSN to open either. The
//! only lever is `SET SESSION AUTHORIZATION`, which is superuser-only and is
//! exactly what `viewer_fixture::as_role` wraps. **Every behavioural test in
//! this file goes through it**, and each one carries a calibration assertion
//! showing the instrument can fail — a negative-only suite is satisfied by a
//! policy that returns nothing to anybody.
//!
//! `grant_app_privileges` is called first in each, because migration 060 issues
//! no GRANT of its own and a bare `as_role` block dies on
//! `42501 permission denied for table claims` — a plausible-looking error that
//! has nothing to do with tenancy and would mask the assertion under test.
//! (Migration 077 now issues those grants too; the fixture call is kept because
//! it is what makes the test independent of that.)
//!
//! # The three classes here
//!
//! * **Catalog** — the `pg_policy.polcmd` per-command coverage table. Plan §0.2
//!   D4 requires it to be enumerated FROM THE CATALOG, never from the migration
//!   text; that is what would have caught the `agents` FOR-SELECT-only trap.
//!   A catalog check proves a policy EXISTS per command; it never proves the
//!   policy FILTERS. That is why it is only part of the file.
//! * **Behavioural** — the named regressions and the acceptance items, each run
//!   as a non-owner, non-bypass role against real repository code wherever one
//!   exists.
//! * **Unstamped-negative, and the predicate-shape ratchet** — added after
//!   review found three policy arms that referenced only ROW columns and
//!   therefore filtered nothing. The first two classes were both green through
//!   that, and the reason is worth stating: the catalog half scores `USING
//!   (true)` as full SELECT coverage, and every behavioural test stamped the
//!   session GUCs before asserting, so none of them constructed the state a
//!   request-path connection is actually in. See the section header further
//!   down.

mod viewer_fixture;

use sqlx::PgPool;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;
use viewer_fixture as fixture;

/// Commands a policy can cover, as `pg_policy.polcmd` spells them.
///
/// `'*'` is `FOR ALL` and covers all four.
const COMMANDS: &[(char, &str)] = &[
    ('r', "SELECT"),
    ('a', "INSERT"),
    ('w', "UPDATE"),
    ('d', "DELETE"),
];

/// Commands deliberately left uncovered, with the reason, as
/// `(table, command, why)`.
///
/// **This is an exact-set ratchet.** A table/command pair that stops being
/// covered and is not listed here fails the build, and a pair listed here that
/// IS covered fails it too — so the register cannot rot in either direction.
/// Plan §0.2 D4 asks for exactly this shape: "every table with `visibility` has
/// an RLS policy for each of SELECT/INSERT/UPDATE/DELETE, **or a recorded
/// exemption**".
///
/// Every entry is a default-deny. An absent policy in PostgreSQL denies the
/// command outright; none of these is a permissive gap.
const DELIBERATELY_UNCOVERED: &[(&str, &str, &str)] = &[
    (
        "agents",
        "DELETE",
        "Agents are never deleted through the app role. An agent row IS a \
         principal and is referenced by claims.agent_id; deletion is a \
         maintenance operation on the maintenance pool, where epigraph_bypass() \
         admits it.",
    ),
    (
        "security_events",
        "UPDATE",
        "The actor log is append-only. Default-deny is now one of three \
         controls, not the whole of it: PR-18a's migration 082 adds the \
         `security_events_no_mutate` BEFORE UPDATE OR DELETE trigger and \
         REVOKEs UPDATE and DELETE from epigraph_app. The pair stays HERE and \
         not deleted because a trigger is not a `pg_policy` row — the command \
         is still uncovered, which is what this register measures.",
    ),
    (
        "security_events",
        "DELETE",
        "Same as UPDATE: an actor must not be able to erase its own audit \
         trail. The plan put the trigger 'in 078'; under migrations/README.md \
         that is PR-18's 082, which now ships it. The trigger is the control \
         that also binds the TABLE OWNER, which RLS does not; the REVOKE and \
         this default-deny are the other two.",
    ),
    // ---- PR-18a: the four D4 tables. -------------------------------------
    //
    // 080 creates `privatization_plans` and `privatization_plan_items` with
    // ENABLE + FORCE and NO POLICY AT ALL, which is full default deny on all
    // four commands. That is deliberate and it is the honest posture for
    // PR-18a, which ships no reader and no writer of either table: the preview
    // routes are 18b and the apply/revert handlers are 18c. A read policy with
    // no consumer is a grant nobody asked for.
    //
    // Because this register is exact in BOTH directions, a slice cannot add a
    // policy to either table without deleting the matching row here in the same
    // commit — which is the property that makes the eight rows worth their
    // weight rather than boilerplate.
    //
    // AMENDED TWICE. The first amendment recorded that 18b's SECOND slice did
    // not do what the paragraph above predicts: it shipped the selection pass as
    // a repo-layer computation with no route, no persisted plan and therefore no
    // policy, because adding one needs a migration and no number was assigned to
    // it. THE THIRD SLICE CLAIMED 087 AND DID. The four SELECT/INSERT pairs the
    // paragraph above predicted are gone from this register, deleted in the same
    // commit as `migrations/087_privatization_plan_policies.sql`, which is the
    // property that makes the remaining rows worth their weight.
    //
    // What is left is UPDATE and DELETE on both tables, and their owners are
    // unchanged. Migration 080's header states the whole-slice expectation and
    // is FROZEN by the applied-checksum rule, so it cannot be corrected there;
    // that disagreement is recorded rather than resolved by silence, which is
    // this register's own culture rule.
    (
        "privatization_plans",
        "UPDATE",
        "State transitions (approve, dispatch, cursor advance) are 18c's \
         apply/revert handlers, on the maintenance pool.",
    ),
    (
        "privatization_plans",
        "DELETE",
        "A plan is the record that a privatization was attempted and is never \
         deleted. Nothing is expected to claim this pair.",
    ),
    (
        "privatization_plan_items",
        "UPDATE",
        "Per-item state (applied/skipped/failed/reverted) is 18c's handler.",
    ),
    (
        "privatization_plan_items",
        "DELETE",
        "Items cascade with their plan and are never deleted individually; the \
         FK carries ON DELETE CASCADE, which does not consult a policy.",
    ),
    (
        "privatization_audit",
        "UPDATE",
        "Append-only, by the same three controls as security_events: 082's \
         `privatization_audit_no_mutate` trigger, its REVOKE of UPDATE and \
         DELETE from epigraph_app, and this default-deny. The trigger is the \
         only one of the three that also binds the table owner.",
    ),
    (
        "privatization_audit",
        "DELETE",
        "Same as UPDATE. The audit trail of a privatization outlives the plan \
         it describes; the FK to privatization_plans is ON DELETE RESTRICT \
         precisely so a plan cannot take its own record with it.",
    ),
    (
        "instance_admins",
        "DELETE",
        "Revocation is a `revoked_at` stamp, never a DELETE: the row is the \
         record that the authority once existed. 083 grants INSERT and UPDATE \
         to a bypass-only policy pair so the operator CLI can grant and revoke \
         on the maintenance role, and deliberately stops short of FOR ALL, \
         which would have covered DELETE too.",
    ),
];

/// Every relation the migrations FORCE.
///
/// Transcribed, not derived: a test that asked the catalog which relations are
/// protected and then checked that those relations are protected would pass
/// whatever the migration did. `rls_canary` is absent because 078 FORCEs it at
/// creation and 079's array omits it.
///
/// # It was "079's array" until PR-18a
///
/// 079 flips thirty-five relations in one file. The four D4 tables are FORCEd by
/// the migrations that CREATE them — 080, 082 and 083 — because 079 is applied
/// and frozen, so this constant's referent is now the catalog's FORCEd set
/// rather than any one file's transcription.
/// `locked_decisions.rs::d4_the_force_array_is_tier_a_plus_the_control_tables`
/// is what pins the two together, and it is a TOTAL comparison against
/// `pg_class.relforcerowsecurity`.
const PROTECTED: &[&str] = &[
    "claims",
    "evidence",
    "edges",
    "triples",
    "entity_mentions",
    "claim_versions",
    "mass_functions",
    "ds_combined_beliefs",
    "ds_bayesian_divergence",
    "claim_frames",
    "harvester_claim_provenance",
    "challenges",
    "reasoning_traces",
    "experiment_triples",
    "experiment_entity_mentions",
    "claim_clusters",
    "claim_cluster_membership",
    "claim_neighborhood_membership",
    "claim_signature_revocations",
    "harvester_fragments",
    "frames",
    "contexts",
    "perspectives",
    "communities",
    "recall_events",
    "groups",
    "group_memberships",
    "group_key_epochs",
    "agents",
    "jobs",
    "security_events",
    "claim_encryption",
    "claim_version_encryption",
    "evidence_encryption",
    "edge_encryption",
    "privatization_plans",
    "privatization_plan_items",
    "privatization_audit",
    "instance_admins",
];

// ===========================================================================
// Catalog: the polcmd coverage table
// ===========================================================================

/// Every protected relation carries ENABLE **and** FORCE.
///
/// Both flags, not one. `repos/entity_type.rs` already pins the converse trap
/// in `force_without_enable_is_not_satisfied` — "with `relrowsecurity = false`
/// it applies NO policy at all" — and migration 079 refuses to run against a
/// table 077 missed, for the same reason.
#[sqlx::test(migrations = "../../migrations")]
async fn every_protected_relation_is_enabled_and_forced(pool: PgPool) {
    let rows: Vec<(String, bool, bool)> = sqlx::query_as(
        "SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity \
           FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
          WHERE n.nspname = 'public' AND c.relname = ANY($1) AND c.relkind IN ('r','p')",
    )
    .bind(PROTECTED)
    .fetch_all(&pool)
    .await
    .expect("catalog probe");

    assert_eq!(
        rows.len(),
        PROTECTED.len(),
        "PROTECTED names {} relations but only {} exist as ordinary tables. 079 RAISEs on a \
         missing name among its own thirty-five, and 080/082/083 create the four they FORCE, \
         so reaching this means the array and the schema disagree.",
        PROTECTED.len(),
        rows.len()
    );

    let bad: Vec<String> = rows
        .iter()
        .filter(|(_, en, fo)| !en || !fo)
        .map(|(t, en, fo)| format!("{t}(enable={en},force={fo})"))
        .collect();
    assert!(
        bad.is_empty(),
        "these protected relations are not fully armed: {bad:?}. ENABLE without FORCE leaves \
         the owner unfiltered; FORCE without ENABLE applies NO policy at all and denies every \
         row to every non-owner."
    );
}

/// **The per-command coverage table**, enumerated from `pg_policy`.
///
/// This is the assertion that would have caught the `agents` trap: with only a
/// `FOR SELECT` policy PostgreSQL default-denies INSERT and UPDATE, so
/// `AgentRepository::ensure_for_client` — and therefore every token mint —
/// would have been refused the day 079 landed, while a "policies exist" check
/// stayed green.
///
/// Read from the catalog, never from the migration text. A test that parsed
/// `077_rls_policies.sql` would agree with the migration by construction,
/// including when the migration is wrong.
#[sqlx::test(migrations = "../../migrations")]
async fn every_protected_relation_covers_every_command_or_records_why(pool: PgPool) {
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT c.relname, p.polname, p.polcmd::text \
           FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid \
           JOIN pg_namespace n ON n.oid = c.relnamespace \
          WHERE n.nspname = 'public'",
    )
    .fetch_all(&pool)
    .await
    .expect("pg_policy probe");
    assert!(
        !rows.is_empty(),
        "pg_policy is empty: migration 077 did not run, and every assertion below would be \
         vacuously satisfied"
    );

    // table -> set of covered command letters.
    let mut covered: BTreeMap<String, BTreeSet<char>> = BTreeMap::new();
    for (relname, _polname, cmd) in &rows {
        let c = cmd.chars().next().unwrap_or('?');
        let entry = covered.entry(relname.clone()).or_default();
        if c == '*' {
            for (letter, _) in COMMANDS {
                entry.insert(*letter);
            }
        } else {
            entry.insert(c);
        }
    }

    let exempt: BTreeSet<(&str, &str)> = DELIBERATELY_UNCOVERED
        .iter()
        .map(|(t, c, _)| (*t, *c))
        .collect();

    let mut gaps: BTreeSet<(String, String)> = BTreeSet::new();
    for table in PROTECTED {
        let have = covered.get(*table).cloned().unwrap_or_default();
        for (letter, name) in COMMANDS {
            if !have.contains(letter) {
                gaps.insert(((*table).to_string(), (*name).to_string()));
            }
        }
    }

    let declared: BTreeSet<(String, String)> = exempt
        .iter()
        .map(|(t, c)| ((*t).to_string(), (*c).to_string()))
        .collect();

    let undeclared: Vec<_> = gaps.difference(&declared).cloned().collect();
    assert!(
        undeclared.is_empty(),
        "these (table, command) pairs have NO policy and are therefore DEFAULT-DENIED, and \
         none of them is recorded in DELIBERATELY_UNCOVERED: {undeclared:?}. A silently \
         uncovered write command is how the agents FOR-SELECT-only trap (sec-F13) would have \
         broken every authentication. Either add the policy in a migration or add the pair \
         here with a reason."
    );

    let stale: Vec<_> = declared.difference(&gaps).cloned().collect();
    assert!(
        stale.is_empty(),
        "DELIBERATELY_UNCOVERED claims these pairs are uncovered, but a policy now covers \
         them: {stale:?}. Drop the entries — an exemption register that is not exact is a \
         comment style, not a control."
    );
}

/// `oauth_clients` must have NO policy: the other half of sec-F13.
///
/// The token mint's `UPDATE oauth_clients SET agent_id = $2` runs on an
/// unauthenticated endpoint where no principal, and therefore no principal GUC,
/// can exist. The table carries neither `visibility` nor `owner_group_id`, so
/// any tenancy-shaped policy on it would match zero rows and the whole OAuth
/// flow would die. Its absence from migration 079's array is load-bearing and
/// is pinned here so a later PR cannot "complete the set" by accident.
#[sqlx::test(migrations = "../../migrations")]
async fn oauth_clients_is_deliberately_unprotected(pool: PgPool) {
    let (policies, rls): (i64, bool) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM pg_policy p WHERE p.polrelid = 'public.oauth_clients'::regclass), \
                (SELECT c.relrowsecurity FROM pg_class c WHERE c.oid = 'public.oauth_clients'::regclass)",
    )
    .fetch_one(&pool)
    .await
    .expect("oauth_clients catalog probe");
    assert_eq!(
        policies, 0,
        "oauth_clients has {policies} policy/policies. It carries no tenancy columns, and the \
         token mint updates it with no principal GUC set — a policy here matches zero rows and \
         breaks every authentication (sec-F13)."
    );
    assert!(
        !rls,
        "oauth_clients has row security ENABLEd; with no policy that denies every row to every \
         non-owner, which is the same outage by a different route"
    );
}

// ===========================================================================
// Behavioural — all under `as_role("epigraph_app")`
// ===========================================================================

/// Bind the three session GUCs on a connection, the way `ScopedPool` does.
///
/// `acquire_as` cannot be used here: it takes a `ScopedPool`, and these tests
/// need a connection whose `session_user` has already been switched, which is a
/// property of the connection rather than of the pool.
async fn set_gucs(conn: &mut sqlx::PgConnection, groups: &str, writable: &str, principal: &str) {
    sqlx::query(
        "SELECT set_config('epigraph.group_ids', $1, false), \
                        set_config('epigraph.writable_group_ids', $2, false), \
                        set_config('epigraph.principal_id', $3, false)",
    )
    .bind(groups)
    .bind(writable)
    .bind(principal)
    .execute(&mut *conn)
    .await
    .expect("set session gucs");
}

/// **sec-F1, the positive class.** A `Scoped` viewer reads its own
/// group-private rows under FORCE.
///
/// Plan §0.5 and §8.4 P1: the suite is written entirely as "assert a stranger
/// CANNOT read", so **an over-restricting policy passes every existing case**.
/// This is the assertion that fails on a policy that filters too much — the
/// defect the whole of §4.5 exists to prevent, and the one that "would have
/// failed on the previous revision's design".
///
/// Both directions are asserted on the SAME connection, so the negative half
/// doubles as the calibration for the positive half: if the private row were
/// visible with no GUCs set, RLS would not be filtering at all and the second
/// assertion would prove nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn a_scoped_principal_reads_its_own_group_private_rows_under_force(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "secf1").await;
    let private = fixture::seed_group_claim(&pool, agent, group, "sec-F1 private").await;
    let public = fixture::seed_public_claim(&pool, agent, "sec-F1 public").await;
    fixture::grant_app_privileges(&pool, "epigraph_app").await;

    let (unstamped, stamped, public_seen) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            // No GUCs: the policy collapses to `visibility = 'public'`.
            set_gucs(&mut conn, "", "", "").await;
            let unstamped: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE id = $1")
                .bind(private)
                .fetch_one(&mut *conn)
                .await
                .expect("unstamped read");

            set_gucs(
                &mut conn,
                &group.to_string(),
                &group.to_string(),
                &agent.to_string(),
            )
            .await;
            let stamped: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE id = $1")
                .bind(private)
                .fetch_one(&mut *conn)
                .await
                .expect("stamped read");
            let public_seen: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE id = $1")
                .bind(public)
                .fetch_one(&mut *conn)
                .await
                .expect("public read");
            (conn, (unstamped, stamped, public_seen))
        })
        .await;

    assert_eq!(
        unstamped, 0,
        "CALIBRATION: with no session GUCs a group-private claim must be invisible. Seeing it \
         means RLS is not filtering this connection at all and the positive assertion below \
         proves nothing."
    );
    assert_eq!(
        stamped, 1,
        "sec-F1: a Scoped principal must read its OWN group-private claim under FORCE. Zero \
         here is the fail-closed defect — the row is invisible to its own owner, silently, \
         and it is indistinguishable from data loss."
    );
    assert_eq!(public_seen, 1, "a public claim stays readable");
}

/// **The `Viewer::resolve` chicken-and-egg**, which is sec-F1 one layer up.
///
/// `GroupMembershipRepository::list_live_for_agent` runs BEFORE any GUC is set,
/// because `acquire_as` needs the very `Viewer` it is constructing. Read
/// directly, `group_memberships` returns zero rows to an unstamped connection
/// and every viewer in the system resolves to an empty group set.
///
/// The two counts here are the entire argument: same connection, same
/// principal, same instant — one path returns the membership and the other does
/// not.
///
/// # The membership under test is in a TEAM group, deliberately
///
/// A team membership is reachable by no policy arm other than the session ones,
/// so the `direct == 0` calibration below is unambiguous. (An earlier draft of
/// 077 admitted `role = 'admin' AND epigraph_is_personal_group(…)` in USING, so
/// a PERSONAL membership was readable unstamped and would have made the
/// calibration fail for a correct-looking reason. That arm is gone — see
/// `no_policy_arm_is_session_independent` — but the team group is kept because
/// it is the stricter control either way.)
#[sqlx::test(migrations = "../../migrations")]
async fn viewer_resolve_still_sees_memberships_on_an_unstamped_connection(pool: PgPool) {
    let (agent, _personal) = fixture::seed_agent_with_group(&pool, "resolve").await;
    let group = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO groups (id, display_name, did_key, public_key, kind, created_by_agent_id) \
         VALUES ($1, 'resolve-team', 'did:probe:resolve-team', $2, 'team', $3)",
    )
    .bind(group)
    .bind(vec![7u8; 32])
    .bind(agent)
    .execute(&pool)
    .await
    .expect("seed team group");
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'writer')",
    )
    .bind(group)
    .bind(agent)
    .execute(&pool)
    .await
    .expect("seed team membership");
    fixture::grant_app_privileges(&pool, "epigraph_app").await;

    let (via_function, direct) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        set_gucs(&mut conn, "", "", "").await;
        let via_function: i64 =
            sqlx::query_scalar("SELECT count(*) FROM public.epigraph_live_memberships($1)")
                .bind(agent)
                .fetch_one(&mut *conn)
                .await
                .expect("definer read");
        let direct: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM group_memberships WHERE group_id = $1 AND revoked_at IS NULL",
        )
        .bind(group)
        .fetch_one(&mut *conn)
        .await
        .expect("direct read");
        (conn, (via_function, direct))
    })
    .await;

    assert_eq!(
        direct, 0,
        "CALIBRATION: a DIRECT read of group_memberships on an unstamped connection must be \
         filtered to nothing. If it is not, the policy is not filtering and the assertion \
         below proves nothing."
    );
    assert_eq!(
        via_function, 2,
        "Viewer::resolve reads through epigraph_live_memberships() precisely so it keeps \
         working here, and must return BOTH the personal and the team membership. Zero means \
         every viewer in the system resolves to group_ids = [] and the whole corpus narrows \
         to visibility='public' for its own owners."
    );
}

/// **sec-F13.** A token mint succeeds under FORCE as `epigraph_app`.
///
/// Goes through the REAL `AgentRepository::ensure_for_client`, not a
/// transcription of its SQL — the plan's own words are "without it, PR-17
/// breaks every authentication", and a transcription would drift.
///
/// The mint runs on an unauthenticated endpoint, so **no principal GUC is set**
/// — that is not an omission in this test, it is the defining condition of the
/// path. It exercises four separate policy decisions that the plan's sketch
/// denied: the `agents` upsert (both branches), the `groups` personal-group
/// upsert, and the `group_memberships` admin upsert.
///
/// Called TWICE. The second call takes every `ON CONFLICT DO UPDATE` branch,
/// which is the case that fails when a provisioning arm is present in
/// `WITH CHECK` but missing from `USING` — `INSERT … ON CONFLICT` is checked
/// against the SELECT-side policy, and on a `FOR ALL` policy that is the USING
/// clause. A single call passes with the bug still present.
#[sqlx::test(migrations = "../../migrations")]
async fn sec_f13_a_token_mint_succeeds_under_force_as_the_app_role(pool: PgPool) {
    let client_row_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO oauth_clients (id, client_id, client_name, client_type, \
                                    allowed_scopes, granted_scopes, status, \
                                    legal_entity_name, legal_contact_email) \
         VALUES ($1, $2, 'probe', 'service', ARRAY['claims:read'], ARRAY['claims:read'], \
                 'active', 'Probe Ltd', 'probe@example.invalid')",
    )
    .bind(client_row_id)
    .bind(client_row_id.to_string())
    .execute(&pool)
    .await
    .expect("seed oauth client");
    // `client_type = 'service'`, not `'agent'`: the latter requires `owner_id`
    // (`agents_must_have_owner`) and would send `ensure_for_client` down its
    // real-signer branch, which is a plain SELECT. The DERIVED branch is the one
    // that runs `INSERT INTO agents … ON CONFLICT DO UPDATE`, which is the
    // statement sec-F13 is about. `services_must_have_legal_entity` is why the
    // two legal columns are bound.
    fixture::grant_app_privileges(&pool, "epigraph_app").await;

    let (first, second) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        set_gucs(&mut conn, "", "", "").await;
        let first = epigraph_db::AgentRepository::ensure_for_client(&mut conn, client_row_id).await;
        let second =
            epigraph_db::AgentRepository::ensure_for_client(&mut conn, client_row_id).await;
        (conn, (first, second))
    })
    .await;

    let first = first.expect(
        "sec-F13: the first token mint must succeed as epigraph_app under FORCE. A failure \
         here means agents/groups/group_memberships deny provisioning and EVERY \
         authentication is broken.",
    );
    let second = second.expect(
        "sec-F13: the SECOND mint must succeed too — it takes the ON CONFLICT DO UPDATE \
         branches, which are checked against each policy's USING clause and not only its \
         WITH CHECK.",
    );
    assert_eq!(
        first, second,
        "ensure_for_client is idempotent: the same client must resolve to the same principal"
    );
}

/// **The canary**, both directions.
///
/// One integer is the whole posture, so it is asserted from both sides: zero on
/// a non-bypass connection, one on a bypassing one. Without the positive
/// control, a dropped table or a policy denying everybody would satisfy the
/// first assertion perfectly.
#[sqlx::test(migrations = "../../migrations")]
async fn the_canary_is_invisible_to_the_app_role_and_visible_under_bypass(pool: PgPool) {
    fixture::grant_app_privileges(&pool, "epigraph_app").await;

    let under_bypass: i64 = sqlx::query_scalar("SELECT count(*) FROM rls_canary")
        .fetch_one(&pool)
        .await
        .expect("canary read as owner");
    assert_eq!(
        under_bypass, 1,
        "POSITIVE CONTROL: migration 078 seeds exactly one canary row and the test connection \
         is a BYPASSRLS superuser, so it must see it. Zero means the row is missing and the \
         negative assertion below would pass on an empty table."
    );

    let as_app = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM rls_canary")
            .fetch_one(&mut *conn)
            .await
            .expect("canary read as app");
        (conn, n)
    })
    .await;
    assert_eq!(
        as_app, 0,
        "the canary MUST be invisible to epigraph_app. A visible row means row-level security \
         is not protecting this database — it is the single integer AppState::assert_rls_posture \
         refuses to boot on."
    );
}

/// A `recall_events` row with `agent_id IS NULL` is not visible to a session
/// whose principal GUC is unset.
///
/// Named on PR-17's *Acceptance* line. Without the `IS NOT NULL` conjunct the
/// predicate degenerates to `agent_id IS NOT DISTINCT FROM NULL`, which is TRUE
/// for every NULL-`agent_id` row — the exact inverse of the leak the policy
/// closes. The owned row is the calibration: it proves the principal arm works,
/// so a zero on the NULL row is filtering rather than a broken policy.
#[sqlx::test(migrations = "../../migrations")]
async fn a_null_agent_recall_event_is_invisible_without_a_principal(pool: PgPool) {
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "recall").await;
    sqlx::query(
        "INSERT INTO recall_events (agent_id, tool, query_text, visibility, owner_group_id) \
         VALUES (NULL, 'probe', 'orphan', 'public', '00000000-0000-0000-0000-000000000000')",
    )
    .execute(&pool)
    .await
    .expect("seed null-agent recall event");
    sqlx::query(
        "INSERT INTO recall_events (agent_id, tool, query_text, visibility, owner_group_id) \
         VALUES ($1, 'probe', 'owned', 'public', '00000000-0000-0000-0000-000000000000')",
    )
    .bind(agent)
    .execute(&pool)
    .await
    .expect("seed owned recall event");
    fixture::grant_app_privileges(&pool, "epigraph_app").await;

    let (orphan_unstamped, owned_stamped, orphan_stamped) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            set_gucs(&mut conn, "", "", "").await;
            let orphan_unstamped: i64 =
                sqlx::query_scalar("SELECT count(*) FROM recall_events WHERE query_text='orphan'")
                    .fetch_one(&mut *conn)
                    .await
                    .expect("orphan unstamped");

            set_gucs(&mut conn, "", "", &agent.to_string()).await;
            let owned_stamped: i64 =
                sqlx::query_scalar("SELECT count(*) FROM recall_events WHERE query_text='owned'")
                    .fetch_one(&mut *conn)
                    .await
                    .expect("owned stamped");
            let orphan_stamped: i64 =
                sqlx::query_scalar("SELECT count(*) FROM recall_events WHERE query_text='orphan'")
                    .fetch_one(&mut *conn)
                    .await
                    .expect("orphan stamped");
            (conn, (orphan_unstamped, owned_stamped, orphan_stamped))
        })
        .await;

    assert_eq!(
        orphan_unstamped, 0,
        "a NULL-agent_id recall event must NOT be visible to a session with no principal GUC. \
         Without the `IS NOT NULL` conjunct this reads 1 and every orphan row is world-readable."
    );
    assert_eq!(
        owned_stamped, 1,
        "CALIBRATION: with the principal GUC set, an agent must read its OWN recall events. \
         Zero here would mean the policy denies everybody and the assertions above are vacuous."
    );
    assert_eq!(
        orphan_stamped, 0,
        "a NULL-agent_id row is nobody's, so it stays invisible even to a stamped session"
    );
}

/// The `group_memberships` policy must not recurse.
///
/// Named on PR-17's *Acceptance* line. A policy ON `group_memberships` whose
/// `WITH CHECK` selects FROM `group_memberships` re-applies the policy to the
/// inner scan and raises `42P17 infinite recursion detected in policy for
/// relation "group_memberships"`. The `SECURITY DEFINER` helper closes it, and
/// the closure is real rather than relocated because the USING clause carries no
/// self-reference — so the inner scan is admitted by a constant.
///
/// A recursion failure is an ERROR, not a wrong row count, so the assertion is
/// that the statements complete at all. The INSERT is what matters: `WITH CHECK`
/// is not evaluated on a SELECT.
#[sqlx::test(migrations = "../../migrations")]
async fn group_memberships_policy_does_not_recurse(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "recurse").await;
    let (other, _) = fixture::seed_agent_with_group(&pool, "recurse2").await;
    fixture::grant_app_privileges(&pool, "epigraph_app").await;

    let (read, write) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        set_gucs(
            &mut conn,
            &group.to_string(),
            &group.to_string(),
            &agent.to_string(),
        )
        .await;
        let read = sqlx::query("SELECT count(*) FROM group_memberships")
            .execute(&mut *conn)
            .await;
        // `agent` is an admin of `group`, so `epigraph_is_group_admin` — the
        // self-referencing arm — is the disjunct that has to be evaluated.
        let write = sqlx::query(
            "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
             VALUES ($1, $2, ''::bytea, 0, 'reader')",
        )
        .bind(group)
        .bind(other)
        .execute(&mut *conn)
        .await;
        (conn, (read, write))
    })
    .await;

    read.expect("a SELECT on group_memberships must not raise 42P17 infinite recursion");
    write.expect(
        "an INSERT into group_memberships must not raise 42P17 infinite recursion. WITH CHECK \
         is where the self-referencing predicate lives and it is not evaluated on a SELECT, so \
         this statement is the one that actually tests it.",
    );
}

/// The four ownerless registries accept `TenancyDecl::instance_wide()`.
///
/// `('public', <world group>)` is the ONLY legal declaration for `frames`,
/// `contexts`, `perspectives` and `communities`, and the world group is
/// memberless by design — so it is in nobody's `epigraph_writable_groups()`,
/// ever. The plan deletes the world arm from every `WITH CHECK` on a rationale
/// that is correct for `claims` and wrong for these four; under the strict form
/// every frame, context, perspective and community write raises `42501`.
///
/// `claims` is the calibration and the guard: it must STILL refuse a world-owned
/// row, because §8.2 acceptance query A4 requires
/// `count(*) FROM claims WHERE owner_group_id = <world>` to stay at zero. If
/// this test passed on both, the arm would have been added far too widely.
#[sqlx::test(migrations = "../../migrations")]
async fn the_ownerless_registries_accept_instance_wide_but_claims_does_not(pool: PgPool) {
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "registry").await;
    fixture::grant_app_privileges(&pool, "epigraph_app").await;

    let (frame, ctx, claim) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        set_gucs(&mut conn, "", "", &agent.to_string()).await;
        let frame = sqlx::query(
            "INSERT INTO frames (id, name, description, hypotheses, visibility, owner_group_id) \
             VALUES (gen_random_uuid(), 'rls-probe', 'd', ARRAY['h1','h2'], 'public', \
                     '00000000-0000-0000-0000-000000000000')",
        )
        .execute(&mut *conn)
        .await;
        let ctx = sqlx::query(
            "INSERT INTO contexts (id, name, context_type, visibility, owner_group_id) \
             VALUES (gen_random_uuid(), 'rls-probe-ctx', 'probe', 'public', \
                     '00000000-0000-0000-0000-000000000000')",
        )
        .execute(&mut *conn)
        .await;
        let claim = sqlx::query(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current, \
                                 visibility, owner_group_id) \
             VALUES ('world-owned', $1, 0.5, $2, true, 'public', \
                     '00000000-0000-0000-0000-000000000000')",
        )
        .bind(vec![9u8; 32])
        .bind(agent)
        .execute(&mut *conn)
        .await;
        (conn, (frame, ctx, claim))
    })
    .await;

    frame.expect(
        "frames is an ownerless instance-wide registry: TenancyDecl::instance_wide() is its \
         ONLY legal declaration and repos/frame.rs binds it at two production sites. A refusal \
         here is a total outage on frame creation.",
    );
    ctx.expect("contexts is the same shape as frames; repos/context.rs binds instance_wide()");
    assert!(
        claim.is_err(),
        "claims must STILL refuse a world-owned row. §8.2 acceptance query A4 requires that \
         count to stay at zero, and TenancyDecl::instance_wide()'s own doc says it 'is not \
         available for claims'. Accepting it here would mean the registry arm was added to \
         the generic policy instead of only to the four registries."
    );
}

/// Group creation and the first admin membership succeed on the app pool.
///
/// The bootstrap is circular: at the instant the `groups` row is written the
/// creator is a member of nothing, so `epigraph_is_group_admin` is false and
/// `epigraph_session_groups()` cannot contain an id that did not exist when the
/// connection was stamped. `routes/groups.rs::create_group` and
/// `routes/community.rs` are live HTTP paths on the app pool, and both are
/// denied at three consecutive statements without the creator arm.
///
/// The negative half is the point of the arm being keyed on
/// `created_by_agent_id` rather than being permissive: you may bootstrap a group
/// you declare YOURSELF the creator of, and no other.
#[sqlx::test(migrations = "../../migrations")]
async fn a_principal_can_create_a_group_and_enrol_itself_but_not_impersonate(pool: PgPool) {
    let (agent, _g) = fixture::seed_agent_with_group(&pool, "creator").await;
    let (victim, _v) = fixture::seed_agent_with_group(&pool, "victim").await;
    fixture::grant_app_privileges(&pool, "epigraph_app").await;

    let (created, enrolled, impersonated) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            set_gucs(&mut conn, "", "", &agent.to_string()).await;
            let new_group = Uuid::new_v4();
            let created = sqlx::query(
                "INSERT INTO groups (id, display_name, did_key, public_key, kind, \
                                     created_by_agent_id) \
                 VALUES ($1, 'boot', 'did:probe:' || $1::text, $2, 'team', $3)",
            )
            .bind(new_group)
            .bind(vec![3u8; 32])
            .bind(agent)
            .execute(&mut *conn)
            .await;
            let enrolled = sqlx::query(
                "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, \
                                                role) \
                 VALUES ($1, $2, ''::bytea, 0, 'admin')",
            )
            .bind(new_group)
            .bind(agent)
            .execute(&mut *conn)
            .await;
            let impersonated = sqlx::query(
                "INSERT INTO groups (id, display_name, did_key, public_key, kind, \
                                     created_by_agent_id) \
                 VALUES (gen_random_uuid(), 'evil', 'did:probe:evil', $1, 'team', $2)",
            )
            .bind(vec![4u8; 32])
            .bind(victim)
            .execute(&mut *conn)
            .await;
            (conn, (created, enrolled, impersonated))
        })
        .await;

    created.expect(
        "GroupRepository::create_with_admin writes this row on the APP pool from \
         routes/groups.rs::create_group; a refusal is a total outage on group creation",
    );
    enrolled.expect(
        "the creator's own first admin membership is written in the same transaction, before \
         any membership-keyed predicate can be true",
    );
    assert!(
        impersonated.is_err(),
        "the bootstrap arm is keyed on created_by_agent_id = the principal. Creating a group \
         attributed to somebody else must be refused, or the arm would be a permissive hole \
         rather than a bootstrap."
    );
}

// ===========================================================================
// The unstamped-negative class, and the predicate-shape ratchet
//
// WHY THIS SECTION EXISTS. An earlier draft of 077 shipped three arms that
// referenced only ROW columns — a personal group's `did_key` matching its own
// `created_by_agent_id`, and the corresponding `role='admin'` membership. Each
// was argued as "structural, self-certifying, so it can be checked without
// trusting session state". Each was in fact an UNCONDITIONAL GRANT, because a
// predicate over the row alone is satisfied by every well-formed row; and
// because an `INSERT … ON CONFLICT` needs the SELECT side, they were in USING
// and therefore granted READ.
//
// The whole suite was green through that. Nothing here constructed the state an
// app connection is actually in — no principal, no group GUCs — and asserted a
// NEGATIVE. The catalog half cannot help: it proves a policy EXISTS per command
// and would score `USING (true)` on `claims` as full SELECT coverage.
// ===========================================================================

/// Every arm of every 077 policy must reference session-derived state.
///
/// This is the general form of the defect, promoted to a ratchet so the specific
/// instances cannot come back in a new spelling. The helpers below are the only
/// things that read the session; an arm mentioning none of them filters nothing.
///
/// The allowlist is deliberately tiny and literal. `visibility = 'public'` is a
/// row-only predicate ON PURPOSE — that is what "public" means — and the
/// world-group constant is the same idea for ownerless registries. Everything
/// else must key on the session.
#[sqlx::test(migrations = "../../migrations")]
async fn no_policy_arm_is_session_independent(pool: PgPool) {
    const SESSION_HELPERS: &[&str] = &[
        "epigraph_bypass",
        "epigraph_definer_bypass",
        "epigraph_session_groups",
        "epigraph_writable_groups",
        "epigraph_principal_id",
        "epigraph_is_group_admin",
        "epigraph_is_group_creator",
        // 083's roster predicate. It belongs here on the same ground as
        // `epigraph_is_group_admin`: its body binds its subject to
        // `epigraph_principal_id()` (or `epigraph_bypass()`), so an arm naming it
        // IS session-derived however the argument is spelled. Today 083's two
        // arms pass only incidentally — they happen to spell
        // `epigraph_is_instance_admin((SELECT public.epigraph_principal_id()))`,
        // and it is the NESTED helper the substring match finds. An arm written
        // `epigraph_is_instance_admin(agent_id)` would be reported as an
        // unconditional grant while being strictly session-bound, and the natural
        // repair — a `ROW_ONLY_BY_DESIGN` entry — would genuinely weaken this
        // ratchet by excusing an arm rather than recognising a helper.
        "epigraph_is_instance_admin",
    ];
    // ARMS — not policies — that are row-only BY DESIGN, each with the reason.
    //
    // The allowlist is keyed on `(policy, substring OF THE ARM)`, deliberately.
    // Allowlisting a whole POLICY would skip every arm it has, present and
    // future, so a bad arm added later to `agents_identity`, `agents_provision`,
    // `jobs_app` or `security_events_append` would never be reported — which is
    // the same "the exemption is broader than the thing exempted" mistake the
    // policies themselves made. An entry here excuses exactly one arm.
    const ROW_ONLY_BY_DESIGN: &[(&str, &str, &str)] = &[
        (
            "agents_identity",
            "true",
            "USING (true): an agent row must render authorship on a public claim, and \
             PostgreSQL has no column-level RLS. The projection is the control; the \
             VISIBILITY-EXEMPT comment in 077 names the call sites that do and do not apply it.",
        ),
        (
            "agents_provision",
            "key_kind",
            "key_kind <> 'derived' is row-only on purpose: it fences off the OAuth-principal \
             namespace, whose only writer is the definer mint. Creating an ordinary signer row \
             is a route-authorized capability gated above the database.",
        ),
        (
            "jobs_app",
            "privatization_apply",
            "The `job_type NOT IN ('privatization_*')` arm is row-only and is FORWARD-STAGING \
             for PR-18, which is why it is unreachable today: the queue runs on the maintenance \
             pool (bin/server.rs builds job_pool from maintenance_url), and jobs_app's USING is \
             bypass-only, so no non-bypass role reaches this WITH CHECK at all. It cannot be a \
             read grant for the same reason. Delete it or key it on the session when PR-18 adds \
             the job types it names.",
        ),
        (
            "security_events_append",
            "agent_id IS NULL",
            "An UNATTRIBUTED audit row is always writable. It has to be its own arm because \
             `NULL IS NOT DISTINCT FROM <uuid>` is FALSE, so the attribution arm does not cover \
             it, and `provision.rs::record_oauth_event` hard-codes `agent_id: None`. Permitting \
             it admits noise, never MISattribution — the attribution property is carried by the \
             sibling `agent_id = epigraph_principal_id()` arm, which is NOT exempted here.",
        ),
    ];

    let rows: Vec<(String, String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT c.relname::text, p.polname::text, \
                pg_get_expr(p.polqual, p.polrelid), \
                pg_get_expr(p.polwithcheck, p.polrelid) \
           FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid \
          WHERE c.relnamespace = 'public'::regnamespace \
          ORDER BY c.relname, p.polname",
    )
    .fetch_all(&pool)
    .await
    .expect("policy expression catalog");

    assert!(
        rows.len() >= 30,
        "expected the full 077 policy set from the catalog, got {} rows — if this collapsed, \
         every assertion below is vacuous",
        rows.len()
    );

    let mut offenders: Vec<String> = Vec::new();
    let mut exemptions_hit: BTreeSet<&str> = BTreeSet::new();
    for (table, policy, using, with_check) in &rows {
        for (clause, expr) in [("USING", using), ("WITH CHECK", with_check)] {
            let Some(expr) = expr else { continue };
            // Split on the top-level OR arms. `pg_get_expr` normalises to
            // `(a OR b OR c)`, so this is a coarse but honest slice: an arm
            // that mentions no helper is reported even if a sibling does.
            for arm in expr.split(" OR ") {
                let mentions_session = SESSION_HELPERS.iter().any(|h| arm.contains(h));
                let allowed_constant = arm.contains("visibility")
                    || arm.contains("00000000-0000-0000-0000-0000000000")
                    || arm.contains("owner_group_id IS NULL");
                let exempt = ROW_ONLY_BY_DESIGN
                    .iter()
                    .find(|(p, needle, _)| p == policy && arm.contains(needle));
                if let Some((_, needle, _)) = exempt {
                    exemptions_hit.insert(needle);
                    continue;
                }
                if !mentions_session && !allowed_constant {
                    offenders.push(format!("{table}.{policy} {clause}: {arm}"));
                }
            }
        }
    }

    // The allowlist is a ratchet in BOTH directions: an entry that no longer
    // matches any arm is an entry that has silently stopped exempting anything,
    // and would keep excusing a future arm that happened to contain the same
    // substring.
    let stale: Vec<&str> = ROW_ONLY_BY_DESIGN
        .iter()
        .map(|(_, needle, _)| *needle)
        .filter(|n| !exemptions_hit.contains(n))
        .collect();
    assert!(
        stale.is_empty(),
        "these ROW_ONLY_BY_DESIGN entries match no arm in the live policy set, so they are \
         excusing nothing and should be deleted: {stale:?}"
    );

    assert!(
        offenders.is_empty(),
        "these policy arms reference no session-derived state, so they filter NOTHING and are \
         unconditional grants — the exact shape of the personal-group arms 077 used to carry. \
         Either key the arm on the session, or add the policy to ROW_ONLY_BY_DESIGN with a \
         written reason:\n  {}",
        offenders.join("\n  ")
    );
}

/// An app connection with NO GUCs reads no private row from the three tables
/// whose provisioning arms used to leak.
///
/// The measurement that motivated this: with the row-only arms in place, an
/// `epigraph_app` session that had proved nothing saw 194 of 198 `groups` rows
/// and 193 of 195 `group_memberships` rows, the latter carrying
/// `wrapped_key_share` — the column whose existence is why `group_memberships`
/// is in the protected set at all.
///
/// Each assertion has its calibration built in: the fixture seeds rows that a
/// correctly-filtering policy MUST hide, and the counts are exact, not
/// "smaller than before".
#[sqlx::test(migrations = "../../migrations")]
async fn an_unstamped_app_connection_sees_no_private_group_state(pool: PgPool) {
    // Two unrelated agents, each with a personal group and membership. Neither
    // is the session principal, because there is no session principal.
    let (a_agent, a_group) = fixture::seed_agent_with_group(&pool, "unstamped-a").await;
    let (_b_agent, b_group) = fixture::seed_agent_with_group(&pool, "unstamped-b").await;
    let team = fixture::seed_group(&pool).await;
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, $3, 0, 'writer')",
    )
    .bind(team)
    .bind(a_agent)
    .bind(vec![9u8; 16])
    .execute(&pool)
    .await
    .expect("seed team membership with key material");
    fixture::grant_app_privileges(&pool, "epigraph_app").await;

    let (groups, memberships, shares) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            set_gucs(&mut conn, "", "", "").await;
            let groups: i64 = sqlx::query_scalar("SELECT count(*) FROM groups")
                .fetch_one(&mut *conn)
                .await
                .expect("groups read");
            let memberships: i64 = sqlx::query_scalar("SELECT count(*) FROM group_memberships")
                .fetch_one(&mut *conn)
                .await
                .expect("group_memberships read");
            let shares: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM group_memberships WHERE octet_length(wrapped_key_share) > 0",
            )
            .fetch_one(&mut *conn)
            .await
            .expect("key material read");
            (conn, (groups, memberships, shares))
        })
        .await;

    // CALIBRATION: the rows exist and are non-trivial in number, so a zero
    // below is filtering rather than an empty database.
    let (total_groups, total_memberships): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM groups), (SELECT count(*) FROM group_memberships)",
    )
    .fetch_one(&pool)
    .await
    .expect("owner-side totals");
    assert!(
        total_groups >= 3 && total_memberships >= 3,
        "CALIBRATION: the fixture must have seeded rows for the app role to be denied; \
         got {total_groups} groups / {total_memberships} memberships"
    );
    assert_ne!(a_group, b_group, "the two personal groups must be distinct");

    assert_eq!(
        groups, 0,
        "an app connection that has proved nothing must read NO groups row. It read {groups} of \
         {total_groups}. A personal group's did_key is DERIVED from its created_by_agent_id, so \
         any arm keyed on that shape is a tautology and grants the whole table."
    );
    assert_eq!(
        memberships, 0,
        "an app connection that has proved nothing must read NO group_memberships row. It read \
         {memberships} of {total_memberships}."
    );
    assert_eq!(
        shares, 0,
        "wrapped_key_share must never reach an unstamped connection; {shares} rows carrying key \
         material were visible"
    );
}

/// The same connection cannot UPDATE an agent row that is not its principal.
///
/// `agents_self_update` used to admit `key_kind = 'derived' AND
/// epigraph_principal_id() IS NULL`, described as reachable only
/// "pre-authentication". Because the request path does not stamp the session
/// GUCs, a NULL principal is an app connection's steady state, so the arm was
/// live on every statement — over `role` and `default_group_id` as much as over
/// `display_name`. The arm is gone; this pins that it stays gone.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unstamped_app_connection_cannot_update_a_foreign_agent(pool: PgPool) {
    let victim = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, display_name, agent_type, key_kind) \
         VALUES ($1, $2, 'victim', 'software_agent', 'derived')",
    )
    .bind(victim)
    .bind(vec![3u8; 32])
    .execute(&pool)
    .await
    .expect("seed derived victim");
    fixture::grant_app_privileges(&pool, "epigraph_app").await;

    let (foreign, own) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        set_gucs(&mut conn, "", "", "").await;
        let foreign = sqlx::query("UPDATE agents SET role = 'admin' WHERE id = $1")
            .bind(victim)
            .execute(&mut *conn)
            .await
            .map(|r| r.rows_affected());
        // CALIBRATION: with the principal stamped to the victim, the SAME
        // statement must succeed — otherwise "0 rows" above proves only that
        // the connection cannot write agents at all.
        set_gucs(&mut conn, "", "", &victim.to_string()).await;
        let own = sqlx::query("UPDATE agents SET role = 'admin' WHERE id = $1")
            .bind(victim)
            .execute(&mut *conn)
            .await
            .map(|r| r.rows_affected());
        (conn, (foreign, own))
    })
    .await;

    assert_eq!(
        foreign.expect("an UPDATE filtered by USING is 0 rows, not an error"),
        0,
        "an app session with no principal updated a derived agent row it does not own. \
         agents.default_group_id decides where an agent's future claims are owned, so this is \
         ownership redirection, not a cosmetic edit."
    );
    assert_eq!(
        own.expect("self-update must not error"),
        1,
        "CALIBRATION: a session whose principal IS the row must still update itself; if this is \
         0 the assertion above is satisfied by a policy that denies everyone."
    );
}

/// The `derived` namespace is closed to the app role.
///
/// The mint is its only writer, through `epigraph_provision_oauth_agent()`. A
/// forged `derived` row is the one a later `ensure_for_client` would ADOPT as a
/// principal, which is why this direction is fenced while ordinary signer rows
/// are not — `agents.key_kind` DEFAULTs to `'ed25519'` and six live non-mint
/// writers never name the column, so fencing THAT direction would refuse them
/// all. `sec_f13_a_token_mint_succeeds_under_force_as_the_app_role` asserts the
/// positive; this is its negative half.
#[sqlx::test(migrations = "../../migrations")]
async fn the_app_role_cannot_forge_a_derived_principal(pool: PgPool) {
    fixture::grant_app_privileges(&pool, "epigraph_app").await;
    let (derived, ordinary) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        set_gucs(&mut conn, "", "", "").await;
        let derived = sqlx::query(
            "INSERT INTO agents (public_key, display_name, agent_type, key_kind) \
             VALUES ($1, 'forged', 'software_agent', 'derived')",
        )
        .bind(vec![41u8; 32])
        .execute(&mut *conn)
        .await;
        let ordinary = sqlx::query(
            "INSERT INTO agents (public_key, display_name, agent_type) \
             VALUES ($1, 'ordinary', 'software_agent')",
        )
        .bind(vec![42u8; 32])
        .execute(&mut *conn)
        .await;
        (conn, (derived, ordinary))
    })
    .await;

    assert!(
        derived.is_err(),
        "the app role inserted a key_kind='derived' agent. That is the OAuth-principal \
         namespace and only the definer mint may write it."
    );
    ordinary.expect(
        "CALIBRATION: an ordinary agent insert must still succeed — AgentRepository::create is \
         reached from routes/provenance.rs and routes/conventions.rs on the app pool and never \
         names key_kind, so a policy fencing the default would be a total outage there.",
    );
}

/// `SecurityEventRepository::log` writes under RLS, through the real function.
///
/// PostgreSQL applies the SELECT policy to the rows a `RETURNING` clause
/// produces. With `security_events_read` keyed on the principal, an
/// `INSERT … RETURNING` of an event attributed to anyone else is refused — while
/// the identical INSERT without `RETURNING` succeeds. Both production call sites
/// swallow the error behind a `tracing::warn!`, so the symptom would have been a
/// silently absent audit trail rather than a failure. The statement no longer
/// has a `RETURNING`; this goes through the repo function so a reintroduction
/// cannot pass.
#[sqlx::test(migrations = "../../migrations")]
async fn security_event_log_writes_under_rls_on_the_app_role(pool: PgPool) {
    use epigraph_db::repos::security_event::{SecurityEventRepository, SecurityEventRow};
    let (agent, _g) = fixture::seed_agent_with_group(&pool, "sec-ev").await;
    fixture::grant_app_privileges(&pool, "epigraph_app").await;

    let url = fixture::database_url_for(&pool).await;
    let app_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .after_connect(|conn, _| {
            Box::pin(async move {
                sqlx::query("SET SESSION AUTHORIZATION epigraph_app")
                    .execute(conn)
                    .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .expect("app-role pool");

    let row = SecurityEventRow {
        id: Uuid::new_v4(),
        event_type: "rls_probe".to_string(),
        agent_id: Some(agent),
        success: Some(true),
        details: serde_json::json!({"probe": "pr-17"}),
        ip_address: None,
        user_agent: None,
        correlation_id: None,
        created_at: chrono::Utc::now(),
    };
    let id = row.id;
    SecurityEventRepository::log(&app_pool, row).await.expect(
        "logging a security event attributed to an agent that is not the session principal \
             must SUCCEED — an actor must never be able to suppress its own audit record, and \
             the OAuth provisioning path hard-codes agent_id and runs unstamped",
    );

    // CALIBRATION: the row really landed, read back as the owner.
    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM security_events WHERE id = $1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .expect("owner read-back");
    assert_eq!(stored, 1, "the event must actually be in the table");
}

/// Every relation in `public` is reachable by `epigraph_app` on a FRESH migrate.
///
/// **This test must NOT call `grant_app_privileges`.** That fixture re-issues
/// `GRANT … ON ALL TABLES` after all migrations have run, which is precisely
/// what masks the gap: 077's `ON ALL TABLES` binds only the tables that exist at
/// version 077, so on a fresh migrate every table a LATER migration creates is
/// missed — measured, `webhook_subscriptions` (085) was the one relation for
/// which `has_table_privilege` was false, on live app-pool webhook routes. On
/// the already-deployed database the same statement catches it, because there
/// the later tables already exist: a prod/fresh divergence in exactly the
/// environment 11d is rehearsed in. 077 now also issues `ALTER DEFAULT
/// PRIVILEGES`, which is the half that covers later migrations.
#[sqlx::test(migrations = "../../migrations")]
async fn the_app_role_can_reach_every_public_table_without_the_test_fixture(pool: PgPool) {
    let missing: Vec<String> = sqlx::query_scalar(
        "SELECT c.relname::text FROM pg_class c \
          WHERE c.relnamespace = 'public'::regnamespace AND c.relkind = 'r' \
            AND NOT has_table_privilege('epigraph_app', c.oid, 'SELECT') \
          ORDER BY 1",
    )
    .fetch_all(&pool)
    .await
    .expect("privilege sweep");

    assert!(
        missing.is_empty(),
        "epigraph_app has no SELECT on {} relation(s) after a fresh migrate: {}. \
         `GRANT … ON ALL TABLES` in 077 cannot reach a table created by a later migration; \
         `ALTER DEFAULT PRIVILEGES` is the half that does.",
        missing.len(),
        missing.join(", ")
    );
}

/// The correlated-guard enumeration, recorded as a ratchet.
///
/// **The property**: an RLS-filtered read inside a write's guard predicate
/// WIDENS the write. `WHERE NOT EXISTS (SELECT 1 FROM t …)` over a protected `t`
/// returns nothing to a non-bypass role whatever is in the table, so the guard
/// degrades from a dedup check into an unconditional insert — silently, with no
/// error. This is the same mechanism as the `ON CONFLICT`/USING interaction that
/// 077's correction (7) found; the sweep for that one covered `ON CONFLICT` and
/// not this shape.
///
/// The sites, measured with the pool each runs on:
///
/// | Site | Table | Pool | Disposition |
/// |---|---|---|---|
/// | `postgres_queue.rs::enqueue_unique_pending` | `jobs` | maintenance (`bin/server.rs` builds `job_pool` from `maintenance_url`; both `PostgresJobQueue::new` sites take it) | `epigraph_bypass()` is true, guard intact |
/// | `edge.rs::create_symmetric_if_absent` | `edges` | app | degrades to duplicate edge |
/// | `edge.rs::create_symmetric_if_absent_returning` | `edges` | app | ditto, but `alternative_of` carries `edges_alternative_of_symmetric_uniq`, so a duplicate raises 23505 rather than landing |
/// | `graph_view.rs` (2 sites) | `edges` | app | already-decomposed claims reappear as undecomposed |
/// | `graph_neighborhood.rs` (2 sites) | `edges` | app | ditto |
///
/// **None is a read leak**; every one is a correctness degradation on writes or
/// counts, and every one is latent until step 11d repoints `DATABASE_URL` — the
/// same precondition `D-PR17-request-path-never-stamps-session-gucs` already
/// gates. Replacing the read-guards with real unique constraints is recorded as
/// `D-PR17-read-guards-widen-under-rls` and belongs with the `acquire_as`
/// conversion, not with the policy set.
///
/// This test pins the ONE property that is enforceable here and now: the job
/// queue, the only guard site whose widening would let an app connection
/// dispatch work that later runs with `epigraph_bypass()` TRUE, is on the
/// maintenance pool.
#[test]
fn guard_subquery_sites_are_enumerated() {
    let server = include_str!("../../epigraph-api/src/bin/server.rs");
    assert!(
        server.contains("PostgresJobQueue::new(job_pool"),
        "the job queue must be built on job_pool"
    );
    let job_pool_decl = server
        .split("let job_scoped = ")
        .nth(1)
        .expect("job_scoped must be constructed in server.rs");
    assert!(
        job_pool_decl.starts_with(
            "epigraph_db::ScopedPool::connect_with_options(\n            &maintenance_url"
        ),
        "job_pool must be built from maintenance_url. If it moves to the app DSN, \
         `enqueue_unique_pending`'s `WHERE NOT EXISTS` guard becomes an unconditional insert \
         under RLS — no error, duplicate jobs — and `jobs_app`'s job_type exclusion becomes the \
         only thing standing between an app connection and a bypass-running job."
    );
}

// ===========================================================================
// PR-24 — the existence probe, on a role a policy actually filters
// ===========================================================================

/// `ClaimRepository::hidden_claim_ids` must still classify ids on an
/// `epigraph_app` session with FORCE live.
///
/// # This is the acceptance test for migration 086, and it is the ONLY instrument that discriminates
///
/// The probe answers "which of these ids name a `claims` row this viewer may
/// not read" as a set difference between an existence arm and a viewer-filtered
/// arm. That is informative only while the two arms have different authority.
/// Before 086 both read `claims` directly, so on a role the policy applies to
/// they coincided and the difference was empty for every input — and BOTH
/// callers read an empty set as *"nothing is hidden"*
/// (`routes/events.rs::retain_visible_events` returns early and keeps every
/// event; `routes/webhooks.rs::agent_may_receive` returns `true` and delivers).
/// An always-empty probe is therefore uninformative, not conservative.
///
/// Nothing in the pre-existing suite could see that. Every other exerciser —
/// the `#[sqlx::test]` unit test beside the function, `webhook_tenancy.rs`,
/// `tenant_isolation_http.rs`, `events_unified_test.rs` — runs on a pool
/// connected as the owning superuser, for whom no policy applies. Their answers
/// are identical before and after 086. That structural insensitivity, not a
/// missing edge case, is why this test exists.
///
/// # Why an app-role POOL and not `fixture::as_role`
///
/// `hidden_claim_ids` takes a `&PgPool`; `as_role` hands back a
/// `PoolConnection`. Transcribing the SQL into this file would satisfy the
/// words of the criterion and not the criterion — the thing under test is the
/// production function. So this builds a one-connection pool whose
/// `after_connect` issues `SET SESSION AUTHORIZATION epigraph_app`, the shape
/// `security_event_log_writes_under_rls_on_the_app_role` above already
/// establishes. `max_connections(1)` is load-bearing for the GUC arm at the
/// end: a session-level `set_config` only sticks if there is one connection.
///
/// # The four properties, and why the fourth is not garnish
///
/// 1. an existing row the viewer may NOT read comes back **in** the hidden set;
/// 2. an existing row the viewer MAY read does **not** — this is the one an
///    existence-arm-only repair fails, because the viewer-filtered arm would
///    still be narrowed by the policy to `visibility = 'public'` on an
///    unstamped connection, whatever `$V` binds;
/// 3. an id naming **no** row does not (the contract both callers depend on,
///    pinned in `locked_decisions.rs`);
/// 4. **calibration** — the same fixture and the same viewer on the OWNER
///    connection still reports the hidden id. Without (4), a definer that
///    returned nothing for an unrelated reason (a no-opped `OWNER TO`, a lost
///    `SELECT` grant on `claims`, a missing `EXECUTE` grant) satisfies (2) and
///    (3), which are both negative, and only fails (1) — and a suite of
///    negative assertions is satisfied by a mechanism that returns nothing to
///    anybody.
///
/// # The GUCs are deliberately left UNSET for the main arms
///
/// That is the production shape: both call sites take a raw `&PgPool` as a
/// parameter, sourced from `state.db_pool` or the webhook-dispatcher handoff,
/// and nothing on the request path stamps it
/// (`D-PR17-request-path-never-stamps-session-gucs`). Stamping the owning group
/// while passing a stranger viewer would pass on the UNFIXED tree, for a reason
/// unrelated to the repair. The final arm stamps them coherently and asserts the
/// answers are *unchanged*, which is the GUC-independence property 086 buys.
///
/// A `42501` here is a missing `GRANT EXECUTE` from 086, not a broken probe:
/// `fixture::grant_app_privileges` grants schema, tables and sequences and not
/// functions.
#[sqlx::test(migrations = "../../migrations")]
async fn hidden_claim_ids_still_classifies_on_the_app_role_under_force(pool: PgPool) {
    use epigraph_db::repos::ClaimRepository;
    use epigraph_db::Viewer;

    // `member` owns the private claim's group; `stranger` has a personal group
    // of its own and no membership in `member`'s.
    let (member_agent, group) = fixture::seed_agent_with_group(&pool, "pr24-member").await;
    let (stranger_agent, _stranger_group) =
        fixture::seed_agent_with_group(&pool, "pr24-stranger").await;

    let public_id = fixture::seed_public_claim(&pool, member_agent, "pr24 public claim").await;
    let private_id =
        fixture::seed_group_claim(&pool, member_agent, group, "pr24 private claim").await;
    let absent_id = Uuid::new_v4();
    let ids = [public_id, private_id, absent_id];

    // Viewers are resolved the way production resolves them. `Viewer::test_scoped`
    // is `#[cfg(test)]` on its definition and is not reachable from this crate's
    // integration tests; see `viewer_fixture.rs`'s module doc.
    let member = Viewer::resolve(&pool, member_agent)
        .await
        .expect("resolve member");
    let stranger = Viewer::resolve(&pool, stranger_agent)
        .await
        .expect("resolve stranger");
    assert!(
        member.group_bind().is_some_and(|g| g.contains(&group)),
        "the member viewer must actually carry the owning group, or property 2 \
         below is vacuous"
    );
    assert!(
        stranger.group_bind().is_some_and(|g| !g.contains(&group)),
        "the stranger viewer must NOT carry the owning group, or property 1 \
         below is vacuous"
    );

    // ---- (4) CALIBRATION, on the owner connection, BEFORE the app-role arms.
    // If this is empty the fixture cannot detect a hidden id at all and every
    // assertion after it would be meaningless.
    let owner_hidden = ClaimRepository::hidden_claim_ids(&pool, &stranger, &ids)
        .await
        .expect("owner-connection probe");
    assert!(
        owner_hidden.contains(&private_id),
        "CALIBRATION: the owner connection must report the group-private id as \
         hidden from a stranger. It does not, so the fixture — not the policy — \
         is what the app-role assertions below would be measuring."
    );
    assert!(
        !owner_hidden.contains(&public_id) && !owner_hidden.contains(&absent_id),
        "CALIBRATION: a public row and an id naming no row are not hidden"
    );

    fixture::grant_app_privileges(&pool, "epigraph_app").await;
    let url = fixture::database_url_for(&pool).await;
    let app_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .after_connect(|conn, _| {
            Box::pin(async move {
                sqlx::query("SET SESSION AUTHORIZATION epigraph_app")
                    .execute(conn)
                    .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .expect("app-role pool");

    // The instrument is not vacuous: this session really is filtered.
    let visible_to_the_session: i64 =
        sqlx::query_scalar("SELECT count(*) FROM claims WHERE id = ANY($1)")
            .bind(&ids[..])
            .fetch_one(&app_pool)
            .await
            .expect("count under the app role");
    assert_eq!(
        visible_to_the_session, 1,
        "PREMISE: an unstamped epigraph_app session must see exactly the PUBLIC \
         one of the two seeded rows. Seeing both means FORCE is not in effect \
         (or the role is a bypass role) and the whole test is vacuous; seeing \
         neither means a grant is missing."
    );

    // ---- (1) and (3): the stranger.
    let hidden = ClaimRepository::hidden_claim_ids(&app_pool, &stranger, &ids)
        .await
        .expect("app-role probe, stranger");
    assert!(
        hidden.contains(&private_id),
        "an existing row the viewer cannot read must come back HIDDEN on the \
         app role. Empty here is the collapse this migration exists to close, \
         and both callers read empty as \"nothing is hidden\" — so the failure \
         would be uninformative, not conservative."
    );
    assert!(
        !hidden.contains(&public_id),
        "a public row is not hidden from anyone"
    );
    assert!(
        !hidden.contains(&absent_id),
        "an id naming NO row has no owner to protect and must not be reported — \
         reporting it would drop every event carrying an agent id or a \
         hard-deleted claim id"
    );
    assert_eq!(hidden.len(), 1, "exactly the private id, and nothing else");

    // ---- (2): the member. This is the property an existence-arm-only repair
    // fails, and it fails it SILENTLY and in the over-suppressing direction.
    let for_member = ClaimRepository::hidden_claim_ids(&app_pool, &member, &ids)
        .await
        .expect("app-role probe, member");
    assert!(
        for_member.is_empty(),
        "nothing is hidden from a member of the owning group, on an UNSTAMPED \
         app-role connection — which is the shape both call sites have. Without \
         this, a probe that reports every existing id passes every assertion \
         above, and production would silently drop a subscriber's own \
         group-visible events. Got: {for_member:?}"
    );

    // ---- GUC-INDEPENDENCE. Stamp the session coherently and assert the two
    // answers are unchanged. The repair puts both arms inside the definer frame,
    // so the viewer — not `epigraph_session_groups()` — is the only authority
    // either arm consults.
    sqlx::query("SELECT set_config('epigraph.group_ids', $1, false)")
        .bind(group.to_string())
        .execute(&app_pool)
        .await
        .expect("stamp epigraph.group_ids");

    let stamped_member = ClaimRepository::hidden_claim_ids(&app_pool, &member, &ids)
        .await
        .expect("app-role probe, member, stamped");
    let stamped_stranger = ClaimRepository::hidden_claim_ids(&app_pool, &stranger, &ids)
        .await
        .expect("app-role probe, stranger, stamped");
    assert!(
        stamped_member.is_empty(),
        "stamping must not change the member's answer; got {stamped_member:?}"
    );
    assert_eq!(
        stamped_stranger, hidden,
        "stamping the OWNING group must not make the private id readable by a \
         STRANGER. The viewer is the authority here, not the session GUC — and \
         a test that relied on the GUC instead would have passed on the unfixed \
         tree."
    );
}

// ===========================================================================
// PR-25 — the SQL twin of the existence probe, on a role a policy filters
// ===========================================================================

/// `EventRepository::list` must still suppress events on an `epigraph_app`
/// session with FORCE live.
///
/// # This is the ONLY instrument in the tree that discriminates
///
/// `list` decides "does this event name a claim that exists but this viewer
/// cannot read" as a set difference between an existence arm and a
/// viewer-filtered arm, in SQL. That is informative only while the two arms
/// have different authority. Before PR-25 both read `claims` directly, so on a
/// role `claims_tenancy` applies to they were filtered identically, the
/// conjunction became unsatisfiable, and **nothing was suppressed at all** —
/// fail-OPEN, and `events` carries no RLS of its own (it is absent from 077 and
/// from 079's `protected` array, verified in the catalog), so this predicate is
/// the only tenancy control on that read path. That was
/// `F-PR24-event-list-existence-arm-collapses-under-force`.
///
/// Nothing in the pre-existing suite could see it, and no `epigraph-db` test
/// called `EventRepository::list` at all. Every other exerciser —
/// `epigraph-mcp/tests/tenant_isolation_mcp.rs`' four `list_events_*` cases,
/// `epigraph-api/tests/tenant_isolation_http.rs`,
/// `epigraph-api/tests/events_unified_test.rs`,
/// `epigraph-mcp/tests/event_log_wiring_tests.rs` — runs on a pool connected as
/// the owning superuser, for whom no policy applies. Their answers are
/// identical before and after this repair. That structural insensitivity, not a
/// missing edge case, is why this test exists.
///
/// # Why an app-role POOL and not `fixture::as_role`
///
/// `list` takes a `&PgPool`; `as_role` hands back a `PoolConnection`.
/// Transcribing the SQL into this file would satisfy the words of the criterion
/// and not the criterion — the thing under test is the production function. So
/// this builds a one-connection pool whose `after_connect` issues
/// `SET SESSION AUTHORIZATION epigraph_app`, the shape
/// `security_event_log_writes_under_rls_on_the_app_role` and
/// `hidden_claim_ids_still_classifies_on_the_app_role_under_force` already
/// establish. `max_connections(1)` is load-bearing for the GUC arm at the end:
/// a session-level `set_config` only sticks if there is one connection.
///
/// # The four properties, and why the second and the calibration are not garnish
///
/// 1. an event naming an existing claim the viewer may NOT read is
///    **suppressed**;
/// 2. an event naming that same claim is **returned** to a MEMBER of the owning
///    group — this is the one an existence-arm-only repair fails, because the
///    viewer-filtered arm would still be narrowed by the policy to
///    `visibility = 'public'` on an unstamped connection whatever `$V` binds,
///    so a claim the member is entitled to read looks invisible and its event
///    is dropped. Over-suppression, the opposite failure;
/// 3. an event naming **no** uuid at all is returned (most events; `NOT EXISTS`
///    over an empty match set), and an event naming a uuid that matches **no**
///    row is returned — the deliberate survivor documented at
///    `EventRepository::list` and pinned by
///    `tenant_isolation_mcp.rs::list_events_keeps_an_event_whose_payload_uuid_names_no_claim`;
/// 4. **calibration** — the same fixture and the same viewer on the OWNER
///    connection still suppresses the private event. Without (4), a predicate
///    that suppressed nothing for an unrelated reason (a no-opped `OWNER TO`, a
///    lost `SELECT` grant on `claims`) satisfies every *positive* assertion
///    here, and property 1 is the only negative one.
///
/// # The GUCs are deliberately left UNSET for the main arms
///
/// That is the production shape: all three callers
/// (`routes/events.rs::list_events`, `routes/events.rs::graph_snapshot`, MCP
/// `tools/events.rs::list_events`) pass a raw `&PgPool` sourced from
/// `state.db_pool` / `server.pool`, and nothing on the request path stamps it
/// (`D-PR17-request-path-never-stamps-session-gucs`). The final arm stamps them
/// coherently and asserts the answers are *unchanged*, which is the
/// GUC-independence property the definer frame buys.
///
/// Assertions are by id membership, never by position or length: all four
/// events are inserted with `created_at = NOW()`, so `ORDER BY created_at DESC`
/// ties are not deterministic.
///
/// A `42501` here is a missing `GRANT EXECUTE` from 086, not a broken
/// predicate: `fixture::grant_app_privileges` grants schema, tables and
/// sequences and not functions.
#[sqlx::test(migrations = "../../migrations")]
async fn event_list_still_suppresses_on_the_app_role_under_force(pool: PgPool) {
    use epigraph_db::repos::EventRepository;
    use epigraph_db::Viewer;

    // `member` owns the private claim's group; `stranger` has a personal group
    // of its own and no membership in `member`'s.
    let (member_agent, group) = fixture::seed_agent_with_group(&pool, "pr25-member").await;
    let (stranger_agent, _stranger_group) =
        fixture::seed_agent_with_group(&pool, "pr25-stranger").await;

    let public_id = fixture::seed_public_claim(&pool, member_agent, "pr25 public claim").await;
    let private_id =
        fixture::seed_group_claim(&pool, member_agent, group, "pr25 private claim").await;
    let absent_id = Uuid::new_v4();

    // Every event carries the same `actor_id`, and every read below filters on
    // it. That isolates this fixture from any other row in `events` without
    // relying on `LIMIT` or on the `created_at` ordering.
    let ev_private = EventRepository::insert(
        &pool,
        "pr25.names_private",
        Some(member_agent),
        &serde_json::json!({ "claim_id": private_id }),
    )
    .await
    .expect("seed event naming the private claim");
    let ev_public = EventRepository::insert(
        &pool,
        "pr25.names_public",
        Some(member_agent),
        &serde_json::json!({ "claim_id": public_id }),
    )
    .await
    .expect("seed event naming the public claim");
    let ev_no_uuid = EventRepository::insert(
        &pool,
        "pr25.names_nothing",
        Some(member_agent),
        &serde_json::json!({ "note": "no identifier of any kind in this payload" }),
    )
    .await
    .expect("seed event naming no claim");
    let ev_absent = EventRepository::insert(
        &pool,
        "pr25.names_absent",
        Some(member_agent),
        &serde_json::json!({ "claim_id": absent_id }),
    )
    .await
    .expect("seed event naming an id that matches no row");

    // Viewers are resolved the way production resolves them. `Viewer::test_scoped`
    // is `#[cfg(test)]` on its definition and is not reachable from this crate's
    // integration tests; see `viewer_fixture.rs`'s module doc.
    let member = Viewer::resolve(&pool, member_agent)
        .await
        .expect("resolve member");
    let stranger = Viewer::resolve(&pool, stranger_agent)
        .await
        .expect("resolve stranger");
    assert!(
        member.group_bind().is_some_and(|g| g.contains(&group)),
        "the member viewer must actually carry the owning group, or property 2 \
         below is vacuous"
    );
    assert!(
        stranger.group_bind().is_some_and(|g| !g.contains(&group)),
        "the stranger viewer must NOT carry the owning group, or property 1 \
         below is vacuous"
    );

    async fn visible_ids(
        pool: &PgPool,
        viewer: &Viewer,
        actor: Uuid,
    ) -> std::collections::HashSet<Uuid> {
        EventRepository::list(pool, viewer, None, Some(actor), 100)
            .await
            .expect("EventRepository::list")
            .into_iter()
            .map(|row| row.id)
            .collect()
    }

    // ---- (4) CALIBRATION, on the owner connection, BEFORE the app-role arms.
    // If the private event is not suppressed here the fixture cannot detect a
    // suppression at all and every assertion after it would be meaningless.
    let owner_seen = visible_ids(&pool, &stranger, member_agent).await;
    assert!(
        !owner_seen.contains(&ev_private),
        "CALIBRATION: the owner connection must suppress the event naming a \
         group-private claim from a stranger. It does not, so the fixture — not \
         the predicate — is what the app-role assertions below would be \
         measuring."
    );
    assert!(
        owner_seen.contains(&ev_public)
            && owner_seen.contains(&ev_no_uuid)
            && owner_seen.contains(&ev_absent),
        "CALIBRATION: a public claim, no uuid at all, and a uuid naming no row \
         are all returned. Got: {owner_seen:?}"
    );

    fixture::grant_app_privileges(&pool, "epigraph_app").await;
    let url = fixture::database_url_for(&pool).await;
    let app_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .after_connect(|conn, _| {
            Box::pin(async move {
                sqlx::query("SET SESSION AUTHORIZATION epigraph_app")
                    .execute(conn)
                    .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .expect("app-role pool");

    // The instrument is not vacuous: this session really is filtered.
    let visible_to_the_session: i64 =
        sqlx::query_scalar("SELECT count(*) FROM claims WHERE id = ANY($1)")
            .bind(&[public_id, private_id][..])
            .fetch_one(&app_pool)
            .await
            .expect("count under the app role");
    assert_eq!(
        visible_to_the_session, 1,
        "PREMISE: an unstamped epigraph_app session must see exactly the PUBLIC \
         one of the two seeded rows. Seeing both means FORCE is not in effect \
         (or the role is a bypass role) and the whole test is vacuous; seeing \
         neither means a grant is missing."
    );

    // ---- (1) and (3): the stranger.
    let seen = visible_ids(&app_pool, &stranger, member_agent).await;
    assert!(
        !seen.contains(&ev_private),
        "an event naming an existing claim this viewer cannot read must be \
         SUPPRESSED on the app role. Returning it is the collapse this repair \
         exists to close: both inner arms filtered identically, the conjunction \
         unsatisfiable, the outer EXISTS always false — fail-OPEN, and `events` \
         has no RLS behind it. Got: {seen:?}"
    );
    assert!(
        seen.contains(&ev_public),
        "an event naming a public claim is returned to anyone"
    );
    assert!(
        seen.contains(&ev_no_uuid),
        "an event naming no uuid at all is returned — NOT EXISTS over an empty \
         match set"
    );
    assert!(
        seen.contains(&ev_absent),
        "an event naming a uuid that matches NO row is returned: there is no row \
         to classify and no owner to protect, and dropping it would make \
         `graph_snapshot`'s replay depend on referential integrity rather than \
         on visibility"
    );

    // ---- (2): the member. This is the property an existence-arm-only repair
    // fails, and it fails it SILENTLY and in the over-suppressing direction.
    let for_member = visible_ids(&app_pool, &member, member_agent).await;
    assert!(
        for_member.contains(&ev_private),
        "a member of the owning group must still RECEIVE the event naming its \
         own group-private claim, on an UNSTAMPED app-role connection — which \
         is the shape all three callers have. Without this, a predicate that \
         suppresses every event naming any existing claim passes every \
         assertion above, and production would silently drop a member's own \
         group-visible events. Got: {for_member:?}"
    );
    assert!(
        for_member.contains(&ev_public)
            && for_member.contains(&ev_no_uuid)
            && for_member.contains(&ev_absent),
        "the member sees the other three too. Got: {for_member:?}"
    );

    // ---- GUC-INDEPENDENCE. Stamp the session coherently and assert both
    // answers are unchanged. The repair puts both arms inside the definer frame,
    // so the viewer — not `epigraph_session_groups()` — is the only authority
    // either arm consults.
    sqlx::query("SELECT set_config('epigraph.group_ids', $1, false)")
        .bind(group.to_string())
        .execute(&app_pool)
        .await
        .expect("stamp epigraph.group_ids");

    let stamped_member = visible_ids(&app_pool, &member, member_agent).await;
    let stamped_stranger = visible_ids(&app_pool, &stranger, member_agent).await;
    assert_eq!(
        stamped_member, for_member,
        "stamping must not change the member's answer"
    );
    assert_eq!(
        stamped_stranger, seen,
        "stamping the OWNING group must not make the private claim's event \
         visible to a STRANGER. The viewer is the authority here, not the \
         session GUC — and a test that relied on the GUC instead would have \
         passed on the unfixed tree."
    );
}
