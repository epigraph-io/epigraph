//! Migration 263: a Person creates a keyless team group, lists their groups,
//! and invites another Person, whose membership goes live only when THEY
//! accept (backlog ee9e05b4).
//!
//! Every act runs on an APPLICATION-role session (`SET SESSION AUTHORIZATION
//! epigraph_app`) stamped with the caller as `epigraph.principal_id`, exactly
//! what `ScopedPool::begin_as` sets, so the grants and the definers are what
//! is measured, not the harness superuser. Each refusal sits next to the
//! positive control that shows the same call succeeds without the refused
//! condition.
//!
//! What is pinned:
//!
//! * the six request-path functions and the grant check are
//!   `epigraph_maintenance`-owned definers the application role executes and
//!   PUBLIC does not; the grant table is closed to the application role;
//! * create: only a registered human operator, signed in as themselves
//!   (TGP01 for an operated agent and an unstamped session), makes a keyless
//!   verb-made team group whose one admin is that Person, audited; one
//!   active group per name per creator (TGP06), not across creators;
//! * consent: an invitation writes NO membership (the invitee's viewer does
//!   not carry the group) until the invitee accepts; then exactly one live
//!   row at the invited role, the invitation names it, and the act is
//!   audited; decline writes no membership;
//! * who may: only a live admin invites (TGP02; a non-member is told the
//!   group does not exist, TGP08); any agent but a role's node or a system
//!   identity is invited alike and only a Person can accept (TGP03 / TGP01,
//!   migration 284); only the
//!   invitee answers (TGP08 for anyone else, TGP01 for its operated agent);
//!   an invitation is answered once (TGP05); it lapses when its sender is no
//!   longer a live admin (TGP05);
//! * 164's guards: a direct application write to the roster or the group row
//!   of a verb-made group is still refused with 176's exact text, also right
//!   after a person act in the same transaction, and no grant row outlives
//!   the act that wrote it.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{AgentRepository, Viewer};
use sqlx::{Executor, PgConnection, PgPool};
use uuid::Uuid;

fn code_of<T: std::fmt::Debug>(r: &Result<T, sqlx::Error>) -> Option<String> {
    r.as_ref().err().and_then(|e| {
        e.as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .map(|c| c.to_string())
    })
}

fn message_of<T: std::fmt::Debug>(r: &Result<T, sqlx::Error>) -> String {
    r.as_ref()
        .err()
        .and_then(|e| e.as_database_error().map(|d| d.message().to_string()))
        .unwrap_or_default()
}

/// An application-role connection stamped with `principal` (or with none).
async fn app_as(
    pool: &PgPool,
    principal: Option<Uuid>,
) -> sqlx::pool::PoolConnection<sqlx::Postgres> {
    let mut conn = pool.acquire().await.expect("acquire");
    conn.execute("SET SESSION AUTHORIZATION epigraph_app")
        .await
        .expect("downgrade to the application role");
    if let Some(p) = principal {
        sqlx::query("SELECT set_config('epigraph.principal_id', $1, false)")
            .bind(p.to_string())
            .execute(&mut *conn)
            .await
            .expect("stamp the principal");
    }
    conn
}

async fn reset(mut conn: sqlx::pool::PoolConnection<sqlx::Postgres>) {
    conn.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset session authorization");
    conn.execute("RESET epigraph.principal_id")
        .await
        .expect("reset the principal");
}

async fn create_on(conn: &mut PgConnection, name: &str) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar("SELECT public.epigraph_person_create_team_group($1, $2)")
        .bind(name)
        .bind("person team group test")
        .fetch_one(&mut *conn)
        .await
}

async fn create(pool: &PgPool, caller: Option<Uuid>, name: &str) -> Result<Uuid, sqlx::Error> {
    let mut c = app_as(pool, caller).await;
    let r = create_on(&mut c, name).await;
    reset(c).await;
    r
}

async fn invite(
    pool: &PgPool,
    caller: Uuid,
    group: Uuid,
    invitee: Uuid,
    role: &str,
) -> Result<Uuid, sqlx::Error> {
    let mut c = app_as(pool, Some(caller)).await;
    let r = sqlx::query_scalar("SELECT public.epigraph_invite_to_team_group($1, $2, $3, $4)")
        .bind(group)
        .bind(invitee)
        .bind(role)
        .bind("join us")
        .fetch_one(&mut *c)
        .await;
    reset(c).await;
    r
}

/// `(group, membership, role)`.
async fn accept(
    pool: &PgPool,
    caller: Uuid,
    invitation: Uuid,
) -> Result<(Uuid, Uuid, String), sqlx::Error> {
    let mut c = app_as(pool, Some(caller)).await;
    let r = sqlx::query_as(
        "SELECT out_group_id, out_membership_id, out_role \
           FROM public.epigraph_accept_group_invitation($1)",
    )
    .bind(invitation)
    .fetch_one(&mut *c)
    .await;
    reset(c).await;
    r
}

async fn decline(pool: &PgPool, caller: Uuid, invitation: Uuid) -> Result<Uuid, sqlx::Error> {
    let mut c = app_as(pool, Some(caller)).await;
    let r = sqlx::query_scalar("SELECT public.epigraph_decline_group_invitation($1)")
        .bind(invitation)
        .fetch_one(&mut *c)
        .await;
    reset(c).await;
    r
}

/// `(group_id, role, invitable)` of the caller's groups.
async fn my_groups(pool: &PgPool, caller: Uuid) -> Vec<(Uuid, String, bool)> {
    let mut c = app_as(pool, Some(caller)).await;
    let r = sqlx::query_as("SELECT group_id, role, invitable FROM public.epigraph_my_groups()")
        .fetch_all(&mut *c)
        .await
        .expect("my groups");
    reset(c).await;
    r
}

/// `(invitation_id, group_id, role, invited_by)` pending for the caller.
async fn my_invitations(pool: &PgPool, caller: Uuid) -> Vec<(Uuid, Uuid, String, Uuid)> {
    let mut c = app_as(pool, Some(caller)).await;
    let r = sqlx::query_as(
        "SELECT invitation_id, group_id, role, invited_by \
           FROM public.epigraph_my_group_invitations()",
    )
    .fetch_all(&mut *c)
    .await
    .expect("my invitations");
    reset(c).await;
    r
}

async fn human(pool: &PgPool, label: &str) -> Uuid {
    fixture::seed_human_operator(pool, label).await.0
}

/// An agent LIVE-linked to `operator` (107's link).
async fn operated(pool: &PgPool, operator: Uuid, label: &str) -> Uuid {
    let (agent, _) = fixture::seed_agent_with_group(pool, label).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let out = AgentRepository::link_operator(&mut conn, agent, operator)
        .await
        .expect("link the agent");
    assert!(out.link_live, "PREMISE: a live link: {out:?}");
    agent
}

/// A role's graph node (`agent_type = 'role'`, as 123 / 165 seed one): its
/// kind is shown to every reader, so refusing it as an invitee tells no one
/// anything new.
async fn role_node(pool: &PgPool, key: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, role, labels) \
         VALUES (uuid_send(gen_random_uuid()) || uuid_send(gen_random_uuid()), $1, 'role', \
                 'custom', ARRAY['role']) RETURNING id",
    )
    .bind(format!("role:{key}"))
    .fetch_one(pool)
    .await
    .expect("role node")
}

/// A principal provisioned through the real OAuth path
/// (`AgentRepository::ensure_for_client`) for a client of `client_type`: a
/// `human` client with a provider-form id (so the provider's name is
/// adopted), or a `service` one (a nameless service principal, named
/// `oauth:<client row id>`).
async fn provisioned(pool: &PgPool, client_type: &str, name: &str) -> Uuid {
    let client_id = if client_type == "human" {
        format!("fixtureprovider:{}", Uuid::new_v4().simple())
    } else {
        format!("epigraph_{}", Uuid::new_v4().simple())
    };
    let row: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    status, legal_entity_name, legal_contact_email) \
         VALUES ($1, $2, $3, ARRAY['claims:write'], 'active', 'Fixture Org', \
                 'fixture@example.invalid') RETURNING id",
    )
    .bind(&client_id)
    .bind(name)
    .bind(client_type)
    .fetch_one(pool)
    .await
    .expect("client row");
    let mut tx = pool.begin().await.expect("begin");
    let agent = AgentRepository::ensure_for_client(&mut tx, row)
        .await
        .expect("ensure_for_client");
    tx.commit().await.expect("commit");
    agent.into()
}

/// Every membership row of `(group, agent)`: `(role, revoked)`.
async fn rows(pool: &PgPool, group: Uuid, agent: Uuid) -> Vec<(String, bool)> {
    sqlx::query_as(
        "SELECT role::text, revoked_at IS NOT NULL FROM group_memberships \
          WHERE group_id = $1 AND agent_id = $2 ORDER BY epoch",
    )
    .bind(group)
    .bind(agent)
    .fetch_all(pool)
    .await
    .expect("membership rows")
}

/// Whether `agent`'s resolved viewer reads `group`.
async fn reads(pool: &PgPool, agent: Uuid, group: Uuid) -> bool {
    Viewer::resolve(pool, agent)
        .await
        .expect("resolve")
        .group_bind()
        .is_some_and(|g| g.contains(&group))
}

/// The `group.*` audit rows naming `group`: `(event_type, agent_id, details)`.
async fn audit(pool: &PgPool, group: Uuid) -> Vec<(String, Option<Uuid>, serde_json::Value)> {
    sqlx::query_as(
        "SELECT event_type::text, agent_id, details FROM security_events \
          WHERE event_type LIKE 'group.%' AND details->>'group_id' = $1::text \
          ORDER BY created_at, id",
    )
    .bind(group)
    .fetch_all(pool)
    .await
    .expect("audit rows")
}

async fn invitation_state(pool: &PgPool, invitation: Uuid) -> (String, Option<Uuid>) {
    sqlx::query_as("SELECT status, membership_id FROM group_invitations WHERE id = $1")
        .bind(invitation)
        .fetch_one(pool)
        .await
        .expect("invitation row")
}

const REQUEST_PATH: &[&str] = &[
    "public.epigraph_person_create_team_group(text, text)",
    "public.epigraph_invite_to_team_group(uuid, uuid, text, text)",
    "public.epigraph_accept_group_invitation(uuid)",
    "public.epigraph_decline_group_invitation(uuid)",
    "public.epigraph_my_groups()",
    "public.epigraph_my_group_invitations()",
    "public.epigraph_team_group_roster_granted(uuid, uuid)",
];

/// The request-path functions are maintenance-owned definers on 172's path
/// that the application role, and not PUBLIC, executes; the grant table is
/// closed to the application role and `group_invitations` shows it no row.
#[sqlx::test(migrations = "../../migrations")]
async fn the_functions_are_app_callable_maintenance_owned_definers(pool: PgPool) {
    for sig in REQUEST_PATH {
        let (definer, owner, config, app, public): (bool, String, Option<Vec<String>>, bool, bool) =
            sqlx::query_as(
                "SELECT p.prosecdef, pg_get_userbyid(p.proowner)::text, p.proconfig, \
                        has_function_privilege('epigraph_app', p.oid, 'EXECUTE'), \
                        has_function_privilege('public', p.oid, 'EXECUTE') \
                   FROM pg_proc p WHERE p.oid = to_regprocedure($1)",
            )
            .bind(*sig)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("{sig} must exist: {e}"));
        assert!(definer, "{sig}: SECURITY DEFINER");
        assert_eq!(owner, "epigraph_maintenance", "{sig}: owner");
        assert_eq!(
            config,
            Some(vec!["search_path=pg_catalog, pg_temp".to_string()]),
            "{sig}: 172's path"
        );
        assert!(app, "{sig}: the application role executes it");
        assert!(!public, "{sig}: PUBLIC does not");
    }

    let (sel, ins, del): (bool, bool, bool) = sqlx::query_as(
        "SELECT has_table_privilege('epigraph_app', 'public.team_group_roster_grants', 'SELECT'), \
                has_table_privilege('epigraph_app', 'public.team_group_roster_grants', 'INSERT'), \
                has_table_privilege('epigraph_app', 'public.team_group_roster_grants', 'DELETE')",
    )
    .fetch_one(&pool)
    .await
    .expect("grant table privileges");
    assert_eq!(
        (sel, ins, del),
        (false, false, false),
        "the app role holds nothing on the grant table"
    );

    let a = human(&pool, "catalog-a").await;
    let b = human(&pool, "catalog-b").await;
    let group = create(&pool, Some(a), "Synthetic Catalog Team")
        .await
        .expect("create");
    invite(&pool, a, group, b, "reader").await.expect("invite");
    for who in [Some(a), Some(b), None] {
        let mut c = app_as(&pool, who).await;
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM group_invitations")
            .fetch_one(&mut *c)
            .await
            .expect("the app role may select");
        reset(c).await;
        assert_eq!(n, 0, "{who:?}: no invitation row is readable directly");
    }
    assert_eq!(
        my_invitations(&pool, b).await.len(),
        1,
        "POSITIVE CONTROL: through the read"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_person_creates_a_keyless_team_group_they_administer(pool: PgPool) {
    let a = human(&pool, "create-a").await;
    let group = create(&pool, Some(a), "  Synthetic Working Group ")
        .await
        .expect("a Person creates a team group");

    let (kind, did, key_len, creator, name, epochs): (String, String, i32, Uuid, String, i64) =
        sqlx::query_as(
            "SELECT g.kind::text, g.did_key, octet_length(g.public_key), g.created_by_agent_id, \
                    g.display_name::text, \
                    (SELECT count(*) FROM group_key_epochs e WHERE e.group_id = g.id) \
               FROM groups g WHERE g.id = $1",
        )
        .bind(group)
        .fetch_one(&pool)
        .await
        .expect("group row");
    assert_eq!(kind, "team");
    assert_eq!(
        did,
        format!("did:epigraph:group:{group}"),
        "164's namespace"
    );
    assert_eq!(key_len, 0, "keyless");
    assert_eq!(epochs, 0, "no key epoch");
    assert_eq!(creator, a);
    assert_eq!(name, "Synthetic Working Group", "trimmed");
    assert_eq!(
        rows(&pool, group, a).await,
        vec![("admin".to_string(), false)]
    );
    assert!(
        reads(&pool, a, group).await,
        "the creator's viewer carries the group"
    );
    assert_eq!(
        my_groups(&pool, a)
            .await
            .iter()
            .filter(|g| g.0 == group)
            .count(),
        1
    );
    assert!(
        my_groups(&pool, a)
            .await
            .iter()
            .any(|g| g.0 == group && g.1 == "admin" && g.2),
        "listed as an invitable group the caller administers"
    );

    let events = audit(&pool, group).await;
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].0, "group.team_created");
    assert_eq!(events[0].1, Some(a));
    assert_eq!(events[0].2["arm"], "person");
    assert!(
        events[0].2.get("actor").is_none(),
        "no caller-settable actor is recorded"
    );

    // One active group per name per creator; another Person may reuse it.
    let r = create(&pool, Some(a), "synthetic working group").await;
    assert_eq!(code_of(&r).as_deref(), Some("TGP06"), "{r:?}");
    let b = human(&pool, "create-b").await;
    create(&pool, Some(b), "Synthetic Working Group")
        .await
        .expect("POSITIVE CONTROL: the name rule is per creator");

    let r = create(&pool, Some(a), "   ").await;
    assert_eq!(code_of(&r).as_deref(), Some("TGP09"), "{r:?}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn only_a_person_signed_in_as_themselves_creates(pool: PgPool) {
    let a = human(&pool, "who-a").await;
    let agent = operated(&pool, a, "who-agent").await;
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM groups")
        .fetch_one(&pool)
        .await
        .unwrap();
    for caller in [Some(agent), None] {
        let r = create(&pool, caller, "Synthetic Refused Team").await;
        assert_eq!(code_of(&r).as_deref(), Some("TGP01"), "{caller:?}: {r:?}");
        assert!(message_of(&r).starts_with("TGP01:"), "a coded message");
    }
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM groups")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(before, after, "nothing was created");
    create(&pool, Some(a), "Synthetic Refused Team")
        .await
        .expect("POSITIVE CONTROL: the operator itself creates");
}

/// The whole consent flow: an invitation places no one; acceptance does,
/// once, at the invited role.
#[sqlx::test(migrations = "../../migrations")]
async fn a_membership_goes_live_only_when_the_invitee_accepts(pool: PgPool) {
    let a = human(&pool, "flow-a").await;
    let b = human(&pool, "flow-b").await;
    let group = create(&pool, Some(a), "Synthetic Flow Team")
        .await
        .expect("create");

    let invitation = invite(&pool, a, group, b, "writer").await.expect("invite");
    assert!(
        rows(&pool, group, b).await.is_empty(),
        "no membership before consent"
    );
    assert!(
        !reads(&pool, b, group).await,
        "the invitee does not read the group yet"
    );
    assert!(!my_groups(&pool, b).await.iter().any(|g| g.0 == group));
    assert_eq!(
        my_invitations(&pool, b).await,
        vec![(invitation, group, "writer".to_string(), a)]
    );
    assert!(
        my_invitations(&pool, a).await.is_empty(),
        "only the invitee sees it"
    );
    assert_eq!(
        invitation_state(&pool, invitation).await,
        ("pending".to_string(), None)
    );

    let (g, membership, role) = accept(&pool, b, invitation).await.expect("accept");
    assert_eq!((g, role.as_str()), (group, "writer"));
    assert_eq!(
        rows(&pool, group, b).await,
        vec![("writer".to_string(), false)]
    );
    assert!(reads(&pool, b, group).await, "live once accepted");
    assert_eq!(
        invitation_state(&pool, invitation).await,
        ("accepted".to_string(), Some(membership))
    );
    assert!(my_invitations(&pool, b).await.is_empty());
    assert!(my_groups(&pool, b)
        .await
        .iter()
        .any(|x| x.0 == group && x.1 == "writer"));

    let events = audit(&pool, group).await;
    let kinds: Vec<&str> = events.iter().map(|e| e.0.as_str()).collect();
    assert_eq!(
        kinds,
        vec![
            "group.team_created",
            "group.invitation_created",
            "group.member_added"
        ]
    );
    assert_eq!(events[1].1, Some(a), "the invitation is the inviter's act");
    assert_eq!(events[2].1, Some(b), "the acceptance is the invitee's act");
    assert_eq!(events[2].2["arm"], "invitation");
    assert_eq!(events[2].2["invitation_id"], invitation.to_string());
    assert_eq!(events[2].2["invited_by"], a.to_string());
    assert_eq!(events[2].2["membership_id"], membership.to_string());

    // Answered once.
    let r = accept(&pool, b, invitation).await;
    assert_eq!(code_of(&r).as_deref(), Some("TGP05"), "{r:?}");
    let r = decline(&pool, b, invitation).await;
    assert_eq!(code_of(&r).as_deref(), Some("TGP05"), "{r:?}");
    assert_eq!(rows(&pool, group, b).await.len(), 1, "no second row");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_declined_invitation_places_no_one_and_can_be_reissued(pool: PgPool) {
    let a = human(&pool, "decline-a").await;
    let b = human(&pool, "decline-b").await;
    let group = create(&pool, Some(a), "Synthetic Decline Team")
        .await
        .expect("create");
    let invitation = invite(&pool, a, group, b, "reader").await.expect("invite");
    assert_eq!(decline(&pool, b, invitation).await.expect("decline"), group);
    assert_eq!(invitation_state(&pool, invitation).await.0, "declined");
    assert!(
        rows(&pool, group, b).await.is_empty(),
        "declining places no one"
    );
    let r = accept(&pool, b, invitation).await;
    assert_eq!(code_of(&r).as_deref(), Some("TGP05"), "{r:?}");
    assert_eq!(
        audit(&pool, group)
            .await
            .last()
            .map(|e| e.0.clone())
            .as_deref(),
        Some("group.invitation_declined")
    );
    let again = invite(&pool, a, group, b, "reader")
        .await
        .expect("a declined invitation does not block a new one");
    assert_ne!(again, invitation);
}

#[sqlx::test(migrations = "../../migrations")]
async fn only_a_live_admin_invites_and_only_a_person_can_accept(pool: PgPool) {
    let a = human(&pool, "who-inv-a").await;
    let b = human(&pool, "who-inv-b").await;
    let c = human(&pool, "who-inv-c").await;
    let outsider = human(&pool, "who-inv-out").await;
    let agent = operated(&pool, c, "who-inv-agent").await;
    let group = create(&pool, Some(a), "Synthetic Who Team")
        .await
        .expect("create");
    let inv_b = invite(&pool, a, group, b, "writer")
        .await
        .expect("invite b");
    accept(&pool, b, inv_b).await.expect("b joins as writer");

    // A writer is not an admin.
    let r = invite(&pool, b, group, c, "reader").await;
    assert_eq!(code_of(&r).as_deref(), Some("TGP02"), "{r:?}");
    // A non-member is told the group does not exist, as for a missing one.
    let r = invite(&pool, outsider, group, c, "reader").await;
    assert_eq!(code_of(&r).as_deref(), Some("TGP08"), "{r:?}");
    let r = invite(&pool, outsider, Uuid::new_v4(), c, "reader").await;
    assert_eq!(code_of(&r).as_deref(), Some("TGP08"), "{r:?}");
    // An operated agent cannot send one for its human either.
    let r = invite(
        &pool,
        operated(&pool, a, "who-inv-a-agent").await,
        group,
        c,
        "reader",
    )
    .await;
    assert_eq!(code_of(&r).as_deref(), Some("TGP01"), "{r:?}");
    // Operator ruling C10 (migration 284): the invite no longer asks whether
    // the invitee is a person (TGP03 answered "is this id a registered
    // human?" to any team admin). An agent a Person operates is invited like
    // anyone; the refusal is at accept time (TGP01), so it never joins.
    let to_agent = invite(&pool, a, group, agent, "reader")
        .await
        .expect("C10: an operated agent is invited like anyone");
    let r = accept(&pool, agent, to_agent).await;
    assert_eq!(code_of(&r).as_deref(), Some("TGP01"), "{r:?}");
    assert!(rows(&pool, group, agent).await.is_empty(), "no membership");
    // A role's node is no one's to invite (its kind is public), TGP03.
    let r = invite(
        &pool,
        a,
        group,
        role_node(&pool, "who-inv-role").await,
        "reader",
    )
    .await;
    assert_eq!(code_of(&r).as_deref(), Some("TGP03"), "{r:?}");
    // A member or a pending invitee is not invited again.
    let r = invite(&pool, a, group, b, "reader").await;
    assert_eq!(code_of(&r).as_deref(), Some("TGP04"), "{r:?}");
    let r = invite(&pool, a, group, a, "reader").await;
    assert_eq!(code_of(&r).as_deref(), Some("TGP09"), "{r:?}");
    let r = invite(&pool, a, group, c, "owner").await;
    assert_eq!(code_of(&r).as_deref(), Some("TGP09"), "{r:?}");
    invite(&pool, a, group, c, "reader")
        .await
        .expect("POSITIVE CONTROL: the admin invites a Person");
    let r = invite(&pool, a, group, c, "reader").await;
    assert_eq!(code_of(&r).as_deref(), Some("TGP04"), "{r:?}");
}

/// Operator ruling C10 (migration 284; spec R11): the invite answers
/// IDENTICALLY whoever the invitee is, so a team admin cannot use it to learn
/// whether an id is a person, or a person named to them. For an unnamed
/// registered person (profile `'group'`, no shared team, no claims), a named
/// one (a registered person who opted in), a provider-provisioned person who
/// is not a registered operator, a production-shaped nameless service
/// principal and an agent a person operates: the first invite returns an
/// invitation id, and a second answers TGP04 with the same text modulo the
/// ids. The refusal moved to accept time: every invitee that is not a
/// registered person is refused TGP01 and joins nothing; the unnamed person
/// accepts (CALIBRATION).
#[sqlx::test(migrations = "../../migrations")]
async fn an_invitation_answers_alike_whoever_the_invitee_is(pool: PgPool) {
    let admin = human(&pool, "alike-admin").await;
    let group = create(&pool, Some(admin), "Synthetic Alike Team")
        .await
        .expect("create");
    let unnamed = human(&pool, "alike-unnamed").await;
    sqlx::query("UPDATE agents SET profile_visibility = 'group' WHERE id = $1")
        .bind(unnamed)
        .execute(&pool)
        .await
        .expect("unnamed keeps a group profile");
    let unregistered = provisioned(&pool, "human", "Odile Unregistered").await;
    let named = human(&pool, "alike-named").await;
    sqlx::query(
        "UPDATE agents SET profile_visibility = 'public', profile_public_consented_at = now() \
          WHERE id = $1",
    )
    .bind(named)
    .execute(&pool)
    .await
    .expect("named opts in");
    let service = provisioned(&pool, "service", "fixture service").await;
    let bot = operated(&pool, named, "alike-bot").await;

    let mut shapes = Vec::new();
    let mut invitations = Vec::new();
    for (who, label) in [
        (unnamed, "unnamed person"),
        (named, "named person"),
        (unregistered, "unregistered person"),
        (service, "service principal"),
        (bot, "operated agent"),
    ] {
        let first = invite(&pool, admin, group, who, "reader").await;
        let invitation = first.unwrap_or_else(|e| panic!("{label}: invited, got {e:?}"));
        let again = invite(&pool, admin, group, who, "reader").await;
        assert_eq!(
            code_of(&again).as_deref(),
            Some("TGP04"),
            "{label}: {again:?}"
        );
        let shape = message_of(&again)
            .replace(&who.to_string(), "<invitee>")
            .replace(&group.to_string(), "<group>");
        shapes.push((label, shape));
        invitations.push((who, invitation));
    }
    for (label, shape) in &shapes[1..] {
        assert_eq!(shape, &shapes[0].1, "{label} answers as {}", shapes[0].0);
    }

    for (who, invitation) in &invitations[2..] {
        let r = accept(&pool, *who, *invitation).await;
        assert_eq!(code_of(&r).as_deref(), Some("TGP01"), "{who}: {r:?}");
        assert!(
            rows(&pool, group, *who).await.is_empty(),
            "{who} joined nothing"
        );
        assert_eq!(invitation_state(&pool, *invitation).await.0, "pending");
    }
    accept(&pool, unnamed, invitations[0].1)
        .await
        .expect("CALIBRATION: the invited person accepts");
    assert_eq!(
        rows(&pool, group, unnamed).await,
        vec![("reader".to_string(), false)]
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn only_the_invitee_answers_and_its_agent_cannot(pool: PgPool) {
    let a = human(&pool, "answer-a").await;
    let b = human(&pool, "answer-b").await;
    let other = human(&pool, "answer-other").await;
    let b_agent = operated(&pool, b, "answer-b-agent").await;
    let group = create(&pool, Some(a), "Synthetic Answer Team")
        .await
        .expect("create");
    let invitation = invite(&pool, a, group, b, "reader").await.expect("invite");

    for caller in [other, a] {
        let r = accept(&pool, caller, invitation).await;
        assert_eq!(code_of(&r).as_deref(), Some("TGP08"), "{caller}: {r:?}");
        let r = decline(&pool, caller, invitation).await;
        assert_eq!(code_of(&r).as_deref(), Some("TGP08"), "{caller}: {r:?}");
    }
    let r = accept(&pool, b_agent, invitation).await;
    assert_eq!(
        code_of(&r).as_deref(),
        Some("TGP01"),
        "the invitee's agent does not consent for them: {r:?}"
    );
    assert!(rows(&pool, group, b).await.is_empty());
    assert!(rows(&pool, group, b_agent).await.is_empty());
    assert_eq!(invitation_state(&pool, invitation).await.0, "pending");
    accept(&pool, b, invitation)
        .await
        .expect("POSITIVE CONTROL: the invitee accepts");
}

/// An invitation lapses when its sender is no longer a live admin, and the
/// keyed-team and personal groups take none.
#[sqlx::test(migrations = "../../migrations")]
async fn an_invitation_lapses_with_its_sender_and_other_groups_take_none(pool: PgPool) {
    let a = human(&pool, "lapse-a").await;
    let a2 = human(&pool, "lapse-a2").await;
    let b = human(&pool, "lapse-b").await;
    let group = create(&pool, Some(a), "Synthetic Lapse Team")
        .await
        .expect("create");
    let inv_a2 = invite(&pool, a, group, a2, "admin")
        .await
        .expect("invite a2");
    accept(&pool, a2, inv_a2).await.expect("a2 joins as admin");
    let invitation = invite(&pool, a, group, b, "reader")
        .await
        .expect("invite b");

    // The operator's verb removes a, the invitation's sender.
    let mut m = pool.acquire().await.expect("acquire");
    m.execute("SET SESSION AUTHORIZATION epigraph_maintenance")
        .await
        .expect("maintenance");
    sqlx::query("SELECT out_applied FROM public.epigraph_team_group_remove_member($1, $2, $3)")
        .bind(group)
        .bind(a)
        .bind("person team group test")
        .fetch_one(&mut *m)
        .await
        .expect("remove the sender");
    m.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset");

    let r = accept(&pool, b, invitation).await;
    assert_eq!(code_of(&r).as_deref(), Some("TGP05"), "{r:?}");
    assert!(rows(&pool, group, b).await.is_empty());
    let again = invite(&pool, a2, group, b, "reader").await;
    assert_eq!(
        code_of(&again).as_deref(),
        Some("TGP04"),
        "the lapsed invitation is still pending until answered: {again:?}"
    );
    decline(&pool, b, invitation)
        .await
        .expect("decline the lapsed one");
    let fresh = invite(&pool, a2, group, b, "reader")
        .await
        .expect("a current admin re-invites");
    accept(&pool, b, fresh)
        .await
        .expect("POSITIVE CONTROL: then it is accepted");

    // A personal group (its owner is its admin) takes no invitation.
    let (owner, personal) = fixture::seed_human_operator(&pool, "lapse-personal").await;
    let r = invite(&pool, owner, personal, b, "reader").await;
    assert_eq!(code_of(&r).as_deref(), Some("TGP07"), "{r:?}");
}

/// A team group the OPERATOR made with 164's `create-group` takes no
/// invitation, even from a Person who is a live admin of it: its roster stays
/// the operator's audited verbs' alone. Only a group a Person made through
/// 263's create is invitable, and the application role cannot mark one so.
#[sqlx::test(migrations = "../../migrations")]
async fn an_operator_made_team_group_takes_no_invitation(pool: PgPool) {
    let h = human(&pool, "opgroup-admin").await;
    let b = human(&pool, "opgroup-b").await;
    let mut m = pool.acquire().await.expect("acquire");
    m.execute("SET SESSION AUTHORIZATION epigraph_maintenance")
        .await
        .expect("maintenance");
    let op_group: Uuid = sqlx::query_scalar("SELECT public.epigraph_create_team_group($1, $2, $3)")
        .bind("Synthetic Operator Team")
        .bind(h)
        .bind("person team group test")
        .fetch_one(&mut *m)
        .await
        .expect("the operator's verb makes a team group with h as its admin");
    m.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset");
    assert_eq!(
        rows(&pool, op_group, h).await,
        vec![("admin".to_string(), false)],
        "PREMISE: h is a live admin of the operator's group"
    );

    let r = invite(&pool, h, op_group, b, "admin").await;
    assert_eq!(code_of(&r).as_deref(), Some("TGP07"), "{r:?}");
    assert!(rows(&pool, op_group, b).await.is_empty());
    assert!(
        my_groups(&pool, h)
            .await
            .iter()
            .any(|g| g.0 == op_group && g.1 == "admin" && !g.2),
        "listed, but not as invitable"
    );

    // The application role cannot mark the operator's group as Person-made.
    let mut c = app_as(&pool, Some(h)).await;
    let r = sqlx::query("INSERT INTO person_team_groups (group_id, created_by) VALUES ($1, $2)")
        .bind(op_group)
        .bind(h)
        .execute(&mut *c)
        .await;
    assert_eq!(code_of(&r).as_deref(), Some("42501"), "{r:?}");
    reset(c).await;
    let r = invite(&pool, h, op_group, b, "reader").await;
    assert_eq!(code_of(&r).as_deref(), Some("TGP07"), "{r:?}");

    // POSITIVE CONTROL: the same Person's own group takes the same invitation.
    let own = create(&pool, Some(h), "Synthetic Own Team")
        .await
        .expect("create");
    invite(&pool, h, own, b, "admin")
        .await
        .expect("a Person-made group takes invitations");
    assert!(my_groups(&pool, h).await.iter().any(|g| g.0 == own && g.2));
}

/// 164's guards still refuse every direct application write to a verb-made
/// group, with 176's exact text, including right after a person act in the
/// same transaction; and no grant row survives the act that wrote it.
#[sqlx::test(migrations = "../../migrations")]
async fn the_guards_admit_only_the_definers_own_rows(pool: PgPool) {
    let a = human(&pool, "guard-a").await;
    let b = human(&pool, "guard-b").await;
    let mut c = app_as(&pool, Some(a)).await;
    let mut tx = sqlx::Connection::begin(&mut *c).await.expect("begin");
    let group = create_on(&mut tx, "Synthetic Guard Team")
        .await
        .expect("create in the transaction");
    sqlx::query("SAVEPOINT direct")
        .execute(&mut *tx)
        .await
        .unwrap();
    let r = sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'writer')",
    )
    .bind(group)
    .bind(b)
    .execute(&mut *tx)
    .await;
    assert_eq!(code_of(&r).as_deref(), Some("42501"), "{r:?}");
    assert_eq!(
        message_of(&r),
        format!(
            "GRM05: group_memberships: the roster of team group {group} is written only by the \
             team-group verbs (epigraph-operator group-member, on the maintenance DSN); nothing \
             was changed"
        ),
        "176's text, unchanged"
    );
    sqlx::query("ROLLBACK TO SAVEPOINT direct")
        .execute(&mut *tx)
        .await
        .unwrap();
    let probe = Uuid::new_v4();
    let r = sqlx::query(
        "INSERT INTO groups (id, display_name, did_key, public_key, kind, created_by_agent_id) \
         VALUES ($1, 'probe', 'did:epigraph:group:' || $1::text, ''::bytea, 'team', $2)",
    )
    .bind(probe)
    .bind(a)
    .execute(&mut *tx)
    .await;
    assert_eq!(code_of(&r).as_deref(), Some("42501"), "{r:?}");
    assert!(
        message_of(&r).starts_with("GRM06: groups: a keyless team group"),
        "{r:?}"
    );
    sqlx::query("ROLLBACK TO SAVEPOINT direct")
        .execute(&mut *tx)
        .await
        .unwrap();
    // The group the definer made is NOT a grant for the creator's own direct
    // write either (an UPDATE of its admin row).
    let r = sqlx::query(
        "UPDATE group_memberships SET role = 'admin' WHERE group_id = $1 AND agent_id = $2",
    )
    .bind(group)
    .bind(a)
    .execute(&mut *tx)
    .await;
    assert!(message_of(&r).starts_with("GRM05:"), "{r:?}");
    sqlx::query("ROLLBACK TO SAVEPOINT direct")
        .execute(&mut *tx)
        .await
        .unwrap();
    // No grant row is left in this transaction (read as the superuser,
    // still inside it).
    tx.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset in tx");
    let left: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM team_group_roster_grants WHERE xact_id = pg_current_xact_id()",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("count grants");
    assert_eq!(left, 0, "the definer cleared its grants");
    tx.commit().await.expect("commit");
    reset(c).await;
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM team_group_roster_grants")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(total, 0);
    assert_eq!(
        rows(&pool, group, a).await,
        vec![("admin".to_string(), false)]
    );
    assert!(rows(&pool, group, b).await.is_empty());
}

/// `PersonTeamGroupRepository` answers each designed refusal by its kind (the
/// one mapping the REST routes and the MCP tools share): authority, input and
/// state as `Refused`, and a group or invitation the caller may not see as
/// `NotFound`, exactly like a missing one.
#[sqlx::test(migrations = "../../migrations")]
async fn the_repository_maps_each_refusal_by_kind(pool: PgPool) {
    use epigraph_db::{DbError, PersonTeamGroupRepository as Repo, RefusalKind};
    fn kind_of<T: std::fmt::Debug>(r: &Result<T, DbError>) -> String {
        match r {
            Err(DbError::Refused { kind, message }) => {
                format!("{kind:?}:{}", message.split(':').next().unwrap_or(""))
            }
            Err(DbError::NotFound { entity, .. }) => format!("NotFound:{entity}"),
            other => format!("{other:?}"),
        }
    }
    let a = human(&pool, "repo-a").await;
    let b = human(&pool, "repo-b").await;
    let agent = operated(&pool, a, "repo-agent").await;

    let mut c = app_as(&pool, Some(agent)).await;
    let r = Repo::create_conn(&mut c, "Synthetic Repo Team", None).await;
    assert_eq!(kind_of(&r), format!("{:?}:TGP01", RefusalKind::Authority));
    reset(c).await;

    let mut c = app_as(&pool, Some(a)).await;
    let group = Repo::create_conn(&mut c, "Synthetic Repo Team", Some("a reason"))
        .await
        .expect("create");
    let r = Repo::create_conn(&mut c, "Synthetic Repo Team", None).await;
    assert_eq!(kind_of(&r), format!("{:?}:TGP06", RefusalKind::State));
    let role = role_node(&pool, "repo-role").await;
    let r = Repo::invite_conn(&mut c, group, role, "reader", None).await;
    assert_eq!(kind_of(&r), format!("{:?}:TGP03", RefusalKind::Input));
    let r = Repo::invite_conn(&mut c, group, b, "owner", None).await;
    assert_eq!(kind_of(&r), format!("{:?}:TGP09", RefusalKind::Input));
    let missing = Uuid::new_v4();
    let r = Repo::invite_conn(&mut c, missing, b, "reader", None).await;
    assert!(
        matches!(&r, Err(DbError::NotFound { entity, id }) if entity == "group" && *id == missing),
        "{r:?}"
    );
    let invitation = Repo::invite_conn(&mut c, group, b, "writer", Some("join"))
        .await
        .expect("invite");
    let r = Repo::accept_conn(&mut c, invitation).await;
    assert!(
        matches!(&r, Err(DbError::NotFound { entity, .. }) if entity == "invitation"),
        "only the invitee sees it: {r:?}"
    );
    reset(c).await;

    let mut c = app_as(&pool, Some(b)).await;
    let mine = Repo::my_invitations_conn(&mut c)
        .await
        .expect("my invitations");
    assert_eq!(mine.len(), 1);
    assert_eq!(
        (
            mine[0].invitation_id,
            mine[0].group_id,
            mine[0].role.as_str(),
            mine[0].invited_by
        ),
        (invitation, group, "writer", a)
    );
    assert_eq!(mine[0].display_name.as_deref(), Some("Synthetic Repo Team"));
    assert_eq!(mine[0].reason.as_deref(), Some("join"));
    let accepted = Repo::accept_conn(&mut c, invitation).await.expect("accept");
    assert_eq!(
        (accepted.group_id, accepted.role.as_str()),
        (group, "writer")
    );
    let r = Repo::accept_conn(&mut c, invitation).await;
    assert_eq!(kind_of(&r), format!("{:?}:TGP05", RefusalKind::State));
    let groups = Repo::my_groups_conn(&mut c).await.expect("my groups");
    let g = groups.iter().find(|g| g.group_id == group).expect("listed");
    assert_eq!(
        (
            g.kind.as_str(),
            g.status.as_str(),
            g.role.as_str(),
            g.created_by,
            g.invitable
        ),
        ("team", "active", "writer", Some(a), true)
    );
    let r = Repo::invite_conn(&mut c, group, a, "reader", None).await;
    assert_eq!(kind_of(&r), format!("{:?}:TGP02", RefusalKind::Authority));
    reset(c).await;
}

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

/// 284 re-states 263's invite; over any other body it refuses (TIV01) with
/// nothing changed.
#[sqlx::test(migrations = false)]
async fn migration_284_refuses_over_another_invite_body(pool: PgPool) {
    let below = sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            MIGRATOR
                .migrations
                .iter()
                .filter(|m| m.version < 284)
                .cloned()
                .collect(),
        ),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    };
    let mut conn = pool.acquire().await.expect("acquire");
    below.run(&mut *conn).await.expect("migrate to 283");
    sqlx::query("RESET ALL")
        .execute(&mut *conn)
        .await
        .expect("RESET ALL");
    sqlx::query(
        "CREATE OR REPLACE FUNCTION public.epigraph_invite_to_team_group( \
             p_group uuid, p_invitee uuid, p_role text, p_reason text) \
         RETURNS uuid LANGUAGE plpgsql VOLATILE SECURITY DEFINER \
         SET search_path = pg_catalog, pg_temp AS $$ BEGIN RETURN NULL; END $$",
    )
    .execute(&mut *conn)
    .await
    .expect("another body");
    let err = MIGRATOR
        .run(&mut *conn)
        .await
        .expect_err("284 must refuse over another body")
        .to_string();
    assert!(err.contains("TIV01"), "precondition refusal: {err}");
}
