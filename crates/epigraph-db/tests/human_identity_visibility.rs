//! The human-identity disclosure predicate (migration 272) and the profile
//! opt-in / reset that feed it (migrations 273, 274). Spec:
//! `docs/superpowers/specs/2026-11-24-human-identity-visibility-design.md`
//! (sections 3, 4, 6.1, 8, 10 and the T-numbers of section 12).
//!
//! # What is under test
//!
//! * The rule, arm by arm, through the SESSION wrapper
//!   `epigraph_agent_disclosure(target)` on an `epigraph_app` connection
//!   stamped from the viewer's resolved `Viewer`, exactly as a request reads.
//!   Every "unnamed" assertion is paired with a CALIBRATION that the same
//!   target is named to some viewer the rule admits, so no test passes by
//!   redacting everyone.
//! * Non-human targets decide `details` exactly as today's profile rule
//!   (`AgentRepository::profile_details_visible`) does (T11).
//! * The fail directions: a non-member, NOSUPERUSER owner of the core reads no
//!   binding and names no one through a bound agent's claim (T10); the
//!   human-evidence row cannot be deleted or retyped (HEV01).
//! * The accountability property (T13): whoever can read a claim, as the
//!   claims read policy decides on their own stamped session, sees its filer
//!   and the filer's human at filing time named.
//!
//! # Why the reads run as `epigraph_app`
//!
//! `#[sqlx::test]` connects as a superuser, and a superuser session is
//! privileged (`epigraph_bypass()` reads `session_user`), which the rule's
//! privileged arm admits. Fixture rows are seeded on the superuser pool.
//!
//! All names are invented.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::pool::{ScopedPool, SessionGucMode};
use epigraph_db::visibility::Viewer;
use sqlx::PgPool;
use uuid::Uuid;

// ─── harness ─────────────────────────────────────────────────────────────

async fn app_pool(pool: &PgPool) -> ScopedPool {
    ScopedPool::connect_downgraded_for_tests(
        &fixture::database_url_for(pool).await,
        SessionGucMode::Session,
        "epigraph_app",
    )
    .await
    .expect("app-role ScopedPool")
}

async fn viewer(pool: &PgPool, who: Uuid) -> Viewer {
    Viewer::resolve(pool, who).await.expect("resolve viewer")
}

/// `(named, details)` for `target`, read by `v` through the session wrapper on
/// an `epigraph_app` connection stamped from `v`.
async fn disclosure(scoped: &ScopedPool, v: &Viewer, target: Uuid) -> (bool, bool) {
    let mut read = scoped.read_as(v).await.expect("read_as");
    let who_am_i: String = sqlx::query_scalar("SELECT session_user::text")
        .fetch_one(&mut *read)
        .await
        .expect("session_user");
    assert_eq!(
        who_am_i, "epigraph_app",
        "CALIBRATION: reads run as the app role"
    );
    let row: (bool, bool) =
        sqlx::query_as("SELECT named, details FROM public.epigraph_agent_disclosure($1)")
            .bind(target)
            .fetch_one(&mut *read)
            .await
            .expect("epigraph_agent_disclosure");
    let named_only: bool = sqlx::query_scalar("SELECT public.epigraph_human_named_to_viewer($1)")
        .bind(target)
        .fetch_one(&mut *read)
        .await
        .expect("epigraph_human_named_to_viewer");
    assert_eq!(
        named_only, row.0,
        "the name-only wrapper disagrees with the disclosure wrapper"
    );
    row
}

async fn named_to(pool: &PgPool, scoped: &ScopedPool, who: Uuid, target: Uuid) -> bool {
    disclosure(scoped, &viewer(pool, who).await, target).await.0
}

async fn named_to_guest(pool: &PgPool, scoped: &ScopedPool, target: Uuid) -> bool {
    disclosure(scoped, &fixture::public_viewer(pool).await, target)
        .await
        .0
}

// ─── fixtures ────────────────────────────────────────────────────────────

/// An agent with a personal group and a display name.
async fn named(pool: &PgPool, name: &str) -> (Uuid, Uuid) {
    let (a, g) = fixture::seed_agent_with_group(pool, name).await;
    sqlx::query("UPDATE agents SET display_name = $2 WHERE id = $1")
        .bind(a)
        .bind(name)
        .execute(pool)
        .await
        .expect("name");
    (a, g)
}

async fn set_profile(pool: &PgPool, agent: Uuid, profile: &str) {
    sqlx::query("UPDATE agents SET profile_visibility = $2 WHERE id = $1")
        .bind(agent)
        .bind(profile)
        .execute(pool)
        .await
        .expect("profile");
}

/// A registered human operator whose profile is `'group'`, as provisioning
/// writes it from migration 274 on (the fixture's raw insert takes the
/// column default `'public'`, which the rule reads as consent).
async fn human(pool: &PgPool, name: &str) -> (Uuid, Uuid) {
    let (a, g) = named(pool, name).await;
    fixture::make_human_operator(pool, a).await;
    set_profile(pool, a, "group").await;
    (a, g)
}

/// A provider-provisioned person who is NOT a registered operator: the only
/// human evidence is a linked `client_type = 'human'` OAuth client.
async fn client_only_human(pool: &PgPool, name: &str) -> (Uuid, Uuid) {
    let (a, g) = named(pool, name).await;
    sqlx::query(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    status, agent_id) \
         VALUES ($1, $2, 'human', ARRAY['claims:write'], 'active', $3)",
    )
    .bind(format!("fixture-provider:{a}"))
    .bind(name)
    .bind(a)
    .execute(pool)
    .await
    .expect("human client");
    set_profile(pool, a, "group").await;
    (a, g)
}

async fn link(pool: &PgPool, agent: Uuid, operator: Uuid) {
    let mut conn = pool.acquire().await.expect("acquire");
    let out = epigraph_db::AgentRepository::link_operator(&mut conn, agent, operator)
        .await
        .expect("live link");
    assert!(out.link_live, "fixture link must be live");
}

async fn retire_link(pool: &PgPool, agent: Uuid) {
    let outcome: String = fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let r: String = sqlx::query_scalar(
            "SELECT outcome FROM public.epigraph_retire_operator_link($1, 'visibility test', true)",
        )
        .bind(agent)
        .fetch_one(&mut *conn)
        .await
        .expect("retire the link");
        (conn, r)
    })
    .await;
    assert_eq!(outcome, "retired", "CALIBRATION: the link was live");
}

/// An agent bound to `operator` by a 149 allowance on its own service client.
async fn allowance_bound(pool: &PgPool, operator: Uuid, name: &str) -> (Uuid, Uuid) {
    let (agent, _) = named(pool, name).await;
    let client: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    status, agent_id, legal_entity_name, legal_contact_email) \
         VALUES ($1, 'visibility allowance fixture', 'service', ARRAY['claims:write'], \
                 'active', $2, 'Fixture Org', 'fixture@example.invalid') RETURNING id",
    )
    .bind(format!("visibility-allowance-{}", Uuid::new_v4()))
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("service client");
    let allowed: bool = fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let r: bool = sqlx::query_scalar(
            "SELECT allowed_now FROM public.epigraph_allow_author_binding_client($1, $2, $3)",
        )
        .bind(client)
        .bind(operator)
        .bind("visibility test")
        .fetch_one(&mut *conn)
        .await
        .expect("allow the client for the operator");
        (conn, r)
    })
    .await;
    assert!(allowed, "CALIBRATION: the allowance is in force");
    (agent, client)
}

async fn revoke_allowance(pool: &PgPool, client: Uuid) {
    let revoked: bool = fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let r: bool = sqlx::query_scalar(
            "SELECT revoked_now FROM public.epigraph_revoke_author_binding_client($1, \
                                                                              'visibility test')",
        )
        .bind(client)
        .fetch_one(&mut *conn)
        .await
        .expect("revoke the allowance");
        (conn, r)
    })
    .await;
    assert!(revoked, "CALIBRATION: the allowance was live");
}

/// A group of `kind` (`team` carries a 32-byte key, a `community` none) whose
/// `did_key` is `did_key`, with `members` as writers.
async fn group_of(pool: &PgPool, kind: &str, did_key: &str, members: &[Uuid]) -> Uuid {
    let id = Uuid::new_v4();
    let key: Vec<u8> = if kind == "team" {
        id.as_bytes().iter().copied().cycle().take(32).collect()
    } else {
        Vec::new()
    };
    sqlx::query(
        "INSERT INTO groups (id, display_name, did_key, public_key, kind, created_by_agent_id) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(format!("visibility {kind} {id}"))
    .bind(did_key)
    .bind(&key)
    .bind(kind)
    .bind(members[0])
    .execute(pool)
    .await
    .expect("group");
    for m in members {
        sqlx::query(
            "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
             VALUES ($1, $2, ''::bytea, 0, 'writer')",
        )
        .bind(id)
        .bind(m)
        .execute(pool)
        .await
        .expect("membership");
    }
    id
}

async fn keyed_team(pool: &PgPool, members: &[Uuid]) -> Uuid {
    group_of(
        pool,
        "team",
        &format!("did:key:visibility-{}", Uuid::new_v4()),
        members,
    )
    .await
}

// ─── T-basic: a human with no arm ────────────────────────────────────────

/// A human principal with no arm is UNNAMED to an outsider and to the guest
/// viewer, and its details are hidden; it is named to itself and to a
/// teammate (CALIBRATION). Both kinds of human evidence count: a registered
/// operator, and a provider client with no registration.
#[sqlx::test(migrations = "../../migrations")]
async fn a_human_with_no_arm_is_unnamed_to_outsiders_and_named_to_itself(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (outsider, _) = named(&pool, "Quentin Outsider").await;
    for (h, label) in [
        (human(&pool, "Ines Operator").await.0, "registered operator"),
        (
            client_only_human(&pool, "Pavel Provider").await.0,
            "provider client only",
        ),
    ] {
        let (mate, _) = named(&pool, &format!("mate of {label}")).await;
        keyed_team(&pool, &[h, mate]).await;

        assert_eq!(
            disclosure(&scoped, &viewer(&pool, outsider).await, h).await,
            (false, false),
            "{label}: an outsider must see an unnamed human with no details"
        );
        assert!(
            !named_to_guest(&pool, &scoped, h).await,
            "{label}: the guest viewer must see an unnamed human"
        );
        assert_eq!(
            disclosure(&scoped, &viewer(&pool, h).await, h).await,
            (true, true),
            "{label}: a human is always named to itself"
        );
        assert!(
            named_to(&pool, &scoped, mate, h).await,
            "CALIBRATION ({label}): a teammate sees the name"
        );
    }
}

// ─── T11: non-human targets decide as today ──────────────────────────────

/// For a non-human target, `named` is always true and `details` equals
/// today's profile rule (`AgentRepository::profile_details_visible`) over the
/// profile x self x shared-group matrix. A `'group'`-profile service is still
/// NAMED to an outsider: the new rule redacts humans only.
#[sqlx::test(migrations = "../../migrations")]
async fn non_human_targets_are_named_and_details_follow_todays_rule(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (outsider, _) = named(&pool, "Rhea Reader").await;
    let (peer, _) = named(&pool, "Saul Peer").await;
    let mut targets = Vec::new();
    for profile in ["public", "group"] {
        for shares in [false, true] {
            let (t, _) = named(&pool, &format!("svc {profile} {shares}")).await;
            set_profile(&pool, t, profile).await;
            if shares {
                keyed_team(&pool, &[t, peer]).await;
            }
            targets.push(t);
        }
    }
    let mut checked = 0;
    for who in [outsider, peer] {
        let v = viewer(&pool, who).await;
        let mut read = scoped.read_as(&v).await.expect("read_as");
        let today = epigraph_db::AgentRepository::profile_details_visible(&mut *read, &v, &targets)
            .await
            .expect("today's rule");
        drop(read);
        for t in &targets {
            let (n, d) = disclosure(&scoped, &v, *t).await;
            assert!(n, "a non-human agent must be named to every reader");
            assert_eq!(
                d,
                today.contains(t),
                "details for non-human {t} as {who} must equal today's profile rule"
            );
            checked += 1;
        }
        // Self: always details.
        assert_eq!(disclosure(&scoped, &v, who).await, (true, true), "self");
    }
    assert_eq!(checked, 8, "CALIBRATION: the whole matrix was read");
    // CALIBRATION: the matrix holds both answers, so equality is not vacuous.
    let v = viewer(&pool, outsider).await;
    let answers: std::collections::BTreeSet<bool> = {
        let mut s = std::collections::BTreeSet::new();
        for t in &targets {
            s.insert(disclosure(&scoped, &v, *t).await.1);
        }
        s
    };
    assert_eq!(
        answers.len(),
        2,
        "CALIBRATION: details is true for some, false for others"
    );
}

// ─── T3: the team arm ────────────────────────────────────────────────────

/// A shared active team or community names H; a shared personal, world or
/// seed group, a suspended team, or a revoked membership does not.
#[sqlx::test(migrations = "../../migrations")]
async fn the_team_arm_counts_live_team_and_community_memberships_only(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (h, h_personal) = human(&pool, "Tamsin Teamed").await;

    // Active team: named.
    let (mate, _) = named(&pool, "Ulla Mate").await;
    keyed_team(&pool, &[h, mate]).await;
    assert!(named_to(&pool, &scoped, mate, h).await, "a teammate sees H");

    // Active community: named.
    let (comm_mate, _) = named(&pool, "Vito Commoner").await;
    group_of(
        &pool,
        "community",
        &format!("did:key:visibility-community-{}", Uuid::new_v4()),
        &[h, comm_mate],
    )
    .await;
    assert!(
        named_to(&pool, &scoped, comm_mate, h).await,
        "a fellow community member sees H"
    );

    // Suspended team: not named.
    let (susp_mate, _) = named(&pool, "Wren Suspended").await;
    let susp = keyed_team(&pool, &[h, susp_mate]).await;
    sqlx::query("UPDATE groups SET status = 'suspended' WHERE id = $1")
        .bind(susp)
        .execute(&pool)
        .await
        .expect("suspend");
    assert!(
        !named_to(&pool, &scoped, susp_mate, h).await,
        "a suspended team must not name H"
    );

    // Revoked membership (H's side): not named.
    let (rev_mate, _) = named(&pool, "Xavi Revoked").await;
    let rev = keyed_team(&pool, &[h, rev_mate]).await;
    sqlx::query(
        "UPDATE group_memberships SET revoked_at = now() WHERE group_id = $1 AND agent_id = $2",
    )
    .bind(rev)
    .bind(h)
    .execute(&pool)
    .await
    .expect("revoke H's membership");
    assert!(
        !named_to(&pool, &scoped, rev_mate, h).await,
        "a revoked membership must not name H"
    );

    // A member of H's personal group (never a team), with no other arm.
    let (in_personal, _) = named(&pool, "Yusuf Personal").await;
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'reader')",
    )
    .bind(h_personal)
    .bind(in_personal)
    .execute(&pool)
    .await
    .expect("personal-group membership");
    assert!(
        !named_to(&pool, &scoped, in_personal, h).await,
        "co-membership of H's personal group confers nothing"
    );
}

/// Finding 8: a verb-made team (`did:epigraph:group:`, 164/263) counts for H
/// only while H's registration and client are live. Suspending H's client
/// makes H unnamed to a teammate whose only arm was that team; a claim of
/// H's in that team keeps H named (the readable-claim arm reads no status).
#[sqlx::test(migrations = "../../migrations")]
async fn a_suspended_client_lapses_a_verb_made_team_but_not_a_readable_claim(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (h, _) = human(&pool, "Zora Verbteam").await;
    // A verb-made team is a Person team: 236 admits its rows only for a live
    // human, on the viewer's side too.
    let (mate, _) = human(&pool, "Abel Verbmate").await;
    let team = group_of(
        &pool,
        "community",
        &format!("did:epigraph:group:{}", Uuid::new_v4()),
        &[h, mate],
    )
    .await;
    assert!(
        named_to(&pool, &scoped, mate, h).await,
        "CALIBRATION: the verb-made group names H while H's client is active"
    );
    sqlx::query("UPDATE oauth_clients SET status = 'suspended' WHERE agent_id = $1")
        .bind(h)
        .execute(&pool)
        .await
        .expect("suspend H's client");
    assert!(
        !named_to(&pool, &scoped, mate, h).await,
        "a suspended human's verb-made team must lapse (236's live-membership rule)"
    );
    fixture::seed_group_claim(&pool, h, team, "a group claim the mate reads").await;
    assert!(
        named_to(&pool, &scoped, mate, h).await,
        "a claim of H's that the mate can read keeps H named whatever the status"
    );
}

// ─── T5 (rule half): the opt-in arm ──────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn a_public_profile_names_the_human_to_everyone(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (outsider, _) = named(&pool, "Bea Browser").await;
    let (h, _) = human(&pool, "Cyril Consenting").await;
    assert!(
        !named_to(&pool, &scoped, outsider, h).await,
        "CALIBRATION: unnamed before the opt-in"
    );
    set_profile(&pool, h, "public").await;
    assert_eq!(
        disclosure(&scoped, &viewer(&pool, outsider).await, h).await,
        (true, true),
        "an opted-in human is named, with details, to an outsider"
    );
    assert!(
        named_to_guest(&pool, &scoped, h).await,
        "and to the guest viewer"
    );
}

// ─── T2, T6: the public-claim arm ────────────────────────────────────────

/// "No anonymous claims": a human whose only public claim was filed by a
/// bound agent whose binding is now RETIRED (a link) or REVOKED (an
/// allowance) is named to an outsider and to the guest viewer.
#[sqlx::test(migrations = "../../migrations")]
async fn a_public_claim_by_a_retired_or_revoked_bound_agent_names_the_human(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (outsider, _) = named(&pool, "Dora Distant").await;

    // A retired operator link.
    let (h1, _) = human(&pool, "Emil Linked").await;
    let (bot, _) = named(&pool, "emil-bot").await;
    link(&pool, bot, h1).await;
    assert!(
        !named_to(&pool, &scoped, outsider, h1).await,
        "CALIBRATION: a link alone names no one"
    );
    fixture::seed_public_claim(&pool, bot, "a public claim by a linked bot").await;
    retire_link(&pool, bot).await;
    assert!(
        named_to(&pool, &scoped, outsider, h1).await,
        "a retired link's public claim names its human to an outsider"
    );
    assert!(
        named_to_guest(&pool, &scoped, h1).await,
        "and to the guest viewer"
    );
    // The details stay hidden: the profile is still 'group' (spec B4).
    assert_eq!(
        disclosure(&scoped, &viewer(&pool, outsider).await, h1).await,
        (true, false),
        "a public claim names H but does not widen its details"
    );

    // A revoked author-binding allowance.
    let (h2, _) = human(&pool, "Fanny Allowed").await;
    let (svc, client) = allowance_bound(&pool, h2, "fanny-service").await;
    fixture::seed_public_claim(&pool, svc, "a public claim by an allowed service").await;
    revoke_allowance(&pool, client).await;
    assert!(
        named_to(&pool, &scoped, outsider, h2).await,
        "a revoked allowance's public claim names its human"
    );
}

/// T6: the public claim need not be current: a superseded one still names H
/// (`is_current` is never read).
#[sqlx::test(migrations = "../../migrations")]
async fn a_superseded_public_claim_still_names_the_human(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (outsider, _) = named(&pool, "Gil Glancer").await;
    let (h, _) = human(&pool, "Hana Superseded").await;
    let c = fixture::seed_public_claim(&pool, h, "a public claim later superseded").await;
    sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(c)
        .execute(&pool)
        .await
        .expect("retire the claim");
    assert!(
        named_to(&pool, &scoped, outsider, h).await,
        "a superseded public claim still names its human"
    );
}

// ─── the readable-claim arm ──────────────────────────────────────────────

/// A group claim of B(H) names H to a member of that group and to no one
/// else.
#[sqlx::test(migrations = "../../migrations")]
async fn a_readable_group_claim_names_the_human_to_its_readers_only(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (h, _) = human(&pool, "Ivo Grouped").await;
    let (bot, _) = named(&pool, "ivo-bot").await;
    link(&pool, bot, h).await;
    let (reader, _) = named(&pool, "Jana Reader").await;
    let (outsider, _) = named(&pool, "Kai Outside").await;
    // A team the reader and the bot are in, but H is not.
    let g = keyed_team(&pool, &[reader, bot]).await;
    fixture::seed_group_claim(&pool, bot, g, "a group claim the reader reads").await;
    assert!(
        named_to(&pool, &scoped, reader, h).await,
        "whoever can read a claim can trace it to its human"
    );
    assert!(
        !named_to(&pool, &scoped, outsider, h).await,
        "a group claim names H to no one outside the group"
    );
}

// ─── T8: a stranger cannot unhide H ──────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn a_strangers_own_writes_cannot_unhide_a_human(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (h, _) = human(&pool, "Lena Hidden").await;
    let (stranger, _) = named(&pool, "Milo Stranger").await;
    let (outsider, _) = named(&pool, "Nora Onlooker").await;
    // A public claim that mentions H's id.
    fixture::seed_public_claim(&pool, stranger, &format!("agent {h} wrote something")).await;
    // An OPERATED_BY edge from the stranger to H: not a binding.
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'agent', $2, 'agent', 'OPERATED_BY')",
    )
    .bind(stranger)
    .bind(h)
    .execute(&pool)
    .await
    .expect("stranger's OPERATED_BY edge");
    assert!(
        !named_to(&pool, &scoped, outsider, h).await,
        "a stranger's claim or edge must not name H"
    );
    assert!(
        named_to(&pool, &scoped, outsider, stranger).await,
        "CALIBRATION: the stranger (not human) is named"
    );
}

// ─── T9: privileged ──────────────────────────────────────────────────────

/// A maintenance session (`epigraph_bypass()`) and the core's privileged flag
/// (an elevated viewer) name every human.
#[sqlx::test(migrations = "../../migrations")]
async fn privileged_sessions_name_every_human(pool: PgPool) {
    let (h, _) = human(&pool, "Olaf Private").await;
    let via_maint: (bool, bool) =
        fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
            let r: (bool, bool) =
                sqlx::query_as("SELECT named, details FROM public.epigraph_agent_disclosure($1)")
                    .bind(h)
                    .fetch_one(&mut *conn)
                    .await
                    .expect("maintenance read");
            (conn, r)
        })
        .await;
    assert_eq!(via_maint, (true, true), "a maintenance session names H");
    let elevated: (bool, bool) = sqlx::query_as(
        "SELECT named, details FROM public.epigraph_agent_disclosure_for($1, NULL, '{}', true)",
    )
    .bind(h)
    .fetch_one(&pool)
    .await
    .expect("core, privileged");
    assert_eq!(elevated, (true, true), "the privileged arm names H");
    let anon: (bool, bool) = sqlx::query_as(
        "SELECT named, details FROM public.epigraph_agent_disclosure_for($1, NULL, '{}', false)",
    )
    .bind(h)
    .fetch_one(&pool)
    .await
    .expect("core, anonymous");
    assert_eq!(
        anon,
        (false, false),
        "CALIBRATION: the anonymous audience does not"
    );
}

// ─── catalog pins ────────────────────────────────────────────────────────

/// Owners, paths, costs and ACLs of 272's functions: the core and the
/// evidence helper are maintenance-only; the two wrappers are app-callable;
/// PUBLIC executes none; every one is SECURITY DEFINER on
/// `pg_catalog, pg_temp`, and the core and both wrappers cost 1000.
#[sqlx::test(migrations = "../../migrations")]
async fn migration_272_definers_are_pinned_owned_and_granted(pool: PgPool) {
    for (sig, app_exec, cost) in [
        ("public.epigraph_is_human_principal(uuid)", false, None),
        (
            "public.epigraph_agent_disclosure_for(uuid, uuid, uuid[], boolean)",
            false,
            Some(1000.0_f32),
        ),
        ("public.epigraph_agent_disclosure(uuid)", true, Some(1000.0)),
        (
            "public.epigraph_human_named_to_viewer(uuid)",
            true,
            Some(1000.0),
        ),
    ] {
        let (secdef, owner, config, procost): (bool, String, Vec<String>, f32) = sqlx::query_as(
            "SELECT p.prosecdef, pg_get_userbyid(p.proowner)::text, \
                    COALESCE(p.proconfig, '{}'::text[]), p.procost \
               FROM pg_proc p WHERE p.oid = $1::text::regprocedure",
        )
        .bind(sig)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("{sig}: {e}"));
        assert!(secdef, "{sig} must be SECURITY DEFINER");
        assert_eq!(owner, "epigraph_maintenance", "{sig} owner");
        assert_eq!(
            config,
            vec!["search_path=pg_catalog, pg_temp".to_string()],
            "{sig} path"
        );
        if let Some(c) = cost {
            assert!(
                (procost - c).abs() < 0.5,
                "{sig} COST must be {c}, is {procost}"
            );
        }
        let (app, public): (bool, bool) = sqlx::query_as(
            "SELECT has_function_privilege('epigraph_app', $1::text::regprocedure, 'EXECUTE'), \
                    EXISTS (SELECT 1 FROM pg_proc p, aclexplode(p.proacl) a \
                             WHERE p.oid = $1::text::regprocedure AND a.grantee = 0 \
                               AND a.privilege_type = 'EXECUTE') \
                    OR (SELECT proacl IS NULL FROM pg_proc WHERE oid = $1::text::regprocedure)",
        )
        .bind(sig)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("{sig} acl: {e}"));
        assert_eq!(app, app_exec, "{sig}: epigraph_app EXECUTE");
        assert!(!public, "{sig}: PUBLIC must not EXECUTE");
    }
}

// ─── T10: the fail-closed owner ──────────────────────────────────────────

/// Finding 10b. Under the sqlx harness every function is effectively run by
/// a superuser, so a no-op owner block is invisible. This test hands the core
/// and the evidence helper to a fresh NOSUPERUSER NOBYPASSRLS role that is
/// not a maintenance member: the FORCEd `operator_links` read then sees no
/// binding, so a bound agent's public claim no longer names H (fail CLOSED,
/// never "H became a non-human"), while H is still named to itself.
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_member_owner_of_the_core_fails_closed(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (outsider, _) = named(&pool, "Pia Peering").await;
    let (h, _) = human(&pool, "Quirin Bound").await;
    let (bot, _) = named(&pool, "quirin-bot").await;
    link(&pool, bot, h).await;
    fixture::seed_public_claim(&pool, bot, "a public claim by a linked bot").await;
    assert!(
        named_to(&pool, &scoped, outsider, h).await,
        "CALIBRATION: under the maintenance owner the bot's claim names H"
    );

    // Roles are cluster-wide: a fixed name collides between parallel tests.
    let role = format!("hiv_owner_{}", Uuid::new_v4().simple());
    for stmt in [
        format!("CREATE ROLE {role} NOLOGIN NOSUPERUSER NOBYPASSRLS"),
        // The application role's privileges (the policy helpers, table
        // SELECT), which is what a non-member runner would hold at best.
        format!("GRANT epigraph_app TO {role}"),
        format!(
            "GRANT SELECT ON public.agents, public.oauth_clients, public.human_operators, \
             public.group_memberships, public.groups, public.operator_links, \
             public.author_binding_clients, public.claims TO {role}"
        ),
        format!(
            "GRANT EXECUTE ON FUNCTION public.epigraph_live_memberships_unbound(uuid) TO {role}"
        ),
        format!("ALTER FUNCTION public.epigraph_is_human_principal(uuid) OWNER TO {role}"),
        format!(
            "ALTER FUNCTION public.epigraph_agent_disclosure_for(uuid, uuid, uuid[], boolean) \
             OWNER TO {role}"
        ),
        // The wrapper (maintenance-owned) must still be able to call the core.
        "GRANT EXECUTE ON FUNCTION \
         public.epigraph_agent_disclosure_for(uuid, uuid, uuid[], boolean) \
         TO epigraph_maintenance"
            .to_string(),
    ] {
        sqlx::query(&stmt)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("{stmt}: {e}"));
    }
    let scoped2 = app_pool(&pool).await;
    assert!(
        !named_to(&pool, &scoped2, outsider, h).await,
        "a non-member owner reads no binding: H must be UNNAMED, not treated as non-human"
    );
    assert!(
        named_to(&pool, &scoped2, h, h).await,
        "H is still named to itself (the self arm reads no table)"
    );
}

// ─── HEV01: the evidence row is pinned ───────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn the_human_evidence_row_cannot_be_deleted_or_retyped(pool: PgPool) {
    let (h, _) = client_only_human(&pool, "Rosa Evidence").await;
    let client: Uuid = sqlx::query_scalar("SELECT id FROM oauth_clients WHERE agent_id = $1")
        .bind(h)
        .fetch_one(&pool)
        .await
        .expect("client");
    let del = sqlx::query("DELETE FROM oauth_clients WHERE id = $1")
        .bind(client)
        .execute(&pool)
        .await;
    let msg = del
        .expect_err("a linked human client must not be deletable")
        .to_string();
    assert!(msg.contains("HEV01"), "refusal names HEV01: {msg}");
    let retype = sqlx::query("UPDATE oauth_clients SET client_type = 'service' WHERE id = $1")
        .bind(client)
        .execute(&pool)
        .await;
    let msg = retype
        .expect_err("a linked human client must not change type")
        .to_string();
    assert!(msg.contains("HEV01"), "refusal names HEV01: {msg}");

    // An unlinked human client, and a linked service client, are unaffected.
    let unlinked: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, status) \
         VALUES ($1, 'unlinked', 'human', ARRAY['claims:read'], 'active') RETURNING id",
    )
    .bind(format!("unlinked-{}", Uuid::new_v4()))
    .fetch_one(&pool)
    .await
    .expect("unlinked human client");
    sqlx::query(
        "UPDATE oauth_clients SET client_type = 'service', legal_entity_name = 'Fixture Org', \
                legal_contact_email = 'fixture@example.invalid' WHERE id = $1",
    )
    .bind(unlinked)
    .execute(&pool)
    .await
    .expect("an unlinked client may be retyped");
    let n = sqlx::query("DELETE FROM oauth_clients WHERE id = $1")
        .bind(unlinked)
        .execute(&pool)
        .await
        .expect("an unlinked client may be deleted")
        .rows_affected();
    assert_eq!(n, 1);
    // CALIBRATION: the refused statements changed nothing.
    let still: (String,) = sqlx::query_as("SELECT client_type FROM oauth_clients WHERE id = $1")
        .bind(client)
        .fetch_one(&pool)
        .await
        .expect("still there");
    assert_eq!(still.0, "human");
}

// ─── T13: the accountability property, and B(H)'s stickiness ─────────────

/// For every viewer of a small matrix and every claim that viewer can read
/// (as the claims read policy decides on the viewer's own stamped
/// `epigraph_app` session), the claim's filer and the filer's human at filing
/// time (`epigraph_operator_bound_at`) are NAMED to that viewer. Covers
/// public / group-in-V / group-not-in-V claims, current and superseded, filed
/// through a live link, a retired link, a live and a revoked allowance, and
/// by the human directly.
#[sqlx::test(migrations = "../../migrations")]
async fn whoever_can_read_a_claim_sees_its_filer_and_human_named(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (h, _) = human(&pool, "Sana Accountable").await;
    let (live_bot, _) = named(&pool, "sana-live-bot").await;
    link(&pool, live_bot, h).await;
    let (old_bot, _) = named(&pool, "sana-old-bot").await;
    link(&pool, old_bot, h).await;
    let (svc, svc_client) = allowance_bound(&pool, h, "sana-svc").await;
    let (gone_svc, gone_client) = allowance_bound(&pool, h, "sana-gone-svc").await;

    let (mate, _) = named(&pool, "Tito Groupmate").await;
    let (outsider, _) = named(&pool, "Uma Uninvolved").await;
    // A team of the mate and the bots, NOT of H.
    let g = keyed_team(&pool, &[mate, live_bot, old_bot, svc, gone_svc]).await;
    let other = keyed_team(&pool, &[outsider]).await;

    let mut seeded = 0;
    for (filer, tag) in [
        (live_bot, "live link"),
        (old_bot, "retired link"),
        (svc, "live allowance"),
        (gone_svc, "revoked allowance"),
    ] {
        fixture::seed_group_claim(&pool, filer, g, &format!("group claim via {tag}")).await;
        seeded += 1;
    }
    let sup = fixture::seed_group_claim(&pool, h, g, "a superseded group claim by H").await;
    sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(sup)
        .execute(&pool)
        .await
        .expect("supersede");
    fixture::seed_group_claim(&pool, outsider, other, "a claim H's readers cannot see").await;
    retire_link(&pool, old_bot).await;
    revoke_allowance(&pool, gone_client).await;
    let _ = svc_client;

    let mut readable_total = 0;
    for who in [mate, outsider, h, live_bot] {
        let v = viewer(&pool, who).await;
        let rows: Vec<(Uuid, Uuid, Option<Uuid>)> = {
            let mut read = scoped.read_as(&v).await.expect("read_as");
            sqlx::query_as(
                "SELECT c.id, c.agent_id, \
                        public.epigraph_operator_bound_at(c.agent_id, c.created_at) \
                   FROM claims c",
            )
            .fetch_all(&mut *read)
            .await
            .expect("claims this viewer reads")
        };
        for (claim, filer, human_at) in &rows {
            assert!(
                disclosure(&scoped, &v, *filer).await.0,
                "viewer {who} reads claim {claim} but its filer {filer} is unnamed"
            );
            if let Some(hu) = human_at {
                assert!(
                    disclosure(&scoped, &v, *hu).await.0,
                    "viewer {who} reads claim {claim} but its human {hu} is unnamed"
                );
            }
        }
        readable_total += rows.len();
    }
    assert!(
        seeded == 4 && readable_total > 0,
        "CALIBRATION: claims were read"
    );
    // CALIBRATION: the property is not vacuous: the mate reads H's bound
    // agents' claims, and the outsider does not see H named.
    assert!(named_to(&pool, &scoped, mate, h).await);
    assert!(!named_to(&pool, &scoped, outsider, h).await);
}

/// Spec §3: B(H) is sticky because a retired link cannot be re-pointed at
/// another operator. After a retire, an `operator_id` change is refused and H
/// stays named by the retired bot's public claim.
#[sqlx::test(migrations = "../../migrations")]
async fn a_retired_link_cannot_be_repointed_and_keeps_naming_its_human(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (outsider, _) = named(&pool, "Vera Watching").await;
    let (h, _) = human(&pool, "Wim Sticky").await;
    let (other_h, _) = human(&pool, "Xena Other").await;
    let (bot, _) = named(&pool, "wim-bot").await;
    link(&pool, bot, h).await;
    fixture::seed_public_claim(&pool, bot, "the bot's public claim").await;
    retire_link(&pool, bot).await;
    // On a maintenance session (the harness superuser is exempt from 257's
    // guard by design, so it would prove nothing).
    let moved: Option<String> =
        fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
            let r = sqlx::query("UPDATE operator_links SET operator_id = $2 WHERE agent_id = $1")
                .bind(bot)
                .bind(other_h)
                .execute(&mut *conn)
                .await;
            let code = match r {
                Ok(_) => None,
                Err(sqlx::Error::Database(db)) => db.code().map(|c| c.to_string()),
                Err(e) => Some(format!("other: {e}")),
            };
            (conn, code)
        })
        .await;
    assert_eq!(
        moved.as_deref(),
        Some("42501"),
        "an operator link's operator_id must never change (191/257's guard)"
    );
    assert!(
        named_to(&pool, &scoped, outsider, h).await,
        "the retired bot's public claim still names H"
    );
    assert!(
        !named_to(&pool, &scoped, outsider, other_h).await,
        "and never the human it was not bound to"
    );
}
