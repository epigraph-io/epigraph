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
//! * Non-human targets decide `details` exactly as the profile rule every
//!   surface applied before migration 272 did (T11).
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

/// Set `agent`'s profile as the self-service setter would leave it: `'public'`
/// WITH a consent stamp (283's `profile_public_consented_at`, which the
/// opt-in arm requires), `'group'` with none. A test that needs a `'public'`
/// value nobody consented to (062's column default, a direct write) uses
/// [`set_profile_unconsented`].
async fn set_profile(pool: &PgPool, agent: Uuid, profile: &str) {
    sqlx::query(
        "UPDATE agents SET profile_visibility = $2, \
                profile_public_consented_at = CASE WHEN $2 = 'public' THEN now() END \
          WHERE id = $1",
    )
    .bind(agent)
    .bind(profile)
    .execute(pool)
    .await
    .expect("profile");
}

/// `'public'` written directly, with no consent stamp: what 062's column
/// default left on every row, and what any writer other than the setter
/// produces.
async fn set_profile_unconsented(pool: &PgPool, agent: Uuid) {
    sqlx::query(
        "UPDATE agents SET profile_visibility = 'public', profile_public_consented_at = NULL \
          WHERE id = $1",
    )
    .bind(agent)
    .execute(pool)
    .await
    .expect("unconsented profile");
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
/// the profile rule every surface applied before migration 272 (a public
/// profile, or a live group shared with the reader; spelled out here as the
/// expected truth table, since `AgentRepository::profile_details_visible`,
/// the old copy, was folded into the predicate) over the profile x
/// shared-group matrix. A `'group'`-profile service is still NAMED to an
/// outsider: the new rule redacts humans only.
#[sqlx::test(migrations = "../../migrations")]
async fn non_human_targets_are_named_and_details_follow_todays_rule(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (outsider, _) = named(&pool, "Rhea Reader").await;
    let (peer, _) = named(&pool, "Saul Peer").await;
    let mut targets: Vec<(Uuid, bool, bool)> = Vec::new();
    for profile in ["public", "group"] {
        for shares in [false, true] {
            let (t, _) = named(&pool, &format!("svc {profile} {shares}")).await;
            set_profile(&pool, t, profile).await;
            if shares {
                keyed_team(&pool, &[t, peer]).await;
            }
            targets.push((t, profile == "public", shares));
        }
    }
    let mut checked = 0;
    for who in [outsider, peer] {
        let v = viewer(&pool, who).await;
        for (t, public, shares) in &targets {
            let expected = *public || (who == peer && *shares);
            let (n, d) = disclosure(&scoped, &v, *t).await;
            assert!(n, "a non-human agent must be named to every reader");
            assert_eq!(
                d, expected,
                "details for non-human {t} as {who} must equal the profile rule"
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
        for (t, _, _) in &targets {
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

/// Operator ruling C11 (migration 283): the opt-in arm requires
/// `profile_visibility = 'public'` AND a consent stamp only the self-service
/// setter writes. A `'public'` nobody consented to (062's default, a direct
/// write) names the human to no one, and does not widen the `details` of a
/// human some other arm names. CALIBRATION: the same human, opted in through
/// the setter, is named with details to an outsider.
#[sqlx::test(migrations = "../../migrations")]
async fn a_public_profile_without_recorded_consent_names_no_one(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (outsider, _) = named(&pool, "Ines Elsewhere").await;
    let (h, _) = human(&pool, "Jules Unconsenting").await;
    set_profile_unconsented(&pool, h).await;
    assert_eq!(
        disclosure(&scoped, &viewer(&pool, outsider).await, h).await,
        (false, false),
        "an unconsented 'public' is not an opt-in"
    );
    assert!(!named_to_guest(&pool, &scoped, h).await, "nor to the guest");

    // A human named by a public claim keeps its details hidden when its
    // 'public' carries no consent (the details rule's profile term reads
    // consent for a human too).
    let (k, _) = human(&pool, "Kaspar Accountable").await;
    let (bot, _) = named(&pool, "kaspar-bot").await;
    link(&pool, bot, k).await;
    fixture::seed_public_claim(&pool, bot, "kaspar's bot said this publicly").await;
    set_profile_unconsented(&pool, k).await;
    assert_eq!(
        disclosure(&scoped, &viewer(&pool, outsider).await, k).await,
        (true, false),
        "named by the public claim, no details without consent"
    );

    // CALIBRATION: the setter records consent, and then the arm holds.
    let set = set_as(&pool, &scoped, h, epigraph_db::ProfileVisibility::Public)
        .await
        .expect("opt in");
    assert!(set.named_to_everyone);
    assert_eq!(
        disclosure(&scoped, &viewer(&pool, outsider).await, h).await,
        (true, true),
        "CALIBRATION: an opt-in through the setter names H with details"
    );
}

/// C11: the consent stamp is written by the setter alone. The application
/// role holds no UPDATE on the column (not even on its own row), and a stamp
/// on a profile that is not `'public'` violates the table's CHECK, so an
/// opt-out can never leave a stale consent behind for a later `'public'`.
#[sqlx::test(migrations = "../../migrations")]
async fn the_consent_stamp_is_the_setters_alone(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (h, _) = human(&pool, "Lorna Stamped").await;
    let v = viewer(&pool, h).await;
    let mut tx = scoped.begin_as(&v).await.expect("begin_as");
    let r = sqlx::query("UPDATE agents SET profile_public_consented_at = now() WHERE id = $1")
        .bind(h)
        .execute(&mut *tx)
        .await;
    drop(tx);
    let code = match r {
        Err(sqlx::Error::Database(e)) => e.code().map(|c| c.into_owned()),
        other => panic!("expected a refusal, got {other:?}"),
    };
    assert_eq!(code.as_deref(), Some("42501"), "no column grant to the app");

    let r = sqlx::query(
        "UPDATE agents SET profile_visibility = 'group', \
                profile_public_consented_at = now() WHERE id = $1",
    )
    .bind(h)
    .execute(&pool)
    .await;
    let code = match r {
        Err(sqlx::Error::Database(e)) => e.code().map(|c| c.into_owned()),
        other => panic!("expected the CHECK, got {other:?}"),
    };
    assert_eq!(
        code.as_deref(),
        Some("23514"),
        "a consent stamp on a 'group' profile"
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

// ─── C5: the binding window's START (operator ruling) ───────────────────

/// Move a seeded row's `created_at` a day into the past, so it is unmistakably
/// older than any binding the test then writes (`now()` of a later statement).
async fn backdate(pool: &PgPool, table: &str, id: Uuid) {
    let moved = sqlx::query(&format!(
        "UPDATE public.{table} SET created_at = now() - interval '1 day' WHERE id = $1"
    ))
    .bind(id)
    .execute(pool)
    .await
    .expect("backdate");
    assert_eq!(
        moved.rows_affected(),
        1,
        "CALIBRATION: backdated one {table} row"
    );
}

/// Operator ruling C5: an assertion counts for H only if it was created at or
/// after its agent's binding to H began. An agent's public claim, and its
/// readable group claim, filed BEFORE the agent was linked (107) or allowed
/// (149) for H never name H, before or after the binding is retired. H's own
/// claims have no binding to start, so a backdated one still names H
/// (CALIBRATION, with an after-binding claim by the same agents in
/// `an_assertion_after_the_binding_names_the_human_after_the_binding_ends`).
#[sqlx::test(migrations = "../../migrations")]
async fn an_assertion_from_before_the_binding_never_names_the_human(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (outsider, _) = named(&pool, "Pia Passerby").await;

    // A link: the bot's public claim predates the link.
    let (h1, _) = human(&pool, "Rolf Relinked").await;
    let (bot, _) = named(&pool, "rolf-bot").await;
    let early = fixture::seed_public_claim(&pool, bot, "a public claim before the link").await;
    backdate(&pool, "claims", early).await;
    link(&pool, bot, h1).await;
    assert!(
        !named_to(&pool, &scoped, outsider, h1).await,
        "a public claim filed before the link must not name the human"
    );
    assert!(
        !named_to_guest(&pool, &scoped, h1).await,
        "nor to the guest viewer"
    );
    retire_link(&pool, bot).await;
    assert!(
        !named_to(&pool, &scoped, outsider, h1).await,
        "retiring the link does not make a pre-link claim count"
    );

    // An allowance: the service's public claim predates its allowance.
    let (h2, _) = human(&pool, "Sara Sanctioned").await;
    let (svc, _client) = allowance_bound(&pool, h2, "sara-service").await;
    let early = fixture::seed_public_claim(&pool, svc, "a public claim before the allowance").await;
    backdate(&pool, "claims", early).await;
    assert!(
        !named_to(&pool, &scoped, outsider, h2).await,
        "a public claim filed before the allowance must not name the human"
    );

    // The readable-claim arm is windowed too: a group claim the reader reads,
    // filed before the bot's link, does not name H to the reader.
    let (h3, _) = human(&pool, "Tove Teamless").await;
    let (bot3, _) = named(&pool, "tove-bot").await;
    let (reader, _) = named(&pool, "Ugo Reader").await;
    let g = keyed_team(&pool, &[reader, bot3]).await;
    let early = fixture::seed_group_claim(&pool, bot3, g, "a group claim before the link").await;
    backdate(&pool, "claims", early).await;
    link(&pool, bot3, h3).await;
    assert!(
        !named_to(&pool, &scoped, reader, h3).await,
        "a readable group claim filed before the link must not name the human"
    );

    // CALIBRATION: H's own claim needs no binding; backdated, it still names H.
    let (h4, _) = human(&pool, "Vera Veteran").await;
    let own = fixture::seed_public_claim(&pool, h4, "a public claim by the person").await;
    backdate(&pool, "claims", own).await;
    assert!(
        named_to(&pool, &scoped, outsider, h4).await,
        "a human's own public claim names it whenever it was filed"
    );
}

/// C5's other half: an assertion made at or after the binding began keeps
/// naming H after the link is retired or the allowance revoked (sticky), and
/// an earlier claim of the same agent does not stop it. Calibrates
/// `an_assertion_from_before_the_binding_never_names_the_human`.
#[sqlx::test(migrations = "../../migrations")]
async fn an_assertion_after_the_binding_names_the_human_after_the_binding_ends(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (outsider, _) = named(&pool, "Wim Watcher").await;

    let (h1, _) = human(&pool, "Xena Linked").await;
    let (bot, _) = named(&pool, "xena-bot").await;
    let early = fixture::seed_public_claim(&pool, bot, "xena-bot before the link").await;
    backdate(&pool, "claims", early).await;
    link(&pool, bot, h1).await;
    fixture::seed_public_claim(&pool, bot, "xena-bot after the link").await;
    retire_link(&pool, bot).await;
    assert!(
        named_to(&pool, &scoped, outsider, h1).await,
        "a public claim filed while linked names the human after the link is retired"
    );

    let (h2, _) = human(&pool, "Yusuf Allowed").await;
    let (svc, client) = allowance_bound(&pool, h2, "yusuf-service").await;
    fixture::seed_public_claim(&pool, svc, "yusuf-service while allowed").await;
    revoke_allowance(&pool, client).await;
    assert!(
        named_to(&pool, &scoped, outsider, h2).await,
        "a public claim filed while allowed names the human after the revocation"
    );

    let (h3, _) = human(&pool, "Zora Grouped").await;
    let (bot3, _) = named(&pool, "zora-bot").await;
    let (reader, _) = named(&pool, "Abel Reader").await;
    let g = keyed_team(&pool, &[reader, bot3]).await;
    link(&pool, bot3, h3).await;
    fixture::seed_group_claim(&pool, bot3, g, "zora-bot group claim after the link").await;
    retire_link(&pool, bot3).await;
    assert!(
        named_to(&pool, &scoped, reader, h3).await,
        "a readable group claim filed while linked names the human to its reader"
    );
    assert!(
        !named_to(&pool, &scoped, outsider, h3).await,
        "CALIBRATION: and to no one outside the group"
    );
}

/// C5 is sticky across a SECOND binding of the same agent (review2
/// correctness#4). An agent's public claim made while allowed (149) for H
/// names H after the allowance is revoked; the documented next step (149's
/// HINT "Revoke the allowance first") is to link the same agent to H, which
/// writes a later binding start. The window is the EARLIEST start of the
/// agent's bindings to H (`pg_catalog.min(b.since)` in the core), so the
/// later link never un-names H. With `max` this test fails at the last
/// assertion (mutation probe P1, which survived the suite before it).
#[sqlx::test(migrations = "../../migrations")]
async fn a_later_binding_of_the_same_agent_never_un_names_the_human(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (outsider, _) = named(&pool, "Gil Gazer").await;
    let (h, _) = human(&pool, "Hana Twice-Bound").await;
    let (svc, client) = allowance_bound(&pool, h, "hana-service").await;
    fixture::seed_public_claim(&pool, svc, "hana-service while allowed").await;
    revoke_allowance(&pool, client).await;
    assert!(
        named_to(&pool, &scoped, outsider, h).await,
        "CALIBRATION: sticky after the revoke"
    );
    link(&pool, svc, h).await;
    assert!(
        named_to(&pool, &scoped, outsider, h).await,
        "a later link of the same agent must not un-name H (C5 sticky)"
    );
}

// ─── C6: public assertions of every kind (operator ruling) ──────────────

/// The kinds of public row besides a claim that operator ruling C6 considers,
/// each keyed on the column HEAD records its agent in.
#[derive(Debug, Clone, Copy)]
enum Assertion {
    /// `evidence.signer_id`. NOT counted since 302 (Addendum 5): the table has
    /// no column recording the asserting agent, and over MCP the signer is the
    /// server's own agent, so the signer is not the author.
    Evidence,
    /// `challenges.challenger_id`, which 170's CR08 pins to the filing
    /// session's principal.
    Challenge,
    /// `mass_functions.source_agent_id` on an ASSESSMENT slot
    /// (`/claims/:id/assess`, which keys the row to the caller or the caller's
    /// live human): the only BBA shape whose writer is always the attributed
    /// identity's (302).
    MassFunction,
    /// `edges` `paper -ingested_claim-> claim`, `properties.ingested_by`, marked
    /// by the same ingest (`properties.ingest_written.by`).
    IngestRecord,
}

/// The kinds C6 counts (302: evidence is dropped, Addendum 5).
const ASSERTIONS: [Assertion; 3] = [
    Assertion::Challenge,
    Assertion::MassFunction,
    Assertion::IngestRecord,
];

/// A fresh two-hypothesis frame.
async fn fixture_frame(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['h0','h1']::text[]) \
         RETURNING id",
    )
    .bind(format!("visibility-frame-{}", Uuid::new_v4()))
    .fetch_one(pool)
    .await
    .expect("frame")
}

/// A BBA on `claim` attributed to `agent`, keyed on `slot` (267's
/// `slot_kind` / `slot_id`; `None` is an unscoped row), seeded on the
/// superuser pool: the tenancy triggers give it the claim's visibility.
async fn bba_row(pool: &PgPool, claim: Uuid, agent: Uuid, slot: Option<(&str, Uuid)>) -> Uuid {
    let frame = fixture_frame(pool).await;
    sqlx::query_scalar(
        "INSERT INTO mass_functions (claim_id, frame_id, source_agent_id, masses, slot_kind, \
                                     slot_id) \
         VALUES ($1, $2, $3, '{\"0\": 0.5, \"0,1\": 0.5}'::jsonb, $4, $5) RETURNING id",
    )
    .bind(claim)
    .bind(frame)
    .bind(agent)
    .bind(slot.map(|s| s.0))
    .bind(slot.map(|s| s.1))
    .fetch_one(pool)
    .await
    .expect("mass function")
}

/// A public paper (explicit tenancy: `papers` refuses an undeclared insert).
async fn public_paper(pool: &PgPool, doi: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO papers (doi, title, visibility, owner_group_id) \
         VALUES ($1, 'A Fixture Paper', 'public', $2) RETURNING id",
    )
    .bind(doi)
    .bind(fixture::world_group(pool).await)
    .fetch_one(pool)
    .await
    .expect("public paper")
}

/// One PUBLIC assertion of `kind` by `agent`, on a public claim an unbound
/// stranger filed (so no claim arm can name H). Returns `(table, row id)`.
/// CALIBRATION: the stored row is `'public'` (the tenancy triggers decide it).
async fn assert_publicly(pool: &PgPool, kind: Assertion, agent: Uuid) -> (&'static str, Uuid) {
    let (stranger, _) = named(pool, &format!("stranger {}", Uuid::new_v4())).await;
    let claim = fixture::seed_public_claim(
        pool,
        stranger,
        &format!("a stranger's public claim {}", Uuid::new_v4()),
    )
    .await;
    let (table, id): (&'static str, Uuid) = match kind {
        Assertion::Evidence => {
            let hash: Vec<u8> = Uuid::new_v4().as_bytes().repeat(2);
            let sig: Vec<u8> = Uuid::new_v4().as_bytes().repeat(4);
            let id = sqlx::query_scalar(
                "INSERT INTO evidence (claim_id, evidence_type, content_hash, signature, \
                                       signer_id) \
                 VALUES ($1, 'testimony', $2, $3, $4) RETURNING id",
            )
            .bind(claim)
            .bind(&hash)
            .bind(&sig)
            .bind(agent)
            .fetch_one(pool)
            .await
            .expect("signed evidence");
            ("evidence", id)
        }
        Assertion::Challenge => {
            let id = sqlx::query_scalar(
                "INSERT INTO challenges (claim_id, challenger_id, challenge_type, explanation, \
                                         state) \
                 VALUES ($1, $2, 'factual', 'a challenge', 'pending') RETURNING id",
            )
            .bind(claim)
            .bind(agent)
            .fetch_one(pool)
            .await
            .expect("challenge");
            ("challenges", id)
        }
        Assertion::MassFunction => {
            // The assess route's shape: the agent's own assessment slot.
            let id = bba_row(pool, claim, agent, Some(("assessment", Uuid::new_v4()))).await;
            ("mass_functions", id)
        }
        Assertion::IngestRecord => {
            let paper = public_paper(pool, &format!("10.9999/visibility.{}", Uuid::new_v4())).await;
            let mut tx = pool.begin().await.expect("begin");
            sqlx::query("SELECT pg_catalog.set_config('epigraph.ingest_written_edge', 'on', true)")
                .execute(&mut *tx)
                .await
                .expect("declare the ingest's write");
            let id = sqlx::query_scalar(
                "INSERT INTO edges (source_id, source_type, target_id, target_type, \
                                    relationship, properties) \
                 VALUES ($1, 'paper', $2, 'claim', 'ingested_claim', \
                         jsonb_build_object('ingested_by', $3::text, 'created_claim', false, \
                                            'tool', 'ingest_document', \
                                            'ingest_written', jsonb_build_object( \
                                                'tool', 'ingest_document', 'by', $3::text))) \
                 RETURNING id",
            )
            .bind(paper)
            .bind(claim)
            .bind(agent)
            .fetch_one(&mut *tx)
            .await
            .expect("ingest record");
            tx.commit().await.expect("commit");
            ("edges", id)
        }
    };
    let visibility: String = sqlx::query_scalar(&format!(
        "SELECT visibility::text FROM public.{table} WHERE id = $1"
    ))
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("visibility");
    assert_eq!(
        visibility, "public",
        "CALIBRATION: the {kind:?} row is stored public"
    );
    (table, id)
}

/// Operator ruling C6: a public assertion of ANY kind by H or by an agent bound
/// to H names H, as a public claim does: a challenge it raised, an assessment
/// it stated, an ingest record of its document ingest (evidence is not
/// counted since 302: `only_an_agents_own_assertion_names_its_human`). Each is
/// checked alone (on a stranger's claim, so no claim arm holds), by H itself
/// and by a linked agent after its link began, then after the link is retired.
#[sqlx::test(migrations = "../../migrations")]
async fn a_public_assertion_of_every_kind_names_the_human(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (outsider, _) = named(&pool, "Bruno Bystander").await;
    for kind in ASSERTIONS {
        // By H itself.
        let (h, _) = human(&pool, &format!("Person {kind:?} Self")).await;
        assert!(
            !named_to(&pool, &scoped, outsider, h).await,
            "CALIBRATION: {kind:?}: unnamed before"
        );
        assert_publicly(&pool, kind, h).await;
        assert!(
            named_to(&pool, &scoped, outsider, h).await,
            "{kind:?}: a public assertion by the person names it"
        );
        assert!(
            named_to_guest(&pool, &scoped, h).await,
            "{kind:?}: and to the guest viewer"
        );

        // By a linked agent, after the link began; sticky after retirement.
        let (h2, _) = human(&pool, &format!("Person {kind:?} Linked")).await;
        let (bot, _) = named(&pool, &format!("bot {kind:?}")).await;
        link(&pool, bot, h2).await;
        assert_publicly(&pool, kind, bot).await;
        retire_link(&pool, bot).await;
        assert!(
            named_to(&pool, &scoped, outsider, h2).await,
            "{kind:?}: a linked agent's public assertion names its human after the retire"
        );
    }
}

/// C6 is windowed as C5 is: an assertion of any kind that a bound agent made
/// BEFORE its binding to H began never names H. The same agent's assertion
/// after the binding does (CALIBRATION).
#[sqlx::test(migrations = "../../migrations")]
async fn an_assertion_of_any_kind_from_before_the_binding_never_names_the_human(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (outsider, _) = named(&pool, "Carla Curious").await;
    for kind in ASSERTIONS {
        let (h, _) = human(&pool, &format!("Person {kind:?} Late")).await;
        let (bot, _) = named(&pool, &format!("early bot {kind:?}")).await;
        let (table, row) = assert_publicly(&pool, kind, bot).await;
        backdate(&pool, table, row).await;
        link(&pool, bot, h).await;
        assert!(
            !named_to(&pool, &scoped, outsider, h).await,
            "{kind:?}: an assertion from before the link must not name the human"
        );
        assert_publicly(&pool, kind, bot).await;
        assert!(
            named_to(&pool, &scoped, outsider, h).await,
            "CALIBRATION: {kind:?}: the same agent's assertion after the link names it"
        );
    }
}

/// Addendum 5 (security review of 295; review2 leaks#1, correctness#2): the
/// C6 arms count only an assertion the agent ITSELF made, never a row another
/// writer created that names the agent. Each row below is public and names
/// H's bound agent, and each was written by someone else (or, for evidence,
/// records no asserting agent at all), so none names H. CALIBRATION at the
/// end: the agent's own assessment does.
#[sqlx::test(migrations = "../../migrations")]
async fn only_an_agents_own_assertion_names_its_human(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (outsider, _) = named(&pool, "Dora Distant").await;
    let (stranger, _) = named(&pool, "Egon Elsewhere").await;
    let (h, _) = human(&pool, "Fritz Factor").await;
    let (bot, _) = named(&pool, "fritz-bot").await;

    // The bot's public claim P predates its link: by C5 it never names H.
    let p = fixture::seed_public_claim(&pool, bot, "fritz-bot before the link").await;
    backdate(&pool, "claims", p).await;
    link(&pool, bot, h).await;
    let t = fixture::seed_public_claim(&pool, stranger, "the stranger's own public claim").await;
    assert!(
        !named_to(&pool, &scoped, outsider, h).await,
        "CALIBRATION: unnamed before any row below"
    );

    // (1) leaks#1 (a): the stranger links P -supports-> T. The edge writers
    // (`edge_factor.rs::auto_wire_ds_for_edge`, REST and MCP) file the edge
    // factor on T, attributed to P's AUTHOR, with T's visibility and a fresh
    // `created_at` (`store_keyed`'s `created_at = NOW()` on every re-wire).
    let edge: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'supports') RETURNING id",
    )
    .bind(p)
    .bind(t)
    .fetch_one(&pool)
    .await
    .expect("the stranger's edge");
    let factor = bba_row(&pool, t, bot, Some(("edge", edge))).await;
    // (2) a BBA filed under the agent's id by another writer with no slot
    // (`MassFunctionRepository::copy_to_frame`, the operator CLIs).
    let copied = bba_row(&pool, t, bot, None).await;
    // (3) an evidence-slot BBA (the DS auto-wire's shape).
    let derived = bba_row(&pool, t, bot, Some(("evidence", Uuid::new_v4()))).await;
    for id in [factor, copied, derived] {
        let v: String =
            sqlx::query_scalar("SELECT visibility::text FROM mass_functions WHERE id = $1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .expect("visibility");
        assert_eq!(v, "public", "CALIBRATION: the BBA inherits T's 'public'");
    }
    assert!(
        !named_to(&pool, &scoped, outsider, h).await,
        "a BBA another writer attributed to H's agent (edge factor, copy, evidence auto-wire) \
         must not name H"
    );

    // (4) evidence signed under the agent's id: `evidence` records the signer,
    // which over MCP is the server's agent, not the author; no column records
    // the asserting agent, so evidence is not counted at all.
    assert_publicly(&pool, Assertion::Evidence, bot).await;
    assert!(
        !named_to(&pool, &scoped, outsider, h).await,
        "evidence names no one: the signer is not the asserting agent"
    );

    // (5) a challenge filed by the stranger's session under the bot's id is
    // refused (170's CR08 pins challenger_id to the session principal).
    let stranger_v = viewer(&pool, stranger).await;
    let mut tx = scoped.begin_as(&stranger_v).await.expect("begin_as");
    let refused = sqlx::query(
        "INSERT INTO challenges (claim_id, challenger_id, challenge_type, explanation, state) \
         VALUES ($1, $2, 'factual', 'a challenge in another agent''s name', 'pending')",
    )
    .bind(t)
    .bind(bot)
    .execute(&mut *tx)
    .await
    .expect_err("a challenge in another agent's name must be refused");
    assert!(
        refused.to_string().contains("CR08"),
        "refused by the challenger pin: {refused}"
    );
    drop(tx);

    // (6) ingest records naming the bot as ingester: one with no marker (any
    // edge writer's), one whose marker names the stranger's ingest. Only the
    // marker ties a record to the ingest that wrote it (correctness#5).
    let paper = public_paper(&pool, &format!("10.9999/visibility.{}", Uuid::new_v4())).await;
    let t2 = fixture::seed_public_claim(&pool, stranger, "a second stranger claim").await;
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            properties) \
         VALUES ($1, 'paper', $2, 'claim', 'ingested_claim', \
                 jsonb_build_object('ingested_by', $3::text, 'created_claim', false, \
                                    'tool', 'ingest_document'))",
    )
    .bind(paper)
    .bind(t)
    .bind(bot)
    .execute(&pool)
    .await
    .expect("an unmarked record");
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SELECT pg_catalog.set_config('epigraph.ingest_written_edge', 'on', true)")
        .execute(&mut *tx)
        .await
        .expect("declare the ingest's write");
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            properties) \
         VALUES ($1, 'paper', $2, 'claim', 'ingested_claim', \
                 jsonb_build_object('ingested_by', $3::text, 'created_claim', false, \
                                    'tool', 'ingest_document', \
                                    'ingest_written', jsonb_build_object( \
                                        'tool', 'ingest_document', 'by', $4::text)))",
    )
    .bind(paper)
    .bind(t2)
    .bind(bot)
    .bind(stranger)
    .execute(&mut *tx)
    .await
    .expect("a record the stranger's ingest marked");
    tx.commit().await.expect("commit");
    let public_records: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE relationship = 'ingested_claim' \
            AND properties ->> 'ingested_by' = $1::text AND visibility = 'public'",
    )
    .bind(bot)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(public_records, 2, "CALIBRATION: both records are public");
    assert!(
        !named_to(&pool, &scoped, outsider, h).await,
        "an ingest record no ingest of the agent marked must not name H"
    );

    // CALIBRATION: the bot's OWN assessment of T, after its link, names H.
    bba_row(&pool, t, bot, Some(("assessment", Uuid::new_v4()))).await;
    assert!(
        named_to(&pool, &scoped, outsider, h).await,
        "CALIBRATION: the agent's own public assessment names its human"
    );
}

// ─── C2: a countersigned authorship (operator ruling) ───────────────────

/// A paper of `visibility` owned by `owner` (explicit tenancy).
async fn paper_owned(pool: &PgPool, visibility: &str, owner: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO papers (doi, title, visibility, owner_group_id) \
         VALUES ($1, 'A Fixture Paper', $2, $3) RETURNING id",
    )
    .bind(format!("10.9999/countersign.{}", Uuid::new_v4()))
    .bind(visibility)
    .bind(owner)
    .fetch_one(pool)
    .await
    .expect("paper")
}

/// `by`'s document ingest names `author` an author of `paper`, PENDING the
/// author's countersign (an ingester naming someone it does not speak for:
/// the ingest-written `authored` row with `pending_countersign`).
async fn pending_authorship(pool: &PgPool, by: Uuid, author: Uuid, paper: Uuid) {
    let mut conn = pool.acquire().await.expect("conn");
    let (_, created) = epigraph_db::create_ingest_written_edge_if_absent_conn(
        &mut conn,
        None,
        "ingest_document",
        by,
        author,
        "agent",
        paper,
        "paper",
        "authored",
        Some(serde_json::json!({
            "pending_countersign": true,
            "ingested_by": by.to_string(),
            "position": 0,
        })),
    )
    .await
    .expect("pending authorship");
    assert!(created, "CALIBRATION: the pending authorship was written");
}

/// `caller` confirms `agent`'s (default: its own) pending authorship of
/// `paper` through 208's definer on its own stamped transaction.
async fn confirm_authorship(
    pool: &PgPool,
    scoped: &ScopedPool,
    caller: Uuid,
    paper: Uuid,
    agent: Option<Uuid>,
) {
    let v = viewer(pool, caller).await;
    let mut tx = scoped.begin_as(&v).await.expect("stamped tx");
    let rows = epigraph_db::CountersignRepository::countersign_conn(
        &mut tx,
        paper,
        agent,
        epigraph_db::CountersignDecision::Confirm,
        None,
    )
    .await
    .expect("countersign");
    assert_eq!(
        rows.len(),
        1,
        "CALIBRATION: one pending authorship confirmed"
    );
    tx.commit().await.expect("commit");
}

/// Operator ruling C2: a countersigned authorship (the person's own act) of a
/// paper the viewer can read names the person, as a claim does. Confirmed by
/// the person for itself, by a linked agent for itself, or by the person as
/// its agent's live operator. An ingest's naming that nobody countersigned
/// names no one; a group paper's countersign names the person to that group's
/// readers only.
#[sqlx::test(migrations = "../../migrations")]
async fn a_countersigned_authorship_of_a_readable_paper_names_the_human(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let world = fixture::world_group(&pool).await;
    let (outsider, _) = named(&pool, "Dario Distant").await;
    let (ingester, _) = named(&pool, "ingest-bot").await;

    // The person itself, named pending by a stranger's ingest.
    let (h1, _) = human(&pool, "Edda Author").await;
    let p1 = paper_owned(&pool, "public", world).await;
    pending_authorship(&pool, ingester, h1, p1).await;
    assert!(
        !named_to(&pool, &scoped, outsider, h1).await,
        "an ingest-named authorship nobody countersigned must not name the person"
    );
    assert!(
        !named_to_guest(&pool, &scoped, h1).await,
        "nor to the guest viewer"
    );
    confirm_authorship(&pool, &scoped, h1, p1, None).await;
    assert!(
        named_to(&pool, &scoped, outsider, h1).await,
        "the person's countersign of a public paper names it"
    );
    assert!(
        named_to_guest(&pool, &scoped, h1).await,
        "to the guest viewer too"
    );

    // A linked agent confirms its own authorship.
    let (h2, _) = human(&pool, "Finn Fleet").await;
    let (bot2, _) = named(&pool, "finn-bot").await;
    link(&pool, bot2, h2).await;
    let p2 = paper_owned(&pool, "public", world).await;
    pending_authorship(&pool, ingester, bot2, p2).await;
    assert!(
        !named_to(&pool, &scoped, outsider, h2).await,
        "CALIBRATION: pending, the agent's naming names no human"
    );
    confirm_authorship(&pool, &scoped, bot2, p2, None).await;
    assert!(
        named_to(&pool, &scoped, outsider, h2).await,
        "a linked agent's countersign names its human"
    );

    // The person confirms as its agent's live operator.
    let (h3, _) = human(&pool, "Gerd Operator").await;
    let (bot3, _) = named(&pool, "gerd-bot").await;
    link(&pool, bot3, h3).await;
    let p3 = paper_owned(&pool, "public", world).await;
    pending_authorship(&pool, ingester, bot3, p3).await;
    confirm_authorship(&pool, &scoped, h3, p3, Some(bot3)).await;
    assert!(
        named_to(&pool, &scoped, outsider, h3).await,
        "the person's countersign as live operator names it"
    );

    // A group paper: only its readers.
    let (h4, _) = human(&pool, "Hedi Grouped").await;
    let (reader, _) = named(&pool, "Ines Reader").await;
    let team = keyed_team(&pool, &[reader]).await;
    let p4 = paper_owned(&pool, "group", team).await;
    pending_authorship(&pool, ingester, h4, p4).await;
    confirm_authorship(&pool, &scoped, h4, p4, None).await;
    assert!(
        named_to(&pool, &scoped, reader, h4).await,
        "a countersign of a group paper names the person to its readers"
    );
    assert!(
        !named_to(&pool, &scoped, outsider, h4).await,
        "and to no one who cannot read the paper"
    );
}

/// C2 is windowed as C5 is: a linked agent's countersign made BEFORE its
/// binding to H began never names H. The person's own countersign of the
/// agent's next naming, after the link, does (CALIBRATION).
#[sqlx::test(migrations = "../../migrations")]
async fn a_countersign_from_before_the_binding_never_names_the_human(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let world = fixture::world_group(&pool).await;
    let (outsider, _) = named(&pool, "Jo Onlooker").await;
    let (ingester, _) = named(&pool, "ingest-bot-2").await;
    let (h, _) = human(&pool, "Kira Late").await;
    let (bot, _) = named(&pool, "kira-bot").await;
    let p1 = paper_owned(&pool, "public", world).await;
    pending_authorship(&pool, ingester, bot, p1).await;
    // The countersign's audit row is stamped `now()` (208's RESTRICTIVE policy),
    // so it precedes the link written after it.
    confirm_authorship(&pool, &scoped, bot, p1, None).await;
    link(&pool, bot, h).await;
    assert!(
        !named_to(&pool, &scoped, outsider, h).await,
        "a countersign from before the link must not name the human"
    );
    let p2 = paper_owned(&pool, "public", world).await;
    pending_authorship(&pool, ingester, bot, p2).await;
    confirm_authorship(&pool, &scoped, h, p2, Some(bot)).await;
    assert!(
        named_to(&pool, &scoped, outsider, h).await,
        "CALIBRATION: the person's countersign after the link names it"
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
             public.author_binding_clients, public.claims, public.group_role_bindings \
             TO {role}"
        ),
        // The team arm's role derivation (277 calls 249's function directly;
        // 272 reached it through 236's twin).
        format!(
            "GRANT EXECUTE ON FUNCTION \
             public.epigraph_role_derived_memberships(uuid, timestamptz) TO {role}"
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
    // Migration 280 (review finding correctness#5): re-pointing or unlinking
    // the agent removes the old agent's evidence just as a retype does, and
    // would name it to everyone (the fail-open direction).
    let (other, _) = named(&pool, "Rosa Elsewhere").await;
    for (stmt, what) in [
        (
            "UPDATE oauth_clients SET agent_id = $2 WHERE id = $1",
            "re-point",
        ),
        (
            "UPDATE oauth_clients SET agent_id = NULL WHERE id = $1 AND $2::uuid IS NOT NULL",
            "unlink",
        ),
    ] {
        let msg = sqlx::query(stmt)
            .bind(client)
            .bind(other)
            .execute(&pool)
            .await
            .expect_err(what)
            .to_string();
        assert!(msg.contains("HEV01"), "{what}: refusal names HEV01: {msg}");
    }

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
    // CALIBRATION for 280: the first link of an unlinked human client (what
    // `epigraph_oauth_client_link_agent` does) stays allowed.
    let fresh: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, status) \
         VALUES ($1, 'fresh', 'human', ARRAY['claims:read'], 'active') RETURNING id",
    )
    .bind(format!("fresh-{}", Uuid::new_v4()))
    .fetch_one(&pool)
    .await
    .expect("fresh human client");
    sqlx::query("UPDATE oauth_clients SET agent_id = $2 WHERE id = $1 AND agent_id IS NULL")
        .bind(fresh)
        .bind(other)
        .execute(&pool)
        .await
        .expect("an unlinked human client may be linked");
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
    let (old_mate, _) = named(&pool, "Vera Oldgroup").await;
    let (outsider, _) = named(&pool, "Uma Uninvolved").await;
    // A team of the mate and the LIVE-bound agents, NOT of H; and a separate
    // team of `old_mate` and the agents whose binding is later retired /
    // revoked, in which no live-bound agent of H files (review finding
    // tests#3b: otherwise a live bot's claim in the same group names H to the
    // reader, and the matrix cannot tell whether an ENDED binding still
    // traces to H).
    let g = keyed_team(&pool, &[mate, live_bot, svc]).await;
    let g_old = keyed_team(&pool, &[old_mate, old_bot, gone_svc]).await;
    let other = keyed_team(&pool, &[outsider]).await;

    let mut seeded = 0;
    for (filer, group, tag) in [
        (live_bot, g, "live link"),
        (old_bot, g_old, "retired link"),
        (svc, g, "live allowance"),
        (gone_svc, g_old, "revoked allowance"),
    ] {
        fixture::seed_group_claim(&pool, filer, group, &format!("group claim via {tag}")).await;
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
    for who in [mate, old_mate, outsider, h, live_bot] {
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
    assert!(
        named_to(&pool, &scoped, old_mate, h).await,
        "only an ENDED binding's claim traces H to this reader"
    );
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

// ─── T5: the self-service setter (migration 273) ─────────────────────────

/// Set `profile` as the principal `who`, on an `epigraph_app` transaction
/// stamped from `who`'s viewer, through the repository function the MCP tool
/// and the REST route call. Commits on success.
async fn set_as(
    pool: &PgPool,
    scoped: &ScopedPool,
    who: Uuid,
    profile: epigraph_db::ProfileVisibility,
) -> Result<epigraph_db::ProfileVisibilitySet, epigraph_db::DbError> {
    let v = viewer(pool, who).await;
    let mut tx = scoped.begin_as(&v).await.expect("begin_as");
    let r = epigraph_db::AgentRepository::set_profile_visibility_conn(&mut tx, profile).await;
    if r.is_ok() {
        tx.commit().await.expect("commit");
    }
    r
}

async fn profile_of(pool: &PgPool, agent: Uuid) -> String {
    sqlx::query_scalar("SELECT profile_visibility FROM agents WHERE id = $1")
        .bind(agent)
        .fetch_one(pool)
        .await
        .expect("profile")
}

async fn consent_of(pool: &PgPool, agent: Uuid) -> Option<chrono::DateTime<chrono::Utc>> {
    sqlx::query_scalar("SELECT profile_public_consented_at FROM agents WHERE id = $1")
        .bind(agent)
        .fetch_one(pool)
        .await
        .expect("consent stamp")
}

fn refusal_kind(r: Result<epigraph_db::ProfileVisibilitySet, epigraph_db::DbError>) -> String {
    match r {
        Err(epigraph_db::DbError::Refused { kind, message }) => format!("{kind:?} {message}"),
        other => panic!("expected a designed refusal, got {other:?}"),
    }
}

/// A human sets its own profile public: an outsider then sees it named; the
/// answer reports the previous value and that everyone sees the name; one
/// audit row per call. Setting it back to `'group'` hides it again when no
/// other arm holds, and `named_to_everyone` says so.
#[sqlx::test(migrations = "../../migrations")]
async fn a_human_sets_its_own_profile_and_is_told_the_effective_state(pool: PgPool) {
    use epigraph_db::ProfileVisibility::{Group, Public};
    let scoped = app_pool(&pool).await;
    let (outsider, _) = named(&pool, "Ada Bystander").await;
    let (h, _) = human(&pool, "Bram Optin").await;

    let set = set_as(&pool, &scoped, h, Public).await.expect("opt in");
    assert_eq!(set.previous, "group");
    assert_eq!(set.profile_visibility, "public");
    assert!(
        consent_of(&pool, h).await.is_some(),
        "C11: the opt-in records when H consented"
    );
    assert!(
        set.named_to_everyone,
        "a public profile is named to everyone"
    );
    assert!(
        named_to(&pool, &scoped, outsider, h).await,
        "opted in: named"
    );

    let set = set_as(&pool, &scoped, h, Group).await.expect("opt out");
    assert_eq!(
        (set.previous.as_str(), set.profile_visibility.as_str()),
        ("public", "group")
    );
    assert!(
        !set.named_to_everyone,
        "nothing else names H, so the answer must say so"
    );
    assert!(
        !named_to(&pool, &scoped, outsider, h).await,
        "opted out: unnamed"
    );
    assert_eq!(
        consent_of(&pool, h).await,
        None,
        "C11: the opt-out clears the consent stamp"
    );

    let audits: Vec<(Uuid, serde_json::Value)> = sqlx::query_as(
        "SELECT agent_id, details FROM security_events \
          WHERE event_type = 'agent.profile_visibility_set' ORDER BY created_at",
    )
    .fetch_all(&pool)
    .await
    .expect("audit rows");
    assert_eq!(audits.len(), 2, "one audit row per call");
    assert!(audits.iter().all(|(a, _)| *a == h), "attributed to H");
    assert_eq!(audits[0].1["previous"], "group");
    assert_eq!(audits[0].1["profile_visibility"], "public");
    assert_eq!(audits[1].1["previous"], "public");
}

/// Finding 17: setting `'group'` while a public claim of B(H) exists is
/// truthful: the name is still shown to everyone, and the answer says so.
#[sqlx::test(migrations = "../../migrations")]
async fn opting_out_with_a_public_claim_reports_the_name_is_still_public(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (h, _) = human(&pool, "Cleo Accountable").await;
    let (bot, _) = named(&pool, "cleo-bot").await;
    link(&pool, bot, h).await;
    fixture::seed_public_claim(&pool, bot, "cleo's bot said this publicly").await;
    let set = set_as(&pool, &scoped, h, epigraph_db::ProfileVisibility::Group)
        .await
        .expect("set group");
    assert!(
        set.named_to_everyone,
        "a public claim of a bound agent names H whatever the profile"
    );
}

/// Refusals, each changing nothing: a non-human principal (a service, an
/// operated bot) is PVS05 (finding 17); no principal is PVS01; a value other
/// than public / group is PVS02.
#[sqlx::test(migrations = "../../migrations")]
async fn the_setter_refuses_non_humans_anonymous_callers_and_bad_values(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (h, _) = human(&pool, "Dmitri Owner").await;
    let (bot, _) = named(&pool, "dmitri-bot").await;
    link(&pool, bot, h).await;
    let (svc, _) = named(&pool, "Plain Service").await;
    set_profile(&pool, svc, "group").await;

    for (who, label) in [(bot, "operated bot"), (svc, "service")] {
        let msg =
            refusal_kind(set_as(&pool, &scoped, who, epigraph_db::ProfileVisibility::Public).await);
        assert!(
            msg.starts_with("Authority PVS05"),
            "{label}: expected PVS05 authority, got {msg}"
        );
    }
    assert_eq!(profile_of(&pool, svc).await, "group", "nothing changed");
    assert_eq!(
        profile_of(&pool, h).await,
        "group",
        "nor on the bot's human"
    );

    // The guest viewer's stamp (the nil principal): not a person.
    let guest = fixture::public_viewer(&pool).await;
    let mut tx = scoped.begin_as(&guest).await.expect("begin_as guest");
    let r = epigraph_db::AgentRepository::set_profile_visibility_conn(
        &mut tx,
        epigraph_db::ProfileVisibility::Public,
    )
    .await;
    drop(tx);
    let msg = refusal_kind(r);
    assert!(msg.starts_with("Authority PVS05"), "guest: {msg}");

    // No principal at all: an unstamped application session.
    let r = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        let r = epigraph_db::AgentRepository::set_profile_visibility_conn(
            &mut conn,
            epigraph_db::ProfileVisibility::Public,
        )
        .await;
        (conn, r)
    })
    .await;
    let msg = refusal_kind(r);
    assert!(msg.starts_with("Authority PVS01"), "unstamped: {msg}");

    // A value the CHECK does not admit, through raw SQL (the Rust enum
    // cannot express it).
    let v = viewer(&pool, h).await;
    let mut tx = scoped.begin_as(&v).await.expect("begin_as");
    let err = sqlx::query("SELECT * FROM public.epigraph_set_profile_visibility('team')")
        .execute(&mut *tx)
        .await
        .expect_err("'team' is not a profile value")
        .to_string();
    drop(tx);
    assert!(err.contains("PVS02"), "bad value: {err}");
    assert_eq!(profile_of(&pool, h).await, "group", "nothing changed");
    let audits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_events WHERE event_type = 'agent.profile_visibility_set'",
    )
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(audits, 0, "a refused call writes no audit row");
}

/// 273's catalog: SECURITY DEFINER on `pg_catalog, pg_temp`, owned by
/// maintenance, EXECUTE for the application role and not for PUBLIC.
#[sqlx::test(migrations = "../../migrations")]
async fn migration_273_setter_is_pinned_owned_and_granted(pool: PgPool) {
    let sig = "public.epigraph_set_profile_visibility(text)";
    let (secdef, owner, config, app, public): (bool, String, Vec<String>, bool, bool) =
        sqlx::query_as(
            "SELECT p.prosecdef, pg_get_userbyid(p.proowner)::text, \
                    COALESCE(p.proconfig, '{}'::text[]), \
                    has_function_privilege('epigraph_app', p.oid, 'EXECUTE'), \
                    p.proacl IS NULL OR EXISTS (SELECT 1 FROM aclexplode(p.proacl) a \
                                                 WHERE a.grantee = 0 \
                                                   AND a.privilege_type = 'EXECUTE') \
               FROM pg_proc p WHERE p.oid = $1::text::regprocedure",
        )
        .bind(sig)
        .fetch_one(&pool)
        .await
        .expect("catalog");
    assert!(secdef);
    assert_eq!(owner, "epigraph_maintenance");
    assert_eq!(config, vec!["search_path=pg_catalog, pg_temp".to_string()]);
    assert!(app, "epigraph_app must EXECUTE the setter");
    assert!(!public, "PUBLIC must not EXECUTE the setter");
}

// ─── T10 / T7: provisioning as 'group' and the reset (migration 274) ──────

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

fn below(version: i64) -> sqlx::migrate::Migrator {
    sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            MIGRATOR
                .migrations
                .iter()
                .filter(|m| m.version < version)
                .cloned()
                .collect(),
        ),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    }
}

async fn migrate(pool: &PgPool, migrator: &sqlx::migrate::Migrator) -> Result<(), String> {
    let mut conn = pool.acquire().await.expect("acquire");
    let r = migrator.run(&mut *conn).await.map_err(|e| e.to_string());
    sqlx::query("RESET ALL")
        .execute(&mut *conn)
        .await
        .expect("RESET ALL");
    r
}

/// The provisioning definer inserts a human principal as `'group'` (so the
/// value is evidence of consent from the first token) and any other agent as
/// `'public'`, as before. The ON CONFLICT re-find of a derived row is kept.
#[sqlx::test(migrations = "../../migrations")]
async fn provisioning_inserts_humans_as_group_and_others_as_public(pool: PgPool) {
    for (agent_type, want) in [("human", "group"), ("software_agent", "public")] {
        let key: Vec<u8> = Uuid::new_v4()
            .as_bytes()
            .iter()
            .copied()
            .cycle()
            .take(32)
            .collect();
        let id: Option<Uuid> =
            sqlx::query_scalar("SELECT public.epigraph_provision_oauth_agent($1, $2, $3)")
                .bind(&key)
                .bind(format!("oauth:{agent_type}"))
                .bind(agent_type)
                .fetch_one(&pool)
                .await
                .expect("provision");
        let id = id.expect("a fresh derived key provisions a row");
        assert_eq!(profile_of(&pool, id).await, want, "{agent_type}");
        let again: Option<Uuid> =
            sqlx::query_scalar("SELECT public.epigraph_provision_oauth_agent($1, $2, $3)")
                .bind(&key)
                .bind("ignored on the re-find")
                .bind(agent_type)
                .fetch_one(&pool)
                .await
                .expect("re-find");
        assert_eq!(
            again,
            Some(id),
            "the ON CONFLICT re-find returns the same row"
        );
    }
}

/// Seed the reset's population on a database migrated below 274: a
/// registered operator and a provider-client-only person on the column
/// default (`'public'`), a human already on `'group'`, and a non-human on
/// `'public'`.
async fn seed_reset_population(pool: &PgPool) -> (Uuid, Uuid, Uuid, Uuid) {
    let (op, _) = named(pool, "Edda Registered").await;
    fixture::make_human_operator(pool, op).await;
    let (prov, _) = named(pool, "Finn Provider").await;
    sqlx::query(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    status, agent_id) \
         VALUES ($1, 'Finn Provider', 'human', ARRAY['claims:write'], 'active', $2)",
    )
    .bind(format!("fixture-provider:{prov}"))
    .bind(prov)
    .execute(pool)
    .await
    .expect("provider client");
    let (already, _) = named(pool, "Gita Already").await;
    fixture::make_human_operator(pool, already).await;
    // Below 274 (and 283): the column alone, no consent stamp yet.
    sqlx::query("UPDATE agents SET profile_visibility = 'group' WHERE id = $1")
        .bind(already)
        .execute(pool)
        .await
        .expect("already group");
    let (svc, _) = named(pool, "Plain Software").await;
    (op, prov, already, svc)
}

/// Production order: a human on `'public'` before 274 is `'group'` after,
/// both kinds of evidence; a non-human is untouched; one summary audit row
/// carries the pre-count, the rows moved and the post-count.
#[sqlx::test(migrations = false)]
async fn migration_274_resets_every_human_and_audits_the_counts(pool: PgPool) {
    migrate(&pool, &below(274)).await.expect("migrate to 273");
    let (op, prov, already, svc) = seed_reset_population(&pool).await;
    for a in [op, prov, svc] {
        assert_eq!(profile_of(&pool, a).await, "public", "PREMISE");
    }
    migrate(&pool, &MIGRATOR).await.expect("migrate to head");
    for (a, want, who) in [
        (op, "group", "registered operator"),
        (prov, "group", "provider-client person"),
        (already, "group", "already group"),
        (svc, "public", "non-human"),
    ] {
        assert_eq!(profile_of(&pool, a).await, want, "{who}");
    }
    let audits: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT details FROM security_events WHERE event_type = 'agent.profile_visibility_reset'",
    )
    .fetch_all(&pool)
    .await
    .expect("audit");
    assert_eq!(audits.len(), 1, "one summary row");
    let d = &audits[0];
    assert_eq!(d["migration"], 274);
    assert_eq!(d["before"], 2, "two humans were public: {d}");
    assert_eq!(d["rows"], 2, "{d}");
    assert_eq!(d["after"], 0, "{d}");
}

/// Finding 11: an UPDATE that moves no row (a runner row security filters)
/// must fail the migration, not leave every human reading as consented.
/// Reproduced by a trigger that silently skips the reset's rows.
#[sqlx::test(migrations = false)]
async fn migration_274_refuses_when_the_reset_moves_nothing(pool: PgPool) {
    migrate(&pool, &below(274)).await.expect("migrate to 273");
    let (op, _, _, _) = seed_reset_population(&pool).await;
    for stmt in [
        "CREATE FUNCTION public.test_skip_profile_reset() RETURNS trigger \
         LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$ \
         BEGIN IF NEW.profile_visibility IS DISTINCT FROM OLD.profile_visibility THEN \
         RETURN NULL; END IF; RETURN NEW; END $$",
        "CREATE TRIGGER test_skip_profile_reset BEFORE UPDATE ON public.agents \
         FOR EACH ROW EXECUTE FUNCTION public.test_skip_profile_reset()",
    ] {
        sqlx::query(stmt).execute(&pool).await.expect(stmt);
    }
    let err = migrate(&pool, &MIGRATOR)
        .await
        .expect_err("a reset that moved nothing must refuse");
    assert!(err.contains("PVR02"), "post-condition refusal: {err}");
    assert_eq!(profile_of(&pool, op).await, "public", "rolled back whole");
}

/// The precondition: a provisioning definer whose body is not 077's is never
/// overwritten blind.
#[sqlx::test(migrations = false)]
async fn migration_274_refuses_over_another_provision_body(pool: PgPool) {
    migrate(&pool, &below(274)).await.expect("migrate to 273");
    sqlx::query(
        "CREATE OR REPLACE FUNCTION public.epigraph_provision_oauth_agent( \
             p_public_key bytea, p_display_name text, p_agent_type text) \
         RETURNS uuid LANGUAGE sql SECURITY DEFINER \
         SET search_path = public, pg_temp AS $$ SELECT NULL::uuid $$",
    )
    .execute(&pool)
    .await
    .expect("another body");
    let err = migrate(&pool, &MIGRATOR)
        .await
        .expect_err("274 must refuse over another body");
    assert!(err.contains("PVR01"), "precondition refusal: {err}");
}

/// Migration 279 re-orders 277's core (review finding correctness#3): it
/// refuses over a core whose body is not 277's (DAO01), and at head the
/// readable-claim arm precedes the role-derived probe.
#[sqlx::test(migrations = false)]
async fn migration_279_refuses_over_another_core_body(pool: PgPool) {
    migrate(&pool, &below(279)).await.expect("migrate to 278");
    sqlx::query(
        "CREATE OR REPLACE FUNCTION public.epigraph_agent_disclosure_for( \
             p_target uuid, p_principal uuid, p_groups uuid[], p_privileged boolean) \
         RETURNS TABLE (named boolean, details boolean) \
         LANGUAGE plpgsql STABLE SECURITY DEFINER COST 1000 \
         SET search_path = pg_catalog, pg_temp AS $$ \
         BEGIN RETURN QUERY SELECT false, false; END $$",
    )
    .execute(&pool)
    .await
    .expect("another body");
    let err = migrate(&pool, &MIGRATOR)
        .await
        .expect_err("279 must refuse over another body");
    assert!(err.contains("DAO01"), "precondition refusal: {err}");
}

/// 283 re-states 279's core and 273's setter; over any other body of either
/// it refuses (PCN01) with nothing changed.
#[sqlx::test(migrations = false)]
async fn migration_283_refuses_over_another_core_or_setter_body(pool: PgPool) {
    migrate(&pool, &below(283)).await.expect("migrate to 282");
    sqlx::query(
        "CREATE OR REPLACE FUNCTION public.epigraph_set_profile_visibility(p_visibility text) \
         RETURNS TABLE (previous text, profile_visibility text, named_to_everyone boolean) \
         LANGUAGE plpgsql VOLATILE SECURITY DEFINER \
         SET search_path = pg_catalog, pg_temp AS $$ \
         BEGIN RETURN QUERY SELECT NULL::text, NULL::text, false; END $$",
    )
    .execute(&pool)
    .await
    .expect("another setter body");
    let err = migrate(&pool, &MIGRATOR)
        .await
        .expect_err("283 must refuse over another setter body");
    assert!(err.contains("PCN01"), "precondition refusal: {err}");
    let column: Option<String> = sqlx::query_scalar(
        "SELECT column_name::text FROM information_schema.columns \
          WHERE table_schema = 'public' AND table_name = 'agents' \
            AND column_name = 'profile_public_consented_at'",
    )
    .fetch_optional(&pool)
    .await
    .expect("column lookup");
    assert_eq!(column, None, "nothing was changed");
}

/// 288 (C5) re-states 283's core; over any other body it refuses (BWS01) with
/// nothing changed.
#[sqlx::test(migrations = false)]
async fn migration_288_refuses_over_another_core_body(pool: PgPool) {
    migrate(&pool, &below(288)).await.expect("migrate to 287");
    sqlx::query(
        "CREATE OR REPLACE FUNCTION public.epigraph_agent_disclosure_for( \
             p_target uuid, p_principal uuid, p_groups uuid[], p_privileged boolean) \
         RETURNS TABLE (named boolean, details boolean) \
         LANGUAGE plpgsql STABLE SECURITY DEFINER COST 1000 \
         SET search_path = pg_catalog, pg_temp AS $$ \
         BEGIN RETURN QUERY SELECT false, false; END $$",
    )
    .execute(&pool)
    .await
    .expect("another body");
    let err = migrate(&pool, &MIGRATOR)
        .await
        .expect_err("288 must refuse over another body");
    assert!(err.contains("BWS01"), "precondition refusal: {err}");
    let src: String = sqlx::query_scalar(
        "SELECT prosrc FROM pg_proc \
          WHERE oid = to_regprocedure('public.epigraph_agent_disclosure_for(uuid, uuid, uuid[], boolean)')",
    )
    .fetch_one(&pool)
    .await
    .expect("core source");
    assert!(!src.contains("v_since"), "nothing was changed");
}

/// 295 (C6) re-states 288's core; over any other body it refuses (PAK01) with
/// nothing changed.
#[sqlx::test(migrations = false)]
async fn migration_295_refuses_over_another_core_body(pool: PgPool) {
    migrate(&pool, &below(295)).await.expect("migrate to 294");
    sqlx::query(
        "CREATE OR REPLACE FUNCTION public.epigraph_agent_disclosure_for( \
             p_target uuid, p_principal uuid, p_groups uuid[], p_privileged boolean) \
         RETURNS TABLE (named boolean, details boolean) \
         LANGUAGE plpgsql STABLE SECURITY DEFINER COST 1000 \
         SET search_path = pg_catalog, pg_temp AS $$ \
         BEGIN RETURN QUERY SELECT false, false; END $$",
    )
    .execute(&pool)
    .await
    .expect("another body");
    let err = migrate(&pool, &MIGRATOR)
        .await
        .expect_err("295 must refuse over another body");
    assert!(err.contains("PAK01"), "precondition refusal: {err}");
    let src: String = sqlx::query_scalar(
        "SELECT prosrc FROM pg_proc \
          WHERE oid = to_regprocedure('public.epigraph_agent_disclosure_for(uuid, uuid, uuid[], boolean)')",
    )
    .fetch_one(&pool)
    .await
    .expect("core source");
    assert!(!src.contains("ingested_claim"), "nothing was changed");
}

/// 297 (C2) re-states 295's core; over any other body it refuses (CSN01) with
/// nothing changed.
#[sqlx::test(migrations = false)]
async fn migration_297_refuses_over_another_core_body(pool: PgPool) {
    migrate(&pool, &below(297)).await.expect("migrate to 296");
    sqlx::query(
        "CREATE OR REPLACE FUNCTION public.epigraph_agent_disclosure_for( \
             p_target uuid, p_principal uuid, p_groups uuid[], p_privileged boolean) \
         RETURNS TABLE (named boolean, details boolean) \
         LANGUAGE plpgsql STABLE SECURITY DEFINER COST 1000 \
         SET search_path = pg_catalog, pg_temp AS $$ \
         BEGIN RETURN QUERY SELECT false, false; END $$",
    )
    .execute(&pool)
    .await
    .expect("another body");
    let err = migrate(&pool, &MIGRATOR)
        .await
        .expect_err("297 must refuse over another body");
    assert!(err.contains("CSN01"), "precondition refusal: {err}");
    let src: String = sqlx::query_scalar(
        "SELECT prosrc FROM pg_proc \
          WHERE oid = to_regprocedure('public.epigraph_agent_disclosure_for(uuid, uuid, uuid[], boolean)')",
    )
    .fetch_one(&pool)
    .await
    .expect("core source");
    assert!(
        !src.contains("authorship.countersigned"),
        "nothing was changed"
    );
}

/// 300 re-states 297's core; over any other body it refuses (LPR01) with
/// nothing changed. 298's accessor is LEAKPROOF and IMMUTABLE (what lets 299
/// index it and the core's probe use it under row security).
#[sqlx::test(migrations = false)]
async fn migration_300_refuses_over_another_core_body(pool: PgPool) {
    migrate(&pool, &below(300)).await.expect("migrate to 299");
    let (leakproof, volatility): (bool, String) = sqlx::query_as(
        "SELECT proleakproof, provolatile::text FROM pg_proc \
          WHERE oid = to_regprocedure('public.epigraph_ingest_record_ingester(jsonb)')",
    )
    .fetch_one(&pool)
    .await
    .expect("298's accessor");
    assert!(leakproof, "298's accessor is LEAKPROOF");
    assert_eq!(volatility, "i", "298's accessor is IMMUTABLE");
    sqlx::query(
        "CREATE OR REPLACE FUNCTION public.epigraph_agent_disclosure_for( \
             p_target uuid, p_principal uuid, p_groups uuid[], p_privileged boolean) \
         RETURNS TABLE (named boolean, details boolean) \
         LANGUAGE plpgsql STABLE SECURITY DEFINER COST 1000 \
         SET search_path = pg_catalog, pg_temp AS $$ \
         BEGIN RETURN QUERY SELECT false, false; END $$",
    )
    .execute(&pool)
    .await
    .expect("another body");
    let err = migrate(&pool, &MIGRATOR)
        .await
        .expect_err("300 must refuse over another body");
    assert!(err.contains("LPR01"), "precondition refusal: {err}");
    let src: String = sqlx::query_scalar(
        "SELECT prosrc FROM pg_proc \
          WHERE oid = to_regprocedure('public.epigraph_agent_disclosure_for(uuid, uuid, uuid[], boolean)')",
    )
    .fetch_one(&pool)
    .await
    .expect("core source");
    assert!(!src.contains("v_bound_text"), "nothing was changed");
}

/// 302 re-states 300's core; over any other body it refuses (OWN01) with
/// nothing changed.
#[sqlx::test(migrations = false)]
async fn migration_302_refuses_over_another_core_body(pool: PgPool) {
    migrate(&pool, &below(302)).await.expect("migrate to 301");
    sqlx::query(
        "CREATE OR REPLACE FUNCTION public.epigraph_agent_disclosure_for( \
             p_target uuid, p_principal uuid, p_groups uuid[], p_privileged boolean) \
         RETURNS TABLE (named boolean, details boolean) \
         LANGUAGE plpgsql STABLE SECURITY DEFINER COST 1000 \
         SET search_path = pg_catalog, pg_temp AS $$ \
         BEGIN RETURN QUERY SELECT false, false; END $$",
    )
    .execute(&pool)
    .await
    .expect("another body");
    let err = migrate(&pool, &MIGRATOR)
        .await
        .expect_err("302 must refuse over another body");
    assert!(err.contains("OWN01"), "precondition refusal: {err}");
    let src: String = sqlx::query_scalar(
        "SELECT prosrc FROM pg_proc \
          WHERE oid = to_regprocedure('public.epigraph_agent_disclosure_for(uuid, uuid, uuid[], boolean)')",
    )
    .fetch_one(&pool)
    .await
    .expect("core source");
    assert!(
        !src.contains("slot_kind = 'assessment'"),
        "nothing was changed"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_role_derived_probe_is_the_cores_last_arm(pool: PgPool) {
    let src: String = sqlx::query_scalar(
        "SELECT prosrc FROM pg_proc \
          WHERE oid = to_regprocedure('public.epigraph_agent_disclosure_for(uuid, uuid, uuid[], boolean)')",
    )
    .fetch_one(&pool)
    .await
    .expect("core source");
    let readable = src.find("readable claim:").expect("readable arm");
    let derived = src
        .find("epigraph_role_derived_memberships")
        .expect("role-derived arm");
    assert!(
        readable < derived,
        "the 0.6 s role-derived probe must run after the readable-claim arm"
    );
}

/// Finding 14 (spec F4): the column default stays `'public'`, so a new path
/// that inserts agents could create a human that reads as consented. The
/// exact set of functions whose body inserts into `public.agents` is pinned:
/// adding one is a visible change to this list, reviewed for whether it can
/// create a human principal (it must then insert `'group'`).
#[sqlx::test(migrations = "../../migrations")]
async fn the_functions_that_insert_agents_are_exactly_the_register(pool: PgPool) {
    let found: Vec<String> = sqlx::query_scalar(
        "SELECT p.oid::regprocedure::text FROM pg_proc p \
           JOIN pg_namespace n ON n.oid = p.pronamespace \
          WHERE n.nspname = 'public' \
            AND p.prosrc ~* 'insert\\s+into\\s+(public\\.)?agents(\\s|\\()' \
          ORDER BY 1",
    )
    .fetch_all(&pool)
    .await
    .expect("catalog");
    assert_eq!(
        found, AGENT_INSERTING_FUNCTIONS,
        "functions that insert agents"
    );
}

/// See [`the_functions_that_insert_agents_are_exactly_the_register`]. Only
/// `epigraph_provision_oauth_agent` can create a human principal (it is the
/// mint of every OAuth principal, and inserts `'group'` for a human).
const AGENT_INSERTING_FUNCTIONS: &[&str] = &[
    // 165 and later: a group role's agent node (`agent_type` role). Never a human
    // principal: it has no human OAuth client and no registration.
    "epigraph_define_group_role(text,text,uuid,text,boolean,text)",
    "epigraph_define_group_role(text,text,uuid,text,text,text)",
    // 077, re-stated by 274: the OAuth principal mint; a human is 'group'.
    "epigraph_provision_oauth_agent(bytea,text,text)",
    // 161 / 166: an LLM agent identity keyed on (model, prompt). Never a human
    // principal: it is linked to one, it does not become one.
    "epigraph_register_agent_identity(bytea,uuid,text,text,text,bytea,jsonb)",
];

// ─── part B: the Rust disclosure reader (spec 6.2) ───────────────────────

/// `AgentDisclosureRepository::names` / `disclosure` on a stamped
/// `epigraph_app` connection: an unnamed human reads as a nameless service
/// principal (its `oauth:<client row id>` placeholder, operator ruling C7), a
/// teammate gets the name (CALIBRATION), a named non-human is named to
/// everyone, and an unknown id is absent rather than `None`.
#[sqlx::test(migrations = "../../migrations")]
async fn the_rust_reader_names_exactly_what_the_session_may_see(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (h, _) = human(&pool, "Petra Unseen").await;
    let (mate, _) = named(&pool, "Petra Teammate").await;
    let (outsider, _) = named(&pool, "Petra Outsider").await;
    let (bot, _) = named(&pool, "Petra Service Bot").await;
    keyed_team(&pool, &[h, mate]).await;
    let ghost = Uuid::new_v4();

    let read_names = |who: Uuid| {
        let pool = pool.clone();
        let scoped = &scoped;
        async move {
            let v = viewer(&pool, who).await;
            let mut read = scoped.read_as(&v).await.expect("read_as");
            let names = epigraph_db::AgentDisclosureRepository::names(&mut read, &[h, bot, ghost])
                .await
                .expect("names");
            let d = epigraph_db::AgentDisclosureRepository::disclosure(&mut read, &[h, bot, ghost])
                .await
                .expect("disclosure");
            (names, d)
        }
    };
    let (names, d) = read_names(outsider).await;
    let placeholder: String =
        sqlx::query_scalar("SELECT 'oauth:' || id::text FROM oauth_clients WHERE agent_id = $1")
            .bind(h)
            .fetch_one(&pool)
            .await
            .expect("the fixture's one client");
    assert_eq!(
        names.get(&h),
        Some(&Some(placeholder.clone())),
        "unnamed human reads as a nameless service principal"
    );
    assert_eq!(
        names.get(&bot),
        Some(&Some("Petra Service Bot".to_string()))
    );
    assert!(!names.contains_key(&ghost), "an unknown id is absent");
    assert_eq!(
        d.get(&h).cloned(),
        Some(epigraph_db::Disclosure {
            named: false,
            details: false,
            unnamed_as: Some(placeholder),
        })
    );
    assert_eq!(
        d[&bot].unnamed_as, None,
        "a named agent carries no placeholder"
    );
    let (names, d) = read_names(mate).await;
    assert_eq!(
        names.get(&h),
        Some(&Some("Petra Unseen".to_string())),
        "CALIBRATION: a teammate sees the name"
    );
    assert!(d[&h].named);
}

/// `names_for_audience` decides for the MAP's audience, never for the
/// maintenance session that builds the document: the public map does not
/// name an unnamed human even though the building session would; a team
/// map whose team H belongs to does. The application role may not call it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_stored_documents_names_follow_its_audience_not_its_builder(pool: PgPool) {
    use epigraph_db::repos::atlas_map::AtlasMap;
    let (h, _) = human(&pool, "Quentin Mapped").await;
    let (mate, _) = named(&pool, "Quentin Teammate").await;
    let team = keyed_team(&pool, &[h, mate]).await;
    let (public, for_team, builder) =
        fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
            let public = epigraph_db::AgentDisclosureRepository::names_for_audience(
                &mut conn,
                &[h],
                AtlasMap::Public,
            )
            .await
            .expect("public audience");
            let for_team = epigraph_db::AgentDisclosureRepository::names_for_audience(
                &mut conn,
                &[h],
                AtlasMap::Team(team),
            )
            .await
            .expect("team audience");
            let builder = epigraph_db::AgentDisclosureRepository::names(&mut conn, &[h])
                .await
                .expect("builder session");
            (conn, (public, for_team, builder))
        })
        .await;
    let placeholder: String =
        sqlx::query_scalar("SELECT 'oauth:' || id::text FROM oauth_clients WHERE agent_id = $1")
            .bind(h)
            .fetch_one(&pool)
            .await
            .expect("the fixture's one client");
    assert_eq!(
        public.get(&h),
        Some(&Some(placeholder)),
        "the public map's audience sees the placeholder (C7)"
    );
    assert_eq!(
        for_team.get(&h),
        Some(&Some("Quentin Mapped".to_string())),
        "the team map's audience shares H's team"
    );
    assert_eq!(
        builder.get(&h),
        Some(&Some("Quentin Mapped".to_string())),
        "CALIBRATION: the building session itself is privileged, which is why it is never the audience"
    );
    let scoped = app_pool(&pool).await;
    let v = viewer(&pool, mate).await;
    let mut read = scoped.read_as(&v).await.expect("read_as");
    let refused = epigraph_db::AgentDisclosureRepository::names_for_audience(
        &mut read,
        &[h],
        AtlasMap::Public,
    )
    .await;
    assert!(
        refused.is_err(),
        "the application role must not ask about an arbitrary audience"
    );
}

// ─── part B: agent lookup (spec 7, rows A1-A5; T1) ───────────────────────

/// An `oauth_clients` row of `client_type` linked through the REAL
/// provisioning path (`AgentRepository::ensure_for_client`, which calls
/// migration 077/274's `epigraph_provision_oauth_agent`), as a token mint
/// does. A `human` client is given a provider-form id (`<provider>:<subject>`)
/// so the provider-asserted name is adopted (spec 9).
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
    let agent = epigraph_db::AgentRepository::ensure_for_client(&mut tx, row)
        .await
        .expect("ensure_for_client");
    tx.commit().await.expect("commit");
    agent.into()
}

/// T1's pair: H, a provider-provisioned person under its real name, and N, a
/// production-shaped nameless OAuth service principal, provisioned the same
/// way and left exactly as `ensure_for_client` mints it: named
/// `oauth:<client row id>`, profile `'public'`, label `oauth-principal`
/// (operator ruling C7: an unnamed human reads as THIS, not as a null name).
async fn h_and_n(pool: &PgPool, name: &str) -> (Uuid, Uuid) {
    let h = provisioned(pool, "human", name).await;
    let shown: Option<String> = sqlx::query_scalar("SELECT display_name FROM agents WHERE id = $1")
        .bind(h)
        .fetch_one(pool)
        .await
        .expect("name");
    assert_eq!(
        shown.as_deref(),
        Some(name),
        "CALIBRATION: H carries its real name"
    );
    let n = provisioned(pool, "service", "fixture service").await;
    let n_client = client_of(pool, n).await;
    let minted: Option<String> =
        sqlx::query_scalar("SELECT display_name FROM agents WHERE id = $1")
            .bind(n)
            .fetch_one(pool)
            .await
            .expect("name");
    assert_eq!(
        minted,
        Some(format!("oauth:{n_client}")),
        "CALIBRATION: N is the nameless service principal ensure_for_client mints"
    );
    (h, n)
}

/// The ONE OAuth client a provisioned fixture principal is linked to (the
/// client `ensure_for_client` was called with), read from the link, not from
/// the placeholder function under test.
async fn client_of(pool: &PgPool, agent: Uuid) -> Uuid {
    let rows: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM oauth_clients WHERE agent_id = $1")
        .bind(agent)
        .fetch_all(pool)
        .await
        .expect("linked clients");
    assert_eq!(rows.len(), 1, "a provisioned fixture has one client");
    rows[0]
}

/// The name an unnamed provisioned principal must be shown under: what
/// `ensure_for_client` names a service principal, `oauth:<client row id>`.
async fn placeholder_of(pool: &PgPool, agent: Uuid) -> String {
    format!("oauth:{}", client_of(pool, agent).await)
}

/// A card's JSON with the fields that legitimately differ between H and N
/// (identity, timestamp, and the client row id inside the `oauth:`
/// placeholder each is shown under) replaced.
fn card_shape(card: &epigraph_db::AgentCard, placeholder: &str) -> serde_json::Value {
    let mut v = serde_json::to_value(card).expect("card json");
    let o = v.as_object_mut().expect("object");
    o.insert("id".into(), serde_json::json!("<id>"));
    o.insert("created_at".into(), serde_json::json!("<t>"));
    if o.get("display_name") == Some(&serde_json::json!(placeholder)) {
        o.insert("display_name".into(), serde_json::json!("oauth:<client>"));
    }
    v
}

async fn cards_by(
    pool: &PgPool,
    scoped: &ScopedPool,
    who: Option<Uuid>,
    ids: &[Uuid],
) -> Vec<epigraph_db::AgentCard> {
    let v = match who {
        Some(w) => viewer(pool, w).await,
        None => fixture::public_viewer(pool).await,
    };
    let mut read = scoped.read_as(&v).await.expect("read_as");
    epigraph_db::AgentLookupRepository::cards(&mut read, &v, ids)
        .await
        .expect("cards")
}

async fn find_by(
    pool: &PgPool,
    scoped: &ScopedPool,
    who: Uuid,
    q: &str,
    kind: Option<&str>,
) -> epigraph_db::FindAgentResult {
    let v = viewer(pool, who).await;
    let mut read = scoped.read_as(&v).await.expect("read_as");
    let q = epigraph_db::FindAgentQuery::new(q, kind, None, Some(25)).expect("query");
    epigraph_db::AgentLookupRepository::find(&mut read, &v, &q)
        .await
        .expect("find")
}

/// T1, rows A2 / A3: an outsider's and the guest's card of an unnamed human
/// equal their card of N modulo id and timestamp, the bound LLM agent's
/// `operator_human` shows H's id with no name; a teammate sees the name
/// (CALIBRATION).
#[sqlx::test(migrations = "../../migrations")]
async fn an_unnamed_humans_card_is_a_nameless_agents_card(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (h, n) = h_and_n(&pool, "Rosalind Quell").await;
    let (outsider, _) = named(&pool, "Rosalind Outsider").await;
    let (mate, _) = named(&pool, "Rosalind Teammate").await;
    keyed_team(&pool, &[h, mate]).await;
    // H is a registered operator too (registration is in play), and
    // operates an agent: the reverse binding is human evidence.
    sqlx::query("INSERT INTO human_operators (agent_id, reason) VALUES ($1, 'fixture')")
        .bind(h)
        .execute(&pool)
        .await
        .expect("register H");
    let (bot, _) = named(&pool, "quell-bot").await;
    link(&pool, bot, h).await;

    let (ph, pn) = (
        placeholder_of(&pool, h).await,
        placeholder_of(&pool, n).await,
    );
    for who in [Some(outsider), None] {
        let c = cards_by(&pool, &scoped, who, &[h, n, bot]).await;
        assert_eq!(
            c[0].display_name.as_deref(),
            Some(ph.as_str()),
            "{who:?}: C7, H is shown under its own placeholder"
        );
        assert_eq!(
            card_shape(&c[0], &ph),
            card_shape(&c[1], &pn),
            "{who:?}: H reads as N"
        );
        let oh = c[2].operator_human.as_ref().expect("bot's human id shown");
        assert_eq!(
            (oh.id, oh.display_name.as_deref()),
            (h, Some(ph.as_str())),
            "{who:?}: the bot's human is shown under the placeholder too"
        );
    }
    let c = cards_by(&pool, &scoped, Some(mate), &[h, bot]).await;
    assert_eq!(
        c[0].display_name.as_deref(),
        Some("Rosalind Quell"),
        "CALIBRATION"
    );
    assert_eq!(c[0].kind, epigraph_db::AgentKind::Human, "CALIBRATION");
    assert_eq!(
        c[1].operator_human
            .as_ref()
            .and_then(|h| h.display_name.as_deref()),
        Some("Rosalind Quell")
    );
}

/// T1, row A2, the pending count (review findings leaks#2 / correctness#2):
/// an ingester may name ANY agent as a document's author
/// (`check_explicit_author_ids` has no human gate), so a pending authorship
/// is the ingester's word, not human evidence. An outsider's cards of an
/// unnamed H and of N carrying the SAME pending `authored` edge (from the
/// same stranger, on papers of the same shape) are byte-identical modulo id,
/// counts included: `pending_authored_papers` is 1 on both and `capped`
/// agrees. The first cut zeroed it for an unnamed human only, so `0` marked
/// exactly the hidden humans; that mutant fails the equality here.
#[sqlx::test(migrations = "../../migrations")]
async fn a_pending_naming_reads_the_same_on_an_unnamed_human_and_a_nameless_agent(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (h, n) = h_and_n(&pool, "Ottoline Pendle").await;
    let (outsider, _) = named(&pool, "Pendle Outsider").await;
    let (stranger, _) = named(&pool, "Pendle Ingester").await;
    for (who, doi) in [(h, "10.9999/hiv.pending.h"), (n, "10.9999/hiv.pending.n")] {
        let paper = Uuid::new_v4();
        sqlx::query("INSERT INTO papers (id, doi, title) VALUES ($1, $2, 'A Fixture Paper')")
            .bind(paper)
            .bind(doi)
            .execute(&pool)
            .await
            .expect("paper");
        let v = viewer(&pool, stranger).await;
        let mut tx = scoped.begin_as(&v).await.expect("stamped tx");
        epigraph_db::create_ingest_written_edge_if_absent_conn(
            &mut tx,
            None,
            "ingest_document",
            stranger,
            who,
            "agent",
            paper,
            "paper",
            "authored",
            Some(serde_json::json!({
                "position": 0,
                "role": "author",
                "explicit_agent_id": true,
                "pending_countersign": true,
                "ingested_by": stranger.to_string(),
            })),
        )
        .await
        .expect("pending authored edge");
        tx.commit().await.expect("commit");
    }
    let c = cards_by(&pool, &scoped, Some(outsider), &[h, n]).await;
    assert_eq!(
        (
            c[0].counts.pending_authored_papers,
            c[1].counts.pending_authored_papers
        ),
        (1, 1),
        "CALIBRATION: both carry one pending naming: {:?} / {:?}",
        c[0].counts,
        c[1].counts
    );
    let (ph, pn) = (
        placeholder_of(&pool, h).await,
        placeholder_of(&pool, n).await,
    );
    assert_eq!(
        c[0].display_name.as_deref(),
        Some(ph.as_str()),
        "CALIBRATION: H is unnamed to the outsider"
    );
    assert_eq!(
        card_shape(&c[0], &ph),
        card_shape(&c[1], &pn),
        "H with a pending naming reads as N with the same pending naming"
    );
}

/// T1, row A1: an unnamed human is never FOUND, by exact name, prefix,
/// trigram or ORCID, and a kind filter does not surface it; a teammate finds
/// it (CALIBRATION). ORCID is matched only on `details`.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unnamed_human_is_never_found_by_name_or_identifier(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (h, _n) = h_and_n(&pool, "Rosalind Quell").await;
    sqlx::query("UPDATE agents SET orcid = '0000-0002-0000-0099' WHERE id = $1")
        .bind(h)
        .execute(&pool)
        .await
        .expect("orcid");
    let (outsider, _) = named(&pool, "someone else").await;
    let (mate, _) = named(&pool, "a teammate").await;
    keyed_team(&pool, &[h, mate]).await;
    for q in [
        "Rosalind Quell",
        "rosalind",
        "Rosalnd Quell",
        "0000-0002-0000-0099",
    ] {
        let r = find_by(&pool, &scoped, outsider, q, None).await;
        assert!(
            r.results.iter().all(|x| x.card.id != h),
            "{q}: an outsider found the unnamed human"
        );
        let r = find_by(&pool, &scoped, mate, q, None).await;
        assert!(
            r.results.iter().any(|x| x.card.id == h),
            "{q}: CALIBRATION, a teammate finds H"
        );
    }
}

/// Operator ruling C7, row A1: a nameless service principal is FOUND by its
/// `oauth:<client row id>` name (exact and prefix), so an unnamed human must
/// be found by its own placeholder the same way, with the same tier, score
/// and shown name (modulo the client row id), and still never by its real
/// name. A teammate, to whom H is named, finds H by its real name and not by
/// the placeholder (CALIBRATION: the placeholder row is the unnamed reading
/// only). The ingest's same-name candidates list H under its placeholder as
/// they list N under N's.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unnamed_human_is_found_by_its_placeholder_as_a_service_principal_is(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (h, n) = h_and_n(&pool, "Severine Placeheld").await;
    let (outsider, _) = named(&pool, "someone else").await;
    let (mate, _) = named(&pool, "a teammate").await;
    keyed_team(&pool, &[h, mate]).await;
    let (ph, pn) = (
        placeholder_of(&pool, h).await,
        placeholder_of(&pool, n).await,
    );
    let hit_shape = |r: &epigraph_db::FindAgentResult, id: Uuid, p: &str| {
        // The trigram score of a prefix depends on the uuid's own letters, for
        // N as for H, so it is not compared; the tier and the card are.
        r.results.iter().find(|x| x.card.id == id).map(|x| {
            (
                serde_json::to_value(x.tier).expect("tier"),
                card_shape(&x.card, p),
            )
        })
    };
    // exact: the whole placeholder; prefix: `oauth:` and the first 13 chars
    // of the client row id.
    for (qh, qn) in [
        (ph.clone(), pn.clone()),
        (ph[..19].to_string(), pn[..19].to_string()),
    ] {
        let rh = find_by(&pool, &scoped, outsider, &qh, None).await;
        let rn = find_by(&pool, &scoped, outsider, &qn, None).await;
        let (sh, sn) = (hit_shape(&rh, h, &ph), hit_shape(&rn, n, &pn));
        assert!(sn.is_some(), "CALIBRATION: {qn} finds N: {rn:?}");
        assert_eq!(sh, sn, "{qh}: H is found as N is");
    }
    let r = find_by(&pool, &scoped, outsider, "Severine Placeheld", None).await;
    assert!(
        r.results.iter().all(|x| x.card.id != h),
        "never by its name"
    );
    let r = find_by(&pool, &scoped, mate, &ph, None).await;
    assert!(
        r.results.iter().all(|x| x.card.id != h),
        "CALIBRATION: a teammate reads the real name, not the placeholder"
    );
    let r = find_by(&pool, &scoped, mate, "Severine Placeheld", None).await;
    assert!(r.results.iter().any(|x| x.card.id == h), "CALIBRATION");

    let v = viewer(&pool, outsider).await;
    let mut c = scoped.read_as(&v).await.expect("read_as");
    let found = epigraph_db::AgentLookupRepository::exact_name_candidates(
        &mut c,
        &[ph.clone(), pn.clone()],
        &[Uuid::nil(), Uuid::nil()],
        10,
    )
    .await
    .expect("candidates");
    let ids = |i: usize| found[i].0.iter().map(|m| m.agent_id).collect::<Vec<_>>();
    assert_eq!(
        (ids(0), found[0].1),
        (vec![h], 1),
        "H listed under its placeholder"
    );
    assert_eq!((ids(1), found[1].1), (vec![n], 1), "as N under N's");
}

/// Operator ruling C7: the placeholder an unnamed human is shown under is
/// checkable as a service principal's is. For N, migration 285's
/// `epigraph_unnamed_agent_name` spells exactly the name `ensure_for_client`
/// stored. For H and for N, the client row id inside the name derives the
/// agent's public key (`blake3::derive_key("epigraph-oauth-client", ..)`, the
/// derivation `ensure_for_client` uses), so H's placeholder names its
/// PROVISIONING client: one a later client linked to H would fail the check.
/// A second client linked to H afterwards does not move it.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unnamed_humans_placeholder_is_its_provisioning_clients(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (h, n) = h_and_n(&pool, "Wilhelmina Derived").await;
    let stored: String = sqlx::query_scalar("SELECT display_name FROM agents WHERE id = $1")
        .bind(n)
        .fetch_one(&pool)
        .await
        .expect("N's name");
    let spelled: Option<String> =
        sqlx::query_scalar("SELECT public.epigraph_unnamed_agent_name($1)")
            .bind(n)
            .fetch_one(&pool)
            .await
            .expect("placeholder");
    assert_eq!(spelled.as_deref(), Some(stored.as_str()), "one spelling");

    // A later client linked to H (a second sign-in method, say).
    sqlx::query(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    status, agent_id, created_at) \
         VALUES ($1, 'later', 'human', ARRAY['claims:write'], 'active', $2, \
                 now() + interval '1 minute')",
    )
    .bind(format!("fixtureprovider:later-{h}"))
    .bind(h)
    .execute(&pool)
    .await
    .expect("a later client");

    let (outsider, _) = named(&pool, "someone else").await;
    let v = viewer(&pool, outsider).await;
    let mut c = scoped.read_as(&v).await.expect("read_as");
    let names = epigraph_db::AgentDisclosureRepository::names(&mut c, &[h, n])
        .await
        .expect("names");
    for id in [h, n] {
        let shown = names[&id].clone().expect("a placeholder");
        let client: Uuid = shown
            .strip_prefix("oauth:")
            .and_then(|u| u.parse().ok())
            .unwrap_or_else(|| panic!("{shown} is oauth:<uuid>"));
        let key: Vec<u8> = sqlx::query_scalar("SELECT public_key FROM agents WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("key");
        assert_eq!(
            key,
            blake3::derive_key("epigraph-oauth-client", client.as_bytes()).to_vec(),
            "{id}: the shown client derives the agent's key"
        );
    }
}

/// Rows A1 truncation (findings L6, 3): the disclosure filter runs BEFORE
/// the candidate pool is cut. Exactly `CANDIDATE_POOL` visible agents named
/// like H, plus H: the outsider's search reports `candidates_truncated:
/// false` (H takes no slot); the teammate's, which also matches H, reports
/// true (CALIBRATION).
#[sqlx::test(migrations = "../../migrations")]
async fn an_unnamed_human_takes_no_candidate_slot(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (h, _n) = h_and_n(&pool, "Decoy Target").await;
    let (outsider, _) = named(&pool, "someone else").await;
    let (mate, _) = named(&pool, "a teammate").await;
    keyed_team(&pool, &[h, mate]).await;
    sqlx::query(
        "INSERT INTO agents (public_key, display_name) \
         SELECT pg_catalog.decode(pg_catalog.md5(g::text || 'a') || pg_catalog.md5(g::text || 'b'), \
                                  'hex'), 'Decoy Target' \
           FROM pg_catalog.generate_series(1, $1::int) g",
    )
    .bind(i32::try_from(epigraph_db::agent_lookup::CANDIDATE_POOL).expect("pool"))
    .execute(&pool)
    .await
    .expect("decoys");
    let r = find_by(&pool, &scoped, outsider, "Decoy Target", None).await;
    assert!(
        !r.candidates_truncated,
        "H moved the outsider's truncation flag"
    );
    assert!(r.results.iter().all(|x| x.card.id != h));
    let r = find_by(&pool, &scoped, mate, "Decoy Target", None).await;
    assert!(
        r.candidates_truncated,
        "CALIBRATION: H is a 201st match to a teammate"
    );
}

/// Row A4: the ingest's same-name candidates neither list nor count an
/// unnamed human; a teammate's do (CALIBRATION).
#[sqlx::test(migrations = "../../migrations")]
async fn same_name_candidates_neither_list_nor_count_an_unnamed_human(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (h, _n) = h_and_n(&pool, "Twin Name").await;
    let (other, _) = named(&pool, "Twin Name").await;
    let (outsider, _) = named(&pool, "someone else").await;
    let (mate, _) = named(&pool, "a teammate").await;
    keyed_team(&pool, &[h, mate]).await;
    let names = vec!["Twin Name".to_string()];
    let attached = vec![Uuid::nil()];
    let read = |who: Uuid| {
        let pool = pool.clone();
        let scoped = &scoped;
        let names = names.clone();
        let attached = attached.clone();
        async move {
            let v = viewer(&pool, who).await;
            let mut c = scoped.read_as(&v).await.expect("read_as");
            epigraph_db::AgentLookupRepository::exact_name_candidates(&mut c, &names, &attached, 10)
                .await
                .expect("candidates")
                .remove(0)
        }
    };
    let (list, total) = read(outsider).await;
    assert_eq!(
        list.iter().map(|m| m.agent_id).collect::<Vec<_>>(),
        vec![other]
    );
    assert_eq!(total, 1, "the hidden match is not counted");
    let (list, total) = read(mate).await;
    assert_eq!(total, 2, "CALIBRATION");
    assert!(list.iter().any(|m| m.agent_id == h));
}

/// Row A5: the ingest's explicit-author report names an unnamed human under
/// its `oauth:<client row id>` placeholder (operator ruling C7); the
/// internal checks are unchanged.
#[sqlx::test(migrations = "../../migrations")]
async fn an_explicit_authors_reported_name_follows_the_rule(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (h, _n) = h_and_n(&pool, "Ines Explicit").await;
    let (outsider, _) = named(&pool, "someone else").await;
    let v = viewer(&pool, outsider).await;
    let mut c = scoped.read_as(&v).await.expect("read_as");
    let nodes = epigraph_db::AgentLookupRepository::author_nodes(&mut c, &[h])
        .await
        .expect("author_nodes");
    assert_eq!(nodes.len(), 1, "the node is still returned");
    assert_eq!(
        nodes[0].display_name,
        Some(placeholder_of(&pool, h).await),
        "C7: reported under its placeholder"
    );
    drop(c);
    let v = viewer(&pool, h).await;
    let mut c = scoped.read_as(&v).await.expect("read_as");
    let nodes = epigraph_db::AgentLookupRepository::author_nodes(&mut c, &[h])
        .await
        .expect("author_nodes");
    assert_eq!(
        nodes[0].display_name.as_deref(),
        Some("Ines Explicit"),
        "CALIBRATION"
    );
}

/// The A1 placement, measured: the disclosure predicate runs once per RAW
/// name match, never once per agent in the table (findings L6, 3; advisor
/// row-count trap). Counted with `track_functions = 'all'` in the reading
/// transaction (`pg_stat_xact_user_functions`).
#[sqlx::test(migrations = "../../migrations")]
async fn the_name_match_calls_the_predicate_once_per_match(pool: PgPool) {
    let db: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&pool)
        .await
        .expect("db");
    sqlx::query(&format!(
        "ALTER DATABASE \"{db}\" SET track_functions = 'all'"
    ))
    .execute(&pool)
    .await
    .expect("track_functions");
    // 300 unrelated agents and 4 that match.
    sqlx::query(
        "INSERT INTO agents (public_key, display_name) \
         SELECT pg_catalog.decode(pg_catalog.md5(g::text || 'x') || pg_catalog.md5(g::text || 'y'), \
                                  'hex'), 'unrelated ' || g \
           FROM pg_catalog.generate_series(1, 300) g",
    )
    .execute(&pool)
    .await
    .expect("population");
    for _ in 0..4 {
        named(&pool, "Quillon Probe").await;
    }
    let (asker, _) = named(&pool, "asker").await;
    let scoped = app_pool(&pool).await;
    let v = viewer(&pool, asker).await;
    let mut c = scoped.read_as(&v).await.expect("read_as");
    sqlx::query("BEGIN").execute(&mut *c).await.expect("begin");
    let tracked: String = sqlx::query_scalar("SHOW track_functions")
        .fetch_one(&mut *c)
        .await
        .expect("show");
    assert_eq!(tracked, "all", "CALIBRATION: calls are counted");
    let found = epigraph_db::AgentLookupRepository::match_by_name(&mut c, "Quillon Probe", 50)
        .await
        .expect("match");
    assert_eq!(found.len(), 4, "CALIBRATION: the four match");
    let calls: i64 = sqlx::query_scalar(
        "SELECT COALESCE(sum(calls), 0)::bigint FROM pg_stat_xact_user_functions \
          WHERE funcname = 'epigraph_agent_disclosure'",
    )
    .fetch_one(&mut *c)
    .await
    .expect("calls");
    sqlx::query("ROLLBACK")
        .execute(&mut *c)
        .await
        .expect("rollback");
    assert!(
        (4..=8).contains(&calls),
        "the predicate ran {calls} times for 4 matches over 300+ agents: it was pushed into \
         the agents scan"
    );
}

/// T1, row B1: `get_public_profile` of an unnamed human, to an outsider,
/// equals N's (a production-shaped nameless service principal) apart from id,
/// key and the client row id in the placeholder: the placeholder name, key
/// kind `derived`, a `'public'` profile with N's empty properties and no
/// ORCID / ROR (operator ruling C7), whatever H's row holds. A teammate sees
/// the name (CALIBRATION).
#[sqlx::test(migrations = "../../migrations")]
async fn an_unnamed_humans_public_profile_is_a_nameless_agents(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (h, n) = h_and_n(&pool, "Odette Profiled").await;
    sqlx::query(
        "UPDATE agents SET properties = '{\"full_name\": \"Odette Profiled\"}'::jsonb, \
                orcid = '0000-0002-0000-0077' WHERE id = $1",
    )
    .bind(h)
    .execute(&pool)
    .await
    .expect("details");
    let (outsider, _) = named(&pool, "someone else").await;
    let (mate, _) = named(&pool, "a teammate").await;
    keyed_team(&pool, &[h, mate]).await;
    let profile = |who: Uuid, id: Uuid| {
        let pool = pool.clone();
        let scoped = &scoped;
        async move {
            let v = viewer(&pool, who).await;
            let mut c = scoped.read_as(&v).await.expect("read_as");
            epigraph_db::AgentRepository::get_public_profile(&mut *c, id)
                .await
                .expect("profile")
                .expect("exists")
        }
    };
    let (ph, pn) = (
        placeholder_of(&pool, h).await,
        placeholder_of(&pool, n).await,
    );
    let shape = |p: epigraph_db::repos::agent::AgentPublicProfile| {
        (
            p.display_name.map(|x| {
                x.replace(&ph, "oauth:<client>")
                    .replace(&pn, "oauth:<client>")
            }),
            p.key_kind,
            p.profile_visibility,
            p.properties,
            p.orcid,
            p.ror_id,
        )
    };
    let theirs = profile(outsider, n).await;
    assert_eq!(
        (
            theirs.profile_visibility.as_deref(),
            theirs.properties.clone()
        ),
        (Some("public"), Some(serde_json::json!({}))),
        "CALIBRATION: N is a minted service principal"
    );
    assert_eq!(
        shape(profile(outsider, h).await),
        shape(theirs),
        "H's profile reads as N's"
    );
    let mine = profile(mate, h).await;
    assert_eq!(
        mine.display_name.as_deref(),
        Some("Odette Profiled"),
        "CALIBRATION"
    );
    assert_eq!(
        mine.orcid.as_deref(),
        Some("0000-0002-0000-0077"),
        "a teammate shares a live group with H, the profile rule's group arm"
    );
}

/// T1, row H1: the ego hydration labels an unnamed human exactly as it
/// labels a nameless service principal (under the `oauth:` placeholder,
/// operator ruling C7), and a teammate's with the name (CALIBRATION).
#[sqlx::test(migrations = "../../migrations")]
async fn the_ego_view_labels_an_unnamed_human_as_a_nameless_agent(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (h, n) = h_and_n(&pool, "Theodora Egoless").await;
    let (outsider, _) = named(&pool, "someone else").await;
    let (mate, _) = named(&pool, "a teammate").await;
    keyed_team(&pool, &[h, mate]).await;
    let hydrate = |who: Uuid| {
        let pool = pool.clone();
        let scoped = &scoped;
        async move {
            let v = viewer(&pool, who).await;
            let mut c = scoped.read_as(&v).await.expect("read_as");
            epigraph_db::EgoRepository::hydrate(&mut c, &v, &[h, n])
                .await
                .expect("hydrate")
        }
    };
    let out = hydrate(outsider).await;
    let (ph, pn) = (
        placeholder_of(&pool, h).await,
        placeholder_of(&pool, n).await,
    );
    let label = |id: Uuid, list: &[epigraph_db::EgoEntity]| {
        let e = list.iter().find(|e| e.id == id).expect("hydrated");
        (
            e.entity_type.clone(),
            e.label
                .replace(&ph, "oauth:<client>")
                .replace(&pn, "oauth:<client>")
                .replace(&id.to_string()[..8], "<id>"),
        )
    };
    assert_eq!(label(h, &out), label(n, &out), "H's ego node reads as N's");
    let mine = hydrate(mate).await;
    assert_eq!(label(h, &mine).1, "Theodora Egoless", "CALIBRATION");
}

// ─── T3: the team arm through a ROLE-derived membership (165 / 249) ──────

async fn seed_role(pool: &PgPool, key: &str) {
    let node = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, display_name, agent_type, role, labels) \
         VALUES ($1, uuid_send(gen_random_uuid()) || uuid_send(gen_random_uuid()), $2, 'role', \
                 'custom', ARRAY['role'])",
    )
    .bind(node)
    .bind(key)
    .execute(pool)
    .await
    .expect("role node");
    sqlx::query(
        "INSERT INTO platform_roles (key, elevates, reads_audit, role_node_id, description) \
         VALUES ($1, false, false, $2, 'visibility test role')",
    )
    .bind(key)
    .bind(node)
    .execute(pool)
    .await
    .expect("platform role");
}

async fn grant_role(pool: &PgPool, role: &str, holder: Uuid) {
    let _: Uuid = sqlx::query_scalar(
        "SELECT public.epigraph_grant_role($1, $2, now() - interval '5 seconds', NULL, NULL, \
                'visibility test grant')",
    )
    .bind(role)
    .bind(holder)
    .fetch_one(pool)
    .await
    .expect("grant role");
}

async fn bind_role(pool: &PgPool, group: Uuid, role: &str) {
    sqlx::query(
        "INSERT INTO group_role_bindings (group_id, role, member_role, include_agents, reason) \
         VALUES ($1, $2, 'reader', false, 'visibility test binding')",
    )
    .bind(group)
    .bind(role)
    .execute(pool)
    .await
    .expect("group role binding");
}

/// T3 (spec 12): a teammate through a ROLE is a teammate, in both
/// directions. H holds role X bound to team G and V is a direct member of G:
/// H is named to V. Mirror: H is a direct member of G2 and V holds role Y
/// bound to G2 (V's resolved viewer carries G2): named. CALIBRATION: before
/// the grants neither sees H. This is the path migration 277 reaches without
/// 236's twin (the role derivation is consulted only for a bound group).
#[sqlx::test(migrations = "../../migrations")]
async fn a_role_derived_teammate_sees_the_human_in_both_directions(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (h, _) = human(&pool, "Rosamund Roleheld").await;
    let (v, _) = named(&pool, "Role Reader").await;
    seed_role(&pool, "role:hiv-test-x").await;
    seed_role(&pool, "role:hiv-test-y").await;

    // Direction 1: H's side is role-derived.
    let g = keyed_team(&pool, &[v]).await;
    bind_role(&pool, g, "role:hiv-test-x").await;
    assert!(
        !named_to(&pool, &scoped, v, h).await,
        "CALIBRATION: no grant yet, no arm"
    );
    grant_role(&pool, "role:hiv-test-x", h).await;
    assert!(
        named_to(&pool, &scoped, v, h).await,
        "H holds the role bound to V's team: a teammate"
    );

    // Direction 2: V's side is role-derived.
    let (h2, _) = human(&pool, "Rosamund Direct").await;
    let (v2, _) = named(&pool, "Role Holder Reader").await;
    fixture::make_human_operator(&pool, v2).await;
    let g2 = keyed_team(&pool, &[h2]).await;
    bind_role(&pool, g2, "role:hiv-test-y").await;
    assert!(
        !named_to(&pool, &scoped, v2, h2).await,
        "CALIBRATION: no grant yet"
    );
    grant_role(&pool, "role:hiv-test-y", v2).await;
    assert!(
        viewer(&pool, v2)
            .await
            .group_bind()
            .is_some_and(|gs| gs.contains(&g2)),
        "CALIBRATION: the role-derived group is in V's resolved set"
    );
    assert!(
        named_to(&pool, &scoped, v2, h2).await,
        "V holds the role bound to H's team: a teammate"
    );
}

/// Migration 279's cheap role probe (review finding correctness#3 option
/// (b)) answers exactly as 249's `epigraph_role_derived_memberships` does,
/// for targets no other arm names: a live binding, a binding whose
/// revocation is FUTURE-dated (still live now), a binding revoked in the
/// past, a target linked as another human's agent (the fallback to 249,
/// which admits it through an `include_agents` binding of its operator's
/// role), and a target holding a 149 allowance (the same fallback). Each
/// reference answer is computed from 249's function itself, and the cases
/// that only the fallback can name are calibrated true, so the equivalence
/// cannot pass by both sides answering false.
#[sqlx::test(migrations = "../../migrations")]
async fn the_cheap_role_probe_answers_as_249_does(pool: PgPool) {
    async fn bind_with(
        pool: &PgPool,
        group: Uuid,
        role: &str,
        agents: bool,
        revoked: Option<&str>,
    ) {
        let mut c = pool.acquire().await.expect("acquire");
        if revoked.is_some() {
            sqlx::query("SET session_replication_role = replica")
                .execute(&mut *c)
                .await
                .expect("replica");
        }
        sqlx::query(&format!(
            "INSERT INTO group_role_bindings (group_id, role, member_role, include_agents, \
                                              reason, revoked_at, revoked_by, revoked_reason) \
             VALUES ($1, $2, 'reader', $3, 'equivalence fixture', {}, {}, {})",
            revoked.map_or("NULL".to_string(), |r| format!("now() + interval '{r}'")),
            if revoked.is_some() {
                "'fixture'"
            } else {
                "NULL"
            },
            if revoked.is_some() {
                "'fixture end'"
            } else {
                "NULL"
            },
        ))
        .bind(group)
        .bind(role)
        .bind(agents)
        .execute(&mut *c)
        .await
        .expect("binding");
        sqlx::query("SET session_replication_role = origin")
            .execute(&mut *c)
            .await
            .expect("origin");
    }
    async fn reference(pool: &PgPool, target: Uuid, groups: &[Uuid]) -> bool {
        sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM public.epigraph_role_derived_memberships($1, now()) d \
                              JOIN groups g ON g.id = d.group_id \
                             WHERE d.group_id = ANY ($2) \
                               AND g.kind IN ('team', 'community') AND g.status = 'active')",
        )
        .bind(target)
        .bind(groups)
        .fetch_one(pool)
        .await
        .expect("249 reference")
    }
    async fn core(pool: &PgPool, target: Uuid, groups: &[Uuid]) -> bool {
        sqlx::query_scalar(
            "SELECT named FROM public.epigraph_agent_disclosure_for($1, NULL, $2, false)",
        )
        .bind(target)
        .bind(groups)
        .fetch_one(pool)
        .await
        .expect("core")
    }
    let (v, _) = named(&pool, "Equivalence Reader").await;
    for r in ["a", "b", "c", "d", "e"] {
        seed_role(&pool, &format!("role:hiv-eq-{r}")).await;
    }
    let mut cases: Vec<(&str, Uuid, Uuid, Option<bool>)> = Vec::new();

    // A: H holds a role live-bound to G.
    let (ha, _) = human(&pool, "Equivalence Live").await;
    let ga = keyed_team(&pool, &[v]).await;
    bind_with(&pool, ga, "role:hiv-eq-a", false, None).await;
    grant_role(&pool, "role:hiv-eq-a", ha).await;
    cases.push(("live binding", ha, ga, Some(true)));

    // B: the binding's revocation is future-dated: live now.
    let (hb, _) = human(&pool, "Equivalence Future").await;
    let gb = keyed_team(&pool, &[v]).await;
    grant_role(&pool, "role:hiv-eq-b", hb).await;
    bind_with(&pool, gb, "role:hiv-eq-b", false, Some("1 hour")).await;
    cases.push(("future-dated revocation", hb, gb, Some(true)));

    // C: the binding was revoked in the past.
    let (hc, _) = human(&pool, "Equivalence Past").await;
    let gc = keyed_team(&pool, &[v]).await;
    grant_role(&pool, "role:hiv-eq-c", hc).await;
    bind_with(&pool, gc, "role:hiv-eq-c", false, Some("-1 hour")).await;
    cases.push(("past revocation", hc, gc, Some(false)));

    // D: a human principal linked as the agent of O, who holds a role bound
    // with include_agents: only 249's via-agent candidate admits it.
    let (od, _) = human(&pool, "Equivalence Operator D").await;
    let (td, _) = client_only_human(&pool, "Equivalence Linked").await;
    set_profile(&pool, td, "group").await;
    link(&pool, td, od).await;
    let gd = keyed_team(&pool, &[v]).await;
    bind_with(&pool, gd, "role:hiv-eq-d", true, None).await;
    grant_role(&pool, "role:hiv-eq-d", od).await;
    cases.push(("linked as an agent", td, gd, None));

    // E: a person whose human client was REVOKED (still a human principal:
    // the evidence is structural, 272) and who holds a live service client
    // allowlisted to O2 (149 admits no second non-revoked client), whose role
    // is bound with include_agents.
    let (oe, _) = human(&pool, "Equivalence Operator E").await;
    let (te, _) = allowance_bound(&pool, oe, "Equivalence Allowed").await;
    sqlx::query(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    status, agent_id) \
         VALUES ($1, 'Equivalence Allowed', 'human', ARRAY['claims:write'], 'revoked', $2)",
    )
    .bind(format!("fixture-provider:{te}"))
    .bind(te)
    .execute(&pool)
    .await
    .expect("human client");
    set_profile(&pool, te, "group").await;
    let ge = keyed_team(&pool, &[v]).await;
    bind_with(&pool, ge, "role:hiv-eq-e", true, None).await;
    grant_role(&pool, "role:hiv-eq-e", oe).await;
    cases.push(("allowance holder", te, ge, None));

    let mut fallback_named = Vec::new();
    for (label, target, group, want) in cases {
        let is_human: bool = sqlx::query_scalar("SELECT public.epigraph_is_human_principal($1)")
            .bind(target)
            .fetch_one(&pool)
            .await
            .expect("evidence");
        assert!(
            is_human,
            "CALIBRATION ({label}): the target is a human principal"
        );
        let r = reference(&pool, target, &[group]).await;
        if let Some(w) = want {
            assert_eq!(r, w, "CALIBRATION ({label}): 249's answer");
        } else if r {
            fallback_named.push(label);
        }
        assert_eq!(
            core(&pool, target, &[group]).await,
            r,
            "{label}: the core's role arm disagrees with 249"
        );
        assert!(
            !core(&pool, target, &[]).await,
            "CALIBRATION ({label}): no other arm names the target"
        );
    }
    assert_eq!(
        fallback_named,
        vec!["linked as an agent", "allowance holder"],
        "CALIBRATION: both fallback targets are named by 249's via-agent candidate"
    );
}
