//! Performance measurement of migration 272's disclosure predicate (spec
//! `docs/superpowers/specs/2026-11-24-human-identity-visibility-design.md`,
//! section 11). `#[ignore]`d: it bulk-loads millions of rows. Run it on a
//! throwaway test database only:
//!
//! ```text
//! cargo test -p epigraph-db --test human_identity_visibility_perf -- --ignored --nocapture
//! ```
//!
//! Shape (section 11): one human H with 1,500 bound agents (operator links)
//! that filed 150,000 group claims in a group the viewer does not read, and no
//! public claim (the worst case: every arm runs and misses); (a) the viewer's
//! own group holds 1,000,000 non-public claims by another agent; (b)
//! 1,000,000 public claims by another agent; (c) skewed `operator_links`:
//! 10,000 operators with one link each beside H's 1,500; (d) the viewer holds
//! 30 groups.
//!
//! What it prints, for the spec's performance section:
//! * the GENERIC plans (`plan_cache_mode = force_generic_plan`, six
//!   executions) of the core's body statements, run under
//!   `SET ROLE epigraph_maintenance` (the core's owner, so the FORCEd row
//!   policies apply exactly as in the definer frame);
//! * p50 / max wall time of the core per human evaluation (worst case, and
//!   with one public claim by the LAST bound agent) and per non-human
//!   evaluation, including one local round trip;
//! * call counts (`track_functions = 'all'`) for a 200-card read and a
//!   two-character-prefix name search;
//! * the insert cost of the two partial indexes (275, 276).
//!
//! It asserts only the pass conditions it can state exactly: each probe plan
//! uses the per-agent partial index and no plan scans a whole `claims`
//! partition sequentially. The time budget is reported, not asserted (a
//! shared CI host's timing is not a measurement).

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::pool::{ScopedPool, SessionGucMode};
use epigraph_db::visibility::Viewer;
use sqlx::{Executor, PgPool};
use std::time::Instant;
use uuid::Uuid;

const BOUND: i64 = 1_500;
const H_CLAIMS: i64 = 150_000;
const OTHER_GROUP_CLAIMS: i64 = 1_000_000;
const OTHER_PUBLIC_CLAIMS: i64 = 1_000_000;
const SKEW_OPERATORS: i64 = 10_000;
const VIEWER_GROUPS: i64 = 30;

fn key_sql(seed: &str) -> String {
    format!(
        "pg_catalog.decode(pg_catalog.md5({seed} || 'k1') || pg_catalog.md5({seed} || 'k2'), \
         'hex')"
    )
}

async fn exec(conn: &mut sqlx::PgConnection, sql: &str) {
    conn.execute(sql)
        .await
        .unwrap_or_else(|e| panic!("{sql}: {e}"));
}

async fn team(conn: &mut sqlx::PgConnection, label: &str) -> Uuid {
    let id = Uuid::new_v4();
    let key: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO groups (id, display_name, did_key, public_key, kind) \
         VALUES ($1, $2, 'did:key:perf-' || $1::text, $3, 'team')",
    )
    .bind(id)
    .bind(label)
    .bind(&key)
    .execute(&mut *conn)
    .await
    .expect("team");
    id
}

/// `((p50, max) ms, named)` of `n` core evaluations of `target` for viewer
/// `v` with `groups`, as the core's owner.
async fn time_core(
    pool: &PgPool,
    target: Uuid,
    v: Uuid,
    groups: &[Uuid],
    n: usize,
) -> ((f64, f64), bool) {
    let mut c = pool.acquire().await.expect("conn");
    exec(&mut c, "SET ROLE epigraph_maintenance").await;
    let mut samples = Vec::new();
    let mut named = None;
    for _ in 0..n {
        let t = Instant::now();
        let r: bool = sqlx::query_scalar(
            "SELECT named FROM public.epigraph_agent_disclosure_for($1, $2, $3, false)",
        )
        .bind(target)
        .bind(v)
        .bind(groups)
        .fetch_one(&mut *c)
        .await
        .expect("core");
        samples.push(t.elapsed().as_secs_f64() * 1000.0);
        named = Some(r);
    }
    exec(&mut c, "RESET ROLE").await;
    (pct(samples), named.expect("ran"))
}

fn pct(mut v: Vec<f64>) -> (f64, f64) {
    v.sort_by(f64::total_cmp);
    (v[v.len() / 2], *v.last().expect("samples"))
}

async fn generic_plan(conn: &mut sqlx::PgConnection, label: &str, execute: &str) -> String {
    let mut last = String::new();
    for _ in 0..6 {
        let rows: Vec<(String,)> =
            sqlx::query_as(&format!("EXPLAIN (ANALYZE, BUFFERS, COSTS OFF) {execute}"))
                .fetch_all(&mut *conn)
                .await
                .unwrap_or_else(|e| panic!("{label}: {e}"));
        last = rows.into_iter().map(|r| r.0).collect::<Vec<_>>().join("\n");
    }
    println!("\n=== generic plan: {label} ===\n{last}");
    last
}

#[sqlx::test(migrations = "../../migrations")]
#[ignore = "bulk-loads ~2.2M claims; run on a throwaway database with --ignored --nocapture"]
async fn measure_the_disclosure_predicate(pool: PgPool) {
    let mut c = pool.acquire().await.expect("conn");
    let t0 = Instant::now();
    exec(&mut c, "SET session_replication_role = replica").await;

    // H: a provider-provisioned person (human client evidence), profile group.
    let h = Uuid::new_v4();
    sqlx::query(&format!(
        "INSERT INTO agents (id, public_key, display_name, profile_visibility) \
         VALUES ($1, {}, 'Perf Human', 'group')",
        key_sql("'perf-human'")
    ))
    .bind(h)
    .execute(&mut *c)
    .await
    .expect("H");
    sqlx::query(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    status, agent_id) \
         VALUES ('perfprovider:h', 'Perf Human', 'human', ARRAY['claims:write'], 'active', $1)",
    )
    .bind(h)
    .execute(&mut *c)
    .await
    .expect("H client");
    let h_group = team(&mut c, "perf H group").await;

    // 1,500 bound agents, named so a two-character prefix matches them all.
    sqlx::query(&format!(
        "INSERT INTO agents (id, public_key, display_name) \
         SELECT gen_random_uuid(), {}, 'perf agent ' || g \
           FROM pg_catalog.generate_series(1, $1) g",
        key_sql("'bound' || g::text")
    ))
    .bind(BOUND)
    .execute(&mut *c)
    .await
    .expect("bound agents");
    sqlx::query(
        "INSERT INTO operator_links (agent_id, operator_id, operator_group_id) \
         SELECT a.id, $1, $2 FROM agents a WHERE a.display_name LIKE 'perf agent %'",
    )
    .bind(h)
    .bind(h_group)
    .execute(&mut *c)
    .await
    .expect("links");

    // 150k group claims by the bound agents, in H's group.
    sqlx::query(&format!(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         SELECT gen_random_uuid(), 'h claim ' || g, {}, 0.5, \
                (SELECT array_agg(id) FROM agents \
                  WHERE display_name LIKE 'perf agent %')[1 + (g % $2)::int], \
                true, 'group', $3 \
           FROM pg_catalog.generate_series(1, $1) g",
        key_sql("'hc' || g::text")
    ))
    .bind(H_CLAIMS)
    .bind(BOUND)
    .bind(h_group)
    .execute(&mut *c)
    .await
    .expect("H's claims");

    // The viewer, its 30 groups, and (a) / (b) by other agents.
    let (v, _) = fixture::seed_agent_with_group(&pool, "perf viewer").await;
    let mut groups = Vec::new();
    for i in 0..VIEWER_GROUPS {
        let g = team(&mut c, &format!("perf viewer group {i}")).await;
        sqlx::query(
            "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
             VALUES ($1, $2, ''::bytea, 0, 'writer')",
        )
        .bind(g)
        .bind(v)
        .execute(&mut *c)
        .await
        .expect("viewer membership");
        groups.push(g);
    }
    let other = Uuid::new_v4();
    sqlx::query(&format!(
        "INSERT INTO agents (id, public_key, display_name) VALUES ($1, {}, 'perf other')",
        key_sql("'other'")
    ))
    .bind(other)
    .execute(&mut *c)
    .await
    .expect("other");
    let world = fixture::world_group(&pool).await;
    for (n, vis, owner, tag) in [
        (OTHER_GROUP_CLAIMS, "group", groups[0], "og"),
        (OTHER_PUBLIC_CLAIMS, "public", world, "op"),
    ] {
        sqlx::query(&format!(
            "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, \
                                 is_current, visibility, owner_group_id) \
             SELECT gen_random_uuid(), '{tag} ' || g, {}, 0.5, $2, true, $3, $4 \
               FROM pg_catalog.generate_series(1, $1) g",
            key_sql(&format!("'{tag}' || g::text"))
        ))
        .bind(n)
        .bind(other)
        .bind(vis)
        .bind(owner)
        .execute(&mut *c)
        .await
        .expect("other claims");
    }

    // (c) skewed operator_links: 10k operators with one link each.
    sqlx::query(&format!(
        "INSERT INTO agents (id, public_key, display_name) \
         SELECT gen_random_uuid(), {}, 'skew ' || g FROM pg_catalog.generate_series(1, $1 * 2) g",
        key_sql("'skew' || g::text")
    ))
    .bind(SKEW_OPERATORS)
    .execute(&mut *c)
    .await
    .expect("skew agents");
    sqlx::query(
        "INSERT INTO operator_links (agent_id, operator_id, operator_group_id) \
         SELECT b.id, o.id, $1 \
           FROM (SELECT id, row_number() OVER (ORDER BY id) rn FROM agents \
                  WHERE display_name LIKE 'skew %') o \
           JOIN (SELECT id, row_number() OVER (ORDER BY id DESC) rn FROM agents \
                  WHERE display_name LIKE 'skew %') b ON b.rn = o.rn AND b.id <> o.id \
          WHERE o.rn <= $2",
    )
    .bind(h_group)
    .bind(SKEW_OPERATORS)
    .execute(&mut *c)
    .await
    .expect("skew links");

    exec(&mut c, "SET session_replication_role = origin").await;
    exec(&mut c, "ANALYZE agents, operator_links, author_binding_clients, claims, group_memberships, groups, oauth_clients, human_operators").await;
    println!("load + analyze: {:.1}s", t0.elapsed().as_secs_f64());

    // ── generic plans of the body statements, as the definer's owner ───────
    let bound: Vec<Uuid> = sqlx::query_scalar(
        "SELECT ARRAY[$1::uuid] || ARRAY(SELECT l.agent_id FROM operator_links l \
                                           WHERE l.operator_id = $1)",
    )
    .bind(h)
    .fetch_one(&mut *c)
    .await
    .expect("bound");
    assert_eq!(
        bound.len(),
        usize::try_from(BOUND + 1).unwrap(),
        "CALIBRATION"
    );
    let arr = |ids: &[Uuid]| {
        format!(
            "ARRAY[{}]::uuid[]",
            ids.iter()
                .map(|u| format!("'{u}'"))
                .collect::<Vec<_>>()
                .join(",")
        )
    };
    exec(&mut c, "SET ROLE epigraph_maintenance").await;
    exec(&mut c, "SET plan_cache_mode = force_generic_plan").await;
    exec(
        &mut c,
        "PREPARE p_bound(uuid) AS \
           SELECT ARRAY[$1] \
               || ARRAY(SELECT l.agent_id FROM public.operator_links l WHERE l.operator_id = $1) \
               || ARRAY(SELECT r.agent_id FROM public.author_binding_clients r \
                         WHERE r.operator_id = $1)",
    )
    .await;
    exec(
        &mut c,
        "PREPARE p_public(uuid[]) AS \
           SELECT EXISTS (SELECT 1 FROM pg_catalog.unnest($1) b(agent_id) \
                          CROSS JOIN LATERAL (SELECT 1 FROM public.claims c \
                                               WHERE c.agent_id = b.agent_id \
                                                 AND c.visibility = 'public' LIMIT 1) x)",
    )
    .await;
    exec(
        &mut c,
        "PREPARE p_readable(uuid[], uuid[]) AS \
           SELECT EXISTS (SELECT 1 FROM pg_catalog.unnest($1) b(agent_id) \
                          CROSS JOIN pg_catalog.unnest($2) vg(group_id) \
                          CROSS JOIN LATERAL (SELECT 1 FROM public.claims c \
                                               WHERE c.agent_id = b.agent_id \
                                                 AND c.owner_group_id = vg.group_id \
                                                 AND c.visibility <> 'public' LIMIT 1) x)",
    )
    .await;
    exec(
        &mut c,
        "PREPARE p_team(uuid, uuid[]) AS \
           SELECT EXISTS (SELECT 1 FROM public.epigraph_live_memberships_unbound($1) m \
                            JOIN public.groups g ON g.id = m.group_id \
                           WHERE m.group_id = ANY ($2) \
                             AND g.kind IN ('team', 'community') AND g.status = 'active')",
    )
    .await;
    let b = arr(&bound);
    let gs = arr(&groups);
    let plan_bound = generic_plan(&mut c, "B(H)", &format!("EXECUTE p_bound('{h}')")).await;
    let plan_public = generic_plan(
        &mut c,
        "public-claim arm",
        &format!("EXECUTE p_public({b})"),
    )
    .await;
    let plan_readable = generic_plan(
        &mut c,
        "readable-claim arm",
        &format!("EXECUTE p_readable({b}, {gs})"),
    )
    .await;
    let plan_team = generic_plan(&mut c, "team arm", &format!("EXECUTE p_team('{h}', {gs})")).await;
    for (label, plan) in [
        ("B(H)", &plan_bound),
        ("public", &plan_public),
        ("readable", &plan_readable),
        ("team", &plan_team),
    ] {
        assert!(
            !plan.contains("Seq Scan on claims"),
            "{label}: a sequential scan of claims:\n{plan}"
        );
    }
    // Which index each probe chose is REPORTED, not asserted: the generic
    // plan's choice between 276 and `idx_claims_agent_id` moved between runs
    // of the same shape (statistics sampling), which is itself a finding.
    for (label, plan, want) in [
        ("public", &plan_public, "idx_claims_public_by_agent"),
        ("readable", &plan_readable, "idx_claims_group_by_agent"),
    ] {
        println!(
            "probe index, {label} arm: {}",
            if plan.contains(want) {
                want
            } else {
                "OTHER (see plan above)"
            }
        );
    }
    // Where the team arm's time goes: 236's twin and its parts.
    for (label, q) in [
        (
            "live_memberships_unbound",
            "SELECT count(*) FROM public.epigraph_live_memberships_unbound($1)",
        ),
        (
            "role_derived_memberships",
            "SELECT count(*) FROM public.epigraph_role_derived_memberships($1, now())",
        ),
        (
            "operator_actor",
            "SELECT count(*) FROM public.epigraph_operator_actor($1)",
        ),
        (
            "allowlisted_operator",
            "SELECT count(*) FROM public.epigraph_allowlisted_operator($1)",
        ),
        (
            "human_of",
            "SELECT count(*) FROM (SELECT public.epigraph_human_of($1, true)) x",
        ),
        (
            "is_human_principal",
            "SELECT count(*) FROM (SELECT public.epigraph_is_human_principal($1)) x",
        ),
    ] {
        let mut samples = Vec::new();
        for _ in 0..5 {
            let t = Instant::now();
            let _: i64 = sqlx::query_scalar(q)
                .bind(h)
                .fetch_one(&mut *c)
                .await
                .unwrap_or_else(|e| panic!("{label}: {e}"));
            samples.push(t.elapsed().as_secs_f64() * 1000.0);
        }
        let (p50, max) = pct(samples);
        println!("part {label}: p50 {p50:.2} ms, max {max:.2} ms");
    }
    exec(&mut c, "DEALLOCATE ALL").await;
    exec(&mut c, "RESET plan_cache_mode").await;
    exec(&mut c, "RESET ROLE").await;
    drop(c);

    // ── timings of the core, as its owner ──────────────────────────────────
    let ((p50, max), named) = time_core(&pool, h, v, &groups, 25).await;
    assert!(!named, "CALIBRATION: the worst case names nobody");
    println!("\ncore, human, no arm holds (worst case): p50 {p50:.2} ms, max {max:.2} ms");
    let ((p50n, maxn), named) = time_core(&pool, other, v, &groups, 25).await;
    assert!(named, "CALIBRATION: a non-human is named");
    println!("core, non-human: p50 {p50n:.3} ms, max {maxn:.3} ms");
    let last = *bound.last().expect("bound");
    sqlx::query(&format!(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES (gen_random_uuid(), 'the one public claim', {}, 0.5, $1, true, 'public', $2)",
        key_sql("'one-public'")
    ))
    .bind(last)
    .bind(world)
    .execute(&pool)
    .await
    .expect("one public claim");
    let ((p50p, maxp), named) = time_core(&pool, h, v, &groups, 25).await;
    assert!(named, "CALIBRATION: the public claim names H");
    println!(
        "core, human, one public claim by the last bound agent: p50 {p50p:.2} ms, max {maxp:.2} ms"
    );

    // ── call counts on the application role ───────────────────────────────
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
    let scoped = ScopedPool::connect_downgraded_for_tests(
        &fixture::database_url_for(&pool).await,
        SessionGucMode::Session,
        "epigraph_app",
    )
    .await
    .expect("app pool");
    let viewer = Viewer::resolve(&pool, v).await.expect("viewer");
    let mut read = scoped.read_as(&viewer).await.expect("read_as");
    exec(&mut read, "BEGIN").await;
    let cards: Vec<Uuid> = bound.iter().take(200).copied().collect();
    let t = Instant::now();
    let out = epigraph_db::AgentLookupRepository::cards(&mut read, &viewer, &cards)
        .await
        .expect("cards");
    let cards_ms = t.elapsed().as_secs_f64() * 1000.0;
    let n_cards: i64 = sqlx::query_scalar(
        "SELECT COALESCE(sum(calls), 0)::bigint FROM pg_stat_xact_user_functions \
          WHERE funcname = 'epigraph_agent_disclosure'",
    )
    .fetch_one(&mut *read)
    .await
    .expect("calls");
    exec(&mut read, "ROLLBACK").await;
    println!(
        "\n200-card read: {} cards in {cards_ms:.1} ms, epigraph_agent_disclosure calls {n_cards}",
        out.len()
    );
    exec(&mut read, "BEGIN").await;
    let t = Instant::now();
    let found = epigraph_db::AgentLookupRepository::match_by_name(&mut read, "pe", 200)
        .await
        .expect("match");
    let find_ms = t.elapsed().as_secs_f64() * 1000.0;
    let n_find: i64 = sqlx::query_scalar(
        "SELECT COALESCE(sum(calls), 0)::bigint FROM pg_stat_xact_user_functions \
          WHERE funcname = 'epigraph_agent_disclosure'",
    )
    .fetch_one(&mut *read)
    .await
    .expect("calls");
    let raw_matches: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM agents WHERE display_name ILIKE 'pe%' OR display_name ILIKE '% pe%'",
    )
    .fetch_one(&mut *read)
    .await
    .expect("raw");
    exec(&mut read, "ROLLBACK").await;
    println!(
        "two-character prefix 'pe': {} returned in {find_ms:.1} ms, raw name matches \
         {raw_matches}, epigraph_agent_disclosure calls {n_find}",
        found.len()
    );
    let all_agents: i64 = sqlx::query_scalar("SELECT count(*) FROM agents")
        .fetch_one(&pool)
        .await
        .expect("agents");
    println!("agents in the table: {all_agents}");
    // Per match, not per agent: well under the table (about 23k rows here).
    // The count is not exactly the raw ILIKE count: the matcher's fold and
    // trigram tiers match a little more than ILIKE, and the figure is
    // reported in the spec as measured.
    assert!(
        n_find <= 2 * raw_matches && n_find * 4 < all_agents,
        "the predicate ran per agent, not per match: {n_find} calls for {raw_matches} matches \
         over {all_agents} agents"
    );
    drop(read);

    // ── insert cost of 275 / 276 ───────────────────────────────────────────
    let mut c = pool.acquire().await.expect("conn");
    let insert = |tag: &'static str| {
        format!(
            "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, \
                                 is_current, visibility, owner_group_id) \
             SELECT gen_random_uuid(), '{tag} ' || g, {}, 0.5, '{other}', true, 'group', \
                    '{}' FROM pg_catalog.generate_series(1, 20000) g",
            key_sql(&format!("'{tag}' || g::text")),
            groups[0]
        )
    };
    exec(&mut c, "SET session_replication_role = replica").await;
    let t = Instant::now();
    exec(&mut c, &insert("with-idx")).await;
    let with_ms = t.elapsed().as_secs_f64() * 1000.0;
    exec(&mut c, "DROP INDEX public.idx_claims_public_by_agent").await;
    exec(&mut c, "DROP INDEX public.idx_claims_group_by_agent").await;
    let t = Instant::now();
    exec(&mut c, &insert("without-idx")).await;
    let without_ms = t.elapsed().as_secs_f64() * 1000.0;
    exec(&mut c, "SET session_replication_role = origin").await;
    println!(
        "\ninsert of 20,000 group claims: {with_ms:.0} ms with 275/276, {without_ms:.0} ms \
         without (triggers off, so the difference is the two indexes)"
    );
}
