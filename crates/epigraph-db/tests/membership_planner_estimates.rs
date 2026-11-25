//! The membership resolve plans under `jit_above_cost` (backlog 8377cf18,
//! migration 275).
//!
//! # The defect
//!
//! `epigraph_live_memberships(agent)` reads `epigraph_live_memberships_unbound`,
//! whose role-derived arm is `epigraph_role_derived_memberships(agent, at)`.
//! That body builds a `candidates` CTE from `epigraph_operator_actor(agent)`, a
//! set-returning SQL function with no `ROWS` clause, so the planner takes
//! PostgreSQL's default estimate of 1000 rows for it. Joined with the active
//! groups and the live role bindings, and with a per-row role-assignment check
//! and a correlated recursive subplan on top, the plan's estimated total cost
//! passes `jit_above_cost` (default 100000) and the jit inline and optimize
//! thresholds (default 500000), so every call JIT-compiles the plan. The item
//! measured about 1 s per call, almost all of it JIT, for a call that returns
//! a handful of rows and runs in about 25 ms with JIT off.
//!
//! `epigraph_operator_actor` returns at most ONE row: it reads
//! `operator_links` by `agent_id`, the table's primary key. Migration 275
//! declares `ROWS 1` on it, which is exact.
//!
//! # How the cost is measured
//!
//! The membership functions are `SECURITY DEFINER` with a `SET search_path`,
//! so PostgreSQL never inlines them: each body is planned on its own, and on
//! PostgreSQL 16 a SQL function's body is planned with its arguments as
//! unvalued parameters (a generic plan). So the test reads the function's
//! body from `pg_proc`, puts `$1`/`$2` in place of its argument names, and
//! asks for `EXPLAIN (GENERIC_PLAN, FORMAT JSON)`. The top plan node's total
//! cost is the number the JIT decision compares with `jit_above_cost`.
//!
//! A database freshly migrated for a test has never been analyzed, and an
//! analyzed but empty one estimates one row per table, which hides the
//! defect. So [`seed_prod_shape`] writes a production-sized shape (2,000
//! active groups, 40 live role bindings, 100 role attachments) and analyzes
//! those tables. The rows exist for the planner's statistics only: they are
//! written with triggers and foreign keys off (`session_replication_role =
//! replica`, local to the seeding transaction) and nothing reads them back.
//!
//! # What is pinned
//!
//! * [`the_role_derived_body_plans_under_jit_above_cost`]: on the seeded
//!   shape, the role-derived body's generic plan costs less than 100000.
//!   Measured: about 8.9M before 275 and 26.7k after. The ratio, 334, is the
//!   candidate count (1,002 / 3) and held at every binding count tried (5 to
//!   300); the cost after 275 grows linearly with the live bindings, so this
//!   shape is also the margin the test keeps.
//! * [`the_operator_actor_estimate_is_one_row_and_exact`]: the catalog
//!   carries `ROWS 1` on `epigraph_operator_actor`, and `operator_links` is
//!   still keyed on `agent_id`, so the estimate stays true. A later `CREATE
//!   OR REPLACE FUNCTION` of it resets `ROWS` to 1000 unless it restates
//!   `ROWS 1`; this test names that.
//!
//! Uses the non-macro `sqlx` forms so the offline `.sqlx/` cache is not
//! extended for one test.

use sqlx::{PgPool, Row};

/// PostgreSQL's default `jit_above_cost`. A database on the default setting
/// JIT-compiles any plan that costs this much or more.
const JIT_ABOVE_COST_DEFAULT: f64 = 100_000.0;

/// Replace each whole-word occurrence of a parameter name with its
/// placeholder. Word characters are ASCII alphanumerics and `_`, so `p_at`
/// does not match inside a longer identifier.
fn substitute(body: &str, params: &[(&str, &str)]) -> String {
    let is_word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let b = body.as_bytes();
    let mut out = String::with_capacity(body.len());
    let mut i = 0;
    let mut start = 0;
    while i < b.len() {
        if i == 0 || !is_word(b[i - 1]) {
            if let Some((name, rep)) = params.iter().find(|(name, _)| {
                let end = i + name.len();
                b[i..].starts_with(name.as_bytes()) && (end == b.len() || !is_word(b[end]))
            }) {
                out.push_str(&body[start..i]);
                out.push_str(rep);
                i += name.len();
                start = i;
                continue;
            }
        }
        i += 1;
    }
    out.push_str(&body[start..]);
    out
}

/// The generic-plan total cost of `sig`'s SQL body, with the plan as text for
/// a failure message.
async fn body_cost(pool: &PgPool, sig: &str, params: &[(&str, &str)]) -> (f64, String) {
    let src: String =
        sqlx::query_scalar("SELECT prosrc FROM pg_catalog.pg_proc WHERE oid = $1::regprocedure")
            .bind(sig)
            .fetch_one(pool)
            .await
            .expect("read the function body");
    let body = substitute(&src, params);
    // Simple-query protocol: the `$n` in the body are EXPLAIN's generic-plan
    // parameters, not bind parameters of this statement.
    let row = sqlx::raw_sql(&format!("EXPLAIN (GENERIC_PLAN, FORMAT JSON) {body}"))
        .fetch_one(pool)
        .await
        .expect("EXPLAIN the body");
    let plan: serde_json::Value = row.try_get(0).expect("EXPLAIN JSON");
    let cost = plan[0]["Plan"]["Total Cost"]
        .as_f64()
        .expect("top plan node's Total Cost");
    let text = sqlx::raw_sql(&format!("EXPLAIN (GENERIC_PLAN) {body}"))
        .fetch_all(pool)
        .await
        .expect("EXPLAIN the body as text")
        .iter()
        .map(|r| r.get::<String, _>(0))
        .collect::<Vec<_>>()
        .join("\n");
    (cost, text)
}

/// A production-sized shape for the planner's statistics: 2,000 active team
/// groups, a role bound to 40 of them (mixed binding modes), and 100
/// attachments of agents to that role. Written in one transaction with
/// triggers and foreign keys off for that transaction only, then analyzed.
async fn seed_prod_shape(pool: &PgPool) {
    let mut tx = pool.begin().await.expect("begin");
    sqlx::raw_sql(
        "SET LOCAL session_replication_role = replica;
         INSERT INTO public.platform_roles (key, elevates, reads_audit, role_node_id, description)
         VALUES ('role:planner-shape', false, false, gen_random_uuid(), 'planner shape');
         INSERT INTO public.groups (did_key, public_key, kind, display_name)
         SELECT 'did:key:planner-shape-' || g,
                decode(md5(g::text) || md5((g + 1)::text), 'hex'),
                'team', 'planner shape ' || g
           FROM generate_series(1, 2000) AS g;
         INSERT INTO public.group_role_bindings
                (group_id, role, member_role, include_agents, attached_agents, reason)
         SELECT s.id, 'role:planner-shape', 'reader', s.n % 3 = 0, s.n % 3 = 1, 'planner shape'
           FROM (SELECT id, row_number() OVER (ORDER BY id) AS n
                   FROM public.groups WHERE did_key LIKE 'did:key:planner-shape-%'
                  ORDER BY id LIMIT 40) AS s;
         INSERT INTO public.role_agents (role, agent_id, reason)
         SELECT 'role:planner-shape', gen_random_uuid(), 'planner shape'
           FROM generate_series(1, 100);",
    )
    .execute(&mut *tx)
    .await
    .expect("seed the planner shape");
    tx.commit().await.expect("commit the planner shape");
    sqlx::raw_sql(
        "ANALYZE public.platform_roles, public.groups, public.group_role_bindings, \
                 public.role_agents",
    )
    .execute(pool)
    .await
    .expect("analyze the planner shape");
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_role_derived_body_plans_under_jit_above_cost(pool: PgPool) {
    seed_prod_shape(&pool).await;
    let (cost, plan) = body_cost(
        &pool,
        "public.epigraph_role_derived_memberships(uuid, timestamptz)",
        &[("p_agent", "$1::uuid"), ("p_at", "$2::timestamptz")],
    )
    .await;
    assert!(
        cost < JIT_ABOVE_COST_DEFAULT,
        "epigraph_role_derived_memberships' body plans at total cost {cost}, at or above the \
         default jit_above_cost {JIT_ABOVE_COST_DEFAULT}, so every membership resolve would \
         JIT-compile it. A set-returning helper it calls has probably lost its ROWS estimate \
         (migration 275).\n{plan}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_operator_actor_estimate_is_one_row_and_exact(pool: PgPool) {
    let (rows, retset): (f32, bool) = sqlx::query_as(
        "SELECT prorows, proretset FROM pg_catalog.pg_proc \
          WHERE oid = 'public.epigraph_operator_actor(uuid)'::regprocedure",
    )
    .fetch_one(&pool)
    .await
    .expect("read epigraph_operator_actor's estimate");
    assert!(retset, "epigraph_operator_actor no longer returns a set");
    assert_eq!(
        rows, 1.0,
        "epigraph_operator_actor estimates {rows} rows. A CREATE OR REPLACE FUNCTION resets \
         ROWS to 1000 unless it restates ROWS 1 (migration 275); the 1000 estimate pushes \
         the membership resolve over jit_above_cost"
    );
    // ROWS 1 is exact only while the function reads `operator_links` by its
    // key: one link per agent.
    let keyed: bool = sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1 FROM pg_catalog.pg_index i
              WHERE i.indrelid = 'public.operator_links'::regclass
                AND i.indisunique AND i.indpred IS NULL AND i.indnatts = 1
                AND i.indkey[0] = (SELECT a.attnum FROM pg_catalog.pg_attribute a
                                    WHERE a.attrelid = 'public.operator_links'::regclass
                                      AND a.attname = 'agent_id'))",
    )
    .fetch_one(&pool)
    .await
    .expect("read operator_links' keys");
    assert!(
        keyed,
        "operator_links is no longer unique on agent_id alone, so epigraph_operator_actor's \
         ROWS 1 is no longer an upper bound; restate the estimate"
    );
}
