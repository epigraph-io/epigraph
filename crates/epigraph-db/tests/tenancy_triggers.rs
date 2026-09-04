//! Migration 070 / 071 behaviour — the write-side stamping PR-12 ships.
//!
//! # What these tests are for
//!
//! PR-12's *Tests* line names five assertions and gives three of them no home
//! (§8.2 places two in `crates/epigraph-db/tests/tenancy_required.rs`, which
//! does not exist and is **PR-16's** file). They live here, in a file named for
//! the migration whose behaviour they pin.
//!
//! # What a green run here does and does not prove
//!
//! Every `#[sqlx::test]` connects as `epigraph`, which is `rolsuper = true` on
//! this host. `epigraph_definer_bypass()` is `pg_has_role(current_user,
//! 'epigraph_maintenance', 'MEMBER')`, and `pg_has_role` is true of a superuser
//! for every role — so **arm (d)'s 42501 assertion can never fire in this
//! suite**, whoever owns the function. A test asserting "propagation succeeds"
//! is therefore NOT evidence that the production deploy will work.
//!
//! What *is* checkable, and what
//! [`propagation_function_is_owned_by_the_maintenance_role`] checks, is the
//! catalog: `pg_proc.proowner`. That is the fact the deploy depends on, it is
//! independent of who runs the test, and it was measured to matter — re-owning
//! the function without `GRANT EXECUTE ON FUNCTION epigraph_definer_bypass()
//! TO epigraph_maintenance` produces `permission denied for function
//! epigraph_definer_bypass` on the first batch, and re-owning it to a
//! non-maintenance role makes the assertion return false.

mod viewer_fixture;

use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture as fixture;

const WORLD: Uuid = Uuid::nil();

/// Insert a claim the way an unpatched production call site does — naming
/// neither tenancy column, so migration 062's DEFAULTs supply the world group.
/// This is precisely the "undeclared write" arm (a) exists to catch.
async fn insert_undeclared_claim(pool: &PgPool, agent: Uuid, content: &str) -> Uuid {
    let id = Uuid::new_v4();
    let mut hash = vec![0u8; 32];
    for (i, b) in content.as_bytes().iter().enumerate() {
        hash[i % 32] ^= *b;
    }
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current) \
         VALUES ($1, $2, $3, 0.8, $4, true)",
    )
    .bind(id)
    .bind(content)
    .bind(&hash)
    .bind(agent)
    .execute(pool)
    .await
    .expect("insert undeclared claim");
    id
}

async fn insert_evidence(pool: &PgPool, claim: Uuid, tag: &str) -> Uuid {
    let id = Uuid::new_v4();
    let mut hash = vec![0u8; 32];
    for (i, b) in tag.as_bytes().iter().enumerate() {
        hash[i % 32] ^= *b;
    }
    sqlx::query(
        "INSERT INTO evidence (id, claim_id, evidence_type, content_hash) \
         VALUES ($1, $2, 'document', $3)",
    )
    .bind(id)
    .bind(claim)
    .bind(&hash)
    .execute(pool)
    .await
    .expect("insert evidence");
    id
}

async fn tenancy_of(pool: &PgPool, table: &str, id: Uuid) -> (Uuid, String) {
    sqlx::query_as(&format!(
        "SELECT owner_group_id, visibility::text FROM {table} WHERE id = $1"
    ))
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("read tenancy of {table}: {e}"))
}

// =============================================================================
// Arm (a) — supersede must not declassify
// =============================================================================

/// PR-12 *Tests*: "a test asserting `supersede` of a `('group', G)` claim
/// yields a `('group', G)` successor".
///
/// The bug this pins is real and specific: `ClaimRepository::supersede` inserts
/// a new UUID and carries labels forward but NOT ownership, so before 070 the
/// successor of a private claim came out world/public — a silent
/// declassification performed by an ordinary edit.
#[sqlx::test(migrations = "../../migrations")]
async fn supersede_of_a_group_claim_yields_a_group_successor(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "author").await;
    let predecessor = fixture::seed_group_claim(&pool, agent, group, "secret").await;

    // The successor names NEITHER tenancy column — exactly what the unpatched
    // supersede path does. Arm (a) must fill them from `supersedes`.
    let successor = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, supersedes) \
         VALUES ($1, 'secret v2', $2, 0.8, $3, true, $4)",
    )
    .bind(successor)
    .bind(vec![7u8; 32])
    .bind(agent)
    .bind(predecessor)
    .execute(&pool)
    .await
    .expect("insert successor");

    let (owner, vis) = tenancy_of(&pool, "claims", successor).await;
    assert_eq!(
        (owner, vis.as_str()),
        (group, "group"),
        "superseding a ('group', G) claim must yield a ('group', G) successor; \
         a world/public successor is a silent declassification"
    );
}

/// The `step_lineage_id` limb of arm (a). `evolve_step` inserts a successor
/// **without** setting `supersedes` — it links through the lineage id plus an
/// edge — so a trigger that only understood `supersedes` would declassify every
/// evolved step while passing the test above.
#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_lineage_also_inherits_tenancy(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "author").await;
    let lineage = Uuid::new_v4();

    let first = fixture::seed_group_claim(&pool, agent, group, "step 1").await;
    sqlx::query("UPDATE claims SET step_lineage_id = $1 WHERE id = $2")
        .bind(lineage)
        .bind(first)
        .execute(&pool)
        .await
        .expect("set lineage");

    let second = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, step_lineage_id) \
         VALUES ($1, 'step 2', $2, 0.8, $3, true, $4)",
    )
    .bind(second)
    .bind(vec![9u8; 32])
    .bind(agent)
    .bind(lineage)
    .execute(&pool)
    .await
    .expect("insert evolved step");

    let (owner, vis) = tenancy_of(&pool, "claims", second).await;
    assert_eq!((owner, vis.as_str()), (group, "group"));
}

/// The instrument limb: a genuinely undeclared insert is COUNTED, and the
/// counter is per-table and per-day because plan §9.2's week-11b gate reads it
/// that way.
///
/// Arm (a) WARNS; it does not raise. That is the transition form, and reading
/// it as the enforcement point over-reports PR-12's blast radius by 13
/// production call sites — migration 074 (PR-16) is what raises.
#[sqlx::test(migrations = "../../migrations")]
async fn an_undeclared_insert_is_counted_and_not_rejected(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "author").await;

    let before: i64 = sqlx::query_scalar(
        "SELECT COALESCE(sum(n), 0)::bigint FROM tenancy_undeclared_writes \
          WHERE table_name = 'claims' AND day = current_date",
    )
    .fetch_one(&pool)
    .await
    .expect("read counter");

    let id = insert_undeclared_claim(&pool, agent, "undeclared").await;

    let after: i64 = sqlx::query_scalar(
        "SELECT COALESCE(sum(n), 0)::bigint FROM tenancy_undeclared_writes \
          WHERE table_name = 'claims' AND day = current_date",
    )
    .fetch_one(&pool)
    .await
    .expect("read counter");

    assert_eq!(
        after,
        before + 1,
        "arm (a) must bump tenancy_undeclared_writes for an undeclared insert — \
         this counter IS the week-11b deploy gate"
    );

    let (owner, vis) = tenancy_of(&pool, "claims", id).await;
    assert_eq!(
        (owner, vis.as_str()),
        (WORLD, "public"),
        "the transition form must let the row through on the default, not raise; \
         migration 074 is what turns this into a 23502"
    );
}

// =============================================================================
// Arm (c) — claim-derived inheritance at INSERT
// =============================================================================

/// PR-12 *Tests*: "a test asserting evidence of a group-private claim comes out
/// group-private".
///
/// `evidence` matters more than its siblings and the plan's own draft omitted
/// it: `evidence.raw_content` plus `evidence.embedding` are a full second copy
/// of claim-derived text **with its own ANN vector**. Stamped world/public, a
/// private claim's text stays retrievable by similarity search.
#[sqlx::test(migrations = "../../migrations")]
async fn evidence_of_a_group_private_claim_comes_out_group_private(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "author").await;
    let claim = fixture::seed_group_claim(&pool, agent, group, "private").await;

    let ev = insert_evidence(&pool, claim, "ev").await;

    let (owner, vis) = tenancy_of(&pool, "evidence", ev).await;
    assert_eq!(
        (owner, vis.as_str()),
        (group, "group"),
        "evidence inserted against a group-private claim must inherit its tenancy"
    );
}

/// PR-12 *Tests*: "a test asserting each of the eight §2.4-added tables
/// inherits correctly".
///
/// The plan phrases this as though PR-12 owed the COLUMNS. It does not —
/// migration 062's `tier_a` array already added `owner_group_id` / `visibility`
/// to all eight. What PR-12 owes is exactly this: proof that arm (c)'s trigger
/// is actually installed on each of them, which is a different claim and the
/// one that can regress.
///
/// Driven off a literal list rather than a catalog query on purpose: a
/// catalog-derived list would shrink silently if a trigger went missing, and
/// the test would still pass over the smaller set.
#[sqlx::test(migrations = "../../migrations")]
async fn each_of_the_eight_section_2_4_tables_inherits_from_its_claim(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "author").await;
    let claim = fixture::seed_group_claim(&pool, agent, group, "parent").await;

    // The eight tables plan §2.4 added, and the minimal INSERT each accepts.
    // `challenges` and `reasoning_traces` carry their own NOT NULLs; the rest
    // are keyed only on claim_id plus their composite key parts.
    for table in [
        "challenges",
        "reasoning_traces",
        "experiment_triples",
        "experiment_entity_mentions",
        "claim_clusters",
        "claim_cluster_membership",
        "claim_neighborhood_membership",
        "claim_signature_revocations",
    ] {
        let armed: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pg_trigger \
                             WHERE tgname = $1 \
                               AND tgrelid = ('public.' || $2)::regclass \
                               AND NOT tgisinternal \
                               AND tgenabled = 'O')",
        )
        .bind(format!("{table}_inherit_tenancy"))
        .bind(table)
        .fetch_one(&pool)
        .await
        .expect("read pg_trigger");

        assert!(
            armed,
            "{table} has no ENABLED {table}_inherit_tenancy trigger — migration 070 \
             arm (c) did not cover it, so a row inserted against a group-private \
             claim would stay world/public"
        );
    }

    // =====================================================================
    // AND PROVE THE MECHANISM END TO END ON ALL EIGHT.
    //
    // An earlier revision of this test did one table, swallowed the INSERT
    // with `.ok()`, and asserted `count(*) WHERE owner_group_id <> group == 0`
    // — which is trivially true when NO ROW WAS INSERTED. It was not: the
    // statement named a `cluster_label` column `claim_clusters` does not have,
    // so it failed silently on every run and the "end-to-end" leg proved
    // nothing at all. The catalog loop above was the whole test.
    //
    // Every INSERT below is `.expect()`ed, and each table's row is asserted to
    // EXIST before its tenancy is asserted, so a schema drift that breaks an
    // INSERT fails the test instead of vacuously passing it.
    //
    // Note this also pins arm (c)'s deliberate lack of a no-widening gate: a
    // derived row has no independent tenancy, so it always equals its parent.
    // =====================================================================
    let entity: Uuid = sqlx::query_scalar(
        "INSERT INTO experiment_entities (canonical_name, entity_type) \
         VALUES ('e', 'reagent') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("seed experiment entity");
    let run = Uuid::new_v4();
    sqlx::query("INSERT INTO graph_cluster_runs (run_id, cluster_count) VALUES ($1, 1)")
        .bind(run)
        .execute(&pool)
        .await
        .expect("seed graph cluster run (graph_neighborhoods.run_id FKs to it)");
    let cluster: Uuid = sqlx::query_scalar(
        "INSERT INTO graph_clusters (id, run_id, label, size) \
         VALUES (gen_random_uuid(), $1, 'c', 1) RETURNING id",
    )
    .bind(run)
    .fetch_one(&pool)
    .await
    .expect("seed graph cluster");
    let theme: Uuid =
        sqlx::query_scalar("INSERT INTO claim_themes (label) VALUES ('t') RETURNING id")
            .fetch_one(&pool)
            .await
            .expect("seed claim theme (graph_neighborhoods.theme_id FKs to it)");
    let neighborhood: Uuid = sqlx::query_scalar(
        "INSERT INTO graph_neighborhoods (run_id, theme_id, label, size) \
         VALUES ($1, $2, 'n', 1) RETURNING id",
    )
    .bind(run)
    .bind(theme)
    .fetch_one(&pool)
    .await
    .expect("seed graph neighborhood");

    let inserts: Vec<(&str, String)> = vec![
        (
            "challenges",
            "INSERT INTO challenges (claim_id, challenge_type, explanation) \
             VALUES ($1, 'evidence', 'why')"
                .to_string(),
        ),
        (
            "reasoning_traces",
            "INSERT INTO reasoning_traces (claim_id, reasoning_type, explanation) \
             VALUES ($1, 'deductive', 'because')"
                .to_string(),
        ),
        (
            "experiment_triples",
            format!(
                "INSERT INTO experiment_triples \
                   (claim_id, subject_entity_id, predicate, object_entity_id) \
                 VALUES ($1, '{entity}', 'reacts_with', '{entity}')"
            ),
        ),
        (
            "experiment_entity_mentions",
            format!(
                "INSERT INTO experiment_entity_mentions (claim_id, entity_id, surface_form) \
                 VALUES ($1, '{entity}', 'e')"
            ),
        ),
        (
            "claim_clusters",
            format!(
                "INSERT INTO claim_clusters (claim_id, cluster_id, centroid_distance, \
                    second_centroid_dist, boundary_ratio, silhouette_score, cluster_run_id) \
                 VALUES ($1, 1, 0.1, 0.2, 0.5, 0.3, '{run}')"
            ),
        ),
        (
            "claim_cluster_membership",
            format!(
                "INSERT INTO claim_cluster_membership (claim_id, cluster_id, run_id) \
                 VALUES ($1, '{cluster}', '{run}')"
            ),
        ),
        (
            "claim_neighborhood_membership",
            format!(
                "INSERT INTO claim_neighborhood_membership (run_id, claim_id, neighborhood_id) \
                 VALUES ('{run}', $1, '{neighborhood}')"
            ),
        ),
        (
            "claim_signature_revocations",
            format!(
                "INSERT INTO claim_signature_revocations \
                   (claim_id, previous_signature, previous_content_hash, revoked_by, reason) \
                 VALUES ($1, decode(repeat('00', 64), 'hex'), \
                         decode(repeat('00', 32), 'hex'), '{agent}', 'test')"
            ),
        ),
    ];

    for (table, sql) in inserts {
        sqlx::query(&sql)
            .bind(claim)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("insert into {table}: {e}"));

        let (n, wrong): (i64, i64) = sqlx::query_as(&format!(
            "SELECT count(*), count(*) FILTER (WHERE owner_group_id <> $2 OR visibility <> 'group') \
               FROM {table} WHERE claim_id = $1"
        ))
        .bind(claim)
        .bind(group)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("read back {table}: {e}"));

        assert_eq!(
            n, 1,
            "{table}: the row must actually EXIST — an INSERT that silently fails \
             makes the tenancy assertion below vacuously true, which is exactly \
             how the previous version of this test proved nothing"
        );
        assert_eq!(
            wrong, 0,
            "{table}: a row derived from a ('group', G) claim must come out \
             ('group', G); keeping the world/public default would publish \
             claim-derived content of a private claim"
        );
    }
}

/// Arm (c) fails CLOSED on an unresolvable parent.
///
/// This matters for the three claim-derived tables that carry `claim_id` with
/// **no foreign key** to `claims` — `claim_versions`,
/// `claim_cluster_membership` and `ds_combined_beliefs`. On those, a synthetic
/// claim_id is legal today; arm (c)'s explicit orphan check is the only thing
/// that stops such a row from existing with no derivable owner.
#[sqlx::test(migrations = "../../migrations")]
async fn an_orphan_claim_id_is_rejected_where_no_foreign_key_would_catch_it(pool: PgPool) {
    let has_fk: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_constraint \
                         WHERE conrelid = 'public.claim_versions'::regclass \
                           AND contype = 'f' \
                           AND confrelid = 'public.claims'::regclass)",
    )
    .fetch_one(&pool)
    .await
    .expect("read pg_constraint");
    assert!(
        !has_fk,
        "claim_versions gained an FK to claims — this test's premise is stale, and \
         arm (c)'s orphan check is now belt-and-braces rather than the only guard"
    );

    let err = sqlx::query(
        "INSERT INTO claim_versions (id, claim_id, version_number, content, truth_value) \
         VALUES ($1, $2, 1, 'x', 0.5)",
    )
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4()) // no such claim
    .execute(&pool)
    .await
    .expect_err("an orphan claim_id must be rejected, never defaulted");

    let msg = err.to_string();
    assert!(
        msg.contains("nonexistent parent claim") || msg.contains("23503"),
        "expected arm (c)'s 23503 orphan rejection, got: {msg}"
    );
}

// =============================================================================
// Arm (d) — statement-level propagation
// =============================================================================

/// PR-12 *Tests*: "a test asserting the statement trigger issues one UPDATE per
/// table per statement, not per row".
///
/// # Why this is measured with a counting trigger and not `pg_stat_statements`
///
/// The property is "arm (d) fired ONCE for a multi-row UPDATE", and the honest
/// instrument is a per-statement counter that arm (d)'s own firing increments.
/// A row-level trigger on `evidence` counts how many times the propagation
/// **wrote**, which is the thing that was wrong in the previous plan revision:
/// the row form issued ten UPDATEs per claim, 5,000 statements per 500-item
/// batch.
///
/// The discriminating measurement is that updating N claims that share a
/// derived table produces ONE propagation pass, not N — so the evidence rows
/// are each touched exactly once even though three claims changed.
#[sqlx::test(migrations = "../../migrations")]
async fn propagation_is_one_pass_per_statement_not_one_per_row(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "author").await;

    let mut claims = Vec::new();
    for i in 0..3 {
        let c = insert_undeclared_claim(&pool, agent, &format!("claim {i}")).await;
        insert_evidence(&pool, c, &format!("ev {i}")).await;
        claims.push(c);
    }

    // A counting trigger on `evidence`, installed AFTER the seed so it counts
    // only the propagation.
    sqlx::query("CREATE TABLE prop_counter (n bigint NOT NULL)")
        .execute(&pool)
        .await
        .expect("create counter");
    sqlx::query("INSERT INTO prop_counter VALUES (0)")
        .execute(&pool)
        .await
        .expect("seed counter");
    // The counting trigger fires INSIDE arm (d)'s SECURITY DEFINER frame, i.e.
    // as `epigraph_maintenance`. Migration 070's schema-wide grant bound the
    // tables that existed when it ran; `prop_counter` was created after, so
    // without this the counter write fails with `permission denied for table
    // prop_counter`. That error is itself confirmation that arm (d) really does
    // run as the maintenance role rather than as the test's superuser.
    sqlx::query("GRANT SELECT, INSERT, UPDATE ON prop_counter TO epigraph_maintenance")
        .execute(&pool)
        .await
        .expect("grant on counter");
    sqlx::query(
        "CREATE FUNCTION count_evidence_updates() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN UPDATE prop_counter SET n = n + 1; RETURN NULL; END $$",
    )
    .execute(&pool)
    .await
    .expect("create counting fn");
    // FOR EACH STATEMENT: counts how many UPDATE STATEMENTS hit `evidence`,
    // which is exactly the quantity the plan's ops F11 correction is about.
    sqlx::query(
        "CREATE TRIGGER count_evidence_updates AFTER UPDATE ON evidence \
         FOR EACH STATEMENT EXECUTE FUNCTION count_evidence_updates()",
    )
    .execute(&pool)
    .await
    .expect("create counting trigger");

    // ONE statement, three claims.
    sqlx::query("UPDATE claims SET owner_group_id = $1, visibility = 'group' WHERE id = ANY($2)")
        .bind(group)
        .bind(&claims)
        .execute(&pool)
        .await
        .expect("privatize three claims in one statement");

    let passes: i64 = sqlx::query_scalar("SELECT n FROM prop_counter")
        .fetch_one(&pool)
        .await
        .expect("read counter");

    assert_eq!(
        passes, 1,
        "arm (d) must issue ONE UPDATE against `evidence` per statement. Got {passes} \
         for a 3-claim statement — a per-row trigger would give 3, and at a 500-item \
         privatization batch that is 500 statements per derived table."
    );

    // And it actually propagated, so the count above is not one pass over nothing.
    let unpropagated: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM evidence e JOIN claims c ON c.id = e.claim_id \
          WHERE c.id = ANY($1) AND (e.owner_group_id, e.visibility) \
                IS DISTINCT FROM (c.owner_group_id, c.visibility)",
    )
    .bind(&claims)
    .fetch_one(&pool)
    .await
    .expect("count unpropagated");
    assert_eq!(unpropagated, 0, "propagation must reach every evidence row");
}

/// An UPDATE that changes no tenancy must not run the propagation walk.
///
/// This is the guard that replaced the plan's `AFTER UPDATE OF owner_group_id,
/// visibility` column list, which PostgreSQL **rejects** when combined with a
/// transition table ("transition tables cannot be specified for triggers with
/// column lists"). Without the replacement, every ordinary `UPDATE claims`
/// would run ~36 correlated statements and, on a deploy that had not re-owned
/// the function, raise 42501 on the application write path.
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_tenancy_update_does_not_trigger_the_propagation_walk(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "author").await;
    let claim = fixture::seed_group_claim(&pool, agent, group, "content").await;
    insert_evidence(&pool, claim, "ev").await;

    sqlx::query("CREATE TABLE prop_counter (n bigint NOT NULL)")
        .execute(&pool)
        .await
        .expect("create counter");
    sqlx::query("INSERT INTO prop_counter VALUES (0)")
        .execute(&pool)
        .await
        .expect("seed counter");
    // The counting trigger fires INSIDE arm (d)'s SECURITY DEFINER frame, i.e.
    // as `epigraph_maintenance`. Migration 070's schema-wide grant bound the
    // tables that existed when it ran; `prop_counter` was created after, so
    // without this the counter write fails with `permission denied for table
    // prop_counter`. That error is itself confirmation that arm (d) really does
    // run as the maintenance role rather than as the test's superuser.
    sqlx::query("GRANT SELECT, INSERT, UPDATE ON prop_counter TO epigraph_maintenance")
        .execute(&pool)
        .await
        .expect("grant on counter");
    sqlx::query(
        "CREATE FUNCTION count_evidence_updates() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN UPDATE prop_counter SET n = n + 1; RETURN NULL; END $$",
    )
    .execute(&pool)
    .await
    .expect("create counting fn");
    sqlx::query(
        "CREATE TRIGGER count_evidence_updates AFTER UPDATE ON evidence \
         FOR EACH STATEMENT EXECUTE FUNCTION count_evidence_updates()",
    )
    .execute(&pool)
    .await
    .expect("create counting trigger");

    // Edit the content. Tenancy is untouched.
    sqlx::query("UPDATE claims SET content = 'edited' WHERE id = $1")
        .bind(claim)
        .execute(&pool)
        .await
        .expect("edit content");

    let passes: i64 = sqlx::query_scalar("SELECT n FROM prop_counter")
        .fetch_one(&pool)
        .await
        .expect("read counter");
    assert_eq!(
        passes, 0,
        "an UPDATE that changes no tenancy must short-circuit before the walk; \
         got {passes} propagation pass(es) over `evidence`"
    );

    // Control: the SAME setup with a real tenancy change must count 1, or the
    // assertion above is satisfied by a trigger that never fires at all.
    let (_, other_group) = fixture::seed_agent_with_group(&pool, "other").await;
    sqlx::query("UPDATE claims SET owner_group_id = $1 WHERE id = $2")
        .bind(other_group)
        .bind(claim)
        .execute(&pool)
        .await
        .expect("change tenancy");
    let passes: i64 = sqlx::query_scalar("SELECT n FROM prop_counter")
        .fetch_one(&pool)
        .await
        .expect("read counter");
    assert_eq!(
        passes, 1,
        "control: a real tenancy change MUST propagate — otherwise the zero above \
         proves only that the trigger is dead"
    );
}

// =============================================================================
// Ownership — the catalog fact CI cannot otherwise reach
// =============================================================================

/// The SECURITY DEFINER bodies must be owned by `epigraph_maintenance`.
///
/// # Why a catalog assertion rather than a behavioural one
///
/// `epigraph_definer_bypass()` keys on `current_user`, which inside a SECURITY
/// DEFINER frame is the function OWNER. CI connects as a superuser, for whom
/// `pg_has_role` is true of every role, so a behavioural test passes whatever
/// the owner is. `pg_proc.proowner` is the fact the deploy actually depends on
/// and the only one that discriminates here.
///
/// Measured consequence of getting it wrong: with the owner set but without
/// `GRANT EXECUTE ON FUNCTION epigraph_definer_bypass() TO
/// epigraph_maintenance`, the first backfill batch fails with `permission
/// denied for function epigraph_definer_bypass`. With the owner left as the
/// migration role, arm (d) raises 42501 in production while this suite is
/// green.
#[sqlx::test(migrations = "../../migrations")]
async fn propagation_function_is_owned_by_the_maintenance_role(pool: PgPool) {
    let role_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance')",
    )
    .fetch_one(&pool)
    .await
    .expect("read pg_roles");
    assert!(
        role_exists,
        "epigraph_maintenance is absent; migration 060 creates it and this \
         assertion is vacuous without it"
    );

    for f in [
        "epigraph_propagate_tenancy",
        "epigraph_inherit_tenancy_stmt",
        "epigraph_claims_require_tenancy",
        "epigraph_edges_tenancy",
        "epigraph_node_tenancy",
        "epigraph_ownership_transcribe",
    ] {
        let owner: String = sqlx::query_scalar(
            "SELECT r.rolname FROM pg_proc p \
               JOIN pg_roles r ON r.oid = p.proowner \
               JOIN pg_namespace n ON n.oid = p.pronamespace \
              WHERE n.nspname = 'public' AND p.proname = $1 LIMIT 1",
        )
        .bind(f)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("{f} not found in pg_proc: {e}"));

        assert_eq!(
            owner, "epigraph_maintenance",
            "{f} must be owned by epigraph_maintenance. Owned by '{owner}', its \
             SECURITY DEFINER frame runs as that role instead, so \
             epigraph_definer_bypass() is false in production and every \
             propagation raises 42501 — while this suite stays green because CI \
             connects as a superuser."
        );
    }

    // The GRANT the re-owning depends on. Without it the owner change turns a
    // working deploy into `permission denied for function
    // epigraph_definer_bypass` on batch 1.
    let granted: bool = sqlx::query_scalar(
        "SELECT has_function_privilege('epigraph_maintenance', \
                'public.epigraph_definer_bypass()', 'EXECUTE')",
    )
    .fetch_one(&pool)
    .await
    .expect("check EXECUTE privilege");
    assert!(
        granted,
        "epigraph_maintenance lacks EXECUTE on epigraph_definer_bypass(). \
         Migration 067 revoked it FROM PUBLIC, so re-owning the trigger bodies \
         without re-granting it makes every propagation fail with 42501's \
         cousin: permission denied for function."
    );
}

/// Every tenancy trigger is ENABLED — plan §8.2 acceptance A5.
///
/// `tgenabled = 'O'` (origin) is the default, but `ALTER TABLE … DISABLE
/// TRIGGER` is exactly what an on-call reaches for at 2 a.m., and a disabled
/// stamping trigger is indistinguishable from an absent one at the row level.
#[sqlx::test(migrations = "../../migrations")]
async fn every_tenancy_trigger_is_enabled(pool: PgPool) {
    let disabled: Vec<String> = sqlx::query_scalar(
        "SELECT t.tgname FROM pg_trigger t \
          WHERE NOT t.tgisinternal \
            AND (t.tgname IN ('claims_require_tenancy', 'edges_tenancy', \
                              'claims_propagate_tenancy', 'ownership_transcribe') \
                 OR t.tgname LIKE '%\\_inherit\\_tenancy') \
            AND t.tgenabled <> 'O' \
          ORDER BY t.tgname",
    )
    .fetch_all(&pool)
    .await
    .expect("read pg_trigger");
    assert!(
        disabled.is_empty(),
        "these tenancy triggers are not ENABLED (tgenabled <> 'O'): {disabled:?}"
    );

    // Vacuity guard: the query above passes trivially if no such trigger exists.
    let armed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_trigger t \
          WHERE NOT t.tgisinternal \
            AND (t.tgname IN ('claims_require_tenancy', 'edges_tenancy', \
                              'claims_propagate_tenancy', 'ownership_transcribe') \
                 OR t.tgname LIKE '%\\_inherit\\_tenancy')",
    )
    .fetch_one(&pool)
    .await
    .expect("count tenancy triggers");
    assert_eq!(
        armed, 21,
        "expected 21 tenancy triggers (4 named + 17 claim-derived inheritors); \
         found {armed}. A changed count means arm (c)'s table set moved."
    );
}

// =============================================================================
// Migration 071 — the ownership compat shim
// =============================================================================

/// Writing a `private` ownership row reclassifies the claim AND its evidence,
/// and writes the ledger row migration 084's pre-flight reads.
#[sqlx::test(migrations = "../../migrations")]
async fn a_private_ownership_row_transcribes_into_the_tenancy_columns(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "owner").await;
    let claim = insert_undeclared_claim(&pool, agent, "to be privatized").await;
    let ev = insert_evidence(&pool, claim, "ev").await;

    sqlx::query(
        "INSERT INTO ownership (node_id, node_type, partition_type, owner_id) \
         VALUES ($1, 'claim', 'private', $2)",
    )
    .bind(claim)
    .bind(agent)
    .execute(&pool)
    .await
    .expect("write ownership");

    assert_eq!(
        tenancy_of(&pool, "claims", claim).await,
        (group, "group".to_string()),
        "a 'private' ownership row must reclassify the claim to its owner's personal group"
    );
    assert_eq!(
        tenancy_of(&pool, "evidence", ev).await,
        (group, "group".to_string()),
        "and arm (d) must carry that to the claim's evidence in the same transaction"
    );

    let (node_type, from_partition, to_visibility): (String, String, String) = sqlx::query_as(
        "SELECT node_type, from_partition, to_visibility FROM tenancy_transcription_log \
          WHERE node_id = $1",
    )
    .bind(claim)
    .fetch_one(&pool)
    .await
    .expect("ledger row must exist — migration 084 refuses to drop `ownership` without it");
    assert_eq!(
        (
            node_type.as_str(),
            from_partition.as_str(),
            to_visibility.as_str()
        ),
        ("claim", "private", "group")
    );
}

/// An owner with no personal group gets one MINTED — the shim must not refuse.
///
/// # Why materializing is the fail-closed answer, and refusing was not
///
/// An earlier revision of migration 071 RAISED here. That reads as strictness
/// and is the opposite: refusing the write leaves the claim **public** when the
/// caller explicitly asked for private. Failing open, dressed up as a guard.
///
/// Minting is not a "fallback to some other group" — the thing D2 and the plan
/// actually forbid. It is the same idempotent act
/// `AgentRepository::ensure_personal_group` performs on the OAuth mint path,
/// and it yields a real group whose only live member is the owner, which is
/// precisely what `private` means.
///
/// The ~1,198 orphan agents migration 057 documents make this the common case,
/// not an edge case: an agent that has never authenticated has no personal
/// group, and `ownership.owner_id` can name it.
#[sqlx::test(migrations = "../../migrations")]
async fn an_owner_with_no_personal_group_gets_one_minted(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let claim = insert_undeclared_claim(&pool, author, "claim").await;

    // An agent with NO personal group under either identification.
    let stranger = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(stranger)
        .bind(vec![42u8; 32])
        .execute(&pool)
        .await
        .expect("seed groupless agent");

    sqlx::query(
        "INSERT INTO ownership (node_id, node_type, partition_type, owner_id) \
         VALUES ($1, 'claim', 'private', $2)",
    )
    .bind(claim)
    .bind(stranger)
    .execute(&pool)
    .await
    .expect("the shim must mint the owner's personal group rather than refuse");

    let (owner_group, vis) = tenancy_of(&pool, "claims", claim).await;
    assert_eq!(
        vis, "group",
        "'private' must actually make the claim private"
    );

    let did_key: String = sqlx::query_scalar("SELECT did_key FROM groups WHERE id = $1")
        .bind(owner_group)
        .fetch_one(&pool)
        .await
        .expect("read the minted group");
    assert_eq!(
        did_key,
        format!("did:epigraph:personal:{stranger}"),
        "the minted group must carry the canonical did_key ensure_personal_group \
         derives, or the two paths mint duplicates of each other"
    );

    // The property that makes this fail-CLOSED rather than a black hole.
    let live: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM group_memberships \
          WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL",
    )
    .bind(owner_group)
    .bind(stranger)
    .fetch_one(&pool)
    .await
    .expect("count membership");
    assert_eq!(
        live, 1,
        "the minted group must have the owner as a LIVE member; a group-visible \
         row owned by a memberless group is unreadable by everyone including its \
         owner, and 062's CHECK cannot catch it because an empty REAL group is \
         not in its NOT IN list"
    );

    // And it is emphatically not world or seed.
    assert_ne!(owner_group, WORLD);
    let seed: Uuid = sqlx::query_scalar("SELECT id FROM groups WHERE kind = 'seed'")
        .fetch_one(&pool)
        .await
        .expect("seed group");
    assert_ne!(owner_group, seed);
}

/// A `community` row whose `community_id` does not resolve falls back to the
/// owner's personal group as `('group', personal)` — **it does not raise**.
///
/// This is a legacy shape, not a bug: before migration 068 the gating community
/// lived stringified in `ownership.encryption_key_id`, and 068 created the
/// `ownership_key_id_quarantine` VIEW precisely to REPORT the ones that did not
/// resolve. `tenancy_coverage.rs::quarantine_reports_a_dangling_community_uuid`
/// records the reviewed decision in its own assertion — such a row "must be
/// REPORTED, not swallowed and not fatal" and must stay WRITABLE. A raise here
/// would defeat the quarantine's entire purpose.
///
/// Falling back to the owner is fail-CLOSED: strictly more restrictive than
/// public, on a real group with a real live member.
#[sqlx::test(migrations = "../../migrations")]
async fn a_dangling_community_reference_falls_back_to_the_owner_not_a_raise(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "owner").await;
    let claim = insert_undeclared_claim(&pool, agent, "legacy community row").await;

    sqlx::query(
        "INSERT INTO ownership (node_id, node_type, partition_type, owner_id, encryption_key_id) \
         VALUES ($1, 'claim', 'community', $2, $3::text)",
    )
    .bind(claim)
    .bind(agent)
    .bind(Uuid::new_v4()) // a well-formed UUID naming no community
    .execute(&pool)
    .await
    .expect("a dangling community UUID must stay WRITABLE so the quarantine view can report it");

    assert_eq!(
        tenancy_of(&pool, "claims", claim).await,
        (group, "group".to_string()),
        "an unresolvable community must fail CLOSED to the owner's personal group, \
         not stay public"
    );

    // The quarantine view must still see it — that is the point of not raising.
    let reported: Vec<Uuid> = sqlx::query_scalar("SELECT node_id FROM ownership_key_id_quarantine")
        .fetch_all(&pool)
        .await
        .expect("quarantine read");
    assert_eq!(reported, vec![claim]);

    // And the ledger records the ORIGINAL partition, so PR-18's migration-080
    // gate still sees the transition it is looking for.
    let from_partition: String = sqlx::query_scalar(
        "SELECT from_partition FROM tenancy_transcription_log WHERE node_id = $1",
    )
    .bind(claim)
    .fetch_one(&pool)
    .await
    .expect("ledger row");
    assert_eq!(from_partition, "community");
}

/// A `community` partition projects the community's group **and its members**.
///
/// Projecting the group without the members would produce `('group', G)` where
/// G has zero live memberships — unreadable by everyone, including the
/// community's own members. 062's `_group_needs_real_group` CHECK cannot catch
/// it: that is a `NOT IN (world, seed)` list, and an empty REAL group passes.
#[sqlx::test(migrations = "../../migrations")]
async fn a_community_partition_projects_the_group_and_its_members(pool: PgPool) {
    let (owner, _) = fixture::seed_agent_with_group(&pool, "owner").await;
    let (member, _) = fixture::seed_agent_with_group(&pool, "member").await;
    let claim = insert_undeclared_claim(&pool, owner, "community claim").await;

    // A community created by raw SQL — i.e. with NO projected group, the state
    // migration 068's one-time snapshot leaves for anything created after it.
    let community = Uuid::new_v4();
    sqlx::query("INSERT INTO communities (id, name) VALUES ($1, 'physics')")
        .bind(community)
        .execute(&pool)
        .await
        .expect("seed community");
    let perspective: Uuid = sqlx::query_scalar(
        "INSERT INTO perspectives (name, owner_agent_id) VALUES ('p', $1) RETURNING id",
    )
    .bind(member)
    .fetch_one(&pool)
    .await
    .expect("seed perspective");
    sqlx::query("INSERT INTO community_members (community_id, perspective_id) VALUES ($1, $2)")
        .bind(community)
        .bind(perspective)
        .execute(&pool)
        .await
        .expect("seed community member");

    sqlx::query(
        "INSERT INTO ownership (node_id, node_type, partition_type, owner_id, community_id) \
         VALUES ($1, 'claim', 'community', $2, $3)",
    )
    .bind(claim)
    .bind(owner)
    .bind(community)
    .execute(&pool)
    .await
    .expect("write community ownership");

    assert_eq!(
        tenancy_of(&pool, "claims", claim).await,
        (community, "group".to_string()),
        "migration 068's projection is ID-PRESERVING, so the group id IS the \
         community id"
    );

    let member_live: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM group_memberships \
          WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL",
    )
    .bind(community)
    .bind(member)
    .fetch_one(&pool)
    .await
    .expect("count membership");
    assert_eq!(
        member_live, 1,
        "the community's member must be projected into the group, or the claim is \
         a black hole readable by nobody"
    );

    // THE DECLARING OWNER IS DELIBERATELY NOT PROJECTED IN.
    //
    // Adding them would guarantee the declaring agent can read back what it just
    // declared — tempting, and wrong. `epigraph-mcp/tests/community_partition.rs::
    // community_owner_who_is_not_a_member_is_redacted` states the reviewed
    // decision in its own assertion: "on the community arm, ownership alone does
    // NOT grant access once a community resolves — membership is the whole test.
    // If you are changing this, change it on purpose." Projecting the owner in
    // would change it by accident.
    let owner_live: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM group_memberships \
          WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL",
    )
    .bind(community)
    .bind(owner)
    .fetch_one(&pool)
    .await
    .expect("count membership");
    assert_eq!(
        owner_live, 0,
        "ownership alone must not grant community membership; the shim must not \
         quietly add the declaring owner to the community's group"
    );
}

/// A community with NO projectable members must not be stamped onto the node.
///
/// Its group would have zero live memberships — a row unreadable by EVERYONE,
/// permanently. 062's `_group_needs_real_group` CHECK cannot catch this: it is a
/// `NOT IN (world, seed)` list, and an empty REAL group passes straight through.
/// The shim falls back to the owner's personal group, which is still `'group'`
/// (fail-closed, not public) and readable by at least the declaring owner.
#[sqlx::test(migrations = "../../migrations")]
async fn an_empty_community_falls_back_to_the_owner_rather_than_a_black_hole(pool: PgPool) {
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "owner").await;
    let claim = insert_undeclared_claim(&pool, owner, "claim").await;

    let community = Uuid::new_v4();
    sqlx::query("INSERT INTO communities (id, name) VALUES ($1, 'empty')")
        .bind(community)
        .execute(&pool)
        .await
        .expect("seed community");

    sqlx::query(
        "INSERT INTO ownership (node_id, node_type, partition_type, owner_id, community_id) \
         VALUES ($1, 'claim', 'community', $2, $3)",
    )
    .bind(claim)
    .bind(owner)
    .bind(community)
    .execute(&pool)
    .await
    .expect("write community ownership against an empty community");

    let (stamped, vis) = tenancy_of(&pool, "claims", claim).await;
    assert_eq!(
        vis, "group",
        "the fallback must stay fail-closed — never public"
    );
    assert_eq!(
        stamped, owner_group,
        "an empty community's group is a black hole; the shim must fall back to \
         the owner's personal group instead of stamping it"
    );
    assert_ne!(stamped, community);
}

/// The ledger is keyed one row per node, so a re-classification OVERWRITES.
///
/// This is a known, documented defect, not an accident:
/// `tenancy_transcription_log` is `node_id uuid PRIMARY KEY` and
/// `schema_contract.rs` pins the 6-column shape in order, so PR-12 cannot add a
/// sequence without a migration number — and 072–084 are all allocated. It does
/// not block the consumer: migration 084's pre-flight reads this table for the
/// EXISTENCE of a row per non-public `ownership` row, which last-write-wins
/// still satisfies. What is lost is history.
///
/// Pinned as a test so the limitation is discovered here rather than by PR-18.
#[sqlx::test(migrations = "../../migrations")]
async fn the_transcription_ledger_is_last_write_wins(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "owner").await;
    let claim = insert_undeclared_claim(&pool, agent, "reclassified twice").await;

    let community = Uuid::new_v4();
    sqlx::query("INSERT INTO communities (id, name) VALUES ($1, 'c')")
        .bind(community)
        .execute(&pool)
        .await
        .expect("seed community");
    sqlx::query(
        "INSERT INTO groups (id, display_name, did_key, public_key, kind) \
         VALUES ($1, 'c', 'did:epigraph:community:' || $1::text, ''::bytea, 'community')",
    )
    .bind(community)
    .execute(&pool)
    .await
    .expect("project community group");

    sqlx::query(
        "INSERT INTO ownership (node_id, node_type, partition_type, owner_id) \
         VALUES ($1, 'claim', 'private', $2)",
    )
    .bind(claim)
    .bind(agent)
    .execute(&pool)
    .await
    .expect("first classification");

    sqlx::query(
        "UPDATE ownership SET partition_type = 'community', community_id = $2 WHERE node_id = $1",
    )
    .bind(claim)
    .bind(community)
    .execute(&pool)
    .await
    .expect("reclassify to community");

    let rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM tenancy_transcription_log WHERE node_id = $1")
            .bind(claim)
            .fetch_one(&pool)
            .await
            .expect("count ledger rows");
    assert_eq!(
        rows, 1,
        "node_id is the PRIMARY KEY, so a node can only ever have one ledger row"
    );

    let from_partition: String = sqlx::query_scalar(
        "SELECT from_partition FROM tenancy_transcription_log WHERE node_id = $1",
    )
    .bind(claim)
    .fetch_one(&pool)
    .await
    .expect("read ledger");
    assert_eq!(
        from_partition, "community",
        "the ledger records the LAST transition, not the first — the 'private' \
         step is gone. Documented in migration 071; migration 084's gate reads \
         existence, not history."
    );
}

/// **The shim never WIDENS.** A `partition_type = 'public'` ownership row must
/// not declassify a claim that is already group-private.
///
/// # How this was found
///
/// Not by reasoning — by a red test.
/// `epigraph-api/tests/structural_features_authz.rs::seed_corpus` stamps a
/// `'public'` ownership row over all three of its claims as bookkeeping,
/// including the one it deliberately seeded as `('group', owner_group)`. An
/// earlier revision of migration 071 honoured that row and made the claim
/// public, and
/// `owner_sees_the_whole_subgraph_and_a_stranger_only_its_public_part` caught
/// it: a stranger saw **3** claims where it must see 2.
///
/// A compat shim for a table on its way out must not be able to declassify
/// content. Widening is the one direction that turns a bookkeeping write into a
/// disclosure, and it is what PR-16's migration 074 `claims_block_widening`
/// trigger exists to forbid.
#[sqlx::test(migrations = "../../migrations")]
async fn a_public_ownership_row_cannot_declassify_a_group_private_claim(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "owner").await;
    let claim = fixture::seed_group_claim(&pool, agent, group, "already private").await;

    sqlx::query(
        "INSERT INTO ownership (node_id, node_type, partition_type, owner_id) \
         VALUES ($1, 'claim', 'public', $2)",
    )
    .bind(claim)
    .bind(agent)
    .execute(&pool)
    .await
    .expect("a 'public' ownership row must be accepted, not raise");

    assert_eq!(
        tenancy_of(&pool, "claims", claim).await,
        (group, "group".to_string()),
        "a 'public' ownership row must NOT declassify an already group-private \
         claim — that is a widening, and a compat shim must not be able to \
         disclose content"
    );

    // The attempt is still LEDGERED, so a refused widening is visible rather
    // than silent.
    let logged: i64 =
        sqlx::query_scalar("SELECT count(*) FROM tenancy_transcription_log WHERE node_id = $1")
            .bind(claim)
            .fetch_one(&pool)
            .await
            .expect("count ledger rows");
    assert_eq!(logged, 1, "the refused widening must still be recorded");
}

/// The converse: a `'public'` row on a claim that IS public still stamps the
/// owner, so D2 ("a public row still has an OWNER") holds.
///
/// Without this, the no-widening guard above could be satisfied by a shim that
/// simply ignores the `'public'` arm entirely.
#[sqlx::test(migrations = "../../migrations")]
async fn a_public_ownership_row_still_stamps_the_owner_on_a_public_claim(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "owner").await;
    let claim = insert_undeclared_claim(&pool, agent, "public claim").await;
    assert_eq!(
        tenancy_of(&pool, "claims", claim).await,
        (WORLD, "public".to_string()),
        "precondition: the claim starts on 062's world default"
    );

    sqlx::query(
        "INSERT INTO ownership (node_id, node_type, partition_type, owner_id) \
         VALUES ($1, 'claim', 'public', $2)",
    )
    .bind(claim)
    .bind(agent)
    .execute(&pool)
    .await
    .expect("write ownership");

    assert_eq!(
        tenancy_of(&pool, "claims", claim).await,
        (group, "public".to_string()),
        "D2: a public row still has an OWNER — world is a shape constant, not an \
         owner. Visibility stays 'public'; only the owner is filled in."
    );
}

// =============================================================================
// Arm (b) — the endpoint meet, and its no-widening gate
// =============================================================================

/// An edge touching a group-private claim is itself group-private.
///
/// This is the structural leak the endpoint meet exists to close: an edge
/// ATTESTS THAT ITS ENDPOINT EXISTS and stands in a named relationship to the
/// other one. A `('public', world)` edge onto a private claim leaks the private
/// claim's existence, its id, and the relationship type — without ever
/// returning its content, so no content-redaction test would notice.
#[sqlx::test(migrations = "../../migrations")]
async fn an_edge_onto_a_group_private_claim_is_stamped_group_private(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "author").await;
    let public_claim = fixture::seed_public_claim(&pool, agent, "public").await;
    let private_claim = fixture::seed_group_claim(&pool, agent, group, "private").await;

    // Bound explicitly as PUBLIC, exactly as an unpatched call site would.
    let edge: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            visibility, owner_group_id) \
         VALUES ($1, 'claim', $2, 'claim', 'SUPPORTS', 'public', $3) RETURNING id",
    )
    .bind(public_claim)
    .bind(private_claim)
    .bind(WORLD)
    .fetch_one(&pool)
    .await
    .expect("insert edge");

    let (owner, vis) = tenancy_of(&pool, "edges", edge).await;
    assert_eq!(
        (owner, vis.as_str()),
        (group, "group"),
        "arm (b) must stamp the MEET: an edge onto a group-private claim is \
         group-private, whatever the writer bound"
    );
}

/// **Arm (b) never widens.** An edge EXPLICITLY declared `('group', G)` between
/// two PUBLIC endpoints keeps its declaration.
///
/// # Correction to the plan
///
/// Plan §3/066 makes arm (b) unconditional — it assigns the meet over whatever
/// the writer bound, with no equivalent of arm (a)'s "still equals the world
/// default" gate. That silently rewrites a declared-private edge to
/// `('public', world)`.
///
/// Found by a red test, not by reading:
/// `epigraph-api/tests/structural_features_authz.rs::owner_sees_the_whole_subgraph_and_a_stranger_only_its_public_part`
/// seeds exactly this edge and asserts a stranger cannot count it; under the
/// plan's form the stranger saw it.
///
/// The derivation is unchanged for an UNDECLARED edge, so the plan's "edges need
/// no call-site edits" property survives intact — pinned by the test above,
/// which binds the world default and gets the meet.
#[sqlx::test(migrations = "../../migrations")]
async fn arm_b_does_not_widen_an_explicitly_private_edge(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "author").await;
    let a = fixture::seed_public_claim(&pool, agent, "public a").await;
    let b = fixture::seed_public_claim(&pool, agent, "public b").await;

    let edge: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            visibility, owner_group_id) \
         VALUES ($1, 'claim', $2, 'claim', 'RELATES_TO', 'group', $3) RETURNING id",
    )
    .bind(a)
    .bind(b)
    .bind(group)
    .fetch_one(&pool)
    .await
    .expect("insert edge");

    let (owner, vis) = tenancy_of(&pool, "edges", edge).await;
    assert_eq!(
        (owner, vis.as_str()),
        (group, "group"),
        "an edge explicitly declared ('group', G) must NOT be widened to \
         ('public', world) just because both its endpoints are public"
    );
}

// =============================================================================
// Arm (d) — the edge MEET on the UPDATE path
// =============================================================================

/// **Arm (d) recomputes the meet from BOTH endpoints; it does not copy the one
/// that changed.**
///
/// An earlier revision of migration 070 wrote
/// `UPDATE edges SET (owner_group_id, visibility) = (ch.owner_group_id,
/// ch.visibility) FROM changed ch WHERE …` — which never reads the other
/// endpoint. Declassifying ONE endpoint then rewrote the edge to
/// `('public', world)` while the other stayed group-private, publishing an edge
/// that attests a private claim exists and stands in a named relationship. That
/// is exactly the structural leak arm (b) exists to close, reached through the
/// UPDATE door, and this file already asserts the INSERT side of the same rule
/// in [`an_edge_onto_a_group_private_claim_is_stamped_group_private`].
#[sqlx::test(migrations = "../../migrations")]
async fn arm_d_recomputes_the_meet_rather_than_copying_the_changed_endpoint(pool: PgPool) {
    let (agent_a, group_a) = fixture::seed_agent_with_group(&pool, "a").await;
    let (agent_b, group_b) = fixture::seed_agent_with_group(&pool, "b").await;
    let a = fixture::seed_group_claim(&pool, agent_a, group_a, "A").await;
    let b = fixture::seed_group_claim(&pool, agent_b, group_b, "B").await;

    // Both endpoints are in group_a to start, so arm (b) can stamp the edge
    // without hitting its cross-group RAISE.
    sqlx::query("UPDATE claims SET owner_group_id = $1 WHERE id = $2")
        .bind(group_a)
        .bind(b)
        .execute(&pool)
        .await
        .expect("park B in group_a");

    let edge: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'SUPPORTS') RETURNING id",
    )
    .bind(a)
    .bind(b)
    .fetch_one(&pool)
    .await
    .expect("insert edge");
    assert_eq!(
        tenancy_of(&pool, "edges", edge).await,
        (group_a, "group".into())
    );

    // Move B to its own group. The edge must FOLLOW the surviving private
    // endpoint, not the world default.
    sqlx::query("UPDATE claims SET owner_group_id = $1 WHERE id = $2")
        .bind(group_b)
        .bind(b)
        .execute(&pool)
        .await
        .expect("move B");

    // Now declassify A alone. B is still group-private, so the MEET is
    // ('group', group_b) — NOT ('public', world).
    sqlx::query("UPDATE claims SET owner_group_id = $1, visibility = 'public' WHERE id = $2")
        .bind(WORLD)
        .bind(a)
        .execute(&pool)
        .await
        .expect("declassify A");

    let (owner, vis) = tenancy_of(&pool, "edges", edge).await;
    assert_eq!(
        (owner, vis.as_str()),
        (group_b, "group"),
        "declassifying ONE endpoint must not widen an edge whose other endpoint \
         is still group-private: a public edge onto a private claim discloses \
         that the claim exists and stands in a named relationship"
    );
}

/// **Arm (d) leaves a cross-group edge UNCHANGED rather than picking a side —
/// and does not RAISE.**
///
/// Measured on a throwaway database against the earlier one-endpoint form: a
/// single statement privatizing two claims into DIFFERENT personal groups made
/// the edge take whichever join row Postgres matched first, so one group's
/// members could see an edge whose far endpoint was the other group's private
/// claim. Arm (b) RAISEs on that configuration at INSERT; the UPDATE path was
/// silently picking a winner.
///
/// It must not raise either, and that asymmetry with arm (b) is deliberate:
/// arm (d) fires on EVERY `claims` UPDATE, including this series' own backfill,
/// so an exception here is a total write outage on any privatization that
/// happens to touch a cross-group edge. Stale-but-still-private is fail-closed;
/// PR-13's migration 072 resolves it properly with `co_owner_group_id`.
#[sqlx::test(migrations = "../../migrations")]
async fn arm_d_leaves_a_cross_group_edge_unchanged_rather_than_picking_a_side(pool: PgPool) {
    let (agent_a, group_a) = fixture::seed_agent_with_group(&pool, "a").await;
    let (agent_b, group_b) = fixture::seed_agent_with_group(&pool, "b").await;
    let a = fixture::seed_public_claim(&pool, agent_a, "A").await;
    let b = fixture::seed_public_claim(&pool, agent_b, "B").await;

    let edge: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'SUPPORTS') RETURNING id",
    )
    .bind(a)
    .bind(b)
    .fetch_one(&pool)
    .await
    .expect("insert edge between two public claims");
    assert_eq!(
        tenancy_of(&pool, "edges", edge).await,
        (WORLD, "public".into()),
        "arm (b): two public endpoints meet at ('public', world)"
    );

    // ONE statement privatizing both into DIFFERENT groups.
    sqlx::query(
        "UPDATE claims SET owner_group_id = CASE WHEN id = $1 THEN $2 ELSE $3 END, \
                           visibility = 'group' \
          WHERE id IN ($1, $4)",
    )
    .bind(a)
    .bind(group_a)
    .bind(group_b)
    .bind(b)
    .execute(&pool)
    .await
    .expect("a cross-group privatization must not raise from arm (d)");

    let (owner, vis) = tenancy_of(&pool, "edges", edge).await;
    assert_eq!(
        (owner, vis.as_str()),
        (WORLD, "public"),
        "with no computable meet the edge must be LEFT ALONE, not assigned to \
         whichever endpoint the planner joined first — that would let one \
         group see an edge whose far endpoint is the other group's private claim"
    );
    assert_ne!(owner, group_a);
    assert_ne!(owner, group_b);
}

// =============================================================================
// Migration 071 — the shim never TRANSFERS, not only never widens
// =============================================================================

/// **A stranger cannot move a group-private node into its own group with an
/// `ownership` row.**
///
/// # The composition this closes, and why it is new in PR-12
///
/// `require_declassify_authority` (both `routes/ownership.rs` and
/// `tools/perspectives.rs`) resolves `(None, Some(requested)) if requested ==
/// principal.id()` to ALLOW — a node with no `ownership` row may be claimed to
/// yourself. PR-11 filed that as a public→private denial of service, harmless
/// while the row landed in an ACL table nothing read.
///
/// PR-12 makes that write land on the LIVE tenancy columns, and PR-12 also
/// MANUFACTURES the victims: `ClaimRepository::supersede` writes no `ownership`
/// row, so arm (a) stamps every superseded private claim's successor
/// `('group', G)` with `owner_of_record = None` — i.e. self-claimable. Evidence
/// is worse: no production path ever gives it an `ownership` row, arm (c)
/// stamps it from its parent, and `evidence.raw_content` is a full second copy
/// of the claim text. `node_type` is caller-supplied and unvalidated,
/// `ownership.node_id` carries no FK, and MCP `assign_ownership` is gated at
/// `claims:write`, not `claims:admin`.
///
/// A guard that blocked only group→public would leave all of that open. This
/// asserts the transfer half.
#[sqlx::test(migrations = "../../migrations")]
async fn the_shim_refuses_to_transfer_a_private_node_into_a_strangers_group(pool: PgPool) {
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "owner").await;
    let (attacker, _) = fixture::seed_agent_with_group(&pool, "attacker").await;
    let claim = fixture::seed_group_claim(&pool, owner, owner_group, "victim").await;
    let evidence = insert_evidence(&pool, claim, "victim-evidence").await;
    assert_eq!(
        tenancy_of(&pool, "evidence", evidence).await,
        (owner_group, "group".into()),
        "precondition: arm (c) stamped the evidence from its parent claim"
    );

    // The self-claim `require_declassify_authority` permits: no prior
    // `ownership` row, owner_id == the caller.
    for (node, node_type) in [(claim, "claim"), (evidence, "evidence")] {
        sqlx::query(
            "INSERT INTO ownership (node_id, node_type, partition_type, owner_id) \
             VALUES ($1, $2, 'private', $3)",
        )
        .bind(node)
        .bind(node_type)
        .bind(attacker)
        .execute(&pool)
        .await
        .expect("the shim must DENY by matching no row, not by raising");
    }

    assert_eq!(
        tenancy_of(&pool, "claims", claim).await,
        (owner_group, "group".into()),
        "a stranger's `ownership` row must not move a group-private claim into \
         its own group — that is a confidentiality break, not the denial of \
         service PR-11 filed"
    );
    assert_eq!(
        tenancy_of(&pool, "evidence", evidence).await,
        (owner_group, "group".into()),
        "and evidence is the sharper case: raw_content is a full second copy of \
         the claim text, and no production path ever gives it an ownership row"
    );
}

/// The transfer guard has a membership escape hatch, and it is REQUIRED.
///
/// A bare "never change group" rule would also forbid the LEGITIMATE
/// re-declaration migration 071's own header describes — private → community,
/// which the MCP `update_partition` path and two fixtures perform. A declarer
/// who is a live member of the node's CURRENT group is a co-owner expressing
/// the existing owners' intent, which is what a transcriber is for; a stranger
/// is not. This is the half that keeps the guard from being a wall.
#[sqlx::test(migrations = "../../migrations")]
async fn a_live_member_of_the_current_group_may_still_re_declare(pool: PgPool) {
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "owner").await;
    let claim = fixture::seed_group_claim(&pool, owner, owner_group, "mine").await;

    // A second personal group for the same owner, with a live membership, is
    // the simplest stand-in for "a group the declarer is already in".
    let second: Uuid = sqlx::query_scalar(
        "INSERT INTO groups (display_name, did_key, public_key, kind, created_by_agent_id) \
         VALUES ('second', 'did:epigraph:personal:' || $1::text, ''::bytea, 'personal', $1) \
         RETURNING id",
    )
    .bind(owner)
    .fetch_one(&pool)
    .await
    .expect("seed a canonical personal group for the owner");
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'admin')",
    )
    .bind(second)
    .bind(owner)
    .execute(&pool)
    .await
    .expect("seed membership");

    sqlx::query(
        "INSERT INTO ownership (node_id, node_type, partition_type, owner_id) \
         VALUES ($1, 'claim', 'private', $2)",
    )
    .bind(claim)
    .bind(owner)
    .execute(&pool)
    .await
    .expect("insert ownership");

    let (group, vis) = tenancy_of(&pool, "claims", claim).await;
    assert_eq!(vis, "group");
    assert_eq!(
        group, second,
        "the owner IS a live member of the claim's current group, so the shim \
         must honour its re-declaration and resolve to the canonical personal \
         group — refusing here would break the private → community path 071's \
         header describes"
    );
}

/// The OWNER OF RECORD may move its own node between groups — the second
/// escape hatch, and the one a red test found.
///
/// # Why the membership hatch alone is not enough
///
/// `community_partition.rs::demoting_out_of_community_clears_the_gate` demotes a
/// community-partitioned claim to `private`. The shim must move it from the
/// community group to the OWNER's personal group — and the owner is
/// deliberately NOT projected into the community group
/// (`community_owner_who_is_not_a_member_is_redacted` pins that as a reviewed
/// decision), so hatch (i) does not cover it.
///
/// Blocking it would be a WIDENING dressed as strictness: the demoted node
/// would stay readable by every member of a community it has just left, which
/// is the exact failure mode the guard exists against.
///
/// The attack stays closed because it is an INSERT. PR-11's
/// `require_declassify_authority` permits a self-claim ONLY when there is no
/// owner of record, so an attacker's write can never be `TG_OP = 'UPDATE'` with
/// `OLD.owner_id = NEW.owner_id`; and with an owner of record present, that same
/// function denies `(Some(victim), Some(attacker))` before the trigger runs.
#[sqlx::test(migrations = "../../migrations")]
async fn the_owner_of_record_may_move_its_own_node_between_groups(pool: PgPool) {
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "owner").await;
    let (member, _) = fixture::seed_agent_with_group(&pool, "member").await;

    // A community whose group has a live member who is NOT the owner — the
    // shape `demoting_out_of_community_clears_the_gate` builds.
    let community: Uuid =
        sqlx::query_scalar("INSERT INTO communities (name) VALUES ('demotable') RETURNING id")
            .fetch_one(&pool)
            .await
            .expect("seed community");
    sqlx::query(
        "INSERT INTO groups (id, display_name, did_key, public_key, kind) \
         VALUES ($1, 'demotable', 'did:epigraph:community:' || $1::text, ''::bytea, 'community')",
    )
    .bind(community)
    .execute(&pool)
    .await
    .expect("project the community group");
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'reader')",
    )
    .bind(community)
    .bind(member)
    .execute(&pool)
    .await
    .expect("seed the community membership");

    let claim = insert_undeclared_claim(&pool, owner, "to be demoted").await;
    sqlx::query(
        "INSERT INTO ownership (node_id, node_type, partition_type, owner_id, community_id) \
         VALUES ($1, 'claim', 'community', $2, $3)",
    )
    .bind(claim)
    .bind(owner)
    .bind(community)
    .execute(&pool)
    .await
    .expect("assign to the community");
    assert_eq!(
        tenancy_of(&pool, "claims", claim).await,
        (community, "group".into()),
        "precondition: the claim is owned by the COMMUNITY group, which the owner \
         is deliberately not a member of"
    );

    // The demotion: an UPDATE of the existing row, by the same owner_id.
    sqlx::query(
        "UPDATE ownership SET partition_type = 'private', community_id = NULL \
          WHERE node_id = $1",
    )
    .bind(claim)
    .execute(&pool)
    .await
    .expect("demote");

    let (group, vis) = tenancy_of(&pool, "claims", claim).await;
    assert_eq!(
        (group, vis.as_str()),
        (owner_group, "group"),
        "the owner of record must be able to move its own node out of a group it \
         is not a member of — refusing leaves the demoted node readable by every \
         member of the community it has just left, which is a WIDENING"
    );
    assert_ne!(
        group, community,
        "and it must actually LEAVE the community group, not merely be relabelled"
    );
}
