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
//! **CORRECTION, MEASURED — the paragraph that stood here said arm (d)'s 42501
//! could never fire because CI connects as a superuser. That was a
//! mis-diagnosis, and it had already been contradicted by the sentence on
//! [`propagation_function_is_owned_by_the_maintenance_role`] two screens
//! below.** `epigraph_propagate_tenancy` is `SECURITY DEFINER`, so inside its
//! frame `current_user` is the function OWNER, not whoever connected.
//! `epigraph_definer_bypass()` is `SECURITY INVOKER`, so called from inside
//! that frame it evaluates `pg_has_role(<owner>, 'epigraph_maintenance',
//! 'MEMBER')`. Measured on this host: with the session at
//! `SET SESSION AUTHORIZATION epigraph_app`, a nested definer frame owned by
//! `epigraph_maintenance` still reports `current_user = epigraph_maintenance`
//! and `epigraph_definer_bypass() = true`.
//!
//! Two consequences, and they point in opposite directions from the old text:
//!
//! * Downgrading the CONNECTION — `SET ROLE`, `SET SESSION AUTHORIZATION`, a
//!   dedicated non-superuser login — cannot reach arm (d) at all. The three
//!   non-superuser roles are `NOLOGIN` (migration 060) and, more decisively,
//!   the connecting role is simply not what the predicate reads.
//! * The OWNER is the lever, and it is reachable from a test.
//!   [`propagation_refuses_when_its_definer_frame_is_not_the_maintenance_role`]
//!   re-owns the function to `epigraph_app` inside its own `#[sqlx::test]`
//!   database and drives a real tenancy `UPDATE`, so the refusal now fires
//!   behaviourally rather than being asserted only from the catalog.
//!
//! The catalog assertion in
//! [`propagation_function_is_owned_by_the_maintenance_role`] STAYS and is still
//! the primary instrument: it pins the fact the deploy depends on
//! (`pg_proc.proowner`) without depending on any error path. It was measured to
//! matter — re-owning the function without `GRANT EXECUTE ON FUNCTION
//! epigraph_definer_bypass() TO epigraph_maintenance` produces `permission
//! denied for function epigraph_definer_bypass` on the first batch, and
//! re-owning it to a non-maintenance role makes the assertion return false.
//! That "permission denied" is ALSO SQLSTATE 42501, which is why the
//! behavioural arm discriminates on the message text as well as the code.

mod viewer_fixture;

use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture as fixture;

const WORLD: Uuid = Uuid::nil();

// `insert_legacy_world_claim` lived here until PR-22. It built the pre-074
// `('public', <world group>)` shape, and its only callers were the migration-071
// shim cases deleted below. Removed rather than left behind an `#[allow]`: an
// unused fixture is a fixture nobody is checking.

/// Insert a claim the way an unpatched production call site does — naming
/// neither tenancy column.
///
/// Before migration 074 that meant 062's DEFAULTs supplied the world group and
/// arm (a) counted the write. After 074 it means arm 4: on the harness role
/// (which satisfies `pg_has_role(session_user, 'epigraph_seed', 'MEMBER')`
/// because it is a superuser) the row is stamped `('public', <seed group>)`,
/// and on `epigraph_app` the same statement raises `23502`.
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

/// [`tenancy_of`] widened with `edges.co_owner_group_id` (migration 072).
///
/// Separate from `tenancy_of` rather than replacing it: `co_owner_group_id`
/// exists ONLY on `edges`, and `tenancy_of` is called for `claims`, `evidence`
/// and the derived tables throughout this file.
async fn edge_tenancy_of(pool: &PgPool, id: Uuid) -> (Uuid, String, Option<Uuid>) {
    sqlx::query_as(
        "SELECT owner_group_id, visibility::text, co_owner_group_id FROM edges WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("read edge tenancy: {e}"))
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

/// **INVERTED BY PR-16.** This test used to assert the TRANSITION behaviour:
/// that an undeclared insert bumped `tenancy_undeclared_writes` and landed on
/// `('public', world)`. Its own message named migration 074 as the thing that
/// would turn that into a `23502`, and 074 has now landed.
///
/// What replaced it, and why it is a different shape rather than a tweak:
///
/// * **The counter can no longer be exercised at all on this harness.** Arm 4
///   (`pg_has_role(session_user, 'epigraph_seed', 'MEMBER')`) returns before
///   the counting arm, and a superuser satisfies `pg_has_role` for every role —
///   so on the test connection an undeclared insert is STAMPED, not counted.
///   Under `SET SESSION AUTHORIZATION epigraph_app` it RAISES, so it is not
///   counted there either. There is no role on this host that both reaches the
///   counting arm and can write, because migration 074 deleted that arm.
///
/// * **That is the point, not a gap.** The counter is plan §9.2's week-11b
///   deploy INSTRUMENT: it measures how many undeclared writes are still
///   happening while the defaults are present, so an operator can gate the
///   074 rollout on it being flat at zero. Once 074 is applied the question it
///   answers is settled by construction. `tenancy_gauge.rs` keeps the
///   counter-table→Prometheus half under test; what is no longer test-covered
///   is arm (a) FEEDING it, and that is stated there rather than dropped
///   silently.
///
/// So this now asserts the two things that ARE still true and still regressible:
/// the stamp goes to the seed group (not world — §8.2 A4), and the counter
/// table survives 074 so the deploy instrument can still be read on a database
/// that has not applied it yet.
#[sqlx::test(migrations = "../../migrations")]
async fn an_undeclared_insert_takes_the_seed_arm_after_074(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "author").await;

    let seed: Uuid = sqlx::query_scalar("SELECT id FROM groups WHERE kind = 'seed'")
        .fetch_one(&pool)
        .await
        .expect("the seed group is seeded by migration 062");

    let id = insert_undeclared_claim(&pool, agent, "undeclared").await;

    let (owner, vis) = tenancy_of(&pool, "claims", id).await;
    assert_eq!(
        (owner, vis.as_str()),
        (seed, "public"),
        "after migration 074 an undeclared insert on a seed-satisfying role must be \
         STAMPED with the seed group, not the world group. Stamping world would make \
         plan §8.2 A4 (count of world-owned claims is 0) unsatisfiable, and would \
         make the deferred strong CHECK (owner_group_id <> world) permanently \
         unshippable."
    );
    assert_ne!(owner, WORLD);

    // The counter table itself must survive 074: the week-11b gate is read on
    // databases that have NOT yet applied 074, and dropping the table here
    // would silently remove the evidence that gate depends on.
    let counter_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
                         WHERE n.nspname = 'public' AND c.relname = 'tenancy_undeclared_writes')",
    )
    .fetch_one(&pool)
    .await
    .expect("counter table probe");
    assert!(
        counter_exists,
        "tenancy_undeclared_writes must outlive migration 074 — it is plan §9.2's \
         week-11b deploy gate, read BEFORE 074 is applied"
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

    // PR-16 changed WHICH arm refuses, and the assertion moved off the prose
    // onto the SQLSTATE because of it. Before migration 074 the only guard was
    // 070 arm (c) — AFTER STATEMENT — whose message is "N row(s) in <table>
    // reference a nonexistent parent claim". 074 adds
    // `epigraph_derived_require_tenancy`, a BEFORE ROW trigger that has to look
    // the parent up anyway in order to inherit its tenancy, so the orphan is
    // caught one step earlier and its message names the ROW rather than the
    // statement.
    //
    // That is a better diagnosis, not a regression, and the contract both arms
    // share is the SQLSTATE — which is what the API/MCP layer maps to a 4xx.
    // Matching on message text made this test a hostage to which arm fired
    // first.
    assert_eq!(
        err.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("23503"),
        "an orphan claim_id must be refused as a foreign-key violation, by \
         whichever arm reaches it first; got: {err}"
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
/// # Why a catalog assertion, and what it is now paired with
///
/// `epigraph_definer_bypass()` keys on `current_user`, which inside a SECURITY
/// DEFINER frame is the function OWNER — so `pg_proc.proowner` is the fact the
/// deploy actually depends on, and reading it is independent of every error
/// path, every role grant and every trigger firing condition. That is why this
/// stays the primary instrument.
///
/// It is now PAIRED with
/// [`propagation_refuses_when_its_definer_frame_is_not_the_maintenance_role`],
/// which re-owns the function inside its own per-test database and shows the
/// refusal actually raises. A catalog read alone cannot tell you the RAISE is
/// still wired; the behavioural arm alone cannot tell you production's owner is
/// right. Neither replaces the other.
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
        // `epigraph_ownership_transcribe` was the sixth name until PR-22.
        // Migration 084 drops it with the table its trigger fired on, so an
        // entry here would assert the existence of a function the migrator has
        // just removed.
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
             epigraph_definer_bypass() is false and every propagation raises \
             42501. That is not hypothetical: \
             propagation_refuses_when_its_definer_frame_is_not_the_maintenance_role \
             reproduces exactly this state on purpose."
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

/// Arm (d)'s refusal FIRES when the definer frame is not the maintenance role.
///
/// # What was wrong with the previous account of this
///
/// This suite recorded for four PRs that the 42501 refusal "can never fire,
/// whoever owns the function", because CI connects as a superuser and
/// `pg_has_role` is true of a superuser for every role. That reasoning applies
/// to a `SECURITY INVOKER` body. `epigraph_propagate_tenancy` is `SECURITY
/// DEFINER` (migration 070), so `current_user` inside it is the OWNER and the
/// connecting role never appears in the predicate at all. The recorded
/// conclusion was therefore both wrong and load-bearing: it is why no
/// behavioural arm was ever written.
///
/// Measured on this host before writing this test: with the session at
/// `SET SESSION AUTHORIZATION epigraph_app`, a nested `SECURITY DEFINER` frame
/// owned by `epigraph_maintenance` reports `current_user = epigraph_maintenance`
/// and `epigraph_definer_bypass() = true`. Downgrading the connection cannot
/// reach the arm; re-owning the function is the only lever, and it needs no
/// migration, no deploy-time grant and no second CI container — `#[sqlx::test]`
/// gives this arm a private database, so the re-own is local to it and the
/// catalog assertion above, which runs against its own database, cannot see it.
///
/// # Why both directions are asserted here
///
/// A refusal test that only shows "the UPDATE failed" proves nothing: the
/// trigger stack in front of arm (d) has several other RAISEs, and
/// `permission denied for function epigraph_definer_bypass` — the failure mode
/// of re-owning without re-granting — is ALSO SQLSTATE 42501. So this asserts
/// the code AND the message, and it first asserts the same UPDATE SUCCEEDS
/// under the shipped owner, so a green run cannot come from a statement that
/// was broken for an unrelated reason.
///
/// The UPDATE narrows (`public` → `group`) rather than widening, because
/// `epigraph_claims_block_widening` refuses the declassifying direction outright
/// and would mask arm (d) entirely. It also changes tenancy for real: migration
/// 070's firing gate returns before the assertion when the new
/// `(owner_group_id, visibility)` is not distinct from the old, so a no-op
/// UPDATE would pass this test without arm (d) ever being evaluated.
#[sqlx::test(migrations = "../../migrations")]
async fn propagation_refuses_when_its_definer_frame_is_not_the_maintenance_role(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "owner").await;

    // Two public claims: one for the positive direction, one for the refusal.
    // Separate rows so the first UPDATE's committed effect cannot make the
    // second one a no-op that the firing gate short-circuits.
    let ok_claim = insert_undeclared_claim(&pool, agent, "reaches arm (d) as shipped").await;
    let refused_claim = insert_undeclared_claim(&pool, agent, "reaches arm (d) re-owned").await;
    let ok_evidence = insert_evidence(&pool, ok_claim, "ev ok").await;
    let refused_evidence = insert_evidence(&pool, refused_claim, "ev refused").await;

    // POSITIVE DIRECTION, under the shipped owner.
    sqlx::query("UPDATE claims SET owner_group_id = $1, visibility = 'group' WHERE id = $2")
        .bind(group)
        .bind(ok_claim)
        .execute(&pool)
        .await
        .expect("privatizing a claim must succeed while epigraph_maintenance owns the function");
    let (ev_group, ev_vis) = tenancy_of(&pool, "evidence", ok_evidence).await;
    assert_eq!(
        (ev_group, ev_vis.as_str()),
        (group, "group"),
        "the positive direction must actually propagate, or the refusal below \
         is being compared against a path that never worked"
    );

    // Now make the frame a non-member. `epigraph_app` is the role production
    // connects as, and it is NOT a member of epigraph_maintenance — which is
    // precisely the deploy mistake the catalog assertion above exists to catch.
    sqlx::query("ALTER FUNCTION public.epigraph_propagate_tenancy() OWNER TO epigraph_app")
        .execute(&pool)
        .await
        .expect("re-own the propagation function");

    let err =
        sqlx::query("UPDATE claims SET owner_group_id = $1, visibility = 'group' WHERE id = $2")
            .bind(group)
            .bind(refused_claim)
            .execute(&pool)
            .await
            .expect_err(
                "arm (d) must REFUSE once its definer frame is not a member of \
             epigraph_maintenance. A success here means the assertion is no \
             longer wired and every deploy-owner regression is invisible.",
            );

    let db_err = err.as_database_error().expect("a database error");
    assert_eq!(
        db_err.code().as_deref(),
        Some("42501"),
        "arm (d) raises USING ERRCODE = '42501'; got {db_err:?}"
    );
    assert!(
        db_err
            .message()
            .contains("propagation requires a maintenance-role"),
        "the refusal must be arm (d)'s own RAISE, not another 42501 on the way \
         to it — `permission denied for function epigraph_definer_bypass` \
         carries the same SQLSTATE and would mean the arm was never evaluated. \
         Got: {}",
        db_err.message()
    );

    // EFFECT, not just the status: the refusal aborted the whole statement, so
    // neither the claim nor its derived row moved.
    let (claim_group, claim_vis) = tenancy_of(&pool, "claims", refused_claim).await;
    assert_eq!(
        claim_vis, "public",
        "the refused UPDATE must leave the claim's visibility untouched"
    );
    assert_ne!(
        claim_group, group,
        "the refused UPDATE must leave the claim's owner_group_id untouched"
    );
    let (ev_group, ev_vis) = tenancy_of(&pool, "evidence", refused_evidence).await;
    assert_eq!(
        (ev_group, ev_vis.as_str()),
        (claim_group, claim_vis.as_str()),
        "the derived row must still agree with its claim — a partial \
         propagation would be worse than a refusal"
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
                              'claims_propagate_tenancy') \
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
                              'claims_propagate_tenancy') \
                 OR t.tgname LIKE '%\\_inherit\\_tenancy')",
    )
    .fetch_one(&pool)
    .await
    .expect("count tenancy triggers");
    // 20 SINCE PR-22, and the fourth name is gone from both queries above.
    // `ownership_transcribe` (migration 071) went with the table migration 084
    // drops. Keeping the name in the IN-list while lowering the count would have
    // made the vacuity guard self-fulfilling — it would still be looking for a
    // trigger that cannot exist.
    assert_eq!(
        armed, 20,
        "expected 20 tenancy triggers (3 named + 17 claim-derived inheritors); \
         found {armed}. A changed count means arm (c)'s table set moved."
    );
}

// =============================================================================
// Migration 071 — the ownership compat shim. DELETED IN PR-22.
// =============================================================================
//
// Eleven cases lived here and in a second block at the end of this file, and
// every one of them wrote a row into `public.ownership` and asserted what
// migration 071's `ownership_transcribe` trigger did with it:
//
//   a_private_ownership_row_transcribes_into_the_tenancy_columns
//   an_owner_with_no_personal_group_gets_one_minted
//   a_dangling_community_reference_falls_back_to_the_owner_not_a_raise
//   a_community_partition_projects_the_group_and_its_members
//   an_empty_community_falls_back_to_the_owner_rather_than_a_black_hole
//   the_transcription_ledger_is_last_write_wins
//   a_public_ownership_row_cannot_declassify_a_group_private_claim
//   a_public_ownership_row_still_stamps_the_owner_on_a_public_claim
//   the_shim_refuses_to_transfer_a_private_node_into_a_strangers_group
//   a_live_member_of_the_current_group_may_still_re_declare
//   the_owner_of_record_may_move_its_own_node_between_groups
//
// Migration 084 drops the table AND the trigger AND
// `public.epigraph_ownership_transcribe()`. There is no relation left to write
// and no body left to fire, so these are removed rather than re-pointed: the
// shim was a COMPATIBILITY layer with an announced end, and this is it.
//
// WHAT WAS BEING PROTECTED, AND WHERE IT IS NOW. The shim's job was to keep a
// legacy `ownership` write from diverging from the tenancy columns — including
// the two guards the transfer block existed for (never widen `group` to
// `public`; never move a node into a group its current owners are not in). With
// the table gone there is no writer to guard: the tenancy columns are the only
// declaration, and migration 070's arm (a) / `claims_block_widening` and 074's
// per-table `_require_tenancy` triggers are what enforce them. Those are
// exercised by the arm (a) / arm (c) / arm (d) cases above and by
// `tenancy_required.rs`, none of which mention `ownership`.
//
// The transcription LEDGER is not deleted with them. `tenancy_transcription_log`
// survives 084 and is the only surviving record of what the dropped rows
// declared; migration 084's second pre-flight reads it, and
// `retire_ownership_preflight.rs` is what asserts the pre-flight refuses an
// untranscribed non-public row.

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

    // THE INTERMEDIATE, ASSERTED (PR-13). Before migration 072 this step left
    // the edge unchanged at `group_a` and nothing checked it, so the test
    // passed whatever arm (d) did here. It is the only point in this file where
    // the co-owner CASE's SIDE ORDERING is observable: A is in `group_a` and is
    // the SOURCE, B is in `group_b` and is the TARGET, and the CASE is written
    // `owner := s.g, co_owner := t.g`.
    assert_eq!(
        edge_tenancy_of(&pool, edge).await,
        (group_a, "group".to_string(), Some(group_b)),
        "moving one endpoint into a second group must co-own the edge, not \
         leave it stale at the first group"
    );

    // Now declassify A alone. B is still group-private, so the MEET is
    // ('group', group_b) — NOT ('public', world).
    //
    // PR-16: this needs `epigraph.allow_declassify` now. Migration 074 adds
    // `claims_block_widening`, which refuses a group→public UPDATE unless the
    // admin declassification surface's GUC is set. The GUC is SESSION-scoped,
    // so it and the UPDATE must ride the SAME connection — issuing the SET on
    // the pool would land on an arbitrary one and the UPDATE would be refused
    // intermittently.
    {
        use sqlx::Executor;
        let mut conn = pool.acquire().await.expect("acquire");
        conn.execute("SET epigraph.allow_declassify = 'yes'")
            .await
            .expect("set the admin declassification GUC");
        sqlx::query("UPDATE claims SET owner_group_id = $1, visibility = 'public' WHERE id = $2")
            .bind(WORLD)
            .bind(a)
            .execute(&mut *conn)
            .await
            .expect("declassify A");
    }

    let (owner, vis, co) = edge_tenancy_of(&pool, edge).await;
    assert_eq!(
        (owner, vis.as_str()),
        (group_b, "group"),
        "declassifying ONE endpoint must not widen an edge whose other endpoint \
         is still group-private: a public edge onto a private claim discloses \
         that the claim exists and stands in a named relationship"
    );
    assert_eq!(
        co, None,
        "the meet collapsed to a single group, so the co-owner must be CLEARED. \
         Leaving group_b in co_owner_group_id here would make the row \
         (owner = group_b, co_owner = group_b) and raise 23514 from \
         edges_co_owner_shape — inside a statement-level AFTER UPDATE on claims, \
         i.e. a write outage on privatization"
    );
}

// =============================================================================
// Migration 072 — the three-CASE meet, read from the catalog
// =============================================================================

/// **PR-13 acceptance: `epigraph_propagate_tenancy`'s body after 072 contains
/// the three-CASE meet — asserted by reading `pg_proc.prosrc`.**
///
/// The plan says to read the catalog rather than the migration text, and the
/// reason is recorded in `progress.json`: migration 070 names this function
/// `epigraph_propagate_tenancy` with a zero-argument trigger signature
/// *specifically* so this assertion can find it — "a hard downstream contract,
/// not a naming preference". Reading the `.sql` file would prove only that
/// somebody typed the SQL, not that the LIVE function is that SQL; the whole
/// class of bug 072 exists to close (070's prose describing one body while
/// another was installed) is invisible to a file-text assertion.
///
/// # Why this is paired with a behavioural assertion
///
/// A keyword count is a weak oracle on its own — a body could contain three
/// `CASE`s and still compute the wrong meet, and prose in the body's own
/// comments can inflate the count (the comment in 072 says "three CASE
/// expressions", which is why this counts `CASE WHEN` and not `CASE`). The
/// structural checks below are therefore paired with
/// `arm_d_co_owns_a_cross_group_edge_rather_than_picking_a_side` and with
/// `privatization_boundary.rs`, which exercise the same body end to end.
#[sqlx::test(migrations = "../../migrations")]
async fn arm_d_body_carries_the_three_case_meet_over_co_ownership(pool: PgPool) {
    let src: String = sqlx::query_scalar(
        "SELECT prosrc FROM pg_proc \
          WHERE proname = 'epigraph_propagate_tenancy' \
            AND pronamespace = 'public'::regnamespace",
    )
    .fetch_one(&pool)
    .await
    .expect(
        "epigraph_propagate_tenancy must exist under exactly this name — \
         migration 070 chose the name for this assertion",
    );

    assert_eq!(
        src.matches("CASE WHEN").count(),
        3,
        "the edges UPDATE must carry THREE CASE expressions — owner_group_id, \
         visibility and co_owner_group_id. Migration 070's body had two and no \
         way to express a second owner.\n\n{src}"
    );
    assert!(
        src.contains("co_owner_group_id = m.co"),
        "the edges UPDATE must ASSIGN the third CASE; computing it and not \
         writing it is the shape of the divergence 072 exists to end.\n\n{src}"
    );
    assert!(
        !src.contains("ELSE NULL END AS g"),
        "070's `ELSE NULL` sentinel on the owner CASE — 'no computable meet, \
         leave the row alone' — must be GONE. It is what made a cross-group \
         edge stale-but-private, and 072 replaces it with `ELSE s.g` plus a \
         co-owner.\n\n{src}"
    );
    // The two guards 070 added against measured leaks, still present.
    assert!(
        src.contains("NOT (e.visibility = 'group' AND m.v = 'public')"),
        "arm (d)'s no-widening guard must survive the replacement: without it a \
         declassification re-widens an explicitly private edge, which \
         `structural_features_authz.rs` measured.\n\n{src}"
    );
    assert!(
        src.contains("IS DISTINCT FROM (m.g, m.v, m.co)"),
        "the idempotence guard must compare the whole TRIPLE; on the pair alone \
         a co-ownership-only change would not be written.\n\n{src}"
    );
    // Arm (d) must never raise — see this file's arm (d) tests for why.
    assert!(
        !src.contains("edge spans groups"),
        "arm (b)'s cross-group RAISE must not have been copied into arm (d), \
         which fires on every claims UPDATE.\n\n{src}"
    );
}

/// **Migration 072 removed arm (b)'s cross-group RAISE, and that is the window
/// this PR closes.**
///
/// 070's own comment (070:210-218) says the RAISE "becomes reachable once
/// migration 071's transcription makes two claims with DIFFERENT owners
/// genuinely ('group', G), at which point a cross-owner link_epistemic /
/// link_hierarchical / decomposition edge hard-fails", and names 072 as the
/// fix. No test pinned the RAISE, so nothing would have gone red if 072 had
/// silently left it in place. This pins its ABSENCE from the live body.
///
/// The session-membership hatch goes with it. It was unsatisfiable in
/// production for two independent reasons — for personal groups one principal
/// can never be a live member of two, and every production edge writer reaches
/// this trigger on a bare `&PgPool` where `epigraph_session_groups()` is empty
/// — so its removal takes away nothing that ever fired. Write-side
/// authorization is PR-16's, and `locked_decisions.rs` pins that split.
#[sqlx::test(migrations = "../../migrations")]
async fn arm_b_no_longer_raises_on_a_cross_group_edge(pool: PgPool) {
    let src: String = sqlx::query_scalar(
        "SELECT prosrc FROM pg_proc \
          WHERE proname = 'epigraph_edges_tenancy' \
            AND pronamespace = 'public'::regnamespace",
    )
    .fetch_one(&pool)
    .await
    .expect("epigraph_edges_tenancy must exist");

    assert!(
        !src.contains("RAISE EXCEPTION"),
        "arm (b) must not raise: a cross-group edge is expressible as of 072.\n\n{src}"
    );
    assert!(
        !src.contains("epigraph_session_groups"),
        "the session-membership hatch is write-side AUTHORIZATION, which is \
         PR-16's; it never fired here (personal groups make it unsatisfiable, \
         and edge writers use a bare pool with no GUCs).\n\n{src}"
    );
    // The no-widening guard PR-12 added is NOT part of what 072 removes. The
    // plan's printed body drops it; copying that verbatim reinstates a leak
    // `arm_b_does_not_widen_an_explicitly_private_edge` measures.
    assert!(
        src.contains("NOT (sv = 'group' OR tv = 'group')"),
        "arm (b)'s no-widening guard must survive the replacement.\n\n{src}"
    );
    // Every branch must clear or set the co-owner: this trigger also fires on
    // `UPDATE OF source_id, target_id`, so a branch that left NEW.co_owner
    // alone would carry a stale second owner across a re-pointed edge.
    assert_eq!(
        src.matches("NEW.co_owner_group_id := NULL").count(),
        4,
        "the four single-owner branches must each CLEAR co_owner_group_id.\n\n{src}"
    );
    assert!(
        src.contains("NEW.co_owner_group_id := tg"),
        "the cross-group branch must stamp the target's group as co-owner.\n\n{src}"
    );
}

/// **The FIFTH branch — the no-widening early `RETURN NEW` — deliberately does
/// NOT assign `co_owner_group_id`, and that is pinned rather than left implicit.**
///
/// The assertion above counts the four branches that CLEAR the co-owner. By
/// construction it cannot pin the one that does not, and 072's header makes an
/// explicit claim about it: "EVERY BRANCH ASSIGNS co_owner_group_id
/// EXPLICITLY... The single exception is the no-widening early RETURN, which
/// honours the writer's whole declaration; a writer-supplied co-owner there is
/// STRICTER than the meet."
///
/// # Why the behaviour is left as-is rather than changed
///
/// On an INSERT the surviving co-owner is the writer's own, and keeping it is
/// the same direction as the declaration that branch exists to preserve. On an
/// `UPDATE OF source_id, target_id` it is the PRE-EXISTING row's, so the
/// "writer-supplied" argument does not transfer: an edge at
/// `('group', G, co = H)` whose endpoints both become public would keep `co = H`
/// and stay invisible to G-only members. That direction is fail-CLOSED — it
/// hides a row, it does not disclose one — and no single-statement path reaches
/// it: the production re-pointing sites are `claim.rs`'s merge/dedup
/// `UPDATE edges SET source_id = $1` / `SET target_id = $1`, which move ONE
/// endpoint at a time, so the first move takes the `sv = 'public'` or
/// `tv = 'public'` branch and clears the co-owner before both-public is ever
/// reached.
///
/// So this test pins the CURRENT shape. If a future change makes the early
/// RETURN assign, this test is the one to update — not silently, which is the
/// whole point of writing it down.
#[sqlx::test(migrations = "../../migrations")]
async fn arm_b_early_return_is_the_one_branch_that_does_not_touch_the_co_owner(pool: PgPool) {
    let src: String =
        sqlx::query_scalar("SELECT prosrc FROM pg_proc WHERE proname = 'epigraph_edges_tenancy'")
            .fetch_one(&pool)
            .await
            .expect("epigraph_edges_tenancy must exist");

    // The body has exactly ONE bare `RETURN NEW;` that is not preceded by a
    // co-owner assignment: the no-widening guard's. Locate it structurally.
    let guard = src
        .find("NOT (sv = 'group' OR tv = 'group')")
        .expect("the no-widening guard must be present");
    let early_return = src[guard..]
        .find("RETURN NEW;")
        .expect("the guard must be followed by an early RETURN NEW");
    let branch = &src[guard..guard + early_return];
    assert!(
        !branch.contains("co_owner_group_id"),
        "the no-widening branch must leave the writer's declaration ENTIRELY \
         alone, co-ownership included — 072's header says so and the four \
         clearing branches are counted separately.\n\n{branch}"
    );

    // Five branches total: four that assign, one that returns early.
    assert_eq!(
        src.matches("RETURN NEW;").count(),
        2,
        "arm (b) has exactly two RETURN NEW statements — the early one and the \
         tail. A third would be an unpinned branch.\n\n{src}"
    );
}

/// **Arm (d) CO-OWNS a cross-group edge rather than picking a side — and still
/// does not RAISE.**
///
/// # Retargeted by PR-13, deliberately, and what survived
///
/// Before migration 072 this test was
/// `arm_d_leaves_a_cross_group_edge_unchanged_rather_than_picking_a_side` and
/// asserted `(WORLD, "public")` — the edge left alone. That was fail-CLOSED
/// under a single-uuid `owner_group_id`, not a desirable end state: the edge
/// stayed *stale*, still claiming to be public while both its endpoints had
/// become private. 072 makes the meet expressible, so the assertion inverts to
/// the real answer, `('group', group_a, co_owner = group_b)`.
///
/// Three things did NOT change and are still the point of the test:
///
/// * **It must not RAISE.** `.expect("a cross-group privatization must not
///   raise from arm (d)")` is load-bearing. Arm (d) fires on EVERY `claims`
///   UPDATE, including this series' own backfill, so an exception here is a
///   total write outage on any privatization that happens to touch a
///   cross-group edge — not a rejected row. This is why arm (d) never got arm
///   (b)'s RAISE, and it is also why 072's co-owner CASE must yield NULL on
///   every collapse path (see
///   [`declassifying_one_endpoint_of_a_co_owned_edge_clears_the_co_owner`] in
///   `privatization_boundary.rs`).
/// * **It must not pick a side.** Measured on a throwaway database against the
///   earlier one-endpoint form: a single statement privatizing two claims into
///   DIFFERENT personal groups made the edge take whichever join row Postgres
///   matched first, so one group's members could see an edge whose far endpoint
///   was the other group's private claim. Co-ownership is not "picking
///   `group_a`": under the INTERSECTION read fragment the edge is visible to
///   neither group alone, which the read-side half of this asserts in
///   `privatization_boundary.rs`.
/// * **It must not stay public.** `assert_ne!(vis, "public")` is what the old
///   `(WORLD, "public")` assertion would now silently permit if the edges
///   UPDATE stopped firing altogether.
#[sqlx::test(migrations = "../../migrations")]
async fn arm_d_co_owns_a_cross_group_edge_rather_than_picking_a_side(pool: PgPool) {
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

    let (owner, vis, co) = edge_tenancy_of(&pool, edge).await;
    assert_eq!(
        (owner, vis.as_str(), co),
        (group_a, "group", Some(group_b)),
        "a cross-group privatization must stamp BOTH owning groups; assigning \
         whichever endpoint the planner joined first would let one group see an \
         edge whose far endpoint is the other group's private claim"
    );
    // Not a formatting variant of the assertion above: it is the property that
    // survives a future change to which side lands in which column.
    assert_ne!(
        owner,
        co.unwrap(),
        "owner and co-owner must be DISTINCT groups — equal values would also \
         violate edges_co_owner_shape"
    );
    assert_ne!(
        vis, "public",
        "an edge between two group-private claims is never public"
    );
}
