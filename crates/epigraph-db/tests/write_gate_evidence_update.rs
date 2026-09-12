//! **The acceptance test for the write-side tenancy predicate** (PR-16,
//! delivered as 16b).
//!
//! # What this file has to prove, and why the obvious test does not prove it
//!
//! The failure mode this whole PR exists to avoid is a control that *looks*
//! like a control and gates nothing. `epigraph-interfaces`'
//! `PolicyGate::authorize` is already in the tree with zero production call
//! sites; shipping a second mechanism of that kind would be worse than shipping
//! nothing, because it would retire the finding that says the gate is missing.
//!
//! So the bar is not "a test exercises `update_raw_content`". It is: **there
//! exists a single-token mutation to the production code that a reviewer would
//! read as correct, and this file fails when it is applied.** That mutation is:
//!
//! ```ignore
//! //  repos/evidence.rs::update_raw_content
//! -   if let Some(w) = viewer.writable_bind() { q = q.bind(w); }
//! +   if let Some(w) = viewer.group_bind()    { q = q.bind(w); }
//! ```
//!
//! The fragment, the `/* {WRITABLE:e} */` marker, the splice call and the bind
//! arity are all untouched. Real SQL executes against the real database. The
//! diff is three characters and reads as obviously fine — `group_bind()` is the
//! idiom used by every read site in the same file, and `writable_bind()` has
//! exactly one consumer in the tree. It is the realistic implementation error,
//! and it silently converts a WRITE gate into a READ gate.
//!
//! # THE FIXTURE ASYMMETRY IS THE PROOF
//!
//! Principal `P` is a **reader** in group `R` and a **writer** in group `W`, so
//! `Viewer::resolve` yields `group_ids = [R, W]` and `writable = [W]`. The two
//! sets are DIFFERENT, and that difference is the only thing that can
//! distinguish the two accessors.
//!
//! If this fixture instead gave `P` a principal whose `group_ids == writable`
//! — which is what every convenience helper in the tree produces, including
//! `Viewer::test_scoped` — then `group_bind()` and `writable_bind()` return the
//! same array, the mutation above is undetectable, every assertion below stays
//! green, and the PR ships a read gate at a write site. **Do not simplify this
//! fixture.**
//!
//! # Why every assertion reads the row back
//!
//! `update_raw_content` returns `Ok(false)` for both "no such row" and "you may
//! not write this row". A test that asserted only on the returned `bool` would
//! also pass under a mutation that makes the statement match NOTHING — a botched
//! alias, a wrong bind index, an accidentally-empty array. That is a
//! "the query matched zero rows" test wearing a write-gate test's clothes, which
//! is the same defect class as the gate it is meant to guard. Every case below
//! therefore asserts on the DATABASE state, not on the return value alone.

#![allow(clippy::items_after_test_module)]

use epigraph_core::EvidenceId;
use epigraph_db::repos::EvidenceRepository;
use epigraph_db::visibility::Viewer;
use sqlx::PgPool;
use uuid::Uuid;

#[path = "viewer_fixture.rs"]
mod viewer_fixture;

// ---------------------------------------------------------------------------
// fixture
// ---------------------------------------------------------------------------

/// A distinct 32-byte content hash derived from `seed`.
///
/// `claims_content_hash_length` and its evidence twin CHECK `length(..) = 32`,
/// and both columns are UNIQUE-constrained in combination, so the bytes have to
/// be both the right width and per-row distinct.
fn hash32(seed: Uuid) -> Vec<u8> {
    seed.as_bytes().iter().copied().cycle().take(32).collect()
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO agents (id, public_key, agent_type, display_name) \
         VALUES ($1, $2, 'system', $3)",
    )
    .bind(id)
    .bind(&pk)
    .bind(format!("write-gate-{id}"))
    .execute(pool)
    .await
    .expect("seed agent");
    id
}

async fn seed_group(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO groups (id, did_key, public_key, kind, display_name) \
         VALUES ($1, $2, $3, 'team', 'write-gate-test')",
    )
    .bind(id)
    .bind(format!("did:key:write-gate-{id}"))
    .bind(&pk)
    .execute(pool)
    .await
    .expect("seed group");
    id
}

/// `role` is the whole point of this fixture: `Viewer::resolve` puts
/// `admin`/`writer` into `writable` and every live membership into `group_ids`.
async fn seed_membership(pool: &PgPool, group_id: Uuid, agent_id: Uuid, role: &str) {
    sqlx::query(
        "INSERT INTO group_memberships \
             (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, $3, 0, $4)",
    )
    .bind(group_id)
    .bind(agent_id)
    .bind(vec![0u8; 48])
    .bind(role)
    .execute(pool)
    .await
    .expect("seed membership");
}

/// A group-private claim owned by `group_id`, carrying one evidence row also owned by
/// `group_id`.
///
/// Tenancy is declared EXPLICITLY on both inserts. Migration 074's BEFORE
/// trigger raises 23502 on an undeclared write, so a fixture that let the
/// columns default would fail to seed rather than seed something wrong — but it
/// is spelled out anyway, because the point of the row is WHO OWNS IT and a
/// derived owner would make the test's premise implicit.
async fn seed_evidence(pool: &PgPool, agent_id: Uuid, group_id: Uuid, body: &str) -> EvidenceId {
    seed_evidence_with_visibility(pool, agent_id, group_id, body, "group").await
}

/// `seed_evidence`, with `visibility` as a parameter rather than a literal.
///
/// Exists so the file can seed a **`public`** row. `visibility` was hardcoded to
/// `'group'` on both inserts, which meant the widest fail-open the mechanism
/// names — a write fragment carrying the read fragment's
/// `visibility = 'public'` disjunct, making every world-readable row writable by
/// every authenticated principal — had no row in any database that could
/// demonstrate it. See
/// [`a_public_row_is_readable_by_everyone_and_writable_by_nobody`].
async fn seed_evidence_with_visibility(
    pool: &PgPool,
    agent_id: Uuid,
    group_id: Uuid,
    body: &str,
    visibility: &str,
) -> EvidenceId {
    let claim_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, owner_group_id, visibility) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(claim_id)
    .bind(format!("write-gate claim {claim_id}"))
    .bind(hash32(claim_id))
    .bind(agent_id)
    .bind(group_id)
    .bind(visibility)
    .execute(pool)
    .await
    .expect("seed claim");

    let evidence_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO evidence \
             (id, content_hash, evidence_type, raw_content, claim_id, owner_group_id, visibility) \
         VALUES ($1, $2, 'document', $3, $4, $5, $6)",
    )
    .bind(evidence_id)
    .bind(hash32(evidence_id))
    .bind(body)
    .bind(claim_id)
    .bind(group_id)
    .bind(visibility)
    .execute(pool)
    .await
    .expect("seed evidence");

    EvidenceId::from(evidence_id)
}

async fn raw_content_of(pool: &PgPool, id: EvidenceId) -> Option<String> {
    sqlx::query_scalar("SELECT raw_content FROM evidence WHERE id = $1")
        .bind(Uuid::from(id))
        .fetch_one(pool)
        .await
        .expect("read back raw_content")
}

/// The asymmetric world every test below shares.
struct Fixture {
    /// Reader in `r`, writer in `w`.
    principal: Uuid,
    /// Evidence owned by the group `principal` can only READ.
    ev_r: EvidenceId,
    /// Evidence owned by the group `principal` can WRITE.
    ev_w: EvidenceId,
}

const SEEDED_R: &str = "seeded body, group R";
const SEEDED_W: &str = "seeded body, group W";

async fn fixture(pool: &PgPool) -> Fixture {
    let principal = seed_agent(pool).await;
    let author = seed_agent(pool).await;
    let r = seed_group(pool).await;
    let w = seed_group(pool).await;

    seed_membership(pool, r, principal, "reader").await;
    seed_membership(pool, w, principal, "writer").await;

    let ev_r = seed_evidence(pool, author, r, SEEDED_R).await;
    let ev_w = seed_evidence(pool, author, w, SEEDED_W).await;

    Fixture {
        principal,
        ev_r,
        ev_w,
    }
}

// ---------------------------------------------------------------------------
// the fixture's own premise
// ---------------------------------------------------------------------------

/// **Run this first when anything else in the file starts failing.**
///
/// Every discriminating assertion below depends on `group_ids != writable`. If
/// the roles stopped being distinguishable — a change to `Viewer::resolve`'s
/// role set, a migration that rewrites `group_memberships.role`, a fixture
/// simplified in review — the mutation test silently stops testing anything and
/// the rest of this file goes green over a read gate.
#[sqlx::test(migrations = "../../migrations")]
async fn the_fixture_principal_reads_more_groups_than_it_writes(pool: PgPool) {
    let f = fixture(&pool).await;
    let viewer = Viewer::resolve(&pool, f.principal).await.expect("resolve");

    let readable = viewer.group_bind().expect("scoped viewer binds groups");
    let writable = viewer
        .writable_bind()
        .expect("scoped viewer binds writable");

    assert_eq!(
        readable.len(),
        2,
        "the principal must be a live member of BOTH groups"
    );
    assert_eq!(
        writable.len(),
        1,
        "exactly one of the two memberships is `writer`; if this is 2, the \
         `reader` role has stopped narrowing the writable set and the mutation \
         proof in this file is vacuous"
    );
    assert_ne!(
        readable, writable,
        "group_bind() and writable_bind() MUST return different arrays here. \
         When they are equal, binding the wrong one is undetectable and every \
         other test in this file passes over a read gate."
    );
}

// ---------------------------------------------------------------------------
// the gate
// ---------------------------------------------------------------------------

/// **The mutation-breakable assertion.** Read authority over a group is not
/// write authority over its rows.
///
/// Fails under the `writable_bind()` → `group_bind()` mutation, in the
/// exfiltration direction: the update succeeds and another group's evidence
/// body changes.
#[sqlx::test(migrations = "../../migrations")]
async fn a_principal_that_only_reads_a_group_cannot_update_its_evidence(pool: PgPool) {
    let f = fixture(&pool).await;
    let viewer = Viewer::resolve(&pool, f.principal).await.expect("resolve");

    let updated = EvidenceRepository::update_raw_content(&pool, &viewer, f.ev_r, "TAMPERED")
        .await
        .expect("the statement must execute, not error");

    assert!(
        !updated,
        "a principal holding only `reader` in the owning group updated its \
         evidence. The write predicate is binding the READ group set — check \
         that `update_raw_content` binds `writable_bind()` and not \
         `group_bind()`."
    );
    assert_eq!(
        raw_content_of(&pool, f.ev_r).await.as_deref(),
        Some(SEEDED_R),
        "the row must be byte-unchanged. Asserting only on the returned bool \
         would also pass if the statement had matched nothing for an unrelated \
         reason, which is not what this test is for."
    );
}

/// **The over-suppression assertion.** The gate must not be a wall.
///
/// Fails under mutation M3 (`writable_bind()` returning `Some(&[])`) and under
/// any predicate that is accidentally unsatisfiable. Asserted because
/// over-suppression is silent and permanent: a provisioning bug that dropped a
/// `writer` membership would otherwise present to a user as "my updates do
/// nothing", with no error anywhere.
#[sqlx::test(migrations = "../../migrations")]
async fn a_writer_updates_evidence_in_its_own_writable_group(pool: PgPool) {
    let f = fixture(&pool).await;
    let viewer = Viewer::resolve(&pool, f.principal).await.expect("resolve");

    let updated = EvidenceRepository::update_raw_content(&pool, &viewer, f.ev_w, "BACKFILLED")
        .await
        .expect("update");

    assert!(
        updated,
        "a principal holding `writer` in the owning group could not update its \
         own evidence — the predicate is over-suppressing"
    );
    assert_eq!(
        raw_content_of(&pool, f.ev_w).await.as_deref(),
        Some("BACKFILLED"),
        "the returned `true` must correspond to a real change to THIS row"
    );
    assert_eq!(
        raw_content_of(&pool, f.ev_r).await.as_deref(),
        Some(SEEDED_R),
        "the permitted update must not have touched the other group's row"
    );
}

/// A principal with no writable groups at all writes nothing, anywhere.
///
/// This is the `writable = []` shape a `reader`-only principal has, and it is
/// the case where an `ANY($3::uuid[])` against an empty array must be FALSE
/// rather than vacuously true.
#[sqlx::test(migrations = "../../migrations")]
async fn a_principal_with_no_writable_group_updates_nothing(pool: PgPool) {
    let f = fixture(&pool).await;

    let reader_only = seed_agent(&pool).await;
    // Member of both groups, `reader` in both: reads two groups, writes none.
    let groups: Vec<Uuid> =
        sqlx::query_scalar("SELECT DISTINCT owner_group_id FROM evidence ORDER BY 1")
            .fetch_all(&pool)
            .await
            .expect("owning groups");
    for g in &groups {
        seed_membership(&pool, *g, reader_only, "reader").await;
    }

    let viewer = Viewer::resolve(&pool, reader_only).await.expect("resolve");
    assert_eq!(
        viewer.writable_bind(),
        Some(&[][..]),
        "a reader-only principal must resolve to an EMPTY writable set, not to \
         a bypass and not to its read set"
    );

    for (id, seeded) in [(f.ev_r, SEEDED_R), (f.ev_w, SEEDED_W)] {
        let updated = EvidenceRepository::update_raw_content(&pool, &viewer, id, "TAMPERED")
            .await
            .expect("update");
        assert!(!updated, "an empty writable set authorized a write");
        assert_eq!(
            raw_content_of(&pool, id).await.as_deref(),
            Some(seeded),
            "an empty writable set must make the predicate FALSE, not vacuous"
        );
    }
}

/// **The widest fail-open, given a row instead of a string assertion.**
///
/// `Viewer::writable_fragment`'s own doc calls carrying the read fragment's
/// leading `visibility = 'public'` disjunct into the write predicate "the widest
/// possible fail-open, spelled as an apparent symmetry": every world-readable
/// row in the database would become writable by every authenticated principal.
///
/// Until this test, that named worst case was guarded by exactly one thing —
/// `assert!(!f.contains("visibility"))` on a `&'static str` in a unit test. That
/// assertion holds today, but it is a text check on a literal, and no row in any
/// database ever demonstrated the consequence. The rest of this file proves the
/// gate discriminates READ authority from WRITE authority; this proves it does
/// not treat PUBLICNESS as write authority either, which is a different
/// direction and a strictly worse failure — the read/write confusion leaks one
/// group's rows to that group's readers, the public disjunct leaks every public
/// row to everyone.
///
/// The row is owned by a group the principal has NO membership in, so the
/// `public` visibility is the only thing that could possibly admit the write.
/// Note the principal CAN read it: this is a row that is legitimately
/// world-readable and must still be writable by nobody but its owners.
#[sqlx::test(migrations = "../../migrations")]
async fn a_public_row_is_readable_by_everyone_and_writable_by_nobody(pool: PgPool) {
    let f = fixture(&pool).await;

    // A stranger group: the principal holds `reader` in R and `writer` in W, and
    // nothing at all here.
    let author = seed_agent(&pool).await;
    let stranger_group = seed_group(&pool).await;
    const SEEDED_PUBLIC: &str = "seeded body, public row in a stranger group";
    let ev_public =
        seed_evidence_with_visibility(&pool, author, stranger_group, SEEDED_PUBLIC, "public").await;

    let viewer = Viewer::resolve(&pool, f.principal).await.expect("resolve");
    assert!(
        !viewer
            .writable_bind()
            .expect("scoped")
            .contains(&stranger_group),
        "the fixture's premise: the principal must not be able to write the \
         owning group by membership, or `public` is not the thing under test"
    );

    let updated = EvidenceRepository::update_raw_content(&pool, &viewer, ev_public, "TAMPERED")
        .await
        .expect("the statement must execute, not error");

    assert!(
        !updated,
        "a `visibility = 'public'` row was written by a principal with no \
         membership in its owning group. Public is a READ grant. Check that \
         `Viewer::writable_fragment` has not acquired the read fragment's \
         leading `visibility = 'public'` disjunct — that single disjunct makes \
         every world-readable row in the database writable by every \
         authenticated principal."
    );
    assert_eq!(
        raw_content_of(&pool, ev_public).await.as_deref(),
        Some(SEEDED_PUBLIC),
        "the public row must be byte-unchanged"
    );
}

/// A maintenance `Bypass` viewer writes without a group — and without a bind.
///
/// This pins the two-strings-only property end to end at a real statement: the
/// bypass arm renders a single space and emits no `$3`, so the conditional bind
/// at the call site must supply nothing. If `writable_bind()` ever returned
/// `Some(&[])` for `Bypass` instead of `None`, the statement would be handed a
/// parameter it does not declare and this test would fail with a bind-count
/// error rather than silently doing the wrong thing.
#[sqlx::test(migrations = "../../migrations")]
async fn a_bypass_viewer_updates_without_binding_a_group(pool: PgPool) {
    let f = fixture(&pool).await;

    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;
    assert!(viewer.writable_bind().is_none(), "a Bypass binds nothing");

    let updated = EvidenceRepository::update_raw_content(&pool, &viewer, f.ev_r, "MAINTENANCE")
        .await
        .expect("a bypass write must execute, not fail on bind arity");

    assert!(updated, "maintenance must reach a row in any group");
    assert_eq!(
        raw_content_of(&pool, f.ev_r).await.as_deref(),
        Some("MAINTENANCE")
    );
}
