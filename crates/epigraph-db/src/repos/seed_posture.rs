//! The seed escape-hatch question, as SQL expressions the API's boot posture
//! probes embed (`AppState::probe_rls_posture`,
//! `AppState::warn_on_privileged_connection`).
//!
//! # Why an expression and not a call to `epigraph_session_is_seed()`
//!
//! Migration 113 moved the question the three `*_require_tenancy` triggers ask
//! from `pg_has_role(session_user, 'epigraph_seed', 'MEMBER')` (true of every
//! superuser without any grant) to `public.epigraph_session_is_seed()` (an
//! explicit grant, over edges that confer the role). A boot probe that still
//! asked `pg_has_role` would tell a superuser-DSN deployment its undeclared
//! writes are stamped onto the seed group, which after 113 is false.
//!
//! The probe must also run on a database BELOW 113: a binary can be deployed
//! before its migrations are applied. A reference to a function that does not
//! exist is a PARSE-time error in PostgreSQL, even inside a `CASE` branch that
//! is never taken, and each probe is pinned to one statement
//! (`no_unscoped_pool.rs` counts `state.rs`'s pool sites exactly). So
//! [`SESSION_IS_SEED_SQL`] carries an inline copy of 113's walk, taken only
//! when the function exists, and 074's `pg_has_role` question otherwise.
//!
//! `tenancy_required.rs::the_boot_probe_asks_the_seed_question_the_triggers_ask`
//! pins the copy to the function, role kind by role kind (a non-seed
//! superuser, an indirect seed, an ADMIN-only grantee directly and one hop
//! away, and the application role), and exercises the below-113 branch.
//!
//! # Requires PostgreSQL 16
//!
//! `pg_auth_members.inherit_option` / `set_option` exist from PostgreSQL 16,
//! as migration 113 itself requires. The branch that names them is only taken
//! once 113's function exists, but the columns are resolved at parse time
//! regardless of the branch, so this expression does not parse on 15.

/// `true` once migration 113's `public.epigraph_session_is_seed()` exists,
/// i.e. once the triggers ask the explicit-grant question. Parses at any
/// migration level.
pub const SEED_FUNCTION_EXISTS_SQL: &str =
    "(to_regprocedure('public.epigraph_session_is_seed()') IS NOT NULL)";

/// Can this connection's `session_user` take the seed escape hatch, as the
/// `*_require_tenancy` triggers at THIS database's migration level decide it?
///
/// At or above 113: the same walk as `epigraph_session_is_seed()` (session
/// user IS `epigraph_seed`, or reaches it over `pg_auth_members` edges that
/// confer the role: `inherit_option OR set_option`). Below 113: 074's
/// `pg_has_role(..., 'MEMBER')`, which is what the triggers there ask.
pub const SESSION_IS_SEED_SQL: &str = "(CASE \
    WHEN to_regprocedure('public.epigraph_session_is_seed()') IS NOT NULL THEN \
        EXISTS ( \
            WITH RECURSIVE seed AS ( \
                SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = 'epigraph_seed' \
            ), \
            members(oid) AS ( \
                SELECT m.member FROM pg_catalog.pg_auth_members m \
                  JOIN seed s ON m.roleid = s.oid \
                 WHERE m.inherit_option OR m.set_option \
                UNION \
                SELECT m.member FROM pg_catalog.pg_auth_members m \
                  JOIN members x ON m.roleid = x.oid \
                 WHERE m.inherit_option OR m.set_option \
            ) \
            SELECT 1 FROM pg_catalog.pg_roles me, seed s \
             WHERE me.rolname = session_user \
               AND (me.oid = s.oid OR me.oid IN (SELECT oid FROM members)) \
        ) \
    ELSE \
        EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'epigraph_seed') \
        AND pg_has_role(session_user, 'epigraph_seed', 'MEMBER') \
    END)";
