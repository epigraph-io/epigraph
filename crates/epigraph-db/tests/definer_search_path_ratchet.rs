//! Every SECURITY DEFINER function pins a `search_path` that lists `pg_temp`
//! last, and the definers that still resolve names through `public` can only
//! become fewer (backlog 368ce622).
//!
//! # The defect class
//!
//! A SECURITY DEFINER body runs with its owner's privileges and resolves every
//! unqualified name through its pinned `search_path`, so that path must not
//! put a schema the session controls ahead of the schemas the body means.
//!
//! * **The session's temporary schema.** A path that does not list `pg_temp`
//!   searches it FIRST for relation and type names (never for functions or
//!   operators); [`a_path_without_pg_temp_searches_the_temporary_schema_first`]
//!   pins that resolution order. The fix is to list `pg_temp` LAST.
//! * **`public`.** A path that lists `public` resolves unqualified built-in
//!   calls through it as well (migration 172's header). The form that does
//!   not depend on `public` is `SET search_path = pg_catalog, pg_temp` with
//!   every relation and function schema-qualified (172's form).
//!
//! # What is pinned
//!
//! * [`every_definer_pins_a_search_path_that_lists_pg_temp_last`]: no definer
//!   outside the system schemas is unpinned, and every pinned path lists
//!   `pg_temp`, last. No allowlist.
//! * [`definers_resolving_through_public_are_exactly_the_register`]: the set of
//!   definers whose path names any schema other than `pg_catalog` / `pg_temp`
//!   equals [`PUBLIC_PATH_REGISTER`] exactly, in both directions, so a NEW
//!   definer that resolves through `public` fails, and a definer moved off
//!   `public` must leave the register in the same change.
//! * [`definers_off_public_name_every_public_object_qualified`]: a definer whose
//!   path is only `pg_catalog, pg_temp` names every `public` relation, type and
//!   function it uses schema-qualified, because on that path an unqualified
//!   relation or type name is not looked up in `public`.
//! * [`no_function_keeps_state_in_a_session_temporary_relation`]: no function
//!   body a definer can run (the definers themselves, and the INVOKER helpers
//!   and triggers they run as their owner) creates a temporary relation or
//!   names a `pg_temp`-qualified one. A temporary relation is the calling
//!   SESSION's, so the caller can create a same-named one first and the body
//!   would use it with the owner's rights. No allowlist.
//! * [`the_refresh_and_revocation_family_resolves_in_pg_catalog_only`][]: the
//!   OAuth refresh-token and access-token revocation definers (the family the
//!   backlog item names first) are on 172's form, keep their owner and grants.
//! * [`migration_190_changes_only_paths_and_the_family_bodies`],
//!   [`migration_190_refuses_to_apply_over_another_body`] and
//!   [`migration_190_sweep_refuses_temp_before_last_and_pins_the_unpinned`]:
//!   what 190 changed, its md5 precondition, and its sweep's refusal and
//!   unpinned / quoted-path branches (shapes a fresh database does not have).
//!
//! Each catalog check is CALIBRATED in-test: probe definers of each wrong shape
//! are created on the test database and must be reported.
//!
//! # The rule for later migrations
//!
//! A new SECURITY DEFINER function uses `SET search_path = pg_catalog, pg_temp`
//! and schema-qualifies every relation, type and function it names (built-ins
//! as `pg_catalog.now()`, tables as `public.claims`). A body that still needs
//! `public` on its path lists `pg_temp` LAST (`public, pg_temp` or
//! `pg_catalog, public, pg_temp`) and is added to [`PUBLIC_PATH_REGISTER`]
//! with [`HIGH_WATER`] raised to match, which a reviewer sees. Re-stating a
//! registered function on 172's form removes its entry and lowers
//! [`HIGH_WATER`] by one (the test requires they are equal, so every register
//! change edits the constant).
//!
//! What the unqualified-name scan of pg_catalog-only bodies cannot see: names
//! built inside dynamic SQL strings (`EXECUTE format(...)`) and `regclass` /
//! `regproc` literals (`'claims'::regclass`), which it strips with every other
//! string literal; `DECLARE`d variable types (`v some_type;`) and
//! `CAST(x AS some_type)` (it reads a type only after `::` or before `%`); the
//! second and later relations of a comma-joined `FROM a, b`, and the relation
//! after `DELETE .. USING`; quoted identifiers. No pg_catalog-only body at
//! 190 uses any of these forms.
//!
//! Uses the non-macro `sqlx::query` forms so the offline `.sqlx/` cache is not
//! extended for one test.

use sqlx::migrate::Migrator;
use sqlx::PgPool;
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");

/// Definers whose pinned path names `public` (every other schema too), by
/// `schema.name(argument types)`. May only shrink: see the module docs.
const PUBLIC_PATH_REGISTER: &[&str] = &[
    "public.epigraph_act_for_ceremony(uuid)",
    "public.epigraph_admin_acts_of_principal(integer)",
    "public.epigraph_admin_audit_write(uuid, uuid, uuid, text, jsonb)",
    "public.epigraph_admin_group_ids()",
    "public.epigraph_admin_patch_claim(uuid, uuid, uuid, text, text[], text[], jsonb, uuid)",
    "public.epigraph_admin_scope_enforcement_audit()",
    "public.epigraph_admin_scope_enforcement_guard()",
    "public.epigraph_admin_scopes_armed()",
    "public.epigraph_agent_is_retired(uuid)",
    "public.epigraph_agent_key_set_status(uuid, text, text, uuid)",
    "public.epigraph_agent_prompt_history(uuid)",
    "public.epigraph_agents_refuse_registered_system_key()",
    "public.epigraph_allow_author_binding_client(uuid, uuid, text)",
    "public.epigraph_allowlisted_operator(uuid)",
    "public.epigraph_arm_operator_binding()",
    "public.epigraph_attach_agent_to_role(text, uuid, timestamp with time zone, timestamp with time zone, text)",
    "public.epigraph_author_binding(uuid)",
    "public.epigraph_author_binding_clients_audit()",
    "public.epigraph_author_binding_clients_guard_insert()",
    "public.epigraph_author_binding_clients_guard_update()",
    "public.epigraph_author_binding_clients_refuse_delete()",
    "public.epigraph_backfill_legacy_agent_keys()",
    "public.epigraph_bind_group_role(text, uuid, text, boolean, text)",
    "public.epigraph_bind_group_role(text, uuid, text, text, text)",
    "public.epigraph_cascade_delete_edge_bbas(uuid[], text)",
    "public.epigraph_cascade_delete_node_edges()",
    "public.epigraph_claim_tenancy_by_ids(uuid[])",
    "public.epigraph_claims_require_operator_binding()",
    "public.epigraph_claims_require_tenancy()",
    "public.epigraph_community_add_member(uuid, uuid, uuid)",
    "public.epigraph_community_remove_member(uuid, uuid, uuid)",
    "public.epigraph_complete_passkey_enrollment(uuid, bytea, jsonb, uuid, text, boolean, boolean)",
    "public.epigraph_confirm_admin_act(uuid, bytea, bigint, boolean, jsonb)",
    "public.epigraph_confirm_elevation(uuid, bytea, bigint, boolean, jsonb)",
    "public.epigraph_consume_admin_act(uuid, text, bytea, uuid, jsonb)",
    "public.epigraph_countersign_authorship(uuid, uuid, text, uuid)",
    "public.epigraph_create_elevation_ticket(uuid, uuid, text, text, bytea)",
    "public.epigraph_create_passkey_enrollment(uuid, text, text)",
    "public.epigraph_create_passkey_enrollment(uuid, text, text, uuid)",
    "public.epigraph_create_team_group(text, uuid, text)",
    "public.epigraph_dedup_move_bbas(uuid, uuid, uuid[])",
    "public.epigraph_define_group_role(text, text, uuid, text, boolean, text)",
    "public.epigraph_define_group_role(text, text, uuid, text, text, text)",
    "public.epigraph_derived_require_tenancy()",
    "public.epigraph_detach_agent_from_role(text, uuid, text)",
    "public.epigraph_edges_tenancy()",
    "public.epigraph_elevated_access_audit(timestamp with time zone, integer)",
    "public.epigraph_elevated_access_guard_change()",
    "public.epigraph_elevated_access_guard_insert()",
    "public.epigraph_elevated_access_ready()",
    "public.epigraph_elevation_live(uuid, uuid)",
    "public.epigraph_elevation_session_is_live(uuid)",
    "public.epigraph_elevation_sessions_audit()",
    "public.epigraph_elevation_sessions_guard_insert()",
    "public.epigraph_elevation_sessions_guard_update()",
    "public.epigraph_elevation_tickets_audit()",
    "public.epigraph_elevation_tickets_guard_insert()",
    "public.epigraph_elevation_tickets_guard_update()",
    "public.epigraph_end_elevation(uuid, text)",
    "public.epigraph_end_elevations_on_assignment_revoke()",
    "public.epigraph_end_elevations_on_client_revoke()",
    "public.epigraph_end_elevations_on_family_revoke()",
    "public.epigraph_end_elevations_on_operator_revoke()",
    "public.epigraph_end_elevations_on_passkey_revoke()",
    "public.epigraph_end_expired_elevations(uuid, uuid)",
    "public.epigraph_end_group_role_binding(uuid, text)",
    "public.epigraph_end_role_assignment(uuid, text)",
    "public.epigraph_end_role_assignment(uuid, text, uuid)",
    "public.epigraph_enrollment_for_ceremony(uuid)",
    "public.epigraph_ensure_personal_group(uuid)",
    "public.epigraph_family_of_person_is_live(uuid, uuid, uuid)",
    "public.epigraph_foreign_aggregate_audit(uuid, uuid, text, jsonb, jsonb)",
    "public.epigraph_foreign_aggregate_target(uuid)",
    "public.epigraph_foreign_belief_cache(uuid, double precision, double precision, double precision, double precision, double precision, uuid)",
    "public.epigraph_foreign_belief_clear(uuid)",
    "public.epigraph_foreign_claim_classification(uuid, text, uuid)",
    "public.epigraph_foreign_claim_frame(uuid, uuid, integer)",
    "public.epigraph_grant_role(text, uuid, timestamp with time zone, timestamp with time zone, uuid, text)",
    "public.epigraph_grant_role(text, uuid, timestamp with time zone, timestamp with time zone, uuid, text, uuid)",
    "public.epigraph_group_memberships_operator_scope()",
    "public.epigraph_group_role_bindings_audit()",
    "public.epigraph_group_role_bindings_guard_insert()",
    "public.epigraph_group_role_bindings_guard_update()",
    "public.epigraph_group_role_bindings_refuse_delete()",
    "public.epigraph_group_role_roster(uuid, timestamp with time zone)",
    "public.epigraph_group_roster_admits_principal(uuid)",
    "public.epigraph_has_live_passkey(uuid)",
    "public.epigraph_holds_role(uuid, text, timestamp with time zone)",
    "public.epigraph_human_of(uuid, boolean)",
    "public.epigraph_human_operators_audit()",
    "public.epigraph_human_operators_guard_insert()",
    "public.epigraph_human_operators_guard_update()",
    "public.epigraph_human_operators_mirror_instance_admins()",
    "public.epigraph_human_operators_refuse_system_agent()",
    "public.epigraph_inherit_fragment_tenancy_stmt()",
    "public.epigraph_inherit_tenancy_stmt()",
    "public.epigraph_instance_admins_frozen()",
    "public.epigraph_is_elevated()",
    "public.epigraph_is_group_admin(uuid)",
    "public.epigraph_is_group_creator(uuid)",
    "public.epigraph_is_human_operator(uuid)",
    "public.epigraph_is_instance_admin(uuid)",
    "public.epigraph_is_legacy_fleet_parent(uuid)",
    "public.epigraph_link_legacy_authors(uuid, uuid[], timestamp with time zone)",
    "public.epigraph_link_operator(uuid, uuid)",
    "public.epigraph_link_retired_agent(uuid, uuid)",
    "public.epigraph_link_retired_shared_signer(uuid, uuid, uuid[])",
    "public.epigraph_live_elevating_assignment(uuid, timestamp with time zone)",
    "public.epigraph_live_memberships(uuid)",
    "public.epigraph_live_role_assignment(uuid, text, timestamp with time zone)",
    "public.epigraph_lock_public_claim_for_attach(uuid)",
    "public.epigraph_node_tenancy(uuid, text)",
    "public.epigraph_oauth_client_approve(uuid, text[], uuid)",
    "public.epigraph_oauth_client_link_agent(uuid, uuid)",
    "public.epigraph_oauth_client_lock_for_link(uuid)",
    "public.epigraph_oauth_code_consume(bytea)",
    "public.epigraph_oauth_session_take(text)",
    "public.epigraph_oauth_session_to_consent(text, text, uuid, text[])",
    "public.epigraph_operates_agents(uuid)",
    "public.epigraph_operator_actor(uuid)",
    "public.epigraph_operator_binding_armed()",
    "public.epigraph_operator_binding_enforced()",
    "public.epigraph_operator_links_audit()",
    "public.epigraph_operator_links_operator_is_human()",
    "public.epigraph_operator_links_refuse_allowlisted_agent()",
    "public.epigraph_operator_links_refuse_retired_system_agent()",
    "public.epigraph_operator_links_refuse_role_holder()",
    "public.epigraph_operator_of_author(uuid)",
    "public.epigraph_operator_scope_exempt()",
    "public.epigraph_operator_writes_group(uuid, uuid)",
    "public.epigraph_passkey_enrollments_audit()",
    "public.epigraph_passkey_enrollments_guard_insert()",
    "public.epigraph_passkey_enrollments_guard_update()",
    "public.epigraph_passkeys_for_act(uuid)",
    "public.epigraph_passkeys_for_ticket(uuid)",
    "public.epigraph_pending_admin_acts_audit()",
    "public.epigraph_pending_admin_acts_guard_insert()",
    "public.epigraph_pending_admin_acts_guard_update()",
    "public.epigraph_person_authenticators_audit()",
    "public.epigraph_person_authenticators_guard_insert()",
    "public.epigraph_person_authenticators_guard_update()",
    "public.epigraph_platform_audit(timestamp with time zone, integer)",
    "public.epigraph_platform_roles_guard_update()",
    "public.epigraph_propagate_tenancy()",
    "public.epigraph_propose_admin_act(text, jsonb, text, text)",
    "public.epigraph_provision_oauth_agent(bytea, text, text)",
    "public.epigraph_record_admin_scope_would_strip(uuid, text, text[])",
    "public.epigraph_record_cascade_deferral(text, uuid, uuid, uuid, uuid[], jsonb, text)",
    "public.epigraph_record_custodial_act(uuid, uuid, text, text, uuid, jsonb)",
    "public.epigraph_record_custodial_act(uuid, uuid, text, text, uuid, jsonb, uuid)",
    "public.epigraph_record_elevated_access(text, jsonb, integer, uuid[])",
    "public.epigraph_record_legacy_succession(uuid, uuid, text, text)",
    "public.epigraph_redeem_elevation_ticket(uuid, bytea, uuid)",
    "public.epigraph_refuse_role_node_subject()",
    "public.epigraph_register_agent_identity(bytea, uuid, text, text, text, bytea, jsonb)",
    "public.epigraph_register_human_operator(uuid, text, uuid)",
    "public.epigraph_register_system_agent(text, uuid, text)",
    "public.epigraph_reown_legacy_edges_to_signer(integer, uuid[])",
    "public.epigraph_reown_legacy_writer_bbas(integer)",
    "public.epigraph_require_attributable(uuid, uuid, boolean)",
    "public.epigraph_require_bound_author(uuid)",
    "public.epigraph_require_bound_writer(uuid)",
    "public.epigraph_require_operator_scope(uuid, uuid)",
    "public.epigraph_require_role_holder(uuid)",
    "public.epigraph_require_writer_scope(uuid, uuid)",
    "public.epigraph_resolve_challenge(uuid, text, jsonb)",
    "public.epigraph_retract_mass_function(uuid, text, uuid, uuid)",
    "public.epigraph_revoke_author_binding_client(uuid, text)",
    "public.epigraph_revoke_human_operator(uuid, text)",
    "public.epigraph_revoke_passkey(uuid, text)",
    "public.epigraph_role_agent_gate(uuid, timestamp with time zone)",
    "public.epigraph_role_agent_may_run(uuid)",
    "public.epigraph_role_agent_write_check()",
    "public.epigraph_role_agents_audit()",
    "public.epigraph_role_agents_follow_lineage()",
    "public.epigraph_role_agents_guard_insert()",
    "public.epigraph_role_agents_guard_update()",
    "public.epigraph_role_assignment_for(uuid, text, timestamp with time zone)",
    "public.epigraph_role_assignments_audit()",
    "public.epigraph_role_assignments_guard_insert()",
    "public.epigraph_role_assignments_guard_update()",
    "public.epigraph_role_derived_memberships(uuid, timestamp with time zone)",
    "public.epigraph_root_require_tenancy()",
    "public.epigraph_session_writes_node(uuid, text)",
    "public.epigraph_set_admin_act_challenge(uuid, jsonb)",
    "public.epigraph_set_admin_scope_enforcement(boolean, text)",
    "public.epigraph_set_elevation_ticket_challenge(uuid, jsonb)",
    "public.epigraph_set_passkey_enrollment_challenge(uuid, jsonb)",
    "public.epigraph_system_agents_audit()",
    "public.epigraph_system_agents_guard_insert()",
    "public.epigraph_system_agents_immutable()",
    "public.epigraph_team_group_add_member(uuid, uuid, text, text)",
    "public.epigraph_team_group_remove_member(uuid, uuid, text)",
    "public.epigraph_team_group_roster_verbs_only()",
    "public.epigraph_team_group_set_member_role(uuid, uuid, text, text)",
    "public.epigraph_ticket_for_ceremony(uuid)",
    "public.epigraph_unretract_mass_function(uuid, text, uuid, uuid)",
    "public.epigraph_writer_group()",
];

/// [`PUBLIC_PATH_REGISTER`]'s length, which must equal it. Raising it is a
/// visible decision to add a definer that resolves through `public`; it falls
/// by one each time a registered definer moves to 172's form.
const HIGH_WATER: usize = 198;

/// The family 190 re-states on 172's form, plus 172's own rotate definer.
/// `(signature, the application role executes it)`.
const PG_CATALOG_ONLY_FAMILY: &[(&str, bool)] = &[
    (
        "public.epigraph_access_token_revoke(uuid, uuid, timestamp with time zone)",
        true,
    ),
    ("public.epigraph_refresh_token_check(bytea)", true),
    ("public.epigraph_refresh_token_on_reuse(bytea)", false),
    ("public.epigraph_refresh_token_revoke(uuid, text)", true),
    ("public.epigraph_refresh_token_revoke_by_hash(bytea)", true),
    ("public.epigraph_refresh_token_revoke_client(uuid)", true),
    (
        "public.epigraph_refresh_token_rotate(bytea, bytea, timestamp with time zone)",
        true,
    ),
];

/// The functions 190 re-bodies (the family above without 172's rotate).
fn rebodied() -> BTreeSet<&'static str> {
    PG_CATALOG_ONLY_FAMILY
        .iter()
        .map(|(s, _)| *s)
        .filter(|s| !s.contains("refresh_token_rotate"))
        .collect()
}

/// One `definers` row: signature, `search_path`, `proconfig`, owner, ACL,
/// volatility, body.
type DefinerRow = (
    String,
    Option<String>,
    Option<Vec<String>>,
    String,
    Option<String>,
    String,
    String,
);

#[derive(Debug, Clone, PartialEq, Eq)]
struct Definer {
    /// `search_path` as the catalog stores it, `None` when unpinned.
    path: Option<String>,
    /// Every `proconfig` entry, in order.
    config: Vec<String>,
    owner: String,
    acl: Option<String>,
    volatile: String,
    src: String,
}

impl Definer {
    fn path_items(&self) -> Option<Vec<String>> {
        self.path.as_ref().map(|p| {
            p.split(',')
                .map(|s| s.trim().trim_matches('"').to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
    }

    fn resolves_through_another_schema(&self) -> bool {
        self.path_items()
            .is_some_and(|items| items.iter().any(|s| s != "pg_catalog" && s != "pg_temp"))
    }
}

/// Every SECURITY DEFINER function outside the system schemas and outside any
/// extension, by `schema.name(argument types)`.
async fn definers(pool: &PgPool) -> BTreeMap<String, Definer> {
    let rows: Vec<DefinerRow> = sqlx::query_as(
        "SELECT format('%s.%s(%s)', n.nspname, p.proname, \
                           pg_catalog.oidvectortypes(p.proargtypes)), \
                    (SELECT pg_catalog.substr(c, 13) FROM pg_catalog.unnest(p.proconfig) c \
                      WHERE c LIKE 'search_path=%' LIMIT 1), \
                    p.proconfig, \
                    pg_catalog.pg_get_userbyid(p.proowner)::text, \
                    p.proacl::text, p.provolatile::text, p.prosrc \
               FROM pg_catalog.pg_proc p \
               JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace \
              WHERE p.prosecdef \
                AND n.nspname NOT IN ('pg_catalog', 'information_schema') \
                AND n.nspname !~ '^pg_(toast|temp)' \
                AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d \
                                 WHERE d.classid = 'pg_catalog.pg_proc'::regclass \
                                   AND d.objid = p.oid AND d.deptype = 'e')",
    )
    .fetch_all(pool)
    .await
    .expect("read the definers");
    rows.into_iter()
        .map(|(sig, path, config, owner, acl, volatile, src)| {
            (
                sig,
                Definer {
                    path,
                    config: config.unwrap_or_default(),
                    owner,
                    acl,
                    volatile,
                    src,
                },
            )
        })
        .collect()
}

/// The definers whose path is unpinned, omits `pg_temp`, or lists it anywhere
/// but last, with the reason.
fn temp_shadowable(defs: &BTreeMap<String, Definer>) -> BTreeMap<String, String> {
    defs.iter()
        .filter_map(|(sig, d)| {
            let why = match d.path_items() {
                None => Some("no search_path pinned".to_string()),
                Some(items) if items.last().map(String::as_str) != Some("pg_temp") => {
                    Some(format!("pg_temp is not listed last: {:?}", d.path))
                }
                Some(items) if items.iter().filter(|s| *s == "pg_temp").count() != 1 => {
                    Some(format!("pg_temp listed twice: {:?}", d.path))
                }
                Some(_) => None,
            };
            why.map(|w| (sig.clone(), w))
        })
        .collect()
}

fn through_public(defs: &BTreeMap<String, Definer>) -> BTreeSet<String> {
    defs.iter()
        .filter(|(_, d)| d.resolves_through_another_schema())
        .map(|(s, _)| s.clone())
        .collect()
}

/// `src` with comments and string literals blanked (so a name inside a
/// message or a dynamic-SQL string is not read as a reference), lowercased.
fn code_only(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\'' {
            i += 1;
            while i < b.len() {
                if b[i] == b'\'' {
                    if b.get(i + 1) == Some(&b'\'') {
                        i += 2;
                        continue;
                    }
                    i += 1;
                    break;
                }
                i += 1;
            }
            out.push_str("''");
        } else if b[i] == b'-' && b.get(i + 1) == Some(&b'-') {
            i = src[i..].find('\n').map_or(b.len(), |n| i + n);
        } else if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
            i = src[i + 2..].find("*/").map_or(b.len(), |n| i + 2 + n + 2);
            out.push(' ');
        } else {
            // Push the whole (possibly multi-byte) character.
            let ch = src[i..].chars().next().expect("a char");
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out.to_lowercase()
}

/// One identifier of a code-only body: the word, the non-space character
/// before it, the non-space character after it, and the word before it.
struct Word<'a> {
    word: &'a str,
    before: Option<char>,
    two_before: Option<char>,
    after: Option<char>,
    prev_word: Option<&'a str>,
}

fn words(code: &str) -> Vec<Word<'_>> {
    let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '$';
    let chars: Vec<(usize, char)> = code.char_indices().collect();
    let mut out: Vec<Word<'_>> = Vec::new();
    let mut k = 0;
    let mut prev_word: Option<&str> = None;
    while k < chars.len() {
        let (start, c) = chars[k];
        if !(c.is_ascii_alphabetic() || c == '_') {
            k += 1;
            continue;
        }
        let mut e = k;
        while e < chars.len() && is_ident(chars[e].1) {
            e += 1;
        }
        let end = chars.get(e).map_or(code.len(), |(i, _)| *i);
        let word = &code[start..end];
        let mut bk = k;
        let mut before = None;
        let mut two_before = None;
        while bk > 0 {
            bk -= 1;
            if !chars[bk].1.is_whitespace() {
                before = Some(chars[bk].1);
                two_before = bk.checked_sub(1).map(|j| chars[j].1);
                break;
            }
        }
        let after = chars[e..]
            .iter()
            .map(|(_, c)| *c)
            .find(|c| !c.is_whitespace());
        out.push(Word {
            word,
            before,
            two_before,
            after,
            prev_word,
        });
        prev_word = Some(word);
        k = e;
    }
    out
}

/// The `public` names a pg_catalog-only body must qualify:
/// `(relations, types, functions)`. Functions that share a name with a
/// pg_catalog function (pgvector's `avg` / `sum`) are left out: unqualified,
/// they resolve to pg_catalog on such a path, which is the intent.
async fn public_names(pool: &PgPool) -> (BTreeSet<String>, BTreeSet<String>, BTreeSet<String>) {
    let rels: Vec<String> = sqlx::query_scalar(
        "SELECT c.relname::text FROM pg_catalog.pg_class c \
          WHERE c.relnamespace = 'public'::regnamespace \
            AND c.relkind IN ('r', 'v', 'm', 'p', 'f', 'S')",
    )
    .fetch_all(pool)
    .await
    .expect("public relations");
    let types: Vec<String> = sqlx::query_scalar(
        "SELECT t.typname::text FROM pg_catalog.pg_type t \
          WHERE t.typnamespace = 'public'::regnamespace AND t.typtype IN ('e', 'd', 'c')",
    )
    .fetch_all(pool)
    .await
    .expect("public types");
    let fns: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT p.proname::text FROM pg_catalog.pg_proc p \
          WHERE p.pronamespace = 'public'::regnamespace \
            AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_proc q \
                             WHERE q.pronamespace = 'pg_catalog'::regnamespace \
                               AND q.proname = p.proname)",
    )
    .fetch_all(pool)
    .await
    .expect("public functions");
    (
        rels.into_iter().collect(),
        types.into_iter().collect(),
        fns.into_iter().collect(),
    )
}

/// The unqualified `public` references in one body, as `kind name`.
fn unqualified_public_refs(
    src: &str,
    rels: &BTreeSet<String>,
    types: &BTreeSet<String>,
    fns: &BTreeSet<String>,
) -> BTreeSet<String> {
    const RELATION_KEYWORDS: &[&str] = &["from", "join", "update", "into", "table", "only"];
    let code = code_only(src);
    let mut out = BTreeSet::new();
    for w in words(&code) {
        if w.before == Some('.') || w.before == Some('"') {
            continue;
        }
        if rels.contains(w.word) && w.prev_word.is_some_and(|p| RELATION_KEYWORDS.contains(&p)) {
            out.insert(format!("relation {}", w.word));
        }
        if types.contains(w.word)
            && ((w.before == Some(':') && w.two_before == Some(':')) || w.after == Some('%'))
        {
            out.insert(format!("type {}", w.word));
        }
        if fns.contains(w.word) && w.after == Some('(') {
            out.insert(format!("function {}", w.word));
        }
    }
    out
}

/// Probe definers, one per wrong shape the checks must report. plpgsql bodies
/// are not resolved at CREATE, so a probe naming `claims` unqualified on a
/// pg_catalog-only path can be created.
const PROBES: &str = r#"
CREATE FUNCTION public.b04_probe_unpinned() RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN RETURN 1; END $$;
CREATE FUNCTION public.b04_probe_temp_first() RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
    AS $$ BEGIN RETURN 1; END $$;
CREATE FUNCTION public.b04_probe_temp_not_last() RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_temp, public
    AS $$ BEGIN RETURN 1; END $$;
CREATE FUNCTION public.b04_probe_temp_twice() RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_temp, public, pg_temp
    AS $$ BEGIN RETURN 1; END $$;
CREATE FUNCTION public.b04_probe_public_last_temp() RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp
    AS $$ BEGIN RETURN 1; END $$;
CREATE FUNCTION public.b04_probe_unqualified(p uuid) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE v bigint;
BEGIN
    -- comment naming FROM claims is not a reference
    RAISE NOTICE 'neither is a message naming FROM claims';
    SELECT count(*) INTO v FROM claims c WHERE c.id = p;
    PERFORM epigraph_bypass();
    RETURN v;
END $$;
CREATE FUNCTION public.b04_probe_qualified(p uuid) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE v bigint;
BEGIN
    SELECT pg_catalog.count(*) INTO v FROM public.claims c WHERE c.id = p;
    PERFORM public.epigraph_bypass();
    RETURN v;
END $$;
"#;

#[sqlx::test(migrations = "../../migrations")]
async fn every_definer_pins_a_search_path_that_lists_pg_temp_last(pool: PgPool) {
    let at_head = definers(&pool).await;
    assert!(
        at_head.len() > 100,
        "CALIBRATION: the scan sees the schema's definers ({})",
        at_head.len()
    );
    let bad = temp_shadowable(&at_head);

    sqlx::raw_sql(PROBES).execute(&pool).await.expect("probes");
    let with_probes = temp_shadowable(&definers(&pool).await);
    let probed: BTreeSet<&str> = with_probes
        .keys()
        .filter(|k| !bad.contains_key(*k))
        .map(String::as_str)
        .collect();
    assert_eq!(
        probed,
        BTreeSet::from([
            "public.b04_probe_temp_first()",
            "public.b04_probe_temp_not_last()",
            "public.b04_probe_temp_twice()",
            "public.b04_probe_unpinned()",
        ]),
        "CALIBRATION: exactly the unpinned, temp-unlisted, temp-first and temp-twice \
         probes are reported"
    );
    assert!(
        with_probes["public.b04_probe_temp_twice()"].contains("listed twice"),
        "CALIBRATION: a path listing pg_temp first and last is reported as such: {:?}",
        with_probes["public.b04_probe_temp_twice()"]
    );

    assert!(
        bad.is_empty(),
        "{} SECURITY DEFINER function(s) do not pin a search_path that lists pg_temp \
         exactly once, LAST (unpinned, unlisted, or listed earlier). Pin \
         `SET search_path = pg_catalog, pg_temp` (172's form) or append `, pg_temp`:\n{}",
        bad.len(),
        bad.iter()
            .map(|(s, w)| format!("  {s}: {w}"))
            .collect::<Vec<_>>()
            .join("\n")
    );

    // A path change by ALTER FUNCTION keeps every other config entry: the
    // un-retract definer's transaction-local marker (184) survives.
    let unretract = at_head
        .get("public.epigraph_unretract_mass_function(uuid, text, uuid, uuid)")
        .expect("184's un-retract definer");
    assert!(
        unretract
            .config
            .iter()
            .any(|c| c.starts_with("epigraph.mf_unretract_id=")),
        "the un-retract definer keeps its epigraph.mf_unretract_id entry: {:?}",
        unretract.config
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn definers_resolving_through_public_are_exactly_the_register(pool: PgPool) {
    let measured = through_public(&definers(&pool).await);

    sqlx::raw_sql(PROBES).execute(&pool).await.expect("probes");
    let with_probes = through_public(&definers(&pool).await);
    let probed: BTreeSet<&str> = with_probes
        .difference(&measured)
        .map(String::as_str)
        .collect();
    assert_eq!(
        probed,
        BTreeSet::from([
            "public.b04_probe_public_last_temp()",
            "public.b04_probe_temp_first()",
            "public.b04_probe_temp_not_last()",
            "public.b04_probe_temp_twice()",
        ]),
        "CALIBRATION: exactly the probes whose path names public are seen"
    );

    let register: BTreeSet<String> = PUBLIC_PATH_REGISTER.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        register.len(),
        PUBLIC_PATH_REGISTER.len(),
        "PUBLIC_PATH_REGISTER lists an entry twice"
    );
    assert_eq!(
        PUBLIC_PATH_REGISTER.len(),
        HIGH_WATER,
        "PUBLIC_PATH_REGISTER's length is not HIGH_WATER: raise HIGH_WATER with a new entry \
         (a visible decision), lower it with a removed one"
    );
    let unlisted: Vec<&String> = measured.difference(&register).collect();
    let stale: Vec<&String> = register.difference(&measured).collect();
    assert!(
        unlisted.is_empty() && stale.is_empty(),
        "the definers whose search_path names public are not PUBLIC_PATH_REGISTER.\n\
         UNLISTED (a new definer resolving through public: pin `SET search_path = \
         pg_catalog, pg_temp` and schema-qualify every name, 172's form):\n{}\n\
         STALE (no longer a definer on a public path: remove the entry):\n{}\n\
         measured ({}):\n{}",
        unlisted
            .iter()
            .map(|s| format!("  {s}"))
            .collect::<Vec<_>>()
            .join("\n"),
        stale
            .iter()
            .map(|s| format!("  {s}"))
            .collect::<Vec<_>>()
            .join("\n"),
        measured.len(),
        measured
            .iter()
            .map(|s| format!("    \"{s}\","))
            .collect::<Vec<_>>()
            .join("\n"),
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn definers_off_public_name_every_public_object_qualified(pool: PgPool) {
    sqlx::raw_sql(PROBES).execute(&pool).await.expect("probes");
    let (rels, types, fns) = public_names(&pool).await;
    assert!(
        rels.contains("claims") && fns.contains("epigraph_bypass") && !fns.contains("sum"),
        "CALIBRATION: the public name sets are read"
    );
    let defs = definers(&pool).await;
    let mut found: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut scanned = 0;
    for (sig, d) in &defs {
        if d.path.is_none() || d.resolves_through_another_schema() {
            continue;
        }
        scanned += 1;
        let refs = unqualified_public_refs(&d.src, &rels, &types, &fns);
        if !refs.is_empty() {
            found.insert(sig.clone(), refs);
        }
    }
    assert_eq!(
        found.remove("public.b04_probe_unqualified(uuid)"),
        Some(BTreeSet::from([
            "function epigraph_bypass".to_string(),
            "relation claims".to_string(),
        ])),
        "CALIBRATION: the unqualified probe's two references are reported, and the \
         comment and the message naming claims are not"
    );
    assert!(
        !found.contains_key("public.b04_probe_qualified(uuid)"),
        "CALIBRATION: the qualified probe is clean"
    );
    assert!(
        scanned >= 3,
        "CALIBRATION: pg_catalog-only definers were scanned ({scanned})"
    );
    assert!(
        found.is_empty(),
        "pg_catalog-only definers name public objects unqualified (on a \
         `pg_catalog, pg_temp` path such a name is not looked up in public; a function \
         fails 42883). Qualify them `public.<name>`:\n{found:#?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_refresh_and_revocation_family_resolves_in_pg_catalog_only(pool: PgPool) {
    let defs = definers(&pool).await;
    for (sig, app_executes) in PG_CATALOG_ONLY_FAMILY {
        let d = defs
            .get(*sig)
            .unwrap_or_else(|| panic!("{sig} is not a SECURITY DEFINER function"));
        assert_eq!(
            d.config,
            vec!["search_path=pg_catalog, pg_temp".to_string()],
            "{sig}: 172's path"
        );
        assert_eq!(d.owner, "epigraph_maintenance", "{sig}: owner");
        // Style pin, not the security property: on this path an unqualified
        // built-in still resolves in pg_catalog. It keeps the bodies on 172's
        // written form, so a re-statement copied from 118 / 141 shows up here.
        let code = code_only(&d.src);
        for builtin in ["now(", "jsonb_build_object(", "unnest("] {
            let all = code.matches(builtin).count();
            let qualified = code.matches(&format!("pg_catalog.{builtin}")).count();
            assert_eq!(
                all, qualified,
                "{sig}: an unqualified {builtin}..) remains; 172's written form qualifies \
                 every built-in (a body copied from 118 / 141?)"
            );
        }
        let can: (bool, bool) = sqlx::query_as(
            "SELECT has_function_privilege('public', $1::regprocedure, 'EXECUTE'), \
                    has_function_privilege('epigraph_app', $1::regprocedure, 'EXECUTE')",
        )
        .bind(*sig)
        .fetch_one(&pool)
        .await
        .expect("privileges");
        assert_eq!(
            can,
            (false, *app_executes),
            "{sig}: (PUBLIC, epigraph_app) EXECUTE"
        );
    }
    // A pg_catalog-first body still reaches the tables it names.
    let n: i64 = sqlx::query_scalar("SELECT public.epigraph_refresh_token_revoke_client($1)")
        .bind(uuid::Uuid::new_v4())
        .fetch_one(&pool)
        .await
        .expect("revoke_client runs on its pinned path");
    assert_eq!(n, 0);
}

fn below(version: i64) -> Migrator {
    Migrator {
        migrations: Cow::Owned(
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

async fn migrate(pool: &PgPool, migrator: &Migrator) -> Result<(), String> {
    let mut conn = pool.acquire().await.expect("acquire");
    let r = migrator.run(&mut *conn).await.map_err(|e| e.to_string());
    sqlx::query("RESET ALL")
        .execute(&mut *conn)
        .await
        .expect("RESET ALL");
    r
}

/// 190 changes, on every definer that existed before it, only the
/// `search_path` entry (pg_temp appended where it was missing), except the
/// family it re-states, whose path becomes `pg_catalog, pg_temp` and whose
/// body changes only by qualification. No definer appears or disappears, and
/// no owner, ACL or volatility moves.
#[sqlx::test(migrations = false)]
async fn migration_190_changes_only_paths_and_the_family_bodies(pool: PgPool) {
    migrate(&pool, &below(190)).await.expect("migrate to 189");
    let before = definers(&pool).await;
    migrate(&pool, &below(191)).await.expect("migrate to 190");
    let after = definers(&pool).await;
    assert_eq!(
        before.keys().collect::<Vec<_>>(),
        after.keys().collect::<Vec<_>>(),
        "190 adds or drops no definer"
    );
    let family = rebodied();
    let mut appended = 0;
    for (sig, b) in &before {
        let a = &after[sig];
        assert_eq!(
            (&a.owner, &a.acl, &a.volatile),
            (&b.owner, &b.acl, &b.volatile),
            "{sig}: owner, ACL and volatility unchanged"
        );
        let other = |d: &Definer| -> Vec<String> {
            d.config
                .iter()
                .filter(|c| !c.starts_with("search_path="))
                .cloned()
                .collect()
        };
        assert_eq!(other(a), other(b), "{sig}: other config entries unchanged");
        if family.contains(sig.as_str()) {
            assert_eq!(a.path.as_deref(), Some("pg_catalog, pg_temp"), "{sig}");
            assert_ne!(a.src, b.src, "{sig}: 190 re-states the body");
            // The body changes by qualification only: strip the qualifiers
            // 190 adds and the two bodies are the same text.
            let unqualify = |s: &str| s.replace("pg_catalog.", "");
            assert_eq!(
                unqualify(&a.src),
                unqualify(&b.src),
                "{sig}: qualification only"
            );
            continue;
        }
        assert_eq!(a.src, b.src, "{sig}: body unchanged");
        let bp = b.path.clone().expect("every definer before 190 is pinned");
        if b.path_items().unwrap().last().map(String::as_str) == Some("pg_temp") {
            assert_eq!(
                a.path, b.path,
                "{sig}: an already temp-last path is untouched"
            );
        } else {
            assert_eq!(
                a.path,
                Some(format!("{bp}, pg_temp")),
                "{sig}: pg_temp appended"
            );
            appended += 1;
        }
    }
    assert!(appended > 0, "CALIBRATION: 190 appended pg_temp somewhere");
    assert!(
        family.iter().all(|s| before.contains_key(*s)),
        "CALIBRATION: the re-stated family exists before 190"
    );
}

/// 190 re-states each family body whole, so it refuses to apply over any
/// other body and changes nothing (its path sweep included).
/// POSITIVE CONTROL: restored to the exact body, 190 applies.
#[sqlx::test(migrations = false)]
async fn migration_190_refuses_to_apply_over_another_body(pool: PgPool) {
    migrate(&pool, &below(190)).await.expect("migrate to 189");
    let sig = "public.epigraph_refresh_token_revoke(uuid, text)";
    let original: String =
        sqlx::query_scalar("SELECT prosrc FROM pg_catalog.pg_proc WHERE oid = $1::regprocedure")
            .bind(sig)
            .fetch_one(&pool)
            .await
            .expect("the body before 190");
    let set_body = |src: String| {
        let pool = pool.clone();
        async move {
            sqlx::raw_sql(&format!(
                "CREATE OR REPLACE FUNCTION public.epigraph_refresh_token_revoke(p_id uuid, p_reason text) \
                 RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER \
                 SET search_path = pg_catalog, public AS $body${src}$body$"
            ))
            .execute(&pool)
            .await
            .expect("re-body");
        }
    };
    set_body(format!("{original}-- a later migration's delta\n")).await;
    let before = definers(&pool).await;
    let err = migrate(&pool, &below(191))
        .await
        .expect_err("190 over another body");
    assert!(
        err.contains("is not the body 190 re-states"),
        "the refusal names the reason: {err}"
    );
    let applied: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = 190)")
            .fetch_one(&pool)
            .await
            .expect("probe");
    assert!(!applied, "a refused 190 is not recorded");
    assert_eq!(
        definers(&pool).await,
        before,
        "a refused 190 changes no definer"
    );

    set_body(original).await;
    migrate(&pool, &below(191))
        .await
        .expect("POSITIVE CONTROL: over the pre-190 body, 190 applies");
}

/// 190's sweep on path shapes a fresh database does not have, so the ratchets
/// above cannot see them: a path that lists `pg_temp` before another schema
/// (alone, or also last) is refused and changes nothing; once it is gone, an
/// unpinned definer gets `pg_catalog, <its schema>, pg_temp`, a quoted path
/// item survives the append, an already temp-last path is untouched, and
/// other config entries are kept.
#[sqlx::test(migrations = false)]
async fn migration_190_sweep_refuses_temp_before_last_and_pins_the_unpinned(pool: PgPool) {
    migrate(&pool, &below(190)).await.expect("migrate to 189");
    sqlx::raw_sql(
        r#"
CREATE FUNCTION public.b04_sweep_unpinned() RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN RETURN 1; END $$;
CREATE FUNCTION public.b04_sweep_quoted() RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = "$user", public
    AS $$ BEGIN RETURN 1; END $$;
CREATE FUNCTION public.b04_sweep_already_last() RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp
    AS $$ BEGIN RETURN 1; END $$;
"#,
    )
    .execute(&pool)
    .await
    .expect("sweep probes");

    for (bad, path) in [
        ("b04_sweep_temp_first", "pg_temp, public"),
        ("b04_sweep_temp_twice", "pg_temp, public, pg_temp"),
    ] {
        sqlx::raw_sql(&format!(
            "CREATE FUNCTION public.{bad}() RETURNS integer LANGUAGE plpgsql SECURITY DEFINER \
             SET search_path = {path} AS $$ BEGIN RETURN 1; END $$"
        ))
        .execute(&pool)
        .await
        .expect("refusal probe");
        let before = definers(&pool).await;
        let err = migrate(&pool, &below(191))
            .await
            .expect_err("190 over a path listing pg_temp before another schema");
        assert!(
            err.contains("lists pg_temp before another schema") && err.contains(bad),
            "{path}: the refusal names the reason and the function: {err}"
        );
        let applied: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = 190)",
        )
        .fetch_one(&pool)
        .await
        .expect("probe");
        assert!(!applied, "{path}: a refused 190 is not recorded");
        assert_eq!(
            definers(&pool).await,
            before,
            "{path}: a refused 190 changes no definer (its re-bodies roll back too)"
        );
        sqlx::raw_sql(&format!("DROP FUNCTION public.{bad}()"))
            .execute(&pool)
            .await
            .expect("drop the refusal probe");
    }

    migrate(&pool, &below(191))
        .await
        .expect("POSITIVE CONTROL: without the refused shapes, 190 applies");
    let after = definers(&pool).await;
    for (sig, want) in [
        (
            "public.b04_sweep_unpinned()",
            "search_path=pg_catalog, public, pg_temp",
        ),
        (
            "public.b04_sweep_quoted()",
            r#"search_path="$user", public, pg_temp"#,
        ),
        (
            "public.b04_sweep_already_last()",
            "search_path=public, pg_temp",
        ),
    ] {
        assert_eq!(after[sig].config, vec![want.to_string()], "{sig}");
    }
    assert!(
        after["public.epigraph_unretract_mass_function(uuid, text, uuid, uuid)"]
            .config
            .iter()
            .any(|c| c.starts_with("epigraph.mf_unretract_id=")),
        "the sweep keeps the un-retract definer's other config entry"
    );
}

/// `current_schemas(true)` under `path`, with the session's temporary schema
/// written `pg_temp`.
async fn schema_order(conn: &mut sqlx::PgConnection, path: &str) -> Vec<String> {
    sqlx::query(&format!("SET LOCAL search_path = {path}"))
        .execute(&mut *conn)
        .await
        .expect("set the path");
    let s: Vec<String> = sqlx::query_scalar("SELECT pg_catalog.current_schemas(true)::text[]")
        .fetch_one(&mut *conn)
        .await
        .expect("current_schemas");
    s.into_iter()
        .map(|n| {
            if n.starts_with("pg_temp_") {
                "pg_temp".to_string()
            } else {
                n
            }
        })
        .collect()
}

/// The PostgreSQL resolution order every check above relies on: a path that
/// does not list `pg_temp` searches the session's temporary schema first;
/// listing it puts it where it is listed.
#[sqlx::test(migrations = false)]
async fn a_path_without_pg_temp_searches_the_temporary_schema_first(pool: PgPool) {
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("CREATE TEMP TABLE b04_premise (x integer) ON COMMIT DROP")
        .execute(&mut *tx)
        .await
        .expect("a temporary schema exists for the session");
    assert_eq!(
        schema_order(&mut tx, "pg_catalog, public").await,
        ["pg_temp", "pg_catalog", "public"],
        "pg_temp unlisted: searched first"
    );
    assert_eq!(
        schema_order(&mut tx, "pg_catalog, pg_temp").await,
        ["pg_catalog", "pg_temp"],
        "pg_temp listed last: searched last"
    );
    assert_eq!(
        schema_order(&mut tx, "public, pg_temp").await,
        ["pg_catalog", "public", "pg_temp"],
        "pg_catalog unlisted: searched first; pg_temp listed last: searched last"
    );
}

/// What a definer body does with the session's temporary schema, by form:
/// creating a temporary relation, or naming a `pg_temp`-qualified one. Read on
/// the RAW body, lowercased with whitespace collapsed, so a dynamic-SQL string
/// (`EXECUTE 'CREATE TEMP TABLE ..'`) is seen too. A `search_path` value such
/// as `'public, pg_temp'` names no relation (no dot) and is not reported.
fn session_temp_uses(src: &str) -> BTreeSet<&'static str> {
    let flat = src
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace(" .", ".")
        .replace(". ", ".");
    const FORMS: &[(&str, &str)] = &[
        ("create temp ", "CREATE TEMP"),
        ("create temporary ", "CREATE TEMP"),
        ("create global temp", "CREATE TEMP"),
        ("create local temp", "CREATE TEMP"),
        ("create unlogged temp", "CREATE TEMP"),
        ("into temp ", "SELECT INTO TEMP"),
        ("into temporary ", "SELECT INTO TEMP"),
        ("pg_temp.", "pg_temp-qualified relation"),
        ("\"pg_temp\".", "pg_temp-qualified relation"),
    ];
    FORMS
        .iter()
        .filter(|(needle, _)| flat.contains(needle))
        .map(|(_, form)| *form)
        .collect()
}

/// Every function body a definer can run, by `schema.name(argument types)`:
/// every function and procedure outside the system schemas and outside any
/// extension, SECURITY DEFINER or not, except those whose body is a C symbol
/// (`c`, `internal`), with `prosecdef`.
///
/// Not only the definers: an INVOKER function a definer calls, and an INVOKER
/// trigger a definer's statement fires, run with `current_user` = the
/// definer's owner, so a temporary relation one of them creates or names is
/// the caller's to plant exactly as if the definer named it. 206's write
/// window fires 001's invoker `trigger_validate_edge_refs` ->
/// `validate_edge_reference`, for one. The set is wider than what a definer
/// can reach (an invoker function the caller runs directly gains nothing), and
/// deliberately so: walking calls, dynamic SQL and the triggers each statement
/// fires is a fragile analysis, and the superset costs nothing at head.
async fn function_bodies(pool: &PgPool) -> BTreeMap<String, (bool, String)> {
    let rows: Vec<(String, bool, String)> = sqlx::query_as(
        "SELECT format('%s.%s(%s)', n.nspname, p.proname, \
                           pg_catalog.oidvectortypes(p.proargtypes)), \
                    p.prosecdef, p.prosrc \
               FROM pg_catalog.pg_proc p \
               JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace \
               JOIN pg_catalog.pg_language l ON l.oid = p.prolang \
              WHERE l.lanname NOT IN ('c', 'internal') \
                AND n.nspname NOT IN ('pg_catalog', 'information_schema') \
                AND n.nspname !~ '^pg_(toast|temp)' \
                AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d \
                                 WHERE d.classid = 'pg_catalog.pg_proc'::regclass \
                                   AND d.objid = p.oid AND d.deptype = 'e')",
    )
    .fetch_all(pool)
    .await
    .expect("read the function bodies");
    rows.into_iter()
        .map(|(sig, secdef, src)| (sig, (secdef, src)))
        .collect()
}

/// Probe functions for [`no_function_keeps_state_in_a_session_temporary_relation`]:
/// each form it must report, and one it must not.
const TEMP_PROBES: &str = r#"
CREATE FUNCTION public.tmp_probe_static() RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    CREATE TEMP TABLE IF NOT EXISTS pg_temp.tmp_probe (x integer) ON COMMIT DROP;
    RETURN 1;
END $$;
CREATE FUNCTION public.tmp_probe_dynamic() RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    EXECUTE 'CREATE   TEMPORARY TABLE tmp_probe (x integer)';
    RETURN 1;
END $$;
CREATE FUNCTION public.tmp_probe_reads() RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM 1 FROM pg_temp . tmp_probe;
    RETURN 1;
END $$;
CREATE FUNCTION public.tmp_probe_path_only() RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM pg_catalog.set_config('search_path', 'public, pg_temp', true);
    RETURN 1;
END $$;
CREATE FUNCTION public.tmp_probe_invoker_trigger() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    CREATE TEMP TABLE IF NOT EXISTS tmp_probe_seen (x integer);
    RETURN NEW;
END $$;
"#;

/// No function a SECURITY DEFINER body can run keeps state in a
/// session-temporary relation: not the definers, and not the INVOKER helpers
/// and triggers they run as their owner ([`function_bodies`]).
///
/// A temporary relation belongs to the SESSION, not to the definer's owner, so
/// the caller can create one of the same name before the call (with its own
/// triggers and rows), and `CREATE TEMP TABLE IF NOT EXISTS` then adopts it.
/// The body would read and write the caller's relation with the owner's
/// privileges. Classify into local variables, arrays or a CTE instead. 115's
/// `epigraph_delete_mass_functions_scoped` and 206's visibility acts do. The
/// behavioural pin for 206 is the app-role test
/// `a_temp_table_planted_by_the_caller_cannot_steer_publicize_or_share`
/// (epigraph-mcp). No allowlist.
#[sqlx::test(migrations = "../../migrations")]
async fn no_function_keeps_state_in_a_session_temporary_relation(pool: PgPool) {
    let scan =
        |fns: &BTreeMap<String, (bool, String)>| -> BTreeMap<String, BTreeSet<&'static str>> {
            fns.iter()
                .map(|(sig, (_, src))| (sig.clone(), session_temp_uses(src)))
                .filter(|(_, forms)| !forms.is_empty())
                .collect()
        };
    let at_head_fns = function_bodies(&pool).await;
    let definer_count = at_head_fns.values().filter(|(secdef, _)| *secdef).count();
    assert!(
        definer_count > 100 && at_head_fns.len() > definer_count,
        "CALIBRATION: the scan sees the schema's definers ({definer_count}) and more \
         ({} functions)",
        at_head_fns.len()
    );
    for invoker in [
        "public.trigger_validate_edge_refs()",
        "public.validate_edge_reference(uuid, character varying)",
    ] {
        assert!(
            at_head_fns.get(invoker).is_some_and(|(secdef, _)| !secdef),
            "CALIBRATION: the scan sees {invoker}, an INVOKER function 206's write window runs"
        );
    }
    let at_head = scan(&at_head_fns);

    sqlx::raw_sql(TEMP_PROBES)
        .execute(&pool)
        .await
        .expect("probes");
    let with_probes = scan(&function_bodies(&pool).await);
    let probed: BTreeMap<&str, &BTreeSet<&str>> = with_probes
        .iter()
        .filter(|(k, _)| !at_head.contains_key(*k))
        .map(|(k, v)| (k.as_str(), v))
        .collect();
    assert_eq!(
        probed,
        BTreeMap::from([
            (
                "public.tmp_probe_dynamic()",
                &BTreeSet::from(["CREATE TEMP"])
            ),
            (
                "public.tmp_probe_invoker_trigger()",
                &BTreeSet::from(["CREATE TEMP"])
            ),
            (
                "public.tmp_probe_reads()",
                &BTreeSet::from(["pg_temp-qualified relation"])
            ),
            (
                "public.tmp_probe_static()",
                &BTreeSet::from(["CREATE TEMP", "pg_temp-qualified relation"])
            ),
        ]),
        "CALIBRATION: the static, dynamic-SQL, qualified-read and INVOKER-trigger probes are \
         reported, and a body that only sets a search_path naming pg_temp is not"
    );

    assert!(
        at_head.is_empty(),
        "{} function(s) a SECURITY DEFINER body can run create or name a session-temporary \
         relation, which the caller's session can create first. Keep the state in local \
         variables, arrays or a CTE:\n{}",
        at_head.len(),
        at_head
            .iter()
            .map(|(s, f)| format!("  {s}: {f:?}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}
