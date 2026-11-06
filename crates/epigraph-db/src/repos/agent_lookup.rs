//! Find an agent (a person, an LLM agent, a system identity) by name, and the
//! card that tells near-duplicates apart.
//!
//! Serves `GET /api/v1/agents/search` and the MCP tools `find_agent` and
//! `get_agent`, which all call [`AgentLookupRepository`] and nothing else, on
//! the caller's viewer-stamped connection (`read_as`). The ingest author path
//! calls the matcher alone ([`AgentLookupRepository::match_by_name`]).
//!
//! # A new disclosure surface, held to what the caller could already read
//!
//! `agents` rows are readable by every session (migration 077 section 9:
//! `agents_identity ... USING (true)`), and `GET /api/v1/agents/:id` answers
//! for any id, so the EXISTENCE of an agent, its `display_name`, `public_key`
//! and `created_at` are not secrets and name search reveals no hidden agent.
//! Everything else on a card is computed under the caller's [`Viewer`], and
//! every rule below makes a fact the caller may not see produce EXACTLY what
//! an agent without that fact produces (never a distinguishable "hidden"):
//!
//! * `orcid` / `ror_id`, and matching on them: only when the caller passes
//!   [`AgentRepository::get_public_profile`]'s rule (profile public, the
//!   caller is the agent, or shares a live group with it; or an admin). A
//!   private ORCID never matches, so it is not an oracle. `properties`
//!   (`full_name`, `email`, `affiliations`) is never matched and never
//!   returned. `display_name` is matched as written, so a display name that
//!   is itself an email address matches like any other name (every
//!   `display_name` is already public through `GET /api/v1/agents`).
//! * `operator_human` (the human the agent acts for): shown to EVERY reader,
//!   by design: who an agent acts for is public, like the claims it files.
//!   It is read from the binding RECORD (`operator_binding_sql`: the
//!   agent's operator link, else its client allowance), never inferred from
//!   an `OPERATED_BY` edge, which any edge writer can add, and never from
//!   client or registration status, which would let a reader watch a
//!   suspension. The agent's model, prompt snapshot and prompt text are NOT
//!   on the card; they stay behind the prompt-history gate
//!   ([`D4_OPERATOR_GATE_SQL`]).
//! * `kind`: derived from EVIDENCE, never from `agents.agent_type` alone
//!   (the legacy create path defaulted every row to `'human'`). Each evidence
//!   arm is consulted only when the caller may see that evidence; a hidden arm
//!   falls through, so an agent whose only evidence is hidden reads exactly as
//!   one with no evidence (`unknown`). See [`AgentKind`].
//! * `roles`: migration 198's `epigraph_disclosed_role_assignments`: for any
//!   agent, the assignments of roles that neither elevate nor read the audit
//!   trail whose window is open now (exactly what 123's public projection
//!   shows, and decided by the window alone, so client or registration
//!   status never moves it), plus the caller's own assignments of any role.
//! * counts: computed under the caller's viewer with the canonical splice
//!   markers, so a claim or paper edge the caller cannot read never moves a
//!   number. Capped at [`COUNT_CAP`] so a fleet agent with 10^5 claims cannot
//!   stall a request.
//!
//! # Matching
//!
//! Case-insensitive and accent-folded ([`fold_sql`], applied in SQL to BOTH
//! the stored name and the query, so the two can never fold differently).
//! Ranked: ORCID / ROR exact > folded exact > folded prefix (of the name or of
//! one of its words) > trigram similarity ([`TRIGRAM_THRESHOLD`], pg_trgm),
//! then by similarity, then oldest first. No extension beyond pg_trgm
//! (migration 001) is needed: `unaccent` is not assumed.
//!
//! Filters (`kind`, `role`) apply BEFORE the limit: the matcher ranks a
//! bounded candidate set ([`CANDIDATE_POOL`]), the cards are built for it, the
//! filters drop cards, and the result is cut to `limit`. A name shared by
//! more than [`CANDIDATE_POOL`] agents reports `candidates_truncated: true`.
//!
//! Runtime `sqlx::query_as` throughout, so no `.sqlx/` cache entry is needed.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgConnection;
use uuid::Uuid;

use crate::errors::DbError;
use crate::visibility::Viewer;

/// Shortest accepted query, in characters after trimming.
pub const NAME_QUERY_MIN_CHARS: usize = 2;
/// Longest accepted query, in characters.
pub const NAME_QUERY_MAX_CHARS: usize = 200;
/// Default number of results.
pub const FIND_AGENT_DEFAULT_LIMIT: i64 = 10;
/// Most results one call returns.
pub const FIND_AGENT_MAX_LIMIT: i64 = 25;
/// How many ranked name matches are carded and filtered before the limit.
/// Also the cap migration 198's reader enforces per call (200).
pub const CANDIDATE_POOL: i64 = 200;
/// pg_trgm's default `similarity_threshold`.
pub const TRIGRAM_THRESHOLD: f64 = 0.3;
/// Counts stop here; a capped count is reported as this value with
/// `capped: true`.
pub const COUNT_CAP: i64 = 10_000;

/// The prompt-history gate (design D4, migration 161), as a SQL boolean over
/// an agent expression `{agent}`, binding the caller's principal at `$P` and
/// the admin bit ([`Viewer::bypass_bind`]: a bypass or elevated viewer) at
/// `$A`. True when the caller is the human `epigraph_human_of({agent}, false)`
/// names, or an admin. A NULL principal (an unstamped or anonymous caller)
/// is never admitted. It omits 161's unarmed-scopes
/// `epigraph_is_instance_admin` arm, so it admits a subset of what 161
/// admits: never more.
///
/// It gates an agent's PROMPT STATE (model, prompt snapshot, prompt text),
/// never the agent's human: the human is shown to every reader (the card's
/// `operator_human`). The card itself shows no prompt state and does not use
/// this gate; it is the shared text for a surface that does.
pub const D4_OPERATOR_GATE_SQL: &str = "($A::bool OR ($P::uuid IS NOT NULL \
     AND public.epigraph_human_of({agent}, false) = $P::uuid))";

/// [`D4_OPERATOR_GATE_SQL`] with its placeholders filled.
#[must_use]
pub fn d4_operator_gate(agent_expr: &str, principal_bind: usize, admin_bind: usize) -> String {
    D4_OPERATOR_GATE_SQL
        .replace("{agent}", agent_expr)
        .replace("$P", &format!("${principal_bind}"))
        .replace("$A", &format!("${admin_bind}"))
}

/// The accent-, case- and punctuation-folding of a text expression, in SQL.
///
/// NFD-decompose, drop the combining marks (U+0300..U+036F), spell out the
/// letters that do not decompose (`ß` → `ss`, `æ` → `ae`, `ø` → `o`, `ł` →
/// `l`, ...), drop apostrophes (`O'Brien`, `O’Brien` and `OBrien` fold
/// alike), turn hyphens, dashes, periods and commas into spaces
/// (`Jean-Pierre` folds as `jean pierre`, so each part is a word for the
/// prefix tier), lower-case, and collapse whitespace. Built-in functions
/// only: no `unaccent`.
///
/// `lower()` follows the database's collation: under a libc or ICU UTF-8
/// collation it folds Greek, Cyrillic and other cased scripts too; under the
/// `C` collation it folds ASCII only, so non-Latin names then match
/// case-sensitively. The query and the stored name always fold on the same
/// database, so the two sides never fold differently.
#[must_use]
pub fn fold_sql(expr: &str) -> String {
    format!(
        "pg_catalog.btrim(pg_catalog.regexp_replace(pg_catalog.lower(\
           pg_catalog.regexp_replace(pg_catalog.regexp_replace(\
           pg_catalog.translate(\
             pg_catalog.replace(pg_catalog.replace(pg_catalog.replace(pg_catalog.replace(\
             pg_catalog.replace(pg_catalog.replace(pg_catalog.replace(pg_catalog.replace(\
               pg_catalog.regexp_replace(pg_catalog.normalize({expr}, 'NFD'), \
                                         '[\\u0300-\\u036f]', '', 'g'), \
             'ß', 'ss'), 'ẞ', 'SS'), 'æ', 'ae'), 'Æ', 'AE'), 'œ', 'oe'), 'Œ', 'OE'), \
             'þ', 'th'), 'Þ', 'TH'), \
             'øØłŁđĐħĦŧŦıðÐ', 'oOlLdDhHtTidD'), \
           '[''’ʼ]', '', 'g'), \
           '[‐‑‒–—―.,-]', ' ', 'g')), \
         '\\s+', ' ', 'g'))"
    )
}

/// Strip the resolver prefix a ROR id may be written with, in SQL.
fn ident_sql(expr: &str) -> String {
    format!(
        "pg_catalog.lower(pg_catalog.btrim(pg_catalog.regexp_replace(pg_catalog.btrim({expr}), \
           '^https?://(www\\.)?(orcid\\.org|ror\\.org)/', '', 'i')))"
    )
}

/// An ORCID iD's 16-character key, in SQL, or NULL when `expr` is not one:
/// the resolver prefix (with or without a scheme) and every separator are
/// dropped and the check character upper-cased, so `0000-0002-0000-000x`,
/// `000000020000000X` and `https://orcid.org/0000-0002-0000-000X` are one key.
fn orcid_sql(expr: &str) -> String {
    let norm = format!(
        "pg_catalog.upper(pg_catalog.regexp_replace(pg_catalog.regexp_replace(\
           pg_catalog.btrim({expr}), '^(https?://)?(www\\.)?orcid\\.org/', '', 'i'), \
           '[^0-9A-Za-z]', '', 'g'))"
    );
    format!("(CASE WHEN {norm} ~ '^[0-9]{{15}}[0-9X]$' THEN {norm} END)")
}

/// The human an agent acts for, in SQL, read from the binding RECORD so that
/// no client or registration event moves it (it is shown to every reader):
/// the agent's operator link in any state (107's
/// `epigraph_operator_of_author`, retired links included, as
/// `epigraph_human_of(agent, false)` reads them), else the operator its
/// unrevoked migration-149 client allowance names.
///
/// It equals `epigraph_human_of(agent, false)` for every bound agent while
/// that binding is in force. It differs only where `epigraph_human_of`
/// consults client or registration STATUS, which a reader must not be able
/// to watch: an allowance whose client (or whose operator's human client) is
/// not active, or that a second client of the agent suspends, still names
/// its operator; and a registered human that is also linked as an agent (an
/// operated agent, migration 123) names its link operator whether or not its
/// own client is active. Never inferred from an `OPERATED_BY` edge, which
/// any edge writer can add. NULL for an unbound agent.
fn operator_binding_sql(agent: &str) -> String {
    format!(
        "COALESCE((SELECT o.operator_id FROM public.epigraph_operator_of_author({agent}) o), \
                  (SELECT r.operator_id FROM public.author_binding_clients r \
                    WHERE r.agent_id = {agent} AND r.revoked_at IS NULL))"
    )
}

/// How a name matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchTier {
    /// The query is the agent's ORCID (visible to the caller).
    Orcid,
    /// The query is the agent's ROR id (visible to the caller).
    Ror,
    /// The folded name equals the folded query.
    Exact,
    /// The folded name, or one of its words, starts with the folded query.
    Prefix,
    /// Trigram similarity at or above [`TRIGRAM_THRESHOLD`].
    Trigram,
}

impl MatchTier {
    fn parse(s: &str) -> Result<Self, DbError> {
        Ok(match s {
            "orcid" => Self::Orcid,
            "ror" => Self::Ror,
            "exact" => Self::Exact,
            "prefix" => Self::Prefix,
            "trigram" => Self::Trigram,
            other => {
                return Err(DbError::InvalidData {
                    reason: format!("unknown match tier {other}"),
                })
            }
        })
    }
}

/// One ranked candidate of [`AgentLookupRepository::match_by_name`].
#[derive(Debug, Clone, Serialize)]
pub struct AgentNameMatch {
    pub agent_id: Uuid,
    pub display_name: Option<String>,
    pub tier: MatchTier,
    /// pg_trgm `similarity` of the folded name to the folded query (1.0 for
    /// an exact folded match; 0 for an identifier match on a nameless agent).
    pub score: f64,
    pub created_at: DateTime<Utc>,
}

/// What kind of identity an agent is, from the evidence the caller may see.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentKind {
    /// A role's graph node (`agent_type = 'role'`, migrations 123 / 165).
    Role,
    /// A registered system identity (migration 148's `system_agents`).
    System,
    /// A registered human operator (migration 122's `human_operators`), shown
    /// to the human itself and admins (registration status is never shown to
    /// anyone else, the human's own agents included), and to every caller
    /// when the human holds a disclosed role (only registered humans are
    /// granted roles; the window, not the current status, decides).
    Human,
    /// An agent with an LLM model on its (visible) profile, or, failing a
    /// derived author key, an agent bound to a human (`operator_human`).
    LlmAgent,
    /// An author node the document ingest created: its key is the
    /// deterministic name- (or ORCID-) derived key of `did_key_for_author`,
    /// whose private half nobody holds.
    IngestAuthor,
    /// No visible evidence (the legacy rows; `agent_type` is not evidence).
    Unknown,
}

impl AgentKind {
    /// Parse a `kind` filter (`llm_agent`, `ingest_author`, ...).
    ///
    /// # Errors
    /// `DbError::InvalidData` naming the accepted values.
    pub fn parse(s: &str) -> Result<Self, DbError> {
        Ok(
            match s.trim().to_ascii_lowercase().replace('-', "_").as_str() {
                "role" => Self::Role,
                "system" => Self::System,
                "human" => Self::Human,
                "llm_agent" | "llm" | "agent" => Self::LlmAgent,
                "ingest_author" | "author" => Self::IngestAuthor,
                "unknown" => Self::Unknown,
                other => {
                    return Err(DbError::InvalidData {
                        reason: format!(
                            "unknown kind {other:?}: expected one of human, llm_agent, system, \
                         role, ingest_author, unknown"
                        ),
                    })
                }
            },
        )
    }
}

/// An agent the card names (the operator-linked human).
#[derive(Debug, Clone, Serialize)]
pub struct AgentRef {
    pub id: Uuid,
    pub display_name: Option<String>,
}

/// One live role assignment shown on a card.
#[derive(Debug, Clone, Serialize)]
pub struct CardRole {
    pub role: String,
    pub valid_from: DateTime<Utc>,
    pub valid_to: Option<DateTime<Utc>>,
}

/// Counts computed under the caller's viewer.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct CardCounts {
    /// Visible `authored` edges from the agent to a paper.
    pub authored_papers: i64,
    /// Visible claims the agent asserts: those it authored
    /// (`claims.agent_id`) and those an ingest attributed to it (an `asserts`
    /// edge from the agent), each claim once.
    pub asserted_claims: i64,
    /// True when either count reached [`COUNT_CAP`] (the value shown is the cap).
    pub capped: bool,
}

/// What one caller may see about one agent.
#[derive(Debug, Clone, Serialize)]
pub struct AgentCard {
    pub id: Uuid,
    pub display_name: Option<String>,
    pub kind: AgentKind,
    /// The visible evidence `kind` was derived from (every arm the caller may
    /// see, not only the winning one): `role_node`, `system_registry`,
    /// `registered_human_operator`, `holds_disclosed_role`,
    /// `llm_model_on_profile`, `bound_to_visible_human`, `name_derived_key`,
    /// `orcid_derived_key`.
    pub kind_evidence: Vec<&'static str>,
    pub roles: Vec<CardRole>,
    pub orcid: Option<String>,
    pub ror_id: Option<String>,
    /// The human this agent acts for (its binding record), shown to every
    /// reader; `None` for an unbound agent and for a human itself.
    pub operator_human: Option<AgentRef>,
    pub created_at: DateTime<Utc>,
    pub counts: CardCounts,
}

/// An agent the document ingest may be asked to attach as an author
/// ([`AgentLookupRepository::author_nodes`]).
#[derive(Debug, Clone)]
pub struct AuthorNode {
    pub id: Uuid,
    pub display_name: Option<String>,
    /// `agent_type = 'role'` (migrations 123 / 165): a role's graph node.
    pub is_role_node: bool,
    /// Registered in migration 148's `system_agents`.
    pub is_registered_system: bool,
    /// Holds a system role's legacy public-constant key (migration 148).
    pub has_reserved_key: bool,
}

/// One `find_agent` result: the card and how its name matched.
#[derive(Debug, Clone, Serialize)]
pub struct AgentSearchHit {
    pub tier: MatchTier,
    pub score: f64,
    #[serde(flatten)]
    pub card: AgentCard,
}

/// `find_agent` parameters, validated by [`FindAgentQuery::new`].
#[derive(Debug, Clone)]
pub struct FindAgentQuery {
    name: String,
    kind: Option<AgentKind>,
    role: Option<String>,
    limit: i64,
}

impl FindAgentQuery {
    /// Validate a search.
    ///
    /// # Errors
    /// `DbError::InvalidData` for a name shorter than
    /// [`NAME_QUERY_MIN_CHARS`] or longer than [`NAME_QUERY_MAX_CHARS`], an
    /// unknown `kind`, or a blank `role`. `limit` is clamped to
    /// `1..=FIND_AGENT_MAX_LIMIT` (default [`FIND_AGENT_DEFAULT_LIMIT`]).
    pub fn new(
        name: &str,
        kind: Option<&str>,
        role: Option<&str>,
        limit: Option<i64>,
    ) -> Result<Self, DbError> {
        let name = name.trim();
        let n = name.chars().count();
        if !(NAME_QUERY_MIN_CHARS..=NAME_QUERY_MAX_CHARS).contains(&n) {
            return Err(DbError::InvalidData {
                reason: format!(
                    "name must be {NAME_QUERY_MIN_CHARS} to {NAME_QUERY_MAX_CHARS} characters \
                     (got {n})"
                ),
            });
        }
        let kind = kind
            .filter(|k| !k.trim().is_empty())
            .map(AgentKind::parse)
            .transpose()?;
        let role = match role.map(str::trim) {
            None => None,
            Some("") => {
                return Err(DbError::InvalidData {
                    reason: "role must not be blank".to_string(),
                })
            }
            Some(r) => Some(normalize_role_key(r)),
        };
        Ok(Self {
            name: name.to_string(),
            kind,
            role,
            limit: limit
                .unwrap_or(FIND_AGENT_DEFAULT_LIMIT)
                .clamp(1, FIND_AGENT_MAX_LIMIT),
        })
    }
}

/// `role:ndi-member` and `ndi-member` name the same catalog role.
fn normalize_role_key(r: &str) -> String {
    let r = r.trim().to_ascii_lowercase();
    if r.starts_with("role:") {
        r
    } else {
        format!("role:{r}")
    }
}

/// `find_agent`'s result.
#[derive(Debug, Clone, Serialize)]
pub struct FindAgentResult {
    pub results: Vec<AgentSearchHit>,
    /// True when more than [`CANDIDATE_POOL`] agents matched the name, so a
    /// filtered search may have missed some: narrow the name.
    pub candidates_truncated: bool,
}

/// Agent lookup: the matcher, the card, and the search that joins them.
pub struct AgentLookupRepository;

impl AgentLookupRepository {
    /// Agents whose name (or visible ORCID / ROR id) matches `query`, ranked,
    /// at most `limit` (clamped to `1..=CANDIDATE_POOL`).
    ///
    /// The reusable matcher: `find_agent` and the ingest author path both
    /// call it. Runs on the caller's connection (a `read_as` connection or the
    /// ingest's stamped transaction); `viewer` decides only whether ORCID /
    /// ROR may match.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the read fails.
    pub async fn match_by_name(
        conn: &mut PgConnection,
        viewer: &Viewer,
        query: &str,
        limit: i64,
    ) -> Result<Vec<AgentNameMatch>, DbError> {
        Self::match_ranked(conn, viewer, query, limit.clamp(1, CANDIDATE_POOL)).await
    }

    /// [`Self::match_by_name`] without the clamp (`find` asks for one more
    /// than the pool, to tell "exactly the pool" from "more").
    async fn match_ranked(
        conn: &mut PgConnection,
        viewer: &Viewer,
        query: &str,
        limit: i64,
    ) -> Result<Vec<AgentNameMatch>, DbError> {
        let sql = format!(
            "WITH q AS ( \
                 SELECT {fold_q} AS f, {ident_q} AS ident, {orcid_q} AS orcid_q \
             ), q2 AS ( \
                 SELECT f, ident, orcid_q, \
                        pg_catalog.replace(pg_catalog.replace(pg_catalog.replace(f, '\\', '\\\\'), \
                                           '%', '\\%'), '_', '\\_') AS f_like \
                   FROM q \
             ), cand AS ( \
                 SELECT a.id, a.display_name, a.created_at, \
                        {fold_name} AS fname, \
                        ($4::bool OR a.profile_visibility = 'public' \
                           OR ($2::uuid IS NOT NULL AND a.id = $2::uuid) \
                           OR EXISTS (SELECT 1 FROM group_memberships gm \
                                       WHERE gm.agent_id = a.id AND gm.revoked_at IS NULL \
                                         AND gm.group_id = ANY($3::uuid[]))) AS details_ok, \
                        {ident_orcid} AS orcid_k, {ident_ror} AS ror_k \
                   FROM agents a \
             ), ranked AS ( \
                 SELECT c.id, c.display_name, c.created_at, \
                        CASE \
                          WHEN c.details_ok AND c.orcid_k = q2.orcid_q THEN 'orcid' \
                          WHEN c.details_ok AND q2.ident <> '' AND c.ror_k = q2.ident THEN 'ror' \
                          WHEN c.fname = q2.f THEN 'exact' \
                          WHEN c.fname LIKE q2.f_like || '%' \
                            OR c.fname LIKE '% ' || q2.f_like || '%' THEN 'prefix' \
                          ELSE 'trigram' \
                        END AS tier, \
                        COALESCE(similarity(c.fname, q2.f), 0)::float8 AS score \
                   FROM cand c, q2 \
                  WHERE q2.f <> '' AND ( \
                        (c.details_ok AND (c.orcid_k = q2.orcid_q \
                                            OR (q2.ident <> '' AND c.ror_k = q2.ident))) \
                     OR c.fname = q2.f \
                     OR c.fname LIKE q2.f_like || '%' \
                     OR c.fname LIKE '% ' || q2.f_like || '%' \
                     OR similarity(c.fname, q2.f) >= $5) \
             ) \
             SELECT id, display_name, created_at, tier, score FROM ranked \
              ORDER BY CASE tier WHEN 'orcid' THEN 0 WHEN 'ror' THEN 0 WHEN 'exact' THEN 1 \
                                 WHEN 'prefix' THEN 2 ELSE 3 END, \
                       score DESC, created_at, id \
              LIMIT $6",
            fold_q = fold_sql("$1::text"),
            ident_q = ident_sql("$1::text"),
            orcid_q = orcid_sql("$1::text"),
            fold_name = fold_sql("a.display_name"),
            ident_orcid = orcid_sql("a.orcid"),
            ident_ror = ident_sql("a.ror_id"),
        );
        type MatchRow = (Uuid, Option<String>, DateTime<Utc>, String, f64);
        let rows: Vec<MatchRow> = sqlx::query_as(&sql)
            .bind(query)
            .bind(viewer.principal())
            .bind(viewer.group_bind().unwrap_or(&[]))
            .bind(viewer.bypass_bind())
            .bind(TRIGRAM_THRESHOLD)
            .bind(limit)
            .fetch_all(&mut *conn)
            .await?;
        rows.into_iter()
            .map(|(agent_id, display_name, created_at, tier, score)| {
                Ok(AgentNameMatch {
                    agent_id,
                    display_name,
                    tier: MatchTier::parse(&tier)?,
                    score,
                    created_at,
                })
            })
            .collect()
    }

    /// The card of each of `ids` that exists, in `ids` order (duplicates and
    /// unknown ids dropped). At most [`CANDIDATE_POOL`] ids.
    ///
    /// # Errors
    /// `DbError::InvalidData` for more than [`CANDIDATE_POOL`] ids;
    /// `DbError::QueryFailed` if a read fails.
    pub async fn cards(
        conn: &mut PgConnection,
        viewer: &Viewer,
        ids: &[Uuid],
    ) -> Result<Vec<AgentCard>, DbError> {
        Self::cards_inner(conn, viewer, ids, true).await
    }

    /// [`Self::cards`], with the (capped, but per-agent) counts computed only
    /// when `with_counts`; otherwise they are zero and `find` fills them in for
    /// the cards it returns, so a 200-candidate pool never costs 200 counts.
    async fn cards_inner(
        conn: &mut PgConnection,
        viewer: &Viewer,
        ids: &[Uuid],
        with_counts: bool,
    ) -> Result<Vec<AgentCard>, DbError> {
        let mut seen = std::collections::HashSet::new();
        let ids: Vec<Uuid> = ids.iter().copied().filter(|id| seen.insert(*id)).collect();
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        if ids.len() > usize::try_from(CANDIDATE_POOL).unwrap_or(200) {
            return Err(DbError::InvalidData {
                reason: format!("at most {CANDIDATE_POOL} agents per card read"),
            });
        }

        // 1. The rows, and every evidence bit already narrowed IN SQL to what
        //    this caller may see (a hidden bit is computed as false/NULL, so
        //    it never reaches Rust as a distinguishable value).
        let sql = format!(
            "SELECT a.id, a.display_name, a.created_at, a.public_key, \
                    COALESCE(a.agent_type = 'role', false) AS is_role_node, \
                    EXISTS (SELECT 1 FROM public.system_agents sa WHERE sa.agent_id = a.id) \
                        AS is_system, \
                    COALESCE(d.details_ok AND a.properties ? 'llm_model', false) AS llm_model_visible, \
                    CASE WHEN d.details_ok THEN a.orcid END AS orcid, \
                    CASE WHEN d.details_ok THEN a.ror_id END AS ror_id, \
                    COALESCE(($4::bool OR ($2::uuid IS NOT NULL AND a.id = $2::uuid)) \
                      AND public.epigraph_is_human_operator(a.id), false) AS human_visible, \
                    CASE WHEN h.human IS DISTINCT FROM a.id THEN h.human END AS operator_human, \
                    u.ord \
               FROM unnest($1::uuid[]) WITH ORDINALITY AS u(id, ord) \
               JOIN agents a ON a.id = u.id \
              CROSS JOIN LATERAL (SELECT COALESCE(($4::bool OR a.profile_visibility = 'public' \
                     OR ($2::uuid IS NOT NULL AND a.id = $2::uuid) \
                     OR EXISTS (SELECT 1 FROM group_memberships gm \
                                 WHERE gm.agent_id = a.id AND gm.revoked_at IS NULL \
                                   AND gm.group_id = ANY($3::uuid[]))), false) AS details_ok) d \
              CROSS JOIN LATERAL (SELECT {binding} AS human) h \
              ORDER BY u.ord",
            binding = operator_binding_sql("a.id"),
        );
        type Row = (
            Uuid,
            Option<String>,
            DateTime<Utc>,
            Vec<u8>,
            bool,
            bool,
            bool,
            Option<String>,
            Option<String>,
            bool,
            Option<Uuid>,
            i64,
        );
        let rows: Vec<Row> = sqlx::query_as(&sql)
            .bind(&ids)
            .bind(viewer.principal())
            .bind(viewer.group_bind().unwrap_or(&[]))
            .bind(viewer.bypass_bind())
            .fetch_all(&mut *conn)
            .await?;

        // 2. Disclosed roles (migration 198), for every carded agent at once.
        let roles = Self::disclosed_roles(conn, &ids).await?;

        // 3. The operator-linked humans' names (agents are public).
        let humans: Vec<Uuid> = rows.iter().filter_map(|r| r.10).collect();
        let human_names: HashMap<Uuid, Option<String>> = if humans.is_empty() {
            HashMap::new()
        } else {
            sqlx::query_as::<_, (Uuid, Option<String>)>(
                "SELECT id, display_name FROM agents WHERE id = ANY($1::uuid[])",
            )
            .bind(&humans)
            .fetch_all(&mut *conn)
            .await?
            .into_iter()
            .collect()
        };

        // 4. Counts under the caller's viewer.
        let counts = if with_counts {
            Self::counts(conn, viewer, &ids).await?
        } else {
            HashMap::new()
        };

        let mut out = Vec::with_capacity(rows.len());
        for (
            id,
            display_name,
            created_at,
            public_key,
            is_role_node,
            is_system,
            llm_model_visible,
            orcid,
            ror_id,
            human_visible,
            operator_human,
            _ord,
        ) in rows
        {
            let roles = roles.get(&id).cloned().unwrap_or_default();
            let mut evidence: Vec<&'static str> = Vec::new();
            if is_role_node {
                evidence.push("role_node");
            }
            if is_system {
                evidence.push("system_registry");
            }
            if human_visible {
                evidence.push("registered_human_operator");
            }
            if !roles.is_empty() {
                evidence.push("holds_disclosed_role");
            }
            if llm_model_visible {
                evidence.push("llm_model_on_profile");
            }
            if operator_human.is_some() {
                evidence.push("bound_to_visible_human");
            }
            let (name_key, orcid_key) =
                derived_key_evidence(&public_key, display_name.as_deref(), orcid.as_deref());
            if name_key {
                evidence.push("name_derived_key");
            }
            if orcid_key {
                evidence.push("orcid_derived_key");
            }
            let kind = kind_from_evidence(&evidence);
            out.push(AgentCard {
                id,
                display_name,
                kind,
                kind_evidence: evidence,
                roles,
                orcid,
                ror_id,
                operator_human: operator_human.map(|h| AgentRef {
                    id: h,
                    display_name: human_names.get(&h).cloned().flatten(),
                }),
                created_at,
                counts: counts.get(&id).copied().unwrap_or(CardCounts {
                    authored_papers: 0,
                    asserted_claims: 0,
                    capped: false,
                }),
            });
        }
        Ok(out)
    }

    /// One agent's card (`get_agent`), or `None` for an id with no agent.
    ///
    /// # Errors
    /// As [`Self::cards`].
    pub async fn card(
        conn: &mut PgConnection,
        viewer: &Viewer,
        id: Uuid,
    ) -> Result<Option<AgentCard>, DbError> {
        Ok(Self::cards(conn, viewer, &[id]).await?.into_iter().next())
    }

    /// What the document ingest needs to know about each of `ids` it may
    /// attach as an author: public `agents` columns (`agents_identity` is
    /// `USING (true)`, so this reveals nothing a caller could not read with
    /// `GET /api/v1/agents/:id`) and migration 148's registry, which the
    /// application role may read. Unknown ids are dropped; at most
    /// [`CANDIDATE_POOL`] ids.
    ///
    /// # Errors
    /// `DbError::InvalidData` for more than [`CANDIDATE_POOL`] ids;
    /// `DbError::QueryFailed` if the read fails.
    pub async fn author_nodes(
        conn: &mut PgConnection,
        ids: &[Uuid],
    ) -> Result<Vec<AuthorNode>, DbError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        if ids.len() > usize::try_from(CANDIDATE_POOL).unwrap_or(200) {
            return Err(DbError::InvalidData {
                reason: format!("at most {CANDIDATE_POOL} agent ids per call"),
            });
        }
        type Row = (Uuid, Option<String>, String, Vec<u8>, bool);
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT a.id, a.display_name, a.agent_type, a.public_key, \
                    EXISTS (SELECT 1 FROM system_agents s WHERE s.agent_id = a.id) \
               FROM agents a WHERE a.id = ANY($1::uuid[])",
        )
        .bind(ids)
        .fetch_all(&mut *conn)
        .await?;
        let mut by_id: HashMap<Uuid, AuthorNode> = rows
            .into_iter()
            .map(|(id, display_name, agent_type, public_key, system)| {
                let has_reserved_key = <[u8; 32]>::try_from(public_key.as_slice())
                    .is_ok_and(|k| crate::is_reserved_author_key(&k));
                (
                    id,
                    AuthorNode {
                        id,
                        display_name,
                        is_role_node: agent_type == "role",
                        is_registered_system: system,
                        has_reserved_key,
                    },
                )
            })
            .collect();
        Ok(ids.iter().filter_map(|id| by_id.remove(id)).collect())
    }

    /// For each `(name, attached)` pair, the agents OTHER than `attached`
    /// whose folded name equals the folded `name` (the matcher's `exact` tier,
    /// [`fold_sql`] on both sides, exactly as [`Self::match_by_name`] folds),
    /// excluding registered system identities, holders of a system role's
    /// legacy key and role nodes (none can author), oldest first, at most
    /// `limit` per pair; and how many there are in all (so the caller knows
    /// when the list is cut).
    ///
    /// What the document ingest reports as an author's `candidates` when it
    /// attaches the name-derived node and will not choose among the others.
    /// One statement for the whole author list, so the folded name of each
    /// agent is computed once per document rather than once per author
    /// (MEASURED, 7,600 agents, debug build: a 50-author document spent ~12 s
    /// in a per-author matcher call). The matches carry only public fields
    /// (id, `display_name`, `created_at`); the ORCID / ROR tiers never apply,
    /// so nothing here depends on the caller's viewer.
    ///
    /// # Errors
    /// `DbError::InvalidData` when `names` and `attached` differ in length;
    /// `DbError::QueryFailed` if the read fails.
    pub async fn exact_name_candidates(
        conn: &mut PgConnection,
        names: &[String],
        attached: &[Uuid],
        limit: i64,
    ) -> Result<Vec<(Vec<AgentNameMatch>, i64)>, DbError> {
        if names.len() != attached.len() {
            return Err(DbError::InvalidData {
                reason: "one attached id per name".to_string(),
            });
        }
        if names.is_empty() {
            return Ok(Vec::new());
        }
        // A system role's legacy key is unique in `agents`, so at most one row
        // per role can hold one: fetch that many extra and drop them below
        // (`is_reserved_author_key`), keeping `limit` and the total exact.
        let slack =
            i64::try_from(crate::repos::system_agent::SystemAgentRole::ALL.len()).unwrap_or(1);
        let sql = format!(
            "WITH q AS ( \
                 SELECT u.ord, {fold_q} AS f, u.attached \
                   FROM unnest($1::text[], $2::uuid[]) WITH ORDINALITY AS u(name, attached, ord) \
             ), c AS ( \
                 SELECT a.id, a.display_name, a.created_at, a.public_key, {fold_name} AS fname \
                   FROM agents a \
                  WHERE a.agent_type <> 'role' \
                    AND NOT EXISTS (SELECT 1 FROM system_agents s WHERE s.agent_id = a.id) \
             ), m AS ( \
                 SELECT q.ord, c.id, c.display_name, c.created_at, c.public_key, \
                        pg_catalog.row_number() OVER (PARTITION BY q.ord \
                                                      ORDER BY c.created_at, c.id) AS rn, \
                        pg_catalog.count(*) OVER (PARTITION BY q.ord) AS n \
                   FROM q JOIN c ON c.fname = q.f \
                  WHERE q.f <> '' AND c.id <> q.attached \
             ) \
             SELECT ord, id, display_name, created_at, public_key, n FROM m \
              WHERE rn <= $3 + $4 ORDER BY ord, rn",
            fold_q = fold_sql("u.name"),
            fold_name = fold_sql("a.display_name"),
        );
        type Row = (i64, Uuid, Option<String>, DateTime<Utc>, Vec<u8>, i64);
        let limit = limit.max(1);
        let rows: Vec<Row> = sqlx::query_as(&sql)
            .bind(names)
            .bind(attached)
            .bind(limit)
            .bind(slack)
            .fetch_all(&mut *conn)
            .await?;
        let keep = usize::try_from(limit).unwrap_or(usize::MAX);
        let mut out: Vec<(Vec<AgentNameMatch>, i64)> =
            (0..names.len()).map(|_| (Vec::new(), 0)).collect();
        let mut counted = vec![false; names.len()];
        for (ord, agent_id, display_name, created_at, public_key, n) in rows {
            let Some(i) = usize::try_from(ord - 1).ok().filter(|i| *i < out.len()) else {
                continue;
            };
            let slot = &mut out[i];
            if !counted[i] {
                counted[i] = true;
                slot.1 = n;
            }
            if <[u8; 32]>::try_from(public_key.as_slice())
                .is_ok_and(|k| crate::is_reserved_author_key(&k))
            {
                slot.1 -= 1;
                continue;
            }
            if slot.0.len() < keep {
                slot.0.push(AgentNameMatch {
                    agent_id,
                    display_name,
                    tier: MatchTier::Exact,
                    score: 1.0,
                    created_at,
                });
            }
        }
        Ok(out)
    }

    /// `find_agent`: rank name matches, card them, filter, cut to the limit.
    ///
    /// # Errors
    /// As [`Self::match_by_name`] and [`Self::cards`].
    pub async fn find(
        conn: &mut PgConnection,
        viewer: &Viewer,
        query: &FindAgentQuery,
    ) -> Result<FindAgentResult, DbError> {
        // One more than the pool, to tell "exactly the pool" from "more".
        let mut matches = Self::match_ranked(conn, viewer, &query.name, CANDIDATE_POOL + 1).await?;
        let pool = usize::try_from(CANDIDATE_POOL).unwrap_or(200);
        let candidates_truncated = matches.len() > pool;
        matches.truncate(pool);
        let ids: Vec<Uuid> = matches.iter().map(|m| m.agent_id).collect();
        // Cards WITHOUT counts for the whole pool (counts never filter), then
        // counts for the survivors only.
        let cards = Self::cards_inner(conn, viewer, &ids, false).await?;
        let by_id: HashMap<Uuid, &AgentNameMatch> =
            matches.iter().map(|m| (m.agent_id, m)).collect();
        let limit = usize::try_from(query.limit).unwrap_or(1);
        let mut results: Vec<AgentSearchHit> = cards
            .into_iter()
            .filter(|c| query.kind.is_none_or(|k| c.kind == k))
            .filter(|c| {
                query
                    .role
                    .as_deref()
                    .is_none_or(|r| c.roles.iter().any(|cr| cr.role == r))
            })
            .take(limit)
            .filter_map(|card| {
                by_id.get(&card.id).map(|m| AgentSearchHit {
                    tier: m.tier,
                    score: m.score,
                    card,
                })
            })
            .collect();
        let survivors: Vec<Uuid> = results.iter().map(|h| h.card.id).collect();
        if !survivors.is_empty() {
            let counts = Self::counts(conn, viewer, &survivors).await?;
            for hit in &mut results {
                if let Some(c) = counts.get(&hit.card.id) {
                    hit.card.counts = *c;
                }
            }
        }
        Ok(FindAgentResult {
            results,
            candidates_truncated,
        })
    }

    /// Migration 198's disclosed role assignments of `ids`, by agent.
    async fn disclosed_roles(
        conn: &mut PgConnection,
        ids: &[Uuid],
    ) -> Result<HashMap<Uuid, Vec<CardRole>>, DbError> {
        type RoleRow = (Uuid, String, DateTime<Utc>, Option<DateTime<Utc>>);
        let rows: Vec<RoleRow> = sqlx::query_as(
            "SELECT agent_id, role, valid_from, valid_to \
               FROM public.epigraph_disclosed_role_assignments($1::uuid[])",
        )
        .bind(ids)
        .fetch_all(&mut *conn)
        .await?;
        let mut out: HashMap<Uuid, Vec<CardRole>> = HashMap::new();
        for (agent, role, valid_from, valid_to) in rows {
            out.entry(agent).or_default().push(CardRole {
                role,
                valid_from,
                valid_to,
            });
        }
        Ok(out)
    }

    /// Visible authored papers and asserted claims of each of `ids`, capped.
    async fn counts(
        conn: &mut PgConnection,
        viewer: &Viewer,
        ids: &[Uuid],
    ) -> Result<HashMap<Uuid, CardCounts>, DbError> {
        let sql = viewer.splice(
            r"
            SELECT u.id,
                   (SELECT count(*) FROM (
                        SELECT 1 FROM edges e
                         WHERE e.source_id = u.id AND e.source_type = 'agent'
                           AND e.relationship = 'authored' AND e.target_type = 'paper'
                           /* {EDGE_VISIBILITY:e} */
                         LIMIT $2) p) AS papers,
                   (SELECT count(*) FROM (
                        (SELECT c.id FROM claims c
                          WHERE c.agent_id = u.id
                            /* {VISIBILITY:c} */
                          LIMIT $2)
                        UNION
                        (SELECT c2.id FROM edges e2
                           JOIN claims c2 ON c2.id = e2.target_id
                          WHERE e2.source_id = u.id AND e2.source_type = 'agent'
                            AND e2.relationship = 'asserts' AND e2.target_type = 'claim'
                            /* {EDGE_VISIBILITY:e2} */
                            /* {VISIBILITY:c2} */
                          LIMIT $2)) k) AS claims
              FROM unnest($1::uuid[]) AS u(id)
            ",
            3,
        );
        let mut q = sqlx::query_as::<_, (Uuid, i64, i64)>(&sql)
            .bind(ids)
            .bind(COUNT_CAP + 1);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows = q.fetch_all(&mut *conn).await?;
        Ok(rows
            .into_iter()
            .map(|(id, papers, claims)| {
                let capped = papers > COUNT_CAP || claims > COUNT_CAP;
                (
                    id,
                    CardCounts {
                        authored_papers: papers.min(COUNT_CAP),
                        asserted_claims: claims.min(COUNT_CAP),
                        capped,
                    },
                )
            })
            .collect())
    }
}

/// Is `public_key` the deterministic author key the document ingest derives
/// (`did_key_for_author`) from this name, or from this (visible) ORCID?
fn derived_key_evidence(
    public_key: &[u8],
    name: Option<&str>,
    orcid: Option<&str>,
) -> (bool, bool) {
    let by_name = name.is_some_and(|n| {
        !n.trim().is_empty()
            && epigraph_crypto::did_key::did_key_for_author(None, n)
                .1
                .as_slice()
                == public_key
    });
    let by_orcid = orcid.is_some_and(|o| {
        !o.trim().is_empty()
            && epigraph_crypto::did_key::did_key_for_author(Some(o), "")
                .1
                .as_slice()
                == public_key
    });
    (by_name, by_orcid)
}

/// The winning kind, by precedence over the visible evidence.
fn kind_from_evidence(evidence: &[&str]) -> AgentKind {
    let has = |e: &str| evidence.contains(&e);
    if has("role_node") {
        AgentKind::Role
    } else if has("system_registry") {
        AgentKind::System
    } else if has("registered_human_operator") || has("holds_disclosed_role") {
        AgentKind::Human
    } else if has("llm_model_on_profile") {
        AgentKind::LlmAgent
    } else if has("name_derived_key") || has("orcid_derived_key") {
        // An ingest author node bound to its human (a legacy author) is
        // still an ingest author: the binding says whose it is, not what.
        AgentKind::IngestAuthor
    } else if has("bound_to_visible_human") {
        AgentKind::LlmAgent
    } else {
        AgentKind::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_precedence_and_fallthrough() {
        assert_eq!(kind_from_evidence(&[]), AgentKind::Unknown);
        assert_eq!(
            kind_from_evidence(&["name_derived_key"]),
            AgentKind::IngestAuthor
        );
        // A legacy author node bound to its human is still an ingest author;
        // only a model on its profile makes it an LLM agent.
        assert_eq!(
            kind_from_evidence(&["bound_to_visible_human", "name_derived_key"]),
            AgentKind::IngestAuthor
        );
        assert_eq!(
            kind_from_evidence(&["llm_model_on_profile", "orcid_derived_key"]),
            AgentKind::LlmAgent
        );
        assert_eq!(
            kind_from_evidence(&["bound_to_visible_human"]),
            AgentKind::LlmAgent
        );
        assert_eq!(
            kind_from_evidence(&["holds_disclosed_role"]),
            AgentKind::Human
        );
        assert_eq!(
            kind_from_evidence(&["system_registry", "registered_human_operator"]),
            AgentKind::System
        );
        assert_eq!(kind_from_evidence(&["role_node"]), AgentKind::Role);
    }

    #[test]
    fn the_ingest_author_key_is_recognised_by_name_only_when_it_is_that_name() {
        let (_, k) = epigraph_crypto::did_key::did_key_for_author(None, "Wren Halloway");
        assert_eq!(
            derived_key_evidence(&k, Some("Wren Halloway"), None),
            (true, false)
        );
        assert_eq!(
            derived_key_evidence(&k, Some("Wren Hallowey"), None),
            (false, false)
        );
        assert_eq!(
            derived_key_evidence(&[7u8; 32], Some("Wren Halloway"), None),
            (false, false)
        );
    }

    #[test]
    fn query_validation() {
        assert!(FindAgentQuery::new("a", None, None, None).is_err());
        assert!(FindAgentQuery::new(&"x".repeat(201), None, None, None).is_err());
        assert!(FindAgentQuery::new("ab", Some("wizard"), None, None).is_err());
        assert!(FindAgentQuery::new("ab", None, Some("  "), None).is_err());
        let q = FindAgentQuery::new(" ab ", Some("LLM-agent"), Some("NDI-Member"), Some(999))
            .expect("valid");
        assert_eq!(q.name, "ab");
        assert_eq!(q.kind, Some(AgentKind::LlmAgent));
        assert_eq!(q.role.as_deref(), Some("role:ndi-member"));
        assert_eq!(q.limit, FIND_AGENT_MAX_LIMIT);
        assert_eq!(
            FindAgentQuery::new("ab", None, None, Some(0))
                .expect("valid")
                .limit,
            1
        );
    }

    #[test]
    fn the_d4_gate_fills_every_placeholder() {
        let g = d4_operator_gate("a.id", 2, 4);
        assert_eq!(
            g,
            "($4::bool OR ($2::uuid IS NOT NULL AND public.epigraph_human_of(a.id, false) = $2::uuid))"
        );
    }
}
