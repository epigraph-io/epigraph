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
//!   returned; no contact field is ever searched.
//! * `operator_human` (the human the agent acts for, migration 149's
//!   `epigraph_human_of(agent, false)`): only through the prompt-history gate
//!   (design D4, migration 161): the caller IS that human, or the caller is
//!   an admin (a bypass or elevated viewer). [`D4_OPERATOR_GATE_SQL`] is that
//!   gate, in one place, for every surface that shows an agent's human or its
//!   prompt state. (It omits 161's unarmed-scopes `epigraph_is_instance_admin`
//!   arm, so it admits a subset of what 161 admits: never more.)
//! * `kind`: derived from EVIDENCE, never from `agents.agent_type` alone
//!   (the legacy create path defaulted every row to `'human'`). Each evidence
//!   arm is consulted only when the caller may see that evidence; a hidden arm
//!   falls through, so an agent whose only evidence is hidden reads exactly as
//!   one with no evidence (`unknown`). See [`AgentKind`].
//! * `roles`: migration 198's `epigraph_disclosed_role_assignments`, the live
//!   assignments of NON-elevating roles (publicly projected by design, 165),
//!   plus the caller's own assignments of any role.
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
/// is never admitted.
///
/// Every surface that shows an agent's operator-linked human or its prompt
/// state goes through this text, so the surfaces cannot drift apart.
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

/// The accent- and case-folding of a text expression, in SQL.
///
/// NFD-decompose, drop the combining marks (U+0300..U+036F), spell out the
/// letters that do not decompose (`ß` → `ss`, `æ` → `ae`, `ø` → `o`, `ł` →
/// `l`, ...), lower-case (last, so it only ever lower-cases ASCII letters,
/// which every collation does, a `C` one included), and collapse whitespace.
/// Built-in functions only: no `unaccent`.
#[must_use]
pub fn fold_sql(expr: &str) -> String {
    format!(
        "pg_catalog.btrim(pg_catalog.regexp_replace(pg_catalog.lower(\
           pg_catalog.translate(\
             pg_catalog.replace(pg_catalog.replace(pg_catalog.replace(pg_catalog.replace(\
             pg_catalog.replace(pg_catalog.replace(pg_catalog.replace(pg_catalog.replace(\
               pg_catalog.regexp_replace(pg_catalog.normalize({expr}, 'NFD'), \
                                         '[\\u0300-\\u036f]', '', 'g'), \
             'ß', 'ss'), 'ẞ', 'SS'), 'æ', 'ae'), 'Æ', 'AE'), 'œ', 'oe'), 'Œ', 'OE'), \
             'þ', 'th'), 'Þ', 'TH'), \
             'øØłŁđĐħĦŧŦıðÐ', 'oOlLdDhHtTidD')), \
         '\\s+', ' ', 'g'))"
    )
}

/// The profile-detail rule of [`crate::AgentRepository::get_public_profile`]
/// over alias `a`, binding principal `$P`, groups `$G`, admin `$A`.
fn profile_details_sql(principal_bind: usize, groups_bind: usize, admin_bind: usize) -> String {
    format!(
        "(${admin_bind}::bool OR a.profile_visibility = 'public' \
           OR (${principal_bind}::uuid IS NOT NULL AND a.id = ${principal_bind}::uuid) \
           OR EXISTS (SELECT 1 FROM group_memberships gm \
                       WHERE gm.agent_id = a.id AND gm.revoked_at IS NULL \
                         AND gm.group_id = ANY(${groups_bind}::uuid[])))"
    )
}

/// Strip the resolver prefix an ORCID or ROR id may be written with, in SQL.
fn ident_sql(expr: &str) -> String {
    format!(
        "pg_catalog.lower(pg_catalog.btrim(pg_catalog.regexp_replace(pg_catalog.btrim({expr}), \
           '^https?://(www\\.)?(orcid\\.org|ror\\.org)/', '', 'i')))"
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
    /// to the human itself, its own agents, admins, and to every caller when
    /// the human holds a disclosed role (only registered humans hold roles).
    Human,
    /// An agent with an LLM model on its (visible) profile, or bound to a
    /// human the caller may see (D4).
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
    /// The human this agent acts for, when the caller passes the D4 gate.
    pub operator_human: Option<AgentRef>,
    pub created_at: DateTime<Utc>,
    pub counts: CardCounts,
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
                 SELECT {fold_q} AS f, {ident_q} AS ident \
             ), q2 AS ( \
                 SELECT f, ident, \
                        pg_catalog.replace(pg_catalog.replace(pg_catalog.replace(f, '\\', '\\\\'), \
                                           '%', '\\%'), '_', '\\_') AS f_like \
                   FROM q \
             ), cand AS ( \
                 SELECT a.id, a.display_name, a.created_at, \
                        {fold_name} AS fname, \
                        {details} AS details_ok, \
                        {ident_orcid} AS orcid_k, {ident_ror} AS ror_k \
                   FROM agents a \
             ), ranked AS ( \
                 SELECT c.id, c.display_name, c.created_at, \
                        CASE \
                          WHEN c.details_ok AND q2.ident <> '' AND c.orcid_k = q2.ident THEN 'orcid' \
                          WHEN c.details_ok AND q2.ident <> '' AND c.ror_k = q2.ident THEN 'ror' \
                          WHEN c.fname = q2.f THEN 'exact' \
                          WHEN c.fname LIKE q2.f_like || '%' \
                            OR c.fname LIKE '% ' || q2.f_like || '%' THEN 'prefix' \
                          ELSE 'trigram' \
                        END AS tier, \
                        COALESCE(similarity(c.fname, q2.f), 0)::float8 AS score \
                   FROM cand c, q2 \
                  WHERE q2.f <> '' AND ( \
                        (c.details_ok AND q2.ident <> '' \
                          AND (c.orcid_k = q2.ident OR c.ror_k = q2.ident)) \
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
            fold_name = fold_sql("a.display_name"),
            details = profile_details_sql(2, 3, 4),
            ident_orcid = ident_sql("a.orcid"),
            ident_ror = ident_sql("a.ror_id"),
        );
        let rows: Vec<(Uuid, Option<String>, DateTime<Utc>, String, f64)> = sqlx::query_as(&sql)
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
                    COALESCE(($4::bool OR ($2::uuid IS NOT NULL \
                         AND (a.id = $2::uuid \
                              OR public.epigraph_human_of($2::uuid, false) = a.id))) \
                      AND public.epigraph_is_human_operator(a.id), false) AS human_visible, \
                    CASE WHEN {d4} AND h.human IS DISTINCT FROM a.id THEN h.human END \
                        AS operator_human, \
                    u.ord \
               FROM unnest($1::uuid[]) WITH ORDINALITY AS u(id, ord) \
               JOIN agents a ON a.id = u.id \
              CROSS JOIN LATERAL (SELECT COALESCE({details}, false) AS details_ok) d \
              CROSS JOIN LATERAL (SELECT public.epigraph_human_of(a.id, false) AS human) h \
              ORDER BY u.ord",
            d4 = d4_operator_gate("a.id", 2, 4),
            details = profile_details_sql(2, 3, 4),
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
        let counts = Self::counts(conn, viewer, &ids).await?;

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
        let cards = Self::cards(conn, viewer, &ids).await?;
        let by_id: HashMap<Uuid, &AgentNameMatch> =
            matches.iter().map(|m| (m.agent_id, m)).collect();
        let limit = usize::try_from(query.limit).unwrap_or(1);
        let results = cards
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
        let rows: Vec<(Uuid, String, DateTime<Utc>, Option<DateTime<Utc>>)> = sqlx::query_as(
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
    } else if has("llm_model_on_profile") || has("bound_to_visible_human") {
        AgentKind::LlmAgent
    } else if has("name_derived_key") || has("orcid_derived_key") {
        AgentKind::IngestAuthor
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
        assert_eq!(
            kind_from_evidence(&["bound_to_visible_human", "name_derived_key"]),
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
