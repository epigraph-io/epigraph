//! Repository for challenge operations (anti-sycophancy system).
//!
//! Challenges are typed objections to claims that must be resolved.
//! Five challenge types: insufficient_evidence, outdated_evidence,
//! flawed_methodology, contradicting_evidence, factual_error.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

/// Row type for challenge queries.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct ChallengeRow {
    pub id: Uuid,
    pub claim_id: Uuid,
    pub challenger_id: Option<Uuid>,
    pub challenge_type: String,
    pub explanation: String,
    pub state: String,
    pub resolved_by: Option<Uuid>,
    pub resolution_details: Option<serde_json::Value>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Gap-originated challenge row (subset of fields).
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct GapChallengeRow {
    pub id: Uuid,
    pub claim_id: Uuid,
    pub challenge_type: String,
    pub explanation: String,
    pub state: String,
    pub created_at: DateTime<Utc>,
}

/// Where a challenge lands, per operator ruling R-CH1 (migration 168).
///
/// An OUTSIDER is a challenger that cannot write the challenged claim's owning
/// group. [`ChallengeRepository::admission_of`] computes this from the
/// session's stamp; the INSERT's triggers apply the same rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeAdmission {
    /// The challenger writes the claim's group: the row inherits the claim's
    /// tenancy (unchanged by R-CH1).
    Insider,
    /// A PUBLIC claim the challenger cannot write: the row is owned by the
    /// challenger's own write `group`, public, and never follows the claim.
    Outsider { group: Uuid },
    /// A NON-public claim the challenger can read but not write. Refused: an
    /// outsider-owned row about it would be hidden from the claim's owners.
    NotWriter,
    /// A PUBLIC claim the challenger cannot write, and no write group of its
    /// own (`epigraph_writer_group()` is NULL) to own the row. Refused.
    NoWriterGroup,
}

impl ChallengeAdmission {
    /// The rule, from the three facts [`ChallengeRepository::admission_of`]
    /// reads: does the session write the claim's group, the claim's
    /// visibility, and the session's own write group.
    #[must_use]
    pub fn decide(insider: bool, claim_visibility: &str, writer_group: Option<Uuid>) -> Self {
        if insider {
            return Self::Insider;
        }
        if claim_visibility != "public" {
            return Self::NotWriter;
        }
        writer_group.map_or(Self::NoWriterGroup, |group| Self::Outsider { group })
    }
}

pub struct ChallengeRepository;

impl ChallengeRepository {
    /// Insert a new challenge against a claim.
    ///
    /// # The executor is generic, and that is what makes this table writable
    ///
    /// `challenges` is in migration 062's tier-A array and 077 gives it the
    /// strict `WITH CHECK (owner_group_id = ANY(epigraph_writable_groups()))`,
    /// which no unstamped application session can satisfy — its writable set is
    /// `{}`. The only connection that CAN satisfy it comes from
    /// `ScopedPool::begin_as`, and that hands back a transaction rather than a
    /// pool, so a `&PgPool` parameter made this function unreachable from the one
    /// connection shape that works. `&PgPool` and `&mut PgConnection` both
    /// satisfy [`sqlx::PgExecutor`], so the three `epigraph-api` callers compile
    /// unchanged. Same change and same reasoning as
    /// [`crate::repos::ReasoningTraceRepository::create`].
    ///
    /// # Whose group the row lands in is NOT the caller's choice
    ///
    /// The database decides it, from the session's stamp (migrations 074, 070,
    /// 114 and 168), so declaring the columns here would change nothing:
    ///
    /// * an INSIDER (the session can write the claim's owning group): the row
    ///   inherits the CLAIM's `(visibility, owner_group_id)`, exactly as every
    ///   claim-derived row does;
    /// * an OUTSIDER on a PUBLIC claim (ruling R-CH1, migration 168): the row is
    ///   owned by the challenger's own write group (`epigraph_writer_group()`),
    ///   `visibility = 'public'`, `writer_owned = true`, and never follows the
    ///   claim afterwards;
    /// * anything else (a non-public claim the session cannot write, an
    ///   unreadable claim, a challenger with no write group of its own): left to
    ///   the inherit rule, which 077's `WITH CHECK` refuses (42501).
    ///
    /// The transports decide the same thing first, by name, with
    /// [`Self::admission_of`] on the same stamped transaction, so the refusal a
    /// caller sees is never the raw row-security error.
    pub async fn create<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        claim_id: Uuid,
        challenger_id: Option<Uuid>,
        challenge_type: &str,
        explanation: &str,
    ) -> Result<Uuid, sqlx::Error> {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO challenges (id, claim_id, challenger_id, challenge_type, explanation, state) \
             VALUES ($1, $2, $3, $4, $5, 'pending')",
        )
        .bind(id)
        .bind(claim_id)
        .bind(challenger_id)
        .bind(challenge_type)
        .bind(explanation)
        .execute(executor)
        .await?;
        Ok(id)
    }

    /// Where a challenge on `claim_id` would land for the session `executor`
    /// is stamped as, decided BEFORE the INSERT so a transport can refuse by
    /// name. `None` when the claim does not exist OR `viewer` cannot read it;
    /// the two are deliberately indistinguishable (ruling R-CH1b), so a caller
    /// that answers `None` with "not found" leaks nothing.
    ///
    /// Asks the database the questions the INSERT's triggers ask, with the
    /// same functions and on the same stamp, so the preflight and the row
    /// cannot disagree: is the claim's owner in `epigraph_writable_groups()`,
    /// is the claim public, and what is `epigraph_writer_group()`. Run it on
    /// the transaction the INSERT will use.
    pub async fn admission_of<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
    ) -> Result<Option<ChallengeAdmission>, sqlx::Error> {
        let sql = viewer.splice(
            "SELECT c.owner_group_id = ANY (public.epigraph_writable_groups()), \
                    c.visibility::text, public.epigraph_writer_group() \
             FROM claims c WHERE c.id = $1 /* {VISIBILITY:c} */",
            2,
        );
        let mut q = sqlx::query_as::<_, (bool, String, Option<Uuid>)>(&sql).bind(claim_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_optional(executor)
            .await?
            .map(|(insider, visibility, writer_group)| {
                ChallengeAdmission::decide(insider, &visibility, writer_group)
            }))
    }

    /// Get a single challenge by ID.
    ///
    /// `challenges.explanation` is free prose about a claim's weaknesses and is
    /// the surface plan §2.4 / §4.9 #23 flags: it leaks the substance of a claim
    /// the caller may not be able to read. `challenges` carries its own tenancy
    /// columns (migration 062), so the predicate applies to the row directly.
    ///
    /// AND to its claim (ruling R-CH1b). Since migration 168 an outsider's
    /// challenge is public and stays public when its claim is privatized, so a
    /// challenge row alone no longer implies a readable claim: without the
    /// claim's predicate the row would tell a caller that this id names a
    /// claim, which must read exactly like a random id to anyone who cannot
    /// read the claim. 168's `challenges_claim_readable` policy enforces the
    /// same rule in row security; this in-query predicate is what protects a
    /// privileged connection, which row security does not filter. Every read
    /// of `challenges` in this file carries both markers.
    pub async fn get<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        id: Uuid,
    ) -> Result<Option<ChallengeRow>, sqlx::Error> {
        let sql = viewer.splice(
            "SELECT id, claim_id, challenger_id, challenge_type, explanation, state, \
                    resolved_by, resolution_details, resolved_at, created_at \
             FROM challenges WHERE id = $1 /* {VISIBILITY:challenges} */ \
               AND EXISTS (SELECT 1 FROM claims c WHERE c.id = challenges.claim_id \
                           /* {VISIBILITY:c} */)",
            2,
        );
        let mut q = sqlx::query_as::<_, ChallengeRow>(&sql).bind(id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        q.fetch_optional(executor).await
    }

    /// List all challenges for a given claim.
    ///
    /// Only for a claim the viewer can read: see [`Self::get`]. A claim the
    /// viewer cannot read lists exactly as a nonexistent one (empty).
    pub async fn list_for_claim<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
    ) -> Result<Vec<ChallengeRow>, sqlx::Error> {
        let sql = viewer.splice(
            "SELECT id, claim_id, challenger_id, challenge_type, explanation, state, \
                    resolved_by, resolution_details, resolved_at, created_at \
             FROM challenges WHERE claim_id = $1 \
             /* {VISIBILITY:challenges} */ \
               AND EXISTS (SELECT 1 FROM claims c WHERE c.id = challenges.claim_id \
                           /* {VISIBILITY:c} */) \
             ORDER BY created_at DESC",
            2,
        );
        let mut q = sqlx::query_as::<_, ChallengeRow>(&sql).bind(claim_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        q.fetch_all(executor).await
    }

    /// Update challenge state (e.g. pending -> accepted/rejected).
    pub async fn update_state(
        pool: &PgPool,
        challenge_id: Uuid,
        state: &str,
        resolved_by: Option<Uuid>,
        resolution_details: Option<&serde_json::Value>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE challenges SET state = $1, resolved_by = $2, resolution_details = $3, \
             resolved_at = CASE WHEN $1 IN ('accepted', 'rejected') THEN NOW() ELSE resolved_at END \
             WHERE id = $4",
        )
        .bind(state)
        .bind(resolved_by)
        .bind(resolution_details)
        .bind(challenge_id)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Set a challenge's RESOLUTION STATUS as a writer of the CHALLENGED
    /// CLAIM's owning group (operator ruling R-3, migration 168 section 7).
    ///
    /// An outsider's challenge is owned by the outsider (R-CH1), so 077's
    /// `WITH CHECK` refuses the claim's owner a plain UPDATE of it. This goes
    /// through `epigraph_resolve_challenge`, which changes ONLY `state`,
    /// `resolved_by` (always the session principal: the caller cannot name
    /// another resolver), `resolved_at` and `resolution_details`, and appends
    /// one `security_events` row (`challenges.claim_owner_resolution`) naming
    /// the resolver. The outsider's text, challenger, claim and ownership are
    /// not reachable from here, and nothing on this surface deletes a row.
    ///
    /// `state` is one of `under_review`, `accepted`, `rejected`. Run it on the
    /// STAMPED transaction of the request (`ScopedPool::begin_as`): an
    /// unstamped connection has no principal to name and is refused.
    ///
    /// # Errors
    ///
    /// The definer's refusals, as `sqlx::Error::Database`:
    /// * `42501` no session principal (CR01), an elevated session (CR05), or a
    ///   session that cannot write the claim's owning group (CR03);
    /// * `P0002` "challenge not found" when the challenge does not exist OR
    ///   the session cannot read its claim, indistinguishably (CR02);
    /// * `22023` a state outside the three above (CR04);
    /// * `55000` a challenge its challenger withdrew (CR06): a withdrawal is
    ///   the challenger's act, not overturned by a resolution.
    pub async fn resolve_as_claim_owner<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        challenge_id: Uuid,
        state: &str,
        resolution_details: Option<&serde_json::Value>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT public.epigraph_resolve_challenge($1, $2, $3)")
            .bind(challenge_id)
            .bind(state)
            .bind(resolution_details)
            .execute(executor)
            .await?;
        Ok(())
    }

    /// Insert a gap-originated challenge with event emission.
    pub async fn insert_gap_challenge(
        pool: &PgPool,
        claim_id: Uuid,
        gap_type: &str,
        severity: f64,
        unconstrained_claim: &str,
        nearest_graph_claim: Option<&str>,
        agent_id: Option<Uuid>,
    ) -> Result<Uuid, sqlx::Error> {
        let id = Uuid::new_v4();
        let challenge_type = format!("epistemic_gap_{gap_type}");
        let explanation = format!(
            "Epistemic gap detected (severity: {severity:.2}). Unconstrained claim: \"{unconstrained_claim}\". \
             Nearest graph claim: {}",
            nearest_graph_claim.unwrap_or("(none)")
        );

        sqlx::query(
            "INSERT INTO challenges (id, claim_id, challenger_id, challenge_type, explanation, state) \
             VALUES ($1, $2, $3, $4, $5, 'pending')",
        )
        .bind(id)
        .bind(claim_id)
        .bind(agent_id)
        .bind(&challenge_type)
        .bind(&explanation)
        .execute(pool)
        .await?;

        Ok(id)
    }

    /// Query gap-originated challenges with optional filters.
    /// The change inventory expected this to join `claims`; it did not until
    /// ruling R-CH1b: a gap challenge is listed only with a claim the viewer can
    /// read (see [`Self::get`]), so the query carries two markers.
    pub async fn get_gap_challenges<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        gap_type: Option<&str>,
        state: Option<&str>,
        limit: i64,
    ) -> Result<Vec<GapChallengeRow>, sqlx::Error> {
        let type_filter = gap_type
            .map(|t| format!("epistemic_gap_{t}"))
            .unwrap_or_else(|| "epistemic_gap_%".into());
        let state_filter = state.unwrap_or("%");

        let sql = viewer.splice(
            "SELECT id, claim_id, challenge_type, explanation, state, created_at \
             FROM challenges \
             WHERE challenge_type LIKE $1 AND state LIKE $2 \
             /* {VISIBILITY:challenges} */ \
               AND EXISTS (SELECT 1 FROM claims c WHERE c.id = challenges.claim_id \
                           /* {VISIBILITY:c} */) \
             ORDER BY created_at DESC LIMIT $3",
            4,
        );
        let mut q = sqlx::query_as::<_, GapChallengeRow>(&sql)
            .bind(&type_filter)
            .bind(state_filter)
            .bind(limit);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        q.fetch_all(executor).await
    }
}

#[cfg(test)]
mod admission_tests {
    use super::ChallengeAdmission;
    use uuid::Uuid;

    #[test]
    fn an_insider_inherits_whatever_the_claims_visibility() {
        let g = Some(Uuid::new_v4());
        for vis in ["public", "group", "private"] {
            assert_eq!(
                ChallengeAdmission::decide(true, vis, g),
                ChallengeAdmission::Insider
            );
            assert_eq!(
                ChallengeAdmission::decide(true, vis, None),
                ChallengeAdmission::Insider
            );
        }
    }

    #[test]
    fn an_outsider_owns_its_challenge_only_on_a_public_claim() {
        let g = Uuid::new_v4();
        assert_eq!(
            ChallengeAdmission::decide(false, "public", Some(g)),
            ChallengeAdmission::Outsider { group: g }
        );
        assert_eq!(
            ChallengeAdmission::decide(false, "public", None),
            ChallengeAdmission::NoWriterGroup
        );
        for vis in ["group", "private"] {
            assert_eq!(
                ChallengeAdmission::decide(false, vis, Some(g)),
                ChallengeAdmission::NotWriter,
                "{vis}"
            );
        }
    }
}
