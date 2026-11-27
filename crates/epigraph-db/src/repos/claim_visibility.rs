//! Caller-facing claim visibility: **team** (the default), **private** and
//! **public** at write time, and the two audited acts that change a claim's
//! visibility later (publish a team claim; move a private claim into a team).
//!
//! Spec and owner decisions D-V1..D-V5: `docs/tenancy/claim-visibility-controls.md`.
//! Database half: migration 206 (`epigraph_writable_teams`,
//! `epigraph_default_group`, `epigraph_set_default_group`,
//! `epigraph_publicize_claims`, `epigraph_share_claims_with_team`) and
//! migration 209 (`agents.default_private`, `epigraph_default_private`,
//! `epigraph_set_agent_default_group`: a private default, and an operator
//! setting the default of an agent it operates).
//!
//! # Where this sits relative to `default_decl_for_author`
//!
//! [`ClaimRepository::resolve_write_decl`] calls
//! [`ClaimRepository::default_decl_for_author`] FIRST, so every refusal that
//! function makes (`OPL01` unbound author, `OPL02` revoked operator scope,
//! `RVK01` revoked personal membership) fires first, in the same order, for
//! every visibility. The home group it returns is the owner of a `private` or
//! `public` claim. A `team` claim is owned by the team instead.
//!
//! `default_decl_for_author` keeps its own callers. The system-agent and
//! registry writers that never grew a visibility parameter still land public
//! (spec §3.5).

use epigraph_core::{TenancyDecl, Visibility, VisibilityChoice};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::errors::{DbError, RefusalKind};
use crate::repos::ClaimRepository;
use crate::visibility::Viewer;

/// Proof that `agent` may write a claim into team `group` ONLY through its
/// live human (owner decision D-V3: an operated agent writes where its human
/// writes).
///
/// Minted only by [`ClaimRepository::resolve_write_decl`], from
/// `epigraph_writable_teams` answering `via = 'operator'`. Its fields are
/// crate-private, so no caller can build one for a group it picked itself. The
/// one thing it unlocks is [`crate::Viewer::with_team_write_grant`]: the
/// author-stamped transaction then carries the team in its writable set, so
/// 077's `WITH CHECK` admits the same write the claims trigger's writer scope
/// (`epigraph_require_writer_scope`) already admits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeamWriteGrant {
    pub(crate) agent: Uuid,
    pub(crate) group: Uuid,
}

impl TeamWriteGrant {
    /// The agent the grant is for.
    #[must_use]
    pub const fn agent(&self) -> Uuid {
        self.agent
    }

    /// The team it may write.
    #[must_use]
    pub const fn group(&self) -> Uuid {
        self.group
    }
}

/// Whose a claim is, before the home group is known:
/// [`ClaimRepository::resolve_visibility_choice`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChoiceResolution {
    /// The author's home group owns it; `public` or private.
    Home {
        /// `true` for `public`, `false` for private.
        public: bool,
        /// D-V1's note when a default write fell back to private.
        note: Option<String>,
    },
    /// A team owns it, group-visible.
    Team {
        /// The team.
        group: Uuid,
        /// `Some` when the author writes it only through its human (D-V3).
        grant: Option<TeamWriteGrant>,
    },
}

impl ChoiceResolution {
    /// The declaration, given the author's home group.
    #[must_use]
    pub const fn decl(&self, home: Uuid) -> TenancyDecl {
        match self {
            Self::Home { public: true, .. } => TenancyDecl::public(home),
            Self::Home { public: false, .. } => TenancyDecl::group(home),
            Self::Team { group, .. } => TenancyDecl::group(*group),
        }
    }

    /// `"public"`, `"private"` or `"team"`.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Home { public: true, .. } => "public",
            Self::Home { public: false, .. } => "private",
            Self::Team { .. } => "team",
        }
    }

    /// The team-write grant to stamp, if any.
    #[must_use]
    pub const fn grant(&self) -> Option<&TeamWriteGrant> {
        match self {
            Self::Team { grant, .. } => grant.as_ref(),
            Self::Home { .. } => None,
        }
    }

    /// The team, if it is one.
    #[must_use]
    pub const fn team(&self) -> Option<Uuid> {
        match self {
            Self::Team { group, .. } => Some(*group),
            Self::Home { .. } => None,
        }
    }

    /// D-V1's note, if any.
    #[must_use]
    pub fn note(&self) -> Option<String> {
        match self {
            Self::Home { note, .. } => note.clone(),
            Self::Team { .. } => None,
        }
    }
}

/// What a caller-facing write's [`VisibilityChoice`] resolved to.
#[derive(Debug, Clone)]
pub struct ResolvedWriteDecl {
    /// The declaration to write the claim with.
    pub decl: TenancyDecl,
    /// The author's home group (personal, or its operator's).
    pub home_group: Uuid,
    /// `"team"`, `"private"` or `"public"`.
    pub resolved: &'static str,
    /// `Some` when the author writes the team only through its human (D-V3).
    pub operator_grant: Option<TeamWriteGrant>,
    /// Set when the caller should know how the default was resolved (D-V1).
    pub note: Option<String>,
}

/// The tenancy a write actually landed in, for the response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteTenancyReport {
    /// `"team"`, `"private"` or `"public"`.
    pub visibility: &'static str,
    /// The stored owner group.
    pub owner_group_id: Uuid,
    /// D-V1's resolution note, or D-V4's "existing claim, not re-scoped" note.
    pub note: Option<String>,
}

/// One claim's outcome from [`ClaimRepository::publicize_conn`] or
/// [`ClaimRepository::share_with_team_conn`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VisibilityActOutcome {
    /// The claim.
    pub claim_id: Uuid,
    /// `publicized` / `already_public`, or `shared`.
    pub outcome: String,
}

impl VisibilityActOutcome {
    /// The user-facing reason for a refused outcome (`refused_*`), as the
    /// act's refusal message words it; `None` for an outcome the act accepts
    /// (`publicize`, `already_public`, `share`, and their done forms) and for
    /// `not_found`.
    #[must_use]
    pub fn refusal_text(&self) -> Option<&'static str> {
        self.outcome
            .starts_with("refused")
            .then(|| refusal_text(&self.outcome))
    }
}

/// The refusal the act named `act` (`publicize_claims` /
/// `share_claims_with_team`) answers for this classification, worded and
/// kinded exactly as the act's own (`not_found` first, as a missing claim);
/// `None` when every outcome is one the act accepts. For a caller that
/// classified with [`ClaimRepository::preview_publicize_conn`] or
/// [`ClaimRepository::preview_share_with_team_conn`] and refuses on the
/// definer's word without calling the act.
#[must_use]
pub fn preview_refusal(act: &str, outcomes: &[VisibilityActOutcome]) -> Option<DbError> {
    outcomes_or_refusal(
        act,
        outcomes
            .iter()
            .map(|o| (o.claim_id, o.outcome.clone()))
            .collect(),
        &["publicize", "already_public", "share"],
    )
    .err()
}

/// The most claim ids one preview call hands a definer: the definers' own
/// cap (500) less the one sentinel id the preview adds.
const PREVIEW_CHUNK: usize = 499;

/// What [`ClaimRepository::set_agent_default_conn`] sets an agent's default to
/// (migration 209).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultGroupSetting {
    /// A team the agent may write (its own writer/admin membership or its live
    /// human's), checked when it is set and again at every write.
    Team(Uuid),
    /// Private: a write that names no visibility lands in the agent's home
    /// group, ahead of its human's default team and of the single-team
    /// fallback.
    Private,
    /// Neither: the agent inherits its live human's default again.
    Clear,
}

impl DefaultGroupSetting {
    /// The team, if it is one.
    #[must_use]
    pub const fn group(self) -> Option<Uuid> {
        match self {
            Self::Team(g) => Some(g),
            Self::Private | Self::Clear => None,
        }
    }

    /// `true` for [`Self::Private`].
    #[must_use]
    pub const fn private(self) -> bool {
        matches!(self, Self::Private)
    }
}

/// The user-facing word for a stored `(visibility, owner)` pair.
fn label_of(visibility: Visibility, owner: Uuid, home: Uuid) -> &'static str {
    match visibility {
        Visibility::Public => "public",
        Visibility::Group if owner == home => "private",
        Visibility::Group => "team",
    }
}

/// Map a migration-206/209 refusal (`VIS01`..`VIS06`) to a designed refusal
/// of the kind the refusal-code registry gives it, and anything else to the
/// ordinary conversion.
fn map_vis_error(e: sqlx::Error) -> DbError {
    DbError::from_definer(e, crate::refusal_codes::Family::Vis)
}

/// The refusal for one act's classification, or the outcomes when every claim
/// was acted on. `not_found` wins over every refusal and is answered as a
/// missing claim (an unreadable claim must not read as "exists, forbidden").
fn outcomes_or_refusal(
    act: &str,
    rows: Vec<(Uuid, String)>,
    ok: &[&str],
) -> Result<Vec<VisibilityActOutcome>, DbError> {
    if let Some((id, _)) = rows.iter().find(|(_, o)| o == "not_found") {
        return Err(DbError::NotFound {
            entity: "claim".to_string(),
            id: *id,
        });
    }
    let refused: Vec<&(Uuid, String)> = rows
        .iter()
        .filter(|(_, o)| !ok.contains(&o.as_str()))
        .collect();
    if !refused.is_empty() {
        let state_only = refused
            .iter()
            .all(|(_, o)| o == "refused_sealed" || o == "refused_not_private");
        let detail = refused
            .iter()
            .map(|(id, o)| format!("{id}: {}", refusal_text(o)))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(DbError::Refused {
            kind: if state_only {
                RefusalKind::State
            } else {
                RefusalKind::Authority
            },
            message: format!("{act}: refused, and nothing was changed ({detail})"),
        });
    }
    Ok(rows
        .into_iter()
        .map(|(claim_id, outcome)| VisibilityActOutcome { claim_id, outcome })
        .collect())
}

/// [`ClaimRepository::preview_publicize_conn`] (`share_into` `None`) or
/// [`ClaimRepository::preview_share_with_team_conn`].
async fn preview_conn(
    conn: &mut PgConnection,
    claim_ids: &[Uuid],
    share_into: Option<Uuid>,
) -> Result<Vec<VisibilityActOutcome>, DbError> {
    let mut ids: Vec<Uuid> = claim_ids.to_vec();
    ids.sort_unstable();
    ids.dedup();
    let mut out = Vec::with_capacity(ids.len());
    for chunk in ids.chunks(PREVIEW_CHUNK) {
        let sentinel = loop {
            let s = Uuid::new_v4();
            if !chunk.contains(&s) {
                break s;
            }
        };
        let mut call: Vec<Uuid> = chunk.to_vec();
        call.push(sentinel);
        sqlx::query("SAVEPOINT epigraph_visibility_preview")
            .execute(&mut *conn)
            .await?;
        let rows = match share_into {
            None => {
                sqlx::query_as::<_, (Uuid, String)>(
                    "SELECT claim_id, outcome \
                       FROM public.epigraph_publicize_claims($1, 'preview')",
                )
                .bind(&call)
                .fetch_all(&mut *conn)
                .await
            }
            Some(group) => {
                sqlx::query_as::<_, (Uuid, String)>(
                    "SELECT claim_id, outcome \
                       FROM public.epigraph_share_claims_with_team($1, $2, 'preview')",
                )
                .bind(&call)
                .bind(group)
                .fetch_all(&mut *conn)
                .await
            }
        };
        // Always back to before the call, whatever it answered or did.
        sqlx::query("ROLLBACK TO SAVEPOINT epigraph_visibility_preview")
            .execute(&mut *conn)
            .await?;
        sqlx::query("RELEASE SAVEPOINT epigraph_visibility_preview")
            .execute(&mut *conn)
            .await?;
        let rows = rows.map_err(map_vis_error)?;
        out.extend(
            rows.into_iter()
                .filter(|(id, _)| *id != sentinel)
                .map(|(claim_id, outcome)| VisibilityActOutcome { claim_id, outcome }),
        );
    }
    out.sort_by_key(|o| o.claim_id);
    Ok(out)
}

fn refusal_text(outcome: &str) -> &'static str {
    match outcome {
        "refused_not_admin" => {
            "only a live admin of the claim's owning group may publish it (owner decision D-V2)"
        }
        "refused_sealed" => "the claim is sealed (encrypted); unseal it first",
        "refused_not_private" => {
            "the claim is not private to your home group (it is public, or already a team's)"
        }
        "refused_not_author" => {
            "you did not write this claim and are not an admin of the group it is private to"
        }
        "refused_not_team_writer" => {
            "the target is not a team you may write (your own live writer or admin membership)"
        }
        // Migration 242 (spec ruling R1, backlog ecd842bf).
        "refused_not_human" => {
            "only a human moves existing work out of its group: you are an operated agent, and \
             an operated agent does not share or publish work on its own authority, whatever \
             memberships it holds; your human operator makes this call"
        }
        _ => "refused",
    }
}

impl ClaimRepository {
    /// The TEAM groups `agent` may write a claim into, with `"own"` (its own
    /// writer/admin membership) or `"operator"` (its live human writes it,
    /// owner decision D-V3). Read through migration 206's definer on `conn`
    /// AS IT IS STAMPED: since migration 346 the definer answers only when
    /// `agent` is the session principal, when the principal is the live human
    /// operator holding a live (not retired) operator link to `agent`, or on
    /// a maintenance or superuser session. Asked about anyone else, it
    /// answers no team (fail-closed). The set-default routes call it on the
    /// transaction stamped as their caller, which is the agent itself or its
    /// operator. A write resolving its own author's teams goes through
    /// [`Self::resolve_visibility_choice`], which stamps the author.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the read fails or migration 206 is absent.
    pub async fn writable_teams(
        conn: &mut PgConnection,
        agent: Uuid,
    ) -> Result<Vec<(Uuid, String)>, DbError> {
        Ok(sqlx::query_as::<_, (Uuid, String)>(
            "SELECT group_id, via FROM public.epigraph_writable_teams($1)",
        )
        .bind(agent)
        .fetch_all(&mut *conn)
        .await?)
    }

    /// [`Self::writable_teams`] for `agent` asked as ITS OWN principal: the
    /// author of the write being resolved.
    ///
    /// Since migration 346 the definer answers only for the session principal
    /// (or that agent's live operator). The visibility resolution runs on an
    /// unstamped pool connection before the write's stamped transaction
    /// exists (the team it picks must be stamped into that transaction), so
    /// this stamps `agent` as `epigraph.principal_id` for the one read.
    ///
    /// The stamp is scoped by a transaction of its own that is always rolled
    /// back: on a connection outside a transaction that is a `BEGIN` /
    /// `ROLLBACK` around the read, and on one already inside a transaction
    /// (sqlx then issues a `SAVEPOINT`) the rollback to the savepoint restores
    /// the caller's own stamp. So the connection's principal after the call is
    /// what it was before, in both shapes. Against a database below 346 the
    /// stamp changes nothing.
    ///
    /// As with 236's `list_live_for_agent`, the stamp is a transport, not an
    /// authority (a holder of the application DSN can set it): what 346
    /// removes is the ambient answer for an agent the caller did not stamp.
    /// The callers pass the author of the write they are resolving.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the read fails or migration 206 is absent.
    async fn writable_teams_as_self(
        conn: &mut PgConnection,
        agent: Uuid,
    ) -> Result<Vec<(Uuid, String)>, DbError> {
        use sqlx::Connection;
        let mut scope = conn.begin().await?;
        let teams = sqlx::query_as::<_, (Uuid, String)>(
            "SELECT t.group_id, t.via \
               FROM (SELECT set_config('epigraph.principal_id', $1::text, true)::uuid \
                            AS principal) s \
              CROSS JOIN LATERAL public.epigraph_writable_teams(s.principal) t \
              ORDER BY t.group_id",
        )
        .bind(agent)
        .fetch_all(&mut *scope)
        .await?;
        scope.rollback().await?;
        Ok(teams)
    }

    /// `agents.default_group_id` of `agent`, else of its live human. Not
    /// validated: [`Self::resolve_write_decl`] uses it only while it is still
    /// one of [`Self::writable_teams`].
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the read fails or migration 206 is absent.
    pub async fn default_group_of(
        conn: &mut PgConnection,
        agent: Uuid,
    ) -> Result<Option<Uuid>, DbError> {
        Ok(
            sqlx::query_scalar::<_, Option<Uuid>>("SELECT public.epigraph_default_group($1)")
                .bind(agent)
                .fetch_one(&mut *conn)
                .await?,
        )
    }

    /// `agents.default_group_id` of `agent`'s live human
    /// (`epigraph_human_of(agent, true)`), read through the same definer. For
    /// an agent with no live human it is `None`; for a human it is the human's
    /// own default, i.e. [`Self::default_group_of`]'s answer again. Not
    /// validated: [`Self::resolve_visibility_choice`] asks for it only when
    /// [`Self::default_group_of`] gave no writable team (the case that matters:
    /// the agent's own default is set but no longer writable, which hides the
    /// human's), and uses it only while it is one of [`Self::writable_teams`]
    /// (D-V1).
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the read fails or migration 206 is absent.
    pub async fn human_default_group_of(
        conn: &mut PgConnection,
        agent: Uuid,
    ) -> Result<Option<Uuid>, DbError> {
        Ok(sqlx::query_scalar::<_, Option<Uuid>>(
            "SELECT public.epigraph_default_group(public.epigraph_human_of($1, true))",
        )
        .bind(agent)
        .fetch_one(&mut *conn)
        .await?)
    }

    /// `agents.default_private` of `agent` itself (migration 209's definer
    /// `epigraph_default_private`); `false` for an unknown agent.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the read fails or migration 209 is absent.
    pub async fn default_private_of(conn: &mut PgConnection, agent: Uuid) -> Result<bool, DbError> {
        Ok(
            sqlx::query_scalar::<_, bool>("SELECT public.epigraph_default_private($1)")
                .bind(agent)
                .fetch_one(&mut *conn)
                .await?,
        )
    }

    /// `agents.default_private` of `agent`'s live human
    /// (`epigraph_human_of(agent, true)`); `false` with no live human. For a
    /// human it is its own flag again.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the read fails or migration 209 is absent.
    pub async fn human_default_private_of(
        conn: &mut PgConnection,
        agent: Uuid,
    ) -> Result<bool, DbError> {
        Ok(sqlx::query_scalar::<_, bool>(
            "SELECT public.epigraph_default_private(public.epigraph_human_of($1, true))",
        )
        .bind(agent)
        .fetch_one(&mut *conn)
        .await?)
    }

    /// Resolve a caller-facing write's [`VisibilityChoice`] for `agent`.
    ///
    /// * `Public`: `('public', home)`, today's answer, byte for byte.
    /// * `Private`: `('group', home)`.
    /// * `Team(Some(g))`: `('group', g)` when `g` is one of
    ///   [`Self::writable_teams`]. Otherwise a refusal (`Authority`) that says a
    ///   reader membership does not admit writes, and does not say whether `g`
    ///   exists. `g == home` is refused (`Input`): that is `private`.
    /// * `Team(None)` / `Default`: owner decision D-V1. The agent's own default
    ///   team if it is still writable, else its live human's default team under
    ///   the same condition, else the only writable team. Otherwise `Default`
    ///   lands PRIVATE with a note, and an explicit `Team(None)` is refused,
    ///   because the caller asked for a team and no single team is implied.
    ///   Never public.
    /// * `Default` only (migration 209, operator ruling 2026-11-12): a PRIVATE
    ///   default comes first. The agent's own `default_private`, else, when the
    ///   agent has no usable default team of its own, its live human's. It
    ///   wins over the human's default team and over the single-team fallback.
    ///   An explicit `Team(None)` asked for a team and still resolves through
    ///   the team chain.
    ///
    /// Run it on any connection: every read is a definer.
    ///
    /// # Errors
    /// Every error of [`Self::default_decl_for_author`], first; then
    /// `DbError::Refused` as above; `DbError::QueryFailed` for read faults.
    pub async fn resolve_write_decl(
        conn: &mut PgConnection,
        agent: Uuid,
        choice: VisibilityChoice,
    ) -> Result<ResolvedWriteDecl, DbError> {
        let base = Self::default_decl_for_author(&mut *conn, agent).await?;
        let home = base
            .owner_group_bind()
            .ok_or_else(|| DbError::InvalidData {
                reason: "default_decl_for_author returned an inherited declaration".to_string(),
            })?;
        let resolution = Self::resolve_visibility_choice(&mut *conn, agent, choice).await?;
        Ok(ResolvedWriteDecl {
            decl: resolution.decl(home),
            home_group: home,
            resolved: resolution.label(),
            operator_grant: resolution.grant().cloned(),
            note: resolution.note(),
        })
    }

    /// The half of [`Self::resolve_write_decl`] that needs no home group: is
    /// the claim the home group's (`private` / `public`), or which team's?
    ///
    /// Pure definer reads (`epigraph_writable_teams`,
    /// `epigraph_default_group`). It never provisions a personal group, so a
    /// path that resolves its home group itself, read-only (the document
    /// ingest's `owner_decl`), can use it. The home group is never a team:
    /// personal groups are not of kind `team`/`community`, so naming one as
    /// `group_id` is refused like any group the author may not write.
    ///
    /// # Errors
    /// `DbError::Refused` as [`Self::resolve_write_decl`] documents;
    /// `DbError::QueryFailed` for read faults.
    pub async fn resolve_visibility_choice(
        conn: &mut PgConnection,
        agent: Uuid,
        choice: VisibilityChoice,
    ) -> Result<ChoiceResolution, DbError> {
        let team_of = |g: Uuid, via: &str| ChoiceResolution::Team {
            group: g,
            grant: (via == "operator").then_some(TeamWriteGrant { agent, group: g }),
        };
        match choice {
            VisibilityChoice::Public => Ok(ChoiceResolution::Home {
                public: true,
                note: None,
            }),
            VisibilityChoice::Private => Ok(ChoiceResolution::Home {
                public: false,
                note: None,
            }),
            VisibilityChoice::Team(Some(g)) => {
                let teams = Self::writable_teams_as_self(&mut *conn, agent).await?;
                match teams.iter().find(|(t, _)| *t == g) {
                    Some((_, via)) => Ok(team_of(g, via)),
                    None => Err(DbError::Refused {
                        kind: RefusalKind::Authority,
                        message: format!(
                            "group {g} is not a team you may write. A team write needs a live \
                             writer or admin membership of the group, yours or your human's (a \
                             reader membership does not admit writes); a personal group is \
                             never a team (pass visibility \"private\" for your own). Nothing \
                             was written"
                        ),
                    }),
                }
            }
            VisibilityChoice::Team(None) | VisibilityChoice::Default => {
                // 209: a PRIVATE default beats every team below it, the
                // single-team fallback included, but only for a write that
                // names no visibility. An explicit `team` asked for a team.
                let by_default = choice == VisibilityChoice::Default;
                if by_default && Self::default_private_of(&mut *conn, agent).await? {
                    return Ok(Self::private_by_default(
                        "this agent's own default is private",
                    ));
                }
                let teams = Self::writable_teams_as_self(&mut *conn, agent).await?;
                let writable =
                    |d: Option<Uuid>| d.and_then(|d| teams.iter().find(|(t, _)| *t == d));
                // D-V1's chain, each default checked on its own: the agent's
                // default (`epigraph_default_group` answers the human's when the
                // agent's is unset), and only when that one is set but no longer
                // writable, the human's. Coalescing the two before the check
                // would let a stale own default hide a valid human default.
                let mut picked = writable(Self::default_group_of(&mut *conn, agent).await?);
                if picked.is_none() {
                    // The agent has no usable default team of its own, so its
                    // live human's default decides, private included (209).
                    if by_default && Self::human_default_private_of(&mut *conn, agent).await? {
                        return Ok(Self::private_by_default(
                            "the default of this agent's live human is private",
                        ));
                    }
                    picked = writable(Self::human_default_group_of(&mut *conn, agent).await?);
                }
                let picked = picked.or_else(|| (teams.len() == 1).then(|| &teams[0]));
                if let Some((g, via)) = picked {
                    return Ok(team_of(*g, via));
                }
                let why = if teams.is_empty() {
                    "you may write no team".to_string()
                } else {
                    format!(
                        "you may write {} teams and no default team is set (set one with \
                         set_default_group, or pass group_id)",
                        teams.len()
                    )
                };
                if choice == VisibilityChoice::Team(None) {
                    return Err(DbError::Refused {
                        kind: RefusalKind::Input,
                        message: format!(
                            "visibility \"team\" without a group_id needs a default team, but \
                             {why}. Nothing was written"
                        ),
                    });
                }
                Ok(ChoiceResolution::Home {
                    public: false,
                    note: Some(format!(
                        "no visibility was named and {why}, so this is PRIVATE (readable only \
                         by your home group). share_claims_with_team moves it into a team and \
                         publicize_claims publishes it"
                    )),
                })
            }
        }
    }

    /// A no-visibility write that a private default (209) sent home.
    fn private_by_default(why: &str) -> ChoiceResolution {
        ChoiceResolution::Home {
            public: false,
            note: Some(format!(
                "no visibility was named and {why}, so this is PRIVATE (readable only by your \
                 home group). share_claims_with_team moves it into a team and publicize_claims \
                 publishes it"
            )),
        }
    }

    /// The tenancy claim `claim_id` actually has, read on `conn`'s own session,
    /// as the response reports it. When the write returned an EXISTING claim
    /// whose tenancy differs from the request, the note says so (owner decision
    /// D-V4: returned unchanged, never re-scoped, never forked).
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the read fails.
    pub async fn write_tenancy_report(
        conn: &mut PgConnection,
        claim_id: Uuid,
        resolved: &ResolvedWriteDecl,
        was_created: bool,
    ) -> Result<WriteTenancyReport, DbError> {
        let requested = (
            resolved
                .decl
                .visibility_bind()
                .and_then(Visibility::from_db_str),
            resolved.decl.owner_group_bind(),
        );
        let stored = Self::tenancy_on_session_conn(&mut *conn, &[claim_id])
            .await?
            .into_iter()
            .next()
            .and_then(|(_, v, o)| Visibility::from_db_str(&v).map(|v| (v, o)));
        let Some((vis, owner)) = stored else {
            // Not readable on this session (should not happen for a row it just
            // wrote or returned): report what was asked.
            return Ok(WriteTenancyReport {
                visibility: resolved.resolved,
                owner_group_id: requested.1.unwrap_or(resolved.home_group),
                note: resolved.note.clone(),
            });
        };
        let label = label_of(vis, owner, resolved.home_group);
        let differs = (Some(vis), Some(owner)) != requested;
        let note = if !was_created && differs {
            let widen = match label {
                "public" => "",
                "private" => {
                    " share_claims_with_team moves it into a team; publicize_claims publishes it."
                }
                _ => " publicize_claims publishes it (team admins only).",
            };
            Some(format!(
                "this content already existed as your {label} claim (owner group {owner}); it \
                 was returned unchanged and was NOT re-scoped to the {} visibility you asked \
                 for. This call's evidence and trace were attached to it and carry its \
                 visibility.{widen}",
                resolved.resolved
            ))
        } else {
            resolved.note.clone()
        };
        Ok(WriteTenancyReport {
            visibility: label,
            owner_group_id: owner,
            note,
        })
    }

    /// Set `agent`'s default (a team, private, or clear) through migration
    /// 209's definer `epigraph_set_agent_default_group`, as the session
    /// principal on `conn` (which must be stamped). The definer admits the
    /// agent itself (`"self"`) or the registered live human operator holding a
    /// live, non-retired operator link to it (`"operator"`), checks a team
    /// against the AGENT's writable teams, and writes one
    /// `agent.default_group_set` audit row attributed to the caller. Returns
    /// how the caller was admitted.
    ///
    /// # Errors
    /// `DbError::Refused`: `Authority` without a principal (VIS01), for a team
    /// the agent may not write (VIS02), or for a caller that is neither the
    /// agent nor its live operator (VIS05); `State` if the row did not move
    /// (VIS06). Nothing is changed on any of them. `DbError::QueryFailed`
    /// otherwise.
    pub async fn set_agent_default_conn(
        conn: &mut PgConnection,
        agent: Uuid,
        setting: DefaultGroupSetting,
    ) -> Result<String, DbError> {
        sqlx::query_scalar::<_, String>(
            "SELECT public.epigraph_set_agent_default_group($1, $2, $3)",
        )
        .bind(agent)
        .bind(setting.group())
        .bind(setting.private())
        .fetch_one(&mut *conn)
        .await
        .map_err(map_vis_error)
    }

    /// Publish group-visible claims (group -> public), as the session principal
    /// on `conn` (which must be stamped). All or nothing. Only a live admin of
    /// each claim's owning group may (owner decision D-V2). Sealed claims are
    /// refused. Derived rows follow, except pinned evidence, and incident edges
    /// are re-met. One `claim.publicized` audit row is written (migration 206
    /// section 4).
    ///
    /// # Errors
    /// `DbError::NotFound` for a claim the session cannot read (or that does
    /// not exist); `DbError::Refused` (`Authority` for a non-admin, `State` for
    /// a sealed claim or for one that changed under the act after it was
    /// classified (`VIS04`; retry), `Input` for a bad request) with nothing
    /// changed;
    /// `DbError::QueryFailed` for faults.
    ///
    /// Call `epigraph_engine::visibility_act::publicize_claims` instead: this
    /// does not refold the moved claims' cached belief for their new audience.
    /// `tests/visibility_act_callers_ratchet.rs` fails on any other caller.
    pub async fn publicize_conn(
        conn: &mut PgConnection,
        claim_ids: &[Uuid],
        reason: &str,
    ) -> Result<Vec<VisibilityActOutcome>, DbError> {
        let rows = sqlx::query_as::<_, (Uuid, String)>(
            "SELECT claim_id, outcome FROM public.epigraph_publicize_claims($1, $2)",
        )
        .bind(claim_ids)
        .bind(reason)
        .fetch_all(&mut *conn)
        .await
        .map_err(map_vis_error)?;
        outcomes_or_refusal("publicize_claims", rows, &["publicized", "already_public"])
    }

    /// Move private claims (`('group', home)`) into a team the session principal
    /// writes. All or nothing. One `claim.shared_with_team` audit row is written
    /// (migration 206 section 5).
    ///
    /// # Errors
    /// As [`Self::publicize_conn`].
    ///
    /// Call `epigraph_engine::visibility_act::share_claims_with_team` instead,
    /// for the same reason; the same ratchet holds it.
    pub async fn share_with_team_conn(
        conn: &mut PgConnection,
        claim_ids: &[Uuid],
        group_id: Uuid,
        reason: &str,
    ) -> Result<Vec<VisibilityActOutcome>, DbError> {
        let rows = sqlx::query_as::<_, (Uuid, String)>(
            "SELECT claim_id, outcome FROM public.epigraph_share_claims_with_team($1, $2, $3)",
        )
        .bind(claim_ids)
        .bind(group_id)
        .bind(reason)
        .fetch_all(&mut *conn)
        .await
        .map_err(map_vis_error)?;
        outcomes_or_refusal("share_claims_with_team", rows, &["shared"])
    }

    /// How `epigraph_publicize_claims` would classify each of `claim_ids` for
    /// the session principal on `conn`, without acting: `publicize`,
    /// `already_public`, `not_found`, or a `refused_*` outcome. Ordered by id,
    /// one row per distinct id.
    ///
    /// The definer itself classifies, so the preview cannot disagree with the
    /// act about who may move what (backlog 02d9e9a1: a selection reuses the
    /// migration-206 definers unchanged and adds no authority). Each call
    /// hands it one extra id that names no claim (a fresh v4), which the
    /// definer classifies `not_found`; a call with any outcome other than an
    /// accepted one returns its classification before it changes anything
    /// (the early return after classifying, re-stated by 242 and 284). The
    /// call also runs inside a savepoint that is always rolled back, so even
    /// a definer that one day acted on such a call leaves nothing behind:
    /// no move, no audit row, no row lock.
    ///
    /// # Errors
    /// `DbError::Refused` for the definer's own refusals of the whole call
    /// (`VIS01` no principal, `VIS03`); `DbError::QueryFailed` for faults.
    pub async fn preview_publicize_conn(
        conn: &mut PgConnection,
        claim_ids: &[Uuid],
    ) -> Result<Vec<VisibilityActOutcome>, DbError> {
        preview_conn(conn, claim_ids, None).await
    }

    /// How `epigraph_share_claims_with_team` would classify each of
    /// `claim_ids` for a share into `group_id` by the session principal on
    /// `conn`, without acting: `share`, `not_found`, or a `refused_*`
    /// outcome. As [`Self::preview_publicize_conn`].
    ///
    /// # Errors
    /// As [`Self::preview_publicize_conn`].
    pub async fn preview_share_with_team_conn(
        conn: &mut PgConnection,
        claim_ids: &[Uuid],
        group_id: Uuid,
    ) -> Result<Vec<VisibilityActOutcome>, DbError> {
        preview_conn(conn, claim_ids, Some(group_id)).await
    }

    /// Of `claim_ids`, those this SESSION cannot write: the claim is not
    /// readable under its row security, or its owner group is not in the
    /// session's writable set (`epigraph_writable_groups()`). Used after a
    /// widening act, before the moved claims' cached belief is refolded on the
    /// same session (`epigraph_engine::visibility_act`): a claim listed here
    /// would take no refold, and keep a value folded for its old audience.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the read fails.
    pub async fn claims_not_writable_on_session(
        conn: &mut PgConnection,
        claim_ids: &[Uuid],
    ) -> Result<Vec<Uuid>, DbError> {
        Ok(sqlx::query_scalar::<_, Uuid>(
            "SELECT i.id FROM unnest($1::uuid[]) AS i(id) \
              WHERE NOT EXISTS (SELECT 1 FROM claims c \
                                 WHERE c.id = i.id \
                                   AND c.owner_group_id = ANY(public.epigraph_writable_groups())) \
              ORDER BY i.id",
        )
        .bind(claim_ids)
        .fetch_all(&mut *conn)
        .await?)
    }

    /// After a widening act refolded `claim_id`'s cached belief for its new
    /// audience (`epigraph_engine::visibility_act`), set its `truth_value` to
    /// that refolded BetP (`pignistic_prob`, clamped to `[0, 1]`; NaN reads as
    /// 0.5, as `TruthValue::clamped`), on the act's own stamped transaction.
    /// Returns whether the row was written.
    ///
    /// Several writers persist `truth_value` as a copy of the fold they just
    /// cached (`submit_claim`, `update_with_evidence`), so it can carry a BBA
    /// the new audience may not read (evidence pinned behind, a private edge
    /// source); a copy that a later recompute left stale carries it as well.
    /// The refolded cache is admissible by construction, so it is the value
    /// served from now on. That holds for workflow, step and procedural claims
    /// too: `report_workflow_outcome` persists the same fold copy, and a
    /// workflow's outcome track (the REST outcome route's Bayesian update) is
    /// itself derived from outcome reports the new audience may not read, so
    /// they are written like any other claim. Not written:
    /// * a claim with no cache (`pignistic_prob IS NULL`);
    /// * a claim at the deprecation marker (`truth_value` 0.05, whether or not
    ///   it is current): the marker is a state set by a retirement
    ///   (`deprecate_claim`, `deprecate_workflow`) or a step's soft delete
    ///   (`delete_step`, which leaves the step current), not a fold, so it
    ///   carries no input, and writing over it would revive what was retired;
    /// * a claim whose `truth_value` already equals the new value;
    /// * a claim whose owner group `viewer` does not write (the write gate).
    ///
    /// The guards read only the claim's own row, so what the session can see
    /// of the claim's edges or workflow rows cannot change what is written.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the write fails.
    pub async fn mirror_refolded_cache_into_truth_conn(
        conn: &mut PgConnection,
        viewer: &Viewer,
        claim_id: Uuid,
    ) -> Result<bool, DbError> {
        let sql = viewer.splice_write(
            "WITH n AS ( \
                     SELECT c.id, \
                            CASE WHEN c.pignistic_prob = 'NaN'::float8 THEN 0.5::float8 \
                                 ELSE LEAST(GREATEST(c.pignistic_prob, 0.0::float8), 1.0::float8) \
                            END AS tv \
                       FROM claims c \
                      WHERE c.id = $1 \
                        AND c.pignistic_prob IS NOT NULL \
                        AND abs(c.truth_value - 0.05) > 1e-9) \
                 UPDATE claims AS u SET truth_value = n.tv, updated_at = NOW() \
                   FROM n \
                  WHERE u.id = n.id AND u.truth_value IS DISTINCT FROM n.tv \
                  /* {WRITABLE:u} */ \
                 RETURNING u.id",
            2,
        );
        let mut q = sqlx::query_scalar::<_, Uuid>(&sql).bind(claim_id);
        // Conditional: a `Bypass` viewer renders no `$2`.
        if let Some(w) = viewer.writable_bind() {
            q = q.bind(w);
        }
        Ok(q.fetch_optional(&mut *conn).await?.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Migrations 206 and 209's VIS codes, each answered by its kind with
    /// the database's text; anything else is the ordinary conversion.
    #[test]
    fn vis_codes_are_answered_by_their_kind() {
        use crate::errors::fake_db::{error, shape};
        for (code, message, want) in [
            ("42501", "VIS01: x", "Refused(Authority): VIS01: x"),
            ("42501", "VIS02: x", "Refused(Authority): VIS02: x"),
            ("22023", "VIS03: x", "Refused(Input): VIS03: x"),
            ("40001", "VIS04: x", "Refused(State): VIS04: x"),
            ("42501", "VIS05: x", "Refused(Authority): VIS05: x"),
            ("55000", "VIS06: x", "Refused(State): VIS06: x"),
            ("P0001", "VIS07: x", "QueryFailed"),
            ("P0001", "x VIS01: x", "QueryFailed"),
            ("OPL02", "OPL02: x", "OperatorScopeRefused: OPL02: x"),
            ("P0001", "PVS01: x", "QueryFailed"),
        ] {
            assert_eq!(
                shape(&map_vis_error(error(code, message))),
                want,
                "{message}"
            );
        }
    }

    fn g(n: u8) -> Uuid {
        Uuid::from_bytes([n; 16])
    }

    #[test]
    fn labels_follow_owner_and_visibility() {
        assert_eq!(label_of(Visibility::Public, g(1), g(1)), "public");
        assert_eq!(label_of(Visibility::Group, g(1), g(1)), "private");
        assert_eq!(label_of(Visibility::Group, g(2), g(1)), "team");
    }

    #[test]
    fn not_found_wins_and_refusals_change_nothing() {
        let rows = vec![
            (g(1), "refused_not_admin".to_string()),
            (g(2), "not_found".to_string()),
        ];
        assert!(matches!(
            outcomes_or_refusal("x", rows, &["publicized"]),
            Err(DbError::NotFound { id, .. }) if id == g(2)
        ));
        let rows = vec![(g(1), "refused_sealed".to_string())];
        assert!(matches!(
            outcomes_or_refusal("x", rows, &["publicized"]),
            Err(DbError::Refused {
                kind: RefusalKind::State,
                ..
            })
        ));
        let rows = vec![
            (g(1), "refused_sealed".to_string()),
            (g(3), "refused_not_admin".to_string()),
        ];
        assert!(matches!(
            outcomes_or_refusal("x", rows, &["publicized"]),
            Err(DbError::Refused {
                kind: RefusalKind::Authority,
                ..
            })
        ));
        let rows = vec![
            (g(1), "publicized".to_string()),
            (g(2), "already_public".to_string()),
        ];
        assert_eq!(
            outcomes_or_refusal("x", rows, &["publicized", "already_public"])
                .unwrap()
                .len(),
            2
        );
    }

    /// Migration 242's outcome is an AUTHORITY refusal (403 / INVALID_REQUEST),
    /// never a state one, and its text names the reason rather than the
    /// catch-all "refused".
    #[test]
    fn an_operated_agent_refusal_is_an_authority_refusal_that_says_why() {
        let rows = vec![(g(1), "refused_not_human".to_string())];
        match outcomes_or_refusal("share_claims_with_team", rows, &["shared"]) {
            Err(DbError::Refused {
                kind: RefusalKind::Authority,
                message,
            }) => assert!(message.contains("operated agent"), "{message}"),
            other => panic!("expected an authority refusal, got {other:?}"),
        }
    }
}
