//! Paper entity repository.
//!
//! Papers are first-class graph nodes (entity_type = "paper") used by
//! hierarchical document ingestion. Since migration 246 a row carries the
//! tenancy of the ingest that wrote it and `papers` is unique on (document
//! key, scope): every public ingest of a DOI returns the one public row
//! (get-or-create semantics), and a group's private ingest returns its own. Re-ingestion is gated separately via the `processed_by`
//! edge with a `pipeline` property.

use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

use crate::errors::DbError;

#[derive(Debug, Clone)]
pub struct PaperRow {
    pub id: Uuid,
    pub doi: String,
    pub title: Option<String>,
    pub journal: Option<String>,
}

/// A `papers` row as `POST /api/v1/papers` answers it
/// ([`PaperRepository::registered_row`]).
#[derive(Debug, Clone)]
pub struct RegisteredPaper {
    pub id: Uuid,
    pub doi: String,
    pub title: Option<String>,
    pub journal: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// `(visibility, owner_group_id)` of a declared paper write. A paper has no
/// parent to inherit from, so an `Inherited` declaration is refused here
/// rather than by the database's 23502.
fn declared(decl: epigraph_core::TenancyDecl) -> Result<(&'static str, Uuid), DbError> {
    match (decl.visibility_bind(), decl.owner_group_bind()) {
        (Some(v), Some(g)) => Ok((v, g)),
        _ => Err(DbError::InvalidData {
            reason: "a papers row must be written with a declared tenancy (visibility and \
                     owner group); a paper has no parent to inherit one from"
                .to_string(),
        }),
    }
}

/// A `papers` row as [`PaperRepository::get_or_create_stored`] left it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPaper {
    pub id: Uuid,
    /// The title the row holds AFTER the call. A hit fills only a NULL title,
    /// so this can differ from the title the caller passed (backlog 288801f8),
    /// and it is the one a response should report.
    pub title: Option<String>,
}

/// [`PaperRepository::planned`]: what a get-or-create in one scope would
/// return, read without writing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedPaper {
    /// The existing row's id, else the id a new row of that scope is to be
    /// inserted with: [`public_paper_id`] for a public row, a fresh RANDOM id
    /// for a group's row. Pass it to [`PaperRepository::get_or_create_stored`]
    /// so the walk inserts the row under the id its caller was told.
    pub id: Uuid,
    /// The stored title, else (no row, or a NULL title) the caller's, which
    /// is what the fill-only upsert leaves.
    pub title: Option<String>,
    /// Whether that scope already has a row under some spelling of the key.
    pub exists: bool,
}

/// UUIDv5 namespace for [`public_paper_id`].
pub const PAPER_NAMESPACE: Uuid = Uuid::from_bytes([
    0x5a, 0x9e, 0x7d, 0x10, 0x3c, 0x2b, 0x4f, 0x61, 0x8e, 0x0d, 0x6a, 0x47, 0xb3, 0x19, 0xc2, 0xf8,
]);

/// The id a NEW PUBLIC `papers` row of `doi` is inserted with: a UUIDv5 of
/// its [`canonical_document_key`], so every spelling of the key gives the same
/// id, a re-ingest after a failed walk gets the id the first attempt
/// announced, and two concurrent public ingests of a new document agree on it.
///
/// Public rows only. Since migration 246 a document has one row per SCOPE, and
/// a group's private copy gets a random id instead
/// ([`PaperRepository::planned`]): a private copy cannot share the public
/// row's id (one primary key), and an id computable from the document key
/// would let anyone name a group's private copy and probe whether it exists.
/// A public row written before this keeps its random id; an existing row's id
/// always wins over this one.
#[must_use]
pub fn public_paper_id(doi: &str) -> Uuid {
    Uuid::new_v5(&PAPER_NAMESPACE, canonical_document_key(doi).as_bytes())
}

/// The scope predicate every in-scope `papers` lookup splices into
/// [`document_key_first_in_sql`]: the declared scope's row, never another's.
/// `vis` and `owner` are the bind numbers of the declaration's visibility and
/// owner group (trusted literals, never caller input).
fn in_scope_predicate(vis: usize, owner: usize) -> String {
    format!("visibility = ${vis}::text AND (${vis}::text = 'public' OR owner_group_id = ${owner}::uuid)")
}

pub struct PaperRepository;

impl PaperRepository {
    /// [`Self::get_or_create_stored`] without the stored title, inserting a
    /// new group row under a random id.
    ///
    /// # Errors
    /// Every error of [`Self::get_or_create_stored`].
    pub async fn get_or_create(
        conn: &mut sqlx::PgConnection,
        doi: &str,
        title: Option<&str>,
        journal: Option<&str>,
        decl: epigraph_core::TenancyDecl,
    ) -> Result<Uuid, DbError> {
        Ok(
            Self::get_or_create_stored(conn, doi, title, journal, decl, None)
                .await?
                .id,
        )
    }

    /// Insert a paper in the scope `decl` names, or return the existing row of
    /// that scope if the document key already exists there under any of its
    /// spellings, with the title the row holds after the call.
    ///
    /// # One row per document per scope (migration 246)
    ///
    /// `papers` carries the tenancy of the ingest that wrote it. A PUBLIC row
    /// is shared: every public writer of a document converges on its one public
    /// row, whoever owns it (that is how two sources corroborate, and why a
    /// public ingest behaves as it did before 246). A GROUP row belongs to its
    /// owner group: a team's private ingest of a document another team holds
    /// privately creates its own row and learns nothing about the other's.
    /// The lookup therefore matches the declared SCOPE, not merely what the
    /// session can see: a member sees both its group's row and the public one,
    /// and must reuse the one its declaration names.
    ///
    /// Run it on the writer's STAMPED connection (`decl` is the ingest's
    /// resolved declaration). Row security admits the INSERT only for an owner
    /// group the session writes; the conflicting row of a scope is always one
    /// the writer can read (public, or its own group's), so the upsert never
    /// lands on a hidden row.
    ///
    /// # The id of a new row
    ///
    /// A new PUBLIC row takes [`public_paper_id`], derived from the document
    /// key, whatever `group_copy_id` says, unless that id is already held by
    /// a row this scope's lookup cannot find (another document's row, or a
    /// row moved out of the public scope): the insert then falls back to a
    /// random id rather than failing for good, and a detached ingest's
    /// announced id differs from the stored one. A new GROUP row takes
    /// `group_copy_id` when given (the random id [`Self::planned`] chose and a
    /// detached ingest already announced), else a fresh random one: never an
    /// id derivable from the key (see [`public_paper_id`]), so a
    /// `group_copy_id` equal to it is ignored.
    ///
    /// The key is matched through [`document_key_spellings`] and
    /// [`document_key_first_in_sql`] within the declared scope, canonical
    /// first, so a row an older writer stored under a resolver URL
    /// (`https://doi.org/10.x/y`, or a case variant of its prefix such as
    /// `HTTPS://DOI.ORG/10.x/y`) is reused rather than twinned (backlogs
    /// 90756d26, f3a3ca54). A new row is stored under the
    /// [`canonical_document_key`].
    ///
    /// **A hit fills only NULL fields** (backlog 62ce37ca): the row found keeps
    /// its `title` and `journal`; a provided value is written only where the
    /// stored one is NULL.
    ///
    /// # A concurrent creator
    ///
    /// The insert is `ON CONFLICT DO NOTHING` with no conflict target, so a
    /// concurrent writer of the same new row in the same scope makes this
    /// statement wait for it and then insert nothing, whichever unique index
    /// the two collide on first: the document-key-per-scope index, or the
    /// primary key (two public creators insert the same derived id, and an
    /// `ON CONFLICT` naming only the key index would raise 23505 on the
    /// primary key in that race). The statement then runs once more, on a
    /// fresh snapshot that sees the winner's row, and takes the hit arm
    /// (fill-only), so the loser returns the winner's row. That second run is
    /// why this takes one connection rather than any executor: a pool caller
    /// passes `&mut *pool.acquire().await?`.
    ///
    /// # Errors
    /// `DbError::InvalidData` for an undeclared (`Inherited`) `decl`: a paper
    /// has no parent to inherit from. `DbError::QueryFailed` if the statement
    /// fails, including a row-security refusal (42501) for an owner group the
    /// session does not write. `DbError::InvalidData` if the insert collided
    /// on every id it tried with a row its re-runs still cannot find.
    #[instrument(skip(conn))]
    pub async fn get_or_create_stored(
        conn: &mut sqlx::PgConnection,
        doi: &str,
        title: Option<&str>,
        journal: Option<&str>,
        decl: epigraph_core::TenancyDecl,
        group_copy_id: Option<Uuid>,
    ) -> Result<StoredPaper, DbError> {
        let (visibility, owner) = declared(decl)?;
        let canonical = canonical_document_key(doi);
        let spellings = document_key_spellings(doi);
        let derived = public_paper_id(doi);
        let new_id = if visibility == "public" {
            derived
        } else {
            // Never the derived id, even if a caller passes it: a group copy
            // under an id computable from the key is the shape the id policy
            // forbids, and it would squat the public row's id as well.
            group_copy_id
                .filter(|id| *id != derived)
                .unwrap_or_else(Uuid::new_v4)
        };
        // Runtime-checked, not `query!`: CI's migration runner is built
        // `SQLX_OFFLINE`, so a new compile-time query cannot be cached
        // before the schema it is checked against exists.
        let sql = format!(
            r#"
            WITH found AS (
                {first}
            ),
            updated AS (
                UPDATE papers p SET
                    title = COALESCE(p.title, $3::text),
                    journal = COALESCE(p.journal, $4::text)
                FROM found
                WHERE p.id = found.id
                RETURNING p.id, p.title
            ),
            inserted AS (
                INSERT INTO papers (id, doi, title, journal, visibility, owner_group_id)
                SELECT $7::uuid, $2::text, $3::text, $4::text, $5::text, $6::uuid
                WHERE NOT EXISTS (SELECT 1 FROM found)
                ON CONFLICT DO NOTHING
                RETURNING id, title
            )
            SELECT id, title FROM updated
            UNION ALL
            SELECT id, title FROM inserted
            "#,
            first = document_key_first_in_sql("id", 1, &in_scope_predicate(5, 6)),
        );
        // Each id is tried twice: the second run is the race loser's (see
        // above). A public insert whose derived id is held by a row its scope
        // lookup cannot see (another document's row, or a row moved out of
        // the public scope) falls back to a random id, so that row cannot
        // block the document's public row for good; that is the one case in
        // which a new public row does not take the derived id.
        let fallback = (visibility == "public").then(Uuid::new_v4);
        for id in [Some(new_id), fallback].into_iter().flatten() {
            for _ in 0..2 {
                let row: Option<(Uuid, Option<String>)> = sqlx::query_as(&sql)
                    .bind(&spellings)
                    .bind(&canonical)
                    .bind(title)
                    .bind(journal)
                    .bind(visibility)
                    .bind(owner)
                    .bind(id)
                    .fetch_optional(&mut *conn)
                    .await?;
                if let Some((id, title)) = row {
                    return Ok(StoredPaper { id, title });
                }
            }
            if fallback.is_some_and(|f| f != id) {
                tracing::warn!(
                    "papers: a new public row's derived id is held by a row outside its \
                     scope lookup; inserting it under a random id"
                );
            }
        }
        // Generic on purpose: which row holds the id is not the caller's to learn.
        Err(DbError::InvalidData {
            reason: format!(
                "papers: could not insert or find the row of document key {canonical:?} \
                 in the declared scope"
            ),
        })
    }

    /// What [`Self::get_or_create_stored`] in the scope `decl` names WOULD
    /// return, read without writing: the existing row's id and its title
    /// filled the way the upsert fills it; or, when that scope has no row of
    /// the key, the id a new row is to take ([`public_paper_id`] for a public
    /// row, a fresh random id for a group's) and the caller's title.
    ///
    /// For the detached ingest handlers, which answer the caller before the
    /// walk that writes the row has run (backlog b995f117): they pass
    /// [`PlannedPaper::id`] to the walk's [`Self::get_or_create_stored`], so a
    /// new group copy is inserted under the random id announced. Read on the
    /// writer's stamped connection, with the same in-scope lookup as the
    /// upsert's. The prediction holds unless another writer creates the row
    /// of that scope in between (a concurrent ingest of the same document in
    /// the same scope; for a group copy, its random id then differs, and the
    /// walk converges on the other writer's row).
    ///
    /// # Errors
    /// `DbError::InvalidData` for an undeclared `decl`; `DbError::QueryFailed`
    /// if the query fails.
    pub async fn planned<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        doi: &str,
        title: Option<&str>,
        decl: epigraph_core::TenancyDecl,
    ) -> Result<PlannedPaper, DbError> {
        let (visibility, owner) = declared(decl)?;
        let found: Option<(Uuid, Option<String>)> = sqlx::query_as(&document_key_first_in_sql(
            "id, title",
            1,
            &in_scope_predicate(2, 3),
        ))
        .bind(document_key_spellings(doi))
        .bind(visibility)
        .bind(owner)
        .fetch_optional(executor)
        .await?;
        Ok(match found {
            Some((id, stored)) => PlannedPaper {
                id,
                title: stored.or_else(|| title.map(str::to_string)),
                exists: true,
            },
            None => PlannedPaper {
                id: if visibility == "public" {
                    public_paper_id(doi)
                } else {
                    Uuid::new_v4()
                },
                title: title.map(str::to_string),
                exists: false,
            },
        })
    }

    /// The id of the row of `doi` in the scope `decl` names (see
    /// [`Self::get_or_create`]), under any spelling, canonical first, else a
    /// legacy row of that scope keyed on a case variant of a resolver prefix
    /// (backlog f3a3ca54); `None` when that scope has none. The row a write declared with `decl` would
    /// reuse, read on the writer's stamped connection.
    ///
    /// # Errors
    /// `DbError::InvalidData` for an undeclared `decl`; `DbError::QueryFailed`
    /// if the query fails.
    pub async fn find_in_scope<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        doi: &str,
        decl: epigraph_core::TenancyDecl,
    ) -> Result<Option<Uuid>, DbError> {
        let (visibility, owner) = declared(decl)?;
        Ok(sqlx::query_scalar(&document_key_first_in_sql(
            "id",
            1,
            &in_scope_predicate(2, 3),
        ))
        .bind(document_key_spellings(doi))
        .bind(visibility)
        .bind(owner)
        .fetch_optional(executor)
        .await?)
    }

    /// Every `papers` row of the document `raw` names that `viewer` may read,
    /// under any of its [`document_key_spellings`] ([`document_key_rows_sql`]:
    /// a legacy row keyed on a case variant of a resolver prefix only when no
    /// readable row has an exact spelling, backlog f3a3ca54): spelling order
    /// first (canonical, then as given, then legacy resolver spellings, then a
    /// case-variant row), then the
    /// viewer's own GROUP rows before the public one (the copy a team's ingest
    /// wrote is the one its member asked about), then oldest first.
    ///
    /// Migration 246 gives `papers` row security, so on `viewer`'s stamped
    /// connection a row of another group's private ingest is simply absent: no
    /// existence oracle. Run it on that connection so the predicate spliced
    /// here and the row security agree: the exact-spelling gate of the
    /// case-variant fallback is filtered by that row security alone, so a
    /// hidden row never suppresses the fallback for a readable one.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the query fails.
    pub async fn visible_by_document_key(
        conn: &mut sqlx::PgConnection,
        viewer: &crate::visibility::Viewer,
        raw: &str,
    ) -> Result<Vec<PaperRow>, DbError> {
        let sql = viewer.splice(
            &format!(
                "SELECT p.id, p.doi, p.title, p.journal FROM ({rows}) AS p \
                  WHERE TRUE /* {{VISIBILITY:p}} */ \
                  ORDER BY array_position($1::text[], p.doi), (p.visibility = 'group') DESC, \
                           p.created_at, p.id",
                rows = document_key_rows_sql("*", 1),
            ),
            2,
        );
        let mut q = sqlx::query_as::<_, (Uuid, String, Option<String>, Option<String>)>(&sql)
            .bind(document_key_spellings(raw));
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(&mut *conn)
            .await?
            .into_iter()
            .map(|(id, doi, title, journal)| PaperRow {
                id,
                doi,
                title,
                journal,
            })
            .collect())
    }

    /// The row [`Self::get_or_create`] just returned, read back on the SAME
    /// connection (the writer's stamped transaction) for a response:
    /// `POST /api/v1/papers`. The id came from that write, so row security on
    /// that connection already admits it; there is no viewer to spend.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the query fails or no row has this id.
    pub async fn registered_row<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        id: Uuid,
    ) -> Result<RegisteredPaper, DbError> {
        let (id, doi, title, journal, created_at) = sqlx::query_as::<
            _,
            (
                Uuid,
                String,
                Option<String>,
                Option<String>,
                chrono::DateTime<chrono::Utc>,
            ),
        >(
            "SELECT id, doi, title, journal, COALESCE(created_at, now()) FROM papers WHERE id = $1",
        )
        .bind(id)
        .fetch_one(executor)
        .await?;
        Ok(RegisteredPaper {
            id,
            doi,
            title,
            journal,
            created_at,
        })
    }

    /// Find the paper a caller-supplied document key names, under any stored
    /// spelling of it ([`document_key_spellings`] through
    /// [`document_key_first_sql`]): the canonical key first, then the key as
    /// given, then each legacy resolver-prefix spelling, and only when none of
    /// those is stored, a legacy row whose prefix differs from them only in
    /// letter case. `None` if no row matches.
    ///
    /// Runtime-checked, not `query!`, for the reason given in
    /// [`Self::get_or_create`].
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn find_by_document_key(
        pool: &PgPool,
        raw: &str,
    ) -> Result<Option<PaperRow>, DbError> {
        use sqlx::Row;
        let row = sqlx::query(&document_key_first_sql("id, doi, title, journal", 1))
            .bind(document_key_spellings(raw))
            .fetch_optional(pool)
            .await?;
        Ok(row.map(|r| PaperRow {
            id: r.get("id"),
            doi: r.get("doi"),
            title: r.get("title"),
            journal: r.get("journal"),
        }))
    }

    /// Find a paper by DOI, matching the stored key EXACTLY (no spelling
    /// expansion; see [`Self::find_by_document_key`]). Returns `None` if no
    /// paper has this DOI.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn find_by_doi(pool: &PgPool, doi: &str) -> Result<Option<PaperRow>, DbError> {
        // Use `as "title?"` to override sqlx introspection: the migration
        // declares `title` nullable; the dev DB has historical NOT NULL drift.
        let row = sqlx::query!(
            r#"
            SELECT id, doi, title as "title?", journal
            FROM papers
            WHERE doi = $1
            "#,
            doi
        )
        .fetch_optional(pool)
        .await?;
        Ok(row.map(|r| PaperRow {
            id: r.id,
            doi: r.doi,
            title: r.title,
            journal: r.journal,
        }))
    }

    /// The source licence recorded for a paper (migration 226), or `None`
    /// when none is recorded or no paper has this id. `None` means "unknown",
    /// which every caller must treat as all rights reserved. Ingest only READS
    /// this; it is set by an operator, never from an extraction, so a caller
    /// cannot declare its own source open-licensed (backlog 8709d128). The
    /// database enforces that since migration 255 (backlog 9ee6799d): the
    /// application role holds no INSERT or UPDATE on `licence`, and no UPDATE
    /// on `doi` or `id`, so it can neither write a licence nor move a licensed
    /// row onto another DOI (this is read by id after a lookup by DOI). The
    /// operator writes it through the audited `epigraph_set_paper_licence`.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor))]
    pub async fn licence<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        paper_id: Uuid,
    ) -> Result<Option<String>, DbError> {
        // Runtime-checked, not `query!`: see `get_or_create`.
        let licence: Option<Option<String>> =
            sqlx::query_scalar("SELECT licence FROM papers WHERE id = $1")
                .bind(paper_id)
                .fetch_optional(executor)
                .await?;
        Ok(licence.flatten())
    }

    /// Returns true if the paper has any outgoing `processed_by` edge whose
    /// `properties.pipeline` matches `pipeline_version`. Used as the
    /// re-ingestion version gate by hierarchical ingestion.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn has_processed_by_edge<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        paper_id: Uuid,
        pipeline_version: &str,
    ) -> Result<bool, DbError> {
        // MACRO SITE — the static three-bind spelling; `sqlx::query!` cannot be
        // spliced. See `ClaimRepository::get_by_id`.
        let row = sqlx::query!(
            r#"
            SELECT 1 AS exists_marker
            FROM edges
            WHERE source_id = $1
              AND source_type = 'paper'
              AND relationship = 'processed_by'
              AND properties ->> 'pipeline' = $2
              AND ($3::bool OR visibility = 'public'
                   OR (owner_group_id = ANY($4::uuid[])
                       AND (co_owner_group_id IS NULL
                            OR co_owner_group_id = ANY($4::uuid[]))))
            LIMIT 1
            "#,
            paper_id,
            pipeline_version,
            viewer.bypass_bind(),
            viewer.group_bind().unwrap_or(&[]),
        )
        .fetch_optional(executor)
        .await?;
        Ok(row.is_some())
    }

    /// Every pipeline stamp in the `base` FAMILY that a visible `processed_by`
    /// edge from `paper_id` carries: `base` itself and each chunked
    /// `base:ch{n}` stamp, sorted.
    ///
    /// Backlog 02653c4a (G8). The ingest tools stamp `processed_by` with
    /// `ingestion.rs::effective_pipeline_version`, which appends `:ch{n}` for a
    /// chunked (per-chapter) ingest. A pre-flight that asks only for the bare
    /// `base` stamp therefore reported `already_ingested: false` for a document
    /// ingested chapter by chapter. This is the read that answers "has ANY
    /// ingest of this document at this pipeline landed, and which?".
    ///
    /// Deliberately NOT a replacement for [`Self::has_processed_by_edge`]: an
    /// exact-stamp check is how a caller asks about ONE chunk, and a family
    /// match would let chapter 1's stamp answer for chapter 2. Each chunk
    /// writes its own stamp
    /// ([`crate::EdgeRepository::create_processed_by_stamp_if_absent_conn`]),
    /// so both reads see every chunk that landed.
    ///
    /// `starts_with`, not `LIKE`: the stamp contains `_`, a `LIKE` wildcard.
    /// Edge visibility is the co-owner-aware `EDGE_VISIBILITY` predicate.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn processed_by_pipelines_in_family<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        paper_id: Uuid,
        base: &str,
    ) -> Result<Vec<String>, DbError> {
        let sql = viewer.splice(
            "SELECT DISTINCT e.properties ->> 'pipeline' AS pipeline \
             FROM edges e \
             WHERE e.source_id = $1 \
               AND e.source_type = 'paper' \
               AND e.relationship = 'processed_by' \
               AND (e.properties ->> 'pipeline' = $2 \
                    OR starts_with(e.properties ->> 'pipeline', $2 || ':ch')) \
               /* {EDGE_VISIBILITY:e} */ \
             ORDER BY 1",
            3,
        );
        let mut q = sqlx::query_scalar::<_, String>(&sql)
            .bind(paper_id)
            .bind(base);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?)
    }

    /// Count the claims this paper asserts: its ingest-written
    /// (`crate::ingest_written_edge_sql`) `paper -asserts-> claim` edges,
    /// each claim once (every principal whose ingest of the paper asserts a
    /// claim keeps an edge of its own, `crate::ingest_written`, so one claim
    /// can carry several). An assertion written any other way (by hand,
    /// before the marker existed) is not the ingest's and is not counted.
    ///
    /// This alone under-counts a partially-ingested paper: `do_ingest_document`
    /// / `do_ingest_document_spine` label every claim `doi:<doi>` *before*
    /// writing that claim's `asserts` edge (evidence + reasoning-trace writes
    /// sit in between), so a crash or error mid-loop can leave claims with the
    /// doi label but no edge yet. Callers that need an accurate "has this DOI
    /// landed in the graph at all?" probe must combine this with
    /// [`Self::count_claims_by_doi_label`] (see `query_paper`) — trusting this
    /// alone as a duplicate-ingestion gate is the write-order race behind
    /// backlog 7c6ce1b3-b372-4727-a510-43e63001bf18 (the specific claims that
    /// prompted that report predate the `doi:<doi>` label entirely and were
    /// resolved separately by a full re-ingestion; this closes the gap for
    /// future partial ingestions under the current write order).
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn count_asserted_claims<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        paper_id: Uuid,
    ) -> Result<i64, DbError> {
        // Static three-bind spelling (runtime form: the ingest-written
        // predicate is spliced from `ingest_written`, the one place it is
        // defined).
        let sql = format!(
            "SELECT COUNT(DISTINCT e.target_id) \
               FROM edges e \
              WHERE e.source_id = $1 \
                AND e.source_type = 'paper' \
                AND e.target_type = 'claim' \
                AND e.relationship = 'asserts' \
                AND {marked} \
                AND ($2::bool OR e.visibility = 'public' \
                     OR (e.owner_group_id = ANY($3::uuid[]) \
                         AND (e.co_owner_group_id IS NULL \
                              OR e.co_owner_group_id = ANY($3::uuid[]))))",
            marked = crate::repos::ingest_written::ingest_written_edge_sql("e"),
        );
        let count: i64 = sqlx::query_scalar(&sql)
            .bind(paper_id)
            .bind(viewer.bypass_bind())
            .bind(viewer.group_bind().unwrap_or(&[]))
            .fetch_one(executor)
            .await?;
        Ok(count)
    }

    /// Count current claims labelled `doi:<doi>`, independent of whether a
    /// `paper -asserts-> claim` edge exists yet for them.
    ///
    /// Every claim written by `do_ingest_document` / `do_ingest_document_spine`
    /// picks up this label as soon as the claim row itself is created — ahead
    /// of the `asserts` edge, which lands only after evidence + reasoning-trace
    /// writes succeed. This makes the label a more direct "does this DOI have
    /// node presence in the graph?" signal than the edge-based count, and is
    /// what `query_paper` uses to avoid mis-reporting `claim_count=0` for a
    /// paper that was partially ingested.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn count_claims_by_doi_label<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        doi: &str,
    ) -> Result<i64, DbError> {
        let label = format!("doi:{doi}");
        // MACRO SITE — static three-bind spelling. A count is still a
        // disclosure: it says how much of a DOI landed in a tenant the caller
        // cannot read.
        let row = sqlx::query!(
            r#"
            SELECT COUNT(*) AS "count!"
            FROM claims
            WHERE is_current
              AND labels @> ARRAY[$1]::text[]
              AND ($2::bool OR visibility = 'public' OR owner_group_id = ANY($3::uuid[]))
            "#,
            label,
            viewer.bypass_bind(),
            viewer.group_bind().unwrap_or(&[]),
        )
        .fetch_one(executor)
        .await?;
        Ok(row.count)
    }

    /// The paper's authors as a reader sees them: every in-force,
    /// ingest-written (`crate::ingest_written_edge_sql`) `agent -authored->
    /// paper` edge `viewer` may read, in the extraction's
    /// order (`properties.position`, then age), each with what the edge
    /// records. A RETRACTED authorship (an author the operator CLI replaced)
    /// is not listed. An authorship an ingester asserted for someone it
    /// neither is nor operates is listed with `pending_countersign: true` and
    /// the ingester ([`AUTHORED_PENDING_KEY`], [`AUTHORED_INGESTED_BY_KEY`]),
    /// never as a plain author: the same predicate the agent card counts by
    /// ([`crate::agent_lookup::authorship_pending_sql`]).
    ///
    /// One row per authorship EDGE: every principal whose ingest names an
    /// author keeps an edge of its own (`crate::ingest_written`), so an author
    /// two principals' ingests named is listed once per principal, each row
    /// with its own `written_by`. A reader groups by `written_by`; it never
    /// shows one principal's rows beside another's claims.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn list_authors<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        paper_id: Uuid,
    ) -> Result<Vec<PaperAuthorListing>, DbError> {
        Self::author_listing(executor, viewer, paper_id, None, None).await
    }

    /// The authorships ONE ingest principal's document ingest wrote for the
    /// paper (their ingest-written marker names `ingested_by`), as
    /// [`Self::list_authors`] lists them, at most `limit` rows: that
    /// principal's author list, which goes with that principal's claims
    /// ([`Self::list_asserted_claims_by`]) and never with another's.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn list_authors_by<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        paper_id: Uuid,
        ingested_by: Uuid,
        limit: i64,
    ) -> Result<Vec<PaperAuthorListing>, DbError> {
        Self::author_listing(executor, viewer, paper_id, Some(ingested_by), Some(limit)).await
    }

    /// [`Self::list_authors`] / [`Self::list_authors_by`]: `ingested_by`
    /// `None` lists every principal's rows, `limit` `None` no cap (`LIMIT
    /// NULL`).
    async fn author_listing<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        paper_id: Uuid,
        ingested_by: Option<Uuid>,
        limit: Option<i64>,
    ) -> Result<Vec<PaperAuthorListing>, DbError> {
        let sql = viewer.splice(
            &format!(
                "SELECT {columns} \
                   FROM edges e \
                   JOIN agents a ON a.id = e.source_id \
                  WHERE e.target_id = $1 AND {authored} \
                    AND ($2::text IS NULL OR {written_by} = $2::text) \
                    /* {{EDGE_VISIBILITY:e}} */ \
                  ORDER BY {order} \
                  LIMIT $3",
                columns = author_listing_columns(),
                authored = authored_in_force_readable(),
                order = AUTHOR_LISTING_ORDER,
                written_by = crate::repos::ingest_written::ingest_written_by_sql("e"),
            ),
            4,
        );
        let mut q = sqlx::query_as::<_, AuthorListingRow>(&sql)
            .bind(paper_id)
            .bind(ingested_by.map(|u| u.to_string()))
            .bind(limit);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor)
            .await?
            .into_iter()
            .map(author_listing)
            .collect())
    }

    /// The authors of several papers in ONE read, bounded in SQL, as the
    /// INGESTS named in `writers` wrote them: at most `per_paper` authors of
    /// each paper (under [`Self::list_authors`]'s predicate), plus whether
    /// more exist. Papers with no listed author are absent from the map. For
    /// a reader that lists several documents' authors at once (a claim's
    /// provenance block), so neither the number of papers nor the length of
    /// an author list turns one read into an unbounded one.
    ///
    /// Each principal's ingest keeps its own authorship rows
    /// (`crate::ingest_written`), so a paper's authors are a set of words,
    /// one per ingest principal. `writers` names, per paper, the principals
    /// whose rows this read takes, as `(paper, principal, rank)`: only a row
    /// whose ingest-written marker's `by` is one of the paper's writers is
    /// listed (compared as text, so a malformed marker matches nothing). An
    /// author is listed ONCE: from its recorded row if it has one (below),
    /// else from the lowest-ranked writer's row, a row not awaiting
    /// countersignature before one that is, then the oldest.
    ///
    /// `recorded` names the authorships a reader takes from a record rather
    /// than from the edges alone, as `(paper, author, principal)`: a claim's
    /// creating ingest records its document's authors
    /// (`crate::ClaimIngestRecord::authors`), and the row that backs a
    /// recorded author is that SAME principal's own row, never another
    /// ingest's row of the same author. Each listed author carries whether it
    /// was listed from a recorded row; those are listed FIRST (then position
    /// order), so authorships other ingests wrote, however many and wherever
    /// they sort, can never push a recorded author out of the `per_paper`
    /// window.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer, writers, recorded))]
    pub async fn list_authors_bounded<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        paper_ids: &[Uuid],
        per_paper: i64,
        writers: &[(Uuid, Uuid, i32)],
        recorded: &[(Uuid, Uuid, Uuid)],
    ) -> Result<BoundedAuthorListings, DbError> {
        let mut out = BoundedAuthorListings::new();
        if paper_ids.is_empty() || per_paper <= 0 || writers.is_empty() {
            return Ok(out);
        }
        let written_by = crate::repos::ingest_written::ingest_written_by_sql("e");
        let in_record = format!(
            "EXISTS (SELECT 1 FROM unnest($3::uuid[], $4::uuid[], $5::uuid[]) AS r(p, a, w) \
              WHERE r.p = p.id AND r.a = e.source_id AND r.w::text = {written_by})"
        );
        let sql = viewer.splice(
            &format!(
                "SELECT p.id, x.* \
                   FROM unnest($1::uuid[]) AS p(id) \
                  CROSS JOIN LATERAL ( \
                        SELECT d.*, \
                               row_number() OVER (ORDER BY d.in_record DESC, \
                                                  d.pos NULLS LAST, d.at, d.eid) \
                                   AS listing_rank \
                          FROM ( \
                                SELECT DISTINCT ON (e.source_id) \
                                       {columns}, {in_record} AS in_record, \
                                       {pos} AS pos, e.created_at AS at, e.id AS eid \
                                  FROM edges e \
                                  JOIN agents a ON a.id = e.source_id \
                                  JOIN unnest($6::uuid[], $7::uuid[], $8::int[]) \
                                       AS w(p, by, rank) \
                                    ON w.p = p.id AND w.by::text = {written_by} \
                                 WHERE e.target_id = p.id AND {authored} \
                                   /* {{EDGE_VISIBILITY:e}} */ \
                                 ORDER BY e.source_id, {in_record} DESC, w.rank, \
                                          {pending}, e.created_at, e.id) d \
                         ORDER BY d.in_record DESC, d.pos NULLS LAST, d.at, d.eid \
                         LIMIT $2) x \
                  ORDER BY p.id, x.listing_rank",
                columns = author_listing_columns(),
                authored = authored_in_force_readable(),
                pos = AUTHOR_LISTING_POSITION,
                pending = crate::agent_lookup::authorship_pending_sql("e"),
            ),
            9,
        );
        type Row = (
            Uuid,
            Uuid,
            Option<String>,
            Option<i64>,
            String,
            serde_json::Value,
            bool,
            Option<String>,
            Option<String>,
            bool,
            Option<i64>,
            chrono::DateTime<chrono::Utc>,
            Uuid,
            i64,
        );
        let mut q = sqlx::query_as::<_, Row>(&sql)
            .bind(paper_ids)
            .bind(per_paper.saturating_add(1))
            .bind(recorded.iter().map(|(p, _, _)| *p).collect::<Vec<Uuid>>())
            .bind(recorded.iter().map(|(_, a, _)| *a).collect::<Vec<Uuid>>())
            .bind(recorded.iter().map(|(_, _, w)| *w).collect::<Vec<Uuid>>())
            .bind(writers.iter().map(|(p, _, _)| *p).collect::<Vec<Uuid>>())
            .bind(writers.iter().map(|(_, w, _)| *w).collect::<Vec<Uuid>>())
            .bind(writers.iter().map(|(_, _, r)| *r).collect::<Vec<i32>>());
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let limit = usize::try_from(per_paper).unwrap_or(usize::MAX);
        for (paper, a, name, pos, role, aff, pending, by, written, in_record, ..) in
            q.fetch_all(executor).await?
        {
            let entry = out.entry(paper).or_default();
            if entry.0.len() < limit {
                entry.0.push((
                    author_listing((a, name, pos, role, aff, pending, by, written)),
                    in_record,
                ));
            } else {
                entry.1 = true;
            }
        }
        Ok(out)
    }

    /// List claim summaries asserted by this paper — one page of `limit` rows
    /// starting at `offset` — reached via its ingest-written
    /// `paper -asserts-> claim` edges (as [`Self::count_asserted_claims`]).
    /// Ordered by claim `created_at` ascending (ingest order), with an `id`
    /// tiebreaker so `LIMIT`/`OFFSET` paging is stable across the many claims
    /// a single ingestion writes with an identical timestamp.
    ///
    /// Returns `(id, content, truth_value, agent_id, content_hash, created_at,
    /// is_current, supersedes)` per claim — the shape `query_paper` needs for
    /// `ClaimResponse`.
    ///
    /// There is deliberately NO `is_current` filter: a superseded claim the
    /// paper asserted is still on the page, and `query_paper`'s `has_more`
    /// ("a short page is the end of the set") is computed over exactly this
    /// row set. The row's real retirement state is projected instead, so the
    /// caller can report it rather than claim every asserted row is current
    /// (drain unit U008, backlog `1e6efd2d` residual).
    ///
    /// `offset` exists because `query_paper` previously hardcoded
    /// `limit = 100` with no way to reach claim 101, and the resulting
    /// single-shot response exceeded the MCP tool output token limit on dense
    /// paper subgraphs (backlog `0e6ec456`). Pair it with
    /// [`Self::count_asserted_claims`] so a caller can tell a full page from
    /// the end of the set.
    ///
    /// Each claim once (`SELECT DISTINCT`): every principal whose ingest of
    /// the paper asserts a claim keeps an edge of its own.
    ///
    /// Uses the runtime `query_as` form (no compile-time `.sqlx` cache entry),
    /// so adding `OFFSET` (or the ingest-written predicate) needs no
    /// `cargo sqlx prepare`.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn list_asserted_claims<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        paper_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AssertedClaimRow>, DbError> {
        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            content: String,
            truth_value: f64,
            agent_id: Uuid,
            content_hash: Vec<u8>,
            created_at: chrono::DateTime<chrono::Utc>,
            is_current: bool,
            supersedes: Option<Uuid>,
        }

        let rows: Vec<Row> = sqlx::query_as(
            &r#"
            SELECT DISTINCT
                c.id,
                c.content,
                c.truth_value,
                c.agent_id,
                c.content_hash,
                c.created_at,
                COALESCE(c.is_current, true) AS is_current,
                c.supersedes
            FROM edges e
            JOIN claims c ON c.id = e.target_id
            WHERE e.source_id = $1
              AND e.source_type = 'paper'
              AND e.target_type = 'claim'
              AND e.relationship = 'asserts'
              AND __INGEST_WRITTEN__
              AND ($4::bool OR e.visibility = 'public'
                   OR (e.owner_group_id = ANY($5::uuid[])
                       AND (e.co_owner_group_id IS NULL
                            OR e.co_owner_group_id = ANY($5::uuid[]))))
              AND ($4::bool OR c.visibility = 'public' OR c.owner_group_id = ANY($5::uuid[]))
            ORDER BY c.created_at ASC, c.id
            LIMIT $2 OFFSET $3
            "#
            .replace(
                "__INGEST_WRITTEN__",
                &crate::repos::ingest_written::ingest_written_edge_sql("e"),
            ),
        )
        .bind(paper_id) // $1
        .bind(limit) // $2
        .bind(offset) // $3
        // The STATIC three-bind visibility form, not `splice`: both binds are
        // unconditional, so `OFFSET $3` can sit ahead of them without the
        // arity of this statement depending on the viewer's shape. Renumbered
        // from HEAD's $3/$4 because the branch's new `offset` took $3 — left
        // as-is the bypass flag and the page offset would have shared a
        // placeholder, which typechecks and silently pages by a boolean.
        .bind(viewer.bypass_bind()) // $4
        .bind(viewer.group_bind().unwrap_or(&[])) // $5
        .fetch_all(executor)
        .await?;
        rows.into_iter()
            .map(|r| {
                let content_hash: [u8; 32] =
                    r.content_hash
                        .as_slice()
                        .try_into()
                        .map_err(|_| DbError::InvalidData {
                            reason: format!(
                                "claim {} has content_hash of length {} (expected 32)",
                                r.id,
                                r.content_hash.len()
                            ),
                        })?;
                Ok(AssertedClaimRow {
                    id: r.id,
                    content: r.content,
                    truth_value: r.truth_value,
                    agent_id: r.agent_id,
                    content_hash,
                    created_at: r.created_at,
                    is_current: r.is_current,
                    supersedes: r.supersedes,
                })
            })
            .collect()
    }

    /// The ingest principals whose document ingest of the paper wrote an
    /// in-force, ingest-written edge `viewer` may read (a `paper -asserts->
    /// claim` or an `agent -authored-> paper`, each marked with the
    /// principal's `by`), oldest first, at most `limit`. Each principal is one
    /// ingest of the paper as its readers see it: its authors
    /// ([`Self::list_authors_by`]) go with its claims
    /// ([`Self::list_asserted_claims_by`]), never with another principal's.
    /// One principal's several ingests of the same document are one
    /// principal (the writer keeps one row of a fact per principal).
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn ingest_principals<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        paper_id: Uuid,
        limit: i64,
    ) -> Result<Vec<PaperIngestPrincipal>, DbError> {
        // Static three-bind spelling: every bind is unconditional.
        let sql = format!(
            "SELECT k.by::uuid, k.first_at \
               FROM (SELECT {by} AS by, min(e.created_at) AS first_at \
                       FROM edges e \
                      WHERE ((e.source_id = $1 AND e.source_type = 'paper' \
                              AND e.target_type = 'claim' AND e.relationship = 'asserts') \
                          OR (e.target_id = $1 AND e.target_type = 'paper' \
                              AND e.source_type = 'agent' AND e.relationship = 'authored')) \
                        AND {in_force} \
                        AND {marked} \
                        AND {by} ~ '^[0-9a-fA-F]{{8}}-([0-9a-fA-F]{{4}}-){{3}}[0-9a-fA-F]{{12}}$' \
                        AND ($2::bool OR e.visibility = 'public' \
                             OR (e.owner_group_id = ANY($3::uuid[]) \
                                 AND (e.co_owner_group_id IS NULL \
                                      OR e.co_owner_group_id = ANY($3::uuid[])))) \
                      GROUP BY 1) k \
              ORDER BY k.first_at, k.by \
              LIMIT $4",
            by = crate::repos::ingest_written::ingest_written_by_sql("e"),
            in_force = crate::repos::edge::EDGE_IN_FORCE,
            marked = crate::repos::ingest_written::ingest_written_edge_sql("e"),
        );
        let rows: Vec<(Uuid, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(&sql)
            .bind(paper_id)
            .bind(viewer.bypass_bind())
            .bind(viewer.group_bind().unwrap_or(&[]))
            .bind(limit)
            .fetch_all(executor)
            .await?;
        Ok(rows
            .into_iter()
            .map(|(ingested_by, first_written_at)| PaperIngestPrincipal {
                ingested_by,
                first_written_at,
            })
            .collect())
    }

    /// The provenance half of the predicate [`Self::count_asserted_claims_by`]
    /// and [`Self::list_asserted_claims_by`] share, over `e` (the assertion):
    /// the in-force, ingest-written `paper -asserts-> claim` edge whose marker
    /// names `$2` (the principal, text), from paper `$1`. Each caller spells
    /// the same static visibility predicate (`$3` bypass, `$4` groups) over
    /// `e` and `c` inline in its own SQL, so count and page stay one set.
    fn asserted_by_predicate() -> String {
        format!(
            "e.source_id = $1 AND e.source_type = 'paper' \
             AND e.target_type = 'claim' AND e.relationship = 'asserts' \
             AND {in_force} AND {marked} AND {by} = $2::text",
            in_force = crate::repos::edge::EDGE_IN_FORCE,
            marked = crate::repos::ingest_written::ingest_written_edge_sql("e"),
            by = crate::repos::ingest_written::ingest_written_by_sql("e"),
        )
    }

    /// Count the claims ONE ingest principal's document ingest of the paper
    /// asserts (its own in-force, ingest-written `paper -asserts-> claim`
    /// edges), each once. In step with [`Self::list_asserted_claims_by`]
    /// (one predicate), so a pager can tell a full page from the end.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn count_asserted_claims_by<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        paper_id: Uuid,
        ingested_by: Uuid,
    ) -> Result<i64, DbError> {
        // Static four-bind spelling over the assertion and the claim; the
        // same predicate as `list_asserted_claims_by`.
        let sql = format!(
            "SELECT COUNT(DISTINCT c.id) FROM edges e JOIN claims c ON c.id = e.target_id \
              WHERE {pred} \
                AND ($3::bool OR e.visibility = 'public' \
                     OR (e.owner_group_id = ANY($4::uuid[]) \
                         AND (e.co_owner_group_id IS NULL \
                              OR e.co_owner_group_id = ANY($4::uuid[])))) \
                AND ($3::bool OR c.visibility = 'public' OR c.owner_group_id = ANY($4::uuid[]))",
            pred = Self::asserted_by_predicate(),
        );
        let count: i64 = sqlx::query_scalar(&sql)
            .bind(paper_id)
            .bind(ingested_by.to_string())
            .bind(viewer.bypass_bind())
            .bind(viewer.group_bind().unwrap_or(&[]))
            .fetch_one(executor)
            .await?;
        Ok(count)
    }

    /// One page of the claims ONE ingest principal's document ingest of the
    /// paper asserts ([`Self::count_asserted_claims_by`]'s set, oldest
    /// first), each with whether THAT ingest created it: its own
    /// ingest-written, in-force `ingested_claim` record says so and names the
    /// claim's filer (the rule `crate::ClaimIngestRepository::for_claims`
    /// reads the creator by). Another principal's ingest of the same document
    /// is never on this page.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails, and
    /// `DbError::InvalidData` for a stored hash that is not 32 bytes.
    #[instrument(skip(executor, viewer))]
    pub async fn list_asserted_claims_by<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        paper_id: Uuid,
        ingested_by: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<IngestAssertedClaimRow>, DbError> {
        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            content: String,
            truth_value: f64,
            agent_id: Uuid,
            content_hash: Vec<u8>,
            created_at: chrono::DateTime<chrono::Utc>,
            is_current: bool,
            supersedes: Option<Uuid>,
            created_claim: bool,
        }
        let sql = format!(
            "SELECT DISTINCT c.id, c.content, c.truth_value, c.agent_id, c.content_hash, \
                    c.created_at, COALESCE(c.is_current, true) AS is_current, c.supersedes, \
                    EXISTS (SELECT 1 FROM edges r \
                             WHERE r.source_id = $1 AND r.source_type = 'paper' \
                               AND r.target_id = c.id AND r.target_type = 'claim' \
                               AND r.relationship = '{rel}' \
                               AND {in_force_r} AND {marked_r} AND {by_r} = $2::text \
                               AND r.properties ->> '{rec_by}' = $2::text \
                               AND COALESCE(r.properties ->> '{created}' = 'true', false) \
                               AND c.agent_id::text = $2::text \
                               AND ($3::bool OR r.visibility = 'public' \
                                    OR (r.owner_group_id = ANY($4::uuid[]) \
                                        AND (r.co_owner_group_id IS NULL \
                                             OR r.co_owner_group_id = ANY($4::uuid[]))))) \
                        AS created_claim \
               FROM edges e JOIN claims c ON c.id = e.target_id \
              WHERE {pred} \
                AND ($3::bool OR e.visibility = 'public' \
                     OR (e.owner_group_id = ANY($4::uuid[]) \
                         AND (e.co_owner_group_id IS NULL \
                              OR e.co_owner_group_id = ANY($4::uuid[])))) \
                AND ($3::bool OR c.visibility = 'public' OR c.owner_group_id = ANY($4::uuid[])) \
              ORDER BY c.created_at ASC, c.id \
              LIMIT $5 OFFSET $6",
            rel = crate::INGEST_RECORD_RELATIONSHIP,
            rec_by = crate::INGESTED_BY_PROPERTY,
            created = crate::CREATED_CLAIM_PROPERTY,
            in_force_r = crate::repos::edge::EDGE_IN_FORCE.replace("e.", "r."),
            marked_r = crate::repos::ingest_written::ingest_written_edge_sql("r"),
            by_r = crate::repos::ingest_written::ingest_written_by_sql("r"),
            pred = Self::asserted_by_predicate(),
        );
        let rows: Vec<Row> = sqlx::query_as(&sql)
            .bind(paper_id) // $1
            .bind(ingested_by.to_string()) // $2
            .bind(viewer.bypass_bind()) // $3
            .bind(viewer.group_bind().unwrap_or(&[])) // $4
            .bind(limit) // $5
            .bind(offset) // $6
            .fetch_all(executor)
            .await?;
        rows.into_iter()
            .map(|r| {
                let content_hash: [u8; 32] =
                    r.content_hash
                        .as_slice()
                        .try_into()
                        .map_err(|_| DbError::InvalidData {
                            reason: format!(
                                "claim {} has content_hash of length {} (expected 32)",
                                r.id,
                                r.content_hash.len()
                            ),
                        })?;
                Ok(IngestAssertedClaimRow {
                    claim: AssertedClaimRow {
                        id: r.id,
                        content: r.content,
                        truth_value: r.truth_value,
                        agent_id: r.agent_id,
                        content_hash,
                        created_at: r.created_at,
                        is_current: r.is_current,
                        supersedes: r.supersedes,
                    },
                    created_claim: r.created_claim,
                })
            })
            .collect()
    }

    /// The in-force `authored` edges into `paper_id` that `viewer` may read,
    /// one per (agent, edge), by `position` then age: who a document ingest
    /// finds already attached when it attaches its own authors (backlog
    /// 94cc12db). Runs on the ingest's own author-stamped connection, so row
    /// security answers as well as the spliced predicate.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the read fails.
    pub async fn author_edges_conn(
        conn: &mut sqlx::PgConnection,
        viewer: &crate::visibility::Viewer,
        paper_id: Uuid,
    ) -> Result<Vec<PaperAuthorEdge>, DbError> {
        let sql = viewer.splice(
            &format!(
                "SELECT e.id, e.source_id, \
                        CASE WHEN e.properties ->> 'position' ~ '^[0-9]{{1,9}}$' \
                             THEN (e.properties ->> 'position')::bigint END, \
                        COALESCE(e.properties ->> '{explicit}' = 'true', false), \
                        e.properties ->> '{name}', \
                        {pending}, \
                        CASE WHEN {pending} THEN e.properties ->> '{ingested_by}' END, \
                        {written_by} \
                   FROM edges e \
                  WHERE e.target_id = $1 AND e.target_type = 'paper' \
                    AND e.source_type = 'agent' AND e.relationship = 'authored' \
                    AND {in_force} \
                    /* {{EDGE_VISIBILITY:e}} */ \
                  ORDER BY 3 NULLS LAST, e.created_at, e.id",
                explicit = AUTHORED_EXPLICIT_KEY,
                name = AUTHORED_NAME_KEY,
                pending = crate::agent_lookup::authorship_pending_sql("e"),
                ingested_by = AUTHORED_INGESTED_BY_KEY,
                written_by = crate::repos::ingest_written::ingest_written_by_sql("e"),
                in_force = crate::repos::edge::EDGE_IN_FORCE,
            ),
            2,
        );
        type Row = (
            Uuid,
            Uuid,
            Option<i64>,
            bool,
            Option<String>,
            bool,
            Option<String>,
            Option<String>,
        );
        let mut q = sqlx::query_as::<_, Row>(&sql).bind(paper_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(&mut *conn)
            .await?
            .into_iter()
            .map(
                |(edge_id, agent_id, position, explicit, author_name, pending, by, written)| {
                    PaperAuthorEdge {
                        edge_id,
                        agent_id,
                        position,
                        explicit,
                        author_name,
                        pending,
                        ingested_by: by.and_then(|s| s.parse().ok()),
                        written_by: written.and_then(|s| s.parse().ok()),
                    }
                },
            )
            .collect())
    }

    /// The authors an OPERATOR REPLACEMENT removed from `paper_id`: agents
    /// with a retracted `authored` edge into the paper (retracted after it
    /// was written, never born retracted) whose removal the replacement
    /// itself recorded. The replacing author's own in-force, ingest-written
    /// `authored` edge into the paper names the removed agent
    /// ([`AUTHORED_REPLACES_KEY`]), which only the maintenance replacement
    /// writes. A retraction nothing recorded, or one matched only by position
    /// or spelling, is no replacement and is not listed. The document walk's
    /// name path never credits a listed agent again.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the read fails.
    pub async fn retracted_author_ids_conn(
        conn: &mut sqlx::PgConnection,
        viewer: &crate::visibility::Viewer,
        paper_id: Uuid,
    ) -> Result<Vec<Uuid>, DbError> {
        let sql = viewer.splice(
            &format!(
                "SELECT DISTINCT e.source_id \
                   FROM edges e \
                  WHERE e.target_id = $1 AND e.target_type = 'paper' \
                    AND e.source_type = 'agent' AND e.relationship = 'authored' \
                    AND NOT {in_force} AND e.valid_to > e.created_at \
                    AND EXISTS (SELECT 1 FROM edges rp \
                                 WHERE rp.target_id = $1 AND rp.target_type = 'paper' \
                                   AND rp.source_type = 'agent' \
                                   AND rp.relationship = 'authored' \
                                   AND {in_force_rp} AND {marked_rp} \
                                   AND rp.properties ->> '{replaces}' = e.source_id::text \
                                   /* {{EDGE_VISIBILITY:rp}} */) \
                    /* {{EDGE_VISIBILITY:e}} */",
                in_force = crate::repos::edge::EDGE_IN_FORCE,
                in_force_rp = crate::repos::edge::EDGE_IN_FORCE.replace("e.", "rp."),
                marked_rp = crate::repos::ingest_written::ingest_written_edge_sql("rp"),
                replaces = AUTHORED_REPLACES_KEY,
            ),
            2,
        );
        let mut q = sqlx::query_scalar::<_, Uuid>(&sql).bind(paper_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(&mut *conn).await?)
    }

    /// Take `agent_id` off `paper_id` as an author: retract its in-force
    /// `authored` edge into the paper and its in-force `asserts` edges onto
    /// the claims THIS paper asserts, except a claim that another paper the
    /// agent still authors also asserts (that attribution is not this
    /// paper's to remove). Retraction, not deletion: the rows survive with
    /// `valid_to` closed, and the document walk's
    /// `create_if_absent_including_retracted` writes never revive them.
    ///
    /// What a document ingest does when an explicit `agent_id` replaces the
    /// name-derived node an earlier ingest of the same document attached
    /// (backlog 94cc12db). Agent-to-claim and agent-to-paper edges carry no
    /// factor and no BBA (`edges_auto_factor` and the DS auto-wire both
    /// require claim endpoints), so nothing derived is left behind.
    ///
    /// Returns `(authored, asserts)` retracted.
    ///
    /// # Errors
    /// `DbError::WriteRefused` (run it in a transaction and roll back: some
    /// edges may have closed) when an edge this session can read was not
    /// closed: the spliced writable predicate, and 117's owner-scoped UPDATE
    /// under it, skip a row the session may not write without an error, so
    /// the count tells. An agent's edges are `('public', world)` (migration
    /// 120), so on an application session that is the answer; a privileged
    /// (bypass) session retracts them.
    /// `DbError::QueryFailed` if the statement fails.
    pub async fn retract_author_conn(
        conn: &mut sqlx::PgConnection,
        viewer: &crate::visibility::Viewer,
        paper_id: Uuid,
        agent_id: Uuid,
    ) -> Result<(u64, u64), DbError> {
        let in_force =
            |alias: &str| crate::repos::edge::EDGE_IN_FORCE.replace("e.", &format!("{alias}."));
        // 1. What the session can SEE of this author on this paper (read
        //    predicate). The write below is gated separately: one statement
        //    cannot carry both marker spellings.
        let read = viewer.splice(
            &format!(
                "SELECT e.id FROM edges e \
                  WHERE e.source_id = $1 AND e.source_type = 'agent' \
                    AND e.target_id = $2 AND e.target_type = 'paper' \
                    AND e.relationship = 'authored' AND {e} \
                    /* {{EDGE_VISIBILITY:e}} */ \
                 UNION ALL \
                 SELECT a.id FROM edges a \
                  WHERE a.source_id = $1 AND a.source_type = 'agent' \
                    AND a.target_type = 'claim' AND a.relationship = 'asserts' AND {a} \
                    /* {{EDGE_VISIBILITY:a}} */ \
                    AND EXISTS (SELECT 1 FROM edges pc \
                                 WHERE pc.source_id = $2 AND pc.source_type = 'paper' \
                                   AND pc.relationship = 'asserts' \
                                   AND pc.target_id = a.target_id \
                                   AND pc.target_type = 'claim' AND {pc}) \
                    AND NOT EXISTS ( \
                        SELECT 1 FROM edges oa \
                          JOIN edges oc ON oc.source_id = oa.target_id \
                                       AND oc.source_type = 'paper' \
                                       AND oc.relationship = 'asserts' \
                                       AND oc.target_id = a.target_id \
                                       AND oc.target_type = 'claim' AND {oc} \
                         WHERE oa.source_id = $1 AND oa.source_type = 'agent' \
                           AND oa.relationship = 'authored' AND oa.target_type = 'paper' \
                           AND oa.target_id <> $2 AND {oa})",
                e = in_force("e"),
                a = in_force("a"),
                pc = in_force("pc"),
                oc = in_force("oc"),
                oa = in_force("oa"),
            ),
            3,
        );
        let mut q = sqlx::query_scalar::<_, Uuid>(&read)
            .bind(agent_id)
            .bind(paper_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let seen: Vec<Uuid> = q.fetch_all(&mut *conn).await?;
        if seen.is_empty() {
            return Ok((0, 0));
        }
        // 2. Retract them, gated by the session's WRITABLE set (and row
        //    security under it).
        let write = viewer.splice_write(
            "UPDATE edges AS e SET valid_to = now() \
              WHERE e.id = ANY($1::uuid[]) /* {WRITABLE:e} */ \
             RETURNING e.relationship",
            2,
        );
        let mut q = sqlx::query_scalar::<_, String>(&write).bind(&seen);
        if let Some(w) = viewer.writable_bind() {
            q = q.bind(w);
        }
        let done: Vec<String> = q.fetch_all(&mut *conn).await?;
        if done.len() < seen.len() {
            return Err(DbError::WriteRefused {
                entity: "edge".to_string(),
                id: agent_id,
                action: "retract this author's edges on the paper".to_string(),
            });
        }
        let authored = done.iter().filter(|r| r.as_str() == "authored").count();
        Ok((
            u64::try_from(authored).unwrap_or(0),
            u64::try_from(done.len() - authored).unwrap_or(0),
        ))
    }
}

/// Property on an `authored` edge a document ingest wrote for an explicit
/// `source.authors[].agent_id` (backlog 94cc12db): `true`. Name-derived
/// author edges never carry it.
pub const AUTHORED_EXPLICIT_KEY: &str = "explicit_agent_id";
/// Property on an explicit `authored` edge: the author's name as the
/// extraction spelled it, so a later name-only ingest of the same document
/// finds the explicit author instead of attaching the name-derived node too.
pub const AUTHORED_NAME_KEY: &str = "author_name";
/// Property on an explicit `authored` edge naming an agent the ingester
/// neither is nor operates: `true` while the attribution is the ingester's
/// word alone, until the named person countersigns. Such an author gets no
/// `asserts` edge, and the agent card's `authored_papers` does not count it.
/// The same key the card reads
/// ([`crate::agent_lookup::AUTHORSHIP_PENDING_PROPERTY`]): one spelling.
pub const AUTHORED_PENDING_KEY: &str = crate::agent_lookup::AUTHORSHIP_PENDING_PROPERTY;
/// Property on a pending explicit `authored` edge: the agent that ingested
/// the document, which is the one asserting the authorship
/// ([`crate::agent_lookup::AUTHORSHIP_INGESTED_BY_PROPERTY`]).
pub const AUTHORED_INGESTED_BY_KEY: &str = crate::agent_lookup::AUTHORSHIP_INGESTED_BY_PROPERTY;
/// Property on the REPLACING author's `authored` edge, written by the operator
/// replacement only: the name-derived agent whose authorship of the paper
/// that ingest retracted and this author replaces, as a UUID string. The
/// walk writes it only when its retraction actually retracted an `authored`
/// edge, which only a maintenance connection can do (an application session
/// is refused before anything is written), and it is a reserved edge key
/// ([`crate::RESERVED_EDGE_PROPERTIES`]), so no generic writer sets it. It is
/// the one signal [`PaperRepository::retracted_author_ids_conn`] reads.
pub const AUTHORED_REPLACES_KEY: &str = "replaces_author";

/// The refusal for an application edge write whose `properties` carry
/// [`AUTHORED_REPLACES_KEY`].
pub const AUTHORED_REPLACES_KEY_RESERVED: &str =
    "properties.replaces_author is reserved for the operator's author replacement \
     (the document ingest on the maintenance connection); nothing was written";

/// One in-force `authored` edge into a paper
/// ([`PaperRepository::author_edges_conn`]).
#[derive(Debug, Clone)]
pub struct PaperAuthorEdge {
    pub edge_id: Uuid,
    pub agent_id: Uuid,
    /// `properties.position`, when it is a non-negative integer.
    pub position: Option<i64>,
    /// Written for an explicit `agent_id` ([`AUTHORED_EXPLICIT_KEY`]).
    pub explicit: bool,
    /// The extraction's spelling, on an explicit edge ([`AUTHORED_NAME_KEY`]).
    pub author_name: Option<String>,
    /// The authorship awaits the person's countersignature
    /// ([`AUTHORED_PENDING_KEY`]).
    pub pending: bool,
    /// On a pending edge, the ingester that asserted the authorship
    /// ([`AUTHORED_INGESTED_BY_KEY`]).
    pub ingested_by: Option<Uuid>,
    /// The principal whose document ingest wrote the edge, from its
    /// ingest-written marker (`crate::ingest_written_by_sql`); `None` for an
    /// edge the walk did not mark (written before the marker existed).
    pub written_by: Option<Uuid>,
}

/// What [`PaperRepository::list_authors_bounded`] returns: per paper, its
/// listed authors (each with whether it was listed from a recorded row) and
/// whether more exist.
pub type BoundedAuthorListings =
    std::collections::HashMap<Uuid, (Vec<(PaperAuthorListing, bool)>, bool)>;

/// The columns [`PaperRepository::list_authors`] and
/// [`PaperRepository::list_authors_bounded`] read for one `authored` edge
/// `e` from agent `a`, in [`AuthorListingRow`] order. The author's name is
/// read through migration 309's `epigraph_human_named_to_viewer` on the
/// stamped session: an unnamed human author is listed under the
/// `oauth:<client row id>` placeholder a nameless service principal carries
/// (migration 322, operator ruling C7); its position, role and affiliations are the
/// ingester's edge data and shown as for any author.
fn author_listing_columns() -> String {
    format!(
        "a.id, CASE WHEN public.epigraph_human_named_to_viewer(a.id) THEN a.display_name \
                    ELSE public.epigraph_unnamed_agent_name(a.id) END, \
         CASE WHEN e.properties ->> 'position' ~ '^[0-9]{{1,9}}$' \
              THEN (e.properties ->> 'position')::bigint END, \
         COALESCE(e.properties ->> 'role', 'author'), \
         CASE WHEN jsonb_typeof(e.properties -> 'affiliations') = 'array' \
              THEN e.properties -> 'affiliations' ELSE '[]'::jsonb END, \
         {pending}, \
         CASE WHEN {pending} THEN e.properties ->> '{ingested_by}' END, \
         {written_by}",
        pending = crate::agent_lookup::authorship_pending_sql("e"),
        ingested_by = AUTHORED_INGESTED_BY_KEY,
        written_by = crate::repos::ingest_written::ingest_written_by_sql("e"),
    )
}

/// The predicate both author listings read edge `e` under: an in-force,
/// ingest-written (`crate::ingest_written_edge_sql`) `agent -authored->
/// paper` edge (each listing adds the viewer's edge visibility marker in its
/// own statement).
fn authored_in_force_readable() -> String {
    format!(
        "e.target_type = 'paper' AND e.source_type = 'agent' AND e.relationship = 'authored' \
         AND {in_force} AND {marked}",
        in_force = crate::repos::edge::EDGE_IN_FORCE,
        marked = crate::repos::ingest_written::ingest_written_edge_sql("e"),
    )
}

/// An authorship edge `e`'s extraction position, when it is a non-negative
/// integer.
const AUTHOR_LISTING_POSITION: &str = "CASE WHEN e.properties ->> 'position' ~ '^[0-9]{1,9}$' \
     THEN (e.properties ->> 'position')::bigint END";

/// The listing order: the extraction's position (missing last), then age.
const AUTHOR_LISTING_ORDER: &str = "CASE WHEN e.properties ->> 'position' ~ '^[0-9]{1,9}$' \
     THEN (e.properties ->> 'position')::bigint END NULLS LAST, e.created_at, e.id";

type AuthorListingRow = (
    Uuid,
    Option<String>,
    Option<i64>,
    String,
    serde_json::Value,
    bool,
    Option<String>,
    Option<String>,
);

fn author_listing(
    (agent_id, display_name, position, role, affiliations, pending, by, written): AuthorListingRow,
) -> PaperAuthorListing {
    PaperAuthorListing {
        agent_id,
        display_name,
        position,
        role,
        affiliations: affiliations
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default(),
        pending_countersign: pending,
        ingested_by: by.and_then(|s| s.parse().ok()),
        written_by: written.and_then(|s| s.parse().ok()),
    }
}

/// One author of a paper as [`PaperRepository::list_authors`] lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaperAuthorListing {
    pub agent_id: Uuid,
    pub display_name: Option<String>,
    /// `properties.position` (the extraction's index), when it is a
    /// non-negative integer.
    pub position: Option<i64>,
    /// `properties.role`, `"author"` when absent.
    pub role: String,
    /// `properties.affiliations` (strings only).
    pub affiliations: Vec<String>,
    /// The authorship is an ingester's word, awaiting the person's
    /// countersignature ([`AUTHORED_PENDING_KEY`]): show it as pending,
    /// never as a plain author.
    pub pending_countersign: bool,
    /// On a pending authorship, the ingester that asserted it
    /// ([`AUTHORED_INGESTED_BY_KEY`]); `None` otherwise.
    pub ingested_by: Option<Uuid>,
    /// The principal whose document ingest wrote this authorship (its
    /// ingest-written marker, `crate::ingest_written_by_sql`). Every listed
    /// author has one: only ingest-written authorships are listed. A reader
    /// that combines a paper's authors with one ingest's record of a claim
    /// (`crate::ClaimIngestRepository`) keeps the authors whose `written_by`
    /// is that record's ingester.
    pub written_by: Option<Uuid>,
}

/// Minimal claim shape returned by [`PaperRepository::list_asserted_claims`].
#[derive(Debug, Clone)]
pub struct AssertedClaimRow {
    pub id: Uuid,
    pub content: String,
    pub truth_value: f64,
    pub agent_id: Uuid,
    pub content_hash: [u8; 32],
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// The row's real retirement state (`COALESCE(is_current, true)`); the
    /// query does not filter on it.
    pub is_current: bool,
    /// The claim this one superseded, if any.
    pub supersedes: Option<Uuid>,
}

/// One ingest principal of a paper ([`PaperRepository::ingest_principals`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaperIngestPrincipal {
    /// The principal whose document ingest wrote the edges (the
    /// ingest-written marker's `by`).
    pub ingested_by: Uuid,
    /// Its oldest readable in-force ingest-written edge on the paper.
    pub first_written_at: chrono::DateTime<chrono::Utc>,
}

/// One claim of one ingest principal's listing of a paper
/// ([`PaperRepository::list_asserted_claims_by`]).
#[derive(Debug, Clone)]
pub struct IngestAssertedClaimRow {
    pub claim: AssertedClaimRow,
    /// THAT ingest created the claim (its own creation record, naming the
    /// claim's filer); `false`: it found the claim already there.
    pub created_claim: bool,
}

// =============================================================================
// THE PAPER DOCUMENT KEY (backlog 90756d26)
// =============================================================================
//
// `papers.doi` is the document identity key. Every writer and every reader of
// it, on every transport, goes through the functions below (the key, its
// spellings, and the lookup predicate over them): the MCP
// ingestion and paper-query tools (`epigraph-mcp` `tools/ingestion.rs`) and the
// REST paper routes (`epigraph-api` `routes/papers.rs`). Before they were
// shared, the REST routes stored and matched the caller's spelling verbatim, so
// `https://doi.org/10.x/y`, `doi:10.x/y` and `10.x/y` were three keys there and
// one key over MCP.
//
// Pure functions (the SQL ones only build a statement fragment; none touches
// the database): they live here because this module owns the column they key,
// and both transports already depend on this crate.
//
// Two forms of one key, built on one prefix list ([`DOI_KEY_PREFIXES`]) and one
// bare-DOI test ([`is_bare_doi`]):
//
// - [`canonical_document_key`], the STORED spelling. It keeps the caller's
//   case: existing `papers.doi` rows and their `doi:<key>` labels carry it, and
//   folding it would re-key them.
// - [`document_identity_key`], the case-folded IDENTITY, for deciding whether
//   two spellings name one document: the belief engine's same-source key
//   (`epigraph-engine` `source_dependence.rs`) and its edge-factor paper join
//   (`edge_factor::edge_source_is_intra`) compare with it (backlog e34fd66e).
//   Nothing stores it, so no row or label is re-keyed by it.

/// Resolver prefixes a caller may put in front of a DOI. Matched
/// case-insensitively; `doi:` also tolerates whitespace before the DOI.
pub const DOI_KEY_PREFIXES: [&str; 10] = [
    "https://doi.org/",
    "http://doi.org/",
    "https://dx.doi.org/",
    "http://dx.doi.org/",
    "https://www.doi.org/",
    "http://www.doi.org/",
    // Scheme-less resolver spellings: the key class this normalizer owns is
    // `^(https?://)?(dx\.|www\.)?doi\.org/`, with the scheme optional.
    "doi.org/",
    "dx.doi.org/",
    "www.doi.org/",
    "doi:",
];

/// True for a bare DOI: `10.` + a 4-9 digit registrant + `/` + a non-empty
/// suffix.
#[must_use]
pub fn is_bare_doi(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("10.") else {
        return false;
    };
    let Some((registrant, suffix)) = rest.split_once('/') else {
        return false;
    };
    (4..=9).contains(&registrant.len())
        && registrant.bytes().all(|b| b.is_ascii_digit())
        && !suffix.trim().is_empty()
}

/// The canonical spelling of a document identity key: trimmed, with a DOI
/// resolver prefix (`https://doi.org/`, `dx.doi.org`, `doi:`, ...) removed
/// when what follows is a bare DOI. Anything else is returned trimmed and
/// otherwise unchanged. This is the spelling every writer stores.
///
/// NOT lowercased: DOIs are case-insensitive, but existing rows and their
/// `doi:<key>` labels carry the caller's case, and folding it would re-key
/// them.
#[must_use]
pub fn canonical_document_key(raw: &str) -> String {
    let t = raw.trim();
    for prefix in DOI_KEY_PREFIXES {
        let Some(head) = t.get(..prefix.len()) else {
            continue;
        };
        if head.eq_ignore_ascii_case(prefix) {
            let rest = t[prefix.len()..].trim_start();
            if is_bare_doi(rest) {
                return rest.to_string();
            }
        }
    }
    t.to_string()
}

/// Every stored spelling a lookup for `raw` must match, most preferred first:
/// the [`canonical_document_key`], then the key as given (trimmed), then, for
/// a bare DOI, each [`DOI_KEY_PREFIXES`] spelling of it. Distinct, in that
/// order.
///
/// The legacy spellings are what make a row written under a resolver URL
/// before keys were canonicalized findable by the bare DOI. On their own
/// they are exact-match; a lookup reaches a row keyed on a case variant of a
/// prefix (`HTTPS://DOI.ORG/...`) only through [`document_key_rows_sql`]
/// (lookups) or [`document_key_match_sql`] (a per-row filter).
///
/// A key that is not a bare DOI yields exactly one spelling, itself; a bare
/// DOI yields more than one. [`document_key_rows_sql`] relies on that.
#[must_use]
pub fn document_key_spellings(raw: &str) -> Vec<String> {
    let canonical = canonical_document_key(raw);
    let as_given = raw.trim().to_string();
    let bare = is_bare_doi(&canonical);
    let mut out = vec![canonical.clone()];
    if as_given != canonical {
        out.push(as_given);
    }
    if bare {
        for prefix in DOI_KEY_PREFIXES {
            let legacy = format!("{prefix}{canonical}");
            if !out.contains(&legacy) {
                out.push(legacy);
            }
        }
    }
    out
}

/// Strip one [`DOI_KEY_PREFIXES`] entry (case-insensitively), if `t` starts
/// with one.
fn strip_document_key_prefix(t: &str) -> Option<&str> {
    DOI_KEY_PREFIXES.iter().find_map(|p| {
        t.get(..p.len())
            .filter(|head| head.eq_ignore_ascii_case(p))
            .map(|_| &t[p.len()..])
    })
}

/// A DOI resolver root with nothing behind it (`https://doi.org`,
/// `dx.doi.org/`, ...).
fn is_doi_resolver_root(t: &str) -> bool {
    let t = t.trim().trim_end_matches('/');
    DOI_KEY_PREFIXES
        .iter()
        .filter(|p| p.ends_with('/'))
        .any(|p| t.eq_ignore_ascii_case(p.trim_end_matches('/')))
}

/// What is behind the DOI prefixes of `t` ([`DOI_KEY_PREFIXES`]), all of them
/// peeled (`doi:https://doi.org/10.x` names `10.x`), trimmed; `""` for a
/// resolver root with nothing behind it. `None` when `t` carries no DOI
/// prefix. Unlike [`canonical_document_key`], this peels whatever follows the
/// prefix, not only a bare DOI: `doi:<uri>` (the label ingest builds for a
/// document identified by its URI) names that URI.
#[must_use]
pub fn peel_document_key_prefixes(t: &str) -> Option<&str> {
    let mut rest = match strip_document_key_prefix(t.trim()) {
        Some(r) => r,
        None if is_doi_resolver_root(t) => "",
        None => return None,
    };
    loop {
        rest = rest.trim();
        if is_doi_resolver_root(rest) {
            return Some("");
        }
        match strip_document_key_prefix(rest) {
            Some(r) => rest = r,
            None => return Some(rest),
        }
    }
}

/// The case-folded identity of a document key, for deciding whether two
/// spellings name ONE document (see the section comment): every
/// [`DOI_KEY_PREFIXES`] spelling peeled ([`peel_document_key_prefixes`]),
/// trimmed, trailing `/` removed, ASCII-lowercased (DOIs are
/// case-insensitive). `None` for a blank result, a placeholder
/// (`epigraph_core::domain::evidence::is_placeholder_id`: "unknown", "n/a",
/// ...; an identity built on one would merge every DOI-less document) or
/// anything that is still a URL once the prefixes are gone (a web page is not
/// a DOI). Percent-encoded DOIs are not decoded, so one DOI written both ways
/// stays two identities.
///
/// Every spelling [`canonical_document_key`] folds together has one identity
/// here, so two values the stored key treats as one document are never two
/// sources to the belief engine.
#[must_use]
pub fn document_identity_key(raw: &str) -> Option<String> {
    let t = raw.trim();
    let t = peel_document_key_prefixes(t)
        .unwrap_or(t)
        .trim()
        .trim_end_matches('/');
    if t.is_empty() || t.contains("://") || epigraph_core::domain::evidence::is_placeholder_id(t) {
        None
    } else {
        Some(t.to_ascii_lowercase())
    }
}

/// The case-variant arm shared by [`document_key_match_sql`] and
/// [`document_key_rows_sql`]: `column` equals one of the spellings bound at
/// `$bind` ignoring letter case AND ends in the canonical key (`$bind[1]`)
/// exactly, so only the resolver PREFIX is folded.
fn case_variant_arm_sql(column: &str, bind: usize) -> String {
    format!(
        "(lower({column}) = ANY(SELECT lower(s) FROM unnest(${bind}::text[]) AS s) \
         AND right({column}, char_length((${bind}::text[])[1])) = (${bind}::text[])[1])"
    )
}

/// The per-row SQL predicate for a `papers.doi` match: true when `column`
/// holds a stored spelling of the document key whose
/// [`document_key_spellings`] are bound at `$bind` (as `text[]`).
///
/// A row matches when its key is one of the spellings exactly, OR when it
/// equals one of them ignoring letter case AND ends in the canonical key
/// (`$bind[1]`) exactly. The second arm is what finds a legacy row keyed on a
/// case variant of a resolver prefix (`HTTPS://DOI.ORG/10.x/y`, `Doi:10.x/y`;
/// backlog f3a3ca54), which [`canonical_document_key`] already folds onto the
/// bare DOI but a byte-for-byte match missed, so a re-ingest twinned it. Only
/// the PREFIX is compared case-insensitively: the suffix is the canonical key
/// itself, so its case is kept (keys are not lowercased; see
/// [`canonical_document_key`]). For a key that is not a bare DOI the spellings
/// are just the key, and the second arm then admits nothing but that key.
///
/// **Only for a filter applied to rows already reached another way** (the
/// recall paper filter joins `papers` by primary key). No index serves the
/// second arm, so as the WHERE of a lookup over `papers` it makes even an
/// exact hit scan the whole table; a lookup uses [`document_key_rows_sql`].
///
/// `column` must be a trusted identifier (a static literal such as `doi` or
/// `p.doi`), never caller input.
#[must_use]
pub fn document_key_match_sql(column: &str, bind: usize) -> String {
    format!(
        "({column} = ANY(${bind}::text[]) OR {variant})",
        variant = case_variant_arm_sql(column, bind),
    )
}

/// A `SELECT {columns} FROM papers` returning the rows a lookup for the
/// document key whose [`document_key_spellings`] are bound at `$bind` (as
/// `text[]`) finds: every row stored under one of the spellings EXACTLY; or,
/// only when there is none, every legacy row keyed on a case variant of a
/// resolver prefix (the arm [`document_key_match_sql`] describes; backlog
/// f3a3ca54).
///
/// The fallback is what keeps the lookup on the unique index. The exact set
/// is an index probe. The case-variant set, which no index serves, is gated
/// by an uncorrelated `NOT EXISTS` over the exact spellings (planned once, as
/// a one-time filter), so on a hit its scan of `papers` never runs; it also
/// never runs for a key that is not a bare DOI, whose spellings are the key
/// alone (`cardinality = 1`) and which therefore has no prefix to fold. Only
/// a miss on a bare DOI (a new paper's first ingest) scans `papers`; an
/// expression index on `lower(doi)` would serve that too.
///
/// Wrap it as a derived table and rank by
/// `array_position($bind::text[], doi)` (canonical first; a case-variant row
/// ranks NULL, last), with `doi` as the tiebreak: see
/// [`document_key_first_sql`]. `columns` must be plain `papers` column names
/// written by the caller, never caller input, and must include `doi` to rank.
#[must_use]
pub fn document_key_rows_sql(columns: &str, bind: usize) -> String {
    document_key_rows_in_sql(columns, bind, "TRUE")
}

/// [`document_key_rows_sql`] restricted to the rows `scope` admits (migration
/// 246: a `papers` row carries the tenancy of the ingest that wrote it).
/// `scope` is applied to BOTH arms and to the exact-spelling gate, so a row
/// outside the scope neither matches nor suppresses the case-variant fallback
/// for a row inside it.
///
/// `scope` must be a trusted SQL predicate (a static literal, binds as
/// `$n` placeholders, never caller input) over UNQUALIFIED `papers` columns:
/// inside the gate's `papers k` an unqualified name resolves to `k`, in the
/// arms to their own `papers`.
#[must_use]
pub fn document_key_rows_in_sql(columns: &str, bind: usize, scope: &str) -> String {
    format!(
        "SELECT {columns} FROM papers WHERE doi = ANY(${bind}::text[]) AND ({scope}) \
         UNION ALL \
         SELECT {columns} FROM papers \
         WHERE cardinality(${bind}::text[]) > 1 \
           AND NOT EXISTS (SELECT 1 FROM papers k \
                            WHERE k.doi = ANY(${bind}::text[]) AND ({scope})) \
           AND {variant} AND ({scope})",
        variant = case_variant_arm_sql("doi", bind),
    )
}

/// The single best row of [`document_key_rows_sql`]: `SELECT {columns}`
/// (plain `papers` column names written by the caller, never caller input)
/// of the exact spelling earliest in the list, canonical first, else of a
/// case-variant row, ties broken by `doi`. Used by every `papers` lookup that
/// resolves a key to one paper.
#[must_use]
pub fn document_key_first_sql(columns: &str, bind: usize) -> String {
    document_key_first_in_sql(columns, bind, "TRUE")
}

/// [`document_key_first_sql`] over [`document_key_rows_in_sql`]: the single
/// best row of the document key among the rows `scope` admits (the same
/// trusted-literal rule for `scope`).
#[must_use]
pub fn document_key_first_in_sql(columns: &str, bind: usize, scope: &str) -> String {
    format!(
        "SELECT {columns} FROM ({rows}) AS m \
         ORDER BY array_position(${bind}::text[], m.doi), m.doi LIMIT 1",
        rows = document_key_rows_in_sql("*", bind, scope),
    )
}

#[cfg(test)]
mod document_key_tests {
    use super::*;

    const BARE: &str = "10.1021/acsnano.9b05650";

    /// `document_key_rows_sql` skips its case-variant scan when the
    /// spellings array has one element, on the strength of this: a key that
    /// is not a bare DOI has no resolver prefix to fold and yields one
    /// spelling, and a bare DOI, however it is spelled, yields more.
    #[test]
    fn only_a_bare_doi_has_more_than_one_spelling() {
        for raw in [
            BARE,
            "  10.1021/acsnano.9b05650 ",
            "HTTPS://DOI.ORG/10.1021/acsnano.9b05650",
            "doi: 10.1021/acsnano.9b05650",
        ] {
            assert!(document_key_spellings(raw).len() > 1, "{raw:?}");
        }
        for raw in [
            "urn:epigraph:doc:abc",
            "  URN:EPIGRAPH:DOC:abc  ",
            "https://doi.org/not-a-doi",
            "DOI:not-a-doi",
            "arxiv:2401.00001",
        ] {
            assert_eq!(document_key_spellings(raw).len(), 1, "{raw:?}");
        }
    }

    #[test]
    fn every_resolver_spelling_canonicalizes_to_the_bare_doi() {
        for raw in [
            "https://doi.org/10.1021/acsnano.9b05650",
            "http://dx.doi.org/10.1021/acsnano.9b05650",
            "HTTPS://WWW.DOI.ORG/10.1021/acsnano.9b05650",
            "doi:10.1021/acsnano.9b05650",
            "doi: 10.1021/acsnano.9b05650",
            "  10.1021/acsnano.9b05650  ",
            // Scheme-less resolver spellings (the reconcile count's regex
            // makes the scheme optional, so the normalizer must too).
            "doi.org/10.1021/acsnano.9b05650",
            "dx.doi.org/10.1021/acsnano.9b05650",
            "WWW.DOI.ORG/10.1021/acsnano.9b05650",
        ] {
            assert_eq!(canonical_document_key(raw), BARE, "{raw:?}");
        }
    }

    #[test]
    fn non_doi_keys_are_kept_verbatim_but_trimmed() {
        for raw in [
            "https://doi.org/about",
            "https://doi.org/10.1021",
            "https://doi.org/10.12/short-registrant",
            "https://example.org/paper.pdf",
            "urn:epigraph:doc:some-title-abc",
        ] {
            assert_eq!(canonical_document_key(&format!(" {raw} ")), raw);
        }
    }

    #[test]
    fn spellings_put_the_canonical_key_first_and_cover_every_legacy_prefix() {
        let s = document_key_spellings("https://doi.org/10.1021/acsnano.9b05650");
        assert_eq!(s[0], BARE);
        for prefix in DOI_KEY_PREFIXES {
            let legacy = format!("{prefix}{BARE}");
            assert_eq!(
                s.iter().filter(|x| **x == legacy).count(),
                1,
                "{legacy} exactly once in {s:?}"
            );
        }
        assert_eq!(s.len(), 1 + DOI_KEY_PREFIXES.len(), "{s:?}");
        // Named, not only through the array: a lookup by the bare DOI must
        // reach a row an older writer stored scheme-less.
        for legacy in ["doi.org/", "dx.doi.org/", "www.doi.org/"] {
            assert!(s.contains(&format!("{legacy}{BARE}")), "{legacy} in {s:?}");
        }
    }

    #[test]
    fn a_case_variant_prefix_is_matched_as_given_too() {
        let raw = "HTTPS://DOI.ORG/10.1021/acsnano.9b05650";
        let s = document_key_spellings(raw);
        assert_eq!(s[0], BARE);
        assert_eq!(s[1], raw);
    }

    /// Backlog e34fd66e: one document, one identity, for every spelling the
    /// stored key folds together (the scheme-less resolver spellings
    /// included) and for case variants, which the stored key keeps apart.
    #[test]
    fn every_spelling_of_one_document_has_one_identity() {
        let spellings = [
            "10.1021/acsnano.9b05650",
            "10.1021/ACSNANO.9B05650",
            "https://doi.org/10.1021/acsnano.9b05650",
            "HTTPS://WWW.DOI.ORG/10.1021/acsnano.9b05650/",
            "http://dx.doi.org/10.1021/acsnano.9b05650",
            "doi:10.1021/acsnano.9b05650",
            " DOI: 10.1021/acsnano.9b05650 ",
            "doi.org/10.1021/acsnano.9b05650",
            "dx.doi.org/10.1021/acsnano.9b05650",
            "WWW.DOI.ORG/10.1021/acsnano.9b05650",
            "doi:https://doi.org/10.1021/acsnano.9b05650",
        ];
        for raw in spellings {
            assert_eq!(document_identity_key(raw).as_deref(), Some(BARE), "{raw:?}");
            // The identity is the stored key, case-folded.
            assert_eq!(
                document_identity_key(&canonical_document_key(raw)).as_deref(),
                Some(BARE),
                "{raw:?}"
            );
        }
        // A document identified by its URI: the `doi:<uri>` label names it.
        assert_eq!(
            document_identity_key("doi:urn:epigraph:doc:Some-Title"),
            document_identity_key("urn:epigraph:doc:some-title")
        );
        assert_ne!(
            document_identity_key("10.5555/a"),
            document_identity_key("10.5555/b")
        );
        for none in [
            "",
            "  ",
            "doi:",
            "https://doi.org",
            "doi.org/",
            "unknown",
            "doi:n/a",
            "https://example.org/articles/10.5555/x",
        ] {
            assert_eq!(document_identity_key(none), None, "{none:?}");
        }
    }

    #[test]
    fn a_non_doi_key_has_exactly_one_spelling() {
        assert_eq!(
            document_key_spellings("https://doi.org/about"),
            vec!["https://doi.org/about".to_string()]
        );
    }
}
