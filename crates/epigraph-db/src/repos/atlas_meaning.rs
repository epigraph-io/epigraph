//! The scoped reads of the Atlas "by meaning" hierarchy (Atlas W4, backlog
//! f9fc052c): which themes a map draws, each theme's members with their
//! embeddings, the claim labels a skeleton leaf carries, and, from a stored
//! run, which leaf group holds each claim.
//!
//! The clustering itself is off the box (`scripts/atlas_meaning_core.py`) and
//! the build is `epigraph-cli`'s `atlas_meaning`; every statement it runs on
//! claims lives here or in [`crate::repos::atlas_leaf`].
//!
//! # Scope
//!
//! Each statement takes the build's connection (the transaction
//! [`crate::AtlasMapRepository::begin_build_snapshot`] opened), a viewer and the
//! map, is spliced on the viewer, and carries the MAP predicate W3 uses
//! ([`crate::repos::atlas_leaf`]): `visibility = 'public' OR (visibility =
//! 'group' AND owner_group_id = T)`, with T bound NULL on the public map. The
//! nightly runs on the maintenance connection with a bypass viewer, where the
//! splice renders nothing and row security filters nothing, so the map
//! predicate is what keeps another team's claims off a team map.
//!
//! # Members
//!
//! A theme's members on a map are its claims the map may draw that are current
//! (`COALESCE(is_current, true)`, what the Atlas draws and what W1's cap
//! counts). Only members with an embedding can be clustered; the others are
//! counted ([`ThemeMembers::unembedded`]) and left out of the tree.

use std::collections::BTreeMap;

use sqlx::PgConnection;
use uuid::Uuid;

use crate::errors::DbError;
use crate::repos::atlas_map::{AtlasHierarchy, AtlasMap};
use crate::visibility::Viewer;

/// One theme's current members on one map.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ThemeMembers {
    /// Members with an embedding, sorted by claim id, each with its
    /// embedding in pgvector's text form (`[v,v,...]`).
    pub embedded: Vec<(Uuid, String)>,
    /// Current members the map draws that have no embedding: not clustered.
    pub unembedded: usize,
}

/// The "by meaning" reads. See the module documentation.
pub struct AtlasMeaningRepository;

/// The team a map's predicate binds: `None` for the public map.
const fn map_team(map: AtlasMap) -> Option<Uuid> {
    match map {
        AtlasMap::Public => None,
        AtlasMap::Team(t) => Some(t),
    }
}

/// The contract's schema version whose leaf shape [`AtlasMeaningRepository::leaf_membership`] reads.
const LEAF_SCHEMA_VERSION: i32 = 1;

impl AtlasMeaningRepository {
    /// Every theme with at least one current claim `map` may draw, sorted.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the statement fails.
    pub async fn theme_ids_on_map(
        conn: &mut PgConnection,
        viewer: &Viewer,
        map: AtlasMap,
    ) -> Result<Vec<Uuid>, DbError> {
        let sql = viewer.splice(
            "SELECT DISTINCT c.theme_id \
               FROM claims c \
              WHERE c.theme_id IS NOT NULL \
                AND COALESCE(c.is_current, true) \
                AND (c.visibility = 'public' \
                     OR ($1::uuid IS NOT NULL AND c.visibility = 'group' \
                         AND c.owner_group_id = $1)) \
                /* {VISIBILITY:c} */ \
              ORDER BY 1",
            2,
        );
        let mut q = sqlx::query_scalar::<_, Uuid>(&sql).bind(map_team(map));
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(&mut *conn).await?)
    }

    /// The current members of `theme_id` that `map` may draw: the embedded
    /// ones with their embeddings, sorted by id, and how many have none.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the statement fails.
    pub async fn theme_members(
        conn: &mut PgConnection,
        viewer: &Viewer,
        map: AtlasMap,
        theme_id: Uuid,
    ) -> Result<ThemeMembers, DbError> {
        let sql = viewer.splice(
            "SELECT c.id, c.embedding::text \
               FROM claims c \
              WHERE c.theme_id = $1 \
                AND COALESCE(c.is_current, true) \
                AND (c.visibility = 'public' \
                     OR ($2::uuid IS NOT NULL AND c.visibility = 'group' \
                         AND c.owner_group_id = $2)) \
                /* {VISIBILITY:c} */ \
              ORDER BY c.id",
            3,
        );
        let mut q = sqlx::query_as::<_, (Uuid, Option<String>)>(&sql)
            .bind(theme_id)
            .bind(map_team(map));
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let mut out = ThemeMembers::default();
        for (id, embedding) in q.fetch_all(&mut *conn).await? {
            match embedding {
                Some(e) => out.embedded.push((id, e)),
                None => out.unembedded += 1,
            }
        }
        Ok(out)
    }

    /// The text of each claim of `claim_ids` that `map` may draw, for a leaf
    /// node's label. Ids the map may not draw are absent.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the statement fails.
    pub async fn claim_labels(
        conn: &mut PgConnection,
        viewer: &Viewer,
        map: AtlasMap,
        claim_ids: &[Uuid],
    ) -> Result<BTreeMap<Uuid, String>, DbError> {
        let sql = viewer.splice(
            "SELECT c.id, c.content \
               FROM claims c \
              WHERE c.id = ANY($1) \
                AND (c.visibility = 'public' \
                     OR ($2::uuid IS NOT NULL AND c.visibility = 'group' \
                         AND c.owner_group_id = $2)) \
                /* {VISIBILITY:c} */",
            3,
        );
        let mut q = sqlx::query_as::<_, (Uuid, String)>(&sql)
            .bind(claim_ids)
            .bind(map_team(map));
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(&mut *conn).await?.into_iter().collect())
    }

    /// Which leaf group of `hierarchy` holds each claim, in run `run_id` of
    /// `map`: the claim nodes of every stored leaf document (W10a schema v1,
    /// `kind = 'leaf'`, `nodes[].kind = 'claim'`). This is the membership the
    /// nightly's incremental assignment (W9) starts from; it needs no table
    /// of its own because every leaf document lists its claims.
    ///
    /// One statement, a primary-key prefix scan of the run's levels, spliced
    /// on the viewer.
    ///
    /// # Errors
    /// `DbError::InvalidData` if a claim is in two leaves of the run (a
    /// malformed run); `DbError::QueryFailed` if the statement fails.
    pub async fn leaf_membership(
        conn: &mut PgConnection,
        viewer: &Viewer,
        map: AtlasMap,
        run_id: Uuid,
        hierarchy: AtlasHierarchy,
    ) -> Result<BTreeMap<Uuid, Uuid>, DbError> {
        let (owner, visibility) = map.tenancy();
        let sql = viewer.splice(
            "SELECT (n.value->>'id')::uuid, l.group_id \
               FROM atlas_map_levels l \
               CROSS JOIN LATERAL jsonb_array_elements(l.payload->'nodes') n \
              WHERE l.run_id = $1 AND l.hierarchy = $2 \
                AND l.owner_group_id = $3 AND l.visibility = $4 \
                AND l.schema_version = $5 \
                AND l.payload->>'kind' = 'leaf' \
                AND n.value->>'kind' = 'claim' \
                /* {VISIBILITY:l} */",
            6,
        );
        let mut q = sqlx::query_as::<_, (Uuid, Uuid)>(&sql)
            .bind(run_id)
            .bind(hierarchy.as_str())
            .bind(owner)
            .bind(visibility)
            .bind(LEAF_SCHEMA_VERSION);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let mut out = BTreeMap::new();
        for (claim, leaf) in q.fetch_all(&mut *conn).await? {
            if let Some(other) = out.insert(claim, leaf) {
                if other != leaf {
                    return Err(DbError::InvalidData {
                        reason: format!(
                            "claim {claim} is in two leaf groups ({other}, {leaf}) of run {run_id}"
                        ),
                    });
                }
            }
        }
        Ok(out)
    }
}
