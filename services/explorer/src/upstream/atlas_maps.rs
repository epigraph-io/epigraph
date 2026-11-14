//! Upstream DTOs and calls for the per-team Atlas maps (backlog W10).
//! OWNED BY THE ATLAS AREA.
//!
//! The kernel routes, each read with the viewer's own bearer:
//!
//! - `GET /api/v1/atlas/maps`: the maps the viewer's session can read, team
//!   maps first, then the public map;
//! - `GET /api/v1/atlas/maps/:map/themes`: each theme's name, claim count and
//!   root level per hierarchy on that map;
//! - `GET /api/v1/atlas/maps/:map/:hierarchy/levels/:id`: one level document
//!   (contract `atlas_level` v1), already filtered for the viewer, passed
//!   through as bytes ([`Api::atlas_level_raw`]);
//! - `GET /api/v1/atlas/maps/:map/:hierarchy/claims/:claim_id/leaf`: the leaf
//!   holding a claim (contract `atlas_claim_leaf` v1).
//!
//! `:map` is `public` or a team group's hyphenated id ([`KernelMap`]).
//!
//! Discipline (as `upstream/types.rs`): unknown fields are ignored and every
//! field is `pub`, except [`ClaimLeaf`], which mirrors a closed contract.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::atlas_level::{Hierarchy, MapScope};
use super::{Api, UpstreamError};
use crate::atlas_maps::hierarchy_segment;

/// The value of every v1 claim-to-leaf answer's `schema_version`.
pub const CLAIM_LEAF_SCHEMA_VERSION: u32 = 1;

/// A map as the kernel's routes name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KernelMap {
    Public,
    Team(Uuid),
}

impl KernelMap {
    /// The kernel's path segment: `public` or the group id.
    pub fn segment(self) -> String {
        match self {
            KernelMap::Public => "public".to_string(),
            KernelMap::Team(g) => g.to_string(),
        }
    }

    /// The map's `data-atlas-maps` key, which is also the BFF's path segment:
    /// `public` or `team-<32 hex>`.
    pub fn key(self) -> String {
        match self {
            KernelMap::Public => "public".to_string(),
            KernelMap::Team(g) => format!("team-{}", g.simple()),
        }
    }

    /// The map a BFF key names, or `None`. Exactly the spellings [`Self::key`]
    /// writes.
    pub fn from_key(key: &str) -> Option<Self> {
        if key == "public" {
            return Some(KernelMap::Public);
        }
        let hex = key.strip_prefix("team-")?;
        if hex.len() != 32
            || !hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return None;
        }
        Uuid::parse_str(hex).ok().map(KernelMap::Team)
    }

    pub fn scope(self) -> (MapScope, Option<Uuid>) {
        match self {
            KernelMap::Public => (MapScope::Public, None),
            KernelMap::Team(g) => (MapScope::Team, Some(g)),
        }
    }
}

/// One map the viewer can see.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct MapEntry {
    pub scope: MapScope,
    pub group_id: Option<Uuid>,
    /// The kernel path segment.
    pub map: String,
    pub label: String,
    pub run_id: Uuid,
}

impl MapEntry {
    /// The map this entry names, when its scope, group and segment agree.
    pub fn kernel_map(&self) -> Option<KernelMap> {
        let m = match (self.scope, self.group_id) {
            (MapScope::Public, None) => KernelMap::Public,
            (MapScope::Team, Some(g)) => KernelMap::Team(g),
            _ => return None,
        };
        (m.segment() == self.map).then_some(m)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct MapsResponse {
    #[serde(default)]
    pub maps: Vec<MapEntry>,
}

/// A theme's root level in each hierarchy.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ThemeRoots {
    pub meaning: Uuid,
    pub links: Uuid,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct MapTheme {
    pub theme_id: Uuid,
    pub label: Option<String>,
    pub claim_count: u32,
    pub roots: ThemeRoots,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct MapThemesResponse {
    pub scope: MapScope,
    pub group_id: Option<Uuid>,
    pub run_id: Uuid,
    #[serde(default)]
    pub themes: Vec<MapTheme>,
}

/// The claim-to-leaf answer (contract `atlas_claim_leaf` v1): closed, as the
/// kernel's `epigraph_atlas_contract::ClaimLeaf` is.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimLeaf {
    pub schema_version: u32,
    pub claim_id: Uuid,
    pub map_scope: MapScope,
    #[serde(deserialize_with = "Option::deserialize")]
    pub map_group_id: Option<Uuid>,
    pub hierarchy: Hierarchy,
    pub theme_id: Uuid,
    pub level_id: Uuid,
}

impl Api<'_> {
    /// `GET /api/v1/atlas/maps`.
    pub async fn atlas_maps(&self) -> Result<MapsResponse, UpstreamError> {
        self.get("/api/v1/atlas/maps").await
    }

    /// `GET /api/v1/atlas/maps/:map/themes`.
    pub async fn atlas_map_themes(
        &self,
        map: KernelMap,
    ) -> Result<MapThemesResponse, UpstreamError> {
        self.get(&format!("/api/v1/atlas/maps/{}/themes", map.segment()))
            .await
    }

    /// `GET /api/v1/atlas/maps/:map/:hierarchy/levels/:id`, as bytes.
    pub async fn atlas_level_raw(
        &self,
        map: KernelMap,
        hierarchy: Hierarchy,
        id: Uuid,
    ) -> Result<Vec<u8>, UpstreamError> {
        self.get_raw(&format!(
            "/api/v1/atlas/maps/{}/{}/levels/{id}",
            map.segment(),
            hierarchy_segment(hierarchy)
        ))
        .await
    }

    /// `GET /api/v1/atlas/maps/:map/:hierarchy/claims/:claim_id/leaf`.
    pub async fn atlas_claim_leaf(
        &self,
        map: KernelMap,
        hierarchy: Hierarchy,
        claim_id: Uuid,
    ) -> Result<ClaimLeaf, UpstreamError> {
        self.get(&format!(
            "/api/v1/atlas/maps/{}/{}/claims/{claim_id}/leaf",
            map.segment(),
            hierarchy_segment(hierarchy)
        ))
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_map_key_round_trips_and_nothing_else_parses() {
        let g = Uuid::from_u128(0xabc);
        for m in [KernelMap::Public, KernelMap::Team(g)] {
            assert_eq!(KernelMap::from_key(&m.key()), Some(m));
        }
        assert_eq!(KernelMap::Team(g).segment(), g.to_string());
        for bad in [
            "",
            "Public",
            "team-",
            &format!("team-{g}"),
            &format!("team-{}", g.simple().to_string().to_uppercase()),
            &g.simple().to_string(),
        ] {
            assert_eq!(KernelMap::from_key(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_map_entry_names_a_map_only_when_it_agrees_with_itself() {
        let g = Uuid::from_u128(7);
        let e = |scope, group_id, map: &str| MapEntry {
            scope,
            group_id,
            map: map.into(),
            label: "x".into(),
            run_id: Uuid::nil(),
        };
        assert_eq!(
            e(MapScope::Team, Some(g), &g.to_string()).kernel_map(),
            Some(KernelMap::Team(g))
        );
        assert_eq!(
            e(MapScope::Public, None, "public").kernel_map(),
            Some(KernelMap::Public)
        );
        assert_eq!(e(MapScope::Team, None, "public").kernel_map(), None);
        assert_eq!(e(MapScope::Public, Some(g), "public").kernel_map(), None);
        assert_eq!(e(MapScope::Team, Some(g), "public").kernel_map(), None);
    }
}
