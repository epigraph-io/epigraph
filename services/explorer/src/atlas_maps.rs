//! The Atlas map list (`data-atlas-maps`, schema v1, backlog W11).
//! OWNED BY THE ATLAS AREA.
//!
//! The level contract (`contract/atlas_level/v1`) says what one level is. It
//! does not say which maps a viewer may pick, which level is a theme's root on
//! each map, or where a level is fetched from. The Atlas page carries that in
//! one attribute, `data-atlas-maps`, whose JSON Schema is
//! `contract/atlas_maps/v1/schema.json` in this crate. The page that renders
//! the Atlas (W10 for the real `/atlas`, [`crate::atlas_preview`] for the
//! fixture preview) builds an [`AtlasMaps`] and renders [`AtlasMaps::to_attr`].
//!
//! **Addressing.** A level is stored per (map, hierarchy, group id) (W2's
//! `atlas_map_levels` key, after finding the map's run), and a group id need
//! not be unique across maps or hierarchies. So every level request names all
//! three: the client fetches
//!
//! ```text
//! <map.level_url><hierarchy>/<level id>
//! ```
//!
//! where `level_url` is the map's own same-origin prefix (ending in `/`) and
//! `hierarchy` is `meaning` or `links` ([`level_path`]). The route answers with
//! a v1 level document of that map and hierarchy, or the contract's not-found
//! body. The client knows the hierarchy of every level it asks for: a theme
//! root's comes from the map entry, a switch names its own, and a child, a
//! breadcrumb ancestor and a link target are in the hierarchy of the level
//! that lists them.
//!
//! W10's route tests check the attribute their page renders with the helper
//! in `tests/common/atlas_maps.rs` (`check_atlas_maps_attr`), as they check
//! level bodies with `check_level_body`.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::upstream::atlas_level::{Hierarchy, MapScope};

/// The `schema_version` of a v1 map list.
pub const ATLAS_MAPS_SCHEMA_VERSION: u32 = 1;

/// The maps a viewer may pick, first the default.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtlasMaps {
    pub schema_version: u32,
    pub maps: Vec<AtlasMap>,
}

/// One map: a team's (served to its members) or the public one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtlasMap {
    /// The picker's value; unique in the list.
    pub key: String,
    pub scope: MapScope,
    /// The team group for a team map; null for the public map.
    #[serde(deserialize_with = "Option::deserialize")]
    pub group_id: Option<Uuid>,
    /// What the picker shows.
    pub label: String,
    /// The same-origin prefix a level of this map is fetched under, ending in
    /// `/` (see [`level_path`]).
    pub level_url: String,
    /// The themes this map draws, each with its name, count and roots on
    /// this map.
    pub themes: Vec<AtlasMapTheme>,
}

/// A theme as one map draws it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtlasMapTheme {
    pub theme_id: Uuid,
    /// The theme's name on this map, generated only from text every viewer of
    /// the map can read; null until named.
    #[serde(deserialize_with = "Option::deserialize")]
    pub label: Option<String>,
    /// Claims this map draws in the theme, as stored.
    pub claim_count: u32,
    pub roots: Roots,
}

/// A theme's root level in each hierarchy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Roots {
    pub meaning: Uuid,
    pub links: Uuid,
}

impl AtlasMaps {
    /// The attribute value (JSON; askama escapes it into the attribute).
    pub fn to_attr(&self) -> String {
        serde_json::to_string(self).expect("the map list serialises")
    }
}

/// The path segment of a hierarchy in a level URL.
pub fn hierarchy_segment(h: Hierarchy) -> &'static str {
    match h {
        Hierarchy::Meaning => "meaning",
        Hierarchy::Links => "links",
    }
}

/// The hierarchy a level URL segment names, or `None`.
pub fn parse_hierarchy(segment: &str) -> Option<Hierarchy> {
    match segment {
        "meaning" => Some(Hierarchy::Meaning),
        "links" => Some(Hierarchy::Links),
        _ => None,
    }
}

/// The URL the client fetches one level from: `<level_url><hierarchy>/<id>`
/// (the same rule as `levelUrl` in `static/atlas_nested.js`).
pub fn level_path(level_url: &str, hierarchy: Hierarchy, level_id: Uuid) -> String {
    format!("{level_url}{}/{level_id}", hierarchy_segment(hierarchy))
}

/// Whether `v` is a usable `level_url`: a same-origin path that starts with
/// one `/`, ends with `/`, and has no query, fragment, backslash or space.
pub fn is_level_url(v: &str) -> bool {
    v.len() >= 2
        && v.starts_with('/')
        && !v.starts_with("//")
        && v.ends_with('/')
        && !v.contains(['?', '#', '\\'])
        && !v.chars().any(char::is_whitespace)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_level_url_is_a_local_prefix() {
        for ok in ["/a/", "/bff/atlas/maps/team/", "/explorer/bff/x/"] {
            assert!(is_level_url(ok), "{ok}");
        }
        for bad in [
            "",
            "/",
            "//evil/",
            "/a",
            "a/",
            "/a?b/",
            "/a#b/",
            "/a\\b/",
            "/a b/",
            "https://x/",
        ] {
            assert!(!is_level_url(bad), "{bad}");
        }
    }

    #[test]
    fn a_level_path_names_map_hierarchy_and_id() {
        let id = Uuid::from_u128(7);
        assert_eq!(
            level_path("/m/team/", Hierarchy::Links, id),
            format!("/m/team/links/{id}")
        );
        assert_eq!(parse_hierarchy("meaning"), Some(Hierarchy::Meaning));
        assert_eq!(parse_hierarchy("Meaning"), None);
    }
}
