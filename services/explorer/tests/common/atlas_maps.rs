//! The Atlas map list (`data-atlas-maps`, schema v1) as a test helper.
//!
//! The page that renders the Atlas with nested levels (W10's `/atlas`, and
//! the fixture preview) carries the maps a viewer may pick in one attribute.
//! Its route tests pull the attribute out of the rendered HTML with
//! [`attr_value`] and check it with [`check_atlas_maps_attr`]: the JSON Schema
//! at `contract/atlas_maps/v1/schema.json`, then the rules a schema cannot
//! express. Which maps a viewer may see (their teams' and the public one) is
//! the route test's to assert on the returned list.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use epigraph_explorer::atlas_maps::{is_level_url, AtlasMaps};
use epigraph_explorer::upstream::atlas_level::MapScope;
use serde_json::Value;

/// `contract/atlas_maps/v1/schema.json` of this crate.
pub const MAPS_SCHEMA: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/contract/atlas_maps/v1/schema.json"
);

pub fn maps_schema() -> &'static Value {
    static SCHEMA: OnceLock<Value> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        serde_json::from_str(&std::fs::read_to_string(MAPS_SCHEMA).unwrap())
            .expect("the map list schema is JSON")
    })
}

fn validator() -> &'static jsonschema::Validator {
    static V: OnceLock<jsonschema::Validator> = OnceLock::new();
    V.get_or_init(|| {
        jsonschema::meta::options()
            .validate(maps_schema())
            .unwrap_or_else(|e| panic!("the map list schema is not a valid 2020-12 schema: {e}"));
        jsonschema::validator_for(maps_schema()).expect("the map list schema compiles")
    })
}

/// Schema errors of a map list value, as `path: message` lines.
pub fn maps_schema_errors(v: &Value) -> Vec<String> {
    validator()
        .iter_errors(v)
        .map(|e| format!("{}: {e}", e.instance_path()))
        .collect()
}

/// Check a `data-atlas-maps` value (the attribute's text, unescaped): the
/// schema, then every rule it cannot express. Returns the decoded list.
pub fn check_atlas_maps_attr(raw: &str) -> Result<AtlasMaps, Vec<String>> {
    let v: Value = serde_json::from_str(raw).map_err(|e| vec![format!("not JSON: {e}")])?;
    let mut errs = maps_schema_errors(&v);
    if !errs.is_empty() {
        return Err(errs);
    }
    let maps: AtlasMaps =
        serde_json::from_value(v).map_err(|e| vec![format!("does not decode: {e}")])?;
    let mut keys = BTreeSet::new();
    let mut groups = BTreeSet::new();
    let mut urls = BTreeSet::new();
    let mut public = 0;
    for (i, m) in maps.maps.iter().enumerate() {
        let p = format!("/maps/{i}");
        if !keys.insert(m.key.as_str()) {
            errs.push(format!("{p}/key: {} is not unique", m.key));
        }
        match (m.scope, m.group_id) {
            (MapScope::Public, None) => public += 1,
            (MapScope::Team, Some(g)) => {
                if !groups.insert(g) {
                    errs.push(format!("{p}/group_id: two maps for team {g}"));
                }
            }
            _ => errs.push(format!(
                "{p}/group_id: a team map names its group, the public map none"
            )),
        }
        if !is_level_url(&m.level_url) {
            errs.push(format!(
                "{p}/level_url: {} is not a local prefix",
                m.level_url
            ));
        }
        // Two maps under one URL could not be told apart by the request.
        if !urls.insert(m.level_url.as_str()) {
            errs.push(format!(
                "{p}/level_url: {} is shared with another map",
                m.level_url
            ));
        }
        let mut themes = BTreeSet::new();
        let mut roots = BTreeSet::new();
        for (j, t) in m.themes.iter().enumerate() {
            let tp = format!("{p}/themes/{j}");
            if !themes.insert(t.theme_id) {
                errs.push(format!("{tp}/theme_id: {} is listed twice", t.theme_id));
            }
            if t.roots.meaning == t.roots.links {
                errs.push(format!("{tp}/roots: one level for both hierarchies"));
            }
            for r in [t.roots.meaning, t.roots.links] {
                if !roots.insert(r) {
                    errs.push(format!("{tp}/roots: {r} is the root of another theme"));
                }
            }
        }
    }
    if public > 1 {
        errs.push("/maps: more than one public map".into());
    }
    if errs.is_empty() {
        Ok(maps)
    } else {
        Err(errs)
    }
}

/// The unescaped value of the first `name="…"` attribute in `html`, or
/// `None`. Undoes the escapes askama writes into an attribute.
pub fn attr_value(html: &str, name: &str) -> Option<String> {
    let start = html.find(&format!("{name}=\""))? + name.len() + 2;
    let end = start + html[start..].find('"')?;
    Some(
        html[start..end]
            .replace("&quot;", "\"")
            .replace("&#34;", "\"")
            .replace("&#x27;", "'")
            .replace("&#39;", "'")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&"),
    )
}
