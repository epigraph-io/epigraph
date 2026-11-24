//! The theme ids a `rebuild_theme_neighborhoods` run covers (backlog
//! 30633061), read from a `scripts/theme_cap_split.py` manifest and
//! `--theme-id` flags. No database: the binary does the rest.

use std::collections::BTreeSet;

use uuid::Uuid;

/// The manifest format `scripts/theme_cap_split.py` writes (`MANIFEST_FORMAT`).
pub const SPLIT_MANIFEST_FORMAT: &str = "theme-cap-manifest/1";

/// Every theme a theme-cap split manifest touched: its `touched_theme_ids`,
/// and every split parent (`themes[].parent_id`) and new part
/// (`themes[].new_parts[].theme_id`), so a manifest written before
/// `touched_theme_ids` existed gives the same set. Sorted, no duplicates.
///
/// # Errors
/// A manifest of another format, an id that is not a UUID, or a manifest that
/// names no theme.
pub fn theme_ids_from_manifest(doc: &serde_json::Value) -> Result<Vec<Uuid>, String> {
    let format = doc.get("format").and_then(serde_json::Value::as_str);
    if format != Some(SPLIT_MANIFEST_FORMAT) {
        return Err(format!(
            "not a {SPLIT_MANIFEST_FORMAT} manifest (format {format:?})"
        ));
    }
    let mut raw: Vec<&serde_json::Value> = Vec::new();
    if let Some(ids) = doc.get("touched_theme_ids").and_then(|v| v.as_array()) {
        raw.extend(ids);
    }
    for theme in doc
        .get("themes")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
    {
        raw.extend(theme.get("parent_id"));
        for part in theme
            .get("new_parts")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
        {
            raw.extend(part.get("theme_id"));
        }
    }
    let mut out = BTreeSet::new();
    for v in raw {
        let id = v
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or_else(|| format!("the manifest names a theme id that is not a UUID: {v}"))?;
        out.insert(id);
    }
    if out.is_empty() {
        return Err("the manifest names no theme (an apply that split nothing)".into());
    }
    Ok(out.into_iter().collect())
}

/// `manifest` ids and `extra` ids together, sorted and deduplicated.
#[must_use]
pub fn merge_theme_ids(manifest: &[Uuid], extra: &[Uuid]) -> Vec<Uuid> {
    manifest
        .iter()
        .chain(extra)
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const P: &str = "11111111-0000-4000-8000-000000000000";
    const A: &str = "22222222-0000-4000-8000-000000000000";
    const B: &str = "33333333-0000-4000-8000-000000000000";

    fn ids(v: &[&str]) -> Vec<Uuid> {
        let mut out: Vec<Uuid> = v.iter().map(|s| Uuid::parse_str(s).unwrap()).collect();
        out.sort();
        out
    }

    #[test]
    fn a_manifest_gives_every_parent_and_part() {
        let doc = json!({"format": SPLIT_MANIFEST_FORMAT, "themes": [
            {"parent_id": P, "kept_claim_ids": [], "new_parts": [
                {"theme_id": A, "claim_ids": []}, {"theme_id": B, "claim_ids": []}]}]});
        assert_eq!(theme_ids_from_manifest(&doc).unwrap(), ids(&[P, A, B]));
    }

    #[test]
    fn touched_theme_ids_are_read_and_merged_with_the_themes() {
        let doc = json!({"format": SPLIT_MANIFEST_FORMAT, "touched_theme_ids": [P, A],
                         "themes": [{"parent_id": P, "new_parts": [{"theme_id": B}]}]});
        assert_eq!(theme_ids_from_manifest(&doc).unwrap(), ids(&[P, A, B]));
    }

    #[test]
    fn another_format_an_empty_manifest_and_a_bad_id_are_refused() {
        assert!(theme_ids_from_manifest(&json!({"format": "theme-cap-result/1"})).is_err());
        assert!(theme_ids_from_manifest(&json!({"themes": [{"parent_id": P}]})).is_err());
        assert!(
            theme_ids_from_manifest(&json!({"format": SPLIT_MANIFEST_FORMAT, "themes": []}))
                .is_err()
        );
        assert!(theme_ids_from_manifest(
            &json!({"format": SPLIT_MANIFEST_FORMAT, "themes": [{"parent_id": "nope"}]})
        )
        .is_err());
    }

    #[test]
    fn merged_ids_are_sorted_and_unique() {
        let m = ids(&[P, A]);
        let e = ids(&[A, B]);
        assert_eq!(merge_theme_ids(&m, &e), ids(&[P, A, B]));
    }
}
