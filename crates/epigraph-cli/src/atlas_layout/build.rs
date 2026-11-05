//! Turn one snapshot of public layout inputs into a layout run (pure: no
//! database, no clock). The orchestration and the guards are in
//! `src/bin/atlas_layout.rs`; the arithmetic is in [`super::math`].

use std::collections::{BTreeMap, HashSet};

use anyhow::{bail, Context};
use epigraph_db::repos::atlas_layout::{
    LayoutBuild, LayoutLinkOut, LayoutRegionOut, LayoutThemeOut, PublicLayoutInputs,
    PublicThemeCentroid, ATLAS_LAYOUT_ALGO,
};
use serde_json::json;
use uuid::Uuid;

use super::math;

/// What the operator chose on the command line.
#[derive(Debug, Clone)]
pub struct BuildOptions {
    /// `--regions K`: override the automatic choice (clamped).
    pub regions: Option<usize>,
    /// `--min-public-members N`: themes with fewer EMBEDDED public members
    /// get no position. At least 1.
    pub min_public_members: i64,
}

impl Default for BuildOptions {
    fn default() -> Self {
        Self {
            regions: None,
            min_public_members: 1,
        }
    }
}

/// A run ready to write, and the operator's report of it.
#[derive(Debug, Clone)]
pub struct BuiltLayout {
    pub build: LayoutBuild,
    /// Params, counts, k and its scores, per-region summaries and link
    /// totals. Theme labels and public counts only, never claim text.
    pub report: serde_json::Value,
}

struct Placed<'a> {
    theme: &'a PublicThemeCentroid,
    unit: Vec<f64>,
}

/// Build a layout from `inputs`.
///
/// # Errors
/// A stored centroid that does not parse, or centroids of different
/// dimensions.
pub fn build_layout(
    inputs: &PublicLayoutInputs,
    opts: &BuildOptions,
) -> anyhow::Result<BuiltLayout> {
    let min_members = opts.min_public_members.max(1);
    let mut themes: Vec<&PublicThemeCentroid> = inputs.themes.iter().collect();
    themes.sort_by_key(|t| t.theme_id);

    let mut placed: Vec<Placed<'_>> = Vec::new();
    for t in &themes {
        if t.embedded_count < min_members {
            continue;
        }
        let Some(text) = t.centroid.as_deref() else {
            continue;
        };
        let raw = epigraph_embeddings::Normalizer::parse_pgvector(text)
            .with_context(|| format!("theme {} has an unreadable centroid", t.theme_id))?;
        let wide: Vec<f64> = raw.iter().map(|x| f64::from(*x)).collect();
        let Some(unit) = math::normalize(&wide) else {
            continue;
        };
        placed.push(Placed { theme: t, unit });
    }
    if let Some(first) = placed.first() {
        let dim = first.unit.len();
        if placed.iter().any(|p| p.unit.len() != dim) {
            bail!("theme centroids have different dimensions; refusing to lay them out");
        }
    }

    let n = placed.len();
    let units: Vec<Vec<f64>> = placed.iter().map(|p| p.unit.clone()).collect();
    let merges = math::ward_merges(&units);
    let candidates = match opts.regions {
        Some(k) => vec![math::clamp_regions(k, n)],
        None => math::k_candidates(n),
    };
    let (k, scores) = if n == 0 {
        (0, Vec::new())
    } else {
        math::choose_k(&units, &merges, &candidates)
    };

    // Group, then order regions by public members (desc), ties by the
    // smallest member theme id; inside a region, by public members (desc),
    // then theme id.
    let mut groups: Vec<Vec<usize>> = Vec::new();
    if n > 0 {
        let labels = math::partition(n, &merges, k);
        groups = vec![Vec::new(); labels.iter().copied().max().map_or(0, |m| m + 1)];
        for (i, l) in labels.iter().enumerate() {
            groups[*l].push(i);
        }
    }
    for g in &mut groups {
        g.sort_by(|&a, &b| {
            placed[b]
                .theme
                .public_member_count
                .cmp(&placed[a].theme.public_member_count)
                .then(placed[a].theme.theme_id.cmp(&placed[b].theme.theme_id))
        });
    }
    let weight =
        |g: &Vec<usize>| -> i64 { g.iter().map(|&i| placed[i].theme.public_member_count).sum() };
    let min_id = |g: &Vec<usize>| -> Uuid {
        g.iter()
            .map(|&i| placed[i].theme.theme_id)
            .min()
            .unwrap_or_default()
    };
    groups.sort_by(|a, b| weight(b).cmp(&weight(a)).then(min_id(a).cmp(&min_id(b))));

    let region_units: Vec<Vec<f64>> = groups
        .iter()
        .map(|g| {
            let dim = placed[g[0]].unit.len();
            let mut mean = vec![0.0_f64; dim];
            for &i in g {
                for (m, v) in mean.iter_mut().zip(&placed[i].unit) {
                    *m += v;
                }
            }
            math::normalize(&mean).unwrap_or_else(|| placed[g[0]].unit.clone())
        })
        .collect();
    let region_pos = math::layout_regions(&region_units);

    let mut regions: Vec<LayoutRegionOut> = Vec::with_capacity(groups.len());
    let mut out_themes: Vec<LayoutThemeOut> = Vec::with_capacity(n);
    let mut region_report = Vec::with_capacity(groups.len());
    for (ordinal, g) in groups.iter().enumerate() {
        let (centre, r) = region_pos[ordinal];
        let id = Uuid::new_v4();
        let ranked: Vec<&str> = g.iter().map(|&i| placed[i].theme.label.as_str()).collect();
        let label = math::region_label(&ranked);
        let member_units: Vec<Vec<f64>> = g.iter().map(|&i| placed[i].unit.clone()).collect();
        let pos = math::layout_themes(&member_units, centre, r);
        for (rank, (&i, p)) in g.iter().zip(&pos).enumerate() {
            out_themes.push(LayoutThemeOut {
                theme_id: placed[i].theme.theme_id,
                region_id: id,
                rank_in_region: i32::try_from(rank).unwrap_or(i32::MAX),
                x: p[0],
                y: p[1],
                public_member_count: placed[i].theme.public_member_count,
            });
        }
        region_report.push(json!({
            "ordinal": ordinal,
            "label": label,
            "theme_count": g.len(),
            "public_member_count": weight(g),
        }));
        let centroid: Vec<f32> = region_units[ordinal].iter().map(|v| *v as f32).collect();
        regions.push(LayoutRegionOut {
            id,
            ordinal: i32::try_from(ordinal).unwrap_or(i32::MAX),
            label,
            x: centre[0],
            y: centre[1],
            r,
            centroid,
        });
    }

    let placed_ids: HashSet<Uuid> = out_themes.iter().map(|t| t.theme_id).collect();
    let theme_links: Vec<LayoutLinkOut> = inputs
        .links
        .iter()
        .filter(|l| placed_ids.contains(&l.theme_a) && placed_ids.contains(&l.theme_b))
        .map(|l| LayoutLinkOut {
            theme_a: l.theme_a.min(l.theme_b),
            theme_b: l.theme_a.max(l.theme_b),
            relationship: l.relationship.to_lowercase(),
            link_count: l.link_count,
        })
        .collect();
    let mut link_totals: BTreeMap<String, i64> = BTreeMap::new();
    for l in &theme_links {
        *link_totals.entry(l.relationship.clone()).or_default() += l.link_count;
    }

    let ids: Vec<Uuid> = out_themes.iter().map(|t| t.theme_id).collect();
    let theme_set_digest = math::theme_set_digest(&ids);
    let public_claim_count: i64 = inputs.themes.iter().map(|t| t.public_member_count).sum();
    let public_link_count: i64 = theme_links.iter().map(|l| l.link_count).sum();
    let silhouette: Vec<serde_json::Value> = scores
        .iter()
        .map(|(k, s)| json!({ "k": k, "score": s }))
        .collect();
    let params = json!({
        "k": k,
        "k_range": candidates,
        "silhouette": silhouette,
        "min_public_members": min_members,
        "regions_override": opts.regions,
        "extent": math::EXTENT,
    });
    let report = json!({
        "algo": ATLAS_LAYOUT_ALGO,
        "visibility_epoch": inputs.visibility_epoch,
        "cluster_run_id": inputs.cluster_run_id,
        "params": params,
        "themes": {
            "with_public_members": inputs.themes.len(),
            "placed": n,
            "unplaced": inputs.themes.len() - n,
        },
        "k": k,
        "regions": region_report,
        "links": link_totals,
        "public_claim_count": public_claim_count,
        "public_link_count": public_link_count,
        "theme_set_digest": theme_set_digest,
    });

    Ok(BuiltLayout {
        build: LayoutBuild {
            algo: ATLAS_LAYOUT_ALGO.to_string(),
            params,
            cluster_run_id: inputs.cluster_run_id,
            visibility_epoch: inputs.visibility_epoch,
            public_claim_count,
            public_link_count,
            theme_set_digest,
            regions,
            themes: out_themes,
            theme_links,
        },
        report,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use epigraph_db::repos::atlas_layout::PublicThemeLinkCount;

    fn vector(dim: usize, axis: usize, tilt: f32) -> String {
        let mut v = vec![0.0_f32; dim];
        v[axis] = 1.0;
        v[(axis + 1) % dim] = tilt;
        let parts: Vec<String> = v.iter().map(ToString::to_string).collect();
        format!("[{}]", parts.join(","))
    }

    fn inputs() -> PublicLayoutInputs {
        let mut themes = Vec::new();
        for i in 0..12_u32 {
            themes.push(PublicThemeCentroid {
                theme_id: Uuid::from_u128(u128::from(i) + 1),
                label: format!("Theme {i}"),
                public_member_count: i64::from(i % 5 + 1),
                embedded_count: i64::from(i % 5 + 1),
                centroid: Some(vector(16, (i % 4) as usize, 0.05 * i as f32)),
            });
        }
        PublicLayoutInputs {
            links: vec![PublicThemeLinkCount {
                theme_a: Uuid::from_u128(1),
                theme_b: Uuid::from_u128(2),
                relationship: "supports".into(),
                link_count: 3,
            }],
            themes,
            cluster_run_id: None,
            visibility_epoch: 7,
        }
    }

    /// Everything but the random region ids.
    fn shape(b: &LayoutBuild) -> String {
        let regions: Vec<_> = b
            .regions
            .iter()
            .map(|r| {
                (
                    r.ordinal,
                    r.label.clone(),
                    r.x.to_bits(),
                    r.y.to_bits(),
                    r.r.to_bits(),
                    r.centroid.iter().map(|c| c.to_bits()).collect::<Vec<_>>(),
                )
            })
            .collect();
        let themes: Vec<_> = b
            .themes
            .iter()
            .map(|t| (t.theme_id, t.rank_in_region, t.x.to_bits(), t.y.to_bits()))
            .collect();
        format!(
            "{regions:?}{themes:?}{:?}{}",
            b.theme_links, b.theme_set_digest
        )
    }

    #[test]
    fn layout_is_bit_identical_across_runs() {
        let a = build_layout(&inputs(), &BuildOptions::default()).unwrap();
        let b = build_layout(&inputs(), &BuildOptions::default()).unwrap();
        assert_eq!(shape(&a.build), shape(&b.build));
        assert_eq!(a.build.visibility_epoch, 7);
        assert_eq!(a.build.themes.len(), 12);
    }

    #[test]
    fn ranks_are_dense_per_region() {
        let built = build_layout(&inputs(), &BuildOptions::default())
            .unwrap()
            .build;
        let by_id: BTreeMap<Uuid, i64> = inputs()
            .themes
            .iter()
            .map(|t| (t.theme_id, t.public_member_count))
            .collect();
        for r in &built.regions {
            let mut members: Vec<&LayoutThemeOut> = built
                .themes
                .iter()
                .filter(|t| t.region_id == r.id)
                .collect();
            members.sort_by_key(|t| t.rank_in_region);
            let ranks: Vec<i32> = members.iter().map(|t| t.rank_in_region).collect();
            assert_eq!(
                ranks,
                (0..i32::try_from(members.len()).unwrap()).collect::<Vec<_>>()
            );
            for w in members.windows(2) {
                let (a, b) = (by_id[&w[0].theme_id], by_id[&w[1].theme_id]);
                assert!(a > b || (a == b && w[0].theme_id < w[1].theme_id));
            }
        }
        // Regions are ordered by their public member total.
        let totals: Vec<i64> = built
            .regions
            .iter()
            .map(|r| {
                built
                    .themes
                    .iter()
                    .filter(|t| t.region_id == r.id)
                    .map(|t| t.public_member_count)
                    .sum()
            })
            .collect();
        assert!(totals.windows(2).all(|w| w[0] >= w[1]), "{totals:?}");
    }

    #[test]
    fn min_public_members_and_missing_centroids_leave_themes_unplaced() {
        let mut inp = inputs();
        inp.themes[0].centroid = None;
        inp.themes[0].embedded_count = 0;
        let built = build_layout(
            &inp,
            &BuildOptions {
                regions: Some(3),
                min_public_members: 2,
            },
        )
        .unwrap();
        let placed: HashSet<Uuid> = built.build.themes.iter().map(|t| t.theme_id).collect();
        assert!(!placed.contains(&Uuid::from_u128(1)));
        // Themes with one embedded member are below the bar of 2.
        for t in &inp.themes {
            assert_eq!(placed.contains(&t.theme_id), t.embedded_count >= 2, "{t:?}");
        }
        assert_eq!(built.build.regions.len(), 3);
        // The link from the unplaced theme is dropped.
        assert!(built.build.theme_links.is_empty());
        assert_eq!(built.report["themes"]["placed"], placed.len());
    }

    #[test]
    fn an_empty_corpus_builds_an_empty_run() {
        let inp = PublicLayoutInputs {
            themes: Vec::new(),
            links: Vec::new(),
            cluster_run_id: None,
            visibility_epoch: 0,
        };
        let built = build_layout(&inp, &BuildOptions::default()).unwrap().build;
        assert!(built.regions.is_empty() && built.themes.is_empty());
        assert_eq!(built.theme_set_digest.len(), 64);
    }
}
