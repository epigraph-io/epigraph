//! The pure arithmetic of the Atlas layout build: Ward clustering, the choice
//! of the region count, and the nested 2-D placement. No database, no clock,
//! no randomness: the same inputs give the same bytes.
//!
//! Every input vector is a theme's public-only centroid, L2-normalised by the
//! caller, and the slices are in `theme_id` order, which is what makes every
//! tie-break here deterministic.

use epigraph_core::projection::project_to_2d_with;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Half-width of the coordinate frame (the API reports it as `run.extent`).
pub const EXTENT: f64 = 1000.0;

/// Power-iteration cap for the offline projections: they run over at most a
/// few hundred rows, so they can afford to iterate to convergence.
pub const PCA_ITERATIONS: usize = 1000;

/// The most regions a run may hold (migration 197's CHECK).
pub const MAX_REGIONS: usize = 200;

/// The automatic region count range, before it is cut to `2..=n-1`.
const AUTO_K_MIN: usize = 8;
const AUTO_K_MAX: usize = 15;

/// Scores within this of each other count as equal; the smaller k wins.
const SCORE_TIE: f64 = 1e-12;

/// A region label names at most this many characters of each theme label.
const LABEL_PART_CHARS: usize = 60;

/// Keeps rounded coordinates strictly inside their bound.
const ROUNDING_MARGIN: f64 = 1e-3;

/// `v / |v|`, or `None` for a zero or non-finite vector.
#[must_use]
pub fn normalize(v: &[f64]) -> Option<Vec<f64>> {
    let norm = v.iter().map(|x| x * x).sum::<f64>().sqrt();
    if !norm.is_finite() || norm == 0.0 {
        return None;
    }
    Some(v.iter().map(|x| x / norm).collect())
}

fn dot(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

fn sq_dist(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b).map(|(x, y)| (x - y) * (x - y)).sum()
}

/// Round to 1e-4, so two runs over one snapshot store identical values.
#[must_use]
pub fn round4(v: f64) -> f64 {
    (v * 1e4).round() / 1e4
}

/// The agglomeration order of Ward's method over `points`, by the
/// Lance-Williams update on squared Euclidean distance.
///
/// Each entry is one merge, named by the smallest input index of each of the
/// two clusters merged (`(a, b)`, `a < b`). Each step merges the closest pair;
/// a tie goes to the lexicographically smallest `(a, b)`. There are `n - 1`
/// merges for `n` points.
#[must_use]
pub fn ward_merges(points: &[Vec<f64>]) -> Vec<(usize, usize)> {
    let n = points.len();
    if n < 2 {
        return Vec::new();
    }
    // `alive` stays sorted by each cluster's smallest member index, so the
    // pair scan below visits pairs in lexicographic order and the first
    // minimum it meets is the tie-break the doc promises.
    let mut alive: Vec<usize> = (0..n).collect();
    let mut size = vec![1.0_f64; n];
    let mut d = vec![vec![0.0_f64; n]; n];
    for (i, pi) in points.iter().enumerate() {
        for (j, pj) in points.iter().enumerate().skip(i + 1) {
            let v = sq_dist(pi, pj);
            d[i][j] = v;
            d[j][i] = v;
        }
    }
    let mut merges = Vec::with_capacity(n - 1);
    while alive.len() > 1 {
        let mut best: Option<(f64, usize, usize)> = None;
        for (pi, &a) in alive.iter().enumerate() {
            for &b in &alive[pi + 1..] {
                let v = d[a][b];
                let better = match best {
                    Some((bv, _, _)) => v < bv,
                    None => true,
                };
                if better {
                    best = Some((v, a, b));
                }
            }
        }
        let Some((dab, a, b)) = best else { break };
        let (na, nb) = (size[a], size[b]);
        for &k in &alive {
            if k == a || k == b {
                continue;
            }
            let nk = size[k];
            let v = ((na + nk) * d[k][a] + (nb + nk) * d[k][b] - nk * dab) / (na + nb + nk);
            d[k][a] = v;
            d[a][k] = v;
        }
        size[a] = na + nb;
        alive.retain(|&k| k != b);
        merges.push((a, b));
    }
    merges
}

/// The partition of `n` points after the first `n - k` merges of `merges`:
/// `labels[i]` is the cluster of point `i`, clusters numbered `0..k` in order
/// of their smallest member index.
#[must_use]
pub fn partition(n: usize, merges: &[(usize, usize)], k: usize) -> Vec<usize> {
    let k = k.clamp(1, n.max(1));
    let mut root: Vec<usize> = (0..n).collect();
    for &(a, b) in merges.iter().take(n.saturating_sub(k)) {
        for r in &mut root {
            if *r == b {
                *r = a;
            }
        }
    }
    let mut seen: Vec<usize> = Vec::new();
    root.iter()
        .map(|r| {
            if let Some(pos) = seen.iter().position(|s| s == r) {
                pos
            } else {
                seen.push(*r);
                seen.len() - 1
            }
        })
        .collect()
}

/// The region counts tried for `n` placed themes.
///
/// `n <= 2` gives `[1]`. Otherwise `8..=15` cut to `2..=n-1`, and when that
/// is empty (`3 <= n <= 8`) the whole of `2..=n-1`.
#[must_use]
pub fn k_candidates(n: usize) -> Vec<usize> {
    if n <= 2 {
        return vec![1];
    }
    let lo = AUTO_K_MIN.max(2);
    let hi = AUTO_K_MAX.min(n - 1);
    if lo <= hi {
        (lo..=hi).collect()
    } else {
        (2..n).collect()
    }
}

/// An operator's `--regions K`, clamped to `1..=min(n, 200)` (and 1 for no
/// themes at all).
#[must_use]
pub fn clamp_regions(k: usize, n: usize) -> usize {
    k.clamp(1, n.clamp(1, MAX_REGIONS))
}

/// Mean silhouette of `labels` under cosine distance `1 - u_i . u_j` (the
/// points are unit vectors). A point alone in its cluster scores 0, and so
/// does a one-cluster partition.
#[must_use]
pub fn silhouette(points: &[Vec<f64>], labels: &[usize]) -> f64 {
    let n = points.len();
    let k = labels.iter().copied().max().map_or(0, |m| m + 1);
    if n == 0 || k < 2 {
        return 0.0;
    }
    let mut total = 0.0;
    for i in 0..n {
        let mut sum = vec![0.0_f64; k];
        let mut cnt = vec![0usize; k];
        for j in 0..n {
            if i == j {
                continue;
            }
            sum[labels[j]] += 1.0 - dot(&points[i], &points[j]);
            cnt[labels[j]] += 1;
        }
        let own = labels[i];
        if cnt[own] == 0 {
            continue;
        }
        let a = sum[own] / cnt[own] as f64;
        let b = (0..k)
            .filter(|&c| c != own && cnt[c] > 0)
            .map(|c| sum[c] / cnt[c] as f64)
            .fold(f64::INFINITY, f64::min);
        if !b.is_finite() {
            continue;
        }
        let m = a.max(b);
        if m > 0.0 {
            total += (b - a) / m;
        }
    }
    total / n as f64
}

/// The candidate with the highest mean silhouette (the smaller k on a tie
/// within 1e-12), and every candidate's score in candidate order.
#[must_use]
pub fn choose_k(
    points: &[Vec<f64>],
    merges: &[(usize, usize)],
    candidates: &[usize],
) -> (usize, Vec<(usize, f64)>) {
    let n = points.len();
    let mut scores = Vec::with_capacity(candidates.len());
    let mut best: Option<(usize, f64)> = None;
    let mut sorted = candidates.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    for &k in &sorted {
        let labels = partition(n, merges, k);
        let s = silhouette(points, &labels);
        scores.push((k, s));
        let better = match best {
            Some((_, bs)) => s > bs + SCORE_TIE,
            None => true,
        };
        if better {
            best = Some((k, s));
        }
    }
    (best.map_or(1, |(k, _)| k), scores)
}

/// `s` cut to `max` characters, on a char boundary.
fn clip_chars(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// A region's label from its member labels in rank order: `"{L1} / {L2}"`, or
/// `"{L1}"` for a one-theme region, each part cut to 60 characters. An empty
/// first label reads `"Region"` (the column refuses an empty label).
#[must_use]
pub fn region_label(ranked_labels: &[&str]) -> String {
    let parts: Vec<String> = ranked_labels
        .iter()
        .take(2)
        .map(|l| clip_chars(l.trim(), LABEL_PART_CHARS))
        .filter(|l| !l.is_empty())
        .collect();
    if parts.is_empty() {
        "Region".to_string()
    } else {
        parts.join(" / ")
    }
}

/// `v` scaled so its largest point norm is `target`; unchanged when every
/// point is at the origin.
fn scale_to(points: &mut [[f64; 2]], target: f64) {
    let max = points
        .iter()
        .map(|p| (p[0] * p[0] + p[1] * p[1]).sqrt())
        .fold(0.0_f64, f64::max);
    if max > 0.0 && max.is_finite() {
        let f = target / max;
        for p in points.iter_mut() {
            p[0] *= f;
            p[1] *= f;
        }
    } else {
        for p in points.iter_mut() {
            *p = [0.0, 0.0];
        }
    }
}

/// Region centres and radii from the regions' unit centroids.
///
/// Centres are the 2-D projection scaled so the farthest sits at
/// `0.8 * EXTENT`; a radius is `0.45 x` the distance to the nearest other
/// centre, clamped to `[0.04, 0.35] x EXTENT`. One region sits at the origin
/// with radius `0.8 * EXTENT`. All values are rounded to 1e-4.
#[must_use]
pub fn layout_regions(centroids: &[Vec<f64>]) -> Vec<([f64; 2], f64)> {
    let k = centroids.len();
    if k == 0 {
        return Vec::new();
    }
    if k == 1 {
        return vec![([0.0, 0.0], round4(0.8 * EXTENT))];
    }
    let mut p = project_to_2d_with(centroids, PCA_ITERATIONS);
    scale_to(&mut p, 0.8 * EXTENT - ROUNDING_MARGIN);
    let p: Vec<[f64; 2]> = p.iter().map(|q| [round4(q[0]), round4(q[1])]).collect();
    (0..k)
        .map(|r| {
            let nearest = (0..k)
                .filter(|&s| s != r)
                .map(|s| ((p[r][0] - p[s][0]).powi(2) + (p[r][1] - p[s][1]).powi(2)).sqrt())
                .fold(f64::INFINITY, f64::min);
            let radius = (0.45 * nearest).clamp(0.04 * EXTENT, 0.35 * EXTENT);
            (p[r], round4(radius))
        })
        .collect()
}

/// Theme positions inside one region: the members' 2-D projection scaled so
/// the farthest sits just inside `0.7 * r` of `centre`. A single member sits
/// at the centre. Rounded to 1e-4.
#[must_use]
pub fn layout_themes(members: &[Vec<f64>], centre: [f64; 2], r: f64) -> Vec<[f64; 2]> {
    if members.is_empty() {
        return Vec::new();
    }
    let mut l = if members.len() == 1 {
        vec![[0.0, 0.0]]
    } else {
        project_to_2d_with(members, PCA_ITERATIONS)
    };
    scale_to(&mut l, (0.7 * r - ROUNDING_MARGIN).max(0.0));
    l.iter()
        .map(|q| [round4(centre[0] + q[0]), round4(centre[1] + q[1])])
        .collect()
}

/// Lower-hex SHA-256 of the sorted theme ids, hyphenated and joined by `,`.
#[must_use]
pub fn theme_set_digest(ids: &[Uuid]) -> String {
    let mut sorted = ids.to_vec();
    sorted.sort_unstable();
    let text = sorted
        .iter()
        .map(|u| u.hyphenated().to_string())
        .collect::<Vec<_>>()
        .join(",");
    hex::encode(Sha256::digest(text.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit(v: &[f64]) -> Vec<f64> {
        normalize(v).expect("non-zero")
    }

    /// `k` tight blobs on distinct axes of a `dim`-dimensional space, `per`
    /// points each.
    fn blobs(k: usize, per: usize, dim: usize) -> Vec<Vec<f64>> {
        let mut out = Vec::new();
        for c in 0..k {
            for i in 0..per {
                let mut v = vec![0.0; dim];
                v[c] = 1.0;
                v[(c + 1) % dim] += 0.01 * (i as f64 + 1.0);
                out.push(unit(&v));
            }
        }
        out
    }

    #[test]
    fn ward_merges_the_nearest_pair_first_and_breaks_ties_by_index() {
        // Points on a line: 0 and 1 are 1 apart, 2 and 3 are 1 apart, the two
        // pairs 10 apart. The two closest pairs tie: (0,1) goes first.
        let pts = vec![vec![0.0], vec![1.0], vec![11.0], vec![12.0]];
        let m = ward_merges(&pts);
        assert_eq!(m, vec![(0, 1), (2, 3), (0, 2)]);
        // A strict nearest pair wins over index order.
        let pts = vec![vec![0.0], vec![5.0], vec![5.5], vec![20.0]];
        assert_eq!(ward_merges(&pts)[0], (1, 2));
    }

    #[test]
    fn ward_partition_does_not_depend_on_input_order() {
        let pts = blobs(3, 4, 6);
        let labels = partition(pts.len(), &ward_merges(&pts), 3);
        // Reverse, then restore the canonical (sorted) order the build uses.
        let mut idx: Vec<usize> = (0..pts.len()).rev().collect();
        idx.sort_unstable();
        let again: Vec<Vec<f64>> = idx.iter().map(|&i| pts[i].clone()).collect();
        assert_eq!(partition(again.len(), &ward_merges(&again), 3), labels);
        assert_eq!(labels, vec![0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2]);
    }

    #[test]
    fn choose_k_maximises_silhouette_and_prefers_smaller_k_on_ties() {
        let pts = blobs(10, 3, 12);
        let merges = ward_merges(&pts);
        let (k, scores) = choose_k(&pts, &merges, &k_candidates(pts.len()));
        assert_eq!(k, 10, "scores {scores:?}");
        assert_eq!(scores.len(), 8);
        // Four identical points: every k scores 0 and the smallest wins.
        let same = vec![unit(&[1.0, 0.0]); 4];
        let merges = ward_merges(&same);
        let (k, _) = choose_k(&same, &merges, &[2, 3]);
        assert_eq!(k, 2);
    }

    #[test]
    fn k_candidates_cover_every_small_n() {
        assert_eq!(k_candidates(1), vec![1]);
        assert_eq!(k_candidates(2), vec![1]);
        assert_eq!(k_candidates(3), vec![2]);
        assert_eq!(k_candidates(5), vec![2, 3, 4]);
        assert_eq!(k_candidates(8), (2..=7).collect::<Vec<_>>());
        assert_eq!(k_candidates(9), vec![8]);
        assert_eq!(k_candidates(10), vec![8, 9]);
        assert_eq!(k_candidates(20), (8..=15).collect::<Vec<_>>());
        for n in 1..=300 {
            let c = k_candidates(n);
            assert!(!c.is_empty(), "n = {n}");
            assert!(c.iter().all(|&k| k >= 1 && k <= n.max(1)), "n = {n}");
        }
        assert_eq!(clamp_regions(99, 40), 40);
        assert_eq!(clamp_regions(500, 300), 200);
        assert_eq!(clamp_regions(0, 5), 1);
        assert_eq!(clamp_regions(3, 0), 1);
    }

    #[test]
    fn region_label_names_the_two_largest_themes() {
        assert_eq!(
            region_label(&["Stern capacitance", "Double layers", "Third"]),
            "Stern capacitance / Double layers"
        );
        assert_eq!(region_label(&["Only"]), "Only");
        let long = "é".repeat(80);
        let l = region_label(&[long.as_str()]);
        assert_eq!(l.chars().count(), 60);
        assert!(long.starts_with(&l));
        assert_eq!(region_label(&["  "]), "Region");
    }

    #[test]
    fn themes_sit_inside_their_region_radius() {
        let regions: Vec<Vec<f64>> = blobs(5, 1, 8);
        let placed = layout_regions(&regions);
        assert_eq!(placed.len(), 5);
        for (p, r) in &placed {
            assert!((p[0] * p[0] + p[1] * p[1]).sqrt() <= 0.8 * EXTENT, "{p:?}");
            assert!(*r >= 0.04 * EXTENT - 1e-9 && *r <= 0.35 * EXTENT + 1e-9);
            let members = blobs(4, 2, 8);
            for q in layout_themes(&members, *p, *r) {
                let d = ((q[0] - p[0]).powi(2) + (q[1] - p[1]).powi(2)).sqrt();
                assert!(d <= 0.7 * r + 1e-9, "{d} > 0.7 * {r}");
            }
        }
    }

    #[test]
    fn single_region_and_single_theme_are_centred() {
        let one = layout_regions(&[unit(&[1.0, 2.0, 3.0])]);
        assert_eq!(one, vec![([0.0, 0.0], 800.0)]);
        let t = layout_themes(&[unit(&[1.0, 0.0])], [12.5, -3.0], 100.0);
        assert_eq!(t, vec![[12.5, -3.0]]);
        // Identical members do not produce NaN.
        let same = vec![unit(&[0.0, 1.0]); 3];
        for q in layout_themes(&same, [0.0, 0.0], 50.0) {
            assert!(q[0].is_finite() && q[1].is_finite());
        }
        assert!(layout_regions(&[]).is_empty());
    }

    #[test]
    fn theme_set_digest_is_sha256_hex() {
        let a = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let b = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
        let d = theme_set_digest(&[b, a]);
        assert_eq!(d.len(), 64);
        assert!(d
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_eq!(d, theme_set_digest(&[a, b]));
        let text = format!("{},{}", a.hyphenated(), b.hyphenated());
        assert_eq!(d, hex::encode(Sha256::digest(text.as_bytes())));
        // The empty set is the digest of the empty string.
        assert_eq!(
            theme_set_digest(&[]),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn rounding_is_to_four_places() {
        assert_eq!(round4(1.234_56), 1.2346);
        assert_eq!(round4(-0.000_04), -0.0);
    }
}
