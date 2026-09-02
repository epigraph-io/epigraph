//! Deterministic 2-D PCA projection of high-dimensional embeddings.
//!
//! # Why this exists
//!
//! `GET /api/v1/themes/:id/embeddings` used to return the complete raw
//! 1536-dimensional `claims.embedding` for up to 5000 claims at `claims:read`.
//! Embeddings are approximately invertible to the content they encode, so that
//! endpoint was a bulk content-exfiltration primitive wearing a clustering
//! endpoint's clothes — plan §4.9 row 4 rates it a blocker in all three columns
//! and assigns the fix to PR-07.
//!
//! The endpoint's one real consumer is
//! `scripts/maintain_themes.py::split_oversized_theme`, which runs
//! `MiniBatchKMeans` over the returned vectors purely to decide *which claim
//! goes in which half* of an oversized theme. A 2-D PCA projection preserves the
//! dominant separating structure that k-means is looking for while disclosing
//! two floats per claim instead of 1536. The sub-theme centroids the script used
//! to compute client-side are now computed server-side from the claim ids (see
//! `crud::create_theme_with_centroid`), so no caller needs raw vectors at all.
//!
//! # Determinism
//!
//! Power iteration is seeded from a fixed LCG, never from a clock or an
//! `OsRng`, so the same input rows always produce the same projection. A theme
//! split that is re-run after a transient failure must not silently reshuffle
//! claims between sub-themes.
//!
//! The sign of a principal component is arbitrary in exact arithmetic, so it is
//! pinned here: each component is negated if needed to make its largest-magnitude
//! coordinate positive. Without that, a numerically identical rerun could mirror
//! the projection and produce different k-means labels for identical input.

/// Maximum power-iteration steps per component.
///
/// The dominant eigengap of a mean-centered embedding matrix is large in
/// practice, so this converges well before the cap; the cap exists to bound
/// worst-case latency at n=5000, d=1536 rather than to be reached.
const MAX_POWER_ITERATIONS: usize = 32;

/// Convergence threshold on the L2 change of the unit eigenvector estimate.
const CONVERGENCE_EPSILON: f64 = 1e-7;

/// Project `rows` (each of identical length `d`) onto their top two principal
/// components, returning one `[x, y]` pair per input row in input order.
///
/// Returns an empty vector for empty input. Rows of inconsistent length are
/// rejected by the caller before reaching here; any row shorter than the first
/// is zero-padded defensively so a single malformed stored vector cannot panic
/// a request.
///
/// When the input has fewer than two meaningful dimensions of variance (e.g. a
/// single row, or all rows identical), the corresponding coordinate is `0.0`
/// rather than an arbitrary direction.
pub fn project_to_2d(rows: &[Vec<f64>]) -> Vec<[f64; 2]> {
    let n = rows.len();
    if n == 0 {
        return Vec::new();
    }
    let d = rows[0].len();
    if d == 0 {
        return vec![[0.0, 0.0]; n];
    }

    // Mean-center. PCA on uncentered data recovers the mean direction as the
    // first component, which carries no separating information.
    let mut mean = vec![0.0_f64; d];
    for row in rows {
        for (m, v) in mean.iter_mut().zip(row.iter()) {
            *m += *v;
        }
    }
    let inv_n = 1.0 / n as f64;
    for m in &mut mean {
        *m *= inv_n;
    }

    let mut centered: Vec<Vec<f64>> = rows
        .iter()
        .map(|row| {
            let mut c = vec![0.0_f64; d];
            for i in 0..d {
                c[i] = row.get(i).copied().unwrap_or(0.0) - mean[i];
            }
            c
        })
        .collect();

    let pc1 = dominant_eigenvector(&centered, d, 0x2545_F491_4F6C_DD1D);
    // Deflate: remove the pc1 component from every row so the next power
    // iteration finds the second component rather than the first again.
    if let Some(ref v1) = pc1 {
        for row in &mut centered {
            let proj = dot(row, v1);
            for i in 0..d {
                row[i] -= proj * v1[i];
            }
        }
    }
    let pc2 = dominant_eigenvector(&centered, d, 0x9E37_79B9_7F4A_7C15);

    rows.iter()
        .map(|row| {
            let mut c = vec![0.0_f64; d];
            for i in 0..d {
                c[i] = row.get(i).copied().unwrap_or(0.0) - mean[i];
            }
            let x = pc1.as_ref().map_or(0.0, |v| dot(&c, v));
            let y = pc2.as_ref().map_or(0.0, |v| dot(&c, v));
            [x, y]
        })
        .collect()
}

/// Power-iterate `X^T X` (never materialised: `d` is 1536, so the `d x d`
/// covariance would be 2.4M doubles) to the dominant unit eigenvector.
///
/// Returns `None` when the data has no variance in any direction, which is the
/// honest answer for a single row or a set of identical rows — the caller maps
/// it to a `0.0` coordinate rather than inventing a direction.
fn dominant_eigenvector(centered: &[Vec<f64>], d: usize, seed: u64) -> Option<Vec<f64>> {
    let mut v = seeded_unit_vector(d, seed);
    let mut last = v.clone();

    for _ in 0..MAX_POWER_ITERATIONS {
        // w = X^T (X v)
        let mut w = vec![0.0_f64; d];
        for row in centered {
            let proj = dot(row, &v);
            if proj == 0.0 {
                continue;
            }
            for i in 0..d {
                w[i] += proj * row[i];
            }
        }
        let norm = w.iter().map(|x| x * x).sum::<f64>().sqrt();
        if !norm.is_finite() || norm < 1e-12 {
            // No variance left along any direction reachable from this seed.
            return None;
        }
        for x in &mut w {
            *x /= norm;
        }
        let delta = w
            .iter()
            .zip(last.iter())
            .map(|(a, b)| (a - b) * (a - b))
            .sum::<f64>()
            .sqrt();
        last.clone_from(&w);
        v = w;
        if delta < CONVERGENCE_EPSILON {
            break;
        }
    }

    Some(pin_sign(v))
}

/// Pin a component's arbitrary sign so reruns are bit-stable.
fn pin_sign(mut v: Vec<f64>) -> Vec<f64> {
    let mut pivot = 0.0_f64;
    for x in &v {
        if x.abs() > pivot.abs() {
            pivot = *x;
        }
    }
    if pivot < 0.0 {
        for x in &mut v {
            *x = -*x;
        }
    }
    v
}

/// Deterministic unit-norm start vector. A constant vector is a poor start (it
/// is orthogonal to any component that sums to zero), so this uses a fixed
/// SplitMix64 stream instead of a clock- or entropy-seeded RNG.
fn seeded_unit_vector(d: usize, seed: u64) -> Vec<f64> {
    let mut state = seed;
    let mut v = Vec::with_capacity(d);
    for _ in 0..d {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        // Map to (-1, 1).
        v.push((z as f64 / u64::MAX as f64) * 2.0 - 1.0);
    }
    let norm = v.iter().map(|x| x * x).sum::<f64>().sqrt();
    if norm > 0.0 {
        for x in &mut v {
            *x /= norm;
        }
    }
    v
}

fn dot(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_yields_empty_output() {
        assert!(project_to_2d(&[]).is_empty());
    }

    #[test]
    fn single_row_has_no_variance_and_projects_to_origin() {
        // One row is its own mean, so the centered matrix is all zeros and
        // there is no direction to report. Asserting the origin (rather than
        // "some finite number") pins that we do not invent a component.
        let out = project_to_2d(&[vec![0.3, -0.7, 1.2, 0.0]]);
        assert_eq!(out.len(), 1);
        assert!(out[0][0].abs() < 1e-9, "x was {}", out[0][0]);
        assert!(out[0][1].abs() < 1e-9, "y was {}", out[0][1]);
    }

    #[test]
    fn identical_rows_all_project_to_origin() {
        let rows = vec![vec![1.0, 2.0, 3.0]; 6];
        for p in project_to_2d(&rows) {
            assert!(p[0].abs() < 1e-9 && p[1].abs() < 1e-9);
        }
    }

    #[test]
    fn recovers_the_separating_axis_of_two_well_separated_clusters() {
        // The whole point of the endpoint is that k-means over the projection
        // still splits the theme the same way it would over raw vectors. Build
        // two clusters separated along dimension 0 with noise elsewhere, and
        // assert the first component separates them with the same sign
        // structure as the raw data.
        let mut rows = Vec::new();
        for i in 0..20 {
            let jitter = (i as f64) * 0.001;
            rows.push(vec![-5.0 + jitter, 0.1 * jitter, -0.2 * jitter, jitter]);
        }
        for i in 0..20 {
            let jitter = (i as f64) * 0.001;
            rows.push(vec![5.0 + jitter, 0.1 * jitter, -0.2 * jitter, jitter]);
        }
        let out = project_to_2d(&rows);
        assert_eq!(out.len(), 40);

        let left_mean: f64 = out[..20].iter().map(|p| p[0]).sum::<f64>() / 20.0;
        let right_mean: f64 = out[20..].iter().map(|p| p[0]).sum::<f64>() / 20.0;
        // Separated along PC1, and by roughly the true 10.0 gap.
        assert!(
            (right_mean - left_mean).abs() > 9.0,
            "PC1 failed to separate the clusters: left={left_mean}, right={right_mean}"
        );
        // Every point lands on the correct side of the midpoint: this is
        // exactly the property MiniBatchKMeans relies on.
        let mid = (left_mean + right_mean) / 2.0;
        for (i, p) in out.iter().enumerate() {
            let on_left = p[0] < mid;
            assert_eq!(on_left, i < 20, "row {i} landed on the wrong side");
        }
    }

    #[test]
    fn is_deterministic_across_runs() {
        // A theme split re-run after a transient failure must not reshuffle
        // claims between sub-themes, so the projection must be bit-stable.
        let rows: Vec<Vec<f64>> = (0..30)
            .map(|i| {
                let f = i as f64;
                vec![f.sin(), f.cos(), (f * 0.5).sin(), (f * 0.25).cos()]
            })
            .collect();
        let a = project_to_2d(&rows);
        let b = project_to_2d(&rows);
        assert_eq!(a, b, "projection is not reproducible");
    }

    #[test]
    fn second_component_is_orthogonal_to_the_first() {
        // Variance 100 along dim 0, variance 1 along dim 1, none elsewhere.
        // PC1 must take dim 0 and PC2 dim 1; if deflation were skipped, PC2
        // would duplicate PC1 and y would be a rescaling of x.
        let mut rows = Vec::new();
        for i in 0..40 {
            let a = ((i % 8) as f64 - 3.5) * 10.0;
            let b = ((i / 8) as f64 - 2.0) * 1.0;
            rows.push(vec![a, b, 0.0]);
        }
        let out = project_to_2d(&rows);
        let xs: Vec<f64> = out.iter().map(|p| p[0]).collect();
        let ys: Vec<f64> = out.iter().map(|p| p[1]).collect();
        let cov: f64 = xs.iter().zip(ys.iter()).map(|(x, y)| x * y).sum::<f64>();
        assert!(
            cov.abs() < 1e-6,
            "PC1 and PC2 are correlated (cov={cov}); deflation did not happen"
        );
        let var_x: f64 = xs.iter().map(|x| x * x).sum();
        let var_y: f64 = ys.iter().map(|y| y * y).sum();
        assert!(
            var_x > var_y,
            "PC1 must capture more variance than PC2 (got {var_x} vs {var_y})"
        );
    }

    #[test]
    fn output_is_two_dimensional_regardless_of_input_width() {
        // The acceptance criterion is "zero raw 1536-d vectors at any limit".
        // This is the shape half of it, at the function boundary.
        let rows: Vec<Vec<f64>> = (0..5)
            .map(|i| (0..1536).map(|j| ((i * j) as f64).sin()).collect())
            .collect();
        for p in project_to_2d(&rows) {
            assert_eq!(p.len(), 2);
            assert!(p[0].is_finite() && p[1].is_finite());
        }
    }
}
