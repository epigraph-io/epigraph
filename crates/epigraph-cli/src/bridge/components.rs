//! Connected-component enumeration over the claim graph.

use sqlx::PgPool;
use std::collections::HashMap;
use uuid::Uuid;

/// Edge relationships that define structural connectivity for component
/// detection. Order does not matter; the union-find is symmetric.
pub const STRUCTURAL_RELATIONSHIPS: &[&str] = &[
    "decomposes_to",
    "CORROBORATES",
    "same_as",
    "same_source",
    "continues_argument",
];

#[derive(Debug, Clone)]
pub struct ComponentSummary {
    /// Canonical ID for the component: the smallest claim UUID it contains.
    /// Stable across runs (UUID ordering is total).
    pub component_id: Uuid,
    pub claim_ids: Vec<Uuid>,
    pub size: usize,
}

/// Compute connected components over the claim graph using STRUCTURAL_RELATIONSHIPS.
///
/// Returns one `ComponentSummary` per component, sorted by `size` descending.
/// Singleton components (claims with no structural edges) are still returned —
/// callers can filter.
pub async fn compute_components(pool: &PgPool) -> Result<Vec<ComponentSummary>, sqlx::Error> {
    // 1. Pull all claim IDs (compact-index them).
    let claim_rows: Vec<(Uuid,)> = sqlx::query_as("SELECT id FROM claims ORDER BY id")
        .fetch_all(pool)
        .await?;
    let claim_ids: Vec<Uuid> = claim_rows.into_iter().map(|(id,)| id).collect();
    let n = claim_ids.len();
    if n == 0 {
        return Ok(Vec::new());
    }
    let mut index: HashMap<Uuid, usize> = HashMap::with_capacity(n);
    for (i, id) in claim_ids.iter().enumerate() {
        index.insert(*id, i);
    }

    // 2. Pull all structural edges (claim-to-claim only).
    let edge_rows: Vec<(Uuid, Uuid)> = sqlx::query_as(
        r#"
        SELECT source_id, target_id
        FROM edges
        WHERE source_type = 'claim'
          AND target_type = 'claim'
          AND relationship = ANY($1)
        "#,
    )
    .bind(STRUCTURAL_RELATIONSHIPS)
    .fetch_all(pool)
    .await?;

    // 3. Union endpoints.
    let mut uf = UnionFind::new(n);
    for (s, t) in edge_rows {
        if let (Some(&si), Some(&ti)) = (index.get(&s), index.get(&t)) {
            uf.union(si, ti);
        }
    }

    // 4. Group by canonical root.
    let mut buckets: HashMap<usize, Vec<Uuid>> = HashMap::new();
    for (i, id) in claim_ids.iter().enumerate() {
        let root = uf.find(i);
        buckets.entry(root).or_default().push(*id);
    }

    // 5. Build summaries.
    let mut summaries: Vec<ComponentSummary> = buckets
        .into_values()
        .map(|mut ids| {
            ids.sort_unstable();
            let component_id = ids[0];
            let size = ids.len();
            ComponentSummary {
                component_id,
                claim_ids: ids,
                size,
            }
        })
        .collect();
    summaries.sort_by(|a, b| {
        b.size
            .cmp(&a.size)
            .then_with(|| a.component_id.cmp(&b.component_id))
    });
    Ok(summaries)
}

// ── Path-halved union-by-rank union-find ──────────────────────────────────

struct UnionFind {
    parent: Vec<usize>,
    rank: Vec<usize>,
}

impl UnionFind {
    fn new(n: usize) -> Self {
        Self {
            parent: (0..n).collect(),
            rank: vec![0; n],
        }
    }

    fn find(&mut self, mut x: usize) -> usize {
        while self.parent[x] != x {
            self.parent[x] = self.parent[self.parent[x]];
            x = self.parent[x];
        }
        x
    }

    fn union(&mut self, x: usize, y: usize) {
        let rx = self.find(x);
        let ry = self.find(y);
        if rx == ry {
            return;
        }
        match self.rank[rx].cmp(&self.rank[ry]) {
            std::cmp::Ordering::Less => self.parent[rx] = ry,
            std::cmp::Ordering::Greater => self.parent[ry] = rx,
            std::cmp::Ordering::Equal => {
                self.parent[ry] = rx;
                self.rank[rx] += 1;
            }
        }
    }
}
