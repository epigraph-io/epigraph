//! The positions below a theme (Atlas W6, backlog f52fff97): the
//! force-directed layout of one leaf, and the circle placement of one group
//! level's children. The browser draws them and does not simulate (design
//! §6).
//!
//! Pure: node ids, a three-valued node kind, child weights and link counts
//! in; positions out. No text enters (design §2: the force layout may run off
//! the prod box on ids and edge structure only), and there is no database, no
//! clock and no randomness.
//!
//! # Determinism
//!
//! * Every input is normalised first: nodes sorted by id, edges folded to
//!   undirected `(min, max)` pairs and deduplicated, self-loops dropped. The
//!   layout uses neither edge direction nor relationship name.
//! * A node's starting point is derived from SHA-256(seed id ‖ node id)
//!   alone, the seed being the leaf's or group's stable id.
//! * The iteration count is fixed. The collision sweeps stop at the first
//!   sweep that moves nothing, which is itself deterministic.
//! * Only `+ - * /` and `sqrt` are used. IEEE 754 rounds them correctly on
//!   every host, so a remote lane and the prod box give the same bytes.
//! * Positions are rounded to 1e-4 ([`super::math::round4`]), and every
//!   guarantee below holds for the rounded values.
//!
//! # The frame (W10a contract, schema v1)
//!
//! `x` and `y` lie in [-1, 1] and a group child's `r` in (0, 1]. A leaf's
//! nodes lie inside the disc of radius [`LEAF_RADIUS`], so a leaf drawn in its
//! parent's child circle stays inside it. A group's child circles lie inside
//! the disc of radius [`GROUP_FIT_RADIUS`] and do not overlap.
//!
//! # The input hash
//!
//! [`leaf_input_hash`] and [`group_input_hash`] digest the algorithm tag, every
//! constant, the seed and the normalised input: exactly what the positions
//! depend on. The nightly stores them with the run and skips a level whose
//! hash has not changed (see `super::fill`).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::math::round4;

/// The algorithm tag every input hash starts with. Change it whenever the
/// arithmetic changes, so a stored layout is not reused under new rules.
pub const LAYOUT_ALGO: &str = "atlas-w6-v1";

/// A leaf's nodes lie inside this disc (after rounding).
pub const LEAF_RADIUS: f64 = 0.95;

/// No two nodes of a leaf are closer than this (after rounding).
pub const LEAF_MIN_DISTANCE: f64 = 0.025;

/// The collision sweeps separate nodes to this distance, so rounding (at most
/// `sqrt(2) * 5e-5` per point) cannot bring two below [`LEAF_MIN_DISTANCE`].
const LEAF_SPACING: f64 = 0.03;

/// The sweeps keep nodes inside this radius, so rounding cannot take one
/// past [`LEAF_RADIUS`].
const LEAF_CLAMP: f64 = LEAF_RADIUS - 2e-4;

/// Fruchterman-Reingold iterations per leaf.
pub const LEAF_ITERATIONS: usize = 150;

/// The ideal edge length is `LEAF_K_SCALE * sqrt(disc area / n)`.
const LEAF_K_SCALE: f64 = 0.75;

/// Pull toward the centre, so an unlinked node or a separate component
/// stays near the rest instead of drifting to the rim.
const LEAF_GRAVITY: f64 = 0.05;

/// The first iteration's largest step; it cools linearly to 0.
const LEAF_START_TEMPERATURE: f64 = 0.1;

/// Upper bound on collision sweeps (they usually stop after a few).
const COLLISION_SWEEPS: usize = 1000;

/// A group's child circles lie inside this disc (after rounding).
pub const GROUP_FIT_RADIUS: f64 = 0.98;

/// The child circles cover this share of the disc before the fit.
const GROUP_FILL: f64 = 0.55;

/// The gap kept between two child circles before the fit.
const GROUP_PADDING: f64 = 0.01;

/// Force iterations per group level.
pub const GROUP_ITERATIONS: usize = 200;

/// How hard a link pulls two children together, per iteration.
const GROUP_LINK_PULL: f64 = 0.1;

/// How hard every child is pulled toward the centre, per iteration.
const GROUP_GRAVITY: f64 = 0.02;

/// The smallest radius a child gets (the contract needs `r > 0`).
pub const GROUP_MIN_RADIUS: f64 = 1e-4;

/// Below this two points count as coincident.
const COINCIDENT: f64 = 1e-12;

/// The kind of a leaf node: the only fact about a node, besides its id, the
/// layout sees.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LayoutNodeKind {
    Claim,
    Agent,
    Evidence,
}

impl LayoutNodeKind {
    const fn code(self) -> u8 {
        match self {
            Self::Claim => 1,
            Self::Agent => 2,
            Self::Evidence => 3,
        }
    }
}

/// A malformed layout input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LayoutError {
    /// One id given twice with different kinds, or one child id twice.
    DuplicateNode(Uuid),
    /// An edge or link names an id that is not a node or child.
    UnknownEndpoint(Uuid),
}

impl fmt::Display for LayoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateNode(id) => write!(f, "node {id} is given twice"),
            Self::UnknownEndpoint(id) => write!(f, "an edge names {id}, which is not a node"),
        }
    }
}

impl std::error::Error for LayoutError {}

/// One leaf's layout input, normalised: nodes sorted by id, edges as sorted,
/// deduplicated undirected `(min, max)` pairs with no self-loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafInput {
    nodes: Vec<(Uuid, LayoutNodeKind)>,
    edges: Vec<(Uuid, Uuid)>,
}

impl LeafInput {
    /// Normalise `nodes` and `edges`, in any order. The same id given twice
    /// with the same kind is one node; an edge given in both directions, or
    /// twice under different relationships, is one pair.
    ///
    /// # Errors
    /// [`LayoutError::DuplicateNode`] for an id given with two kinds,
    /// [`LayoutError::UnknownEndpoint`] for an edge end that is not a node.
    pub fn new(
        nodes: impl IntoIterator<Item = (Uuid, LayoutNodeKind)>,
        edges: impl IntoIterator<Item = (Uuid, Uuid)>,
    ) -> Result<Self, LayoutError> {
        let mut kinds: BTreeMap<Uuid, LayoutNodeKind> = BTreeMap::new();
        for (id, kind) in nodes {
            if let Some(prev) = kinds.insert(id, kind) {
                if prev != kind {
                    return Err(LayoutError::DuplicateNode(id));
                }
            }
        }
        let mut pairs = BTreeSet::new();
        for (a, b) in edges {
            for end in [a, b] {
                if !kinds.contains_key(&end) {
                    return Err(LayoutError::UnknownEndpoint(end));
                }
            }
            if a != b {
                pairs.insert((a.min(b), a.max(b)));
            }
        }
        Ok(Self {
            nodes: kinds.into_iter().collect(),
            edges: pairs.into_iter().collect(),
        })
    }

    /// The nodes, sorted by id.
    #[must_use]
    pub fn nodes(&self) -> &[(Uuid, LayoutNodeKind)] {
        &self.nodes
    }

    /// The undirected pairs, sorted.
    #[must_use]
    pub fn edges(&self) -> &[(Uuid, Uuid)] {
        &self.edges
    }
}

/// One group level's layout input, normalised: children sorted by id with
/// their weighted size; links as sorted undirected `(min, max)` pairs with
/// their counts summed, none from a child to itself and none of count 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupInput {
    children: Vec<(Uuid, u64)>,
    links: Vec<(Uuid, Uuid, u64)>,
}

impl GroupInput {
    /// Normalise `children` (id, size) and `links` (a, b, count), in any
    /// order and either direction.
    ///
    /// # Errors
    /// [`LayoutError::DuplicateNode`] for a child id given twice,
    /// [`LayoutError::UnknownEndpoint`] for a link end that is not a child.
    pub fn new(
        children: impl IntoIterator<Item = (Uuid, u64)>,
        links: impl IntoIterator<Item = (Uuid, Uuid, u64)>,
    ) -> Result<Self, LayoutError> {
        let mut sizes: BTreeMap<Uuid, u64> = BTreeMap::new();
        for (id, size) in children {
            if sizes.insert(id, size).is_some() {
                return Err(LayoutError::DuplicateNode(id));
            }
        }
        let mut counts: BTreeMap<(Uuid, Uuid), u64> = BTreeMap::new();
        for (a, b, n) in links {
            for end in [a, b] {
                if !sizes.contains_key(&end) {
                    return Err(LayoutError::UnknownEndpoint(end));
                }
            }
            if a != b && n > 0 {
                let c = counts.entry((a.min(b), a.max(b))).or_insert(0);
                *c = c.saturating_add(n);
            }
        }
        Ok(Self {
            children: sizes.into_iter().collect(),
            links: counts.into_iter().map(|((a, b), n)| (a, b, n)).collect(),
        })
    }

    /// The children, sorted by id, with their sizes.
    #[must_use]
    pub fn children(&self) -> &[(Uuid, u64)] {
        &self.children
    }

    /// The links, sorted, with their summed counts.
    #[must_use]
    pub fn links(&self) -> &[(Uuid, Uuid, u64)] {
        &self.links
    }
}

/// One child's placement in its parent's unit frame.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Circle {
    pub x: f64,
    pub y: f64,
    pub r: f64,
}

// ── hashing ─────────────────────────────────────────────────────────────────

fn hash_header(h: &mut Sha256, part: &[u8], seed: Uuid, constants: &[f64], counts: &[usize]) {
    h.update(LAYOUT_ALGO.as_bytes());
    h.update([0u8]);
    h.update(part);
    h.update([0u8]);
    for c in constants {
        h.update(c.to_bits().to_le_bytes());
    }
    for c in counts {
        h.update((*c as u64).to_le_bytes());
    }
    h.update(seed.as_bytes());
}

/// Lower-hex SHA-256 of everything [`layout_leaf`] depends on: the algorithm
/// tag, its constants, `seed` and the normalised `input`. Two inputs with the
/// same hash get the same positions.
#[must_use]
pub fn leaf_input_hash(seed: Uuid, input: &LeafInput) -> String {
    let mut h = Sha256::new();
    hash_header(
        &mut h,
        b"leaf",
        seed,
        &[
            LEAF_RADIUS,
            LEAF_MIN_DISTANCE,
            LEAF_SPACING,
            LEAF_CLAMP,
            LEAF_K_SCALE,
            LEAF_GRAVITY,
            LEAF_START_TEMPERATURE,
        ],
        &[LEAF_ITERATIONS, COLLISION_SWEEPS],
    );
    h.update((input.nodes.len() as u64).to_le_bytes());
    for (id, kind) in &input.nodes {
        h.update(id.as_bytes());
        h.update([kind.code()]);
    }
    h.update((input.edges.len() as u64).to_le_bytes());
    for (a, b) in &input.edges {
        h.update(a.as_bytes());
        h.update(b.as_bytes());
    }
    hex::encode(h.finalize())
}

/// Lower-hex SHA-256 of everything [`layout_group`] depends on.
#[must_use]
pub fn group_input_hash(seed: Uuid, input: &GroupInput) -> String {
    let mut h = Sha256::new();
    hash_header(
        &mut h,
        b"group",
        seed,
        &[
            GROUP_FIT_RADIUS,
            GROUP_FILL,
            GROUP_PADDING,
            GROUP_LINK_PULL,
            GROUP_GRAVITY,
            GROUP_MIN_RADIUS,
        ],
        &[GROUP_ITERATIONS, COLLISION_SWEEPS],
    );
    h.update((input.children.len() as u64).to_le_bytes());
    for (id, size) in &input.children {
        h.update(id.as_bytes());
        h.update(size.to_le_bytes());
    }
    h.update((input.links.len() as u64).to_le_bytes());
    for (a, b, n) in &input.links {
        h.update(a.as_bytes());
        h.update(b.as_bytes());
        h.update(n.to_le_bytes());
    }
    hex::encode(h.finalize())
}

// ── shared arithmetic ───────────────────────────────────────────────────────

/// A point in `[-1, 1)^2` derived from `seed` and `id` alone.
fn start_point(seed: Uuid, id: Uuid) -> [f64; 2] {
    let d = Sha256::new()
        .chain_update(b"atlas-w6-start\0")
        .chain_update(seed.as_bytes())
        .chain_update(id.as_bytes())
        .finalize();
    let mut a = [0u8; 8];
    let mut b = [0u8; 8];
    a.copy_from_slice(&d[0..8]);
    b.copy_from_slice(&d[8..16]);
    // The top 53 bits as a fraction in [0, 1): exact in an f64.
    let unit = |w: [u8; 8]| (u64::from_le_bytes(w) >> 11) as f64 / (1u64 << 53) as f64;
    [2.0 * unit(a) - 1.0, 2.0 * unit(b) - 1.0]
}

/// A fixed unit-ish direction for two coincident points `i < j`.
fn split_direction(i: usize, j: usize) -> [f64; 2] {
    let dx = 1.0 + (i % 7) as f64;
    let dy = 1.0 + (j % 5) as f64 - 3.0;
    let n = (dx * dx + dy * dy).sqrt();
    [dx / n, dy / n]
}

/// Subtract the mean, so the layout is centred on the origin.
fn centre(p: &mut [[f64; 2]]) {
    if p.is_empty() {
        return;
    }
    let n = p.len() as f64;
    let (mut cx, mut cy) = (0.0, 0.0);
    for q in p.iter() {
        cx += q[0];
        cy += q[1];
    }
    cx /= n;
    cy /= n;
    for q in p.iter_mut() {
        q[0] -= cx;
        q[1] -= cy;
    }
}

// ── the leaf layout ─────────────────────────────────────────────────────────

/// Lay out one leaf: `x`, `y` per node, keyed by node id.
///
/// Fruchterman-Reingold with a gravity term for [`LEAF_ITERATIONS`]
/// iterations from the seeded starting points, then centred and scaled so the
/// farthest node sits at the clamp radius, then collision sweeps until no two
/// nodes are closer than the spacing and none is outside the clamp radius.
/// Rounded to 1e-4. One node sits at the origin.
///
/// Cost: `O(n^2)` per iteration; the contract caps a leaf at 100 nodes.
#[must_use]
pub fn layout_leaf(seed: Uuid, input: &LeafInput) -> BTreeMap<Uuid, [f64; 2]> {
    let n = input.nodes.len();
    let mut out = BTreeMap::new();
    if n == 0 {
        return out;
    }
    if n == 1 {
        out.insert(input.nodes[0].0, [0.0, 0.0]);
        return out;
    }
    let index: BTreeMap<Uuid, usize> = input
        .nodes
        .iter()
        .enumerate()
        .map(|(i, (id, _))| (*id, i))
        .collect();
    let edges: Vec<(usize, usize)> = input
        .edges
        .iter()
        .map(|(a, b)| (index[a], index[b]))
        .collect();

    let mut p: Vec<[f64; 2]> = input
        .nodes
        .iter()
        .map(|(id, _)| {
            let s = start_point(seed, *id);
            [s[0] * 0.5, s[1] * 0.5]
        })
        .collect();

    // The disc's area (PI is a compile-time constant, not a libm call).
    let area = std::f64::consts::PI * LEAF_RADIUS * LEAF_RADIUS;
    let k = LEAF_K_SCALE * (area / n as f64).sqrt();
    let k2 = k * k;
    let mut disp = vec![[0.0_f64; 2]; n];
    for it in 0..LEAF_ITERATIONS {
        let t = LEAF_START_TEMPERATURE * (1.0 - it as f64 / LEAF_ITERATIONS as f64);
        for d in disp.iter_mut() {
            *d = [0.0, 0.0];
        }
        for i in 0..n {
            for j in (i + 1)..n {
                let mut dx = p[i][0] - p[j][0];
                let mut dy = p[i][1] - p[j][1];
                let mut d2 = dx * dx + dy * dy;
                if d2 < COINCIDENT {
                    let s = split_direction(i, j);
                    dx = s[0] * 1e-6;
                    dy = s[1] * 1e-6;
                    d2 = dx * dx + dy * dy;
                }
                // Repulsion k^2 / d along the unit vector: (dx, dy) * k^2 / d^2.
                let f = k2 / d2;
                disp[i][0] += dx * f;
                disp[i][1] += dy * f;
                disp[j][0] -= dx * f;
                disp[j][1] -= dy * f;
            }
        }
        for &(a, b) in &edges {
            let dx = p[a][0] - p[b][0];
            let dy = p[a][1] - p[b][1];
            let d = (dx * dx + dy * dy).sqrt();
            // Attraction d^2 / k along the unit vector: (dx, dy) * d / k.
            let f = d / k;
            disp[a][0] -= dx * f;
            disp[a][1] -= dy * f;
            disp[b][0] += dx * f;
            disp[b][1] += dy * f;
        }
        for i in 0..n {
            let mut dx = disp[i][0] - LEAF_GRAVITY * p[i][0] / k;
            let mut dy = disp[i][1] - LEAF_GRAVITY * p[i][1] / k;
            let len = (dx * dx + dy * dy).sqrt();
            if len > t && len > 0.0 {
                dx *= t / len;
                dy *= t / len;
            }
            p[i][0] += dx;
            p[i][1] += dy;
        }
    }

    centre(&mut p);
    let max = p
        .iter()
        .map(|q| (q[0] * q[0] + q[1] * q[1]).sqrt())
        .fold(0.0_f64, f64::max);
    if max > 0.0 && max.is_finite() {
        let f = LEAF_CLAMP / max;
        for q in &mut p {
            q[0] *= f;
            q[1] *= f;
        }
    }
    separate_points(&mut p);

    for ((id, _), q) in input.nodes.iter().zip(&p) {
        out.insert(*id, [round4(q[0]), round4(q[1])]);
    }
    out
}

/// Push points apart until none are closer than [`LEAF_SPACING`] and none is
/// outside [`LEAF_CLAMP`], or [`COLLISION_SWEEPS`] sweeps have run.
fn separate_points(p: &mut [[f64; 2]]) {
    let n = p.len();
    for _ in 0..COLLISION_SWEEPS {
        let mut moved = false;
        for i in 0..n {
            for j in (i + 1)..n {
                let mut dx = p[j][0] - p[i][0];
                let mut dy = p[j][1] - p[i][1];
                let mut d = (dx * dx + dy * dy).sqrt();
                if d >= LEAF_SPACING {
                    continue;
                }
                if d < COINCIDENT {
                    let s = split_direction(i, j);
                    dx = s[0];
                    dy = s[1];
                    d = 1.0;
                } else {
                    dx /= d;
                    dy /= d;
                }
                // Half the shortfall each, plus a hair so the pair clears it.
                let push = (LEAF_SPACING - d) / 2.0 + 1e-9;
                p[i][0] -= dx * push;
                p[i][1] -= dy * push;
                p[j][0] += dx * push;
                p[j][1] += dy * push;
                moved = true;
            }
        }
        for q in p.iter_mut() {
            let len = (q[0] * q[0] + q[1] * q[1]).sqrt();
            if len > LEAF_CLAMP {
                q[0] *= LEAF_CLAMP / len;
                q[1] *= LEAF_CLAMP / len;
                moved = true;
            }
        }
        if !moved {
            break;
        }
    }
}

// ── the group layout ────────────────────────────────────────────────────────

/// `r` rounded DOWN to 1e-4 and at least [`GROUP_MIN_RADIUS`]: rounding a
/// radius down cannot make two circles overlap or a circle leave the disc.
fn floor4(r: f64) -> f64 {
    ((r * 1e4).floor() / 1e4).max(GROUP_MIN_RADIUS)
}

/// Place one group level's children: `x`, `y`, `r` per child, keyed by child
/// id.
///
/// A child's circle has area proportional to its size (sizes below 1 count as
/// 1), so `r` is monotone in size. Children start at seeded points; each
/// iteration pulls linked children together (more for more links), pulls
/// every child toward the centre and pushes overlapping circles apart, the
/// lighter one further. Then collision sweeps until no circles overlap, then
/// one uniform scale fits every circle inside [`GROUP_FIT_RADIUS`]. A uniform
/// scale keeps both the non-overlap and the order of the radii. Positions are
/// rounded to 1e-4 and radii rounded down. One child sits at the origin and
/// fills the fit disc.
#[must_use]
pub fn layout_group(seed: Uuid, input: &GroupInput) -> BTreeMap<Uuid, Circle> {
    let m = input.children.len();
    let mut out = BTreeMap::new();
    if m == 0 {
        return out;
    }
    let w: Vec<f64> = input
        .children
        .iter()
        .map(|(_, s)| (*s).max(1) as f64)
        .collect();
    let total: f64 = w.iter().sum();
    let scale = (GROUP_FILL / total).sqrt();
    let mut r: Vec<f64> = w.iter().map(|x| x.sqrt() * scale).collect();

    let mut p: Vec<[f64; 2]> = if m == 1 {
        vec![[0.0, 0.0]]
    } else {
        input
            .children
            .iter()
            .map(|(id, _)| {
                let s = start_point(seed, *id);
                [s[0] * 0.5, s[1] * 0.5]
            })
            .collect()
    };
    let index: BTreeMap<Uuid, usize> = input
        .children
        .iter()
        .enumerate()
        .map(|(i, (id, _))| (*id, i))
        .collect();
    let links: Vec<(usize, usize, f64)> = input
        .links
        .iter()
        .map(|(a, b, c)| {
            let c = *c as f64;
            (index[a], index[b], c / (c + 1.0))
        })
        .collect();

    if m > 1 {
        for it in 0..GROUP_ITERATIONS {
            let alpha = 1.0 - it as f64 / GROUP_ITERATIONS as f64;
            for &(a, b, strength) in &links {
                let dx = p[b][0] - p[a][0];
                let dy = p[b][1] - p[a][1];
                let d = (dx * dx + dy * dy).sqrt();
                let gap = d - (r[a] + r[b] + GROUP_PADDING);
                if gap <= 0.0 || d < COINCIDENT {
                    continue;
                }
                let pull = gap * GROUP_LINK_PULL * strength * alpha;
                let (sa, sb) = (w[b] / (w[a] + w[b]), w[a] / (w[a] + w[b]));
                p[a][0] += dx / d * pull * sa;
                p[a][1] += dy / d * pull * sa;
                p[b][0] -= dx / d * pull * sb;
                p[b][1] -= dy / d * pull * sb;
            }
            for q in &mut p {
                q[0] -= q[0] * GROUP_GRAVITY * alpha;
                q[1] -= q[1] * GROUP_GRAVITY * alpha;
            }
            separate_circles_once(&mut p, &r, &w);
        }
        for _ in 0..COLLISION_SWEEPS {
            if !separate_circles_once(&mut p, &r, &w) {
                break;
            }
        }
        // Centre on the size-weighted mean.
        let (mut cx, mut cy) = (0.0, 0.0);
        for (q, wi) in p.iter().zip(&w) {
            cx += q[0] * wi;
            cy += q[1] * wi;
        }
        cx /= total;
        cy /= total;
        for q in &mut p {
            q[0] -= cx;
            q[1] -= cy;
        }
    }

    let extent = p
        .iter()
        .zip(&r)
        .map(|(q, ri)| (q[0] * q[0] + q[1] * q[1]).sqrt() + ri)
        .fold(0.0_f64, f64::max);
    // Leave room for rounding the centres (at most sqrt(2) * 5e-5).
    let f = (GROUP_FIT_RADIUS - 1e-4) / extent;
    for (q, ri) in p.iter_mut().zip(r.iter_mut()) {
        q[0] *= f;
        q[1] *= f;
        *ri *= f;
    }

    for (((id, _), q), ri) in input.children.iter().zip(&p).zip(&r) {
        out.insert(
            *id,
            Circle {
                x: round4(q[0]),
                y: round4(q[1]),
                r: floor4(*ri),
            },
        );
    }
    out
}

/// One sweep pushing apart every pair of circles closer than their radii plus
/// the padding, the lighter circle further. Returns whether anything moved.
fn separate_circles_once(p: &mut [[f64; 2]], r: &[f64], w: &[f64]) -> bool {
    let m = p.len();
    let mut moved = false;
    for i in 0..m {
        for j in (i + 1)..m {
            let want = r[i] + r[j] + GROUP_PADDING;
            let mut dx = p[j][0] - p[i][0];
            let mut dy = p[j][1] - p[i][1];
            let mut d = (dx * dx + dy * dy).sqrt();
            if d >= want {
                continue;
            }
            if d < COINCIDENT {
                let s = split_direction(i, j);
                dx = s[0];
                dy = s[1];
                d = 0.0;
            } else {
                dx /= d;
                dy /= d;
            }
            let short = want - d + 1e-9;
            let (si, sj) = (w[j] / (w[i] + w[j]), w[i] / (w[i] + w[j]));
            p[i][0] -= dx * short * si;
            p[i][1] -= dy * short * si;
            p[j][0] += dx * short * sj;
            p[j][1] += dy * short * sj;
            moved = true;
        }
    }
    moved
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// A small deterministic generator for test graphs (splitmix64).
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
        fn uuid(&mut self) -> Uuid {
            Uuid::from_u64_pair(self.next(), self.next())
        }
    }

    fn kind_of(i: usize) -> LayoutNodeKind {
        match i % 5 {
            0..=2 => LayoutNodeKind::Claim,
            3 => LayoutNodeKind::Agent,
            _ => LayoutNodeKind::Evidence,
        }
    }

    /// `n` nodes and about `edges` random edges.
    fn random_leaf(seed: u64, n: usize, edges: usize) -> (Vec<Uuid>, LeafInput) {
        let mut rng = Rng(seed);
        let ids: Vec<Uuid> = (0..n).map(|_| rng.uuid()).collect();
        let e: Vec<(Uuid, Uuid)> = (0..edges)
            .map(|_| (ids[rng.below(n)], ids[rng.below(n)]))
            .collect();
        let input = LeafInput::new(ids.iter().enumerate().map(|(i, id)| (*id, kind_of(i))), e)
            .expect("valid");
        (ids, input)
    }

    /// `clusters` cliques of `per` nodes, joined in a ring by one edge each.
    fn clustered_leaf(clusters: usize, per: usize) -> LeafInput {
        let mut rng = Rng(7);
        let ids: Vec<Uuid> = (0..clusters * per).map(|_| rng.uuid()).collect();
        let mut edges = Vec::new();
        for c in 0..clusters {
            for a in 0..per {
                for b in (a + 1)..per {
                    edges.push((ids[c * per + a], ids[c * per + b]));
                }
            }
            edges.push((ids[c * per], ids[((c + 1) % clusters) * per]));
        }
        LeafInput::new(ids.iter().map(|id| (*id, LayoutNodeKind::Claim)), edges).expect("valid")
    }

    fn dist(a: [f64; 2], b: [f64; 2]) -> f64 {
        ((a[0] - b[0]) * (a[0] - b[0]) + (a[1] - b[1]) * (a[1] - b[1])).sqrt()
    }

    fn min_pair_distance(pos: &BTreeMap<Uuid, [f64; 2]>) -> f64 {
        let v: Vec<[f64; 2]> = pos.values().copied().collect();
        let mut best = f64::INFINITY;
        for i in 0..v.len() {
            for j in (i + 1)..v.len() {
                best = best.min(dist(v[i], v[j]));
            }
        }
        best
    }

    fn seed() -> Uuid {
        Uuid::from_u64_pair(0xA71A5, 0x6)
    }

    #[test]
    fn leaf_nodes_keep_the_minimum_distance_and_stay_inside_the_disc() {
        // Random graphs of every size up to the cap, plus a graph where
        // every node starts on one point's worth of structure (a star).
        for s in 0..40u64 {
            let n = 2 + (s as usize * 7) % 99;
            let (_, input) = random_leaf(s, n, n * 2);
            let pos = layout_leaf(seed(), &input);
            assert_eq!(pos.len(), n);
            let min = min_pair_distance(&pos);
            assert!(
                min >= LEAF_MIN_DISTANCE,
                "seed {s}, n {n}: min distance {min}"
            );
            let mut farthest = 0.0_f64;
            for (id, q) in &pos {
                let r = (q[0] * q[0] + q[1] * q[1]).sqrt();
                assert!(r <= LEAF_RADIUS, "seed {s}: {id} at radius {r}");
                assert!(q[0].abs() <= 1.0 && q[1].abs() <= 1.0);
                farthest = farthest.max(r);
            }
            // The layout uses the disc it is given, not a corner of it.
            assert!(
                farthest >= 0.9 * LEAF_RADIUS,
                "seed {s}: farthest node at {farthest}"
            );
        }
        let mut rng = Rng(99);
        let hub = rng.uuid();
        let spokes: Vec<Uuid> = (0..99).map(|_| rng.uuid()).collect();
        let star = LeafInput::new(
            std::iter::once((hub, LayoutNodeKind::Agent))
                .chain(spokes.iter().map(|s| (*s, LayoutNodeKind::Claim))),
            spokes.iter().map(|s| (hub, *s)),
        )
        .unwrap();
        let pos = layout_leaf(seed(), &star);
        assert!(min_pair_distance(&pos) >= LEAF_MIN_DISTANCE);
    }

    #[test]
    fn connected_nodes_sit_closer_than_unconnected_ones() {
        for input in [
            clustered_leaf(5, 12),
            random_leaf(3, 100, 150).1,
            random_leaf(4, 40, 60).1,
        ] {
            let pos = layout_leaf(seed(), &input);
            let linked: BTreeSet<(Uuid, Uuid)> = input.edges().iter().copied().collect();
            let ids: Vec<Uuid> = pos.keys().copied().collect();
            let (mut on, mut non, mut off, mut noff) = (0.0, 0usize, 0.0, 0usize);
            for i in 0..ids.len() {
                for j in (i + 1)..ids.len() {
                    let d = dist(pos[&ids[i]], pos[&ids[j]]);
                    if linked.contains(&(ids[i], ids[j])) {
                        on += d;
                        non += 1;
                    } else {
                        off += d;
                        noff += 1;
                    }
                }
            }
            let (on, off) = (on / non as f64, off / noff as f64);
            // Not merely closer: at most two thirds of the unlinked mean.
            assert!(on < off * 0.67, "linked mean {on}, unlinked mean {off}");
        }
    }

    #[test]
    fn the_same_input_gives_byte_identical_positions_whatever_the_input_order() {
        let (ids, input) = random_leaf(11, 80, 160);
        let a = layout_leaf(seed(), &input);
        let b = layout_leaf(seed(), &input);
        let ja = serde_json::to_string(&a.iter().collect::<Vec<_>>()).unwrap();
        assert_eq!(
            ja,
            serde_json::to_string(&b.iter().collect::<Vec<_>>()).unwrap()
        );

        // The same graph given in reverse node order, with every edge
        // reversed and repeated: the same bytes.
        let rev = LeafInput::new(
            ids.iter()
                .enumerate()
                .rev()
                .map(|(i, id)| (*id, kind_of(i))),
            input
                .edges()
                .iter()
                .rev()
                .flat_map(|(x, y)| [(*y, *x), (*x, *y)]),
        )
        .unwrap();
        assert_eq!(rev, input);
        let c = layout_leaf(seed(), &rev);
        assert_eq!(
            ja,
            serde_json::to_string(&c.iter().collect::<Vec<_>>()).unwrap()
        );

        // Another seed is another layout of the same graph.
        let other = layout_leaf(Uuid::from_u64_pair(1, 2), &input);
        assert_ne!(other, a);
    }

    #[test]
    fn a_full_leaf_lays_out_within_the_time_bound() {
        // The contract's cap (100 nodes) with dense edges (W10a allows 1024).
        let (_, input) = random_leaf(5, 100, 400);
        assert_eq!(input.nodes().len(), 100);
        let mut best = Duration::MAX;
        for _ in 0..5 {
            let t = Instant::now();
            let pos = layout_leaf(seed(), &input);
            best = best.min(t.elapsed());
            assert_eq!(pos.len(), 100);
        }
        eprintln!("atlas W6: a 100-node leaf took {best:?} (best of 5)");
        assert!(best < Duration::from_millis(50), "took {best:?}");
    }

    #[test]
    fn small_leaves_are_placed() {
        let a = Uuid::from_u64_pair(0, 1);
        let b = Uuid::from_u64_pair(0, 2);
        let empty = LeafInput::new([], []).unwrap();
        assert!(layout_leaf(seed(), &empty).is_empty());
        let one = LeafInput::new([(a, LayoutNodeKind::Claim)], []).unwrap();
        assert_eq!(layout_leaf(seed(), &one)[&a], [0.0, 0.0]);
        let two = LeafInput::new(
            [(a, LayoutNodeKind::Claim), (b, LayoutNodeKind::Evidence)],
            [(b, a)],
        )
        .unwrap();
        let pos = layout_leaf(seed(), &two);
        assert!(dist(pos[&a], pos[&b]) >= LEAF_MIN_DISTANCE);
    }

    #[test]
    fn malformed_inputs_are_refused() {
        let a = Uuid::from_u64_pair(0, 1);
        let b = Uuid::from_u64_pair(0, 2);
        assert_eq!(
            LeafInput::new([(a, LayoutNodeKind::Claim), (a, LayoutNodeKind::Agent)], []),
            Err(LayoutError::DuplicateNode(a))
        );
        assert_eq!(
            LeafInput::new([(a, LayoutNodeKind::Claim)], [(a, b)]),
            Err(LayoutError::UnknownEndpoint(b))
        );
        assert_eq!(
            GroupInput::new([(a, 1), (a, 2)], []),
            Err(LayoutError::DuplicateNode(a))
        );
        assert_eq!(
            GroupInput::new([(a, 1)], [(b, a, 1)]),
            Err(LayoutError::UnknownEndpoint(b))
        );
        // A self-loop is dropped, not refused.
        let looped = LeafInput::new([(a, LayoutNodeKind::Claim)], [(a, a)]).unwrap();
        assert!(looped.edges().is_empty());
    }

    #[test]
    fn the_leaf_hash_changes_with_every_layout_input_and_nothing_else() {
        let (ids, input) = random_leaf(21, 30, 45);
        let h = leaf_input_hash(seed(), &input);
        assert_eq!(h.len(), 64);
        assert!(h
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        // Order and direction are not inputs.
        let shuffled = LeafInput::new(
            ids.iter()
                .enumerate()
                .rev()
                .map(|(i, id)| (*id, kind_of(i))),
            input.edges().iter().map(|(a, b)| (*b, *a)),
        )
        .unwrap();
        assert_eq!(leaf_input_hash(seed(), &shuffled), h);
        // The seed, an edge, a node and a kind each are.
        assert_ne!(leaf_input_hash(Uuid::from_u64_pair(9, 9), &input), h);
        let fewer = LeafInput::new(
            ids.iter().enumerate().map(|(i, id)| (*id, kind_of(i))),
            input.edges()[1..].iter().copied(),
        )
        .unwrap();
        assert_ne!(leaf_input_hash(seed(), &fewer), h);
        // As many edges, one of them moved to another pair.
        let free = ids
            .iter()
            .flat_map(|a| ids.iter().map(move |b| (*a.min(b), *a.max(b))))
            .find(|(a, b)| a != b && !input.edges().contains(&(*a, *b)))
            .expect("a free pair");
        let rewired = LeafInput::new(
            ids.iter().enumerate().map(|(i, id)| (*id, kind_of(i))),
            input.edges()[1..].iter().copied().chain([free]),
        )
        .unwrap();
        assert_eq!(rewired.edges().len(), input.edges().len());
        assert_ne!(leaf_input_hash(seed(), &rewired), h);
        let more = LeafInput::new(
            ids.iter()
                .enumerate()
                .map(|(i, id)| (*id, kind_of(i)))
                .chain([(Uuid::from_u64_pair(5, 5), LayoutNodeKind::Claim)]),
            input.edges().iter().copied(),
        )
        .unwrap();
        assert_ne!(leaf_input_hash(seed(), &more), h);
        let rekinded = LeafInput::new(
            ids.iter().enumerate().map(|(i, id)| (*id, kind_of(i + 1))),
            input.edges().iter().copied(),
        )
        .unwrap();
        assert_ne!(leaf_input_hash(seed(), &rekinded), h);
    }

    // ── groups ──────────────────────────────────────────────────────────────

    fn random_group(seed: u64, m: usize, links: usize) -> GroupInput {
        let mut rng = Rng(seed);
        let ids: Vec<Uuid> = (0..m).map(|_| rng.uuid()).collect();
        let sizes: Vec<u64> = (0..m).map(|_| 1 + rng.below(2000) as u64).collect();
        let l: Vec<(Uuid, Uuid, u64)> = (0..links)
            .map(|_| {
                (
                    ids[rng.below(m)],
                    ids[rng.below(m)],
                    1 + rng.below(30) as u64,
                )
            })
            .collect();
        GroupInput::new(ids.into_iter().zip(sizes), l).expect("valid")
    }

    fn assert_packed(input: &GroupInput, placed: &BTreeMap<Uuid, Circle>) {
        assert_eq!(placed.len(), input.children().len());
        let c: Vec<Circle> = placed.values().copied().collect();
        for (i, a) in c.iter().enumerate() {
            assert!(a.r > 0.0 && a.r <= 1.0, "r {}", a.r);
            assert!(a.x.abs() <= 1.0 && a.y.abs() <= 1.0);
            let reach = (a.x * a.x + a.y * a.y).sqrt() + a.r;
            assert!(reach <= GROUP_FIT_RADIUS, "circle {i} reaches {reach}");
            for b in &c[i + 1..] {
                let d = dist([a.x, a.y], [b.x, b.y]);
                assert!(d >= a.r + b.r, "overlap: d {d} < {} + {}", a.r, b.r);
            }
        }
    }

    #[test]
    fn group_circles_do_not_overlap_and_stay_inside_the_unit_disc() {
        for s in 0..30u64 {
            let m = 1 + (s as usize * 13) % 128;
            let input = random_group(s, m, m * 2);
            assert_packed(&input, &layout_group(seed(), &input));
        }
    }

    #[test]
    fn group_radii_are_monotone_in_size() {
        for s in 0..20u64 {
            let input = random_group(100 + s, 40, 60);
            let placed = layout_group(seed(), &input);
            let mut by_size: Vec<(u64, f64)> = input
                .children()
                .iter()
                .map(|(id, size)| (*size, placed[id].r))
                .collect();
            by_size.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.total_cmp(&b.1)));
            for w in by_size.windows(2) {
                assert!(
                    w[0].1 <= w[1].1,
                    "size {} has r {} > size {} r {}",
                    w[0].0,
                    w[0].1,
                    w[1].0,
                    w[1].1
                );
                if w[0].0 * 4 <= w[1].0 {
                    // Four times the size is twice the radius (area ∝ size).
                    assert!(w[0].1 < w[1].1, "{w:?}");
                }
            }
        }
    }

    #[test]
    fn linked_children_sit_closer_than_unlinked_ones() {
        // Two families of 6 equal children, densely linked inside each family.
        let mut rng = Rng(42);
        let ids: Vec<Uuid> = (0..12).map(|_| rng.uuid()).collect();
        let mut links = Vec::new();
        for fam in 0..2 {
            for a in 0..6 {
                for b in (a + 1)..6 {
                    links.push((ids[fam * 6 + a], ids[fam * 6 + b], 20));
                }
            }
        }
        let input = GroupInput::new(ids.iter().map(|id| (*id, 100)), links).unwrap();
        let placed = layout_group(seed(), &input);
        let (mut on, mut non, mut off, mut noff) = (0.0, 0, 0.0, 0);
        for i in 0..12 {
            for j in (i + 1)..12 {
                let a = placed[&ids[i]];
                let b = placed[&ids[j]];
                let d = dist([a.x, a.y], [b.x, b.y]);
                if i / 6 == j / 6 {
                    on += d;
                    non += 1;
                } else {
                    off += d;
                    noff += 1;
                }
            }
        }
        let (on, off) = (on / f64::from(non), off / f64::from(noff));
        assert!(on < off * 0.8, "linked mean {on}, unlinked mean {off}");
    }

    #[test]
    fn group_layout_is_deterministic_and_order_free_and_hashed() {
        let input = random_group(8, 50, 80);
        let a = layout_group(seed(), &input);
        let reordered = GroupInput::new(
            input.children().iter().rev().copied(),
            input
                .links()
                .iter()
                .rev()
                .flat_map(|(x, y, n)| [(*y, *x, n / 2), (*x, *y, n - n / 2)]),
        )
        .unwrap();
        assert_eq!(reordered, input);
        let b = layout_group(seed(), &reordered);
        assert_eq!(format!("{a:?}"), format!("{b:?}"));

        let h = group_input_hash(seed(), &input);
        assert_eq!(group_input_hash(seed(), &reordered), h);
        assert_ne!(group_input_hash(Uuid::from_u64_pair(3, 3), &input), h);
        let resized = GroupInput::new(
            input
                .children()
                .iter()
                .enumerate()
                .map(|(i, (id, s))| (*id, if i == 0 { s + 1 } else { *s })),
            input.links().iter().copied(),
        )
        .unwrap();
        assert_ne!(group_input_hash(seed(), &resized), h);
        let relinked = GroupInput::new(
            input.children().iter().copied(),
            input.links()[1..].iter().copied(),
        )
        .unwrap();
        assert_ne!(group_input_hash(seed(), &relinked), h);
        // A leaf and a group over the same ids never share a hash.
        let as_leaf = LeafInput::new(
            input
                .children()
                .iter()
                .map(|(id, _)| (*id, LayoutNodeKind::Claim)),
            [],
        )
        .unwrap();
        assert_ne!(leaf_input_hash(seed(), &as_leaf), h);
    }

    #[test]
    fn one_child_fills_the_fit_disc() {
        let a = Uuid::from_u64_pair(0, 1);
        let input = GroupInput::new([(a, 7)], []).unwrap();
        let c = layout_group(seed(), &input)[&a];
        assert_eq!((c.x, c.y), (0.0, 0.0));
        assert!(
            c.r > GROUP_FIT_RADIUS - 2e-4 && c.r <= GROUP_FIT_RADIUS,
            "{c:?}"
        );
        assert!(layout_group(seed(), &GroupInput::new([], []).unwrap()).is_empty());
    }
}
