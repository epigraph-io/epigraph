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
//! constant, the seed and the normalised input: exactly what a cold layout
//! ([`layout_leaf`], [`layout_group`]) depends on. The nightly stores them
//! with the run and skips a level whose hash has not changed (see
//! `super::fill`), copying its stored positions.
//!
//! # Warm starts
//!
//! A level whose input did change is laid out again from its previous
//! positions ([`layout_leaf_from`], [`layout_group_from`]), so one new claim
//! does not rearrange its leaf, its parent and every level above. A warm
//! result depends on the previous positions too, so it is deterministic in
//! `(seed, input, previous)` but is not a function of the input hash alone.
//! The hash stays the skip key regardless: it says which input the stored
//! positions were made for, and the skip copies them rather than recomputing.
//! Folding the previous positions into the hash would make every warm-started
//! level miss the skip on every later night, since its previous positions
//! change each time it is laid out.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::math::round4;

/// The algorithm tag every input hash starts with. Change it whenever the
/// arithmetic changes, so a stored layout is not reused under new rules: a
/// run recorded under another tag is neither copied nor warm-started from
/// (`super::fill`), so every level is laid out cold again.
/// `tests::the_layout_output_is_pinned_to_the_algorithm_tag` fails until it
/// is changed.
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

/// The first iteration's largest step when a leaf starts from its previous
/// positions ([`layout_leaf_from`]): a hundredth of the cold start's, so the
/// nodes that were already placed settle where they were. Measured on random
/// leaves of 40 and 99 nodes, one node or edge added or removed: the placed
/// nodes move 0.02 on average and at most 0.05 (a cold relayout: about 0.2
/// and up to 0.8).
const LEAF_WARM_TEMPERATURE: f64 = 0.001;

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

/// Iterations of a group level started from its previous circles
/// ([`layout_group_from`]).
const GROUP_WARM_ITERATIONS: usize = 50;

/// The pull toward the centre per warm iteration: weak, so the gaps left by
/// a removed or shrunk child close over a few nights without reordering.
/// Measured on random levels of 30 to 128 children, one child grown by one
/// claim: no other child moves more than 0.014 (a cold relayout: up to 1.3).
const GROUP_WARM_GRAVITY: f64 = 0.0005;

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
/// same hash get the same cold positions (a warm start also depends on the
/// previous positions; see the module docs).
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
    leaf_layout(seed, input, None)
}

/// Lay out one leaf again, starting from its `previous` positions (the
/// previous night's stored document), so a leaf that gained or lost a node or
/// an edge keeps its shape instead of being laid out from scratch.
///
/// A node `previous` places starts there; a new node starts at the mean of
/// its placed neighbours (offset by its seeded point, so two new nodes never
/// coincide), or at its seeded point when no neighbour is placed. The start
/// is centred and scaled to where the forces balance (the stored positions
/// were scaled to fit the disc), the force iterations run at
/// [`LEAF_WARM_TEMPERATURE`] instead of the cold start's, and the fit and the
/// collision sweeps are the cold layout's, so
/// every bound of [`layout_leaf`] holds. Entries of `previous` that are not
/// nodes of `input` are ignored. With no node in common it is
/// [`layout_leaf`].
///
/// Deterministic in `(seed, input, previous)`: the same three give the same
/// bytes. The positions are not a function of `input` alone, which is why the
/// skip in `super::fill` keys on the input hash and copies the stored
/// positions rather than recomputing them.
#[must_use]
pub fn layout_leaf_from(
    seed: Uuid,
    input: &LeafInput,
    previous: &BTreeMap<Uuid, [f64; 2]>,
) -> BTreeMap<Uuid, [f64; 2]> {
    leaf_layout(seed, input, Some(previous))
}

fn leaf_layout(
    seed: Uuid,
    input: &LeafInput,
    previous: Option<&BTreeMap<Uuid, [f64; 2]>>,
) -> BTreeMap<Uuid, [f64; 2]> {
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

    // The disc's area (PI is a compile-time constant, not a libm call).
    let area = std::f64::consts::PI * LEAF_RADIUS * LEAF_RADIUS;
    let k = LEAF_K_SCALE * (area / n as f64).sqrt();
    let k2 = k * k;

    let seeded = |id: Uuid| {
        let s = start_point(seed, id);
        [s[0] * 0.5, s[1] * 0.5]
    };
    let previous = previous.filter(|prev| input.nodes.iter().any(|(id, _)| prev.contains_key(id)));
    let mut p: Vec<[f64; 2]> = match previous {
        None => input.nodes.iter().map(|(id, _)| seeded(*id)).collect(),
        Some(prev) => warm_leaf_start(input, &edges, prev, k, seeded),
    };
    if previous.is_some() {
        // The stored positions were fitted to the disc; take them back to the
        // scale at which the forces balance, so the warm iterations move only
        // what changed instead of rescaling everything unevenly.
        centre(&mut p);
        let s = equilibrium_scale(&p, &edges, k);
        for q in &mut p {
            q[0] *= s;
            q[1] *= s;
        }
    }
    let start_temperature = if previous.is_some() {
        LEAF_WARM_TEMPERATURE
    } else {
        LEAF_START_TEMPERATURE
    };

    let mut disp = vec![[0.0_f64; 2]; n];
    for it in 0..LEAF_ITERATIONS {
        let t = start_temperature * (1.0 - it as f64 / LEAF_ITERATIONS as f64);
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

/// The uniform scale `s` at which the leaf forces on `p` (centred) balance
/// radially. The virial of the forces is `n(n-1)/2 * k^2` from repulsion
/// (scale-free), minus `s^3 * sum over edges of d^3 / k` from attraction,
/// minus `s^2 * sum of LEAF_GRAVITY * |p|^2 / k` from gravity; the root of
/// that cubic is found by a fixed number of Newton steps (`+ - * /` only).
/// 1 when there is nothing to balance.
fn equilibrium_scale(p: &[[f64; 2]], edges: &[(usize, usize)], k: f64) -> f64 {
    let n = p.len() as f64;
    let rep = n * (n - 1.0) / 2.0 * k * k;
    let mut att = 0.0;
    for &(a, b) in edges {
        let dx = p[a][0] - p[b][0];
        let dy = p[a][1] - p[b][1];
        let d2 = dx * dx + dy * dy;
        att += d2 * d2.sqrt() / k;
    }
    let grav: f64 = p
        .iter()
        .map(|q| LEAF_GRAVITY * (q[0] * q[0] + q[1] * q[1]) / k)
        .sum();
    if !(att + grav > 0.0 && (att + grav).is_finite()) {
        return 1.0;
    }
    let mut s = 1.0_f64;
    for _ in 0..60 {
        let f = att * s * s * s + grav * s * s - rep;
        let df = 3.0 * att * s * s + 2.0 * grav * s;
        if df <= 0.0 || !df.is_finite() {
            break;
        }
        let next = s - f / df;
        s = if next > 0.0 { next } else { s / 2.0 };
    }
    if s.is_finite() && s > 0.0 {
        s
    } else {
        1.0
    }
}

/// The warm starting points of a leaf: a placed node where it was, a new
/// node at the mean of its placed neighbours plus a quarter of the ideal edge
/// length along its seeded direction, or at its seeded point.
fn warm_leaf_start(
    input: &LeafInput,
    edges: &[(usize, usize)],
    prev: &BTreeMap<Uuid, [f64; 2]>,
    k: f64,
    seeded: impl Fn(Uuid) -> [f64; 2],
) -> Vec<[f64; 2]> {
    let placed: Vec<Option<[f64; 2]>> = input
        .nodes
        .iter()
        .map(|(id, _)| prev.get(id).copied())
        .collect();
    let mut sum = vec![[0.0_f64; 2]; placed.len()];
    let mut count = vec![0usize; placed.len()];
    for &(a, b) in edges {
        for (me, other) in [(a, b), (b, a)] {
            if placed[me].is_none() {
                if let Some(q) = placed[other] {
                    sum[me][0] += q[0];
                    sum[me][1] += q[1];
                    count[me] += 1;
                }
            }
        }
    }
    input
        .nodes
        .iter()
        .enumerate()
        .map(|(i, (id, _))| match placed[i] {
            Some(q) => q,
            None if count[i] > 0 => {
                // `seeded` is half the unit start point, so this is a
                // quarter of `k` along it.
                let s = seeded(*id);
                let c = count[i] as f64;
                [
                    sum[i][0] / c + s[0] * k * 0.5,
                    sum[i][1] / c + s[1] * k * 0.5,
                ]
            }
            None => seeded(*id),
        })
        .collect()
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
    group_layout(seed, input, None)
}

/// Place one group level's children again, starting from their `previous`
/// circles (the previous night's stored document), so a level whose
/// children grew, shrank, came or went keeps its arrangement instead of being
/// placed from scratch.
///
/// Every child's radius is computed from its size as in [`layout_group`].
/// A child `previous` places starts at its previous centre, taken back into
/// the frame before the fit: the cold layout's radii have squares summing to
/// [`GROUP_FILL`], so the previous fit scaled them by
/// `sqrt(sum of previous r^2 / GROUP_FILL)`, summed over every previous
/// circle. A new child starts just outside the placed ones, in the direction
/// of its linked placed siblings (weighted by link strength) or else of its
/// seeded point. Then [`GROUP_WARM_ITERATIONS`] rounds of a weak pull toward
/// the centre ([`GROUP_WARM_GRAVITY`]) and one collision sweep each, the
/// collision sweeps, the centring and the fit of [`layout_group`], so every
/// bound of it holds. There is no link pull and no cold-start contraction, so
/// a grown child pushes only its neighbours aside. Entries of `previous` that
/// are not children of `input` are left out of the placement (but counted in
/// the scale). With no child in common it is [`layout_group`].
///
/// Deterministic in `(seed, input, previous)`.
#[must_use]
pub fn layout_group_from(
    seed: Uuid,
    input: &GroupInput,
    previous: &BTreeMap<Uuid, Circle>,
) -> BTreeMap<Uuid, Circle> {
    group_layout(seed, input, Some(previous))
}

fn group_layout(
    seed: Uuid,
    input: &GroupInput,
    previous: Option<&BTreeMap<Uuid, Circle>>,
) -> BTreeMap<Uuid, Circle> {
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

    let warm = if m > 1 {
        previous.and_then(|prev| warm_group_start(seed, input, &r, &links, prev))
    } else {
        None
    };
    let is_warm = warm.is_some();
    let mut p: Vec<[f64; 2]> = if m == 1 {
        vec![[0.0, 0.0]]
    } else if let Some(p) = warm {
        p
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

    if m > 1 {
        if is_warm {
            for _ in 0..GROUP_WARM_ITERATIONS {
                for q in &mut p {
                    q[0] -= q[0] * GROUP_WARM_GRAVITY;
                    q[1] -= q[1] * GROUP_WARM_GRAVITY;
                }
                separate_circles_once(&mut p, &r, &w);
            }
        } else {
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

/// The warm starting centres of a group level, in the frame before the fit
/// ([`layout_group_from`]), or `None` when `prev` places no child of
/// `input` or holds no positive radius.
fn warm_group_start(
    seed: Uuid,
    input: &GroupInput,
    r: &[f64],
    links: &[(usize, usize, f64)],
    prev: &BTreeMap<Uuid, Circle>,
) -> Option<Vec<[f64; 2]>> {
    let sum_r2: f64 = prev.values().map(|c| c.r * c.r).sum();
    if !(sum_r2 > 0.0 && sum_r2.is_finite()) {
        return None;
    }
    let f_prev = (sum_r2 / GROUP_FILL).sqrt();
    let placed: Vec<Option<[f64; 2]>> = input
        .children
        .iter()
        .map(|(id, _)| prev.get(id).map(|c| [c.x / f_prev, c.y / f_prev]))
        .collect();
    if placed.iter().all(Option::is_none) {
        return None;
    }
    let extent = placed
        .iter()
        .zip(r)
        .filter_map(|(q, ri)| q.map(|q| (q[0] * q[0] + q[1] * q[1]).sqrt() + ri))
        .fold(0.0_f64, f64::max);

    let mut pull = vec![[0.0_f64; 2]; placed.len()];
    for &(a, b, strength) in links {
        for (me, other) in [(a, b), (b, a)] {
            if placed[me].is_none() {
                if let Some(q) = placed[other] {
                    pull[me][0] += q[0] * strength;
                    pull[me][1] += q[1] * strength;
                }
            }
        }
    }
    Some(
        input
            .children
            .iter()
            .enumerate()
            .map(|(i, (id, _))| {
                if let Some(q) = placed[i] {
                    return q;
                }
                let mut d = pull[i];
                let mut len = (d[0] * d[0] + d[1] * d[1]).sqrt();
                if len < COINCIDENT {
                    d = start_point(seed, *id);
                    len = (d[0] * d[0] + d[1] * d[1]).sqrt();
                }
                if len < COINCIDENT {
                    d = split_direction(i, i + 1);
                    len = 1.0;
                }
                let reach = extent + r[i] + GROUP_PADDING;
                [d[0] / len * reach, d[1] / len * reach]
            })
            .collect(),
    )
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
        // The contract's cap (100 nodes) with dense edges (W10a allows 1024),
        // cold and warm-started.
        //
        // The item's bound is 50 ms per leaf on one core, which is what the
        // nightly's optimised build must meet: it is asserted in a release
        // build (`cargo test --release`, run by the W6 gate). A debug build
        // (CI's parallel workspace job, on small shared runners) runs about
        // ten times slower and asserts ten times the bound, which still
        // catches a layout that is an order of magnitude too slow without
        // failing on a busy runner.
        let bound = if cfg!(debug_assertions) {
            Duration::from_millis(500)
        } else {
            Duration::from_millis(50)
        };
        let (_, input) = random_leaf(5, 100, 400);
        assert_eq!(input.nodes().len(), 100);
        let cold = layout_leaf(seed(), &input);
        let mut best = Duration::MAX;
        let mut best_warm = Duration::MAX;
        for _ in 0..5 {
            let t = Instant::now();
            let pos = layout_leaf(seed(), &input);
            best = best.min(t.elapsed());
            assert_eq!(pos.len(), 100);
            let t = Instant::now();
            let pos = layout_leaf_from(seed(), &input, &cold);
            best_warm = best_warm.min(t.elapsed());
            assert_eq!(pos.len(), 100);
        }
        eprintln!(
            "atlas W6: a 100-node leaf took {best:?} cold, {best_warm:?} warm (best of 5, bound {bound:?})"
        );
        assert!(best < bound, "took {best:?}");
        assert!(best_warm < bound, "warm took {best_warm:?}");
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
        // The contract's cap on children, for the build report (not a bound).
        let full = random_group(77, 128, 256);
        let t = Instant::now();
        let placed = layout_group(seed(), &full);
        eprintln!("atlas W6: a 128-child group took {:?}", t.elapsed());
        assert_packed(&full, &placed);
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

    // ── warm starts ─────────────────────────────────────────────────────────

    /// How far the children both maps place moved, leaving out `skip`:
    /// (how many moved more than their own previous radius, the largest
    /// move, the mean move).
    fn moved(
        before: &BTreeMap<Uuid, Circle>,
        after: &BTreeMap<Uuid, Circle>,
        skip: Option<Uuid>,
    ) -> (usize, f64, f64) {
        let (mut beyond, mut n, mut max, mut sum) = (0, 0, 0.0_f64, 0.0);
        for (id, a) in after {
            let Some(b) = before.get(id) else { continue };
            if Some(*id) == skip {
                continue;
            }
            let d = dist([a.x, a.y], [b.x, b.y]);
            beyond += usize::from(d > b.r);
            n += 1;
            max = max.max(d);
            sum += d;
        }
        (beyond, max, sum / n as f64)
    }

    fn resized(input: &GroupInput, id: Uuid, size: impl Fn(u64) -> u64) -> GroupInput {
        GroupInput::new(
            input
                .children()
                .iter()
                .map(|(c, s)| (*c, if *c == id { size(*s) } else { *s })),
            input.links().iter().copied(),
        )
        .unwrap()
    }

    #[test]
    fn a_group_relaid_from_its_previous_circles_keeps_them_where_they_were() {
        // Atlas W6 review: one new claim in a leaf changes `claim_count` on
        // every level above it, and a cold relayout of a level of 60 or more
        // children moved nearly every circle by most of the disc.
        for m in [30usize, 60, 128] {
            let input = random_group(500 + m as u64, m, 2 * m);
            let night1 = layout_group(seed(), &input);
            let first = input.children()[0].0;
            let added = Uuid::from_u64_pair(77, 77);
            let cases = [
                // (what changed, the level now, skip, max move, mean move)
                (
                    "one more claim",
                    resized(&input, first, |s| s + 1),
                    Some(first),
                    0.02,
                    0.01,
                ),
                (
                    "twice the claims",
                    resized(&input, first, |s| s * 2),
                    Some(first),
                    0.1,
                    0.03,
                ),
                (
                    "a child removed",
                    GroupInput::new(
                        input.children()[1..].iter().copied(),
                        input
                            .links()
                            .iter()
                            .copied()
                            .filter(|(a, b, _)| *a != first && *b != first),
                    )
                    .unwrap(),
                    None,
                    0.1,
                    0.02,
                ),
                (
                    "a child added",
                    GroupInput::new(
                        input.children().iter().copied().chain([(added, 500)]),
                        input.links().iter().copied().chain([(added, first, 5)]),
                    )
                    .unwrap(),
                    None,
                    0.2,
                    0.1,
                ),
            ];
            for (what, now, skip, max_bound, mean_bound) in cases {
                let night2 = layout_group_from(seed(), &now, &night1);
                assert_packed(&now, &night2);
                let (beyond, max, mean) = moved(&night1, &night2, skip);
                assert!(
                    max < max_bound && mean < mean_bound,
                    "m {m}, {what}: largest move {max}, mean {mean}"
                );
                if what == "one more claim" {
                    assert_eq!(beyond, 0, "m {m}: a circle moved more than its radius");
                }
                // Deterministic in (seed, input, previous).
                assert_eq!(
                    format!("{night2:?}"),
                    format!("{:?}", layout_group_from(seed(), &now, &night1))
                );
            }
        }
    }

    #[test]
    fn a_group_with_nothing_in_common_with_its_previous_circles_is_laid_out_cold() {
        let input = random_group(31, 40, 80);
        let unrelated = layout_group(seed(), &random_group(32, 40, 80));
        assert_eq!(
            layout_group_from(seed(), &input, &unrelated),
            layout_group(seed(), &input)
        );
        assert_eq!(
            layout_group_from(seed(), &input, &BTreeMap::new()),
            layout_group(seed(), &input)
        );
        let a = Uuid::from_u64_pair(0, 1);
        let one = GroupInput::new([(a, 7)], []).unwrap();
        let prev = BTreeMap::from([(
            a,
            Circle {
                x: 0.5,
                y: 0.0,
                r: 0.1,
            },
        )]);
        assert_eq!(
            layout_group_from(seed(), &one, &prev),
            layout_group(seed(), &one)
        );
    }

    #[test]
    fn a_leaf_relaid_from_its_previous_positions_keeps_them_where_they_were() {
        for n in [40usize, 99] {
            let (ids, input) = random_leaf(900 + n as u64, n, n * 2);
            let night1 = layout_leaf(seed(), &input);
            let new = Uuid::from_u64_pair(88, 88);
            let cases = [
                (
                    "a node and its edge added",
                    LeafInput::new(
                        input
                            .nodes()
                            .iter()
                            .copied()
                            .chain([(new, LayoutNodeKind::Claim)]),
                        input.edges().iter().copied().chain([(new, ids[0])]),
                    )
                    .unwrap(),
                ),
                (
                    "an edge removed",
                    LeafInput::new(
                        input.nodes().iter().copied(),
                        input.edges()[1..].iter().copied(),
                    )
                    .unwrap(),
                ),
            ];
            for (what, now) in cases {
                let night2 = layout_leaf_from(seed(), &now, &night1);
                assert_eq!(night2.len(), now.nodes().len());
                assert!(min_pair_distance(&night2) >= LEAF_MIN_DISTANCE);
                assert!(night2
                    .values()
                    .all(|q| (q[0] * q[0] + q[1] * q[1]).sqrt() <= LEAF_RADIUS));
                let (mut max, mut sum) = (0.0_f64, 0.0);
                for (id, q) in &night1 {
                    let d = dist(*q, night2[id]);
                    max = max.max(d);
                    sum += d;
                }
                let mean = sum / night1.len() as f64;
                assert!(
                    max < 0.1 && mean < 0.03,
                    "n {n}, {what}: largest move {max}, mean {mean}"
                );
                assert_eq!(night2, layout_leaf_from(seed(), &now, &night1));
            }
        }
        // Nothing in common: the cold layout.
        let (_, input) = random_leaf(3, 30, 45);
        let (_, other) = random_leaf(4, 30, 45);
        assert_eq!(
            layout_leaf_from(seed(), &input, &layout_leaf(seed(), &other)),
            layout_leaf(seed(), &input)
        );
    }

    /// Lower-hex SHA-256 of positions as `id x y r` lines (`{:?}` of an f64
    /// is its shortest round-trip form, so the text is the bits).
    fn digest(lines: impl Iterator<Item = String>) -> String {
        let mut h = Sha256::new();
        for l in lines {
            h.update(l.as_bytes());
            h.update(b"\n");
        }
        hex::encode(h.finalize())
    }

    #[test]
    fn the_layout_output_is_pinned_to_the_algorithm_tag() {
        // A stored level is reused while its input hash matches, and the hash
        // covers the tag and the constants but not the code. So a change to
        // the arithmetic must come with a new LAYOUT_ALGO; this pin fails
        // until both the tag and the digests below are updated together.
        // It is also the cross-host check: another architecture must give
        // these bytes.
        let (_, leaf) = random_leaf(5, 100, 400);
        let cold_leaf = layout_leaf(seed(), &leaf);
        let (ids, _) = random_leaf(5, 100, 400);
        let grown = LeafInput::new(
            leaf.nodes()
                .iter()
                .copied()
                .chain([(Uuid::from_u64_pair(88, 88), LayoutNodeKind::Claim)])
                .filter(|(id, _)| *id != ids[1]),
            leaf.edges()
                .iter()
                .copied()
                .filter(|(a, b)| *a != ids[1] && *b != ids[1])
                .chain([(Uuid::from_u64_pair(88, 88), ids[0])]),
        )
        .unwrap();
        let warm_leaf = layout_leaf_from(seed(), &grown, &cold_leaf);
        let group = random_group(77, 128, 256);
        let cold_group = layout_group(seed(), &group);
        let warm_group = layout_group_from(
            seed(),
            &resized(&group, group.children()[3].0, |s| s * 3),
            &cold_group,
        );
        let leaf_lines = |p: &BTreeMap<Uuid, [f64; 2]>| {
            p.iter()
                .map(|(id, q)| format!("{id} {:?} {:?}", q[0], q[1]))
                .collect::<Vec<_>>()
        };
        let group_lines = |p: &BTreeMap<Uuid, Circle>| {
            p.iter()
                .map(|(id, c)| format!("{id} {:?} {:?} {:?}", c.x, c.y, c.r))
                .collect::<Vec<_>>()
        };
        let got = [
            digest(leaf_lines(&cold_leaf).into_iter()),
            digest(leaf_lines(&warm_leaf).into_iter()),
            digest(group_lines(&cold_group).into_iter()),
            digest(group_lines(&warm_group).into_iter()),
        ];
        eprintln!("atlas W6 layout digests under {LAYOUT_ALGO}: {got:?}");
        assert_eq!(LAYOUT_ALGO, "atlas-w6-v1", "update the digests below too");
        assert_eq!(
            got,
            [
                "e947bdf92b216e9b5719c9ca3e98a7aa4595739852d81219c57e20fa9b39ff97",
                "982b5643909a69f9dedd8b45fa3f770af71a3ba40f50219c39264853001b1a43",
                "6d591e47392be1892a0dd503a4df691ce9b38cfbc529aaec4ec03f0f6f056d3c",
                "97927dc4110a314e9fd49510cf300f9acaaad5a028a8e51d43cfb19f35ef2d2c",
            ],
            "the layout output changed: bump LAYOUT_ALGO and re-pin"
        );
    }
}
