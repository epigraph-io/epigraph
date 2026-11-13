/* EpiGraph Explorer — the Atlas nested levels: pure rendering rules.
 *
 * No DOM, no canvas, no fetch: every function here maps contract data
 * (services/explorer/contract/atlas_level/v1/schema.json) to numbers and
 * styles, so js-tests/atlas_nested.test.cjs can test it under node:test.
 * atlas.js loads it first and reads it as the global AtlasNested.
 *
 * - Belief as flow: an edge's look comes from its flow_basis, sign and
 *   flow_weight only, never from its relationship name (stored in either
 *   casing). Width grows with flow_weight; proxy (claim to claim, link
 *   strength x sign, no belief factor) is dashed and labelled an estimate;
 *   exact (evidence to claim, the stored mass) is solid; sign sets the tone
 *   (supporting or opposing) and which way particles run. A zero-weight edge
 *   (cites, an agent's authorship) is a hairline and carries no flow.
 * - Positions are the precomputed ones: leafPositions and placeChildren are
 *   affine maps into the parent circle, with no simulation and no settle.
 * - Colour still means truth_value, as on the region and theme levels; no
 *   belief figure is read.
 */
(function (global, factory) {
  'use strict';
  const api = factory();
  if (typeof module === 'object' && module && module.exports) module.exports = api;
  else global.AtlasNested = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const SCHEMA_VERSION = 1;
  /** A node fetches its children once it fills a third of the view (design §6). */
  const LOAD_FRACTION = 1 / 3;
  /** Leaf positions are in a unit square; 0.7 keeps its corners inside the circle. */
  const LEAF_SPREAD = 0.7;
  const PLACEHOLDER = 'Not yet named';
  const HAIRLINE = 0.6;
  const PROXY_DASH = [6, 4];
  /** Fraction of an edge a particle travels per second. */
  const PARTICLE_SPEED = 0.35;
  const HIERARCHIES = ['meaning', 'links'];
  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

  function uuid(v) {
    return typeof v === 'string' && UUID_RE.test(v) ? v : null;
  }

  function finite(v, dflt) {
    return typeof v === 'number' && Number.isFinite(v) ? v : dflt;
  }

  function clamp01(v) {
    return Math.max(0, Math.min(1, finite(v, 0)));
  }

  // ---- names ---------------------------------------------------------------

  /** A group's shown name: a neutral placeholder while it awaits (re)naming. */
  function displayName(entry) {
    if (!entry || entry.needs_naming || typeof entry.name !== 'string' || !entry.name) return PLACEHOLDER;
    return entry.name;
  }

  function isPlaceholder(entry) {
    return displayName(entry) === PLACEHOLDER;
  }

  // ---- belief as flow ------------------------------------------------------

  /** Stroke width (px at the reference zoom) for a flow weight in [0, 1]. */
  function flowWidth(weight) {
    const w = clamp01(weight);
    return w <= 0 ? HAIRLINE : 1 + 5 * w;
  }

  /** 1: belief moves source to target. -1: it pulls back out of the target. 0: none. */
  function flowDirection(sign) {
    if (sign === 1) return 1;
    if (sign === -1) return -1;
    return 0;
  }

  function particleCount(weight) {
    const w = clamp01(weight);
    return w <= 0 ? 0 : 1 + Math.round(3 * w);
  }

  /**
   * How a leaf edge is drawn. `basis` is exact | proxy | none; anything else
   * counts as none. Returns {width, dash, estimate, tone, direction,
   * particles, flows}. `tone` follows the sign whatever the weight; width,
   * direction and particles need a weight above 0 and a non-zero sign.
   */
  function edgeStyle(edge) {
    const e = edge || {};
    const basis = e.flow_basis === 'exact' || e.flow_basis === 'proxy' ? e.flow_basis : 'none';
    const weight = clamp01(e.flow_weight);
    const direction = flowDirection(e.sign);
    const flows = basis !== 'none' && weight > 0 && direction !== 0;
    return {
      basis,
      width: flows ? flowWidth(weight) : HAIRLINE,
      dash: basis === 'proxy' ? PROXY_DASH.slice() : [],
      estimate: basis === 'proxy',
      // The tone comes from the sign alone: a contradicting link stored with
      // strength 0 still reads as opposing, though it carries no flow.
      tone: direction > 0 ? 'support' : direction < 0 ? 'oppose' : 'neutral',
      direction: flows ? direction : 0,
      particles: flows ? particleCount(weight) : 0,
      flows,
    };
  }

  /**
   * Where along an edge (0 = source, 1 = target) each particle is at time
   * `t` seconds. Particles run toward the target for a supporting flow and
   * back toward the source for an opposing one. `phase` in [0, 1) staggers
   * edges.
   */
  function particleFractions(t, style, phase) {
    if (!style || !style.flows || style.particles <= 0 || style.direction === 0) return [];
    const n = style.particles;
    const base = (((finite(t, 0) * PARTICLE_SPEED + finite(phase, 0)) % 1) + 1) % 1;
    const out = [];
    for (let i = 0; i < n; i++) {
      const f = (base + i / n) % 1;
      out.push(style.direction > 0 ? f : 1 - f);
    }
    return out;
  }

  /** A stable phase in [0, 1) for an edge, from its endpoints. */
  function edgePhase(edge) {
    return hashUnit(String(edge && edge.source) + '>' + String(edge && edge.target));
  }

  function hashUnit(s) {
    let h = 2166136261;
    for (const c of String(s)) {
      h ^= c.charCodeAt(0);
      h = Math.imul(h, 16777619);
    }
    return (h >>> 0) / 4294967296;
  }

  /** The angle (radians) at which a stub toward `id` leaves its level. */
  function stubAngle(id) {
    return hashUnit(id) * 2 * Math.PI;
  }

  /** A bundle's width (px) among bundles whose largest count is `max`. */
  function bundleWidth(count, max) {
    const m = Math.max(1, finite(max, 1));
    return 1 + 7 * Math.sqrt(Math.max(0, finite(count, 0)) / m);
  }

  // ---- levels --------------------------------------------------------------

  function otherHierarchy(h) {
    return h === 'meaning' ? 'links' : h === 'links' ? 'meaning' : null;
  }

  /** The meaning/links switch: the counterpart level in the other hierarchy, or null. */
  function switchTarget(doc) {
    if (!doc || !doc.switch) return null;
    const level = uuid(doc.switch.level_id);
    const h = doc.switch.hierarchy;
    if (!level || HIERARCHIES.indexOf(h) < 0 || h !== otherHierarchy(doc.hierarchy)) return null;
    return { hierarchy: h, level_id: level };
  }

  /** Whether a document belongs to the picked map. */
  function mapMatches(doc, map) {
    if (!doc || !map) return false;
    if (map.scope === 'public') return doc.map_scope === 'public' && doc.map_group_id === null;
    return doc.map_scope === 'team' && !!map.group_id && doc.map_group_id === map.group_id;
  }

  /**
   * Why a fetched body is not the level asked for, or null when it is.
   * `want` = {levelId, map, hierarchy, kind?}.
   */
  function levelProblem(doc, want) {
    if (!doc || typeof doc !== 'object') return 'The level could not be read.';
    if (doc.schema_version !== SCHEMA_VERSION) return 'This level is in a newer format than this page reads.';
    if (doc.kind !== 'group' && doc.kind !== 'leaf') return 'The level could not be read.';
    if (want && want.levelId && doc.level_id !== want.levelId) return 'The answer was for another level.';
    if (want && want.map && !mapMatches(doc, want.map)) return 'This level belongs to another map.';
    if (want && want.hierarchy && doc.hierarchy !== want.hierarchy) return 'The answer was for the other grouping.';
    if (want && want.kind && doc.kind !== want.kind) return 'The level is not the kind its parent said.';
    return null;
  }

  /** Group children placed in world space inside `parent` ({x, y, r}). */
  function placeChildren(parent, children) {
    return (children || [])
      .filter((c) => uuid(c && c.id))
      .map((c) => ({
        id: c.id,
        kind: c.kind === 'leaf' ? 'leaf' : 'group',
        x: parent.x + finite(c.x, 0) * parent.r,
        y: parent.y + finite(c.y, 0) * parent.r,
        r: Math.max(1e-12, finite(c.r, 0.05) * parent.r),
      }));
  }

  /** A leaf node's radius as a share of its leaf's radius. */
  function nodeRadius(kind, leafR) {
    return (kind === 'claim' ? 0.03 : 0.024) * leafR;
  }

  /** Leaf nodes in world space inside `leaf` ({x, y, r}): the served positions, scaled, never moved. */
  function leafPositions(leaf, nodes) {
    const s = LEAF_SPREAD * leaf.r;
    return (nodes || [])
      .filter((n) => uuid(n && n.id))
      .map((n) => ({
        id: n.id,
        kind: n.kind === 'agent' || n.kind === 'evidence' ? n.kind : 'claim',
        x: leaf.x + finite(n.x, 0) * s,
        y: leaf.y + finite(n.y, 0) * s,
        r: nodeRadius(n.kind, leaf.r),
      }));
  }

  /**
   * A group level's bundles, each resolved to a sibling child or a listed
   * outside target; unresolvable ones are dropped.
   */
  function resolveBundles(doc) {
    if (!doc || doc.kind !== 'group') return [];
    const kids = new Set((doc.children || []).map((c) => c.id));
    const targets = new Map((doc.targets || []).filter((t) => uuid(t.level_id)).map((t) => [t.level_id, t]));
    const out = [];
    for (const b of doc.bundles || []) {
      if (!kids.has(b.source) || b.source === b.target) continue;
      if (kids.has(b.target)) out.push({ source: b.source, target: b.target, count: b.count, net_sign: b.net_sign, sibling: true, to: null });
      else if (targets.has(b.target)) out.push({ source: b.source, target: b.target, count: b.count, net_sign: b.net_sign, sibling: false, to: targets.get(b.target) });
    }
    return out;
  }

  /** Whether a node `screenR` px in radius should fetch its children. */
  function shouldLoad(screenR, viewMin) {
    return finite(screenR, 0) >= finite(viewMin, 1) * LOAD_FRACTION;
  }

  /** The zoom ceiling: room to frame the smallest attached node, never below the base. */
  function maxZoom(baseMax, smallestR, viewMin) {
    const r = finite(smallestR, 0);
    if (r <= 0) return baseMax;
    return Math.max(baseMax, (finite(viewMin, 1) / (2.2 * r)) * 4);
  }

  /** The ids to fetch to attach a level under its theme: its ancestors, then itself. */
  function chainIds(doc) {
    const ids = (doc.breadcrumbs || []).map((b) => uuid(b.level_id)).filter(Boolean);
    ids.push(doc.level_id);
    return ids;
  }

  // ---- maps (the data-atlas-maps shell input) ------------------------------

  /** The data-atlas-maps version this page reads (contract/atlas_maps/v1). */
  const MAPS_SCHEMA_VERSION = 1;

  /**
   * A same-origin path prefix from the shell, or null: it starts with one
   * '/', ends with '/', and has no query, fragment or backslash.
   */
  function localPrefix(v) {
    if (typeof v !== 'string' || v.length < 2) return null;
    if (v.charAt(0) !== '/' || v.charAt(1) === '/' || v.charAt(v.length - 1) !== '/') return null;
    if (/[?#\\\s]/.test(v)) return null;
    return v;
  }

  /**
   * The maps a viewer may pick, from the page's data-atlas-maps JSON
   * (contract/atlas_maps/v1/schema.json), or [] when it is absent, malformed
   * or another version. Each map: {key, scope, group_id, label, level_url,
   * themes: [{theme_id, label, claim_count, roots: {meaning, links}}]}. A map
   * with no usable level_url is dropped: a level is always fetched through
   * its own map's URL, never a page-wide one.
   */
  function parseMaps(raw) {
    let body;
    try {
      body = typeof raw === 'string' ? JSON.parse(raw) : raw;
    } catch (e) {
      return [];
    }
    if (!body || body.schema_version !== MAPS_SCHEMA_VERSION) return [];
    const out = [];
    const keys = new Set();
    for (const m of (Array.isArray(body.maps) && body.maps) || []) {
      if (!m || (m.scope !== 'team' && m.scope !== 'public')) continue;
      const group = m.scope === 'team' ? uuid(m.group_id) : null;
      if (m.scope === 'team' && !group) continue;
      if (m.scope === 'public' && m.group_id !== null) continue;
      if (typeof m.key !== 'string' || !m.key || keys.has(m.key)) continue;
      const levelUrl = localPrefix(m.level_url);
      if (!levelUrl) continue;
      const themes = [];
      for (const t of Array.isArray(m.themes) ? m.themes : []) {
        const id = uuid(t && t.theme_id);
        const roots = (t && t.roots) || {};
        if (!id || !uuid(roots.meaning) || !uuid(roots.links)) continue;
        themes.push({
          theme_id: id,
          label: typeof t.label === 'string' && t.label ? t.label : null,
          claim_count: Math.max(0, finite(t.claim_count, 0)),
          roots: { meaning: roots.meaning, links: roots.links },
        });
      }
      keys.add(m.key);
      out.push({ key: m.key, scope: m.scope, group_id: group, label: typeof m.label === 'string' ? m.label : m.key, level_url: levelUrl, themes });
    }
    return out;
  }

  /**
   * The URL of one level: its map's level_url, then the hierarchy, then the
   * level id. A level is (map, hierarchy, group id), so all three are in the
   * request and the server reads one row. Null when any part is unusable.
   */
  function levelUrl(map, hierarchy, levelId) {
    if (!map || !localPrefix(map.level_url) || HIERARCHIES.indexOf(hierarchy) < 0 || !uuid(levelId)) return null;
    return map.level_url + hierarchy + '/' + levelId;
  }

  /** The level cache key: the same three parts as the request. */
  function levelKey(map, hierarchy, levelId) {
    return (map ? map.key : '') + '|' + hierarchy + '|' + levelId;
  }

  /** A theme's root level on `map` in `hierarchy`, or null. */
  function rootFor(map, themeId, hierarchy) {
    if (!map) return null;
    const t = map.themes.find((x) => x.theme_id === themeId);
    return t ? t.roots[hierarchy] || null : null;
  }

  return {
    SCHEMA_VERSION,
    LOAD_FRACTION,
    LEAF_SPREAD,
    PLACEHOLDER,
    HAIRLINE,
    displayName,
    isPlaceholder,
    flowWidth,
    flowDirection,
    particleCount,
    edgeStyle,
    particleFractions,
    edgePhase,
    stubAngle,
    bundleWidth,
    otherHierarchy,
    switchTarget,
    mapMatches,
    levelProblem,
    placeChildren,
    nodeRadius,
    leafPositions,
    resolveBundles,
    shouldLoad,
    maxZoom,
    chainIds,
    MAPS_SCHEMA_VERSION,
    localPrefix,
    parseMaps,
    levelUrl,
    levelKey,
    rootFor,
  };
});
