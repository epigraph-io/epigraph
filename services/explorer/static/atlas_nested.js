/* EpiGraph Explorer — the Atlas nested levels: pure rendering rules.
 *
 * No DOM, no canvas, no fetch of its own: every function here maps contract
 * data (services/explorer/contract/atlas_level/v1/schema.json) to numbers and
 * styles, so js-tests/atlas_nested.test.cjs can test it under node:test.
 * The one network step, the claim-to-leaf lookup, takes the page's getter
 * as an argument. atlas.js loads it first and reads it as the global
 * AtlasNested.
 *
 * - Belief as flow: an edge's look comes from its flow_basis, sign and
 *   flow_weight, never from its relationship name (stored in either
 *   casing). Width grows with flow_weight; proxy (claim to claim, link
 *   strength x sign, no belief factor) is dashed and labelled an estimate;
 *   exact (evidence to claim, the stored mass) is solid; sign sets the tone
 *   (supporting or opposing) and which way particles run. A zero-weight edge
 *   (cites, an agent's authorship) is a hairline and carries no flow.
 * - The one exception: evidence with no readable mass is served
 *   flow_basis none, weight 0 and sign 0 whatever it says, so a none edge
 *   from an evidence node to a claim node takes its tone from its
 *   relationship (supports; refutes or contradicts). It is drawn as a thin
 *   solid line with no flow ("evidence, no stored mass"), apart from both
 *   exact flows and dashed estimates. Any other none edge (an agent's, or
 *   one from a claim) stays a neutral hairline whatever it is called.
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
  /** A theme the picked map does not draw. */
  const NOT_ON_MAP = 'Not on this map';
  const HAIRLINE = 0.6;
  /** A massless evidence line: thicker than a hairline, thinner than any flow. */
  const NO_MASS_WIDTH = 0.9;
  /** A none edge's relationship, lower-cased, and the tone it reads as. */
  const NO_MASS_TONES = { supports: 'support', refutes: 'oppose', contradicts: 'oppose' };
  /** Stroke opacity: a flow, a massless evidence line, any other line. */
  const FLOW_ALPHA = 0.7;
  const NO_MASS_ALPHA = 0.55;
  const IDLE_ALPHA = 0.3;
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
   * The tone of a none evidence-to-claim edge that is evidence for or
   * against its claim, from its relationship (either casing), or null for
   * any other relationship. Its sign is 0, so the name is all there is.
   */
  function noMassTone(relationship) {
    if (typeof relationship !== 'string') return null;
    const key = relationship.toLowerCase();
    return Object.prototype.hasOwnProperty.call(NO_MASS_TONES, key) ? NO_MASS_TONES[key] : null;
  }

  /**
   * How a leaf edge is drawn. `basis` is exact | proxy | none; anything else
   * counts as none. `ends` = {source, target} are the kinds (claim |
   * evidence | agent) of the edge's two leaf nodes. Returns {basis, width,
   * alpha, dash, estimate, tone, direction, particles, flows, noMass}. For
   * exact and proxy edges `tone` follows the sign whatever the weight; width,
   * direction and particles need a weight above 0 and a non-zero sign. A none
   * edge never flows; one from an evidence node to a claim node that
   * supports, refutes or contradicts is evidence with no stored mass
   * (`noMass`), toned by that relationship and drawn NO_MASS_WIDTH wide at
   * NO_MASS_ALPHA, so its colour reads where a hairline's would not. Without
   * `ends`, or with any other pair of kinds, a none edge is a neutral
   * hairline: a name alone never makes an edge read as evidence.
   */
  function edgeStyle(edge, ends) {
    const e = edge || {};
    const basis = e.flow_basis === 'exact' || e.flow_basis === 'proxy' ? e.flow_basis : 'none';
    const weight = clamp01(e.flow_weight);
    const direction = flowDirection(e.sign);
    const flows = basis !== 'none' && weight > 0 && direction !== 0;
    const evidenceToClaim = !!ends && ends.source === 'evidence' && ends.target === 'claim';
    const massless = basis === 'none' && evidenceToClaim ? noMassTone(e.relationship) : null;
    // Otherwise the tone comes from the sign alone: a contradicting link
    // stored with strength 0 still reads as opposing, though it carries no
    // flow.
    const signTone = direction > 0 ? 'support' : direction < 0 ? 'oppose' : 'neutral';
    return {
      basis,
      width: flows ? flowWidth(weight) : massless ? NO_MASS_WIDTH : HAIRLINE,
      alpha: flows ? FLOW_ALPHA : massless ? NO_MASS_ALPHA : IDLE_ALPHA,
      dash: basis === 'proxy' ? PROXY_DASH.slice() : [],
      estimate: basis === 'proxy',
      tone: massless || signTone,
      direction: flows ? direction : 0,
      particles: flows ? particleCount(weight) : 0,
      flows,
      noMass: massless !== null,
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

  /**
   * A claim count's words. A map's counts (a theme on a map, a group, a leaf)
   * are stored when the map is built, and the server then drops what the
   * viewer cannot read, so they say "on this map", never "you can read".
   * Live counts from the viewer's own layout keep "you can read".
   */
  function countLabel(n, stored) {
    const v = Math.max(0, Math.round(finite(n, 0)));
    const noun = v === 1 ? ' claim' : ' claims';
    return v.toLocaleString() + noun + (stored ? ' on this map' : ' you can read');
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

  /**
   * The leaf, among already-fetched level documents, that draws claim
   * `claimId` as a claim node, or null. This is the first, free answer: when
   * it is null the caller asks the claim-to-leaf route (lookupClaimLeaf)
   * instead of inventing a place for the claim.
   */
  function findClaimLeaf(docs, claimId) {
    if (!uuid(claimId)) return null;
    for (const d of docs || []) {
      if (!d || d.kind !== 'leaf') continue;
      if ((d.nodes || []).some((n) => n && n.kind === 'claim' && n.id === claimId)) return d;
    }
    return null;
  }

  // ---- the claim-to-leaf lookup (contract atlas_claim_leaf v1) -------------

  /** The atlas_claim_leaf version this page reads. */
  const CLAIM_LEAF_SCHEMA_VERSION = 1;

  /**
   * The lookup URL for claim `claimId` on `map` in `hierarchy`: the page's
   * data-atlas-claim-leaf-url prefix, then the map key (one path segment),
   * the hierarchy and the claim id. Null when any part is unusable.
   */
  function claimLeafUrl(prefix, map, hierarchy, claimId) {
    if (!localPrefix(prefix) || !map || typeof map.key !== 'string' || !map.key) return null;
    if (HIERARCHIES.indexOf(hierarchy) < 0 || !uuid(claimId)) return null;
    return prefix + encodeURIComponent(map.key) + '/' + hierarchy + '/' + claimId;
  }

  /**
   * Why a claim-to-leaf body is not the answer asked for, or null when it is.
   * `want` = {claimId, map, hierarchy}. It must name the same claim, map and
   * hierarchy, and a theme and level by id.
   */
  function claimLeafProblem(body, want) {
    if (!body || typeof body !== 'object') return 'The claim’s place could not be read.';
    if (body.schema_version !== CLAIM_LEAF_SCHEMA_VERSION) return 'The claim’s place is in a newer format than this page reads.';
    if (!want || body.claim_id !== want.claimId) return 'The answer was for another claim.';
    if (!mapMatches(body, want.map)) return 'The answer was for another map.';
    if (body.hierarchy !== want.hierarchy) return 'The answer was for the other grouping.';
    if (!uuid(body.theme_id) || !uuid(body.level_id)) return 'The claim’s place could not be read.';
    return null;
  }

  /**
   * Ask which leaf of `map` in `hierarchy` draws claim `claimId`, through
   * `get(url)` (the page's JSON getter, which throws an error carrying
   * `status` on a non-2xx answer). Resolves to the checked body, or to null
   * when the route answers not-found (the claim is not on this map, or not
   * one the viewer can read: the route does not say which) or when there is
   * nothing to ask. Any other failure, and a body for another claim, map or
   * hierarchy, rejects.
   */
  async function lookupClaimLeaf(get, prefix, map, hierarchy, claimId) {
    const url = claimLeafUrl(prefix, map, hierarchy, claimId);
    if (!url) return null;
    let body;
    try {
      body = await get(url);
    } catch (e) {
      if (e && e.status === 404) return null;
      throw e;
    }
    const problem = claimLeafProblem(body, { claimId, map, hierarchy });
    if (problem) throw Object.assign(new Error(problem), { status: 0, kind: 'bad_claim_leaf' });
    return body;
  }

  /**
   * Which theme a cold claim link lands under, once the claim-to-leaf route
   * has answered with `place` (null for its not-found answer). `theme` is the
   * theme resolve named; `themeById(id)` is the page's loaded-theme lookup.
   * Returns {home} to fetch place.level_id and attach it under `home`, or
   * {notice} to stop at `theme` with that notice. The picked map, not
   * resolve, decides the theme: a place in another loaded theme re-homes
   * there, so its chain is never attached under the wrong theme.
   */
  function coldClaimHome(theme, place, themeById) {
    if (!place) return { notice: 'That claim is not on the map you picked.' };
    if (theme && place.theme_id === theme.id) return { home: theme };
    const home = typeof themeById === 'function' ? themeById(place.theme_id) : null;
    if (!home) return { notice: 'On the map you picked, that claim is in a theme that is not loaded yet.' };
    return { home };
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

  /**
   * What a theme shows and opens onto on the picked map, once the page has a
   * map list. Its name and count are the map's (a team map's names come from
   * text its members can read, the public map's from public text), never the
   * viewer's own layout. A theme the map does not draw shows NOT_ON_MAP, no
   * count, and opens onto nothing: never onto the viewer's own claims.
   * Returns {onMap, label, placeholder, count, opens: 'nested' | 'nothing'}.
   */
  function themeOnMap(map, themeId) {
    const t = map && Array.isArray(map.themes) ? map.themes.find((x) => x.theme_id === themeId) : null;
    if (!t) return { onMap: false, label: NOT_ON_MAP, placeholder: true, count: null, opens: 'nothing' };
    const named = typeof t.label === 'string' && t.label.length > 0;
    return {
      onMap: true,
      label: named ? t.label : PLACEHOLDER,
      placeholder: !named,
      count: Math.max(0, finite(t.claim_count, 0)),
      opens: 'nested',
    };
  }

  /**
   * What opening a theme loads: 'claims' (the theme's claim list, as before
   * nesting) only when the page has no map list; with one, 'nested' or
   * 'nothing' per themeOnMap.
   */
  function themeOpens(nestedOn, map, themeId) {
    if (!nestedOn) return 'claims';
    return themeOnMap(map, themeId).opens;
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
    NOT_ON_MAP,
    HAIRLINE,
    NO_MASS_WIDTH,
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
    countLabel,
    findClaimLeaf,
    CLAIM_LEAF_SCHEMA_VERSION,
    claimLeafUrl,
    claimLeafProblem,
    lookupClaimLeaf,
    coldClaimHome,
    MAPS_SCHEMA_VERSION,
    localPrefix,
    parseMaps,
    levelUrl,
    levelKey,
    themeOnMap,
    themeOpens,
    rootFor,
  };
});
