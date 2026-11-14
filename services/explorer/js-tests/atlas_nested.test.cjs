// Tests for static/atlas_nested.js, the Atlas nested-level rendering rules.
// Run from services/explorer:  node --test js-tests/
// Plain node:test, no dependencies. Data comes from the committed contract
// fixtures and the preview set, so the rules are tested on real shapes.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const N = require('../static/atlas_nested.js');

const CONTRACT = path.join(__dirname, '..', 'contract', 'atlas_level', 'v1');
const fixture = (stem) => JSON.parse(fs.readFileSync(path.join(CONTRACT, 'fixtures', stem + '.json'), 'utf8'));
const previewLevels = () =>
  fs
    .readFileSync(path.join(CONTRACT, 'preview', 'levels.jsonl'), 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((l) => JSON.parse(l));
const manifest = () => fs.readFileSync(path.join(CONTRACT, 'preview', 'manifest.json'), 'utf8');
/** The data-atlas-maps value the preview page renders from the manifest. */
const pageMaps = () => {
  const m = JSON.parse(manifest());
  return {
    schema_version: 1,
    maps: m.maps.map((x) => Object.assign({}, x, { level_url: '/bff/atlas/preview/maps/' + x.key + '/' })),
  };
};

const edge = (o) => Object.assign({ source: 'a', target: 'b', relationship: 'supports', sign: 1, flow_weight: 0.5, flow_basis: 'proxy' }, o);

test('width grows with flow weight, and a zero weight is a hairline', () => {
  const ws = [0.01, 0.1, 0.3, 0.5, 0.8, 1];
  const widths = ws.map(N.flowWidth);
  for (let i = 1; i < widths.length; i++) assert.ok(widths[i] > widths[i - 1], `width(${ws[i]}) > width(${ws[i - 1]})`);
  assert.equal(N.flowWidth(0), N.HAIRLINE);
  assert.ok(N.flowWidth(0.01) > N.HAIRLINE, 'any flow is thicker than no flow');
  // Out-of-range weights clamp rather than blow up.
  assert.equal(N.flowWidth(7), N.flowWidth(1));
  assert.equal(N.flowWidth(-1), N.HAIRLINE);
  // The edge style uses the same mapping.
  assert.equal(N.edgeStyle(edge({ flow_weight: 0.8 })).width, N.flowWidth(0.8));
});

test('proxy edges are dashed estimates; exact and no-flow edges are solid', () => {
  const proxy = N.edgeStyle(edge({ flow_basis: 'proxy' }));
  assert.ok(proxy.dash.length > 0 && proxy.estimate);
  const exact = N.edgeStyle(edge({ flow_basis: 'exact' }));
  assert.deepEqual(exact.dash, []);
  assert.equal(exact.estimate, false);
  const none = N.edgeStyle(edge({ flow_basis: 'none', sign: 0, flow_weight: 0, relationship: 'AUTHORED' }));
  assert.deepEqual(none.dash, []);
  assert.equal(none.flows, false);
  // A flowing edge's style never comes from its relationship's name or
  // casing; only a none edge's tone does (see the sparse-mass tests).
  const a = N.edgeStyle(edge({ relationship: 'supports' }));
  const b = N.edgeStyle(edge({ relationship: 'SUPPORTS' }));
  const c = N.edgeStyle(edge({ relationship: 'refutes' }));
  assert.deepEqual(a, b);
  assert.deepEqual(a, c, 'a proxy +1 edge looks the same whatever it is called');
});

test('the four proxy/exact x support/oppose styles are told apart', () => {
  const key = (s) => JSON.stringify([s.dash, s.tone, s.direction]);
  const styles = [
    N.edgeStyle(edge({ flow_basis: 'proxy', sign: 1 })),
    N.edgeStyle(edge({ flow_basis: 'proxy', sign: -1 })),
    N.edgeStyle(edge({ flow_basis: 'exact', sign: 1 })),
    N.edgeStyle(edge({ flow_basis: 'exact', sign: -1 })),
  ];
  assert.equal(new Set(styles.map(key)).size, 4);
  assert.equal(styles[1].tone, 'oppose');
  assert.equal(styles[3].tone, 'oppose');
  assert.equal(styles[0].tone, 'support');
});

test('sign sets which way particles run', () => {
  assert.equal(N.flowDirection(1), 1);
  assert.equal(N.flowDirection(-1), -1);
  assert.equal(N.flowDirection(0), 0);
  const fwd = N.edgeStyle(edge({ sign: 1, flow_weight: 0.6 }));
  const back = N.edgeStyle(edge({ sign: -1, flow_weight: 0.6 }));
  const dt = 0.05;
  const f0 = N.particleFractions(1.0, fwd, 0.1);
  const f1 = N.particleFractions(1.0 + dt, fwd, 0.1);
  const b0 = N.particleFractions(1.0, back, 0.1);
  const b1 = N.particleFractions(1.0 + dt, back, 0.1);
  assert.equal(f0.length, fwd.particles);
  assert.ok(f0.length > 0);
  // Pick a particle away from the wrap point and follow it.
  const i = f0.findIndex((f) => f > 0.1 && f < 0.85);
  assert.ok(f1[i] > f0[i], 'a supporting flow moves toward the target');
  const j = b0.findIndex((f) => f > 0.15 && f < 0.9);
  assert.ok(b1[j] < b0[j], 'an opposing flow moves back toward the source');
  for (const f of f0.concat(b0)) assert.ok(f >= 0 && f <= 1);
});

test('a cites link, with weight 0, draws no flow', () => {
  // From the committed contract fixture, not a hand-made edge.
  const leaf = fixture('public_leaf');
  const cites = leaf.edges.filter((e) => e.relationship.toLowerCase() === 'cites');
  assert.ok(cites.length > 0, 'the fixture holds a cites edge');
  for (const e of cites) {
    const s = N.edgeStyle(e);
    assert.equal(s.flows, false);
    assert.equal(s.particles, 0);
    assert.deepEqual(N.particleFractions(3.2, s, 0.4), []);
    assert.equal(s.width, N.HAIRLINE);
  }
  // And every edge of the dense leaf that weighs something does flow.
  for (const e of fixture('team_leaf_dense').edges) {
    const s = N.edgeStyle(e);
    assert.equal(s.flows, e.flow_weight > 0 && e.sign !== 0 && e.flow_basis !== 'none', JSON.stringify(e));
  }
});

test('a signed link with weight 0 keeps its tone but carries no flow', () => {
  // A contradicts or refutes link stored with strength 0: still the opposing
  // style, as a hairline with no particles.
  for (const basis of ['proxy', 'exact']) {
    const opp = N.edgeStyle(edge({ flow_basis: basis, sign: -1, flow_weight: 0, relationship: 'contradicts' }));
    assert.equal(opp.tone, 'oppose', basis);
    assert.equal(opp.flows, false, basis);
    assert.equal(opp.particles, 0, basis);
    assert.equal(opp.direction, 0, basis);
    assert.equal(opp.width, N.HAIRLINE, basis);
    assert.deepEqual(N.particleFractions(2.5, opp, 0.3), [], basis);
    // A supporting link with weight 0 likewise draws no flow.
    const sup = N.edgeStyle(edge({ flow_basis: basis, sign: 1, flow_weight: 0 }));
    assert.equal(sup.tone, 'support', basis);
    assert.equal(sup.flows, false, basis);
    assert.equal(sup.particles, 0, basis);
    assert.equal(sup.width, N.HAIRLINE, basis);
  }
  // The proxy dash still marks the zero-weight estimate.
  assert.ok(N.edgeStyle(edge({ flow_basis: 'proxy', sign: -1, flow_weight: 0 })).estimate);
  // Sign 0 (cites) stays neutral at any weight the contract allows.
  assert.equal(N.edgeStyle(edge({ sign: 0, flow_weight: 0 })).tone, 'neutral');
});

// Evidence with no readable mass is served flow_basis none, weight 0 and
// sign 0 whatever it says about the claim, so its direction is in its
// relationship. These read the committed contract fixture, not a hand-made
// edge, so the basis, sign and weight are the ones a builder serves.
const sparse = () => {
  const leaf = fixture('team_leaf_sparse_mass');
  const kinds = new Map(leaf.nodes.map((n) => [n.id, n.kind]));
  const fromEvidence = leaf.edges.filter((e) => kinds.get(e.source) === 'evidence');
  const rel = (e) => e.relationship.toLowerCase();
  return {
    none: (r) => fromEvidence.filter((e) => e.flow_basis === 'none' && rel(e) === r),
    exact: fromEvidence.filter((e) => e.flow_basis === 'exact'),
  };
};

/** A massless evidence edge: no flow at all, solid, and not an estimate. */
function assertNoFlow(s, why) {
  assert.equal(s.flows, false, why);
  assert.equal(s.particles, 0, why);
  assert.equal(s.direction, 0, why);
  assert.deepEqual(N.particleFractions(4.2, s, 0.3), [], why);
  assert.deepEqual(s.dash, [], why + ': solid, never the dashed estimate');
  assert.equal(s.estimate, false, why);
  assert.equal(s.noMass, true, why);
}

/** What a viewer sees of a drawn style: no internal flag. */
const look = (s) => JSON.stringify([s.width, s.alpha, s.dash, s.tone, s.particles > 0]);

test('a none evidence edge that refutes gets the opposing tone and no flow', () => {
  const refutes = sparse().none('refutes');
  assert.ok(refutes.length > 0, 'the fixture holds a none refutes evidence edge');
  for (const e of refutes) {
    assert.equal(e.sign, 0, 'served with sign 0: the direction is in the relationship');
    const s = N.edgeStyle(e);
    assert.equal(s.tone, 'oppose', JSON.stringify(e));
    assertNoFlow(s, JSON.stringify(e));
  }
  // contradicts reads the same way, in either casing.
  const c = N.edgeStyle(Object.assign({}, refutes[0], { relationship: 'CONTRADICTS' }));
  assert.equal(c.tone, 'oppose');
  assertNoFlow(c, 'contradicts');
});

test('a none evidence edge that supports gets the supporting tone and no flow', () => {
  const supports = sparse().none('supports');
  assert.ok(supports.length > 0, 'the fixture holds a none supports evidence edge');
  const upper = supports.filter((e) => e.relationship === 'SUPPORTS');
  assert.ok(upper.length > 0, 'and one spelled SUPPORTS');
  for (const e of supports) {
    assert.equal(e.sign, 0);
    const s = N.edgeStyle(e);
    assert.equal(s.tone, 'support', JSON.stringify(e));
    assertNoFlow(s, JSON.stringify(e));
  }
});

test('a massless evidence line is told apart from exact flows and dashed estimates', () => {
  const sup = N.edgeStyle(sparse().none('supports')[0]);
  const opp = N.edgeStyle(sparse().none('refutes')[0]);
  const others = [
    // exact flows, and an exact signed edge stored with weight 0
    N.edgeStyle(edge({ flow_basis: 'exact', sign: 1, flow_weight: 0.5 })),
    N.edgeStyle(edge({ flow_basis: 'exact', sign: -1, flow_weight: 0.5 })),
    N.edgeStyle(edge({ flow_basis: 'exact', sign: 1, flow_weight: 0 })),
    N.edgeStyle(edge({ flow_basis: 'exact', sign: -1, flow_weight: 0 })),
    // dashed estimates, flowing or not
    N.edgeStyle(edge({ flow_basis: 'proxy', sign: 1, flow_weight: 0.5 })),
    N.edgeStyle(edge({ flow_basis: 'proxy', sign: -1, flow_weight: 0 })),
  ];
  for (const s of [sup, opp]) {
    for (const o of others) assert.notEqual(look(s), look(o), look(s) + ' vs ' + look(o));
    assert.ok(s.width < N.flowWidth(0.01), 'thinner than any flow');
    assert.ok(s.width > N.HAIRLINE, 'and wider than a hairline, so its tone reads');
  }
  assert.notEqual(look(sup), look(opp));
});

test('an exact evidence edge is unchanged: its sign, not its relationship, sets its style', () => {
  const exact = sparse().exact;
  assert.ok(exact.length > 0, 'the fixture keeps some exact evidence beside the none edges');
  for (const e of exact) {
    const s = N.edgeStyle(e);
    assert.equal(s.basis, 'exact');
    assert.equal(s.tone, e.sign > 0 ? 'support' : 'oppose', JSON.stringify(e));
    assert.equal(s.flows, e.flow_weight > 0, JSON.stringify(e));
    assert.equal(s.width, e.flow_weight > 0 ? N.flowWidth(e.flow_weight) : N.HAIRLINE);
    assert.equal(s.direction, e.flow_weight > 0 ? e.sign : 0);
    assert.deepEqual(s.dash, []);
    assert.ok(!s.noMass, JSON.stringify(e));
  }
  // An exact edge whose name disagrees with its sign follows the sign.
  for (const [sign, rel, tone] of [
    [1, 'refutes', 'support'],
    [-1, 'supports', 'oppose'],
  ]) {
    const s = N.edgeStyle(edge({ flow_basis: 'exact', sign, flow_weight: 0.4, relationship: rel }));
    assert.equal(s.tone, tone, rel);
    assert.equal(s.direction, sign, rel);
    assert.ok(s.flows && !s.noMass, rel);
  }
  // A none edge that is not evidence for or against (an agent's authorship)
  // stays neutral.
  for (const rel of ['authored', 'AUTHORED', 'asserts']) {
    const s = N.edgeStyle(edge({ flow_basis: 'none', sign: 0, flow_weight: 0, relationship: rel }));
    assert.equal(s.tone, 'neutral', rel);
    assert.ok(!s.noMass, rel);
  }
});

test('the preview has a leaf with massless evidence for and against, drawn in tone', () => {
  let shown = 0;
  for (const d of previewLevels()) {
    if (d.kind !== 'leaf') continue;
    const kinds = new Map(d.nodes.map((n) => [n.id, n.kind]));
    const tones = new Set(
      d.edges
        .filter((e) => kinds.get(e.source) === 'evidence' && e.flow_basis === 'none')
        .map((e) => N.edgeStyle(e))
        .filter((s) => s.noMass)
        .map((s) => s.tone),
    );
    if (tones.has('support') && tones.has('oppose')) shown += 1;
  }
  assert.ok(shown > 0, 'a preview leaf shows the sparse-mass case');
});

test('the switch leads to the other hierarchy, and nothing else', () => {
  for (const stem of ['team_theme_root', 'team_group_deep', 'team_leaf_dense', 'public_leaf']) {
    const doc = fixture(stem);
    const t = N.switchTarget(doc);
    assert.deepEqual(t, { hierarchy: N.otherHierarchy(doc.hierarchy), level_id: doc.switch.level_id }, stem);
  }
  const doc = fixture('team_theme_root');
  assert.equal(N.switchTarget(Object.assign({}, doc, { switch: { hierarchy: doc.hierarchy, level_id: doc.switch.level_id } })), null, 'same hierarchy is refused');
  assert.equal(N.switchTarget(Object.assign({}, doc, { switch: { hierarchy: 'links', level_id: 'not-a-uuid' } })), null);
  assert.equal(N.switchTarget(Object.assign({}, doc, { switch: undefined })), null);
  // In the preview set every switch lands on a served level of the other
  // hierarchy, which switches back.
  const levels = previewLevels();
  const byId = new Map(levels.map((d) => [d.level_id, d]));
  for (const d of levels) {
    const t = N.switchTarget(d);
    const twin = byId.get(t.level_id);
    assert.ok(twin, 'the switch target is served');
    assert.equal(twin.hierarchy, t.hierarchy);
    assert.equal(twin.theme_id, d.theme_id);
    assert.equal(N.switchTarget(twin).level_id, d.level_id);
  }
});

test('a group awaiting a name shows the neutral placeholder', () => {
  assert.equal(N.displayName({ name: 'Ion channels', needs_naming: false }), 'Ion channels');
  assert.equal(N.displayName({ name: null, needs_naming: true }), N.PLACEHOLDER);
  assert.equal(N.displayName({ name: 'Stale name', needs_naming: true }), N.PLACEHOLDER, 'a stale name is not shown');
  const root = fixture('team_theme_root');
  const flagged = root.children.filter((c) => c.needs_naming);
  assert.ok(flagged.length > 0);
  for (const c of flagged) assert.ok(N.isPlaceholder(c));
});

test('leaf positions are the served ones, only scaled into the circle (no settle)', () => {
  const leaf = fixture('team_leaf_dense');
  const frame = { x: 12.5, y: -3, r: 0.02 };
  const placed = N.leafPositions(frame, leaf.nodes);
  assert.equal(placed.length, leaf.nodes.length);
  const s = N.LEAF_SPREAD * frame.r;
  leaf.nodes.forEach((n, i) => {
    assert.equal(placed[i].id, n.id);
    assert.ok(Math.abs(placed[i].x - (frame.x + n.x * s)) < 1e-12);
    assert.ok(Math.abs(placed[i].y - (frame.y + n.y * s)) < 1e-12);
    // Inside the leaf circle.
    assert.ok(Math.hypot(placed[i].x - frame.x, placed[i].y - frame.y) <= frame.r + 1e-12);
  });
  // The input is untouched.
  assert.deepEqual(leaf.nodes, fixture('team_leaf_dense').nodes);
});

test('group children are placed inside their parent', () => {
  const doc = fixture('team_theme_root');
  const parent = { x: 100, y: 50, r: 30 };
  const placed = N.placeChildren(parent, doc.children);
  doc.children.forEach((c, i) => {
    assert.ok(Math.abs(placed[i].x - (100 + c.x * 30)) < 1e-9);
    assert.ok(Math.abs(placed[i].r - c.r * 30) < 1e-9);
    assert.equal(placed[i].kind, c.kind);
  });
});

test('children load when their node fills a third of the view', () => {
  assert.equal(N.shouldLoad(332, 1000), false);
  assert.equal(N.shouldLoad(334, 1000), true);
});

test('the zoom ceiling grows to frame the smallest attached node', () => {
  const base = 3000;
  assert.equal(N.maxZoom(base, 0, 800), base);
  const r = 1e-4;
  const k = N.maxZoom(base, r, 800);
  // Framing a node takes k = view / (2.2 r); the ceiling allows more.
  assert.ok(k >= 800 / (2.2 * r));
  assert.equal(N.maxZoom(base, 500, 800), base, 'never below the base');
});

test('a fetched level is checked against the map and level asked for', () => {
  const doc = fixture('team_leaf_dense');
  const team = { scope: 'team', group_id: doc.map_group_id };
  const pub = { scope: 'public', group_id: null };
  assert.equal(N.levelProblem(doc, { levelId: doc.level_id, map: team, kind: 'leaf' }), null);
  assert.match(N.levelProblem(doc, { levelId: doc.level_id, map: pub }), /another map/);
  assert.match(N.levelProblem(doc, { levelId: doc.level_id, map: { scope: 'team', group_id: '00000000-0000-4000-8000-000000000001' } }), /another map/);
  assert.match(N.levelProblem(doc, { levelId: '00000000-0000-4000-8000-000000000001', map: team }), /another level/);
  assert.match(N.levelProblem(doc, { levelId: doc.level_id, map: team, kind: 'group' }), /kind/);
  assert.match(N.levelProblem(Object.assign({}, doc, { schema_version: 2 }), { map: team }), /newer/);
  // The same level id in the other hierarchy is another level.
  assert.equal(N.levelProblem(doc, { levelId: doc.level_id, map: team, hierarchy: doc.hierarchy }), null);
  assert.match(N.levelProblem(doc, { levelId: doc.level_id, map: team, hierarchy: N.otherHierarchy(doc.hierarchy) }), /other grouping/);
  const p = fixture('public_leaf');
  assert.equal(N.levelProblem(p, { levelId: p.level_id, map: pub }), null);
  assert.match(N.levelProblem(p, { levelId: p.level_id, map: team }), /another map/);
});

test('bundles resolve to a sibling or a listed target; a stub flies to a target the preview serves', () => {
  const doc = fixture('team_group_deep');
  const all = N.resolveBundles(doc);
  assert.equal(all.length, doc.bundles.length, 'every fixture bundle resolves');
  const siblings = all.filter((b) => b.sibling);
  const stubs = all.filter((b) => !b.sibling);
  assert.ok(siblings.length > 0 && stubs.length > 0);
  for (const b of stubs) assert.ok(doc.targets.some((t) => t.level_id === b.to.level_id));
  // A dangling bundle is dropped rather than drawn to nowhere.
  const broken = Object.assign({}, doc, { bundles: [{ source: doc.children[0].id, target: '00000000-0000-4000-8000-000000000009', count: 3, net_sign: 1 }] });
  assert.deepEqual(N.resolveBundles(broken), []);
  // Every stub of the preview set (group targets and leaf outgoing) lands on a
  // served level of the same map and theme the stub names.
  const levels = previewLevels();
  const byId = new Map(levels.map((d) => [d.level_id, d]));
  let followed = 0;
  for (const d of levels) {
    const targets = d.kind === 'group' ? N.resolveBundles(d).filter((b) => !b.sibling).map((b) => b.to) : d.outgoing.map((o) => o.target);
    for (const t of targets) {
      const to = byId.get(t.level_id);
      assert.ok(to, 'the stub target is served');
      assert.equal(to.theme_id, t.theme_id);
      assert.ok(N.mapMatches(to, { scope: d.map_scope, group_id: d.map_group_id }));
      assert.deepEqual(N.chainIds(to).slice(-1), [t.level_id]);
      followed += 1;
    }
  }
  assert.ok(followed > 20);
});

test('the map picker reads the page map list and finds each theme root', () => {
  const maps = N.parseMaps(JSON.stringify(pageMaps()));
  assert.deepEqual(maps.map((m) => m.scope), ['team', 'public']);
  const levels = new Map(previewLevels().map((d) => [d.level_id, d]));
  for (const m of maps) {
    for (const t of m.themes) {
      for (const h of ['meaning', 'links']) {
        const root = levels.get(N.rootFor(m, t.theme_id, h));
        assert.ok(root, 'the root is served');
        assert.equal(root.depth, 0);
        assert.equal(root.hierarchy, h);
        assert.ok(N.mapMatches(root, m));
      }
    }
  }
  assert.deepEqual(N.parseMaps('not json'), []);
  assert.deepEqual(N.parseMaps(null), []);
  // A team map without its group id is dropped.
  assert.deepEqual(N.parseMaps({ schema_version: 1, maps: [{ key: 'x', scope: 'team', group_id: null, level_url: '/x/', themes: [] }] }), []);
  // The bare manifest (no version, no URLs) is not a map list.
  assert.deepEqual(N.parseMaps(manifest()), []);
});

test('a level is fetched through its own map URL, naming the hierarchy', () => {
  const maps = N.parseMaps(pageMaps());
  const [team, pub] = maps;
  const id = '0f0e0d0c-0b0a-4900-8800-000000000001';
  assert.equal(N.levelUrl(team, 'meaning', id), '/bff/atlas/preview/maps/team/meaning/' + id);
  assert.equal(N.levelUrl(pub, 'links', id), '/bff/atlas/preview/maps/public/links/' + id);
  // One group id on two maps, or in two hierarchies, is four requests and
  // four cache entries, never one.
  const urls = new Set();
  const keys = new Set();
  for (const m of maps) {
    for (const h of ['meaning', 'links']) {
      urls.add(N.levelUrl(m, h, id));
      keys.add(N.levelKey(m, h, id));
    }
  }
  assert.equal(urls.size, 4);
  assert.equal(keys.size, 4);
  // Nothing outside the contract's hierarchies, and no non-UUID id.
  assert.equal(N.levelUrl(team, 'Meaning', id), null);
  assert.equal(N.levelUrl(team, 'meaning', '../x'), null);
  assert.equal(N.levelUrl(null, 'meaning', id), null);
});

test('a map with no usable level URL is dropped', () => {
  const one = (patch) => {
    const v = pageMaps();
    v.maps = [Object.assign({}, v.maps[0], patch)];
    return N.parseMaps(v);
  };
  assert.equal(one({}).length, 1);
  for (const bad of [undefined, '', '/', 'https://evil.example/', '//evil.example/', '/a', '/a?b/', '/a#b/', '/a\\b/', '/a b/']) {
    assert.deepEqual(one({ level_url: bad }), [], String(bad));
  }
  // Two entries with one key: the second is dropped.
  const v = pageMaps();
  v.maps[1].key = v.maps[0].key;
  assert.equal(N.parseMaps(v).length, 1);
  // Another version is not read.
  assert.deepEqual(N.parseMaps(Object.assign(pageMaps(), { schema_version: 2 })), []);
});

test('the picked map names, counts and opens a theme; off the map it opens onto nothing', () => {
  const A = '0f0e0d0c-0b0a-4900-8800-00000000000a';
  const B = '0f0e0d0c-0b0a-4900-8800-00000000000b';
  const C = '0f0e0d0c-0b0a-4900-8800-00000000000c';
  const roots = { meaning: '0f0e0d0c-0b0a-4900-8800-000000000101', links: '0f0e0d0c-0b0a-4900-8800-000000000102' };
  const team = { key: 'team', themes: [{ theme_id: A, label: 'Team name for A', claim_count: 120, roots }, { theme_id: B, label: null, claim_count: 7, roots }] };
  const pub = { key: 'public', themes: [{ theme_id: A, label: 'Public name for A', claim_count: 9, roots }] };
  // No map list: themes open onto their claim list, as before nesting.
  assert.equal(N.themeOpens(false, null, A), 'claims');
  assert.equal(N.themeOpens(false, team, C), 'claims');
  // A theme on the map: the map's own name and count, opening onto its levels.
  assert.deepEqual(N.themeOnMap(team, A), { onMap: true, label: 'Team name for A', placeholder: false, count: 120, opens: 'nested' });
  assert.equal(N.themeOnMap(pub, A).label, 'Public name for A', 'the public map names it from public text');
  assert.equal(N.themeOnMap(pub, A).count, 9);
  assert.equal(N.themeOpens(true, team, A), 'nested');
  // Unnamed on this map: the neutral placeholder, never the layout's label.
  assert.equal(N.themeOnMap(team, B).label, N.PLACEHOLDER);
  assert.equal(N.themeOnMap(team, B).placeholder, true);
  // Not on the picked map: shown as such, no count, and it opens onto
  // nothing, never the viewer's own (team-private) claims.
  for (const [map, id] of [[pub, B], [pub, C], [team, C], [null, A]]) {
    const t = N.themeOnMap(map, id);
    assert.equal(t.onMap, false);
    assert.equal(t.label, N.NOT_ON_MAP);
    assert.equal(t.count, null);
    assert.equal(N.themeOpens(true, map, id), 'nothing');
  }
  // On the preview maps: the second theme is on the team map only.
  const maps = N.parseMaps(pageMaps());
  const second = maps[0].themes[1].theme_id;
  assert.equal(N.themeOpens(true, maps[0], second), 'nested');
  assert.equal(N.themeOpens(true, maps[1], second), 'nothing');
});

test('a claim link finds the fetched leaf that draws the claim, or nothing', () => {
  const levels = previewLevels();
  const leaves = levels.filter((d) => d.kind === 'leaf');
  const leaf = leaves[3];
  const claim = leaf.nodes.find((n) => n.kind === 'claim');
  const agent = leaf.nodes.find((n) => n.kind === 'agent');
  assert.equal(N.findClaimLeaf(levels, claim.id), leaf);
  // Only fetched leaves count: without it, there is no answer to invent.
  assert.equal(N.findClaimLeaf(levels.filter((d) => d !== leaf), claim.id), null);
  // An agent or evidence node is not a claim, and a non-id finds nothing.
  assert.equal(N.findClaimLeaf(levels, agent.id), null);
  assert.equal(N.findClaimLeaf(levels, 'c-' + claim.id), null);
  assert.equal(N.findClaimLeaf([], claim.id), null);
  // Only a leaf answers: a document of another kind is never taken for the
  // claim's leaf, even one that carried the claim node.
  const notLeaf = Object.assign({}, leaf, { kind: 'group' });
  assert.equal(N.findClaimLeaf([notLeaf], claim.id), null);
});

test('a map count is labelled as stored on the map, not as what the viewer can read', () => {
  assert.equal(N.countLabel(8, true), '8 claims on this map');
  assert.equal(N.countLabel(1, true), '1 claim on this map');
  assert.equal(N.countLabel(1200, true), (1200).toLocaleString() + ' claims on this map');
  assert.doesNotMatch(N.countLabel(8, true), /you can read/);
  // The viewer's own layout counts keep their words.
  assert.equal(N.countLabel(8, false), '8 claims you can read');
  assert.equal(N.countLabel(undefined, true), '0 claims on this map');
});
