// Tests for static/atlas_views.js, the Atlas Sources and Timeline view rules.
// Run from services/explorer:  node --test js-tests/atlas_views.test.cjs
// Plain node:test, no dependencies. Bodies are shaped like the
// /bff/atlas/sources and /bff/atlas/timeline answers (tests/atlas_views.rs).
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const V = require('../static/atlas_views.js');

const T = '2c9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10';
const id = (n) => '0b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a' + String(n).padStart(2, '0');
const claim = (n, at, label) => ({ id: id(n), key: 'c-' + id(n).replace(/-/g, ''), label: label || 'claim ' + n, truth_value: 0.5, created_at: at });
const link = (n, rel, a, b) => ({ id: '7a9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a' + String(n).padStart(2, '0'), source_id: id(a), target_id: id(b), relationship: rel });

test('view URLs carry only checked parts, on a local base', () => {
  assert.equal(V.sourcesUrl('/explorer/bff/atlas/sources', T, null), '/explorer/bff/atlas/sources?theme_id=' + T);
  assert.equal(V.sourcesUrl('/explorer/bff/atlas/sources', null, null), '/explorer/bff/atlas/sources');
  assert.equal(
    V.timelineUrl('/explorer/bff/atlas/timeline', T, 'k1.1.ab'),
    '/explorer/bff/atlas/timeline?theme_id=' + T + '&after=k1.1.ab',
  );
  // A cursor is encoded, never spliced.
  assert.equal(V.timelineUrl('/b', T, 'a&b=c'), '/b?theme_id=' + T + '&after=a%26b%3Dc');
  // A timeline needs a theme; ids and bases are checked.
  assert.equal(V.timelineUrl('/b', null, null), null);
  assert.equal(V.timelineUrl('/b', 'nope', null), null);
  assert.equal(V.sourcesUrl('/b', 'nope', null), null);
  for (const base of [null, '', 'https://evil.example/x', '//evil.example/x', '/x?y=1', '/x#y', '/x y']) {
    assert.equal(V.sourcesUrl(base, T, null), null, String(base));
    assert.equal(V.timelineUrl(base, T, null), null, String(base));
  }
});

test('sources group as papers, agents, web, in the API order, each once', () => {
  const groups = V.sourceGroups([
    { kind: 'web', domain: 'example.org', claim_count: 2 },
    {
      kind: 'paper', id: id(1), doi: '10.1/x', doi_href: 'https://doi.org/10.1/x', title: 'A paper',
      authors: [{ id: id(2), name: 'Ada', pending_countersign: false }, { id: id(3), name: 'Bo', pending_countersign: true }],
      authors_truncated: true, claim_count: 12,
    },
    { kind: 'agent', id: id(4), name: null, href: '/explorer/agent/' + id(4), claim_count: 4 },
    { kind: 'paper', id: id(5), doi: '10.1/y', doi_href: 'javascript:alert(1)', title: null, authors: [], authors_truncated: false, claim_count: 3 },
    { kind: 'paper', id: id(1), title: 'again', claim_count: 1 },
    { kind: 'agent', id: id(6), name: 'Evil', href: '//evil.example/agent', claim_count: 1 },
    { kind: 'dataset', id: id(7), claim_count: 9 },
    { kind: 'paper', id: 'nope', claim_count: 1 },
    { kind: 'web', domain: '  ', claim_count: 1 },
  ]);
  assert.deepEqual(groups.map((g) => g.kind), ['paper', 'agent', 'web']);
  const [papers, agents, web] = groups;
  assert.deepEqual(papers.items.map((i) => i.label), ['A paper', '10.1/y']);
  assert.equal(papers.items[0].detail, 'Ada, Bo (unconfirmed) and others');
  assert.equal(papers.items[0].href, 'https://doi.org/10.1/x');
  assert.equal(papers.items[0].count, 12);
  assert.equal(papers.items[1].href, null, 'only a doi.org link goes out');
  assert.equal(papers.items[1].detail, null);
  assert.equal(agents.items[0].label, 'Unnamed agent');
  assert.equal(agents.items[0].href, '/explorer/agent/' + id(4));
  assert.equal(agents.items[1].href, null, 'an agent links only to a local path');
  assert.deepEqual(web.items.map((i) => i.label), ['example.org']);
  assert.deepEqual(V.sourceGroups([]), []);
  assert.deepEqual(V.sourceGroups(null), []);
  assert.equal(V.countWords(1), '1 claim');
  assert.equal(V.countWords(-3), '0 claims');
});

test('timeline ticks follow the span: days, weeks, months, quarters, years', () => {
  const at = (s) => Date.parse(s);
  assert.equal(V.granule(3 * 86400000, 6), 'day');
  assert.equal(V.granule(30 * 86400000, 6), 'week');
  assert.equal(V.granule(150 * 86400000, 6), 'month');
  assert.equal(V.granule(500 * 86400000, 6), 'quarter');
  assert.equal(V.granule(5 * 365 * 86400000, 6), 'year');
  const y = V.ticks(at('2021-06-01T00:00:00Z'), at('2025-02-01T00:00:00Z'), 6);
  assert.equal(y.granule, 'year');
  assert.deepEqual(y.ticks.map((t) => t.label), ['2022', '2023', '2024', '2025']);
  const q = V.ticks(at('2025-02-10T00:00:00Z'), at('2026-01-05T00:00:00Z'), 6);
  assert.equal(q.granule, 'quarter');
  assert.deepEqual(q.ticks.map((t) => t.label), ['Q2 2025', 'Q3 2025', 'Q4 2025', 'Q1 2026']);
  const m = V.ticks(at('2026-01-15T00:00:00Z'), at('2026-04-02T00:00:00Z'), 6);
  assert.deepEqual(m.ticks.map((t) => t.label), ['Feb 2026', 'Mar 2026', 'Apr 2026']);
  // Weeks start on Monday, in UTC (2026-03-02 is a Monday).
  const w = V.ticks(at('2026-03-01T12:00:00Z'), at('2026-03-20T00:00:00Z'), 6);
  assert.equal(w.granule, 'week');
  assert.deepEqual(w.ticks.map((t) => t.label), ['2 Mar', '9 Mar', '16 Mar']);
  const d = V.ticks(at('2026-03-01T12:00:00Z'), at('2026-03-04T00:00:00Z'), 6);
  assert.deepEqual(d.ticks.map((t) => t.label), ['2 Mar', '3 Mar', '4 Mar']);
  for (const r of [y, q, m, w, d]) {
    for (let i = 1; i < r.ticks.length; i++) assert.ok(r.ticks[i].t > r.ticks[i - 1].t);
  }
  assert.deepEqual(V.ticks(5, 1, 6).ticks, []);
});

test('timeline dots sit on a linear time scale, oldest first', () => {
  const lay = V.timelineLayout(
    [
      claim(3, '2026-03-01T00:00:00Z'),
      claim(1, '2026-01-01T00:00:00Z'),
      claim(2, '2026-02-01T00:00:00Z'),
      claim(4, 'not a time'),
      { id: 'nope', created_at: '2026-01-01T00:00:00Z' },
      claim(1, '2026-05-01T00:00:00Z'),
    ],
    [],
    { width: 600, pad: 0 },
  );
  assert.deepEqual(lay.dots.map((d) => d.id), [id(1), id(2), id(3)]);
  assert.equal(lay.dots[0].x, 0);
  assert.equal(lay.dots[2].x, 600);
  // x is proportional to time: Jan→Feb is 31 days of 59.
  assert.ok(Math.abs(lay.dots[1].x - (31 / 59) * 600) < 1e-9);
  // Ticks share the dots' scale.
  for (const t of lay.ticks) assert.ok(Math.abs(t.x - ((t.t - lay.min) / (lay.max - lay.min)) * 600) < 1e-9);
  assert.deepEqual(lay.ticks.map((t) => t.label), ['Jan 2026', 'Feb 2026', 'Mar 2026']);
  // One claim (or one instant) sits in the middle.
  const one = V.timelineLayout([claim(1, '2026-01-01T00:00:00Z')], [], { width: 600 });
  assert.equal(one.dots[0].x, 300);
});

test('timeline arcs run from the earlier claim to the later, toned by relationship', () => {
  const claims = [claim(1, '2026-01-01T00:00:00Z'), claim(2, '2026-02-01T00:00:00Z'), claim(3, '2026-03-01T00:00:00Z')];
  const lay = V.timelineLayout(
    claims,
    [
      link(1, 'supports', 3, 1), // points back in time: drawn 1 → 3
      link(2, 'contradicts', 1, 2),
      link(3, 'cites', 2, 3),
      link(4, 'supports', 2, 99), // an end off the lane
      link(5, 'supports', 2, 2), // a loop
      link(1, 'supports', 3, 1), // the same link twice
    ],
    { width: 600, pad: 0 },
  );
  assert.deepEqual(
    lay.arcs.map((a) => [a.from, a.to, a.tone]),
    [
      [id(1), id(3), 'support'],
      [id(1), id(2), 'oppose'],
      [id(2), id(3), 'neutral'],
    ],
  );
  for (const a of lay.arcs) {
    assert.ok(a.x1 <= a.x2, 'earlier on the left');
    assert.ok(a.rise > 0 && a.rise <= 60);
  }
  assert.equal(V.arcTone('REFUTES'), 'oppose');
  assert.equal(V.arcTone('corroborates'), 'support');
  assert.equal(V.arcTone(undefined), 'neutral');
});

test('later pages append each claim and link once', () => {
  const a = { claims: [claim(1, '2026-01-01T00:00:00Z'), claim(2, '2026-02-01T00:00:00Z')], links: [link(1, 'supports', 1, 2)] };
  const b = { claims: [claim(2, '2026-02-01T00:00:00Z'), claim(3, '2026-03-01T00:00:00Z')], links: [link(1, 'supports', 1, 2), link(2, 'cites', 2, 3)] };
  const m = V.mergePages(a, b);
  assert.deepEqual(m.claims.map((c) => c.id), [id(1), id(2), id(3)]);
  assert.deepEqual(m.links.map((l) => l.relationship), ['supports', 'cites']);
  assert.deepEqual(V.mergePages(null, a).claims.length, 2);
  assert.equal(V.dayLabel('2026-03-12T23:00:00Z'), '12 Mar 2026');
  assert.equal(V.dayLabel('soon'), '');
});

// ---- provenance (the claim panel's section from /bff/atlas/claim) ---------

const person = (n, name) => ({ id: id(n), name, href: '/explorer/agent/' + id(n) });
const flat = (row) => row.parts.map((p) => p.text).join('');
const rowOf = (rows, title) => rows.find((r) => r.title === title);

const literature = () => ({
  source: 'literature',
  filed_at: '2026-11-01T10:00:00Z',
  ingested_at: '2026-10-31T09:00:00Z',
  paper: {
    id: id(1), doi: '10.1/x', doi_href: 'https://doi.org/10.1/x', title: 'A paper',
    authors: [person(2, 'Ada'), Object.assign(person(3, 'Bo'), { role: 'editor' })],
    pending_authors: [person(4, 'Pending Pat')],
    added_authors: [person(5, 'Added Al')],
    authors_truncated: true,
  },
  ingested_by: { agent: person(6, 'ingest-bot'), human: person(7, 'Hal'), model: 'model-x', prompt_snapshot_id: id(8) },
  corroborated_by: [
    { id: id(9), doi: 'urn:epigraph:doc:k', doi_href: null, title: null },
    { id: id(10), doi: '10.2/y', doi_href: 'https://doi.org/10.2/y', title: 'Other' },
  ],
  corroborated_by_truncated: false,
});

test('provenance: a document-made claim lists its authors apart from pending and added ones', () => {
  const rows = V.provenanceRows(literature());
  assert.deepEqual(rows.map((r) => r.title), [
    'Source', 'Authors', 'Named, awaiting confirmation', 'Added by a later ingest', 'Ingested', 'Filed', 'Also recorded in',
  ]);
  assert.equal(flat(rowOf(rows, 'Authors')), 'Ada, Bo (editor) and others');
  assert.ok(!flat(rowOf(rows, 'Authors')).includes('Pending'), 'a pending author is never an author');
  assert.ok(!flat(rowOf(rows, 'Authors')).includes('Added'), 'an added author is never an author');
  assert.equal(flat(rowOf(rows, 'Named, awaiting confirmation')), 'Pending Pat');
  assert.equal(flat(rowOf(rows, 'Ingested')), 'by Hal via ingest-bot, using model-x, prompt snapshot 0b9a5a4e on 31 Oct 2026');
  assert.equal(flat(rowOf(rows, 'Filed')), '1 Nov 2026');
  const src = rowOf(rows, 'Source').parts[0];
  assert.deepEqual(src, { text: 'A paper', href: 'https://doi.org/10.1/x', external: true });
  const also = rowOf(rows, 'Also recorded in').parts;
  assert.deepEqual(also[0], { text: 'urn:epigraph:doc:k', href: null, external: false }, 'a non-DOI key is text only');
  assert.equal(also[2].href, 'https://doi.org/10.2/y');
  for (const p of rowOf(rows, 'Authors').parts.filter((x) => x.href)) {
    assert.ok(p.href.startsWith('/explorer/agent/') && !p.external, p.href);
  }
});

test('provenance: an agent claim names human, agent, then what the viewer may see', () => {
  const rows = V.provenanceRows({
    source: 'agent',
    filed_at: '2026-11-01T10:00:00Z',
    filed_by: { agent: person(6, 'bot'), human: null, model: null, prompt_snapshot_id: null },
    corroborated_by: [],
    corroborated_by_truncated: false,
  });
  assert.deepEqual(rows.map((r) => r.title), ['Filed by', 'Filed']);
  assert.equal(flat(rows[0]), 'bot', 'no human, model or snapshot is invented');
  const withAll = V.provenanceRows({
    source: 'agent',
    filed_by: { agent: person(6, null), human: person(7, 'Hal'), model: 'm', prompt_snapshot_id: id(8) },
  });
  assert.equal(flat(withAll[0]), 'Hal via Unnamed agent, using m, prompt snapshot 0b9a5a4e');
});

test('provenance: unsafe links and unknown bodies are refused', () => {
  const body = literature();
  body.paper.doi_href = 'javascript:alert(1)';
  body.ingested_by.agent.href = 'https://evil.example/agent';
  body.ingested_by.human.href = '//evil.example/x';
  body.corroborated_by[1].doi_href = 'https://evil.example/10.2/y';
  const rows = V.provenanceRows(body);
  assert.equal(rowOf(rows, 'Source').parts[0].href, null);
  for (const p of rowOf(rows, 'Ingested').parts) assert.equal(p.href, null, p.text);
  for (const p of rowOf(rows, 'Also recorded in').parts) assert.equal(p.href, null, p.text);
  for (const bad of [null, 'x', {}, { source: 'dataset' }, { source: 'literature', paper: { id: 'nope' } }]) {
    assert.equal(V.provenanceRows(bad), null, JSON.stringify(bad));
  }
  // An empty corroborating list and no date leave their rows out.
  const bare = V.provenanceRows({ source: 'agent', filed_by: { agent: person(6, 'bot') } });
  assert.deepEqual(bare.map((r) => r.title), ['Filed by']);
});
