/* EpiGraph Explorer — the Atlas Sources and Timeline views: pure rules.
 *
 * No DOM, no canvas, no fetch: every function here maps a /bff/atlas/sources
 * or /bff/atlas/timeline body to lists, positions and labels, so
 * js-tests/atlas_views.test.cjs can test it under node:test. atlas.js loads
 * it first and reads it as the global AtlasViews.
 *
 * - Sources: papers and documents first, then agents that filed claims
 *   directly, then web sources, each in the order the API gave (most claims
 *   first). A paper links out only through a doi.org URL; an agent links
 *   only to a same-origin path. Counts are the API's, never summed.
 * - Timeline: one lane, x is the filing time (created_at) on a linear scale.
 *   Ticks follow the span: years, quarters, months, weeks or days, all in
 *   UTC. Arcs join linked claims of the lane, from the earlier claim to the
 *   later one; their tone comes from the relationship (support or oppose),
 *   never from a belief figure. Colour (truth_value) stays atlas.js's.
 * - Provenance (the claim panel's section from /bff/atlas/claim): rows of
 *   text and links. Who filed the claim reads human, then agent, then model
 *   and prompt snapshot. A claim a document's ingest created lists that
 *   document's authors as its authors; pending and later-added authors get
 *   rows of their own and are never listed as authors. A document links out
 *   only through a doi.org URL and a person only to a same-origin path.
 */
(function (global, factory) {
  'use strict';
  const api = factory();
  if (typeof module === 'object' && module && module.exports) module.exports = api;
  else global.AtlasViews = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  const DOI_HREF_RE = /^https:\/\/doi\.org\/10\.[^\s]+$/;
  const DAY = 86400000;
  const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  /** Tick granules, finest first, with their nominal length. */
  const GRANULES = [
    ['day', DAY],
    ['week', 7 * DAY],
    ['month', 30.44 * DAY],
    ['quarter', 91.31 * DAY],
    ['year', 365.25 * DAY],
  ];
  const SOURCE_GROUPS = [
    { kind: 'paper', title: 'Papers and documents' },
    { kind: 'agent', title: 'Agents that filed claims directly' },
    { kind: 'web', title: 'Web sources' },
  ];
  const TONES = { supports: 'support', corroborates: 'support', refutes: 'oppose', contradicts: 'oppose' };

  function uuid(v) {
    return typeof v === 'string' && UUID_RE.test(v) ? v : null;
  }

  function count(v) {
    return typeof v === 'number' && Number.isFinite(v) && v > 0 ? Math.floor(v) : 0;
  }

  function text(v) {
    return typeof v === 'string' && v.trim() ? v.trim() : null;
  }

  /** A same-origin path: one leading '/', no '//', no backslash or space. */
  function localHref(v) {
    if (typeof v !== 'string' || v.charAt(0) !== '/' || v.charAt(1) === '/') return null;
    return /[\\\s]/.test(v) ? null : v;
  }

  // ---- URLs ----------------------------------------------------------------

  /** `base?k=v…` for the non-empty params; null when `base` is not a bare local path. */
  function viewUrl(base, params) {
    if (!localHref(base) || /[?#]/.test(base)) return null;
    const parts = [];
    for (const k of Object.keys(params || {})) {
      const v = params[k];
      if (v === null || v === undefined || v === '') continue;
      parts.push(encodeURIComponent(k) + '=' + encodeURIComponent(String(v)));
    }
    return parts.length ? base + '?' + parts.join('&') : base;
  }

  /** The sources of one theme (or of everything when `themeId` is null). */
  function sourcesUrl(base, themeId, after) {
    if (themeId !== null && themeId !== undefined && !uuid(themeId)) return null;
    return viewUrl(base, { theme_id: themeId, after });
  }

  /** One theme's timeline page; a theme is required. */
  function timelineUrl(base, themeId, after) {
    if (!uuid(themeId)) return null;
    return viewUrl(base, { theme_id: themeId, after });
  }

  // ---- sources -------------------------------------------------------------

  function countWords(n) {
    const v = count(n);
    return v.toLocaleString() + (v === 1 ? ' claim' : ' claims');
  }

  function authorLine(authors, truncated) {
    const names = (Array.isArray(authors) ? authors : [])
      .map((a) => (a && text(a.name) ? text(a.name) + (a.pending_countersign ? ' (unconfirmed)' : '') : null))
      .filter(Boolean);
    if (!names.length) return truncated ? 'Authors not all listed' : null;
    return names.join(', ') + (truncated ? ' and others' : '');
  }

  function sourceItem(s) {
    if (!s || typeof s !== 'object') return null;
    if (s.kind === 'paper' && uuid(s.id)) {
      const doi = text(s.doi);
      return {
        key: 'paper:' + s.id,
        label: text(s.title) || doi || 'Untitled document',
        detail: authorLine(s.authors, s.authors_truncated === true),
        count: count(s.claim_count),
        href: typeof s.doi_href === 'string' && DOI_HREF_RE.test(s.doi_href) ? s.doi_href : null,
        external: true,
      };
    }
    if (s.kind === 'agent' && uuid(s.id)) {
      return {
        key: 'agent:' + s.id,
        label: text(s.name) || 'Unnamed agent',
        detail: null,
        count: count(s.claim_count),
        href: localHref(s.href),
        external: false,
      };
    }
    if (s.kind === 'web' && text(s.domain)) {
      return { key: 'web:' + text(s.domain), label: text(s.domain), detail: null, count: count(s.claim_count), href: null, external: false };
    }
    return null;
  }

  /**
   * The non-empty source groups of `sources` (one or more pages, in order):
   * [{kind, title, items: [{key, label, detail, count, href, external}]}].
   * An item already listed (same key) is not listed again.
   */
  function sourceGroups(sources) {
    const seen = new Set();
    const groups = SOURCE_GROUPS.map((g) => ({ kind: g.kind, title: g.title, items: [] }));
    for (const s of Array.isArray(sources) ? sources : []) {
      const item = sourceItem(s);
      if (!item || seen.has(item.key)) continue;
      seen.add(item.key);
      groups.find((g) => g.kind === s.kind).items.push(item);
    }
    return groups.filter((g) => g.items.length);
  }

  // ---- timeline ------------------------------------------------------------

  function time(v) {
    if (typeof v !== 'string') return null;
    const t = Date.parse(v);
    return Number.isFinite(t) ? t : null;
  }

  /** The finest granule that puts at most `maxTicks` ticks across `spanMs`. */
  function granule(spanMs, maxTicks) {
    const most = Math.max(1, maxTicks || 1);
    for (const [name, len] of GRANULES) if (spanMs / len <= most) return name;
    return 'year';
  }

  function startOf(name, t) {
    const d = new Date(t);
    const y = d.getUTCFullYear();
    const m = d.getUTCMonth();
    if (name === 'year') return Date.UTC(y, 0, 1);
    if (name === 'quarter') return Date.UTC(y, m - (m % 3), 1);
    if (name === 'month') return Date.UTC(y, m, 1);
    const day = Date.UTC(y, m, d.getUTCDate());
    if (name === 'week') return day - ((d.getUTCDay() + 6) % 7) * DAY; // Monday
    return day;
  }

  function nextOf(name, t) {
    const d = new Date(t);
    const y = d.getUTCFullYear();
    const m = d.getUTCMonth();
    if (name === 'year') return Date.UTC(y + 1, 0, 1);
    if (name === 'quarter') return Date.UTC(y, m + 3, 1);
    if (name === 'month') return Date.UTC(y, m + 1, 1);
    return t + (name === 'week' ? 7 : 1) * DAY;
  }

  function tickLabel(name, t) {
    const d = new Date(t);
    const y = d.getUTCFullYear();
    const m = d.getUTCMonth();
    if (name === 'year') return String(y);
    if (name === 'quarter') return 'Q' + (Math.floor(m / 3) + 1) + ' ' + y;
    if (name === 'month') return MONTHS[m] + ' ' + y;
    return d.getUTCDate() + ' ' + MONTHS[m];
  }

  /** Ticks at the start of each granule inside [min, max]: {granule, ticks: [{t, label}]}. */
  function ticks(min, max, maxTicks) {
    if (!Number.isFinite(min) || !Number.isFinite(max) || max < min) return { granule: null, ticks: [] };
    const name = granule(max - min, maxTicks);
    const out = [];
    for (let t = startOf(name, min); t <= max && out.length <= Math.max(1, maxTicks || 1) + 1; t = nextOf(name, t)) {
      if (t >= min) out.push({ t, label: tickLabel(name, t) });
    }
    return { granule: name, ticks: out };
  }

  function arcTone(relationship) {
    const r = typeof relationship === 'string' ? relationship.toLowerCase() : '';
    return Object.prototype.hasOwnProperty.call(TONES, r) ? TONES[r] : 'neutral';
  }

  /**
   * Positions for one lane `width` wide: {dots, arcs, ticks, granule, min,
   * max}; a tick is {t, label, x} on the same scale as the dots. A dot is {id, key, label, t, x, truth}; claims without an id or a
   * readable time are left out, the rest are ordered by time (ties keep the
   * page order). An arc is {id, from, to, x1, x2, rise, relationship, tone}
   * and always runs from the earlier dot to the later one, whichever way the
   * link points; a link with an end off the lane is left out.
   */
  function timelineLayout(claims, links, opts) {
    const o = opts || {};
    const width = Math.max(1, o.width || 600);
    const pad = Math.max(0, Math.min(width / 2, o.pad === undefined ? 16 : o.pad));
    const maxRise = Math.max(1, o.maxRise || 60);
    const seen = new Set();
    const dots = [];
    (Array.isArray(claims) ? claims : []).forEach((c, i) => {
      const t = time(c && c.created_at);
      if (!c || !uuid(c.id) || t === null || seen.has(c.id)) return;
      seen.add(c.id);
      dots.push({ id: c.id, key: typeof c.key === 'string' ? c.key : null, label: typeof c.label === 'string' ? c.label : '', t, i, truth: c.truth_value });
    });
    dots.sort((a, b) => a.t - b.t || a.i - b.i);
    const min = dots.length ? dots[0].t : null;
    const max = dots.length ? dots[dots.length - 1].t : null;
    const span = dots.length ? max - min : 0;
    dots.forEach((d, i) => {
      d.order = i;
      d.x = span > 0 ? pad + ((d.t - min) / span) * (width - 2 * pad) : width / 2;
      delete d.i;
    });
    const byId = new Map(dots.map((d) => [d.id, d]));
    const arcs = [];
    const arcIds = new Set();
    for (const l of Array.isArray(links) ? links : []) {
      if (!l || !uuid(l.id) || arcIds.has(l.id)) continue;
      const a = byId.get(l.source_id);
      const b = byId.get(l.target_id);
      if (!a || !b || a === b) continue;
      arcIds.add(l.id);
      const [from, to] = a.order <= b.order ? [a, b] : [b, a];
      arcs.push({
        id: l.id,
        from: from.id,
        to: to.id,
        x1: from.x,
        x2: to.x,
        rise: Math.min(maxRise, Math.max(4, (to.x - from.x) / 2)),
        relationship: typeof l.relationship === 'string' ? l.relationship : '',
        tone: arcTone(l.relationship),
      });
    }
    const tk = ticks(min, max, o.maxTicks || 6);
    const tickX = (t) => (span > 0 ? pad + ((t - min) / span) * (width - 2 * pad) : width / 2);
    return { dots, arcs, ticks: tk.ticks.map((k) => ({ t: k.t, label: k.label, x: tickX(k.t) })), granule: tk.granule, min, max };
  }

  /** `prev` with a later page appended: each claim and link once. */
  function mergePages(prev, next) {
    const out = { claims: [], links: [] };
    const ids = new Set();
    const linkIds = new Set();
    for (const page of [prev, next]) {
      if (!page) continue;
      for (const c of page.claims || []) {
        if (c && uuid(c.id) && !ids.has(c.id)) {
          ids.add(c.id);
          out.claims.push(c);
        }
      }
      for (const l of page.links || []) {
        if (l && uuid(l.id) && !linkIds.has(l.id)) {
          linkIds.add(l.id);
          out.links.push(l);
        }
      }
    }
    return out;
  }

  // ---- provenance ----------------------------------------------------------

  /** A link or text part of a provenance row. */
  function part(textValue, href, external) {
    return { text: textValue, href: href || null, external: !!(href && external) };
  }

  function personPart(p, fallback) {
    if (!p || typeof p !== 'object' || !uuid(p.id)) return null;
    return part(text(p.name) || fallback, localHref(p.href), false);
  }

  function documentPart(d) {
    if (!d || typeof d !== 'object' || !uuid(d.id)) return null;
    const href = typeof d.doi_href === 'string' && DOI_HREF_RE.test(d.doi_href) ? d.doi_href : null;
    return part(text(d.title) || text(d.doi) || 'Untitled document', href, true);
  }

  /** Comma-separated people as parts; ' and others' when cut. */
  function peopleParts(list, truncated) {
    const out = [];
    for (const a of Array.isArray(list) ? list : []) {
      const p = personPart(a, 'Unnamed author');
      if (!p) continue;
      if (out.length) out.push(part(', '));
      out.push(p);
      if (text(a.role)) out.push(part(' (' + text(a.role) + ')'));
    }
    if (out.length && truncated) out.push(part(' and others'));
    return out;
  }

  /** human via agent, using model, prompt snapshot <8 hex>; each part only when given. */
  function filerParts(f) {
    if (!f || typeof f !== 'object') return [];
    const agent = personPart(f.agent, 'Unnamed agent');
    const human = personPart(f.human, 'Unnamed person');
    const out = [];
    if (human) out.push(human);
    if (human && agent) out.push(part(' via '));
    if (agent) out.push(agent);
    if (!out.length) return out;
    if (text(f.model)) out.push(part(', using ' + text(f.model)));
    if (uuid(f.prompt_snapshot_id)) out.push(part(', prompt snapshot ' + f.prompt_snapshot_id.slice(0, 8)));
    return out;
  }

  function documentsParts(list, truncated) {
    const out = [];
    for (const d of Array.isArray(list) ? list : []) {
      const p = documentPart(d);
      if (!p) continue;
      if (out.length) out.push(part('; '));
      out.push(p);
    }
    if (out.length && truncated) out.push(part('; and more'));
    return out;
  }

  /**
   * The rows of the claim panel's provenance section, from the `data` of its
   * `provenance` section: [{title, parts: [{text, href, external}]}], or
   * null for a body this build does not know. A row with nothing to show is
   * left out.
   */
  function provenanceRows(p) {
    if (!p || typeof p !== 'object') return null;
    const rows = [];
    const push = (title, parts) => {
      if (parts && parts.length) rows.push({ title, parts });
    };
    if (p.source === 'literature') {
      const doc = documentPart(p.paper);
      if (!doc) return null;
      const paper = p.paper;
      push('Source', [doc]);
      push('Authors', peopleParts(paper.authors, paper.authors_truncated === true));
      push('Named, awaiting confirmation', peopleParts(paper.pending_authors, false));
      push('Added by a later ingest', peopleParts(paper.added_authors, false));
      const by = filerParts(p.ingested_by);
      if (by.length) {
        const when = dayLabel(p.ingested_at);
        push('Ingested', [part('by ')].concat(by, when ? [part(' on ' + when)] : []));
      }
    } else if (p.source === 'agent') {
      push('Filed by', filerParts(p.filed_by));
    } else {
      return null;
    }
    const filed = dayLabel(p.filed_at);
    if (filed) push('Filed', [part(filed)]);
    push('Also recorded in', documentsParts(p.corroborated_by, p.corroborated_by_truncated === true));
    return rows;
  }

  /** "12 Mar 2026" for a filing time, in UTC; '' when unreadable. */
  function dayLabel(iso) {
    const t = time(iso);
    if (t === null) return '';
    const d = new Date(t);
    return d.getUTCDate() + ' ' + MONTHS[d.getUTCMonth()] + ' ' + d.getUTCFullYear();
  }

  return {
    SOURCE_GROUPS,
    viewUrl,
    sourcesUrl,
    timelineUrl,
    countWords,
    sourceGroups,
    granule,
    ticks,
    arcTone,
    timelineLayout,
    mergePages,
    dayLabel,
    provenanceRows,
  };
});
