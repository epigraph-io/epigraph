/* EpiGraph Explorer — the Atlas, Topics view (phase P3a).
 *
 * One camera over a canvas: regions → themes → claims → a claim's ring,
 * loaded level by level from the /bff/atlas/* routes as the viewer zooms in.
 * The markup is templates/atlas/atlas.html (signed in) or
 * templates/atlas/anon.html (sign-in shell); every URL comes from its
 * data- attributes. CSP is script-src 'self', so nothing is inline. Plain
 * ES2020, no build step. d3 modules (vendored under static/vendor/, ISC)
 * provide the zoom interpolator, easing, packing and the collision pass;
 * small local fallbacks keep the map usable if they fail to load.
 *
 * - Colour: fill comes from the authored truth value alone, through the
 *   --atlas-belief-0..6 tokens in atlas.css; no belief figure is read.
 * - Level of detail: a region, theme or claim fetches its children once its
 *   screen radius reaches a third of the view; a failed level keeps its
 *   parent drawn with a retry chip, and the map never goes blank.
 * - Accessibility: the canvas is an image; the panel lists every child of
 *   the selection as buttons, and search reaches any claim, so keyboard
 *   users never need the canvas.
 * - Deep links: selecting a claim writes #c-<32 hex> with replaceState;
 *   #t-… prototype links are resolved here, through a claim key only.
 * - Safety: untrusted strings reach the DOM only through textContent or
 *   setAttribute on non-URL attributes. Local URLs from data must pass
 *   localPath; the only external link is a DOI that passes doiHref. No
 *   string is ever evaluated as code or parsed as markup (tests/atlas.rs
 *   pins this).
 */
(function () {
  'use strict';

  const root = document.getElementById('atlas');
  if (!root) return;

  const HASH_KEY = /^#[ct]-[0-9a-f-]{8,36}$/;
  const UUID_RE = /^[0-9a-f-]{32,36}$/i;
  const DOI_RE = /^https:\/\/doi\.org\/[A-Za-z0-9\-._~/:;()%]+$/;

  /** A same-origin path from the BFF, or null (never a scheme or //host). */
  function localPath(value) {
    if (typeof value !== 'string' || value.length === 0) return null;
    if (value.charAt(0) !== '/') return null;
    const second = value.charAt(1);
    if (second === '/' || second === '\\') return null;
    return value;
  }

  /** The one external link the Atlas renders: a doi.org URL. */
  function doiHref(value) {
    return typeof value === 'string' && DOI_RE.test(value) ? value : null;
  }

  /** A UUID from data, checked before it goes into a URL. */
  function uuid(value) {
    return typeof value === 'string' && UUID_RE.test(value) ? value : null;
  }

  function simple(id) {
    return String(id).replace(/-/g, '').toLowerCase();
  }

  function num(v) {
    return typeof v === 'number' && Number.isFinite(v) ? v : null;
  }

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = String(text);
    return e;
  }

  function button(cls, text, onClick) {
    const b = el('button', cls, text);
    b.type = 'button';
    b.addEventListener('click', onClick);
    return b;
  }

  function link(href, text, cls) {
    const a = el('a', cls, text);
    const p = localPath(href);
    if (p) a.setAttribute('href', p);
    return a;
  }

  /**
   * Copy the deep-link hash into a sign-in link's return_to, so the viewer
   * lands on the same claim after signing in. The server never sees the
   * fragment, so only the client can carry it.
   */
  function carryHash(a, base) {
    if (!a) return;
    const href = localPath(base || a.getAttribute('href'));
    if (!href) return;
    const url = new URL(href, location.origin);
    const back = url.searchParams.get('return_to');
    if (back && back.indexOf('#') === -1 && HASH_KEY.test(location.hash)) {
      url.searchParams.set('return_to', back + location.hash);
    }
    a.setAttribute('href', url.pathname + url.search);
  }

  if (root.getAttribute('data-atlas-mode') === 'anon') {
    const signin = document.querySelector('[data-role="atlas-signin"]');
    const base = signin ? signin.getAttribute('href') : null;
    carryHash(signin, base);
    window.addEventListener('hashchange', () => carryHash(signin, base));
    return;
  }

  // ---- configuration -------------------------------------------------------

  const cfg = {};
  for (const [key, attr] of [
    ['layout', 'data-layout-url'],
    ['themeClaims', 'data-theme-claims-prefix'],
    ['claim', 'data-claim-prefix'],
    ['links', 'data-links-url'],
    ['search', 'data-search-url'],
    ['resolve', 'data-resolve-prefix'],
    ['themes', 'data-themes-url'],
    ['login', 'data-login-url'],
    ['atlas', 'data-atlas-url'],
  ]) {
    cfg[key] = localPath(root.getAttribute(attr));
  }

  const q = (role) => root.querySelector('[data-role="' + role + '"]');
  const dom = {
    stage: q('stage'),
    canvas: q('canvas'),
    notice: q('notice'),
    caption: q('caption'),
    crumbs: q('crumbs'),
    structure: q('structure'),
    inTheme: q('in-theme'),
    panelTitle: q('panel-title'),
    panelStatus: q('panel-status'),
    panelBody: q('panel-body'),
    searchForm: q('search-form'),
    input: document.getElementById('atlas-q'),
    results: document.getElementById('atlas-results'),
  };
  if (!dom.canvas || !dom.stage || !cfg.layout) return;
  const ctx = dom.canvas.getContext('2d');

  const d3 = window.d3 || {};
  const media = (mq) => (window.matchMedia ? window.matchMedia(mq) : null);
  const reducedMotion = media('(prefers-reduced-motion: reduce)');
  const darkScheme = media('(prefers-color-scheme: dark)');
  const motionOK = () => !(reducedMotion && reducedMotion.matches);

  // ---- constants -----------------------------------------------------------

  const WORLD = 1000;
  const GOLDEN = 2.39996;
  const MAX_DRAWN = 2000;
  const MIN_CLAIM_PX = 1.5;
  const MAX_IN_FLIGHT = 4;
  const SEARCH_DEBOUNCE_MS = 250;
  const SETTLE_MS = 150;
  const FIND_PAGES = 3;
  const RIM_PARTNERS = 3;

  // ---- fetching ------------------------------------------------------------

  let inFlight = 0;
  const waiting = [];

  function acquire() {
    if (inFlight < MAX_IN_FLIGHT) {
      inFlight += 1;
      return Promise.resolve();
    }
    return new Promise((resolve) => waiting.push(resolve));
  }

  function release() {
    const next = waiting.shift();
    if (next) next();
    else inFlight -= 1;
  }

  class FetchError extends Error {
    constructor(status, kind, message) {
      super(message);
      this.status = status;
      this.kind = kind;
    }
  }

  /** GET a /bff/atlas URL as JSON; a non-2xx answer throws its message. */
  async function getJSON(url, signal) {
    const path = localPath(url);
    if (!path) throw new FetchError(0, 'bad_url', 'That link is not valid.');
    await acquire();
    try {
      const resp = await fetch(path, {
        credentials: 'same-origin',
        headers: { Accept: 'application/json' },
        signal,
      });
      let body = null;
      try {
        body = await resp.json();
      } catch (e) {
        body = null;
      }
      if (resp.status === 401) {
        sessionExpired();
        throw new FetchError(401, 'unauthorized', 'Your session has expired.');
      }
      if (!resp.ok) {
        const message =
          body && typeof body.message === 'string'
            ? body.message
            : 'The Atlas could not load this.';
        throw new FetchError(resp.status, body && body.error, message);
      }
      return body;
    } finally {
      release();
    }
  }

  function withQuery(base, params) {
    const url = new URL(base, location.origin);
    for (const [k, v] of Object.entries(params)) {
      if (v !== null && v !== undefined && v !== '') url.searchParams.set(k, String(v));
    }
    return url.pathname + url.search;
  }

  const aborts = {};
  /** One AbortController per view: starting a view cancels its last fetch. */
  function signalFor(view) {
    if (aborts[view]) aborts[view].abort();
    aborts[view] = new AbortController();
    return aborts[view].signal;
  }

  const isAbort = (e) => e && e.name === 'AbortError';

  // ---- colours -------------------------------------------------------------

  let colours = {};
  function readColours() {
    const cs = getComputedStyle(document.documentElement);
    const tok = (n) => cs.getPropertyValue(n).trim();
    colours = {
      stage: tok('--atlas-stage') || '#fbfbf9',
      region: tok('--atlas-region') || '#eef0ec',
      theme: tok('--atlas-theme') || '#f4f5f1',
      outline: tok('--atlas-outline') || '#5b6167',
      label: tok('--atlas-label') || '#1d1f21',
      muted: tok('--atlas-muted') || '#8a9096',
      critical: tok('--atlas-critical') || tok('--refute') || '#b3473a',
      accent: tok('--atlas-accent') || tok('--accent') || '#2d5f8a',
      none: tok('--atlas-belief-none') || '#a9adb1',
      ramp: [0, 1, 2, 3, 4, 5, 6].map((i) => tok('--atlas-belief-' + i) || '#7c9fc0'),
    };
  }

  function fillFor(truth) {
    const t = num(truth);
    if (t === null) return colours.none;
    return colours.ramp[Math.max(0, Math.min(6, Math.round(6 * t)))];
  }

  // ---- d3 with local fallbacks --------------------------------------------

  function interpolateZoom(a, b) {
    if (typeof d3.interpolateZoom === 'function') return d3.interpolateZoom(a, b);
    const f = (t) => [
      a[0] + (b[0] - a[0]) * t,
      a[1] + (b[1] - a[1]) * t,
      a[2] * Math.pow(b[2] / a[2], t),
    ];
    f.duration = 900;
    return f;
  }

  function ease(t) {
    if (typeof d3.easeCubicInOut === 'function') return d3.easeCubicInOut(t);
    return t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;
  }

  /** Circles `{r}` packed inside a circle of radius `R` round (cx, cy). */
  function packInto(items, cx, cy, R) {
    if (items.length === 0) return;
    if (typeof d3.pack === 'function' && typeof d3.hierarchy === 'function') {
      const size = 2 * R;
      const h = d3
        .hierarchy({ children: items })
        .sum((d) => (d.children ? 0 : Math.max(1, d.value || 1)));
      d3.pack().size([size, size]).padding(size / 150)(h);
      for (const leaf of h.leaves()) {
        leaf.data.x = cx - R + leaf.x;
        leaf.data.y = cy - R + leaf.y;
        leaf.data.r = leaf.r;
      }
      return;
    }
    // Fallback: a sunflower spiral, area by value.
    const total = items.reduce((s, d) => s + Math.max(1, d.value || 1), 0);
    items.forEach((d, i) => {
      const share = Math.max(1, d.value || 1) / total;
      d.r = R * Math.sqrt(share) * 0.7;
      const rho = 0.8 * R * Math.sqrt((i + 0.5) / items.length);
      d.x = cx + rho * Math.cos(i * GOLDEN);
      d.y = cy + rho * Math.sin(i * GOLDEN);
    });
  }

  /** The client-side collision pass: targets kept, overlaps pushed apart. */
  function collide(items, pad, centre) {
    if (items.length < 2 || typeof d3.forceSimulation !== 'function') return;
    const sim = d3
      .forceSimulation(items.map((d) => ({ x: d.x, y: d.y, tx: d.x, ty: d.y, r: d.r, ref: d })))
      .force('x', d3.forceX((d) => d.tx).strength(0.3))
      .force('y', d3.forceY((d) => d.ty).strength(0.3))
      .force('collide', d3.forceCollide((d) => d.r + pad));
    if (centre && typeof d3.forceRadial === 'function') {
      sim.force('radial', d3.forceRadial(0, centre.x, centre.y).strength(0.02));
    }
    sim.stop().tick(120);
    for (const n of sim.nodes()) {
      n.ref.x = n.x;
      n.ref.y = n.y;
    }
  }

  function hashAngle(id) {
    let h = 2166136261;
    for (const c of String(id)) {
      h ^= c.charCodeAt(0);
      h = Math.imul(h, 16777619);
    }
    return ((h >>> 0) / 4294967296) * 2 * Math.PI;
  }

  // ---- scene ---------------------------------------------------------------

  function makeNode(kind, props) {
    return Object.assign(
      {
        kind,
        id: null,
        key: null,
        label: '',
        x: 0,
        y: 0,
        r: 1,
        value: 0,
        truth: null,
        contested: false,
        parent: null,
        children: null,
        state: 'idle',
        error: null,
        next: null,
        links: [],
        data: null,
      },
      props,
    );
  }

  const S = {
    mode: 'layout',
    run: null,
    scale: 1,
    structure: false,
    root: null,
    regionsById: new Map(),
    themesById: new Map(),
    selected: null,
    ring: null,
    rim: [],
    cam: { cx: 0, cy: 0, k: 1 },
    width: 1,
    height: 1,
    drawn: [],
    curves: [],
    flight: null,
    dirty: false,
    settleTimer: null,
    themeDirectory: null,
  };

  function V() {
    return Math.max(1, Math.min(S.width, S.height));
  }

  function toScreen(x, y) {
    return [(x - S.cam.cx) * S.cam.k + S.width / 2, (y - S.cam.cy) * S.cam.k + S.height / 2];
  }

  function toWorld(sx, sy) {
    return [(sx - S.width / 2) / S.cam.k + S.cam.cx, (sy - S.height / 2) / S.cam.k + S.cam.cy];
  }

  function kBounds() {
    const rootK = S.root ? V() / (2.2 * S.root.r) : 1;
    return [rootK / 2, (V() / 2.2) * 8];
  }

  function clampK(k) {
    const [lo, hi] = kBounds();
    return Math.max(lo, Math.min(hi, k));
  }

  function redraw() {
    if (S.dirty) return;
    S.dirty = true;
    requestAnimationFrame(frame);
  }

  function setNotice(text) {
    if (!dom.notice) return;
    dom.notice.textContent = text || '';
    dom.notice.hidden = !text;
  }

  function setCaption(text) {
    if (!dom.caption) return;
    dom.caption.textContent = text || '';
    dom.caption.hidden = !text;
  }

  function resetScene() {
    S.root = null;
    S.regionsById = new Map();
    S.themesById = new Map();
    S.selected = null;
    S.ring = null;
    S.rim = [];
    S.flight = null;
  }

  function boundingRoot(children) {
    let minX = Infinity;
    let minY = Infinity;
    let maxX = -Infinity;
    let maxY = -Infinity;
    for (const c of children) {
      minX = Math.min(minX, c.x - c.r);
      minY = Math.min(minY, c.y - c.r);
      maxX = Math.max(maxX, c.x + c.r);
      maxY = Math.max(maxY, c.y + c.r);
    }
    if (!Number.isFinite(minX)) return { x: 0, y: 0, r: WORLD / 2 };
    const x = (minX + maxX) / 2;
    const y = (minY + maxY) / 2;
    let r = 1;
    for (const c of children) r = Math.max(r, Math.hypot(c.x - x, c.y - y) + c.r);
    return { x, y, r };
  }

  // ---- loading levels ------------------------------------------------------

  /** Load the top level; `follow` then follows the page's #c- hash. */
  async function loadTop(runPin, follow = true) {
    resetScene();
    setNotice('');
    setPanelStatus('Loading the map…');
    const url = withQuery(cfg.layout, {
      run: runPin ? uuid(runPin) : null,
      structure: S.structure ? '1' : null,
    });
    let body;
    try {
      body = await getJSON(url, signalFor('top'));
    } catch (e) {
      if (isAbort(e) || e.status === 401) return;
      if (e.status === 404 && runPin) return loadTop(null, follow);
      setPanelStatus('');
      showPanelError('The map could not load. ' + e.message, () => loadTop(null));
      return;
    }
    if (body.mode === 'packed') buildPacked(body);
    else buildTop(body);
    fitRoot(false);
    showNodePanel(S.root);
    setPanelStatus('');
    redraw();
    if (follow) await followHash();
  }

  function buildTop(body) {
    S.mode = 'layout';
    S.run = body.run ? uuid(body.run.run_id) : null;
    const extent = num(body.run && body.run.extent) || WORLD;
    S.scale = WORLD / extent;
    const regions = [];
    for (const r of body.regions || []) {
      const id = uuid(r.id);
      if (!id) continue;
      const n = makeNode('region', {
        id,
        label: r.label || '',
        x: (num(r.x) || 0) * S.scale,
        y: (num(r.y) || 0) * S.scale,
        r: Math.max(1, (num(r.r) || 1) * S.scale),
        value: num(r.member_count) || 0,
        themeCount: num(r.theme_count) || 0,
      });
      regions.push(n);
      S.regionsById.set(id, n);
    }
    collide(regions, 4, null);
    const unplaced = num(body.unplaced_theme_count) || 0;
    if (unplaced > 0) {
      const b = boundingRoot(regions);
      const maxR = regions.reduce((m, n) => Math.max(m, n.r), WORLD / 10);
      regions.push(
        makeNode('unplaced', {
          id: 'unplaced',
          label: 'Not on the map',
          x: b.x + b.r + maxR,
          y: b.y + b.r - maxR,
          r: maxR * 0.8,
          themeCount: unplaced,
        }),
      );
    }
    const box = boundingRoot(regions);
    S.root = makeNode('root', {
      label: 'All regions',
      x: box.x,
      y: box.y,
      r: box.r,
      children: regions,
      state: 'ok',
      links: (body.links || []).filter((l) => uuid(l.a) && uuid(l.b)),
      next: body.next && body.next.links ? body.next.links : null,
    });
    for (const c of regions) c.parent = S.root;
    setNotice(body.notice || '');
  }

  function buildPacked(body) {
    S.mode = 'packed';
    S.run = null;
    S.scale = 1;
    const root = S.root || makeNode('root', { label: 'All themes', x: 0, y: 0, r: WORLD / 2, children: [], state: 'ok' });
    for (const t of body.themes || []) {
      const id = uuid(t.id);
      if (!id || S.themesById.has(id)) continue;
      const n = makeNode('theme', { id, label: t.label || '', value: num(t.member_count) || 0, parent: root });
      root.children.push(n);
      S.themesById.set(id, n);
    }
    packInto(root.children, 0, 0, WORLD / 2);
    root.next = body.next || null;
    S.root = root;
    setNotice(body.notice || 'There is no layout run yet, so positions carry no meaning.');
  }

  async function morePacked() {
    if (!S.root || !S.root.next) return;
    try {
      const body = await getJSON(withQuery(cfg.layout, { after: S.root.next, structure: S.structure ? '1' : null }), signalFor('top'));
      if (body.mode === 'packed') buildPacked(body);
      showNodePanel(S.root);
      redraw();
    } catch (e) {
      if (!isAbort(e)) setPanelStatus(e.message);
    }
  }

  function regionQuery(node, extra) {
    return withQuery(
      cfg.layout,
      Object.assign(
        {
          region: node.kind === 'unplaced' ? 'unplaced' : node.id,
          run: S.run,
          structure: S.structure ? '1' : null,
        },
        extra || {},
      ),
    );
  }

  async function loadRegion(node, more) {
    if (node.state === 'loading') return;
    node.state = 'loading';
    redraw();
    let body;
    try {
      body = await getJSON(regionQuery(node, more ? { themes_after: node.next } : null));
    } catch (e) {
      node.state = 'error';
      node.error = e.message;
      if (e.status === 404 && S.run) {
        // The pinned map version is gone: start again from the latest.
        loadTop(null);
        return;
      }
      if (S.selected === node) showNodePanel(node);
      redraw();
      return;
    }
    if (body.mode === 'packed') {
      loadTop(null);
      return;
    }
    const themes = more ? node.children || [] : [];
    for (const t of body.themes || []) {
      const id = uuid(t.id);
      if (!id || themes.some((x) => x.id === id)) continue;
      const n = makeNode('theme', {
        id,
        label: t.label || '',
        value: num(t.member_count) || 0,
        placement: t.placement,
        sx: num(t.x),
        sy: num(t.y),
        parent: node,
      });
      themes.push(n);
      S.themesById.set(id, n);
    }
    placeThemes(node, themes);
    node.children = themes;
    node.links = (more ? node.links : []).concat((body.links || []).filter((l) => uuid(l.a) && uuid(l.b)));
    node.next = body.next && body.next.themes ? body.next.themes : null;
    node.state = 'ok';
    node.error = null;
    if (S.selected === node) showNodePanel(node);
    redraw();
  }

  function placeThemes(region, themes) {
    if (region.kind === 'unplaced') {
      packInto(themes, region.x, region.y, region.r * 0.95);
      return;
    }
    const total = themes.reduce((s, t) => s + Math.max(1, t.value), 0) || 1;
    for (const t of themes) {
      t.r = region.r * Math.sqrt(Math.max(1, t.value) / total) * 0.9;
      if (t.sx !== null && t.sy !== null && t.placement === 'shared') {
        t.x = t.sx * S.scale;
        t.y = t.sy * S.scale;
      } else {
        const a = hashAngle(t.id);
        t.x = region.x + 0.6 * region.r * Math.cos(a);
        t.y = region.y + 0.6 * region.r * Math.sin(a);
      }
    }
    collide(themes, region.r / 100, { x: region.x, y: region.y });
  }

  async function loadTheme(node, more) {
    if (node.state === 'loading') return;
    if (more && !node.next) return;
    node.state = 'loading';
    redraw();
    const url = withQuery(cfg.themeClaims + encodeURIComponent(node.id) + '/claims', {
      after: more ? node.next : null,
    });
    let body;
    try {
      body = await getJSON(url);
    } catch (e) {
      node.state = 'error';
      node.error = e.message;
      if (S.selected === node) showNodePanel(node);
      redraw();
      return;
    }
    const claims = more ? node.children || [] : [];
    node.value = num(body.member_count) || node.value;
    for (const c of body.claims || []) {
      const id = uuid(c.id);
      if (!id || claims.some((x) => x.id === id)) continue;
      claims.push(
        makeNode('claim', {
          id,
          key: 'c-' + simple(id),
          label: c.label || '',
          truth: num(c.truth_value),
          rank: num(c.rank) || 0,
          href: localPath(c.href),
          parent: node,
        }),
      );
    }
    placeClaims(node, claims);
    node.children = claims;
    node.next = body.next || null;
    node.state = 'ok';
    node.error = null;
    if (S.selected === node) showNodePanel(node);
    redraw();
    if (!more) loadRimMarks(node);
  }

  function placeClaims(theme, claims) {
    const n = Math.max(theme.value, claims.length, 1);
    const r = Math.min((0.75 * theme.r) / Math.sqrt(n), 0.12 * theme.r);
    for (const c of claims) {
      if (c.pinned) continue;
      const rho = 0.92 * theme.r * Math.sqrt((c.rank + 0.5) / n);
      const th = c.rank * GOLDEN;
      c.x = theme.x + rho * Math.cos(th);
      c.y = theme.y + rho * Math.sin(th);
      c.r = Math.max(r, theme.r / 400);
    }
  }

  /** Rim marks: the theme's strongest partners only, each list on its own. */
  async function loadRimMarks(theme) {
    const region = theme.parent;
    if (!region || !region.links) return;
    // Theme-theme links are stored once with a < b, so the opened theme can be
    // either end; a theme_region link always has the theme as a.
    const partners = region.links
      .map((l) => ({
        total: l.total,
        b: l.a === theme.id ? l.b : l.b === theme.id && l.kind !== 'theme_region' ? l.a : null,
      }))
      .filter((p) => p.b)
      .sort((x, y) => (y.total || 0) - (x.total || 0))
      .slice(0, RIM_PARTNERS);
    const signal = signalFor('rim');
    S.rim = S.rim.filter((m) => m.theme !== theme);
    for (const p of partners) {
      const url = withQuery(cfg.links, {
        from: theme.id,
        to: p.b,
        run: S.run,
        structure: S.structure ? '1' : null,
        limit: 200,
      });
      getJSON(url, signal)
        .then((body) => {
          const ids = new Set();
          for (const g of body.groups || []) {
            for (const it of g.items || []) {
              if (it.source) ids.add(it.source.id);
              if (it.target) ids.add(it.target.id);
            }
          }
          for (const c of theme.children || []) {
            if (ids.has(c.id)) S.rim.push({ theme, claim: c, partner: p.b });
          }
          redraw();
        })
        .catch(() => {});
    }
  }

  async function loadClaim(node) {
    if (node.state === 'loading') return;
    node.state = 'loading';
    redraw();
    try {
      const body = await getJSON(cfg.claim + encodeURIComponent(node.id), signalFor('claim'));
      node.data = body;
      node.state = 'ok';
      node.error = null;
      node.contested = Boolean(body.contested && body.contested.status === 'ok' && body.contested.data.contested);
      if (body.claim) node.truth = num(body.claim.truth_value);
      buildRing(node, body);
    } catch (e) {
      if (isAbort(e)) {
        node.state = 'idle';
        return;
      }
      node.state = 'error';
      node.error = e.message;
    }
    if (S.selected === node) showClaimPanel(node);
    redraw();
  }

  function buildRing(node, body) {
    const ring = body.ring && body.ring.status === 'ok' ? body.ring.data : null;
    if (!ring) {
      S.ring = { centre: node, inner: [], outer: [] };
      return;
    }
    const inner = [];
    const outer = [];
    const add = (list, n, family, rel) => {
      const id = uuid(n && n.id);
      if (!id || id === node.id || list.some((x) => x.id === id)) return;
      list.push(
        makeNode('ring', {
          id,
          key: 'c-' + simple(id),
          label: n.label || '',
          truth: num(n.truth_value),
          crossTheme: Boolean(n.cross_theme),
          themeLabel: n.theme && n.theme.label ? n.theme.label : null,
          family,
          rel,
          href: localPath(n.href),
          parent: node,
        }),
      );
    };
    if (ring.section) add(inner, ring.section, 'structural', 'section');
    for (const n of (ring.parents && ring.parents.items) || []) add(inner, n, 'structural', 'parent');
    for (const n of (ring.parts && ring.parts.items) || []) add(inner, n, 'structural', 'part');
    for (const e of (ring.edges && ring.edges.items) || []) add(inner, e.neighbor, e.family, e.words);
    for (const n of (ring.siblings && ring.siblings.items) || []) add(outer, n, 'structural', 'sibling');
    const place = (list, radius) => {
      const step = (2 * Math.PI) / Math.max(1, list.length);
      const rr = Math.min(node.r * 0.35, (Math.PI * radius) / Math.max(1, list.length) / 1.2);
      list.forEach((n, i) => {
        n.x = node.x + radius * Math.cos(i * step - Math.PI / 2);
        n.y = node.y + radius * Math.sin(i * step - Math.PI / 2);
        n.r = Math.max(rr, node.r / 50);
      });
    };
    place(inner, 2.4 * node.r);
    place(outer, 3.6 * node.r);
    S.ring = { centre: node, inner, outer };
  }

  /** Children are requested once a node fills about a third of the view. */
  function maybeLoad(node, rs) {
    if (rs < V() / 3 || node.state !== 'idle') return;
    if (node.kind === 'region' || node.kind === 'unplaced') loadRegion(node, false);
    else if (node.kind === 'theme') loadTheme(node, false);
    else if (node.kind === 'claim' && (!S.ring || S.ring.centre !== node)) loadClaim(node);
  }

  // ---- drawing -------------------------------------------------------------

  function smoothstep(a, b, x) {
    const t = Math.max(0, Math.min(1, (x - a) / (b - a)));
    return t * t * (3 - 2 * t);
  }

  const wrapCache = new Map();
  function wrap(text, fontPx, maxWidth) {
    const key = text + '|' + fontPx + '|' + Math.round(maxWidth);
    const hit = wrapCache.get(key);
    if (hit) return hit;
    ctx.font = fontPx + 'px system-ui, sans-serif';
    const words = text.split(' ');
    const lines = [];
    let line = '';
    for (const w of words) {
      const next = line ? line + ' ' + w : w;
      if (ctx.measureText(next).width > maxWidth && line) {
        lines.push(line);
        line = w;
        if (lines.length === 3) break;
      } else {
        line = next;
      }
    }
    if (lines.length < 3 && line) lines.push(line);
    if (wrapCache.size > 4000) wrapCache.clear();
    wrapCache.set(key, lines);
    return lines;
  }

  function drawLabel(text, sx, sy, rs, alpha) {
    if (!text || alpha <= 0.02) return;
    const fontPx = Math.round(Math.max(11, Math.min(18, rs / 5)));
    const lines = wrap(text, fontPx, Math.max(40, rs * 1.6));
    ctx.globalAlpha = alpha;
    ctx.fillStyle = colours.label;
    ctx.font = fontPx + 'px system-ui, sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    const top = sy - ((lines.length - 1) * fontPx * 1.2) / 2;
    lines.forEach((l, i) => ctx.fillText(l, sx, top + i * fontPx * 1.2));
    ctx.globalAlpha = 1;
  }

  function visible(sx, sy, rs) {
    return sx + rs >= 0 && sy + rs >= 0 && sx - rs <= S.width && sy - rs <= S.height;
  }

  function collect(node, out) {
    const [sx, sy] = toScreen(node.x, node.y);
    const rs = node.r * S.cam.k;
    if (node.kind !== 'root') {
      if (!visible(sx, sy, rs)) return;
      if ((node.kind === 'claim' || node.kind === 'ring') && rs < MIN_CLAIM_PX) return;
      out.push({ node, sx, sy, rs });
      maybeLoad(node, rs);
    }
    if (node.children) for (const c of node.children) collect(c, out);
  }

  function curvePoints(ax, ay, bx, by) {
    const mx = (ax + bx) / 2;
    const my = (ay + by) / 2;
    const dx = bx - ax;
    const dy = by - ay;
    const cx = mx - dy * 0.15;
    const cy = my + dx * 0.15;
    const pts = [];
    for (let i = 0; i <= 16; i++) {
      const t = i / 16;
      const u = 1 - t;
      pts.push([u * u * ax + 2 * u * t * cx + t * t * bx, u * u * ay + 2 * u * t * cy + t * t * by]);
    }
    return pts;
  }

  function strokePoints(pts, from, to) {
    ctx.beginPath();
    for (let i = from; i <= to; i++) {
      if (i === from) ctx.moveTo(pts[i][0], pts[i][1]);
      else ctx.lineTo(pts[i][0], pts[i][1]);
    }
    ctx.stroke();
  }

  function drawBundles() {
    S.curves = [];
    const scopes = [];
    if (S.root && S.mode === 'layout') scopes.push(S.root);
    for (const r of S.regionsById.values()) if (r.state === 'ok') scopes.push(r);
    for (const scope of scopes) {
      const lks = scope.links || [];
      const maxTotal = lks.reduce((m, l) => Math.max(m, l.total || 0), 1);
      for (const l of lks) {
        const a = scope === S.root ? S.regionsById.get(l.a) : S.themesById.get(l.a);
        if (!a) continue;
        let b;
        let stub = false;
        if (l.kind === 'theme_region') {
          b = S.regionsById.get(l.b);
          stub = true;
        } else if (scope === S.root) {
          b = S.regionsById.get(l.b);
        } else {
          b = S.themesById.get(l.b);
        }
        if (!b) continue;
        const [ax, ay] = toScreen(a.x, a.y);
        let [bx, by] = toScreen(b.x, b.y);
        if (scope !== S.root && a.r * S.cam.k < 6) continue;
        if (stub) {
          const len = Math.hypot(bx - ax, by - ay) || 1;
          const reach = a.r * S.cam.k + 40;
          bx = ax + ((bx - ax) / len) * reach;
          by = ay + ((by - ay) / len) * reach;
        }
        const pts = curvePoints(ax, ay, bx, by);
        const width = 1 + 7 * Math.sqrt((l.total || 0) / maxTotal);
        ctx.lineWidth = width;
        ctx.strokeStyle = colours.muted;
        ctx.setLineDash([]);
        ctx.globalAlpha = 0.55;
        strokePoints(pts, 0, 16);
        const share = Math.max(0, Math.min(1, num(l.refute_share) || 0));
        if (share > 0) {
          const half = Math.max(1, Math.round(share * 8));
          ctx.strokeStyle = colours.critical;
          ctx.setLineDash([6, 4]);
          strokePoints(pts, Math.max(0, 8 - half), Math.min(16, 8 + half));
          ctx.setLineDash([]);
        }
        ctx.globalAlpha = 1;
        if (stub) {
          const region = S.regionsById.get(l.b);
          ctx.fillStyle = colours.label;
          ctx.font = '11px system-ui, sans-serif';
          ctx.textAlign = 'left';
          ctx.fillText((region ? region.label : '') + ' · ' + (l.total || 0), bx + 4, by);
        }
        S.curves.push({ link: l, pts, a, b: stub ? S.regionsById.get(l.b) : b, stub });
      }
    }
  }

  function drawNode(item) {
    const { node, sx, sy, rs } = item;
    ctx.beginPath();
    ctx.arc(sx, sy, rs, 0, 2 * Math.PI);
    if (node.kind === 'region' || node.kind === 'unplaced') {
      ctx.fillStyle = colours.region;
      ctx.fill();
      ctx.lineWidth = 1;
      ctx.strokeStyle = colours.outline;
      ctx.globalAlpha = 0.35;
      ctx.setLineDash(node.kind === 'unplaced' ? [4, 4] : []);
      ctx.stroke();
      ctx.setLineDash([]);
      ctx.globalAlpha = 1;
    } else if (node.kind === 'theme') {
      ctx.fillStyle = colours.theme;
      ctx.fill();
      ctx.lineWidth = 1;
      ctx.strokeStyle = colours.outline;
      ctx.globalAlpha = 0.5;
      ctx.stroke();
      ctx.globalAlpha = 1;
    } else {
      ctx.fillStyle = fillFor(node.truth);
      ctx.fill();
      ctx.lineWidth = 1;
      ctx.strokeStyle = colours.outline;
      ctx.stroke();
      if (node.contested) {
        ctx.beginPath();
        ctx.arc(sx, sy, rs + 3, 0, 2 * Math.PI);
        ctx.strokeStyle = colours.critical;
        ctx.setLineDash([4, 3]);
        ctx.lineWidth = 2;
        ctx.stroke();
        ctx.setLineDash([]);
      }
    }
    if (S.selected === node) {
      ctx.beginPath();
      ctx.arc(sx, sy, rs + 2, 0, 2 * Math.PI);
      ctx.strokeStyle = colours.accent;
      ctx.lineWidth = 2;
      ctx.stroke();
    }
    const parentFade = node.children && node.children.length ? 1 - smoothstep(0.3 * V(), 0.45 * V(), rs) : 1;
    drawLabel(node.label, sx, sy, rs, smoothstep(28, 60, rs) * parentFade);
    if (node.state === 'error' && rs > 20) {
      ctx.fillStyle = colours.critical;
      ctx.font = '12px system-ui, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText('Couldn’t load, retry', sx, sy + Math.min(rs * 0.6, 40));
    }
    if (node.kind === 'theme' && node.children && rs > 0.35 * V()) {
      S.caption = 'Closer to the centre = closer to the theme’s core.';
    }
  }

  function drawRing() {
    const ring = S.ring;
    if (!ring || !ring.centre) return [];
    const out = [];
    const [cx, cy] = toScreen(ring.centre.x, ring.centre.y);
    for (const n of ring.inner.concat(ring.outer)) {
      const [sx, sy] = toScreen(n.x, n.y);
      const rs = n.r * S.cam.k;
      if (rs < MIN_CLAIM_PX || !visible(sx, sy, rs)) continue;
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.lineTo(sx, sy);
      ctx.lineWidth = 1.5;
      if (n.family === 'refute') {
        ctx.strokeStyle = colours.critical;
        ctx.setLineDash([6, 4]);
      } else if (n.family === 'support') {
        ctx.strokeStyle = colours.accent;
        ctx.setLineDash([]);
      } else {
        ctx.strokeStyle = colours.muted;
        ctx.setLineDash([]);
      }
      ctx.stroke();
      ctx.setLineDash([]);
      out.push({ node: n, sx, sy, rs });
    }
    for (const it of out) {
      drawNode(it);
      if (it.node.crossTheme && it.node.themeLabel && it.rs > 6) {
        ctx.fillStyle = colours.muted;
        ctx.font = '11px system-ui, sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText(it.node.themeLabel, it.sx, it.sy + it.rs + 12);
      }
    }
    return out;
  }

  function drawRim() {
    for (const m of S.rim) {
      const c = m.claim;
      const target = S.themesById.get(m.partner) || S.regionsById.get(m.partner);
      if (!target) continue;
      const [sx, sy] = toScreen(c.x, c.y);
      const rs = c.r * S.cam.k;
      if (rs < 4 || !visible(sx, sy, rs)) continue;
      const a = Math.atan2(target.y - c.y, target.x - c.x);
      const tipX = sx + Math.cos(a) * (rs + 6);
      const tipY = sy + Math.sin(a) * (rs + 6);
      ctx.beginPath();
      ctx.moveTo(tipX, tipY);
      ctx.lineTo(sx + Math.cos(a + 0.35) * rs, sy + Math.sin(a + 0.35) * rs);
      ctx.lineTo(sx + Math.cos(a - 0.35) * rs, sy + Math.sin(a - 0.35) * rs);
      ctx.closePath();
      ctx.fillStyle = colours.accent;
      ctx.fill();
    }
  }

  function frame() {
    S.dirty = false;
    if (S.flight) stepFlight();
    const dpr = window.devicePixelRatio || 1;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.fillStyle = colours.stage;
    ctx.fillRect(0, 0, S.width, S.height);
    S.caption = '';
    if (!S.root) return;
    drawBundles();
    const items = [];
    collect(S.root, items);
    // At most MAX_DRAWN items, the smallest dropped first; parents first.
    let drawn = items;
    if (items.length > MAX_DRAWN) {
      drawn = items
        .slice()
        .sort((x, y) => y.rs - x.rs)
        .slice(0, MAX_DRAWN);
      const keep = new Set(drawn);
      drawn = items.filter((i) => keep.has(i));
    }
    for (const it of drawn) drawNode(it);
    drawRim();
    const ringItems = drawRing();
    S.drawn = drawn.concat(ringItems);
    if (S.rim.length) {
      S.caption = (S.caption ? S.caption + ' ' : '') + 'Rim marks show links to the strongest partners only.';
    }
    if (!dom.caption || dom.caption.textContent !== S.caption) setCaption(S.caption);
    if (S.flight) redraw();
  }

  function resize() {
    const dpr = window.devicePixelRatio || 1;
    const w = Math.max(1, dom.stage.clientWidth);
    const h = Math.max(1, dom.stage.clientHeight);
    S.width = w;
    S.height = h;
    dom.canvas.setAttribute('width', String(Math.round(w * dpr)));
    dom.canvas.setAttribute('height', String(Math.round(h * dpr)));
    wrapCache.clear();
    redraw();
  }

  // ---- camera --------------------------------------------------------------

  function fitRoot(animate) {
    if (!S.root) return;
    if (animate) flyTo(S.root);
    else {
      S.cam = { cx: S.root.x, cy: S.root.y, k: V() / (2.2 * S.root.r) };
      redraw();
    }
  }

  function flyTo(node, done) {
    const w0 = V() / S.cam.k;
    const w1 = 2.2 * node.r;
    if (!motionOK()) {
      S.cam = { cx: node.x, cy: node.y, k: clampK(V() / w1) };
      S.flight = null;
      redraw();
      settle();
      if (done) done();
      return;
    }
    const i = interpolateZoom([S.cam.cx, S.cam.cy, w0], [node.x, node.y, w1]);
    S.flight = { i, start: performance.now(), duration: Math.max(250, (i.duration || 900) * 0.8), done };
    redraw();
  }

  function stepFlight() {
    const f = S.flight;
    const t = Math.min(1, (performance.now() - f.start) / f.duration);
    const [cx, cy, w] = f.i(ease(t));
    S.cam = { cx, cy, k: clampK(V() / w) };
    if (t >= 1) {
      S.flight = null;
      settle();
      if (f.done) f.done();
    }
  }

  function settle() {
    clearTimeout(S.settleTimer);
    S.settleTimer = setTimeout(updateCrumbs, SETTLE_MS);
  }

  function zoomAt(sx, sy, factor) {
    const [wx, wy] = toWorld(sx, sy);
    const k = clampK(S.cam.k * factor);
    S.cam = { cx: wx - (sx - S.width / 2) / k, cy: wy - (sy - S.height / 2) / k, k };
    S.flight = null;
    redraw();
    settle();
  }

  // ---- input ---------------------------------------------------------------

  const pointers = new Map();
  let dragMoved = false;
  let pinchDist = null;

  dom.canvas.addEventListener('pointerdown', (e) => {
    dom.canvas.setPointerCapture(e.pointerId);
    pointers.set(e.pointerId, { x: e.offsetX, y: e.offsetY });
    dragMoved = false;
    pinchDist = null;
    dom.canvas.classList.add('is-dragging');
  });

  dom.canvas.addEventListener('pointermove', (e) => {
    const prev = pointers.get(e.pointerId);
    if (!prev) return;
    const cur = { x: e.offsetX, y: e.offsetY };
    pointers.set(e.pointerId, cur);
    if (pointers.size === 2) {
      const [p1, p2] = Array.from(pointers.values());
      const d = Math.hypot(p1.x - p2.x, p1.y - p2.y);
      if (pinchDist) zoomAt((p1.x + p2.x) / 2, (p1.y + p2.y) / 2, d / pinchDist);
      pinchDist = d;
      dragMoved = true;
      return;
    }
    const dx = cur.x - prev.x;
    const dy = cur.y - prev.y;
    if (Math.abs(dx) + Math.abs(dy) > 0) {
      if (Math.abs(dx) + Math.abs(dy) > 2) dragMoved = true;
      S.cam = { cx: S.cam.cx - dx / S.cam.k, cy: S.cam.cy - dy / S.cam.k, k: S.cam.k };
      S.flight = null;
      redraw();
      settle();
    }
  });

  function endPointer(e) {
    const p = pointers.get(e.pointerId);
    pointers.delete(e.pointerId);
    if (pointers.size < 2) pinchDist = null;
    if (pointers.size === 0) dom.canvas.classList.remove('is-dragging');
    if (p && !dragMoved && e.type === 'pointerup') click(p.x, p.y);
  }
  dom.canvas.addEventListener('pointerup', endPointer);
  dom.canvas.addEventListener('pointercancel', endPointer);

  dom.canvas.addEventListener(
    'wheel',
    (e) => {
      e.preventDefault();
      zoomAt(e.offsetX, e.offsetY, Math.exp(-e.deltaY * 0.0015));
    },
    { passive: false },
  );

  /** Bundles first (within 6 px of a sampled point), then the smallest circle. */
  function hitTest(x, y) {
    for (const c of S.curves) {
      if (c.pts.some((p) => Math.hypot(p[0] - x, p[1] - y) < 6)) return { curve: c };
    }
    let best = null;
    for (const it of S.drawn) {
      if (Math.hypot(it.sx - x, it.sy - y) <= it.rs && (!best || it.rs < best.rs)) best = it;
    }
    return best ? { node: best.node } : null;
  }

  function click(x, y) {
    const hit = hitTest(x, y);
    if (!hit) return;
    if (hit.curve) {
      if (hit.curve.stub && hit.curve.b) {
        select(hit.curve.b, true);
        return;
      }
      showLinksPanel(hit.curve.a, hit.curve.b);
      return;
    }
    const n = hit.node;
    if (n.state === 'error') n.state = 'idle';
    if (n.kind === 'ring') {
      followClaim(n.id);
      return;
    }
    select(n, true);
  }

  // ---- selection, breadcrumb, deep link ------------------------------------

  function pathTo(node) {
    const out = [];
    for (let n = node; n; n = n.parent) out.unshift(n);
    return out;
  }

  function updateCrumbs() {
    if (!dom.crumbs || !S.root) return;
    let deepest = S.root;
    const cx = S.width / 2;
    const cy = S.height / 2;
    for (const it of S.drawn) {
      if (it.node.kind === 'ring') continue;
      if (Math.hypot(it.sx - cx, it.sy - cy) <= it.rs && it.rs >= 0.35 * V()) {
        if (pathTo(it.node).length > pathTo(deepest).length) deepest = it.node;
      }
    }
    while (dom.crumbs.firstChild) dom.crumbs.removeChild(dom.crumbs.firstChild);
    const path = pathTo(deepest);
    path.forEach((n, i) => {
      const li = el('li');
      const b = button('atlas__crumb', n.label || (n.kind === 'root' ? 'All' : n.kind), () => select(n, true));
      if (i === path.length - 1) b.setAttribute('aria-current', 'location');
      li.appendChild(b);
      dom.crumbs.appendChild(li);
    });
    if (dom.inTheme) {
      const theme = path.find((n) => n.kind === 'theme');
      S.currentTheme = theme || (S.selected && S.selected.kind === 'claim' ? S.selected.parent : null);
      dom.inTheme.disabled = !S.currentTheme;
      if (!S.currentTheme) dom.inTheme.checked = false;
    }
  }

  function writeHash(node) {
    const base = location.pathname + location.search;
    if (node && node.kind === 'claim' && uuid(node.id)) {
      history.replaceState(null, '', base + '#c-' + simple(node.id));
    } else if (location.hash) {
      history.replaceState(null, '', base);
    }
  }

  function select(node, fly) {
    S.selected = node;
    writeHash(node);
    if (node.kind === 'claim') {
      showClaimPanel(node);
      if (!node.data) loadClaim(node);
      else buildRing(node, node.data);
    } else {
      S.ring = null;
      showNodePanel(node);
    }
    if (fly) flyTo(node);
    redraw();
    settle();
  }

  function clearSelection() {
    const parent = S.selected && S.selected.parent;
    S.selected = null;
    S.ring = null;
    writeHash(null);
    if (parent) select(parent, true);
    else fitRoot(true);
  }

  function setPanelStatus(text) {
    if (dom.panelStatus) dom.panelStatus.textContent = text || '';
  }

  function clearPanel(title) {
    if (dom.panelTitle) dom.panelTitle.textContent = title;
    while (dom.panelBody.firstChild) dom.panelBody.removeChild(dom.panelBody.firstChild);
    setPanelStatus('');
  }

  function section(title) {
    const s = el('section', 'atlas__section');
    if (title) s.appendChild(el('h3', null, title));
    dom.panelBody.appendChild(s);
    return s;
  }

  function unavailable(container, reason, retry) {
    const p = el('p', 'section-unavailable small', reason || 'Not available right now.');
    if (retry) p.appendChild(button('button-quiet atlas__retry', 'Retry', retry));
    container.appendChild(p);
  }

  function showPanelError(message, retry) {
    clearPanel('The Atlas');
    unavailable(section(null), message, retry);
  }

  function countText(n) {
    const v = num(n) || 0;
    return v.toLocaleString() + (v === 1 ? ' claim you can read' : ' claims you can read');
  }

  function showNodePanel(node) {
    if (!node) return;
    const title =
      node.kind === 'root' ? (S.mode === 'packed' ? 'All themes' : 'All regions') : node.label || 'Untitled';
    clearPanel(title);
    if (node.kind !== 'root' && node.kind !== 'unplaced') dom.panelBody.appendChild(el('p', 'small muted', countText(node.value)));
    if (node.state === 'error') unavailable(section(null), node.error, () => retryNode(node));
    const kids = node.children || [];
    if (node.kind !== 'root' && node.children === null && node.state !== 'error') {
      const s = section(null);
      s.appendChild(button('button-quiet', node.kind === 'theme' ? 'Show its claims' : 'Show its themes', () => select(node, true)));
    }
    if (kids.length) {
      const s = section(
        node.kind === 'theme' ? 'Claims, closest to the theme’s core first' : node.kind === 'root' && S.mode === 'layout' ? 'Regions' : 'Themes',
      );
      const ul = el('ul', 'atlas__list');
      for (const c of kids) {
        const li = el('li');
        li.appendChild(button('atlas__item', c.label || 'Untitled', () => select(c, true)));
        if (c.kind !== 'claim' && c.value) li.appendChild(el('span', 'small muted', (num(c.value) || 0).toLocaleString()));
        if (c.kind === 'claim' && c.href) li.appendChild(link(c.href, 'Open', 'small'));
        ul.appendChild(li);
      }
      s.appendChild(ul);
    }
    if (node.next && node.kind === 'theme') {
      dom.panelBody.appendChild(button('button-quiet', 'Show more claims', () => loadTheme(node, true)));
    } else if (node.next && (node.kind === 'region' || node.kind === 'unplaced')) {
      dom.panelBody.appendChild(button('button-quiet', 'Show more themes', () => loadRegion(node, true)));
    } else if (node.next && node.kind === 'root' && S.mode === 'packed') {
      dom.panelBody.appendChild(button('button-quiet', 'Show more themes', morePacked));
    }
    const partners = partnerLinks(node);
    if (partners.length) {
      const s = section(node.kind === 'theme' ? 'Links to other themes' : 'Links to other regions');
      const ul = el('ul', 'atlas__list');
      for (const p of partners) {
        const li = el('li');
        li.appendChild(button('atlas__item', p.other.label + ' · ' + (p.link.total || 0), () => showLinksPanel(node, p.other)));
        ul.appendChild(li);
      }
      s.appendChild(ul);
    }
  }

  function partnerLinks(node) {
    let scope = null;
    let lookup = null;
    if (node.kind === 'region') {
      scope = S.root;
      lookup = (id) => S.regionsById.get(id);
    } else if (node.kind === 'theme' && node.parent && node.parent.kind === 'region') {
      scope = node.parent;
      lookup = (id) => S.themesById.get(id) || S.regionsById.get(id);
    }
    if (!scope || !scope.links) return [];
    const out = [];
    for (const l of scope.links) {
      const otherId = l.a === node.id ? l.b : l.b === node.id && l.kind !== 'theme_region' ? l.a : null;
      const other = otherId && lookup(otherId);
      if (other) out.push({ link: l, other });
    }
    return out.sort((x, y) => (y.link.total || 0) - (x.link.total || 0)).slice(0, 12);
  }

  function retryNode(node) {
    node.state = 'idle';
    node.error = null;
    if (node.kind === 'claim') loadClaim(node);
    else if (node.kind === 'theme') loadTheme(node, false);
    else loadRegion(node, false);
  }

  function nodeList(container, items, emptyText) {
    if (!items || !items.length) {
      if (emptyText) container.appendChild(el('p', 'small muted', emptyText));
      return;
    }
    const ul = el('ul', 'atlas__list');
    for (const n of items) ul.appendChild(nodeItem(n));
    container.appendChild(ul);
  }

  function nodeItem(n, words) {
    const li = el('li');
    const id = uuid(n.id);
    const b = button('atlas__item', (words ? words + ' ' : '') + (n.label || ''), () => id && followClaim(id));
    if (n.cross_theme && n.theme && n.theme.label) b.appendChild(el('span', 'atlas__item-theme', 'in ' + n.theme.label));
    li.appendChild(b);
    if (n.href) li.appendChild(link(n.href, 'Open', 'small'));
    return li;
  }

  function truthBar(container, truth) {
    const t = num(truth);
    if (t === null) {
      container.appendChild(el('p', 'small muted', 'No authored truth value.'));
      return;
    }
    const bar = el('div', 'atlas__truth');
    bar.setAttribute('role', 'img');
    bar.setAttribute('aria-label', 'Authored truth value ' + t.toFixed(2));
    bar.appendChild(el('span', 'atlas__truth-marker atlas__truth-marker--' + Math.round(Math.max(0, Math.min(1, t)) * 10)));
    container.appendChild(bar);
    container.appendChild(el('p', 'small muted', 'Authored truth value ' + t.toFixed(2)));
  }

  function moreButton(container, claimId, list, cursor, render) {
    if (!cursor) return;
    const b = button('button-quiet', 'Show more', async () => {
      b.disabled = true;
      try {
        const body = await getJSON(withQuery(cfg.claim + encodeURIComponent(claimId), { list, after: cursor }));
        render(body);
        b.remove();
        moreButton(container, claimId, list, body.next, render);
      } catch (e) {
        b.disabled = false;
        if (!isAbort(e)) setPanelStatus(e.message);
      }
    });
    container.appendChild(b);
  }

  function showClaimPanel(node) {
    clearPanel('Claim');
    const body = node.data;
    if (node.state === 'loading' && !body) {
      setPanelStatus('Loading the claim…');
      dom.panelBody.appendChild(el('p', 'atlas__content', node.label));
      return;
    }
    if (node.state === 'error' && !body) {
      dom.panelBody.appendChild(el('p', 'atlas__content', node.label));
      unavailable(section(null), node.error, () => retryNode(node));
      return;
    }
    if (!body || !body.claim) return;
    const c = body.claim;
    const top = section(null);
    top.appendChild(el('p', 'atlas__content', c.content));
    if (c.content_truncated && c.href) top.appendChild(link(c.href, 'Read the full claim'));
    truthBar(top, c.truth_value);
    if (body.contested && body.contested.status === 'ok') {
      const k = body.contested.data;
      if (k.contested) {
        top.appendChild(
          el('p', 'atlas__contested small', 'Contested: ' + k.incoming + (k.incoming === 1 ? ' claim contradicts or refutes this' : ' claims contradict or refute this')),
        );
      }
    } else if (body.contested) {
      top.appendChild(el('p', 'small muted', body.contested.reason));
    }
    if (c.theme && c.theme.label) top.appendChild(el('p', 'small muted', 'Theme: ' + c.theme.label));

    const ringS = section('Linked claims');
    if (!body.ring || body.ring.status !== 'ok') {
      unavailable(ringS, body.ring ? body.ring.reason : null, () => {
        node.data = null;
        retryNode(node);
      });
    } else {
      const ring = body.ring.data;
      if (ring.paper) {
        const p = el('p', 'small');
        const text = ring.paper.title || ring.paper.doi || 'Source paper';
        const href = doiHref(ring.paper.doi_href);
        if (href) {
          const a = el('a', null, text);
          a.setAttribute('href', href);
          a.setAttribute('rel', 'noopener noreferrer');
          a.setAttribute('target', '_blank');
          p.appendChild(a);
        } else {
          p.textContent = text;
        }
        ringS.appendChild(p);
      }
      if (ring.section) {
        const s = el('div');
        s.appendChild(el('h4', 'small', 'Section'));
        nodeList(s, [ring.section]);
        ringS.appendChild(s);
      }
      const edges = ring.edges || { items: [] };
      const groups = new Map();
      for (const e of edges.items || []) {
        if (!groups.has(e.words)) groups.set(e.words, []);
        groups.get(e.words).push(e);
      }
      const edgeBox = el('div');
      for (const [words, list] of groups) {
        edgeBox.appendChild(el('h4', 'small', words));
        const ul = el('ul', 'atlas__list');
        for (const e of list) ul.appendChild(nodeItem(e.neighbor));
        edgeBox.appendChild(ul);
      }
      if (!groups.size) edgeBox.appendChild(el('p', 'small muted', 'No linked claims you can read.'));
      ringS.appendChild(edgeBox);
      moreButton(ringS, c.id, 'edges', edges.next, (page) => {
        const ul = el('ul', 'atlas__list');
        for (const e of page.items || []) ul.appendChild(nodeItem(e.neighbor, e.words));
        edgeBox.appendChild(ul);
      });
      for (const [name, title] of [
        ['parents', 'Part of'],
        ['parts', 'Parts'],
        ['siblings', 'Alongside'],
      ]) {
        const l = ring[name];
        if (!l || !l.items || !l.items.length) continue;
        const box = el('div');
        box.appendChild(el('h4', 'small', title + ' (' + (num(l.total) || l.items.length) + ')'));
        nodeList(box, l.items);
        ringS.appendChild(box);
        moreButton(box, c.id, name, l.next, (page) => nodeList(box, page.items));
      }
    }

    const more = section(null);
    if (c.history_href) more.appendChild(link(c.history_href, 'History'));
    more.appendChild(document.createTextNode(' · '));
    if (c.href) more.appendChild(link(c.href, 'Claim page'));
    const share = el('div', 'atlas__embed');
    const input = el('input');
    input.setAttribute('readonly', '');
    input.setAttribute('aria-label', 'Atlas link to this claim');
    input.value = typeof c.embed_url === 'string' ? c.embed_url : '';
    const copy = button('button-quiet', 'Copy', () => {
      if (navigator.clipboard && input.value) {
        navigator.clipboard.writeText(input.value).then(
          () => setPanelStatus('Link copied.'),
          () => input.select(),
        );
      } else {
        input.select();
      }
    });
    share.appendChild(input);
    share.appendChild(copy);
    more.appendChild(share);
  }

  async function showLinksPanel(a, b) {
    if (!a || !b || !uuid(a.id) || !uuid(b.id)) return;
    clearPanel('Links between ' + a.label + ' and ' + b.label);
    setPanelStatus('Loading links…');
    const signal = signalFor('panel');
    const box = section(null);
    const load = async (after) => {
      try {
        const body = await getJSON(
          withQuery(cfg.links, {
            from: a.id,
            to: b.id,
            run: S.run,
            structure: S.structure ? '1' : null,
            after,
          }),
          signal,
        );
        setPanelStatus('');
        if (body.status === 'layout_invalidated') {
          setNotice('The map has changed since it loaded; reloading.');
          loadTop(null);
          return;
        }
        if (num(body.total) !== null && !after) box.appendChild(el('p', 'small muted', body.total + ' links you can read'));
        for (const g of body.groups || []) {
          box.appendChild(el('h4', 'small', g.words + (num(g.count) !== null ? ' (' + g.count + ')' : '')));
          const ul = el('ul', 'atlas__list');
          for (const it of g.items || []) {
            const li = el('li');
            li.appendChild(button('atlas__item', it.source.label + ' → ' + it.target.label, () => followClaim(it.source.id)));
            ul.appendChild(li);
          }
          box.appendChild(ul);
        }
        if (body.next) {
          const more = button('button-quiet', 'Show more', () => {
            more.remove();
            load(body.next);
          });
          box.appendChild(more);
        }
      } catch (e) {
        if (isAbort(e)) return;
        setPanelStatus('');
        unavailable(box, e.message, () => showLinksPanel(a, b));
      }
    };
    load(null);
  }

  /**
   * A 401 from the BFF: the panel becomes a sign-in link carrying the hash.
   * Later panel writes go to a detached element, so nothing replaces it.
   */
  function sessionExpired() {
    if (S.expired) return;
    S.expired = true;
    clearPanel('Your session has expired');
    const s = section(null);
    const a = link(cfg.login || '/', 'Sign in again', 'button');
    s.appendChild(a);
    carryHash(a, cfg.login);
    dom.panelBody = document.createElement('div');
    dom.panelTitle = null;
    dom.panelStatus = null;
  }

  // ---- finding a claim on the map ------------------------------------------

  async function ensureRegion(regionId) {
    let region = regionId ? S.regionsById.get(regionId) : null;
    if (!region && !regionId && S.root) region = S.root.children.find((c) => c.kind === 'unplaced');
    if (!region) return null;
    if (region.state !== 'ok') {
      region.state = 'idle';
      await loadRegion(region, false);
    }
    return region;
  }

  async function ensureTheme(themeId, regionId) {
    let theme = S.themesById.get(themeId);
    if (!theme && S.mode === 'layout') {
      const region = await ensureRegion(regionId);
      let pages = 0;
      while (region && !S.themesById.get(themeId) && region.next && pages < FIND_PAGES) {
        await loadRegion(region, true);
        pages += 1;
      }
      theme = S.themesById.get(themeId);
    }
    if (!theme) return null;
    if (theme.state !== 'ok') {
      theme.state = 'idle';
      await loadTheme(theme, false);
    }
    return theme;
  }

  /** resolve → region → theme → up to three claim pages → select. */
  async function goToResolved(res) {
    if (S.run && res.run_id && res.run_id !== S.run) {
      // The claim was placed on a newer run than the one pinned: reload
      // the latest top level once (without re-following the hash).
      await loadTop(null, false);
    }
    const themeId = res.theme ? uuid(res.theme.id) : null;
    const claimId = uuid(res.claim_id);
    if (!claimId) return;
    const theme = themeId ? await ensureTheme(themeId, uuid(res.region_id)) : null;
    if (!theme) {
      setNotice('This claim is not on the map yet.');
      return;
    }
    let pages = 0;
    let claim = (theme.children || []).find((c) => c.id === claimId);
    while (!claim && theme.next && pages < FIND_PAGES - 1) {
      await loadTheme(theme, true);
      pages += 1;
      claim = (theme.children || []).find((c) => c.id === claimId);
    }
    if (!claim) {
      claim = makeNode('claim', {
        id: claimId,
        key: 'c-' + simple(claimId),
        label: 'Not among the closest ' + (theme.children || []).length,
        parent: theme,
        pinned: true,
        x: theme.x + theme.r * 0.97,
        y: theme.y,
        r: theme.r / 30,
      });
      theme.children = (theme.children || []).concat([claim]);
    }
    select(claim, true);
  }

  async function followClaim(id) {
    const key = 'c-' + simple(id);
    try {
      const res = await getJSON(cfg.resolve + encodeURIComponent(key), signalFor('resolve'));
      await goToResolved(res);
    } catch (e) {
      if (isAbort(e)) return;
      setNotice(
        e.status === 404
          ? 'This link points to something you cannot see, or that no longer exists.'
          : e.message,
      );
    }
  }

  async function themeDirectory() {
    if (S.themeDirectory) return S.themeDirectory;
    try {
      const body = await getJSON(cfg.themes);
      S.themeDirectory = (body.themes || []).map((t) => uuid(t.id)).filter(Boolean);
    } catch (e) {
      S.themeDirectory = [];
    }
    return S.themeDirectory;
  }

  /** Prototype #t- links: a theme the viewer's own list holds, via its top claim. */
  async function followThemeKey(prefix) {
    const p = prefix.replace(/-/g, '');
    const match = (ids) => {
      const hits = ids.filter((id) => simple(id).startsWith(p));
      return hits.length === 1 ? hits[0] : null;
    };
    let themeId = match(Array.from(S.themesById.keys()));
    if (!themeId) themeId = match(await themeDirectory());
    const older = 'This theme link is from an older map.';
    if (!themeId) {
      setNotice(older);
      return;
    }
    try {
      const body = await getJSON(withQuery(cfg.themeClaims + encodeURIComponent(themeId) + '/claims', { limit: 1 }));
      const first = (body.claims || [])[0];
      if (!first || !uuid(first.id)) {
        setNotice(older);
        return;
      }
      await followClaim(first.id);
    } catch (e) {
      if (!isAbort(e)) setNotice(older);
    }
  }

  async function followHash() {
    const hash = location.hash;
    if (!HASH_KEY.test(hash)) return;
    const key = hash.slice(1);
    if (key.charAt(0) === 't') {
      await followThemeKey(key.slice(2));
      return;
    }
    if (S.selected && S.selected.key === key) return;
    try {
      const res = await getJSON(cfg.resolve + encodeURIComponent(key), signalFor('resolve'));
      await goToResolved(res);
    } catch (e) {
      if (isAbort(e)) return;
      setNotice(
        e.status === 404
          ? 'This link points to something you cannot see, or that no longer exists.'
          : e.message,
      );
    }
  }

  // ---- search --------------------------------------------------------------

  const search = { timer: null, results: [], active: -1, next: null, q: '' };

  function closeResults() {
    if (!dom.results) return;
    dom.results.hidden = true;
    dom.input.setAttribute('aria-expanded', 'false');
    dom.input.removeAttribute('aria-activedescendant');
    search.active = -1;
  }

  function renderResults(append) {
    if (!append) while (dom.results.firstChild) dom.results.removeChild(dom.results.firstChild);
    search.results.forEach((r, i) => {
      if (append && document.getElementById('atlas-r-' + i)) return;
      const li = el('li', 'atlas__result');
      li.id = 'atlas-r-' + i;
      li.setAttribute('role', 'option');
      li.setAttribute('aria-selected', 'false');
      li.appendChild(el('span', null, r.label));
      const t = num(r.truth_value);
      if (t !== null) li.appendChild(el('span', 'atlas__result-meta', ' · truth ' + t.toFixed(2)));
      li.addEventListener('mousedown', (e) => {
        e.preventDefault();
        pick(i);
      });
      dom.results.appendChild(li);
    });
    const old = dom.results.querySelector('[data-role="more-results"]');
    if (old) old.remove();
    if (search.next) {
      const li = el('li', 'atlas__result small muted', 'More results');
      li.setAttribute('data-role', 'more-results');
      li.setAttribute('role', 'option');
      li.addEventListener('mousedown', (e) => {
        e.preventDefault();
        runSearch(true);
      });
      dom.results.appendChild(li);
    }
    if (!search.results.length) dom.results.appendChild(el('li', 'atlas__result small muted', 'No claims found.'));
    dom.results.hidden = false;
    dom.input.setAttribute('aria-expanded', 'true');
  }

  function setActive(i) {
    const items = dom.results.querySelectorAll('[role="option"]');
    if (!items.length) return;
    search.active = (i + items.length) % items.length;
    items.forEach((li, j) => li.setAttribute('aria-selected', j === search.active ? 'true' : 'false'));
    const cur = items[search.active];
    if (cur.id) dom.input.setAttribute('aria-activedescendant', cur.id);
  }

  async function runSearch(more) {
    const text = dom.input.value.trim();
    if (!text) {
      closeResults();
      return;
    }
    const theme = dom.inTheme && dom.inTheme.checked && S.currentTheme ? S.currentTheme.id : null;
    const url = withQuery(cfg.search, { q: text, theme, after: more ? search.next : null });
    try {
      const body = await getJSON(url, signalFor('search'));
      search.q = text;
      search.results = (more ? search.results : []).concat(body.results || []);
      search.next = body.next || null;
      renderResults(more);
    } catch (e) {
      if (isAbort(e)) return;
      while (dom.results.firstChild) dom.results.removeChild(dom.results.firstChild);
      dom.results.appendChild(el('li', 'atlas__result small muted', e.message));
      dom.results.hidden = false;
    }
  }

  function pick(i) {
    const r = search.results[i];
    if (!r || !uuid(r.claim_id)) return;
    closeResults();
    followClaim(r.claim_id);
  }

  if (dom.input && dom.results) {
    dom.input.addEventListener('input', () => {
      clearTimeout(search.timer);
      search.timer = setTimeout(() => runSearch(false), SEARCH_DEBOUNCE_MS);
    });
    dom.input.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        if (dom.results.hidden) runSearch(false);
        else setActive(search.active + 1);
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        setActive(search.active - 1);
      } else if (e.key === 'Enter') {
        e.preventDefault();
        const items = dom.results.querySelectorAll('[role="option"]');
        const cur = items[search.active];
        if (cur && cur.getAttribute('data-role') === 'more-results') runSearch(true);
        else if (search.active >= 0) pick(search.active);
        else runSearch(false);
      } else if (e.key === 'Escape') {
        if (!dom.results.hidden) {
          e.preventDefault();
          closeResults();
        }
      }
    });
    dom.input.addEventListener('blur', () => setTimeout(closeResults, 150));
  }
  if (dom.searchForm) dom.searchForm.addEventListener('submit', (e) => e.preventDefault());
  if (dom.inTheme) dom.inTheme.addEventListener('change', () => dom.input.value.trim() && runSearch(false));

  document.addEventListener('keydown', (e) => {
    const t = e.target;
    const typing = t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.isContentEditable);
    if (e.key === '/' && !typing && dom.input) {
      e.preventDefault();
      dom.input.focus();
    } else if (e.key === 'Escape' && !typing && S.selected) {
      clearSelection();
    }
  });

  if (dom.structure) {
    dom.structure.addEventListener('change', () => {
      S.structure = dom.structure.checked;
      loadTop(S.run);
    });
  }

  // ---- start ---------------------------------------------------------------

  readColours();
  if (darkScheme) {
    const onScheme = () => {
      readColours();
      redraw();
    };
    if (darkScheme.addEventListener) darkScheme.addEventListener('change', onScheme);
    else if (darkScheme.addListener) darkScheme.addListener(onScheme);
  }
  if (window.ResizeObserver) new ResizeObserver(resize).observe(dom.stage);
  else window.addEventListener('resize', resize);
  window.addEventListener('hashchange', followHash);
  resize();
  loadTop(null);
})();
