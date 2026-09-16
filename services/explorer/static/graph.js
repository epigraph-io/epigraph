/* EpiGraph Explorer — graph canvas (plan §3.6).
 *
 * A dependency-free SVG force layout for the claim-graph and neighbourhood
 * views. The markup is templates/graph/_canvas.html; the data comes from the
 * BFF path in `data-graph-source` (CSP is script-src 'self', so nothing is
 * inline). Plain ES2020, no build step.
 *
 * - Layout: velocity Verlet over charge (all pairs), link springs and a weak
 *   centring pull, scaled by a cooling `alpha`; the loop stops once the
 *   layout has settled and restarts on drag or merge.
 * - Interaction: drag the background to pan, wheel to zoom, drag a node to
 *   move it. Click selects a node and fills the side panel; double-click,
 *   the E key or the Expand button fetches that node's ego graph and merges
 *   it (nodes de-duplicated by id, edges by id). Tab moves between nodes,
 *   Enter opens the node's page.
 * - At most `data-node-cap` nodes (150) are drawn; a notice says when more
 *   were left out.
 * - Safety: untrusted strings reach the DOM only through textContent or
 *   setAttribute on non-URL attributes. URLs come from the BFF and must be
 *   same-origin paths (localPath). No string is ever evaluated as code or
 *   parsed as markup (tests/graph.rs pins this).
 */
(function () {
  'use strict';

  const SVG_NS = 'http://www.w3.org/2000/svg';
  const DEFAULT_CAP = 150;
  const FAMILIES = ['support', 'refute', 'structural'];
  const HUES = [212, 152, 272, 28, 334, 96, 190, 248, 4, 56];

  // The belief ramp, as HSL percentages at p = 0 (no belief) and p = 1. Both
  // ends are floored away from the stage the node sits on (--surface: #ffffff
  // light, #1c1f23 dark): a ramp that runs all the way to the stage's own
  // lightness makes low-belief nodes invisible rather than pale. The stroke in
  // graph.css carries the rest of the contrast; tests/graph.rs recomputes the
  // WCAG ratios from these numbers, and .graph__ramp's gradient mirrors them.
  const RAMP_SATURATION = [35, 70];
  const RAMP_LIGHTNESS_LIGHT = [72, 38];
  const RAMP_LIGHTNESS_DARK = [36, 76];
  // Redacted, or no belief at all: a neutral grey, never paler than the ramp.
  const NEUTRAL_LIGHTNESS = [70, 44]; // light theme, dark theme

  // Layout (world units are CSS px at zoom 1).
  const LINK_DISTANCE = 90;
  const LINK_STRENGTH = 0.06;
  const CHARGE = 1400;
  const CHARGE_MIN_D2 = 100; // soften the charge closer than 10 px
  const CENTRE_STRENGTH = 0.002;
  const DAMPING = 0.62; // share of velocity kept per tick
  const MAX_SPEED = 40;
  const ALPHA_DECAY = 0.022;
  const ALPHA_MIN = 0.004;
  const DRAG_ALPHA = 0.25;
  const SETTLED_SPEED = 0.03;
  const SYNC_TICKS = 400;

  // Interaction.
  const DRAG_THRESHOLD = 4;
  const DOUBLE_TAP_MS = 400;
  const ZOOM_MIN = 0.2;
  const ZOOM_MAX = 5;
  const LABEL_ZOOM = 1.6;
  const LABEL_CHARS = 32;
  const PANEL_LABELS = 12;

  const media = (q) => (window.matchMedia ? window.matchMedia(q) : null);
  const reducedMotion = media('(prefers-reduced-motion: reduce)');
  const darkScheme = media('(prefers-color-scheme: dark)');
  const isDark = () => Boolean(darkScheme && darkScheme.matches);
  const motionOK = () => !(reducedMotion && reducedMotion.matches);

  /** A same-origin path from the BFF, or null (never a scheme or //host). */
  function localPath(value) {
    if (typeof value !== 'string' || value.length === 0) return null;
    if (value.charAt(0) !== '/') return null;
    const second = value.charAt(1);
    if (second === '/' || second === '\\') return null;
    return value;
  }

  function svgEl(name, attrs) {
    const el = document.createElementNS(SVG_NS, name);
    if (attrs) {
      for (const key of Object.keys(attrs)) el.setAttribute(key, String(attrs[key]));
    }
    return el;
  }

  function num(v) {
    return typeof v === 'number' && Number.isFinite(v) ? v : null;
  }

  function fmt(v) {
    const n = num(v);
    return n === null ? null : n.toFixed(2);
  }

  /** Cut to `max` characters (code points, not UTF-16 units). */
  function shorten(text, max) {
    const chars = Array.from(text);
    return chars.length > max ? chars.slice(0, max - 1).join('') + '…' : text;
  }

  function nodeLabel(d) {
    if (typeof d.label === 'string' && d.label.length > 0) return d.label;
    return typeof d.entity_type === 'string' && d.entity_type ? d.entity_type : 'node';
  }

  /** FNV-1a over the key, onto a fixed set of hue families. */
  function hueFor(key) {
    let h = 0x811c9dc5;
    for (let i = 0; i < key.length; i++) {
      h ^= key.charCodeAt(i);
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    return HUES[h % HUES.length];
  }

  /** Interpolate one of the ramps above at t in [0, 1]. */
  function rampAt(range, t) {
    return Math.round(range[0] + (range[1] - range[0]) * t);
  }

  /** Sequential ramp on pignistic_prob, else truth_value; neutral grey when
   * the node is redacted or has neither. Hue from frame_id, else type. */
  function nodeFill(d, dark) {
    let p = null;
    if (!d.redacted) {
      p = num(d.pignistic_prob);
      if (p === null) p = num(d.truth_value);
    }
    if (p === null) return 'hsl(210, 6%, ' + NEUTRAL_LIGHTNESS[dark ? 1 : 0] + '%)';
    const t = Math.min(1, Math.max(0, p));
    const hue = hueFor(String(d.frame_id || d.entity_type || 'claim').toLowerCase());
    const sat = rampAt(RAMP_SATURATION, t);
    const light = rampAt(dark ? RAMP_LIGHTNESS_DARK : RAMP_LIGHTNESS_LIGHT, t);
    return 'hsl(' + hue + ', ' + sat + '%, ' + light + '%)';
  }

  function nodeRadius(d, isCentre) {
    const atoms = num(d.atom_count);
    if (atoms !== null && atoms > 0) return 7 + 3 * Math.sqrt(Math.min(atoms, 64));
    return isCentre ? 12 : 8;
  }

  function describe(n) {
    const d = n.d;
    const type = typeof d.entity_type === 'string' && d.entity_type ? d.entity_type : 'node';
    const parts = [type.charAt(0).toUpperCase() + type.slice(1)];
    if (typeof d.kind === 'string' && d.kind) parts.push(d.kind);
    if (n.centre) parts.push('centre of this graph');
    if (d.redacted) parts.push('hidden');
    return parts.join(' · ');
  }

  function setLink(a, href) {
    if (!a) return;
    if (href) {
      a.setAttribute('href', href);
      a.hidden = false;
    } else {
      a.removeAttribute('href');
      a.hidden = true;
    }
  }

  class Graph {
    constructor(root) {
      const q = (role) => root.querySelector('[data-role="' + role + '"]');
      this.root = root;
      this.source = localPath(root.getAttribute('data-graph-source'));
      this.centreId = root.getAttribute('data-graph-center') || '';
      this.cap = parseInt(root.getAttribute('data-node-cap'), 10) || DEFAULT_CAP;
      this.fallback = localPath(root.getAttribute('data-fallback-href'));
      this.svg = q('svg');
      this.statusEl = q('status');
      this.capNotice = q('cap-notice');
      this.fitButton = q('fit');
      this.panel = {
        title: q('p-title'),
        type: q('p-type'),
        content: q('p-content'),
        meta: q('p-meta'),
        labels: q('p-labels'),
        open: q('p-open'),
        expand: q('p-expand'),
        graph: q('p-graph'),
        status: q('p-status'),
      };
      this.nodes = new Map();
      this.edges = new Map();
      this.selected = null;
      this.view = { k: 1, x: 0, y: 0 };
      this.alpha = 0;
      this.running = false;
      this.fitPending = true;
      this.dragging = null;
      this.pan = null;
      this.lastTap = null;
      this.leftOut = 0;
      this.idPrefix = 'graph-' + Math.random().toString(36).slice(2, 8);
      this.frame = this.frame.bind(this);
    }

    start() {
      if (!this.svg || !this.source) return;
      this.root.hidden = false;
      this.measure();
      this.view.x = this.width / 2;
      this.view.y = this.height / 2;
      this.buildSvg();
      this.bindEvents();
      this.applyView();
      this.load(this.source, null).then((ok) => {
        if (!ok) {
          this.addFallbackLink();
          return;
        }
        // Start with the centre's details; a graph without one (a
        // neighbourhood) starts with nothing selected.
        const centre = this.centreId ? this.nodes.get(this.centreId) : null;
        if (centre) this.select(centre);
      });
    }

    measure() {
      const r = this.svg.getBoundingClientRect();
      this.width = r.width > 0 ? r.width : 640;
      this.height = r.height > 0 ? r.height : 420;
    }

    markerId(family) {
      return this.idPrefix + '-arrow-' + family;
    }

    buildSvg() {
      const defs = svgEl('defs');
      for (const family of FAMILIES) {
        const marker = svgEl('marker', {
          id: this.markerId(family),
          viewBox: '0 0 10 10',
          refX: 10,
          refY: 5,
          markerWidth: 8,
          markerHeight: 8,
          markerUnits: 'userSpaceOnUse',
          orient: 'auto',
        });
        marker.appendChild(svgEl('path', { d: 'M0,0 L10,5 L0,10 Z', class: 'garrow garrow--' + family }));
        defs.appendChild(marker);
      }
      this.svg.appendChild(defs);
      this.svg.appendChild(svgEl('rect', { class: 'graph__bg', x: 0, y: 0, width: '100%', height: '100%' }));
      this.viewport = svgEl('g', { class: 'graph__viewport' });
      this.edgeLayer = svgEl('g', { class: 'graph__edges' });
      this.nodeLayer = svgEl('g', { class: 'graph__nodes' });
      this.viewport.appendChild(this.edgeLayer);
      this.viewport.appendChild(this.nodeLayer);
      this.svg.appendChild(this.viewport);
    }

    // ---- view: pan and zoom ------------------------------------------------

    localPoint(ev) {
      const r = this.svg.getBoundingClientRect();
      return { x: ev.clientX - r.left, y: ev.clientY - r.top };
    }

    worldPoint(ev) {
      const p = this.localPoint(ev);
      return { x: (p.x - this.view.x) / this.view.k, y: (p.y - this.view.y) / this.view.k };
    }

    applyView() {
      const v = this.view;
      this.viewport.setAttribute('transform', 'translate(' + v.x.toFixed(1) + ' ' + v.y.toFixed(1) + ') scale(' + v.k.toFixed(3) + ')');
      this.svg.classList.toggle('graph__svg--zoomed', v.k >= LABEL_ZOOM);
    }

    zoomAt(px, py, factor) {
      const v = this.view;
      const k = Math.min(ZOOM_MAX, Math.max(ZOOM_MIN, v.k * factor));
      const wx = (px - v.x) / v.k;
      const wy = (py - v.y) / v.k;
      v.k = k;
      v.x = px - wx * k;
      v.y = py - wy * k;
      this.applyView();
    }

    /** Zoom and pan so every node is visible (never zooming in past 1.5). */
    fit() {
      this.measure();
      if (this.nodes.size === 0) return;
      let minX = Infinity;
      let minY = Infinity;
      let maxX = -Infinity;
      let maxY = -Infinity;
      for (const n of this.nodes.values()) {
        minX = Math.min(minX, n.x - n.r);
        minY = Math.min(minY, n.y - n.r);
        maxX = Math.max(maxX, n.x + n.r);
        maxY = Math.max(maxY, n.y + n.r);
      }
      const pad = 32;
      const w = Math.max(maxX - minX, 1);
      const h = Math.max(maxY - minY, 1);
      const fitK = Math.min((this.width - 2 * pad) / w, (this.height - 2 * pad) / h);
      const k = Math.min(1.5, ZOOM_MAX, Math.max(ZOOM_MIN, fitK));
      this.view.k = k;
      this.view.x = this.width / 2 - (k * (minX + maxX)) / 2;
      this.view.y = this.height / 2 - (k * (minY + maxY)) / 2;
      this.applyView();
    }

    /** Pan a keyboard-focused node into view. */
    ensureVisible(n) {
      const v = this.view;
      const sx = v.x + n.x * v.k;
      const sy = v.y + n.y * v.k;
      const m = 24;
      if (sx < m || sy < m || sx > this.width - m || sy > this.height - m) {
        v.x += this.width / 2 - sx;
        v.y += this.height / 2 - sy;
        this.applyView();
      }
    }

    nodeFromEvent(ev) {
      const el = ev.target && ev.target.closest ? ev.target.closest('.gnode') : null;
      return el ? this.nodes.get(el.getAttribute('data-id')) || null : null;
    }

    bindEvents() {
      const svg = this.svg;

      svg.addEventListener(
        'wheel',
        (ev) => {
          ev.preventDefault();
          const unit = ev.deltaMode === 1 ? 16 : ev.deltaMode === 2 ? this.height : 1;
          const p = this.localPoint(ev);
          this.zoomAt(p.x, p.y, Math.exp(-ev.deltaY * unit * 0.0015));
        },
        { passive: false },
      );

      svg.addEventListener('pointerdown', (ev) => {
        if (ev.button !== 0) return;
        const node = this.nodeFromEvent(ev);
        if (node) {
          this.dragging = { id: ev.pointerId, node: node, x: ev.clientX, y: ev.clientY, moved: false };
        } else {
          this.pan = { id: ev.pointerId, x: ev.clientX, y: ev.clientY, vx: this.view.x, vy: this.view.y, moved: false };
          svg.classList.add('graph__svg--panning');
        }
        svg.setPointerCapture(ev.pointerId);
      });

      svg.addEventListener('pointermove', (ev) => {
        if (this.dragging && this.dragging.id === ev.pointerId) {
          this.dragMove(ev);
          return;
        }
        const pan = this.pan;
        if (!pan || pan.id !== ev.pointerId) return;
        const dx = ev.clientX - pan.x;
        const dy = ev.clientY - pan.y;
        if (!pan.moved && Math.hypot(dx, dy) < DRAG_THRESHOLD) return;
        pan.moved = true;
        this.view.x = pan.vx + dx;
        this.view.y = pan.vy + dy;
        this.applyView();
      });

      const release = (ev) => {
        if (this.dragging && this.dragging.id === ev.pointerId) {
          this.dragEnd(ev);
          return;
        }
        const pan = this.pan;
        if (!pan || pan.id !== ev.pointerId) return;
        this.pan = null;
        svg.classList.remove('graph__svg--panning');
        if (!pan.moved && ev.type === 'pointerup') this.select(null);
      };
      svg.addEventListener('pointerup', release);
      svg.addEventListener('pointercancel', release);

      if (this.fitButton) this.fitButton.addEventListener('click', () => this.fit());
      if (this.panel.expand) this.panel.expand.addEventListener('click', () => this.expand(this.selected));
      window.addEventListener('resize', () => this.measure());
      if (darkScheme && darkScheme.addEventListener) {
        darkScheme.addEventListener('change', () => {
          const dark = isDark();
          for (const n of this.nodes.values()) n.circle.setAttribute('fill', nodeFill(n.d, dark));
        });
      }
    }

    // ---- node drag, click, double-click ------------------------------------
    // The SVG holds pointer capture, so `click`/`dblclick` would not reach the
    // node; a press that does not move is the click, two within
    // DOUBLE_TAP_MS the double-click (this also covers touch).

    dragMove(ev) {
      const d = this.dragging;
      if (!d.moved) {
        if (Math.hypot(ev.clientX - d.x, ev.clientY - d.y) < DRAG_THRESHOLD) return;
        d.moved = true;
        d.node.fixed = true;
      }
      const p = this.worldPoint(ev);
      d.node.x = p.x;
      d.node.y = p.y;
      d.node.vx = 0;
      d.node.vy = 0;
      if (motionOK()) this.reheat(DRAG_ALPHA);
      else this.render();
    }

    dragEnd(ev) {
      const d = this.dragging;
      this.dragging = null;
      d.node.fixed = false;
      if (d.moved) {
        if (motionOK()) this.reheat(DRAG_ALPHA);
        return;
      }
      if (ev.type !== 'pointerup') return;
      const now = performance.now();
      const last = this.lastTap;
      this.lastTap = { node: d.node, t: now };
      this.select(d.node);
      if (last && last.node === d.node && now - last.t < DOUBLE_TAP_MS) {
        this.lastTap = null;
        this.expand(d.node);
      }
    }

    // ---- data ----------------------------------------------------------------

    /** The canvas-wide status under the toolbar. */
    setStatus(text, isError) {
      const el = this.statusEl;
      if (!el) return;
      el.textContent = text;
      el.classList.toggle('graph__status--error', Boolean(isError));
    }

    /** A status about one node, which the panel only shows while that node is
     * the selected one: an expansion's fetch outlives the click that started
     * it, so a message that lands after the user picked another node would
     * describe a node the panel is no longer showing. */
    setPanelStatus(anchor, text) {
      if (!this.panel.status || this.selected !== anchor) return;
      this.panel.status.textContent = text;
    }

    /** A load failure: the panel for an expansion, the toolbar otherwise. */
    reportLoadError(anchor, message) {
      if (anchor) this.setPanelStatus(anchor, message);
      else this.setStatus(message, true);
    }

    addFallbackLink() {
      if (!this.fallback || !this.statusEl) return;
      const a = document.createElement('a');
      a.setAttribute('href', this.fallback);
      a.textContent = 'Go back';
      this.statusEl.appendChild(document.createTextNode(' '));
      this.statusEl.appendChild(a);
    }

    /** Fetch a canvas payload and merge it. Resolves true on success. */
    async load(url, anchor) {
      if (anchor) this.setPanelStatus(anchor, 'Loading neighbours…');
      else this.setStatus('Loading the graph…', false);
      let res;
      try {
        res = await fetch(url, { credentials: 'same-origin', headers: { Accept: 'application/json' } });
      } catch (err) {
        this.reportLoadError(anchor, 'Could not reach the Explorer. Check your connection and try again.');
        return false;
      }
      let body = null;
      try {
        body = await res.json();
      } catch (err) {
        body = null;
      }
      if (!res.ok || !body || typeof body !== 'object') {
        let message = 'The graph could not be loaded.';
        if (res.status === 401) message = 'Your session has ended. Reload the page to sign in again.';
        else if (body && typeof body.message === 'string' && body.message) message = body.message;
        this.reportLoadError(anchor, message);
        return false;
      }
      const added = this.merge(body, anchor);
      if (anchor) {
        this.setPanelStatus(anchor, added === 0 ? 'No new neighbours to add.' : 'Added ' + added + (added === 1 ? ' node.' : ' nodes.'));
      }
      const e = this.edges.size;
      this.setStatus(this.nodes.size + (this.nodes.size === 1 ? ' node, ' : ' nodes, ') + e + (e === 1 ? ' connection.' : ' connections.'), false);
      return true;
    }

    /** Add unseen nodes (up to the cap) around `anchor`, then unseen edges
     * whose endpoints are both drawn. Returns how many nodes were added. */
    merge(data, anchor) {
      const nodes = Array.isArray(data.nodes) ? data.nodes : [];
      const edges = Array.isArray(data.edges) ? data.edges : [];
      const ox = anchor ? anchor.x : 0;
      const oy = anchor ? anchor.y : 0;
      let added = 0;
      let leftOut = 0;
      for (const d of nodes) {
        if (!d || typeof d.id !== 'string' || this.nodes.has(d.id)) continue;
        if (this.nodes.size >= this.cap) {
          leftOut += 1;
          continue;
        }
        const centre = !anchor && (d.id === this.centreId || d.is_center === true);
        const i = added + 1;
        const angle = i * 2.39996323; // golden angle: an even spiral, no overlaps
        const radius = (anchor ? 24 : 18) * Math.sqrt(i);
        const n = {
          id: d.id,
          d: d,
          centre: centre,
          x: centre ? 0 : ox + radius * Math.cos(angle),
          y: centre ? 0 : oy + radius * Math.sin(angle),
          vx: 0,
          vy: 0,
          ax: 0,
          ay: 0,
          fx: 0,
          fy: 0,
          r: nodeRadius(d, centre),
          degree: 0,
          fixed: false,
          expanded: false,
          expanding: false,
          el: null,
          circle: null,
        };
        this.nodes.set(n.id, n);
        this.drawNode(n);
        added += 1;
      }
      for (const e of edges) {
        if (!e || typeof e.source !== 'string' || typeof e.target !== 'string') continue;
        if (e.source === e.target) continue;
        const relationship = typeof e.relationship === 'string' ? e.relationship : '';
        const key = typeof e.id === 'string' && e.id ? e.id : e.source + '|' + e.target + '|' + relationship;
        if (this.edges.has(key)) continue;
        const s = this.nodes.get(e.source);
        const t = this.nodes.get(e.target);
        if (!s || !t) continue;
        const edge = {
          key: key,
          s: s,
          t: t,
          family: FAMILIES.indexOf(e.family) >= 0 ? e.family : 'structural',
          directed: e.directed !== false,
          relationship: relationship,
          el: null,
        };
        this.edges.set(key, edge);
        s.degree += 1;
        t.degree += 1;
        this.drawEdge(edge);
      }
      this.leftOut += leftOut;
      this.updateCapNotice();
      if (added > 0) this.reheat(anchor ? 0.5 : 1);
      else this.render();
      return added;
    }

    updateCapNotice() {
      if (!this.capNotice) return;
      if (this.leftOut > 0) {
        this.capNotice.textContent = 'The graph shows at most ' + this.cap + ' nodes; ' + this.leftOut + (this.leftOut === 1 ? ' more was' : ' more were') + ' left out.';
        this.capNotice.hidden = false;
      } else {
        this.capNotice.hidden = true;
      }
    }

    drawNode(n) {
      const d = n.d;
      const label = nodeLabel(d);
      const type = typeof d.entity_type === 'string' && d.entity_type ? d.entity_type : 'node';
      const classes = ['gnode'];
      if (n.centre) classes.push('gnode--center');
      if (type.toLowerCase() !== 'claim') classes.push('gnode--entity');
      if (d.redacted) classes.push('gnode--redacted');
      const g = svgEl('g', {
        class: classes.join(' '),
        tabindex: 0,
        role: localPath(d.href) ? 'link' : 'button',
        'aria-label': label + ' (' + type + ')',
        'data-id': n.id,
      });
      const title = svgEl('title');
      title.textContent = label;
      const circle = svgEl('circle', { r: n.r.toFixed(1), fill: nodeFill(d, isDark()) });
      const text = svgEl('text', { class: 'glabel', x: (n.r + 4).toFixed(1), y: 4 });
      text.textContent = shorten(label, LABEL_CHARS);
      g.appendChild(title);
      g.appendChild(circle);
      g.appendChild(text);
      n.el = g;
      n.circle = circle;

      g.addEventListener('focus', () => {
        this.select(n);
        let keyboard = true;
        try {
          keyboard = g.matches(':focus-visible');
        } catch (err) {
          keyboard = true;
        }
        if (keyboard) this.ensureVisible(n);
      });
      g.addEventListener('keydown', (ev) => {
        if (ev.key === 'Enter') {
          ev.preventDefault();
          const href = localPath(d.href);
          if (href) window.location.assign(href);
          else this.select(n);
        } else if (ev.key === ' ' || ev.key === 'Spacebar') {
          ev.preventDefault();
          this.select(n);
        } else if (ev.key === 'e' || ev.key === 'E' || ev.key === '+') {
          ev.preventDefault();
          this.expand(n);
        }
      });
      this.nodeLayer.appendChild(g);
    }

    drawEdge(edge) {
      const line = svgEl('line', { class: 'gedge gedge--' + edge.family });
      if (edge.directed) line.setAttribute('marker-end', 'url(#' + this.markerId(edge.family) + ')');
      const title = svgEl('title');
      title.textContent = edge.relationship;
      line.appendChild(title);
      edge.el = line;
      this.edgeLayer.appendChild(line);
    }

    // ---- layout ----------------------------------------------------------------

    /** One velocity-Verlet step. Returns the fastest node's speed. */
    tick() {
      const nodes = Array.from(this.nodes.values());
      const alpha = this.alpha;

      for (const n of nodes) {
        if (n.fixed) continue;
        n.x += n.vx + 0.5 * n.ax;
        n.y += n.vy + 0.5 * n.ay;
      }

      for (const n of nodes) {
        n.fx = -CENTRE_STRENGTH * n.x;
        n.fy = -CENTRE_STRENGTH * n.y;
      }
      for (let i = 0; i < nodes.length; i++) {
        const a = nodes[i];
        for (let j = i + 1; j < nodes.length; j++) {
          const b = nodes[j];
          let dx = b.x - a.x;
          let dy = b.y - a.y;
          let d2 = dx * dx + dy * dy;
          if (d2 === 0) {
            dx = (Math.random() - 0.5) * 0.01;
            dy = (Math.random() - 0.5) * 0.01;
            d2 = dx * dx + dy * dy;
          }
          const d = Math.sqrt(d2);
          const f = CHARGE / Math.max(d2, CHARGE_MIN_D2);
          const fx = (f * dx) / d;
          const fy = (f * dy) / d;
          a.fx -= fx;
          a.fy -= fy;
          b.fx += fx;
          b.fy += fy;
        }
      }
      for (const e of this.edges.values()) {
        const dx = e.t.x - e.s.x;
        const dy = e.t.y - e.s.y;
        const d = Math.hypot(dx, dy) || 0.001;
        // Hubs get softer springs, so a star does not collapse inward.
        const k = LINK_STRENGTH / Math.max(1, Math.min(e.s.degree, e.t.degree));
        const f = k * (d - LINK_DISTANCE);
        const fx = (f * dx) / d;
        const fy = (f * dy) / d;
        e.s.fx += fx;
        e.s.fy += fy;
        e.t.fx -= fx;
        e.t.fy -= fy;
      }

      let fastest = 0;
      for (const n of nodes) {
        const ax = n.fx * alpha;
        const ay = n.fy * alpha;
        if (n.fixed) {
          n.vx = 0;
          n.vy = 0;
          n.ax = 0;
          n.ay = 0;
          continue;
        }
        n.vx = (n.vx + 0.5 * (n.ax + ax)) * DAMPING;
        n.vy = (n.vy + 0.5 * (n.ay + ay)) * DAMPING;
        const speed = Math.hypot(n.vx, n.vy);
        if (speed > MAX_SPEED) {
          n.vx *= MAX_SPEED / speed;
          n.vy *= MAX_SPEED / speed;
        }
        fastest = Math.max(fastest, Math.min(speed, MAX_SPEED));
        n.ax = ax;
        n.ay = ay;
      }

      const floor = this.dragging && this.dragging.moved ? DRAG_ALPHA : 0;
      this.alpha = Math.max(floor, this.alpha * (1 - ALPHA_DECAY));
      return fastest;
    }

    settled(speed) {
      if (this.dragging && this.dragging.moved) return false;
      return this.alpha < ALPHA_MIN || (speed < SETTLED_SPEED && this.alpha < 0.3);
    }

    frame() {
      const speed = this.tick();
      this.render();
      if (this.settled(speed)) {
        this.running = false;
        this.alpha = 0;
        this.afterSettle();
        return;
      }
      window.requestAnimationFrame(this.frame);
    }

    afterSettle() {
      if (this.fitPending) {
        this.fitPending = false;
        this.fit();
      }
    }

    reheat(alpha) {
      this.alpha = Math.max(this.alpha, alpha);
      if (!motionOK()) {
        // Reduced motion: settle off-screen and draw once.
        for (let i = 0; i < SYNC_TICKS; i++) {
          if (this.settled(this.tick())) break;
        }
        this.alpha = 0;
        this.render();
        this.afterSettle();
        return;
      }
      if (!this.running) {
        this.running = true;
        window.requestAnimationFrame(this.frame);
      }
    }

    render() {
      for (const n of this.nodes.values()) {
        n.el.setAttribute('transform', 'translate(' + n.x.toFixed(1) + ' ' + n.y.toFixed(1) + ')');
      }
      for (const e of this.edges.values()) {
        const dx = e.t.x - e.s.x;
        const dy = e.t.y - e.s.y;
        const len = Math.hypot(dx, dy);
        const startGap = e.s.r;
        const endGap = e.t.r + (e.directed ? 1.5 : 0);
        if (len <= startGap + endGap) {
          e.el.setAttribute('visibility', 'hidden');
          continue;
        }
        const ux = dx / len;
        const uy = dy / len;
        e.el.setAttribute('visibility', 'visible');
        e.el.setAttribute('x1', (e.s.x + ux * startGap).toFixed(1));
        e.el.setAttribute('y1', (e.s.y + uy * startGap).toFixed(1));
        e.el.setAttribute('x2', (e.t.x - ux * endGap).toFixed(1));
        e.el.setAttribute('y2', (e.t.y - uy * endGap).toFixed(1));
      }
    }

    // ---- selection, side panel, expansion -----------------------------------

    highlightEdges(n, on) {
      for (const e of this.edges.values()) {
        if (e.s === n || e.t === n) e.el.classList.toggle('gedge--active', on);
      }
    }

    select(n) {
      const previous = this.selected;
      if (previous && previous.el) {
        previous.el.classList.remove('gnode--selected');
        this.highlightEdges(previous, false);
      }
      this.selected = n || null;
      const p = this.panel;
      if (previous !== this.selected && p.status) p.status.textContent = '';
      if (!n) {
        p.title.textContent = 'Select a node';
        p.type.textContent = 'Click a node, or Tab to one, to see its details here.';
        p.content.hidden = true;
        p.meta.hidden = true;
        p.labels.hidden = true;
        setLink(p.open, null);
        setLink(p.graph, null);
        p.expand.hidden = true;
        return;
      }
      n.el.classList.add('gnode--selected');
      this.highlightEdges(n, true);

      const d = n.d;
      p.title.textContent = nodeLabel(d);
      p.type.textContent = describe(n);

      if (d.redacted) {
        p.content.textContent = 'You do not have access to this claim’s text.';
        p.content.hidden = false;
      } else if (typeof d.content === 'string' && d.content && d.content !== d.label) {
        p.content.textContent = d.content;
        p.content.hidden = false;
      } else {
        p.content.textContent = '';
        p.content.hidden = true;
      }

      const rows = [];
      const belief = fmt(d.pignistic_prob);
      if (belief) rows.push(['Belief', belief]);
      const truth = fmt(d.truth_value);
      if (truth) rows.push(['Truth value', truth]);
      if (typeof d.is_current === 'boolean') rows.push(['Current', d.is_current ? 'yes' : 'no, superseded']);
      if (num(d.atom_count) !== null) rows.push(['Atoms', String(d.atom_count)]);
      rows.push(['Connections shown', String(n.degree)]);
      p.meta.replaceChildren();
      for (const [key, value] of rows) {
        const dt = document.createElement('dt');
        dt.textContent = key;
        const dd = document.createElement('dd');
        dd.textContent = value;
        p.meta.appendChild(dt);
        p.meta.appendChild(dd);
      }
      p.meta.hidden = false;

      p.labels.replaceChildren();
      const labels = Array.isArray(d.labels) ? d.labels.filter((l) => typeof l === 'string').slice(0, PANEL_LABELS) : [];
      for (const l of labels) {
        const li = document.createElement('li');
        li.className = 'label';
        li.textContent = l;
        p.labels.appendChild(li);
      }
      p.labels.hidden = labels.length === 0;

      setLink(p.open, localPath(d.href));
      setLink(p.graph, n.centre ? null : localPath(d.graph_href));
      const canExpand = Boolean(localPath(d.expand_href));
      p.expand.hidden = !canExpand;
      p.expand.disabled = n.expanded || n.expanding;
      p.expand.textContent = n.expanded ? 'Expanded' : n.expanding ? 'Expanding…' : 'Expand';
    }

    async expand(n) {
      if (!n || n.expanded || n.expanding) return;
      const url = localPath(n.d.expand_href);
      if (!url) {
        this.setPanelStatus(n, 'This node cannot be expanded.');
        return;
      }
      if (this.nodes.size >= this.cap) {
        // No fetch happens here, so no neighbour was dropped: the cap notice
        // only ever counts nodes a payload really carried past the cap (see
        // merge). The status below is the whole story.
        this.setPanelStatus(n, 'The graph already shows its maximum of ' + this.cap + ' nodes.');
        return;
      }
      n.expanding = true;
      if (this.selected === n) this.select(n);
      const ok = await this.load(url, n);
      n.expanding = false;
      n.expanded = ok;
      if (this.selected === n) this.select(n);
    }
  }

  // ---- "copy claim link" on non-permalink views ------------------------------

  function wireShare(button) {
    const url = button.getAttribute('data-share-url');
    if (!url || !navigator.clipboard || !window.isSecureContext) return; // the link stays
    const label = button.textContent;
    let timer = 0;
    const flash = (text) => {
      button.textContent = text;
      window.clearTimeout(timer);
      timer = window.setTimeout(() => {
        button.textContent = label;
      }, 2000);
    };
    button.hidden = false;
    button.addEventListener('click', () => {
      navigator.clipboard.writeText(url).then(
        () => flash('Copied'),
        () => flash('Copy failed; use the link'),
      );
    });
  }

  function init() {
    for (const root of document.querySelectorAll('.graph[data-graph-source]')) {
      try {
        new Graph(root).start();
      } catch (err) {
        const status = root.querySelector('[data-role="status"]');
        root.hidden = false;
        if (status) status.textContent = 'The graph could not be drawn in this browser.';
        if (window.console) window.console.error(err);
      }
    }
    for (const button of document.querySelectorAll('[data-share-url]')) wireShare(button);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
