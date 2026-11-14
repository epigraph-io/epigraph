// The client half of the Atlas latency gate (backlog W12 824ac5ac, design §6):
// how long the BROWSER takes to put a nested level on screen once it is
// needed, against the Explorer's synthetic preview server.
//
//   node atlas-latency-browser.mjs <preview base URL> [rounds]
//
// Start the preview first (it needs no database and no kernel):
//
//   epigraph-explorer --atlas-fixture-preview 127.0.0.1:8097
//   node atlas-latency-browser.mjs http://127.0.0.1:8097
//
// What it does, in headless Chromium, `rounds` times (default 3; each round
// is a fresh page, so the first round's levels are fetched and later rounds'
// too, the page keeping no cache across loads):
//   1. opens /atlas/preview;
//   2. walks down the panel's first entry (the region, a theme, then its
//      groups) until a leaf is drawn;
//   3. flips the meaning/links switch and back.
//
// What it times: atlas.js marks `atlas:want:<level>` when the viewer needs a
// level (a zoom reaching it, the switch, a link) and
// `atlas:drawn:<kind>:<level>` after the first frame that draws it. Each
// level's sample is drawn minus want: the fetch from the preview server,
// the parse, the layout of its children and the frame. The time a zoom's
// camera flight takes to REACH the level is not in it (the flight is the
// view moving, and children are prefetched during it); for the switch,
// which lands at once, click to drawn is reported too.
//
// The preview answers from memory on loopback, so a sample is the client's
// own cost: the 50 ms CLIENT ALLOWANCE in the budget split
// (docs/superpowers/plans/2026-11-13-atlas-w12-latency-gate-plan.md). It
// exits 1 when any kind's p95 exceeds ATLAS_CLIENT_BUDGET_MS (default 50),
// 2 on a usage or navigation error, and prints one JSON report line (also
// written to ATLAS_LATENCY_BROWSER_REPORT when set).
//
// Needs Node 18+ and `playwright` (or `playwright-core`). With
// ATLAS_BROWSER_EXECUTABLE set (e.g. /usr/bin/google-chrome) it launches that
// browser instead of Playwright's own Chromium. Not part of the per-PR gate:
// CI installs no browser.

let pw;
try {
  pw = await import('playwright');
} catch {
  pw = await import('playwright-core');
}

const [base, roundsArg = '3'] = process.argv.slice(2);
const rounds = Number.parseInt(roundsArg, 10);
if (!base || !/^https?:\/\//.test(base) || !(rounds > 0)) {
  console.error('usage: node atlas-latency-browser.mjs <preview base URL> [rounds]');
  process.exit(2);
}
const budgetMs = Number(process.env.ATLAS_CLIENT_BUDGET_MS || 50);
const STEP_MS = 6000;

const browser = await pw.chromium.launch(
  process.env.ATLAS_BROWSER_EXECUTABLE ? { executablePath: process.env.ATLAS_BROWSER_EXECUTABLE } : {},
);

/** Wait (in the page) until the stage draws a level other than `before`. */
async function nextDrawn(page, before, timeout = STEP_MS) {
  return page.evaluate(
    ([before, timeout]) =>
      new Promise((resolve) => {
        const stage = document.querySelector('[data-role="stage"]') || document.querySelector('.atlas__stage');
        const now = () => stage && stage.getAttribute('data-atlas-drawn-level');
        if (now() && now() !== before) return resolve(now());
        const mo = new MutationObserver(() => {
          if (now() && now() !== before) {
            mo.disconnect();
            resolve(now());
          }
        });
        mo.observe(stage, { attributes: true, attributeFilter: ['data-atlas-drawn-level'] });
        setTimeout(() => {
          mo.disconnect();
          resolve(null);
        }, timeout);
      }),
    [before, timeout],
  );
}

async function drawnNow(page) {
  return page.evaluate(() => {
    const stage = document.querySelector('[data-role="stage"]') || document.querySelector('.atlas__stage');
    return stage ? stage.getAttribute('data-atlas-drawn-level') : null;
  });
}

/** Click the switch button for `h` and time click to drawn, in the page. */
async function flip(page, h) {
  return page.evaluate(
    ([h, timeout]) =>
      new Promise((resolve) => {
        const stage = document.querySelector('[data-role="stage"]') || document.querySelector('.atlas__stage');
        const before = stage.getAttribute('data-atlas-drawn-level');
        const btn = document.querySelector(`[data-role="hierarchy"][data-hierarchy="${h}"]`);
        if (!btn) return resolve({ error: `no ${h} switch` });
        const mo = new MutationObserver(() => {
          const now = stage.getAttribute('data-atlas-drawn-level');
          if (now && now !== before) {
            mo.disconnect();
            resolve({ level: now, t0, click_to_drawn_ms: performance.now() - t0 });
          }
        });
        mo.observe(stage, { attributes: true, attributeFilter: ['data-atlas-drawn-level'] });
        setTimeout(() => {
          mo.disconnect();
          resolve({ error: `the ${h} flip drew nothing` });
        }, timeout);
        const t0 = performance.now();
        btn.click();
      }),
    [h, STEP_MS],
  );
}

/** Every (kind, want -> drawn ms) from the page's marks. */
async function samplesOf(page) {
  return page.evaluate(() => {
    const marks = performance.getEntriesByType('mark');
    const out = [];
    for (const d of marks) {
      const m = /^atlas:drawn:(group|leaf):(.+)$/.exec(d.name);
      if (!m) continue;
      const want = marks.filter((w) => w.name === 'atlas:want:' + m[2] && w.startTime <= d.startTime).pop();
      if (want) out.push({ kind: m[1], level: m[2], at: d.startTime, ms: d.startTime - want.startTime });
    }
    return out;
  });
}

function quantile(xs, q) {
  if (!xs.length) return null;
  const s = xs.slice().sort((a, b) => a - b);
  return s[Math.min(s.length, Math.max(1, Math.ceil(q * s.length))) - 1];
}

const all = [];
const flips = [];
let error = null;
try {
  for (let r = 0; r < rounds && !error; r++) {
    const page = await (await browser.newContext({ viewport: { width: 1280, height: 900 } })).newPage();
    await page.goto(new URL('/atlas/preview', base).href, { waitUntil: 'load' });
    await page.waitForSelector('[data-role="hierarchy"]', { state: 'attached', timeout: STEP_MS });
    // Let the map's own first frames settle before the first want.
    await page.waitForTimeout(800);
    // Down the panel's first entry (the region, then a theme, then its
    // groups) until a leaf is drawn. A region or theme click draws no nested
    // level, so a step that draws nothing is allowed a few times.
    let drawn = await drawnNow(page);
    let misses = 0;
    for (let step = 0; step < 12 && misses < 4; step++) {
      const kinds = (await samplesOf(page)).map((s) => s.kind);
      if (kinds.includes('leaf')) break;
      const item = page.locator('.atlas__item').first();
      if ((await item.count()) === 0) break;
      await item.click();
      const next = await nextDrawn(page, drawn, 3000);
      if (next) {
        drawn = next;
        misses = 0;
        // Let the camera flight end before the next click.
        await page.waitForTimeout(1200);
      } else {
        misses += 1;
      }
    }
    if (!drawn) {
      error = 'walking down the panel drew no nested level';
      break;
    }
    await page.waitForTimeout(1200);
    const flipped = [];
    for (const h of ['links', 'meaning']) {
      const f = await flip(page, h);
      if (f.error) {
        error = f.error;
        break;
      }
      flipped.push(f);
      await page.waitForTimeout(600);
    }
    flips.push(...flipped);
    // A level drawn after the first flip began is a switch sample.
    const flipStart = flipped.length ? flipped[0].t0 : Infinity;
    all.push(
      ...(await samplesOf(page)).map((s) => ({ ...s, kind: s.at >= flipStart ? 'switch' : s.kind, round: r })),
    );
    await page.context().close();
  }
} catch (e) {
  error = String(e && e.message ? e.message : e);
} finally {
  await browser.close();
}

const byKind = {};
for (const s of all) (byKind[s.kind] = byKind[s.kind] || []).push(s.ms);
const kinds = Object.fromEntries(
  Object.entries(byKind).map(([k, xs]) => [
    k,
    {
      n: xs.length,
      p50_ms: Math.round(quantile(xs, 0.5) * 100) / 100,
      p95_ms: Math.round(quantile(xs, 0.95) * 100) / 100,
      max_ms: Math.round(Math.max(...xs) * 100) / 100,
    },
  ]),
);
const clickToDrawn = flips.map((f) => Math.round(f.click_to_drawn_ms * 100) / 100);
const over = Object.entries(kinds)
  .filter(([, v]) => v.p95_ms > budgetMs)
  .map(([k]) => k);
for (const want of ['group', 'leaf', 'switch']) if (!kinds[want] && !error) error = `no ${want} sample`;
const report = {
  harness: 'atlas-latency-browser',
  backlog: '824ac5ac',
  budget_ms: budgetMs,
  rounds,
  kinds,
  switch_click_to_drawn_ms: clickToDrawn,
  over,
  error,
};
const line = JSON.stringify(report);
console.log(line);
if (process.env.ATLAS_LATENCY_BROWSER_REPORT) {
  const { writeFileSync } = await import('node:fs');
  writeFileSync(process.env.ATLAS_LATENCY_BROWSER_REPORT, line + '\n');
}
process.exit(error ? 2 : over.length ? 1 : 0);
