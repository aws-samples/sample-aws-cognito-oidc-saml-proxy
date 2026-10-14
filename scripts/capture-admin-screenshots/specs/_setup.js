'use strict';

// _setup.js — shared capture plumbing for every spec:
//   installOfflineGuards(page)  seed + /api/v1 route mocks + canned Cognito reply + abort-everything-else
//   boxOrNull(locator)          resolve a locator to a rect, treating zero-match (null) OR a
//                               strict-mode multi-match throw as a hard live-path failure
//   writeOptimizedPng(buf,out)  sharp-optimize to PNG and assert <= 410000 bytes
//   captureStaticFallback(...)  co-equal static-image path: same callouts over an existing docs PNG
//
// HARD CONSTRAINT: the abort guard ensures no request can reach live AWS. Only localhost:3000
// (same-origin, incl. Vite module requests), /api/v1/** (served from fixtures), and the ONE
// intercepted-and-answered Cognito host are allowed; everything else is aborted.

const fs = require('fs');
const path = require('path');
const { buildFakeSession } = require('../seed');
const { injectCalloutsInPage } = require('../callouts');

const CLIENT_ID = 'exampleclientid0000000000';
const FIXTURES = path.resolve(__dirname, '../fixtures');
const OUT_DIR = path.resolve(__dirname, '../../../docs/images');
const MAX_BYTES = 410000;

// Map an /api/v1 path (the part after /api/v1/) to a fixture file. Returns parsed JSON or null.
function fixtureFor(apiPath) {
  const map = {
    'identity-sources': 'identity-sources.json',
    'applications': 'applications.json',
    'health/certificates': 'certificates.json',
    'analytics/overview': 'analytics-overview.json',
    'debug/audit-log': 'audit-log.json',
    'settings': 'settings.json',
    'tenants': 'tenants.json',
  };
  const file = map[apiPath];
  if (!file) return null;
  return JSON.parse(fs.readFileSync(path.join(FIXTURES, file), 'utf8'));
}

async function installOfflineGuards(page) {
  // 1) Seed the fake Amplify session BEFORE any app code runs.
  const session = buildFakeSession(CLIENT_ID);
  await page.addInitScript((entries) => {
    try {
      for (const k of Object.keys(entries)) {
        window.localStorage.setItem(k, entries[k]);
      }
    } catch (e) {
      /* localStorage always available on http origin */
    }
  }, session);

  // 2) Mock the management API from fixtures (specific endpoints + {}-200 catch-all).
  await page.route('**/api/v1/**', async (route) => {
    const url = new URL(route.request().url());
    // Everything after /api/v1/ , query stripped.
    const apiPath = url.pathname.replace(/^.*\/api\/v1\//, '').replace(/\/$/, '');
    const body = fixtureFor(apiPath);
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(body === null ? {} : body),
    });
  });

  // 3) Canned OFFLINE reply for any Cognito host call (belt-and-suspenders; the far-future exp
  //    should mean Amplify never refreshes). Never reaches AWS.
  await page.route('**cognito-idp.*.amazonaws.com**', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/x-amz-json-1.1',
      body: JSON.stringify({}),
    });
  });

  // 4) Abort anything that is not localhost:3000, /api/v1/**, or the intercepted Cognito host.
  //    Proves no live AWS is reachable.
  await page.route('**', async (route) => {
    const u = route.request().url();
    const allowed =
      u.startsWith('http://localhost:3000') ||
      u.startsWith('ws://localhost:3000') ||
      u.includes('/api/v1/') ||
      /cognito-idp\.[^.]+\.amazonaws\.com/.test(u) ||
      u.startsWith('data:') ||
      u.startsWith('blob:');
    if (allowed) {
      await route.fallback();
    } else {
      // eslint-disable-next-line no-console
      console.warn('[abort-guard] blocked request to', u);
      await route.abort();
    }
  });
}

// Resolve a locator to a viewport-coordinate rect. Returns null on zero-match OR on a strict-mode
// multi-match throw, so the caller can fall through to the static-image path (A.4 fail-loud rule).
async function boxOrNull(locator) {
  try {
    const box = await locator.boundingBox();
    return box; // null if not visible / not found
  } catch (e) {
    // Strict-mode violation (multiple matches) or detached node — treat as a hard failure.
    // eslint-disable-next-line no-console
    console.warn('[callout] locator failed to resolve to exactly one element:', e.message);
    return null;
  }
}

// Expand a heading rect downward to cover the card/panel body it heads.
async function panelRectFromHeading(headingLocator) {
  const head = await boxOrNull(headingLocator);
  if (!head) return null;
  const container = await boxOrNull(headingLocator.locator('xpath=ancestor::*[self::div][1]'));
  if (container && container.height > head.height) {
    return container;
  }
  return head;
}

function ensureOutDir() {
  if (!fs.existsSync(OUT_DIR)) fs.mkdirSync(OUT_DIR, { recursive: true });
}

async function writeOptimizedPng(buf, outName) {
  ensureOutDir();
  const out = path.join(OUT_DIR, outName);
  let optimized = buf;
  try {
    const sharp = require('sharp');
    optimized = await sharp(buf).png({ compressionLevel: 9, palette: true }).toBuffer();
    if (optimized.length > MAX_BYTES) {
      // Fall back to a quantized palette with fewer colors for flat Cloudscape UI.
      optimized = await sharp(buf)
        .png({ compressionLevel: 9, palette: true, colors: 128, quality: 90 })
        .toBuffer();
    }
  } catch (e) {
    // eslint-disable-next-line no-console
    console.warn('[sharp] optimization unavailable, writing raw PNG:', e.message);
  }
  fs.writeFileSync(out, optimized);
  const size = fs.statSync(out).size;
  if (size > MAX_BYTES) {
    throw new Error(`${outName} is ${size} bytes (> ${MAX_BYTES}); optimize further`);
  }
  // eslint-disable-next-line no-console
  console.log(`[image] wrote ${outName} (${size} bytes)`);
  return out;
}

// Static-image fallback: annotate an existing docs/images/*.png with the SAME callouts.js overlay,
// loaded into a blank page as a data-URI. callouts here are { n, label, rect } relative to the
// image's intrinsic pixels (the caller supplies rects as fractions of width/height).
async function captureStaticFallback(page, { sourcePng, outName, fractionalCallouts }) {
  const srcPath = path.resolve(OUT_DIR, sourcePng);
  if (!fs.existsSync(srcPath)) {
    throw new Error(`static fallback source not found: ${srcPath}`);
  }
  const b64 = fs.readFileSync(srcPath).toString('base64');
  await page.setContent(
    `<!doctype html><html><head><style>html,body{margin:0;padding:0}</style></head>` +
      `<body><img id="src" src="data:image/png;base64,${b64}" style="display:block"></body></html>`,
  );
  const dims = await page.evaluate(() => {
    const img = document.getElementById('src');
    return { w: img.naturalWidth, h: img.naturalHeight };
  });
  await page.setViewportSize({ width: dims.w, height: dims.h });
  const callouts = (fractionalCallouts || []).map((c) => ({
    n: c.n,
    label: c.label,
    rect: {
      x: c.fx * dims.w,
      y: c.fy * dims.h,
      width: (c.fw || 0.05) * dims.w,
      height: (c.fh || 0.03) * dims.h,
    },
  }));
  await page.evaluate(injectCalloutsInPage, callouts);
  const buf = await page.screenshot({ clip: { x: 0, y: 0, width: dims.w, height: dims.h } });
  return writeOptimizedPng(buf, outName);
}

module.exports = {
  CLIENT_ID,
  OUT_DIR,
  MAX_BYTES,
  installOfflineGuards,
  boxOrNull,
  panelRectFromHeading,
  writeOptimizedPng,
  captureStaticFallback,
  injectCalloutsInPage,
};
