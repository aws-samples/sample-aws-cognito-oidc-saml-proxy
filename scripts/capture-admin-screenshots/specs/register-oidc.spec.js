'use strict';

// register-oidc.spec.js — OIDC register-wizard tour image (admin-register-oidc.png).
// Drive /applications/new by clicking Next (never mutate React state): select the OpenID Connect
// tile on step 1, advance to step 2 "Review configuration" which shows the OIDC summary (redirect
// URIs, scopes) + OIDC Settings (grant types, token endpoint auth method, token lifetimes).

const { test } = require('@playwright/test');
const { installOfflineGuards, writeOptimizedPng, captureStaticFallback } = require('./_setup');

const OUT = 'admin-register-oidc.png';

test('capture OIDC register wizard', async ({ page }) => {
  await installOfflineGuards(page);

  let live = true;
  let reason = '';

  // Step 2 "Review configuration" is taller than 900px (summary + settings + custom-login +
  // OIDC Settings). Use a taller viewport so OIDC Settings (grant types / token auth / token
  // lifetimes) is in frame, then trim trailing whitespace.
  await page.setViewportSize({ width: 1440, height: 1500 });

  try {
    await page.goto('http://localhost:3000/applications/new', { waitUntil: 'domcontentloaded' });

    // Step 1: select the OpenID Connect protocol tile.
    const oidcTile = page.getByText('OpenID Connect', { exact: true }).first();
    await oidcTile.waitFor({ state: 'visible', timeout: 20000 });
    await oidcTile.click();

    // Advance to step 2 "Review configuration".
    await page.getByRole('button', { name: 'Next' }).click();
    await page.getByRole('heading', { name: 'Review configuration' }).waitFor({ timeout: 10000 });

    // Confirm the OIDC-specific controls render (redirect URIs/scopes summary + OIDC Settings).
    await page.getByText('OIDC Settings', { exact: true }).first().waitFor({ timeout: 10000 });
    await page.waitForTimeout(400);

    const vp = page.viewportSize();
    const contentH = await page.evaluate(() => {
      const main = document.querySelector('main') || document.body;
      return Math.ceil(main.getBoundingClientRect().bottom + 24);
    });
    const clipH = Math.min(vp.height, Math.max(900, contentH));
    const buf = await page.screenshot({ clip: { x: 0, y: 0, width: vp.width, height: clipH } });
    await writeOptimizedPng(buf, OUT);
  } catch (e) {
    live = false;
    reason = e.message;
    // eslint-disable-next-line no-console
    console.warn(`[register-oidc] live path failed, using static fallback: ${reason}`);
  }

  if (!live) {
    await captureStaticFallback(page, { sourcePng: 'admin-app-detail.png', outName: OUT, fractionalCallouts: [] });
  }

  // eslint-disable-next-line no-console
  console.log(`[register-oidc] produced ${OUT} via ${live ? 'LIVE server' : 'STATIC fallback'}`);
});
