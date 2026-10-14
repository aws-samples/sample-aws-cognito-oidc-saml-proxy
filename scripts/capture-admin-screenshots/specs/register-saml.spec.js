'use strict';

// register-saml.spec.js — SAML register-wizard tour image (admin-register-saml.png).
// SAML 2.0 is the default protocol tile. Step 1 shows Entity ID + ACS URL; advance to step 2
// "Review configuration" which shows NameID format + the SAML Signing toggles.

const { test } = require('@playwright/test');
const { installOfflineGuards, writeOptimizedPng, captureStaticFallback } = require('./_setup');

const OUT = 'admin-register-saml.png';

test('capture SAML register wizard', async ({ page }) => {
  await installOfflineGuards(page);

  let live = true;
  let reason = '';

  // Step 2 "Review configuration" is taller than 900px; use a taller viewport so the SAML Signing
  // toggles are in frame, then trim trailing whitespace.
  await page.setViewportSize({ width: 1440, height: 1500 });

  try {
    await page.goto('http://localhost:3000/applications/new', { waitUntil: 'domcontentloaded' });

    // Step 1: SAML 2.0 is the default; confirm the tile + Entity ID / ACS fields are present.
    await page.getByText('SAML 2.0', { exact: true }).first().waitFor({ state: 'visible', timeout: 20000 });
    await page.getByText('Entity ID', { exact: false }).first().waitFor({ timeout: 10000 });

    // Advance to step 2 "Review configuration" (NameID + SAML Signing toggles).
    await page.getByRole('button', { name: 'Next' }).click();
    await page.getByRole('heading', { name: 'Review configuration' }).waitFor({ timeout: 10000 });
    await page.getByText('SAML Signing', { exact: true }).first().waitFor({ timeout: 10000 });
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
    console.warn(`[register-saml] live path failed, using static fallback: ${reason}`);
  }

  if (!live) {
    await captureStaticFallback(page, { sourcePng: 'admin-app-detail.png', outName: OUT, fractionalCallouts: [] });
  }

  // eslint-disable-next-line no-console
  console.log(`[register-saml] produced ${OUT} via ${live ? 'LIVE server' : 'STATIC fallback'}`);
});
