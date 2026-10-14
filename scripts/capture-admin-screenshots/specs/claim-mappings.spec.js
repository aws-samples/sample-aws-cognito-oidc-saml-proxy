'use strict';

// claim-mappings.spec.js — annotated claim-mapping tour image (admin-claim-mappings-annotated.png).
// README-only filename; the existing plain docs/images/admin-claim-mappings.png is NOT overwritten.
// Drive /applications/new to step 3 "Claim mapping" (click Next twice), then annotate the mapping
// table + the live Preview pane with the ONE consistent callouts.js overlay.

const { test } = require('@playwright/test');
const {
  installOfflineGuards,
  boxOrNull,
  writeOptimizedPng,
  captureStaticFallback,
  injectCalloutsInPage,
} = require('./_setup');

const OUT = 'admin-claim-mappings-annotated.png';

test('capture annotated claim mapping wizard step', async ({ page }) => {
  await installOfflineGuards(page);

  let live = true;
  let reason = '';

  try {
    await page.goto('http://localhost:3000/applications/new', { waitUntil: 'domcontentloaded' });

    // Default protocol (SAML). Advance: step1 -> step2 -> step3 "Claim mapping".
    await page.getByText('SAML 2.0', { exact: true }).first().waitFor({ state: 'visible', timeout: 20000 });
    await page.getByRole('button', { name: 'Next' }).click();
    await page.getByRole('heading', { name: 'Review configuration' }).waitFor({ timeout: 10000 });
    await page.getByRole('button', { name: 'Next' }).click();
    await page.getByRole('heading', { name: 'Claim mapping' }).waitFor({ timeout: 10000 });
    await page.waitForTimeout(400);

    // Annotate the two columns: the Mappings table and the Preview pane.
    // "Mappings" is an h2; "Role Mappings" is an h3 — pin level:2 and exact so the locator
    // resolves to exactly one element (recorded in verification.md).
    const targets = [
      { label: 'Map Cognito attributes to protocol claims', loc: page.getByRole('heading', { level: 2, name: 'Mappings', exact: true }) },
      { label: 'Live assertion / token preview', loc: page.getByRole('heading', { level: 2, name: 'Preview', exact: true }) },
    ];
    const callouts = [];
    for (let i = 0; i < targets.length; i++) {
      const rect = await boxOrNull(targets[i].loc);
      if (!rect) throw new Error(`claim-mapping callout ${i + 1} did not resolve`);
      callouts.push({ n: i + 1, label: targets[i].label, rect });
    }
    await page.evaluate(injectCalloutsInPage, callouts);

    const vp = page.viewportSize();
    const buf = await page.screenshot({ clip: { x: 0, y: 0, width: vp.width, height: vp.height } });
    await writeOptimizedPng(buf, OUT);
  } catch (e) {
    live = false;
    reason = e.message;
    // eslint-disable-next-line no-console
    console.warn(`[claim-mappings] live path failed, using static fallback: ${reason}`);
  }

  if (!live) {
    // Annotate the EXISTING plain admin-claim-mappings.png into the distinct annotated filename.
    await captureStaticFallback(page, {
      sourcePng: 'admin-claim-mappings.png',
      outName: OUT,
      fractionalCallouts: [
        { n: 1, label: 'Map Cognito attributes to protocol claims', fx: 0.1, fy: 0.2 },
        { n: 2, label: 'Live assertion / token preview', fx: 0.6, fy: 0.2 },
      ],
    });
  }

  // eslint-disable-next-line no-console
  console.log(`[claim-mappings] produced ${OUT} via ${live ? 'LIVE server' : 'STATIC fallback'}`);
});
