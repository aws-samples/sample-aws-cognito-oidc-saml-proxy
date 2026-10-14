'use strict';

// overview.spec.js — annotated admin Overview tour image (admin-overview-annotated.png).
// Live-first: seed a fake session, mock /api/v1 from fixtures, abort any other request (no live
// AWS), assert the authenticated-shell gate, expand Gateway Information, resolve the 8 FR-A2
// callout targets to rects and inject the ONE consistent SVG overlay. If the gate OR any locator
// fails, fall through to the committed static-image path over the best existing docs PNG.

const { test, expect } = require('@playwright/test');
const {
  installOfflineGuards,
  boxOrNull,
  panelRectFromHeading,
  writeOptimizedPng,
  captureStaticFallback,
  injectCalloutsInPage,
} = require('./_setup');

const OUT = 'admin-overview-annotated.png';

test('capture annotated admin Overview', async ({ page }) => {
  await installOfflineGuards(page);

  let live = true;
  let reason = '';

  // The Dashboard is taller than 900px once Gateway Information is expanded. Use a taller viewport
  // so the whole page (incl. the expanded panel) is in frame; the fixed-overlay/viewport-clip
  // approach then aligns exactly with the capture (no fullPage/overlay-coordinate mismatch).
  await page.setViewportSize({ width: 1440, height: 1600 });

  try {
    await page.goto('http://localhost:3000/', { waitUntil: 'domcontentloaded' });

    // --- A-ASSUMPTION-2 hard acceptance gate: authenticated shell rendered, no login form. ---
    await expect(page.getByText('Overview', { exact: false }).first()).toBeVisible({ timeout: 20000 });
    await expect(page.getByLabel(/password/i)).toHaveCount(0);

    // Expand Gateway Information (ExpandableSection defaultExpanded={false}).
    const gwHeader = page.getByText('Gateway Information', { exact: true });
    await gwHeader.click();
    // Let the KeyValuePairs render.
    await page.waitForTimeout(400);

    // --- Resolve the 8 callout targets (design A.4). Order top-to-bottom for numbering. ---
    const topNav = page.locator('#top-nav');
    const nav = page.getByRole('navigation');

    // NOTE (locator corrections recorded in verification.md):
    //  - Cloudscape TopNavigation renders TWO copies of each utility dropdown (a visible one and an
    //    off-screen responsive-overflow clone), and exposes them with the ariaLabel as the
    //    accessible name — so `getByRole('button',{name:/Tenant:/})` does not match. Use a
    //    `button:visible` locator filtered by the visible TEXT content instead (resolves to 1).
    //  - The "Identity Sources" and "Monitoring" left-nav SECTION headers are rendered by
    //    Cloudscape as non-interactive text whose boundingBox() is null. Per plan.md's binding
    //    decision, anchor rows 3/4 on the adjacent child LINK inside the nav landmark
    //    ("All sources" under Identity Sources; "Analytics" under Monitoring).
    const targets = [
      { label: 'Support for multi-tenant infrastructure', loc: topNav.locator('button:visible', { hasText: 'Tenant:' }) },
      { label: 'Login with a separate Cognito user pool', loc: topNav.locator('button:visible', { hasText: 'alex@example.com' }) },
      { label: 'Configure Cognito user pools as identity sources', loc: nav.getByRole('link', { name: 'All sources' }) },
      { label: 'Integrated logging and analytics', loc: nav.getByRole('link', { name: 'Analytics' }) },
      { label: 'Key management in KMS with backup key support for smooth rollover', loc: nav.getByRole('link', { name: 'Certificates' }) },
      { label: 'Overview stats', panel: page.getByRole('heading', { level: 2, name: 'Overview' }) },
      { label: 'Last events', panel: page.getByRole('heading', { name: 'Recent Events' }) },
      { label: 'Overview of Gateway and tenant-based URLs', panel: page.getByText('Gateway Information', { exact: true }) },
    ];

    const callouts = [];
    for (let i = 0; i < targets.length; i++) {
      const t = targets[i];
      const rect = t.panel ? await panelRectFromHeading(t.panel) : await boxOrNull(t.loc);
      if (!rect) {
        throw new Error(`callout ${i + 1} ("${t.label}") did not resolve to exactly one visible element`);
      }
      callouts.push({ n: i + 1, label: t.label, rect });
    }

    await page.evaluate(injectCalloutsInPage, callouts);

    const vp = page.viewportSize();
    // Trim the trailing whitespace: clip to the content height (plus a small margin), capped to
    // the viewport so the fixed overlay stays aligned.
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
    console.warn(`[overview] live path failed, using static fallback: ${reason}`);
  }

  if (!live) {
    // Static co-equal fallback over the best existing admin screenshot.
    await captureStaticFallback(page, {
      sourcePng: 'admin-integration.png',
      outName: OUT,
      fractionalCallouts: [
        { n: 1, label: 'Support for multi-tenant infrastructure', fx: 0.78, fy: 0.03 },
        { n: 2, label: 'Login with a separate Cognito user pool', fx: 0.92, fy: 0.03 },
        { n: 3, label: 'Configure Cognito user pools as identity sources', fx: 0.08, fy: 0.28 },
        { n: 4, label: 'Integrated logging and analytics', fx: 0.08, fy: 0.55 },
        { n: 5, label: 'Key management in KMS with backup key support for smooth rollover', fx: 0.08, fy: 0.7 },
        { n: 6, label: 'Overview stats', fx: 0.4, fy: 0.25 },
        { n: 7, label: 'Last events', fx: 0.4, fy: 0.55 },
        { n: 8, label: 'Overview of Gateway and tenant-based URLs', fx: 0.4, fy: 0.8 },
      ],
    });
  }

  // eslint-disable-next-line no-console
  console.log(`[overview] produced ${OUT} via ${live ? 'LIVE server' : 'STATIC fallback'}`);
});
