// Captures the README "custom login showcase" hero images for the demo SPA.
//
// It renders the real built Login page against a FAKE runtime /config.json
// (truthy pool/client + a social-IdP list + passkeysEnabled) so the social
// buttons and the passkey affordance both appear, then screenshots:
//
//   docs/images/login-desktop.png   1440x900
//   docs/images/login-mobile.png     390x844
//
// A hard network guard aborts anything that is not the local Vite dev server
// (:5174) — in particular any cognito-idp.*.amazonaws.com call — so the capture
// can never touch live AWS. Only fake/original content is shown
// ("Nimbus ID", alex@example.com). Each PNG is sharp-optimized and asserted
// to be <= ~400 KB.
//
// Usage: npm run capture:hero  (from examples/custom-ui/frontend)

import { chromium } from '@playwright/test';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { mkdir, writeFile, stat } from 'node:fs/promises';
import sharp from 'sharp';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FRONTEND_DIR = resolve(__dirname, '..');
const REPO_ROOT = resolve(FRONTEND_DIR, '../../..');
const OUT_DIR = resolve(REPO_ROOT, 'docs/images');

const DEV_URL = 'http://localhost:5174';
const MAX_BYTES = 410_000; // ~400 KB ceiling for each committed PNG.

// Fake runtime config: truthy pool/client so loadConfig() uses /config.json, a
// cognitoDomain + socialIdps so the social section renders, passkeysEnabled so
// the passkey button shows. None of these are real credentials.
const FAKE_CONFIG = {
  userPoolId: 'us-east-1_EXAMPLE',
  clientId: 'exampleclientid0000000000',
  region: 'us-east-1',
  cognitoDomain: 'example.auth.us-east-1.amazoncognito.com',
  passkeysEnabled: true,
  socialIdps: [
    { label: 'Google', idp: 'Google', color: '#4285f4' },
    { label: 'Apple', idp: 'SignInWithApple', color: '#111111' },
    { label: 'Microsoft', idp: 'Microsoft', color: '#2f6fed' },
  ],
};

function isLocalDevRequest(url) {
  try {
    const u = new URL(url);
    return u.host === 'localhost:5174' || u.host === '127.0.0.1:5174';
  } catch {
    return false;
  }
}

async function waitForServer(url, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url);
      if (res.ok || res.status === 200) return true;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 400));
  }
  return false;
}

async function startDevServer() {
  // Reuse an already-running dev server if one is up.
  if (await waitForServer(DEV_URL, 1200)) {
    console.log('Reusing existing dev server on :5174');
    return null;
  }
  console.log('Starting Vite dev server on :5174 …');
  const proc = spawn('npm', ['run', 'dev', '--', '--port', '5174', '--strictPort'], {
    cwd: FRONTEND_DIR,
    stdio: 'ignore',
    detached: false,
  });
  const up = await waitForServer(DEV_URL, 60_000);
  if (!up) {
    proc.kill('SIGTERM');
    throw new Error('Vite dev server did not become ready on :5174');
  }
  return proc;
}

async function optimizeAndWrite(buffer, outPath) {
  const png = await sharp(buffer)
    .png({ compressionLevel: 9, palette: true, quality: 90, effort: 10 })
    .toBuffer();
  await writeFile(outPath, png);
  const { size } = await stat(outPath);
  if (size > MAX_BYTES) {
    throw new Error(
      `${outPath} is ${size} bytes, over the ${MAX_BYTES}-byte (~400 KB) ceiling`,
    );
  }
  console.log(`wrote ${outPath} (${(size / 1024).toFixed(1)} KB)`);
}

async function capture() {
  await mkdir(OUT_DIR, { recursive: true });
  const serverProc = await startDevServer();
  const browser = await chromium.launch({ headless: true });

  try {
    for (const variant of [
      { name: 'login-desktop', width: 1440, height: 900, dpr: 1 },
      { name: 'login-mobile', width: 390, height: 844, dpr: 2 },
    ]) {
      const context = await browser.newContext({
        viewport: { width: variant.width, height: variant.height },
        deviceScaleFactor: variant.dpr,
      });
      const page = await context.newPage();

      // Hard guard registered FIRST so the specific /config.json route (added
      // below) takes precedence — Playwright evaluates handlers in reverse
      // registration order. This aborts any Cognito call or non-local request,
      // proving the capture never reaches live AWS.
      await page.route('**/*', (route) => {
        const url = route.request().url();
        if (/cognito-idp\.[a-z0-9-]+\.amazonaws\.com/i.test(url)) {
          return route.abort();
        }
        if (!isLocalDevRequest(url)) {
          return route.abort();
        }
        return route.continue();
      });

      // Serve the fake config instead of the dev server's (there is none locally).
      await page.route('**/config.json', (route) =>
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(FAKE_CONFIG),
        }),
      );

      await page.goto(`${DEV_URL}/login`, { waitUntil: 'networkidle' });

      // Prefill fake, original content so the hero looks real but leaks nothing.
      await page.getByLabel('Email').fill('alex@example.com');
      await page.getByLabel('Password').fill('correct horse battery');

      // Sanity: the Nimbus ID brand + social + passkey affordances must be present.
      await page.getByText('Nimbus ID').first().waitFor({ state: 'visible' });
      await page.getByRole('button', { name: /Continue with Google/i }).waitFor({ state: 'visible' });
      await page.getByRole('button', { name: /passkey/i }).waitFor({ state: 'visible' });

      const buffer = await page.screenshot({ type: 'png' });
      await optimizeAndWrite(buffer, resolve(OUT_DIR, `${variant.name}.png`));

      await context.close();
    }
  } finally {
    await browser.close();
    if (serverProc) serverProc.kill('SIGTERM');
  }
}

capture().catch((err) => {
  console.error(err);
  process.exit(1);
});
