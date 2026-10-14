const { defineConfig } = require('@playwright/test');
const path = require('path');
const fs = require('fs');

// --- arm64-Chromium autodetect (copied pattern from scripts/browser-e2e/playwright.config.js) ---
// On aarch64 AL2023 (the Linux dev workstation) the ms-playwright `chromium_headless_shell`
// bundle is x86-only and crashes with missing libatk/libX11 shared libs. The full Chromium
// binary at chromium-<rev>/chrome-linux/chrome works once the extracted RPM deps are on
// LD_LIBRARY_PATH. Auto-detect both so the config is portable: on any other host (e.g. this
// macOS host) the paths do not exist and Playwright falls back to its own discovery logic.
const CHROME_ARM64 = path.join(
  process.env.HOME || '/home/coder',
  '.cache/ms-playwright/chromium-1228/chrome-linux/chrome',
);
const LIBS_PATH = '/tmp/browser-e2e/libs';

const executablePath = fs.existsSync(CHROME_ARM64) ? CHROME_ARM64 : undefined;
const extraEnv =
  executablePath && fs.existsSync(LIBS_PATH)
    ? { LD_LIBRARY_PATH: LIBS_PATH, PLAYWRIGHT_SKIP_VALIDATE_HOST_REQUIREMENTS: '1' }
    : undefined;

// The admin SPA (frontend/) imports auth.ts at module load, which throws unless the three
// VITE_COGNITO_* vars are present. These are fake, non-resolving placeholder values passed
// ONLY to the dev-server process via webServer.env — never written to any committed .env, and
// never a product-code change (auth.ts is untouched). The region in the pool id matches the
// seeded token iss/aud so no display path trips.
const FAKE_ENV = {
  VITE_COGNITO_USER_POOL_ID: 'us-east-1_EXAMPLE',
  VITE_COGNITO_CLIENT_ID: 'exampleclientid0000000000',
  VITE_COGNITO_DOMAIN: 'example.auth.us-east-1.amazoncognito.com',
};

module.exports = defineConfig({
  testDir: './specs',
  // Capture specs run serially: they share the one dev server and each writes a
  // distinct image. Serial keeps the dev-server log readable and avoids racing the
  // single reused Vite server.
  fullyParallel: false,
  workers: 1,
  timeout: 120000,
  reporter: [['list']],
  use: {
    headless: true,
    ignoreHTTPSErrors: false,
    actionTimeout: 15000,
    navigationTimeout: 30000,
    viewport: { width: 1440, height: 900 },
    deviceScaleFactor: 1,
    launchOptions: {
      ...(executablePath ? { executablePath } : {}),
      ...(extraEnv ? { env: extraEnv } : {}),
      args: ['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage'],
    },
  },
  webServer: {
    command: 'npm run dev',
    cwd: path.resolve(__dirname, '../../frontend'),
    url: 'http://localhost:3000',
    reuseExistingServer: true,
    timeout: 120000,
    env: { ...process.env, ...FAKE_ENV },
  },
});
