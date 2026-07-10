const { defineConfig } = require('@playwright/test');
const path = require('path');
const fs = require('fs');

// On aarch64 AL2023 (the dev workstation) the ms-playwright `chromium_headless_shell`
// bundle is x86-only and crashes with missing libatk/libX11 shared libs. The full
// Chromium binary at chromium-<rev>/chrome-linux/chrome works once the extracted RPM
// deps are on LD_LIBRARY_PATH. Auto-detect both so the config is portable: on any
// other host Playwright falls back to its own discovery logic.
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

module.exports = defineConfig({
  testDir: '.',
  timeout: 45000,
  fullyParallel: true,
  reporter: [['list']],
  use: {
    headless: true,
    ignoreHTTPSErrors: false,
    actionTimeout: 15000,
    navigationTimeout: 30000,
    launchOptions: {
      ...(executablePath ? { executablePath } : {}),
      ...(extraEnv ? { env: extraEnv } : {}),
      args: ['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage'],
    },
  },
});
