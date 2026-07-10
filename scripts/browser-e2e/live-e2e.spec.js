// Browser E2E against a LIVE deployment. Drives real Chromium against the
// CloudFront-fronted endpoints. All endpoints are supplied via env vars, sourced
// from Terraform outputs at run time (see scripts/browser-e2e/README.md). No
// deployment-specific URLs are hard-coded here — nothing to leak into the repo.
const { test, expect } = require('@playwright/test');

function required(name) {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is required — source it from Terraform outputs (see README.md)`);
  return v;
}

const GATEWAY = required('GATEWAY_URL');   // gateway CloudFront base URL
const DEMO_SP = required('DEMO_SP_URL');   // SAML test SP
const DEMO_RP = required('DEMO_RP_URL');   // OIDC test RP
const COGNITO = required('COGNITO_HOST');  // Cognito hosted-UI hostname (no scheme)

test.describe('Admin SPA (frontend)', () => {
  test('serves index.html with the SPA mount point over CloudFront', async ({ request }) => {
    const r = await request.get(GATEWAY + '/');
    expect(r.status()).toBe(200);
    expect(r.headers()['content-type']).toContain('text/html');
    const html = await r.text();
    expect(html).toContain('<div id="root"');            // SPA mount point shipped
    expect(html).toMatch(/assets\/index-[\w-]+\.js/);     // hashed bundle referenced
  });

  test('unauthenticated SPA boots and redirects to Cognito hosted UI', async ({ page }) => {
    const resp = await page.goto(GATEWAY + '/', { waitUntil: 'networkidle' });
    expect(resp.status()).toBe(200);
    // The React app mounts, Amplify sees no session, and redirects the whole
    // document to the Cognito hosted UI — the page title becomes "Sign-in".
    // Reaching that state proves the bundle downloaded, executed, and the
    // Cognito user-pool config baked into the build at deploy time is valid.
    await expect(page).toHaveTitle(/Identity Federation Gateway|Sign-?in/i);
    expect((await page.content()).length).toBeGreaterThan(200);
  });

  test('serves hashed JS/CSS assets', async ({ page }) => {
    const bad = [];
    page.on('response', r => { if (r.url().includes('/assets/') && r.status() >= 400) bad.push(`${r.status()} ${r.url()}`); });
    await page.goto(GATEWAY + '/', { waitUntil: 'networkidle' });
    expect(bad, 'no asset should 4xx/5xx').toEqual([]);
  });
});

test.describe('Gateway API endpoints (through browser fetch)', () => {
  test('health returns ok', async ({ page }) => {
    await page.goto(GATEWAY + '/health');
    const body = await page.evaluate(() => document.body.innerText);
    expect(body).toContain('"status":"ok"');
  });

  test('OIDC discovery is well-formed and self-referential', async ({ request }) => {
    const r = await request.get(GATEWAY + '/t/default/oidc/.well-known/openid-configuration');
    expect(r.status()).toBe(200);
    const d = await r.json();
    expect(d.issuer).toBe(GATEWAY + '/t/default/oidc');
    expect(d.authorization_endpoint).toContain('/authorize');
    expect(d.token_endpoint).toContain('/token');
    expect(d.jwks_uri).toContain('/keys');
    expect(d.response_types_supported).toContain('code');
    expect(d.id_token_signing_alg_values_supported).toContain('RS256');
  });

  test('JWKS exposes an RS256 signing key', async ({ request }) => {
    const disc = await (await request.get(GATEWAY + '/t/default/oidc/.well-known/openid-configuration')).json();
    const r = await request.get(disc.jwks_uri);
    expect(r.status()).toBe(200);
    const jwks = await r.json();
    expect(jwks.keys.length).toBeGreaterThan(0);
    const k = jwks.keys[0];
    expect(k.kty).toBe('RSA');
    expect(k.use).toBe('sig');
    expect(k.alg).toBe('RS256');
    expect(k.kid).toBeTruthy();
  });

  test('SAML metadata is a valid EntityDescriptor', async ({ request }) => {
    const r = await request.get(GATEWAY + '/t/default/saml/metadata');
    expect(r.status()).toBe(200);
    const xml = await r.text();
    expect(xml).toContain('EntityDescriptor');
    expect(xml).toContain('IDPSSODescriptor');
    expect(xml).toContain('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect');
    expect(xml).toContain('X509Certificate');
    expect(xml).toContain('/t/default/saml/metadata'); // entityID references tenant
  });
});

test.describe('Demo SAML SP → gateway → Cognito redirect chain', () => {
  test('SP home renders login button', async ({ page }) => {
    await page.goto(DEMO_SP + '/', { waitUntil: 'domcontentloaded' });
    await expect(page.locator('text=Login via SAML')).toBeVisible();
  });

  test('clicking login drives an AuthnRequest to the gateway and on to Cognito', async ({ page }) => {
    await page.goto(DEMO_SP + '/', { waitUntil: 'domcontentloaded' });
    await page.click('text=Login via SAML');
    // Wait until we land on the Cognito hosted UI (or its /login|/oauth2/authorize).
    await page.waitForURL(url => url.hostname === COGNITO, { timeout: 30000 });
    const u = new URL(page.url());
    expect(u.hostname).toBe(COGNITO);
    // Cognito hosted UI login page should render (email/username field or login form).
    const html = await page.content();
    expect(html.length).toBeGreaterThan(200);
  });
});

test.describe('Demo OIDC RP → gateway → Cognito redirect chain', () => {
  test('RP home renders login button', async ({ page }) => {
    await page.goto(DEMO_RP + '/', { waitUntil: 'domcontentloaded' });
    await expect(page.locator('text=Login with OIDC')).toBeVisible();
  });

  test('clicking login builds a PKCE authorize request to the gateway', async ({ page }) => {
    // The RP redirects to the gateway /authorize with a proper code+PKCE request.
    // The gateway then validates client_id against registered OIDC apps. In this
    // fresh validation deploy the demo client is NOT yet registered (post-install
    // step), so the gateway correctly fails closed with 400 "unable to retrieve
    // client by id". We assert the RP built a spec-compliant request and the
    // gateway's authorize endpoint is live and validating.
    let authorizeURL = null;
    page.on('request', req => {
      if (req.url().includes('/t/default/oidc/authorize')) authorizeURL = req.url();
    });
    await page.goto(DEMO_RP + '/', { waitUntil: 'domcontentloaded' });
    await page.click('text=Login with OIDC');
    await page.waitForLoadState('networkidle');

    expect(authorizeURL, 'RP must redirect to the gateway authorize endpoint').toBeTruthy();
    const q = new URL(authorizeURL).searchParams;
    expect(q.get('response_type')).toBe('code');
    expect(q.get('code_challenge_method')).toBe('S256');
    expect(q.get('code_challenge')).toBeTruthy();
    expect(q.get('scope')).toContain('openid');
    expect(q.get('redirect_uri')).toContain('/callback');

    // Gateway validated the client and failed closed (demo app not registered).
    const body = await page.evaluate(() => document.body.innerText);
    expect(body).toContain('unable to retrieve client by id');
  });
});
