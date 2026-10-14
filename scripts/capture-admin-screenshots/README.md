# Admin console screenshot capture harness

Dev-only Playwright harness that drives the **already-built** admin SPA (`frontend/`, Vite dev
server on `http://localhost:3000`) and produces the annotated admin-tour screenshots embedded in
the repository `README.md`.

It touches **no product code**: `frontend/src/**` and all Go are left exactly as shipped. Auth is
satisfied by seeding a **fake, offline Amplify-v6 token-store session** into `localStorage`, and the
management API is served entirely from local JSON fixtures. A network-abort guard proves **no live
AWS** can be reached during capture.

## Output images (written to `../../docs/images/`)

| Image | Produced by | Contents |
|-------|-------------|----------|
| `admin-overview-annotated.png` | `specs/overview.spec.js` | Dashboard with 8 numbered callouts; Gateway Information expanded |
| `admin-register-oidc.png` | `specs/register-oidc.spec.js` | Register wizard step 2, OIDC (redirect URIs, scopes, token lifetimes, OIDC Settings) |
| `admin-register-saml.png` | `specs/register-saml.spec.js` | Register wizard step 2, SAML (Entity ID / ACS / NameID / signing toggles) |
| `admin-claim-mappings-annotated.png` | `specs/claim-mappings.spec.js` | Register wizard step 3, annotated mapping table + live preview |

> The existing plain `docs/images/admin-claim-mappings.png` (used by `docs/guides/admin-console.md`)
> is **never** overwritten — the annotated variant uses the distinct `*-annotated.png` filename.

Each image is `sharp`-optimized to PNG and the harness asserts it is `<= 410000` bytes.

## Prerequisites

- Node (host has v24.18, npm 11.16) and the admin frontend deps installed:
  `cd ../../frontend && npm install`.
- Playwright's bundled Chromium: `npx playwright install chromium` (run once in this directory
  after `npm install`). On aarch64 Linux dev workstations the config autodetects the arm64 Chromium
  under `~/.cache/ms-playwright`; on macOS Playwright uses its own discovery (the detection block is
  a no-op).

## Run

```sh
cd scripts/capture-admin-screenshots
npm install
npx playwright install chromium   # first run only
npm run capture
```

`npm run capture` starts (or reuses) the admin Vite dev server with fake, non-resolving
`VITE_COGNITO_*` placeholders (so `auth.ts`'s import-time guard does not throw — this is dev-server
config, not a product-code change), seeds the fake session, mocks `/api/v1/**` from `fixtures/`,
and writes all four images.

### Live-first, static-fallback

Each spec prefers the **live** path: it asserts the authenticated shell rendered
(`Overview` visible, no password field) and resolves every callout target to exactly one element.
If the gate fails, or any callout locator resolves to zero or multiple elements, the spec logs the
reason and falls through to a committed **static-image** path that applies the same `callouts.js`
overlay over the best existing `docs/images/admin-*.png`. Either way the image is produced. The run
log prints `via LIVE server` or `via STATIC fallback` for each image.

## No live AWS (hard constraint)

`specs/_setup.js` installs, in order:

1. `page.route('**/api/v1/**')` → JSON fixtures (`{}`-200 for any unlisted endpoint).
2. `page.route('**cognito-idp.*.amazonaws.com**')` → a canned offline reply (never reaches AWS).
3. `page.route('**')` → **aborts** any request whose URL is not `localhost:3000`, `/api/v1/**`, or
   the intercepted Cognito host. Blocked requests are logged as `[abort-guard] blocked request to …`.

The seeded token carries a far-future `exp` (year 2100), so Amplify never fires a refresh.

## No PII / no secrets

Fixtures and the seeded token use only these placeholders:

- `example.com`, `alex@example.com`
- pool id `us-east-1_EXAMPLE`, client id `exampleclientid0000000000`
- account id `111111111111`, KMS key `arn:aws:kms:us-east-1:111111111111:key/0000…`
- URLs under `https://gateway.example.com`

Verify with the no-PII grep (must print nothing):

```sh
grep -REn '@(?!example\.com)[A-Za-z0-9.-]+|AKIA|arn:aws:[a-z0-9-]*:[0-9]{12}' fixtures/ \
  | grep -v '111111111111'
```

(The one `arn:aws:kms:…:111111111111:…` placeholder is expected; the account id is the all-ones
placeholder, not a real account.)
