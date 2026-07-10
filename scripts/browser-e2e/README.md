# Browser E2E (live deployment)

Playwright + Chromium tests that drive a real browser against a **live**
deployment: the admin SPA, the gateway's SAML/OIDC endpoints, and the demo
SAML SP + OIDC RP redirect chains into the Cognito hosted UI.

These complement the in-process Go e2e suite (`make test-e2e`, mocked
KMS/Cognito). This suite exercises the real CloudFront → API Gateway → Lambda →
Cognito path end to end.

## Run

```bash
cd scripts/browser-e2e
npm i -D @playwright/test

# Endpoints default to the dev validation deploy; override for other envs.
# Pull them from Terraform outputs:
export GATEWAY_URL=https://$(terraform -chdir=../../infra/gateway output -raw cloudfront_domain_name)
export DEMO_SP_URL=$(terraform -chdir=../../infra/demo output -raw demo_saml_sp_url)
export DEMO_RP_URL=$(terraform -chdir=../../infra/demo output -raw demo_oidc_rp_url)
export COGNITO_HOST=$(terraform -chdir=../../infra/gateway output -raw cognito_domain | sed 's|https://||')

npx playwright test live-e2e.spec.js --workers=4
```

> **Note:** Do not run `npx playwright install chromium` on this workstation — it
> downloads the x86 `headless_shell` bundle which fails with missing shared libs on
> aarch64. The config auto-detects the working native arm64 binary at
> `~/.cache/ms-playwright/chromium-1228/chrome-linux/chrome` (installed via the
> headless-chrome fix) and sets `LD_LIBRARY_PATH=/tmp/browser-e2e/libs`
> automatically.

## What it asserts

- **Admin SPA**: index.html served over CloudFront with the `#root` mount and a
  hashed bundle; the app boots and (unauthenticated) redirects to the Cognito
  hosted UI — proving the baked-in Cognito config is valid.
- **Gateway API**: `/health` ok; OIDC discovery well-formed and self-referential;
  JWKS exposes an RS256 signing key; SAML metadata is a valid `EntityDescriptor`.
- **SAML SP → gateway → Cognito**: clicking "Login via SAML" produces an
  AuthnRequest to the gateway `/t/<tenant>/saml/sso` and lands on the Cognito
  hosted UI with a PKCE `code` request. (Default tenant's SAML SP is preconfigured.)
- **OIDC RP → gateway**: clicking "Login with OIDC" builds a spec-compliant
  PKCE `code` authorize request to the gateway. On a fresh deploy the demo OIDC
  client is not yet registered (post-install step), so the gateway fails closed
  with `400 unable to retrieve client by id` — asserted as correct behavior.
  Once the demo OIDC app is registered, extend the test to follow through to Cognito.

## Headless Chromium on a minimal host (no root)

On aarch64 Amazon Linux 2023 without X libs and no sudo, the ms-playwright
`chromium_headless_shell` bundle is x86-only and fails. Use the native arm64
`chrome` binary from `~/.cache/ms-playwright/chromium-1228/` instead, with the
system libs extracted once into `/tmp/browser-e2e/libs`:

```bash
mkdir -p /tmp/browser-e2e/{rpm,ex,libs} && cd /tmp/browser-e2e/rpm
dnf download --destdir . libXcomposite libXdamage libXfixes libXrandr libXext \
  libXi libXtst libXScrnSaver at-spi2-atk at-spi2-core atk libX11 libX11-xcb \
  mesa-libgbm mesa-libglapi mesa-dri-drivers libglvnd-glx alsa-lib libdrm \
  libwayland-server libwayland-client libxkbcommon libxshmfence llvm-libs
for r in *.rpm; do (cd ../ex && rpm2cpio ../rpm/"$r" | cpio -idmu --quiet); done
find ../ex -name '*.so*' -exec cp -P {} ../libs/ \;
```

`playwright.config.js` auto-detects the native binary and lib path — no extra
env vars needed when running from this directory.
