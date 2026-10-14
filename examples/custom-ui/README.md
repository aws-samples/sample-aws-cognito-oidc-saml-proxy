# Cognito Custom UI Demo (educational)

A self-contained React SPA showing how to build your **own** authentication UI
against an Amazon Cognito user pool using a **public app client** — instead of
the Cognito Hosted UI. It demonstrates the major operations and is intended as a
reference customers can read and adapt; it is **not** production-hardened.

> **Educational only.** Tokens are stored in `localStorage` for clarity, which is
> exposed to XSS. A production app should consider in-memory storage or a
> backend-for-frontend with HttpOnly cookies. Deploy this demo **separately** from
> any production stack.

## What it demonstrates

| Operation | Page | Cognito API (via `amazon-cognito-identity-js`) |
|-----------|------|------------------------------------------------|
| Login (SRP) | `/login` | `authenticateUser` |
| Self-registration | `/register` | `signUp` |
| Confirm sign-up | `/confirm` | `confirmRegistration`, `resendConfirmationCode` |
| Forgot password | `/forgot-password` | `forgotPassword`, `confirmPassword` |
| Change password (authenticated) | `/change-password` | `getSession` + `changePassword` |
| Logout | `/` (Home) | `signOut` (local), `globalSignOut` |
| Seamless token refresh | everywhere | `getSession` auto-refreshes expired tokens |
| App launcher (SAML IdP-initiated / OIDC redirect) | `/apps` | posts the ID token to the gateway |
| Configuration reference | `/config` | — |

## Architecture (hosting + security)

This demo uses the **same hosting pattern as the Federation Gateway console**:

```
Browser  ──>  CloudFront (+ WAF IP allowlist)  ──>  private S3 bucket (OAC)
                                                       index.html, assets, config.json
```

- The SPA is built to static files and stored in a **private** S3 bucket. Only
  CloudFront can read it (Origin Access Control); the bucket blocks all public access.
- A **WAF web ACL** with an **IP allowlist** can optionally guard the distribution.
  By default (no `allowed_cidrs`) the site is **public** so customers can use it; set
  CIDRs to lock it to specific IPs.
- There is **no Lambda Function URL** and **no public principal** — this avoids the
  "Lambda runs with any principal" finding entirely.
- **Runtime config:** `config.json` is rendered from Terraform variables and stored
  in S3 (no rebuild to change config). The SPA fetches it at startup.

For local dev, config comes from `frontend/.env.local` (`VITE_*`) instead.

## Prerequisites

- A Cognito user pool and a **public** app client (no secret) with
  `ALLOW_USER_SRP_AUTH` + `ALLOW_REFRESH_TOKEN_AUTH`.
- Self-registration requires the pool to allow self sign-up
  (`allow_admin_create_user_only = false`).
- Node 18+, Terraform 1.6+, AWS credentials. (No Go/Docker/ECR — the previous
  Lambda-hosted version was retired for security.)

## Local development

```bash
cd frontend
cp .env.example .env.local      # fill in your pool/client/region
npm install && npm run dev      # http://localhost:5174
```

## Optional: social login and passkeys on the login page

The `/login` page can show **social / external IdP buttons** and a **WebAuthn
passkey button** in addition to the SRP email/password form. Both are **hidden /
off by default** — the page stays a plain email/password form until you configure
them. They are driven entirely by config (no rebuild in a deployed environment):
the values flow through the runtime `/config.json` or, for local `npm run dev`,
the `VITE_*` env vars. The demo-stack `local.config` does **not** need to carry
them; this is operator-driven and optional.

| Config field (`/config.json`) | Local env var | Effect |
|---|---|---|
| `cognitoDomain` | `VITE_COGNITO_DOMAIN` | Cognito user-pool domain used to build the `/oauth2/authorize` social-login URLs. Required for the social section to appear. |
| `socialIdps` | `VITE_SOCIAL_IDPS` | JSON array of `{ "label", "idp", "color"? }`. `idp` is the exact Cognito identity-provider name. Social buttons show only when this is non-empty **and** `cognitoDomain` is set. |
| `passkeysEnabled` | `VITE_PASSKEYS_ENABLED` | `true` shows the passkey button. The button is still disabled when the browser lacks WebAuthn support. |

**Social buttons** perform a real top-level redirect to
`https://{cognitoDomain}/oauth2/authorize?identity_provider={idp}&response_type=code&client_id={clientId}&redirect_uri={origin}/login&scope=openid+email+profile`.
For this to work the operator must:

- create the matching identity providers in the Cognito user pool (e.g. Google,
  Sign in with Apple, or a custom SAML/OIDC provider),
- enable those providers on the app client (the gateway stack exposes
  `spa_additional_identity_providers` for the SPA client — see
  `infra/gateway/variables.tf`), and
- register `{origin}/login` (e.g. `https://your-demo-host/login`) as a callback
  URL on the app client.

**Passkeys** run the real Cognito selection-based `USER_AUTH` → `WEB_AUTHN` flow
(`InitiateAuth` → `navigator.credentials.get()` → `RespondToAuthChallenge`). The
demo pool must be on the **Essentials tier or higher** (WebAuthn is not available
on the Lite tier), and the user is assumed to have a **pre-registered passkey** —
passkey **enrollment** is out of scope for this demo. Enter the user's email in
the Email field first, then click **Sign in with a passkey**.

Example `.env.local` snippet:

```bash
VITE_COGNITO_DOMAIN=example.auth.us-east-1.amazoncognito.com
VITE_SOCIAL_IDPS=[{"label":"Google","idp":"Google","color":"#4285f4"},{"label":"Apple","idp":"SignInWithApple"}]
VITE_PASSKEYS_ENABLED=true
```

## Deploy (AWS)

```bash
cd infra
cp terraform.tfvars.example terraform.tfvars
# edit: cognito_user_pool_id, cognito_client_id, and allowed_cidrs (your IP)
#   get your IP:  curl https://checkip.amazonaws.com   then use <ip>/32
```

Then from `examples/custom-ui/`:

```bash
make deploy
```

`make deploy` builds the SPA, runs `terraform apply` (private bucket + CloudFront +
WAF + config.json), syncs the assets to S3 (excluding the Terraform-managed
`config.json`), and invalidates CloudFront. It prints the CloudFront URL — reachable
only from `allowed_cidrs`. Tear down with `make destroy`.

> **Access control (optional):** by default the demo is **public** (no WAF) so
> customers can use it. To restrict it to specific IPs, set `allowed_cidrs` /
> `allowed_ipv6_cidrs` in `terraform.tfvars` and re-apply — a CloudFront WAF is
> created that blocks everything else.

## Using this as the Federation Gateway custom login page / launcher

This app authenticates against the same pool the gateway uses as an identity
source, so it can serve as a per-application custom login page and IdP-initiated
launcher. See the in-app **Configuration** page for the exact values
(`customLoginUrl`, `trustedLoginRedirectUris`, and the session-establish / idp-initiate
endpoints) for your deployment.

## Layout

```
examples/custom-ui/
  frontend/   React + Vite SPA (the UI + Cognito calls)
  infra/      Terraform: private S3, CloudFront (OAC), WAF IP allowlist, config.json
  Makefile    build -> terraform apply -> S3 sync -> CloudFront invalidate
```
