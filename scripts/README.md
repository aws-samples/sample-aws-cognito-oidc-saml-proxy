# Scripts

## Demo applications

Minimal protocol-specific test applications for verifying the Identity Federation Gateway end-to-end. Each app supports both local development (`go run`) and AWS Lambda deployment (via `aws-lambda-go-api-proxy`).

| App | Protocol | Local port | Path |
|-----|----------|-----------|------|
| [test-sp](test-sp/) | SAML 2.0 Service Provider | `:8081` | `/saml/login`, `/saml/acs`, `/saml/metadata` |
| [test-rp](test-rp/) | OpenID Connect 1.0 Relying Party | `:8082` | `/login`, `/callback` |

### Running locally

Start the gateway first, then each demo app in a separate terminal:

```bash
make run-local      # Gateway on :8080
make test-sp        # SAML SP on :8081
make test-rp        # OIDC RP on :8082
```

### Deployed environment

The `demo` Terraform stack deploys both apps as AWS Lambda functions behind Amazon CloudFront:

| App | URL |
|-----|-----|
| SAML SP | `terraform -chdir=infra/demo output -raw demo_saml_sp_url` (`https://saml.fedgw.<your-domain>` with a custom domain) |
| OIDC RP | `terraform -chdir=infra/demo output -raw demo_oidc_rp_url` (`https://oidc.fedgw.<your-domain>` with a custom domain) |

## Utility scripts

All scripts run from any directory and take their AWS settings from `PROFILE`
(default `default`), `REGION` (default `us-east-1`), and, where relevant, `ENV`
(default `dev`).

| Script | Description |
|--------|-------------|
| `smoke-test.sh <base-url> [tenant]` | Verify gateway endpoints (health, metadata, discovery, JWKS, OpenAPI, API auth). Tenant defaults to `default`. |
| `smoke-onboarding.sh [base-url]` | Walk the six-step tenant onboarding API against a local management API |
| `generate-client.sh` | Generate TypeScript types from the gateway OpenAPI spec |
| `security-scan.sh` | Local security scanner suite (also `make security-scan`) |
| `push-all-images.sh` | Build and push the 8 gateway images (wraps `make push-function-images`) |
| `push-demo-images.sh` | Build and push the 2 demo app images (wraps `make push-demo-images`) |
| `redeploy-function.sh <function>` | Build, push, and roll one gateway Lambda by image digest, and record the digest in `infra/env/<env>.tfvars` |
| `redeploy-saml-sso.sh`, `redeploy-management-api.sh` | Shortcuts for `redeploy-function.sh saml-sso` and `redeploy-function.sh management-api` |
| `reactivate-lambdas.sh` | Re-apply each Lambda's current image so an Inactive function is pulled from ECR again |
| `deploy-tenant-changes.sh` | One-time, phased rollout of the default-tenant changes (code, Terraform, console, user migration), with confirmation gates and code rollback |
| `migrate-default-tenant.sh` | One-time migration of Cognito users' `custom:tenant_id` from `demo` to `default`, with dry-run and restore |

The ECR repositories are immutable and every gateway Lambda deploys by image digest, so
use these scripts or the Makefile targets to ship images; pushing a `:latest` tag by
hand fails.

## Browser end-to-end tests

[`browser-e2e/`](browser-e2e/README.md) drives a real browser against a live deployment.
