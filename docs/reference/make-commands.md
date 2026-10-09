# Make commands

The `Makefile` at the repo root is the primary entry point for building, testing, and
deploying. Common targets are grouped below. Most deploy/teardown targets accept
`ENV=<env>` and `AWS_PROFILE=<profile>` overrides.

## Build & run

| Command | Description |
|---------|-------------|
| `make build` | Build the Go binary (linux/arm64) |
| `make build-all-lambdas` | Build all 8 Lambda function binaries |
| `make run-local` | Run the gateway locally on `:8080` (in-memory store, mock KMS) |
| `make test-sp` | Run the SAML SP demo on `:8081` |
| `make test-rp` | Run the OIDC RP demo on `:8082` |
| `make frontend-dev` | Frontend dev server on `:3000` |

## Test & lint

| Command | Description |
|---------|-------------|
| `make test` | Run unit tests (`./internal/...`) |
| `make test-integration` | Run integration-tagged tests (self-contained) |
| `make test-e2e` | Run end-to-end-tagged tests (self-contained) |
| `make lint` | Run `golangci-lint` and `tflint` |
| `make security-scan` | Run the local security scanner suite |

## Deploy

| Command | Description |
|---------|-------------|
| `make deploy-dev` | Full ordered deploy: registry → images → gateway → demo → frontend |
| `make post-install` | Seed the SAML signing cert and add `ADMIN_EMAIL` to the `Admins` group |
| `make frontend-deploy` | Build the console, sync to S3, invalidate CloudFront |

```bash
make deploy-dev   ENV=dev AWS_PROFILE=<profile>
make post-install ENV=dev AWS_PROFILE=<profile> ADMIN_EMAIL=you@example.com
```

See [Quickstart](../deployment/quickstart.md) for the full first-deploy walkthrough and
[Post-install configuration](../deployment/post-install.md) for what `make post-install` does.

## Teardown

| Command | Description |
|---------|-------------|
| `make destroy-dev` | Tear down all three stacks (demo → gateway → registry) |
| `make demo-destroy` / `make gateway-destroy` / `make registry-destroy` | Destroy a single stack |

```bash
make destroy-dev ENV=dev AWS_PROFILE=<profile>
```

See [Teardown](../deployment/teardown.md) for details.
