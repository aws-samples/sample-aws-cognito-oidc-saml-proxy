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

Both apps are deployed as AWS Lambda functions behind Amazon CloudFront:

| App | URL |
|-----|-----|
| SAML SP | `https://saml.fedgw.<your-domain>` |
| OIDC RP | `https://oidc.fedgw.<your-domain>` |

## Utility scripts

| Script | Description |
|--------|-------------|
| `smoke-test.sh` | Verify gateway endpoints (health, metadata, discovery, JWKS, API auth) |
| `generate-client.sh` | Generate TypeScript types from the gateway OpenAPI spec |
