# Identity Federation Gateway

A multi-tenant, serverless gateway that adds a **SAML 2.0 Identity Provider** role and
extends the **OpenID Connect 1.0 Provider** capabilities of
[Amazon Cognito](https://aws.amazon.com/cognito/) user pools — per-tenant issuers,
per-application claim mappings, token introspection, and cross-pool federation.

> **📖 Full documentation:** the complete, organized docs live in [`docs/`](docs/) and are
> published as a site with MkDocs Material. Start with the
> [Introduction](docs/overview/introduction.md) or the
> [Quickstart](docs/deployment/quickstart.md).

![Identity Federation Gateway — AWS Deployment Architecture](docs/images/architecture.png)

## Why it exists

Amazon Cognito is a solid OIDC provider, but it **cannot issue SAML assertions** and gives
you **one OIDC issuer per pool** with a fixed claim set. This gateway fronts one or more
Cognito pools and presents standards-compliant SAML 2.0 and OpenID Connect 1.0 endpoints per
tenant, with configuration-driven claim and role mapping — no per-application Lambda code.

## Features

- **[SAML 2.0 IdP](docs/protocols/saml.md)** — SSO, SLO, metadata, and signed assertions
  (RSA-SHA256 via AWS KMS).
- **[OpenID Connect Provider](docs/protocols/oidc.md)** — multi-tenant issuers, token
  introspection, per-app claim mapping, RS256 signing.
- **Multi-tenant** — isolated issuers, per-tenant KMS signing keys, cross-pool federation.
- **Admin console** — a React SPA to manage tenants, identity sources, applications, and
  mappings.
- **Serverless** — AWS Lambda + CloudFront + WAF; ~$28–35/month idle
  ([cost estimate](docs/overview/cost.md)).

## Quick start

Run everything locally — no AWS account needed:

```bash
make run-local      # Gateway on :8080 (in-memory store, mock KMS)
make test-sp        # SAML SP demo on :8081
make test-rp        # OIDC RP demo on :8082
```

Deploy to AWS (see the [Quickstart](docs/deployment/quickstart.md) for prerequisites and the
one-time backend bootstrap):

```bash
make deploy-dev   ENV=dev AWS_PROFILE=<profile>
make post-install ENV=dev AWS_PROFILE=<profile> ADMIN_EMAIL=you@example.com
```

## Documentation

| Topic | Link |
|-------|------|
| What it is and why | [Introduction](docs/overview/introduction.md) |
| Deployment architecture | [Architecture](docs/overview/architecture.md) |
| Data model | [Data model](docs/overview/data-model.md) |
| SAML 2.0 IdP | [Protocols → SAML](docs/protocols/saml.md) |
| OpenID Connect | [Protocols → OIDC](docs/protocols/oidc.md) |
| First deploy (new account) | [Quickstart](docs/deployment/quickstart.md) |
| Post-install (cert + admin) | [Post-install](docs/deployment/post-install.md) |
| Teardown | [Teardown](docs/deployment/teardown.md) |
| Cost | [Cost estimate](docs/overview/cost.md) |
| Security | [Security](docs/overview/security.md) |
| All `make` targets | [Make commands](docs/reference/make-commands.md) |

## Technologies

- **Go** with [crewjam/saml](https://github.com/crewjam/saml), [zitadel/oidc](https://github.com/zitadel/oidc),
  [Huma](https://github.com/danielgtaylor/huma), [guregu/dynamo](https://github.com/guregu/dynamo)
- **React 18** with [Cloudscape Design System](https://cloudscape.design) and TanStack Query
- **Terraform** with [terraform-aws-modules](https://github.com/terraform-aws-modules)

## Contributing & security

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

This project is provided as a sample implementation. See [LICENSE](LICENSE) for details.
