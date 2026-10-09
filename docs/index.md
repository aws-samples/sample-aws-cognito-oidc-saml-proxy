# Identity Federation Gateway

A **multi-tenant, serverless gateway** that adds a SAML 2.0 Identity Provider role and
extends the OpenID Connect capabilities of [Amazon Cognito](https://aws.amazon.com/cognito/)
user pools — per-tenant issuers, per-application claim mappings, token introspection, and
cross-pool federation.

![Identity Federation Gateway — AWS Deployment Architecture](images/architecture.png)

## Why it exists

Amazon Cognito is a solid OIDC provider, but it **can't issue SAML assertions** and gives
you **one OIDC issuer per pool** with a fixed claim set. This gateway fills those gaps: it
fronts one or more Cognito pools and presents standards-compliant **SAML 2.0** and
**OpenID Connect 1.0** endpoints per tenant, with configuration-driven claim and role
mapping — no per-application Lambda code.

Read more in [Introduction](overview/introduction.md).

## What you get

- **SAML 2.0 IdP** — SSO, SLO, metadata, and signed assertions (RSA-SHA256 via AWS KMS).
  [Details →](protocols/saml.md)
- **OIDC 1.0 Provider** — multi-tenant issuers, introspection, per-app claim mapping, RS256
  signing. [Details →](protocols/oidc.md)
- **Multi-tenant** — isolated issuers, per-tenant KMS signing keys, cross-pool federation.
- **Admin console** — a React SPA to manage tenants, sources, apps, and mappings.
  [Guide →](guides/admin-console.md)
- **Serverless & low-cost** — Lambda + CloudFront + WAF, ~$28–35/mo idle.
  [Cost →](overview/cost.md)

## Get started

<div class="grid cards" markdown>

- :material-rocket-launch: **[Quickstart](deployment/quickstart.md)** — provision a fresh AWS
  account end-to-end with Terraform.
- :material-laptop: **[Local development](guides/local-development.md)** — run the gateway and
  demos on your machine, no AWS needed.
- :material-sitemap: **[Architecture](overview/architecture.md)** — every component and
  request path.
- :material-shield-lock: **[Security](overview/security.md)** — controls at the edge, API,
  and crypto layers.

</div>

## Quick local start

```bash
make run-local      # Gateway on :8080 (in-memory store, mock KMS)
make test-sp        # SAML SP demo on :8081
make test-rp        # OIDC RP demo on :8082
```

!!! note
    This is a sample implementation intended for evaluation and as a starting point. Review
    and adapt it to your own security and compliance requirements before production use.
