# Deployment Architecture

This document describes the AWS deployment architecture of the Identity Federation
Gateway — a multi-tenant, serverless SAML 2.0 IdP and OIDC Provider that fronts
Amazon Cognito user pools.

![Identity Federation Gateway — AWS Deployment Architecture](../images/architecture.png)

The diagram above is generated from [`diagrams/architecture.json`](../diagrams/architecture.json).
An editable draw.io version of the same architecture is available at
[`diagrams/identity-federation-gateway.drawio`](../diagrams/identity-federation-gateway.drawio)
([rendered PNG](../images/identity-federation-gateway.png)).
The sections below describe each component shown, grouped the same way as the diagram.

## Actors

- **Platform Admin** — operator who manages tenants, identity sources, applications,
  and claim/role mappings through the administration console (a React SPA). All admin
  traffic is HTTPS and authenticated against the Cognito user pool.
- **End User** — the person being federated. They reach the gateway over HTTPS to
  complete a SAML or OIDC single sign-on flow initiated by a relying party.

## Edge — CloudFront + WAF

- **CloudFront** — the single public entry point. It serves the admin console SPA
  from S3 and routes API and protocol traffic (`/api`, `/t/*`, `/login`) to API
  Gateway. It also applies the Content Security Policy and other response headers.
- **AWS WAF** (us-east-1, attached at the edge) — inspects inbound requests with the
  OWASP Core Rule Set and endpoint-specific rate limiting before traffic is served.

## Region — us-east-1

Core regional resources sitting behind the edge.

- **S3 — Admin Console SPA** — private bucket holding the built React/TypeScript
  single-page app, served only through CloudFront via Origin Access Control (OAC).
- **API Gateway (HTTP API)** — front door for all gateway endpoints. Management API
  routes (`ANY /api/v1/*`) are protected by a **Cognito JWT authorizer**; the SAML and
  OIDC protocol routes are public per their respective specifications.
- **Cognito User Pool** — serves two roles: it authenticates platform admins for the
  console, and it acts as an upstream identity source whose users and `cognito:groups`
  are federated out as SAML assertions or OIDC tokens.
- **ECR** — holds the container images for the Lambda functions (one repository per
  function, 8 total). Lambda pulls its image from ECR at deploy time.

### Lambda — per-capability functions (arm64 containers)

Each capability is an independent ARM64 container Lambda, invoked by API Gateway:

- **saml-sso** — handles `/saml/sso` and the ACS callback. Reads tenant/app config and
  session state, signs the SAML assertion with KMS, and looks up the user and groups
  from Cognito. Writes audit steps to CloudWatch Logs.
- **saml-slo** — front-channel Single Logout (`/saml/slo`).
- **saml-metadata** — serves IdP `<EntityDescriptor>` metadata (`/saml/metadata`).
- **oidc-authorize** — OIDC/OAuth2 authorization endpoint.
- **oidc-token** — token endpoint; signs issued JWTs with KMS (RS256).
- **oidc-discovery** — discovery document and JWKS (`/.well-known`).
- **management-api** — backs the admin console; all routes require a valid Cognito JWT.
  Performs CRUD on the config table and writes IaC templates to S3.
- **health** — health/synthetic check endpoint, invoked on a schedule by EventBridge.

### Data stores

- **DynamoDB — config (single-table)** — all tenant, identity-source, application,
  SAML/OIDC config, claim-mapping and role-mapping entities, keyed by composite
  `PK`/`SK`. Encrypted at rest with the symmetric KMS encryption key.
- **DynamoDB — session (TTL)** — short-lived flow/session state, expired automatically
  via DynamoDB TTL.
- **S3 — IaC templates** — stores generated infrastructure-as-code templates produced
  by the management API for onboarding.

### Signing & encryption (KMS)

- **KMS — signing (RSA)** — asymmetric RSA key used to sign SAML responses/assertions
  (RSA-SHA256) and OIDC tokens (RS256).
- **KMS — backup signing (optional)** — optional secondary signing key for rotation
  or key-backup scenarios.
- **KMS — encryption (symmetric)** — symmetric key for server-side encryption of the
  DynamoDB config table and other data at rest.

### Observability & ops

- **CloudWatch Logs** — central audit trail; Lambda functions write structured flow
  audit events here.
- **CloudWatch Alarms** — monitor API Gateway and DynamoDB metrics.
- **SNS** — delivers email alerts when an alarm fires.
- **EventBridge** — scheduled rule that invokes the health Lambda every 5 minutes.

### Demo relying parties (optional)

- **Demo SAML SP** and **Demo OIDC RP** — optional sample apps (each Lambda + API
  Gateway + CloudFront) that initiate SSO through the gateway to demonstrate the
  end-to-end flow. Shown dashed because they are optional.

## Cognito Custom UI Demo — OPTIONAL (separate Terraform stack)

An optional, separately deployed stack demonstrating a custom Cognito login UI:

- **CloudFront + optional IP WAF** — edge for the custom login SPA, with optional
  IP-allowlist WAF.
- **S3 (private, OAC)** — bucket holding the custom login SPA, served only via
  CloudFront with OAC.

The custom UI authenticates end users directly against the Cognito user pool
(SRP/refresh) and then hands off to the gateway as an app launcher. This whole cluster
is dashed/optional and lives in its own Terraform stack.

## Request flow summary

1. An admin or end user reaches **CloudFront**, which is inspected by **WAF**.
2. SPA asset requests are served from the **Admin Console S3** bucket; everything else
   is routed to **API Gateway**.
3. API Gateway authorizes management traffic via the **Cognito JWT authorizer** and
   dispatches protocol traffic to the matching **Lambda** function.
4. Lambdas read/write **DynamoDB** (config + session), sign with **KMS**, resolve users
   and groups from **Cognito**, and emit audit events to **CloudWatch Logs**.
5. **EventBridge** drives periodic health checks; **CloudWatch Alarms** notify via
   **SNS** on metric breaches.
