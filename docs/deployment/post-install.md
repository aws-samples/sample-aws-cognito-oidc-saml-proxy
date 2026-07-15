# Post-install configuration

`make deploy-dev` provisions all infrastructure but intentionally leaves two
account/operator-specific steps for you, because a fresh deployment is not usable until
both are done.

Run the automated target after the stacks are up:

```bash
make post-install ENV=dev AWS_PROFILE=<profile> ADMIN_EMAIL=you@example.com
```

It performs two idempotent actions:

## 1. Seed the SAML signing certificate

Only the `saml-sso` Lambda self-bootstraps the signing certificate (on its first cold
start). The `management-api` and `saml-metadata` Lambdas **read** the certificate at startup
and exit if it is missing.

Consequently, on a fresh deploy the certificate does not exist yet — so opening the admin
console before any SSO traffic returns **HTTP 500** on every database-backed call.
`make post-install` invokes `saml-sso` once, which generates the self-signed certificate
(signed by the primary KMS key) and persists it to DynamoDB. Any real SAML SSO flow also
triggers this.

## 2. Add your user to the `Admins` group

A freshly created Cognito user belongs to no group, and the management API requires the
`Admins` (read + write) or `Operators` (read-only) group for every operation — otherwise it
returns **HTTP 403**. `make post-install ADMIN_EMAIL=...` adds the user to `Admins`.

!!! important
    After being added to a group, sign out and back in so your new token carries the
    `cognito:groups` claim.

## Remaining manual steps

`post-install` does not create a tenant or register applications. Continue with the
[Quickstart](quickstart.md) sections for creating a tenant, adding an identity source, and
registering your first SAML or OIDC application.
