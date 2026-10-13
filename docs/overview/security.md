# Security

The gateway is designed to be safe to expose publicly. Security controls span the edge, the
API layer, cryptographic signing, and the request-handling code.

## Authentication & authorization

- **Management API** endpoints require Amazon Cognito **JWT authentication** at the
  [Amazon API Gateway](https://aws.amazon.com/api-gateway/) layer.
- **Role-based access control**: management operations require membership in the `Admins`
  (read + write) or `Operators` (read-only) Cognito group. The console scopes each admin to
  the tenant in their `custom:tenant_id` claim.
- **Admin-only user creation** in the Amazon Cognito user pool (no self-signup).

## Cryptography

- **SAML assertions** signed with RSA-SHA256; **OIDC tokens** signed with RS256 — both
  through AWS KMS, so private keys never leave KMS.
- **Cookie encryption**: login cookies are AES-256-GCM encrypted and HMAC-SHA256 signed.
  A single 32-byte root key lives in AWS Secrets Manager and is shared by every
  `saml-sso` and `oidc-authorize` instance; each protocol derives its own HMAC and AES
  subkeys from it (a SAML cookie is never valid on the OIDC surface), and every cookie
  carries a key-id prefix so a rotated or mismatched key is rejected explicitly.
- **Per-tenant KMS signing keys** are supported for tenant isolation.

## Request protection

- **AWS WAF** with the OWASP Core Rule Set, AWS managed rule groups (Known Bad Inputs, IP
  reputation), and endpoint-specific rate limiting.
- **CSRF protection** via OAuth2 `state` parameters and PKCE.
- **Login-binding cookies** for custom login pages: the redirect to the page sets a
  short-lived, signed `__Host-` cookie tied to the flow's `state`, and the hand-back to
  `/login/complete` is only accepted from the browser that carries it, so a token cannot
  be posted into someone else's browser to log them in as the attacker.
- **Origin allow-list for IdP-initiated SSO**: a browser form post to
  `/saml/idp-initiate` is only honoured from the gateway's own origin or the origin of
  the app's custom login URL / trusted login redirect URIs; IdP-initiated launches never
  persist a session cookie.
- **AuthnRequest replay detection** on the SAML SSO path.
- **CloudFront origin-verify** header (an edge secret in AWS Secrets Manager) ensures the
  API is only reached through the WAF-protected CloudFront front door.

## Reporting a vulnerability

See the repository [Security Policy](https://github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/security/policy)
(`SECURITY.md`) for how to report security issues.

!!! note
    This is a sample implementation. Review and adapt the controls above to your own
    security requirements before using it beyond evaluation. Full WCAG/compliance validation
    and a security review are your responsibility for production use.
