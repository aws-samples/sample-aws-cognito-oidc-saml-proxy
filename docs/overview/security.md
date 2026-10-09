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
- **Cookie encryption** uses AES-256-GCM with HMAC-SHA256, using separately derived keys.
- **Per-tenant KMS signing keys** are supported for tenant isolation.

## Request protection

- **AWS WAF** with the OWASP Core Rule Set, AWS managed rule groups (Known Bad Inputs, IP
  reputation), and endpoint-specific rate limiting.
- **CSRF protection** via OAuth2 `state` parameters and PKCE.
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
