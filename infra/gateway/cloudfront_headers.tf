################################################################################
# CloudFront Response Headers Policy — Admin SPA security headers + CSP
#
# Attached ONLY to the SPA (S3) default cache behavior. It is intentionally NOT
# attached to the API Gateway behaviors (/api/v1/*, /t/*/saml/*, /t/*/oidc/*,
# /login, /openapi.json):
#   - The SAML HTTP-POST binding returns an HTML page with a cross-origin
#     auto-submitting <form> (action = the SP's ACS URL) plus an inline submit
#     script. A strict CSP (form-action 'self', script-src 'self') would break
#     SSO. Those endpoints have their own security model (signed assertions,
#     OAuth 'state' CSRF protection).
#   - API JSON responses are not rendered, so a CSP there adds no protection.
################################################################################

locals {
  # Cognito Hosted UI origin (Managed Login). Amplify performs the OAuth code
  # exchange and token refresh against this origin, so it must be allowed in
  # connect-src and form-action.
  cognito_hosted_ui_origin = "https://${aws_cognito_user_pool_domain.main.domain}.auth.${var.aws_region}.amazoncognito.com"

  # Content Security Policy for the admin SPA.
  #   script-src 'self'        : Vite emits external module scripts only (no
  #                              inline script). If a dependency needs eval,
  #                              add 'unsafe-eval' here (and document why).
  #   style-src  'unsafe-inline': required by Cloudscape, which injects styles
  #                              and inline style attributes at runtime. Static
  #                              hosting can't use per-response nonces.
  #   connect-src              : same-origin API (via CloudFront) + Cognito
  #                              (Hosted UI token endpoint and cognito-idp).
  content_security_policy = join("; ", [
    "default-src 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "img-src 'self' data:",
    "font-src 'self' data:",
    "style-src 'self' 'unsafe-inline'",
    "script-src 'self'",
    "connect-src 'self' https://cognito-idp.${var.aws_region}.amazonaws.com ${local.cognito_hosted_ui_origin}",
    "form-action 'self' ${local.cognito_hosted_ui_origin}",
    "upgrade-insecure-requests",
  ])
}

resource "aws_cloudfront_response_headers_policy" "spa_security" {
  name    = "${local.name_prefix}-spa-security-headers"
  comment = "CSP + security headers for the admin SPA (S3 behavior only)"

  security_headers_config {
    content_security_policy {
      content_security_policy = local.content_security_policy
      override                = true
    }

    strict_transport_security {
      access_control_max_age_sec = 31536000
      include_subdomains         = true
      preload                    = true
      override                   = true
    }

    content_type_options {
      override = true
    }

    frame_options {
      frame_option = "DENY"
      override     = true
    }

    referrer_policy {
      referrer_policy = "strict-origin-when-cross-origin"
      override        = true
    }

    # X-XSS-Protection: 0 — the legacy auditor is deprecated and can itself
    # introduce vulnerabilities; modern guidance is to disable it and rely on
    # the CSP above.
    xss_protection {
      protection = false
      override   = true
    }
  }

  custom_headers_config {
    items {
      header   = "Permissions-Policy"
      value    = "geolocation=(), microphone=(), camera=(), payment=(), usb=()"
      override = true
    }

    items {
      header   = "Cross-Origin-Opener-Policy"
      value    = "same-origin"
      override = true
    }

    items {
      header   = "Cross-Origin-Resource-Policy"
      value    = "same-origin"
      override = true
    }
  }
}
