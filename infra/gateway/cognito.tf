################################################################################
# Cognito User Pool
################################################################################

resource "aws_cognito_user_pool" "main" {
  name = local.name_prefix

  # Plus tier: required for Cognito threat protection / advanced security
  # (user_pool_add_ons.advanced_security_mode below). Plus still supports
  # Managed Login v2. Moving ESSENTIALS -> PLUS is an in-place update in
  # Cognito (no pool replacement).
  user_pool_tier = "PLUS"

  # Require MFA for every user, satisfied by a TOTP authenticator app
  # (software token). Applying "ON" to the existing pool challenges current
  # users to enrol a TOTP device on their next sign-in; it is an in-place
  # update and does not replace the pool.
  mfa_configuration = "ON"

  software_token_mfa_configuration {
    enabled = true
  }

  # Threat protection (advanced security). ENFORCED actively blocks risky
  # sign-ins (compromised credentials, impossible-travel, etc.) rather than
  # only auditing them. Requires the Plus tier set above.
  user_pool_add_ons {
    advanced_security_mode = "ENFORCED"
  }

  # Case-insensitive usernames. NOTE: this is immutable in Cognito — it only
  # takes effect at pool creation. Applying it to an EXISTING case-sensitive
  # pool forces a full replacement (destroys all users and changes the pool and
  # app client IDs). It is intended to take effect on the next clean
  # destroy-and-recreate; do NOT `terraform apply` against the current live pool
  # unless you intend that replacement.
  username_configuration {
    case_sensitive = false
  }

  # Email delivery. When ses_from_email_address is set, send via SES (DEVELOPER)
  # using a verified identity as the From address. Otherwise Cognito falls back
  # to COGNITO_DEFAULT, which is rate-limited (~50/day) and testing-only.
  dynamic "email_configuration" {
    for_each = var.ses_from_email_address != "" ? [1] : []
    content {
      email_sending_account = "DEVELOPER"
      from_email_address    = var.ses_from_email_address
      source_arn            = "arn:aws:ses:${var.aws_region}:${data.aws_caller_identity.current.account_id}:identity/${var.ses_from_email_address}"
    }
  }

  # Auto-verified attributes (required for user_attribute_update_settings)
  auto_verified_attributes = ["email"]

  # Prevent self-registration
  admin_create_user_config {
    allow_admin_create_user_only = true
  }

  # Password policy
  password_policy {
    minimum_length                   = 8
    require_lowercase                = true
    require_numbers                  = true
    require_symbols                  = true
    require_uppercase                = true
    temporary_password_validity_days = 7
  }

  # Account recovery
  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

  # Schema attributes
  schema {
    name                     = "email"
    attribute_data_type      = "String"
    required                 = true
    mutable                  = true
    developer_only_attribute = false

    string_attribute_constraints {
      min_length = 1
      max_length = 256
    }
  }

  schema {
    name                     = "tenant_id"
    attribute_data_type      = "String"
    required                 = false
    mutable                  = true
    developer_only_attribute = false

    string_attribute_constraints {
      min_length = 1
      max_length = 256
    }
  }

  # Prevent user existence errors (security best practice)
  user_attribute_update_settings {
    attributes_require_verification_before_update = ["email"]
  }

  deletion_protection = var.environment == "prod" ? "ACTIVE" : "INACTIVE"

  tags = merge(local.tags, {
    Component = "identity"
  })

  lifecycle {
    # case_sensitive (in username_configuration) is immutable in Cognito. The
    # live dev pool was created (2026-06-16) before the username_configuration
    # block was added to this file (commit 9df8e2b, 2026-06-17), so it is
    # case-sensitive. Without this ignore, every plan wants a destructive full
    # replacement of the pool — which deletes all users and rotates the pool and
    # app-client IDs the deployed frontend depends on. A fresh (stateless) deploy
    # still creates the pool with case_sensitive = false as intended. Remove this
    # ignore only during an intentional destroy-and-recreate of the pool.
    ignore_changes = [username_configuration]
  }
}

################################################################################
# Cognito Domain (prefix-based)
################################################################################

resource "aws_cognito_user_pool_domain" "main" {
  domain                = "fed-gw-${var.environment}-${data.aws_caller_identity.current.account_id}"
  user_pool_id          = aws_cognito_user_pool.main.id
  managed_login_version = 2
}

################################################################################
# Managed Login Branding (v2)
################################################################################

# Branding for SPA client
resource "aws_cognito_managed_login_branding" "spa" {
  user_pool_id = aws_cognito_user_pool.main.id
  client_id    = aws_cognito_user_pool_client.spa.id

  use_cognito_provided_values = true
}

# Branding for backend client
resource "aws_cognito_managed_login_branding" "backend" {
  user_pool_id = aws_cognito_user_pool.main.id
  client_id    = aws_cognito_user_pool_client.backend.id

  use_cognito_provided_values = true
}

################################################################################
# Cognito Client — SPA (public, no secret)
################################################################################

resource "aws_cognito_user_pool_client" "spa" {
  name         = "${local.name_prefix}-spa"
  user_pool_id = aws_cognito_user_pool.main.id

  generate_secret = false

  explicit_auth_flows = [
    "ALLOW_REFRESH_TOKEN_AUTH",
    "ALLOW_USER_SRP_AUTH",
  ]

  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid", "email", "profile"]

  callback_urls = compact([
    "http://localhost:3000/callback",
    var.custom_domain != "" ? "https://${var.custom_domain}/callback" : "",
    "https://${aws_cloudfront_distribution.main.domain_name}/callback",
  ])

  logout_urls = compact([
    "http://localhost:3000",
    var.custom_domain != "" ? "https://${var.custom_domain}" : "",
    "https://${aws_cloudfront_distribution.main.domain_name}",
  ])

  supported_identity_providers = ["COGNITO"]

  prevent_user_existence_errors = "ENABLED"

  access_token_validity  = 1
  id_token_validity      = 1
  refresh_token_validity = 30

  token_validity_units {
    access_token  = "hours"
    id_token      = "hours"
    refresh_token = "days"
  }
}

################################################################################
# Cognito Client — Backend (confidential, with secret)
################################################################################

resource "aws_cognito_user_pool_client" "backend" {
  name         = "${local.name_prefix}-backend"
  user_pool_id = aws_cognito_user_pool.main.id

  # No client secret -- the backend uses PKCE (public client flow) for the
  # OAuth2 Authorization Code grant. A client secret is incompatible with PKCE
  # and would require the secret to be embedded in the Lambda/container, which
  # is a security anti-pattern for public-facing flows.
  generate_secret = false

  explicit_auth_flows = [
    "ALLOW_REFRESH_TOKEN_AUTH",
    "ALLOW_USER_SRP_AUTH",
    # Enables server-side admin password auth for tooling/automation (e.g. seeding
    # tenants and apps via the management API). No client secret is involved.
    "ALLOW_ADMIN_USER_PASSWORD_AUTH",
  ]

  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid", "email", "profile"]

  callback_urls = compact([
    "${local.base_url}/auth/callback",
    "${local.base_url}/t/default/saml/acs",
    "${local.base_url}/t/default/oidc/callback",
    "https://${aws_cloudfront_distribution.main.domain_name}/auth/callback",
  ])

  logout_urls = compact([
    "${local.base_url}/auth/logout",
    "https://${aws_cloudfront_distribution.main.domain_name}/auth/logout",
  ])

  supported_identity_providers = ["COGNITO"]

  prevent_user_existence_errors = "ENABLED"

  access_token_validity  = 1
  id_token_validity      = 1
  refresh_token_validity = 30

  token_validity_units {
    access_token  = "hours"
    id_token      = "hours"
    refresh_token = "days"
  }
}

################################################################################
# Cognito Groups
################################################################################

resource "aws_cognito_user_group" "admins" {
  name         = "Admins"
  user_pool_id = aws_cognito_user_pool.main.id
  description  = "Administrator users with full access"
  precedence   = 1
}

resource "aws_cognito_user_group" "operators" {
  name         = "Operators"
  user_pool_id = aws_cognito_user_pool.main.id
  description  = "Operator users with read/write access to SP configurations"
  precedence   = 10
}
