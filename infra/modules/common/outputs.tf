output "name_prefix" {
  description = "Standard resource name prefix: <project>-<environment>[-<name_suffix>]. The suffix is appended only when set, so the default (empty) yields the historical <project>-<environment> unchanged."
  value       = var.name_suffix != "" ? "${var.project}-${var.environment}-${var.name_suffix}" : "${var.project}-${var.environment}"
}

output "tags" {
  description = "Standard tag set applied across all stacks"
  value = merge({
    Environment = var.environment
    Project     = var.project
    ManagedBy   = "terraform"
    Owner       = var.owner
  }, var.additional_tags)
}

output "lambda_functions" {
  description = "Canonical per-capability Lambda function set (name -> spec). Single source for the registry (ECR repos) and gateway (functions) stacks."
  value = {
    saml-sso = {
      description = "SAML SSO and ACS handler"
      memory      = 512
      timeout     = 30
    }
    saml-slo = {
      description = "SAML Single Logout handler"
      memory      = 256
      timeout     = 15
    }
    saml-metadata = {
      description = "SAML metadata endpoint"
      memory      = 256
      timeout     = 10
    }
    oidc-authorize = {
      description = "OIDC authorization and login handler"
      memory      = 512
      timeout     = 30
    }
    oidc-token = {
      description = "OIDC token, introspection, and revocation"
      memory      = 256
      timeout     = 15
    }
    oidc-discovery = {
      description = "OIDC discovery, JWKS, userinfo"
      memory      = 256
      timeout     = 10
    }
    management-api = {
      description = "Management REST API"
      memory      = 512
      timeout     = 30
    }
    health = {
      description = "Health check endpoint"
      memory      = 128
      timeout     = 5
    }
  }
}
