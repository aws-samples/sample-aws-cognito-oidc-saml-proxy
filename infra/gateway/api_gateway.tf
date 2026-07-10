################################################################################
# HTTP API Gateway
################################################################################

resource "aws_apigatewayv2_api" "main" {
  name          = "${local.name_prefix}-api"
  protocol_type = "HTTP"

  cors_configuration {
    # x-tenant-id lets the console's tenant switcher configure a tenant other
    # than the one in the caller's token (see middleware.TenantFromJWTForAPI).
    allow_headers = ["content-type", "authorization", "x-amz-date", "x-api-key", "x-tenant-id"]
    allow_methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    allow_origins = compact([
      "http://localhost:3000",
      var.custom_domain != "" ? "https://${var.custom_domain}" : "",
    ])
    max_age = 3600
  }

  tags = merge(local.tags, {
    Component = "api"
  })
}

resource "aws_cloudwatch_log_group" "api_access_logs" {
  name              = "/aws/apigatewayv2/${local.name_prefix}"
  retention_in_days = 365
  kms_key_id        = module.kms_encryption.key_arn

  tags = merge(local.tags, {
    Component = "api"
  })
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.main.id
  name        = "$default"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_access_logs.arn
    format = jsonencode({
      requestId        = "$context.requestId"
      sourceIp         = "$context.identity.sourceIp"
      requestTime      = "$context.requestTime"
      httpMethod       = "$context.httpMethod"
      routeKey         = "$context.routeKey"
      status           = "$context.status"
      protocol         = "$context.protocol"
      responseLength   = "$context.responseLength"
      errorMessage     = "$context.error.message"
      integrationError = "$context.integrationErrorMessage"
    })
  }

  tags = merge(local.tags, {
    Component = "api"
  })
}

################################################################################
# JWT Authorizer (Cognito)
################################################################################

resource "aws_apigatewayv2_authorizer" "cognito" {
  api_id           = aws_apigatewayv2_api.main.id
  authorizer_type  = "JWT"
  name             = "cognito-jwt"
  identity_sources = ["$request.header.Authorization"]

  jwt_configuration {
    audience = [aws_cognito_user_pool_client.spa.id, aws_cognito_user_pool_client.backend.id]
    issuer   = "https://${aws_cognito_user_pool.main.endpoint}"
  }
}

################################################################################
# Routes: SAML SSO (saml-sso Lambda)
################################################################################

resource "aws_apigatewayv2_route" "saml_sso_get" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "GET /t/{tenant}/saml/sso"
  target             = "integrations/${aws_apigatewayv2_integration.saml_sso_v2.id}"
  authorization_type = "NONE"
}

resource "aws_apigatewayv2_route" "saml_sso_post" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "POST /t/{tenant}/saml/sso"
  target             = "integrations/${aws_apigatewayv2_integration.saml_sso_v2.id}"
  authorization_type = "NONE"
}

resource "aws_apigatewayv2_route" "saml_acs" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "POST /t/{tenant}/saml/acs"
  target             = "integrations/${aws_apigatewayv2_integration.saml_sso_v2.id}"
  authorization_type = "NONE"
}

# Cognito callback also goes to saml-sso (OAuth2 redirect after auth)
resource "aws_apigatewayv2_route" "saml_acs_get" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "GET /t/{tenant}/saml/acs"
  target             = "integrations/${aws_apigatewayv2_integration.saml_sso_v2.id}"
  authorization_type = "NONE"
}

# Custom login page session-establish endpoint (custom login flow)
resource "aws_apigatewayv2_route" "saml_login_complete" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "POST /t/{tenant}/saml/login/complete"
  target             = "integrations/${aws_apigatewayv2_integration.saml_sso_v2.id}"
  authorization_type = "NONE"
}

# IdP-initiated SSO endpoint (app launcher)
resource "aws_apigatewayv2_route" "saml_idp_initiate" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "POST /t/{tenant}/saml/idp-initiate"
  target             = "integrations/${aws_apigatewayv2_integration.saml_sso_v2.id}"
  authorization_type = "NONE"
}

################################################################################
# Routes: SAML SLO (saml-slo Lambda)
################################################################################

resource "aws_apigatewayv2_route" "saml_slo" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "GET /t/{tenant}/saml/slo"
  target             = "integrations/${aws_apigatewayv2_integration.saml_slo_v2.id}"
  authorization_type = "NONE"
}

################################################################################
# Routes: SAML Metadata (saml-metadata Lambda)
################################################################################

resource "aws_apigatewayv2_route" "saml_metadata" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "GET /t/{tenant}/saml/metadata"
  target             = "integrations/${aws_apigatewayv2_integration.saml_metadata_v2.id}"
  authorization_type = "NONE"
}

resource "aws_apigatewayv2_route" "saml_metadata_app" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "GET /t/{tenant}/saml/metadata/{appId}"
  target             = "integrations/${aws_apigatewayv2_integration.saml_metadata_v2.id}"
  authorization_type = "NONE"
}

################################################################################
# Routes: OIDC Authorize (oidc-authorize Lambda)
################################################################################

resource "aws_apigatewayv2_route" "oidc_authorize" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "GET /t/{tenant}/oidc/authorize"
  target             = "integrations/${aws_apigatewayv2_integration.oidc_authorize_v2.id}"
  authorization_type = "NONE"
}

resource "aws_apigatewayv2_route" "oidc_login" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "GET /t/{tenant}/oidc/login"
  target             = "integrations/${aws_apigatewayv2_integration.oidc_authorize_v2.id}"
  authorization_type = "NONE"
}

resource "aws_apigatewayv2_route" "oidc_callback" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "GET /t/{tenant}/oidc/callback"
  target             = "integrations/${aws_apigatewayv2_integration.oidc_authorize_v2.id}"
  authorization_type = "NONE"
}

# Custom login page session-establish endpoint (custom login flow)
resource "aws_apigatewayv2_route" "oidc_login_complete" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "POST /t/{tenant}/oidc/login/complete"
  target             = "integrations/${aws_apigatewayv2_integration.oidc_authorize_v2.id}"
  authorization_type = "NONE"
}

resource "aws_apigatewayv2_route" "oidc_authorize_callback" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "GET /t/{tenant}/oidc/authorize/callback"
  target             = "integrations/${aws_apigatewayv2_integration.oidc_authorize_v2.id}"
  authorization_type = "NONE"
}

resource "aws_apigatewayv2_route" "login" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "GET /login"
  target             = "integrations/${aws_apigatewayv2_integration.oidc_authorize_v2.id}"
  authorization_type = "NONE"
}

################################################################################
# Routes: OIDC Token (oidc-token Lambda)
################################################################################

resource "aws_apigatewayv2_route" "oidc_token" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "POST /t/{tenant}/oidc/oauth/token"
  target             = "integrations/${aws_apigatewayv2_integration.oidc_token_v2.id}"
  authorization_type = "NONE"
}

resource "aws_apigatewayv2_route" "oidc_introspect" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "POST /t/{tenant}/oidc/oauth/introspect"
  target             = "integrations/${aws_apigatewayv2_integration.oidc_token_v2.id}"
  authorization_type = "NONE"
}

resource "aws_apigatewayv2_route" "oidc_revoke" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "POST /t/{tenant}/oidc/revoke"
  target             = "integrations/${aws_apigatewayv2_integration.oidc_token_v2.id}"
  authorization_type = "NONE"
}

################################################################################
# Routes: OIDC Discovery (oidc-discovery Lambda)
################################################################################

resource "aws_apigatewayv2_route" "well_known" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "GET /t/{tenant}/oidc/.well-known/{proxy+}"
  target             = "integrations/${aws_apigatewayv2_integration.oidc_discovery_v2.id}"
  authorization_type = "NONE"
}

resource "aws_apigatewayv2_route" "oidc_keys" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "GET /t/{tenant}/oidc/keys"
  target             = "integrations/${aws_apigatewayv2_integration.oidc_discovery_v2.id}"
  authorization_type = "NONE"
}

resource "aws_apigatewayv2_route" "oidc_userinfo" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "GET /t/{tenant}/oidc/userinfo"
  target             = "integrations/${aws_apigatewayv2_integration.oidc_discovery_v2.id}"
  authorization_type = "NONE"
}

resource "aws_apigatewayv2_route" "oidc_end_session" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "GET /t/{tenant}/oidc/end_session"
  target             = "integrations/${aws_apigatewayv2_integration.oidc_discovery_v2.id}"
  authorization_type = "NONE"
}

################################################################################
# Routes: Health (health Lambda)
################################################################################

resource "aws_apigatewayv2_route" "health" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "GET /health"
  target             = "integrations/${aws_apigatewayv2_integration.health_v2.id}"
  authorization_type = "NONE"
}

resource "aws_apigatewayv2_route" "openapi" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "GET /openapi.json"
  target             = "integrations/${aws_apigatewayv2_integration.health_v2.id}"
  authorization_type = "NONE"
}

################################################################################
# Routes: Management API (management-api Lambda, JWT authorized)
################################################################################

resource "aws_apigatewayv2_route" "api" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "ANY /api/v1/{proxy+}"
  target             = "integrations/${aws_apigatewayv2_integration.management_api_v2.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.cognito.id
}

################################################################################
# Per-Capability Lambda Integrations
################################################################################

resource "aws_apigatewayv2_integration" "saml_sso_v2" {
  api_id                 = aws_apigatewayv2_api.main.id
  integration_type       = "AWS_PROXY"
  integration_uri        = module.lambda_fn["saml-sso"].lambda_function_invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_integration" "saml_slo_v2" {
  api_id                 = aws_apigatewayv2_api.main.id
  integration_type       = "AWS_PROXY"
  integration_uri        = module.lambda_fn["saml-slo"].lambda_function_invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_integration" "saml_metadata_v2" {
  api_id                 = aws_apigatewayv2_api.main.id
  integration_type       = "AWS_PROXY"
  integration_uri        = module.lambda_fn["saml-metadata"].lambda_function_invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_integration" "oidc_authorize_v2" {
  api_id                 = aws_apigatewayv2_api.main.id
  integration_type       = "AWS_PROXY"
  integration_uri        = module.lambda_fn["oidc-authorize"].lambda_function_invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_integration" "oidc_token_v2" {
  api_id                 = aws_apigatewayv2_api.main.id
  integration_type       = "AWS_PROXY"
  integration_uri        = module.lambda_fn["oidc-token"].lambda_function_invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_integration" "oidc_discovery_v2" {
  api_id                 = aws_apigatewayv2_api.main.id
  integration_type       = "AWS_PROXY"
  integration_uri        = module.lambda_fn["oidc-discovery"].lambda_function_invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_integration" "management_api_v2" {
  api_id                 = aws_apigatewayv2_api.main.id
  integration_type       = "AWS_PROXY"
  integration_uri        = module.lambda_fn["management-api"].lambda_function_invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_integration" "health_v2" {
  api_id                 = aws_apigatewayv2_api.main.id
  integration_type       = "AWS_PROXY"
  integration_uri        = module.lambda_fn["health"].lambda_function_invoke_arn
  payload_format_version = "2.0"
}
