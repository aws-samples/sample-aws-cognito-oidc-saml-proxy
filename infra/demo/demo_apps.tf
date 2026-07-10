################################################################################
# Demo Apps — SAML SP & OIDC RP
# Deployed as Lambda functions behind CloudFront for live SSO demos.
################################################################################

locals {
  # Custom subdomains — non-empty only when a DNS zone is configured. These gate
  # the CloudFront aliases, the ACM viewer certificate, and the Route53 records.
  demo_gateway_domain = var.dns_zone_name != "" ? "gateway.${var.demo_subdomain_prefix}.${var.dns_zone_name}" : ""
  demo_saml_domain    = var.dns_zone_name != "" ? "saml.${var.demo_subdomain_prefix}.${var.dns_zone_name}" : ""
  demo_oidc_domain    = var.dns_zone_name != "" ? "oidc.${var.demo_subdomain_prefix}.${var.dns_zone_name}" : ""

  # Advertised absolute URLs / hosts the demo apps embed in their SAML and OIDC
  # config. With a DNS zone they use the custom subdomains above; without one
  # (sandbox / E2E validation) they fall back to the generated CloudFront domains
  # so the apps still have working absolute URLs. The gateway URL falls back to
  # data.terraform_remote_state.gateway.outputs.base_url, which is the main
  # distribution's CloudFront domain — the same value the gateway Lambdas
  # advertise as PROXY_BASE_URL.
  demo_saml_host   = local.demo_saml_domain != "" ? local.demo_saml_domain : aws_cloudfront_distribution.demo_saml.domain_name
  demo_oidc_host   = local.demo_oidc_domain != "" ? local.demo_oidc_domain : aws_cloudfront_distribution.demo_oidc.domain_name
  demo_saml_url    = "https://${local.demo_saml_host}"
  demo_oidc_url    = "https://${local.demo_oidc_host}"
  demo_gateway_url = local.demo_gateway_domain != "" ? "https://${local.demo_gateway_domain}" : data.terraform_remote_state.gateway.outputs.base_url
}

################################################################################
# Lambda — Demo SAML SP
################################################################################

module "lambda_demo_saml" {
  source  = "terraform-aws-modules/lambda/aws"
  version = "~> 8.7"

  function_name  = "${local.name_prefix}-demo-saml-sp"
  description    = "Demo SAML Service Provider"
  package_type   = "Image"
  architectures  = ["arm64"]
  image_uri      = "${data.terraform_remote_state.registry.outputs.ecr_demo_saml_url}:latest"
  create_package = false
  memory_size    = 256
  timeout        = 15

  environment_variables = {
    SP_PORT = "8081"
    # Use the fallback-aware locals (custom subdomain when a DNS zone is set,
    # otherwise the generated CloudFront domain). The bare *_domain locals are
    # EMPTY without a DNS zone, which would yield "https://" / "https:///t/..."
    # — test-sp reads IDP_METADATA_URL at init and log.Fatalf's if the fetch
    # fails, so it would crash-loop on the malformed URL. demo_saml_url embeds
    # this app's own CloudFront domain (no Terraform cycle: the demo CloudFront
    # origin points at the API Gateway *stage*, which never references the Lambda).
    SP_ENTITY_ID     = local.demo_saml_url
    SP_ACS_URL       = "${local.demo_saml_url}/saml/acs"
    IDP_METADATA_URL = "${local.demo_gateway_url}/t/default/saml/metadata"
  }

  tags = { Component = "demo-saml-sp" }
}

resource "aws_lambda_permission" "demo_saml_apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_demo_saml.lambda_function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.demo_saml.execution_arn}/*/*"
}

################################################################################
# Lambda — Demo OIDC RP
################################################################################

module "lambda_demo_oidc" {
  source  = "terraform-aws-modules/lambda/aws"
  version = "~> 8.7"

  function_name  = "${local.name_prefix}-demo-oidc-rp"
  description    = "Demo OIDC Relying Party"
  package_type   = "Image"
  architectures  = ["arm64"]
  image_uri      = "${data.terraform_remote_state.registry.outputs.ecr_demo_oidc_url}:latest"
  create_package = false
  memory_size    = 256
  timeout        = 15

  environment_variables = {
    RP_PORT = "8082"
    # Fallback-aware host/URLs (custom subdomain with a DNS zone, else the
    # generated CloudFront domain). The bare *_domain locals are EMPTY without a
    # DNS zone: RP_DOMAIN drives the OIDC callback URL (https://${RP_DOMAIN}/callback),
    # so an empty value yields "https:///callback" and breaks the auth-code round
    # trip. demo_oidc_host is this app's own CloudFront domain (no Terraform cycle:
    # the demo CloudFront origin points at the API Gateway *stage*, not the Lambda).
    RP_DOMAIN = local.demo_oidc_host
    # Placeholder client id. The gateway generates the real OIDC client id
    # server-side at application registration (a random hex id — see
    # internal/store/store.go generateID + internal/api/integration_handlers.go),
    # so it cannot be known at apply time. After registering the demo OIDC app,
    # the operator patches this Lambda's RP_CLIENT_ID to the generated id
    # (post-install step). A `terraform apply` here reverts it to this placeholder
    # and the RP must be re-patched. Binding the demo RP to its real client id is
    # inherently a post-registration action.
    RP_CLIENT_ID = "demo-oidc-069680"
    GATEWAY_URL  = local.demo_gateway_url
    TENANT_SLUG  = "default"
  }

  tags = { Component = "demo-oidc-rp" }
}

resource "aws_lambda_permission" "demo_oidc_apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_demo_oidc.lambda_function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.demo_oidc.execution_arn}/*/*"
}

################################################################################
# API Gateway — Demo SAML SP
################################################################################

resource "aws_apigatewayv2_api" "demo_saml" {
  name          = "${local.name_prefix}-demo-saml-sp"
  protocol_type = "HTTP"
  tags          = merge(local.tags, { Component = "demo-saml-sp" })
}

resource "aws_apigatewayv2_stage" "demo_saml" {
  api_id      = aws_apigatewayv2_api.demo_saml.id
  name        = "$default"
  auto_deploy = true
}

resource "aws_apigatewayv2_integration" "demo_saml" {
  api_id                 = aws_apigatewayv2_api.demo_saml.id
  integration_type       = "AWS_PROXY"
  integration_uri        = module.lambda_demo_saml.lambda_function_invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "demo_saml" {
  api_id    = aws_apigatewayv2_api.demo_saml.id
  route_key = "$default"
  target    = "integrations/${aws_apigatewayv2_integration.demo_saml.id}"
}

################################################################################
# API Gateway — Demo OIDC RP
################################################################################

resource "aws_apigatewayv2_api" "demo_oidc" {
  name          = "${local.name_prefix}-demo-oidc-rp"
  protocol_type = "HTTP"
  tags          = merge(local.tags, { Component = "demo-oidc-rp" })
}

resource "aws_apigatewayv2_stage" "demo_oidc" {
  api_id      = aws_apigatewayv2_api.demo_oidc.id
  name        = "$default"
  auto_deploy = true
}

resource "aws_apigatewayv2_integration" "demo_oidc" {
  api_id                 = aws_apigatewayv2_api.demo_oidc.id
  integration_type       = "AWS_PROXY"
  integration_uri        = module.lambda_demo_oidc.lambda_function_invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "demo_oidc" {
  api_id    = aws_apigatewayv2_api.demo_oidc.id
  route_key = "$default"
  target    = "integrations/${aws_apigatewayv2_integration.demo_oidc.id}"
}

################################################################################
# CloudFront — Demo SAML SP
################################################################################

resource "aws_cloudfront_distribution" "demo_saml" {
  enabled         = true
  is_ipv6_enabled = true
  comment         = "Demo SAML SP - ${local.name_prefix}"
  price_class     = "PriceClass_100"
  # Custom alias only when a DNS zone (and therefore the wildcard ACM cert) is
  # configured; otherwise use the generated CloudFront domain with its default
  # certificate.
  aliases = local.demo_saml_domain != "" ? [local.demo_saml_domain] : []

  origin {
    domain_name = replace(replace(aws_apigatewayv2_stage.demo_saml.invoke_url, "https://", ""), "/", "")
    origin_id   = "api-gateway"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    target_origin_id         = "api-gateway"
    allowed_methods          = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods           = ["GET", "HEAD"]
    cache_policy_id          = data.aws_cloudfront_cache_policy.caching_disabled.id
    origin_request_policy_id = data.aws_cloudfront_origin_request_policy.all_viewer_except_host_header.id
    viewer_protocol_policy   = "redirect-to-https"
    compress                 = true
  }

  dynamic "viewer_certificate" {
    for_each = local.demo_saml_domain != "" ? [1] : []
    content {
      acm_certificate_arn      = data.terraform_remote_state.gateway.outputs.wildcard_cert_arn
      ssl_support_method       = "sni-only"
      minimum_protocol_version = "TLSv1.2_2021"
    }
  }

  dynamic "viewer_certificate" {
    for_each = local.demo_saml_domain != "" ? [] : [1]
    content {
      cloudfront_default_certificate = true
      minimum_protocol_version       = "TLSv1.2_2021"
    }
  }

  restrictions {
    geo_restriction { restriction_type = "none" }
  }

  tags = merge(local.tags, { Component = "demo-saml-sp" })
}

################################################################################
# CloudFront — Demo OIDC RP
################################################################################

resource "aws_cloudfront_distribution" "demo_oidc" {
  enabled         = true
  is_ipv6_enabled = true
  comment         = "Demo OIDC RP - ${local.name_prefix}"
  price_class     = "PriceClass_100"
  # Custom alias only when a DNS zone (and therefore the wildcard ACM cert) is
  # configured; otherwise use the generated CloudFront domain with its default
  # certificate.
  aliases = local.demo_oidc_domain != "" ? [local.demo_oidc_domain] : []

  origin {
    domain_name = replace(replace(aws_apigatewayv2_stage.demo_oidc.invoke_url, "https://", ""), "/", "")
    origin_id   = "api-gateway"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    target_origin_id         = "api-gateway"
    allowed_methods          = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods           = ["GET", "HEAD"]
    cache_policy_id          = data.aws_cloudfront_cache_policy.caching_disabled.id
    origin_request_policy_id = data.aws_cloudfront_origin_request_policy.all_viewer_except_host_header.id
    viewer_protocol_policy   = "redirect-to-https"
    compress                 = true
  }

  dynamic "viewer_certificate" {
    for_each = local.demo_oidc_domain != "" ? [1] : []
    content {
      acm_certificate_arn      = data.terraform_remote_state.gateway.outputs.wildcard_cert_arn
      ssl_support_method       = "sni-only"
      minimum_protocol_version = "TLSv1.2_2021"
    }
  }

  dynamic "viewer_certificate" {
    for_each = local.demo_oidc_domain != "" ? [] : [1]
    content {
      cloudfront_default_certificate = true
      minimum_protocol_version       = "TLSv1.2_2021"
    }
  }

  restrictions {
    geo_restriction { restriction_type = "none" }
  }

  tags = merge(local.tags, { Component = "demo-oidc-rp" })
}
