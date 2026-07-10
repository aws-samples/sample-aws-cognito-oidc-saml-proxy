################################################################################
# S3 Bucket for SPA Frontend
################################################################################

module "frontend_s3" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "~> 5.11"

  bucket = "${local.name_prefix}-frontend-${data.aws_caller_identity.current.account_id}"

  # Block all public access
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  # Versioning
  versioning = {
    enabled = true
  }

  # Encryption
  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm = "AES256"
      }
      bucket_key_enabled = true
    }
  }

  tags = merge(local.tags, {
    Component = "frontend"
  })
}

################################################################################
# S3 Bucket Policy for CloudFront OAC Access
################################################################################

resource "aws_s3_bucket_policy" "frontend" {
  bucket = module.frontend_s3.s3_bucket_id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudFrontOAC"
      Effect    = "Allow"
      Principal = { Service = "cloudfront.amazonaws.com" }
      Action    = "s3:GetObject"
      Resource  = "${module.frontend_s3.s3_bucket_arn}/*"
      Condition = {
        StringEquals = {
          "AWS:SourceArn" = aws_cloudfront_distribution.main.arn
        }
      }
    }]
  })
}

################################################################################
# CloudFront Function — SPA Rewrite
# Rewrites requests for non-asset paths to /index.html so the SPA router
# handles client-side routing. Only applies to the default (S3) behavior.
# This replaces global custom_error_response which would also intercept
# API Gateway 404s from the api-gateway origin.
################################################################################

resource "aws_cloudfront_function" "spa_rewrite" {
  name    = "${local.name_prefix}-spa-rewrite"
  runtime = "cloudfront-js-2.0"
  publish = true

  code = <<-JS
    function handler(event) {
      var request = event.request;
      var uri = request.uri;
      // If the URI has a file extension (asset), pass through as-is.
      // Otherwise rewrite to /index.html for SPA routing.
      if (!uri.includes('.')) {
        request.uri = '/index.html';
      }
      return request;
    }
  JS
}

################################################################################
# CloudFront Origin Access Control
################################################################################

resource "aws_cloudfront_origin_access_control" "s3" {
  name                              = "${local.name_prefix}-s3-oac"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# OAC for the private IaC-templates bucket. CloudFront signs origin
# requests with this identity so the rendered CFN templates are readable at the
# edge without the bucket ever being public.
resource "aws_cloudfront_origin_access_control" "iac_templates" {
  name                              = "${local.name_prefix}-iac-templates-oac"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

################################################################################
# CloudFront Origin-Verify Shared Secret
#
# WAFv2 cannot associate a Web ACL with an API Gateway HTTP (v2) API stage, so
# the CloudFront Web ACL is the API's only edge protection. Without a barrier,
# the raw execute-api invoke URL bypasses that WAF entirely. CloudFront injects
# this secret as the X-Origin-Verify header on every api-gateway origin request
# (and overwrites any viewer-supplied copy), and the application rejects any
# request lacking it (middleware.RequireEdgeSecret). Traffic that skips
# CloudFront therefore cannot forge the header and is refused with 403.
################################################################################

resource "random_password" "edge_secret" {
  length = 48
  # Header value must be a clean token: letters and digits only, no special
  # characters that could complicate HTTP header transport or comparison.
  special = false
}

################################################################################
# CloudFront Managed Cache Policies (Data Sources)
################################################################################

data "aws_cloudfront_cache_policy" "caching_optimized" {
  name = "Managed-CachingOptimized"
}

data "aws_cloudfront_cache_policy" "caching_disabled" {
  name = "Managed-CachingDisabled"
}

################################################################################
# CloudFront Managed Origin Request Policies (Data Sources)
################################################################################

data "aws_cloudfront_origin_request_policy" "all_viewer" {
  name = "Managed-AllViewer"
}

data "aws_cloudfront_origin_request_policy" "all_viewer_except_host_header" {
  name = "Managed-AllViewerExceptHostHeader"
}

################################################################################
# CloudFront Custom Cache Policy for OpenAPI
################################################################################

resource "aws_cloudfront_cache_policy" "openapi" {
  name        = "${local.name_prefix}-openapi-5min"
  comment     = "Custom 5-minute cache policy for OpenAPI spec"
  min_ttl     = 0
  default_ttl = 300
  max_ttl     = 300

  parameters_in_cache_key_and_forwarded_to_origin {
    cookies_config {
      cookie_behavior = "none"
    }

    headers_config {
      header_behavior = "none"
    }

    query_strings_config {
      query_string_behavior = "none"
    }

    enable_accept_encoding_gzip   = true
    enable_accept_encoding_brotli = true
  }
}

################################################################################
# CloudFront Distribution
################################################################################

resource "aws_cloudfront_distribution" "main" {
  enabled             = true
  is_ipv6_enabled     = true
  comment             = "Cognito OIDC to SAML proxy - SPA + API"
  default_root_object = "index.html"
  price_class         = "PriceClass_100"
  web_acl_id          = aws_wafv2_web_acl.main.arn
  aliases             = var.custom_domain != "" ? [var.custom_domain] : []

  # Origin 1: S3 bucket for SPA
  origin {
    domain_name              = module.frontend_s3.s3_bucket_bucket_regional_domain_name
    origin_id                = "s3-frontend"
    origin_access_control_id = aws_cloudfront_origin_access_control.s3.id
  }

  # Origin 2: API Gateway
  origin {
    domain_name = replace(replace(aws_apigatewayv2_stage.default.invoke_url, "https://", ""), "/", "")
    origin_id   = "api-gateway"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }

    # Origin-verify shared secret. CloudFront adds this header on every
    # origin request and overwrites any value a viewer supplied, so only traffic
    # that transited CloudFront (and its WAF) carries it. The app fails closed on
    # any request missing it, closing the raw execute-api bypass.
    custom_header {
      name  = "X-Origin-Verify"
      value = random_password.edge_secret.result
    }
  }

  # Origin 3: private IaC-templates bucket, served anonymously via OAC.
  # The bucket has Block Public Access on and no public policy; CloudFront reads
  # it through aws_cloudfront_origin_access_control.iac_templates so CFN
  # quick-create can fetch rendered templates over HTTPS without the bucket
  # being public.
  origin {
    domain_name              = module.iac_templates_bucket.s3_bucket_bucket_regional_domain_name
    origin_id                = "s3-iac-templates"
    origin_access_control_id = aws_cloudfront_origin_access_control.iac_templates.id
  }

  # Cache Behavior 1: /t/*/saml/* → API Gateway
  ordered_cache_behavior {
    path_pattern     = "/t/*/saml/*"
    target_origin_id = "api-gateway"
    allowed_methods  = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods   = ["GET", "HEAD"]

    cache_policy_id          = data.aws_cloudfront_cache_policy.caching_disabled.id
    origin_request_policy_id = data.aws_cloudfront_origin_request_policy.all_viewer_except_host_header.id
    viewer_protocol_policy   = "redirect-to-https"
    compress                 = true
  }

  # Cache Behavior 1b: /t/*/oidc/* → API Gateway
  ordered_cache_behavior {
    path_pattern     = "/t/*/oidc/*"
    target_origin_id = "api-gateway"
    allowed_methods  = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods   = ["GET", "HEAD"]

    cache_policy_id          = data.aws_cloudfront_cache_policy.caching_disabled.id
    origin_request_policy_id = data.aws_cloudfront_origin_request_policy.all_viewer_except_host_header.id
    viewer_protocol_policy   = "redirect-to-https"
    compress                 = true
  }

  # Cache Behavior 1c: /t/*/.well-known/* → API Gateway
  ordered_cache_behavior {
    path_pattern     = "/t/*/.well-known/*"
    target_origin_id = "api-gateway"
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]

    cache_policy_id          = data.aws_cloudfront_cache_policy.caching_disabled.id
    origin_request_policy_id = data.aws_cloudfront_origin_request_policy.all_viewer_except_host_header.id
    viewer_protocol_policy   = "redirect-to-https"
    compress                 = true
  }

  # Cache Behavior 1d: /login → API Gateway (OIDC login redirect)
  ordered_cache_behavior {
    path_pattern     = "/login"
    target_origin_id = "api-gateway"
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]

    cache_policy_id          = data.aws_cloudfront_cache_policy.caching_disabled.id
    origin_request_policy_id = data.aws_cloudfront_origin_request_policy.all_viewer_except_host_header.id
    viewer_protocol_policy   = "redirect-to-https"
    compress                 = true
  }

  # Cache Behavior 2: /api/v1/* → API Gateway
  ordered_cache_behavior {
    path_pattern     = "/api/v1/*"
    target_origin_id = "api-gateway"
    allowed_methods  = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods   = ["GET", "HEAD"]

    cache_policy_id          = data.aws_cloudfront_cache_policy.caching_disabled.id
    origin_request_policy_id = data.aws_cloudfront_origin_request_policy.all_viewer_except_host_header.id
    viewer_protocol_policy   = "redirect-to-https"
    compress                 = true
  }

  # Cache Behavior 3: /openapi.json → API Gateway with 5min cache
  ordered_cache_behavior {
    path_pattern     = "/openapi.json"
    target_origin_id = "api-gateway"
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]

    cache_policy_id          = aws_cloudfront_cache_policy.openapi.id
    origin_request_policy_id = data.aws_cloudfront_origin_request_policy.all_viewer_except_host_header.id
    viewer_protocol_policy   = "redirect-to-https"
    compress                 = true
  }

  # Cache Behavior 4: /health → API Gateway
  ordered_cache_behavior {
    path_pattern     = "/health"
    target_origin_id = "api-gateway"
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]

    cache_policy_id          = data.aws_cloudfront_cache_policy.caching_disabled.id
    origin_request_policy_id = data.aws_cloudfront_origin_request_policy.all_viewer_except_host_header.id
    viewer_protocol_policy   = "redirect-to-https"
    compress                 = true
  }

  # Cache Behavior 5: /templates/* → private IaC-templates bucket via OAC.
  # Anonymous read is provided at the edge; the bucket stays private. GET/HEAD
  # only — CFN quick-create fetches the rendered template server-side.
  ordered_cache_behavior {
    path_pattern     = "/templates/*"
    target_origin_id = "s3-iac-templates"
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]

    cache_policy_id        = data.aws_cloudfront_cache_policy.caching_optimized.id
    viewer_protocol_policy = "redirect-to-https"
    compress               = true
  }

  # Default Cache Behavior: * → S3 (SPA)
  # Uses a CloudFront Function to rewrite 404s to /index.html for SPA routing
  # (global custom_error_response would also intercept API Gateway 404s)
  default_cache_behavior {
    target_origin_id           = "s3-frontend"
    allowed_methods            = ["GET", "HEAD", "OPTIONS"]
    cached_methods             = ["GET", "HEAD"]
    cache_policy_id            = data.aws_cloudfront_cache_policy.caching_optimized.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.spa_security.id
    viewer_protocol_policy     = "redirect-to-https"
    compress                   = true

    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.spa_rewrite.arn
    }
  }

  # Viewer Certificate
  dynamic "viewer_certificate" {
    for_each = var.custom_domain != "" ? [1] : []
    content {
      acm_certificate_arn      = aws_acm_certificate_validation.wildcard[0].certificate_arn
      ssl_support_method       = "sni-only"
      minimum_protocol_version = "TLSv1.2_2021"
    }
  }

  dynamic "viewer_certificate" {
    for_each = var.custom_domain != "" ? [] : [1]
    content {
      cloudfront_default_certificate = true
      minimum_protocol_version       = "TLSv1.2_2021"
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  tags = merge(local.tags, {
    Component = "cloudfront"
  })
}
