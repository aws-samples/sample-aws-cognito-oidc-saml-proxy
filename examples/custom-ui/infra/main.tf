data "aws_caller_identity" "current" {}

locals {
  cognito_region = coalesce(var.cognito_region, var.aws_region)
  bucket_name    = "${var.name_prefix}-${data.aws_caller_identity.current.account_id}"

  apps = var.apps_json != "" ? jsondecode(var.apps_json) : null

  # When any CIDR is provided, an IP-allowlist WAF is created and the
  # distribution is locked to those CIDRs. When none are provided (the default),
  # NO WAF is created and the site is publicly reachable — so customers can
  # deploy and use it out of the box.
  restrict_access = length(var.allowed_cidrs) > 0 || length(var.allowed_ipv6_cidrs) > 0

  # /config.json served to the SPA — same shape the Lambda used to return, now a
  # static object in S3 rendered from these Terraform variables.
  config = merge(
    {
      userPoolId = var.cognito_user_pool_id
      clientId   = var.cognito_client_id
      region     = local.cognito_region
    },
    var.gateway_base_url != "" ? { gatewayBaseUrl = var.gateway_base_url } : {},
    var.gateway_tenant != "" ? { gatewayTenant = var.gateway_tenant } : {},
    local.apps != null ? { apps = local.apps } : {},
  )

  tags = merge({
    Project   = var.name_prefix
    Component = "custom-ui-demo"
    ManagedBy = "terraform"
  }, var.tags)
}

################################################################################
# Private S3 bucket for the SPA (no public access; reached only via CloudFront)
################################################################################

resource "aws_s3_bucket" "frontend" {
  bucket = local.bucket_name
  tags   = local.tags
}

resource "aws_s3_bucket_public_access_block" "frontend" {
  bucket                  = aws_s3_bucket.frontend.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "frontend" {
  bucket = aws_s3_bucket.frontend.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Runtime config rendered from Terraform variables (replaces the Lambda's
# /config.json). The asset sync excludes this key so it is not deleted.
resource "aws_s3_object" "config" {
  bucket        = aws_s3_bucket.frontend.id
  key           = "config.json"
  content       = jsonencode(local.config)
  content_type  = "application/json"
  cache_control = "no-cache"
  etag          = md5(jsonencode(local.config))
  tags          = local.tags
}

resource "aws_s3_bucket_policy" "frontend" {
  bucket = aws_s3_bucket.frontend.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudFrontOAC"
      Effect    = "Allow"
      Principal = { Service = "cloudfront.amazonaws.com" }
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.frontend.arn}/*"
      Condition = {
        StringEquals = { "AWS:SourceArn" = aws_cloudfront_distribution.main.arn }
      }
    }]
  })
}

################################################################################
# WAF (CLOUDFRONT scope) — OPTIONAL IP allowlist. Only created when allowed_cidrs
# / allowed_ipv6_cidrs are set. With none set, the distribution has no WAF and is
# publicly reachable (the default, so customers can use the demo).
################################################################################

resource "aws_wafv2_ip_set" "allow" {
  count              = local.restrict_access ? 1 : 0
  name               = "${var.name_prefix}-allow"
  scope              = "CLOUDFRONT"
  ip_address_version = "IPV4"
  addresses          = var.allowed_cidrs
  tags               = local.tags
}

resource "aws_wafv2_ip_set" "allow_v6" {
  count              = local.restrict_access ? 1 : 0
  name               = "${var.name_prefix}-allow-v6"
  scope              = "CLOUDFRONT"
  ip_address_version = "IPV6"
  addresses          = var.allowed_ipv6_cidrs
  tags               = local.tags
}

resource "aws_wafv2_web_acl" "main" {
  count       = local.restrict_access ? 1 : 0
  name        = "${var.name_prefix}-waf"
  description = "IP-allowlist for the custom-UI demo"
  scope       = "CLOUDFRONT"

  default_action {
    block {}
  }

  rule {
    name     = "allow-listed-ips"
    priority = 0
    action {
      allow {}
    }
    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.allow[0].arn
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name_prefix}-allow"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "allow-listed-ips-v6"
    priority = 1
    action {
      allow {}
    }
    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.allow_v6[0].arn
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name_prefix}-allow-v6"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name_prefix}-waf"
    sampled_requests_enabled   = true
  }

  tags = local.tags
}

################################################################################
# CloudFront + Origin Access Control (private S3 origin)
################################################################################

resource "aws_cloudfront_origin_access_control" "s3" {
  name                              = "${var.name_prefix}-oac"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# Rewrite non-asset paths (no file extension) to /index.html for SPA routing.
resource "aws_cloudfront_function" "spa_rewrite" {
  name    = "${var.name_prefix}-spa-rewrite"
  runtime = "cloudfront-js-2.0"
  publish = true
  code    = <<-JS
    function handler(event) {
      var request = event.request;
      if (!request.uri.includes('.')) {
        request.uri = '/index.html';
      }
      return request;
    }
  JS
}

data "aws_cloudfront_cache_policy" "caching_optimized" {
  name = "Managed-CachingOptimized"
}

data "aws_cloudfront_cache_policy" "caching_disabled" {
  name = "Managed-CachingDisabled"
}

resource "aws_cloudfront_distribution" "main" {
  enabled             = true
  is_ipv6_enabled     = true
  comment             = "Cognito custom-UI demo"
  default_root_object = "index.html"
  price_class         = "PriceClass_100"
  web_acl_id          = local.restrict_access ? aws_wafv2_web_acl.main[0].arn : null

  origin {
    domain_name              = aws_s3_bucket.frontend.bucket_regional_domain_name
    origin_id                = "s3-frontend"
    origin_access_control_id = aws_cloudfront_origin_access_control.s3.id
  }

  # config.json must never be cached so config changes take effect immediately.
  ordered_cache_behavior {
    path_pattern           = "/config.json"
    target_origin_id       = "s3-frontend"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    cache_policy_id        = data.aws_cloudfront_cache_policy.caching_disabled.id
    viewer_protocol_policy = "redirect-to-https"
    compress               = true
  }

  default_cache_behavior {
    target_origin_id       = "s3-frontend"
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]
    cache_policy_id        = data.aws_cloudfront_cache_policy.caching_optimized.id
    viewer_protocol_policy = "redirect-to-https"
    compress               = true

    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.spa_rewrite.arn
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  tags = local.tags
}
