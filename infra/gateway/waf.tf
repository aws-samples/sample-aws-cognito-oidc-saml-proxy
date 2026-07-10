################################################################################
# WAFv2 Web ACL for CloudFront
################################################################################

resource "aws_wafv2_web_acl" "main" {
  provider = aws.us_east_1

  name        = "${local.name_prefix}-cloudfront"
  description = "WAF rules for CloudFront distribution with OWASP Top 10 and rate limiting"
  scope       = "CLOUDFRONT"

  default_action {
    allow {}
  }

  # Rule 1: AWS Managed Rules - Common Rule Set (OWASP Top 10)
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesCommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  # Rule 2: AWS Managed Rules - Known Bad Inputs
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesKnownBadInputsRuleSet"
      sampled_requests_enabled   = true
    }
  }

  # Rule 3: AWS Managed Rules - IP Reputation List
  rule {
    name     = "AWSManagedRulesAmazonIpReputationList"
    priority = 3

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAmazonIpReputationList"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesAmazonIpReputationList"
      sampled_requests_enabled   = true
    }
  }

  # Rule 4: Rate Limit for SAML SSO endpoints
  rule {
    name     = "RateLimitSAMLSSO"
    priority = 4

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 100
        aggregate_key_type = "IP"

        scope_down_statement {
          byte_match_statement {
            search_string         = "/saml/sso"
            positional_constraint = "CONTAINS"

            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitSAMLSSO"
      sampled_requests_enabled   = true
    }
  }

  # Rule 5: Rate limit Management API
  rule {
    name     = "RateLimitManagementAPI"
    priority = 5

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 200
        aggregate_key_type = "IP"

        scope_down_statement {
          byte_match_statement {
            search_string         = "/api/v1/"
            positional_constraint = "STARTS_WITH"

            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority = 0
              type     = "NONE"
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitManagementAPI"
      sampled_requests_enabled   = true
    }
  }

  # Rule 6: Body size limit on SAML POST (64KB max)
  rule {
    name     = "SAMLBodySizeLimit"
    priority = 6

    action {
      block {}
    }

    statement {
      size_constraint_statement {
        comparison_operator = "GT"
        size                = 65536

        field_to_match {
          body {
            oversize_handling = "MATCH"
          }
        }

        text_transformation {
          priority = 0
          type     = "NONE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "SAMLBodySizeLimit"
      sampled_requests_enabled   = true
    }
  }

  # Rule 7: Global Rate Limit
  rule {
    name     = "GlobalRateLimit"
    priority = 7

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "GlobalRateLimit"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.name_prefix}-cloudfront-waf"
    sampled_requests_enabled   = true
  }

  tags = local.tags
}

################################################################################
# WAFv2 Logging — CloudFront Web ACL
#
# WAF logging destinations must live in the same region as the web ACL, so the
# CLOUDFRONT ACL logs to a us-east-1 CloudWatch Logs group. The log group name
# must be prefixed "aws-waf-logs-" (a hard WAF requirement). Authorization and
# Cookie headers are redacted so credentials/session tokens never land in logs.
################################################################################

resource "aws_cloudwatch_log_group" "waf_cloudfront" {
  # checkov:skip=CKV_AWS_158: This group uses provider=aws.us_east_1 (required by
  # CloudFront WAF). The gateway KMS key lives in eu-north-1 and cannot be used
  # cross-region; encrypting this group would require a dedicated us-east-1 CMK,
  # which is deferred to a future hardening pass (tracking issue: add CMK replica).
  provider = aws.us_east_1

  name              = "aws-waf-logs-${local.name_prefix}-cloudfront"
  retention_in_days = 365

  tags = merge(local.tags, {
    Component = "waf-logging"
  })
}

resource "aws_wafv2_web_acl_logging_configuration" "cloudfront" {
  provider = aws.us_east_1

  resource_arn            = aws_wafv2_web_acl.main.arn
  log_destination_configs = [trimsuffix(aws_cloudwatch_log_group.waf_cloudfront.arn, ":*")]

  redacted_fields {
    single_header {
      name = "authorization"
    }
  }

  redacted_fields {
    single_header {
      name = "cookie"
    }
  }
}

################################################################################
# WAFv2 Web ACL for the regional HTTP API
#
# This REGIONAL ACL mirrors the CloudFront ACL's managed rule groups and rate
# limits, including the per-tenant /t/ rate rule. It is the WAF policy the API
# should carry on its own regional edge.
#
# It is intentionally NOT associated with the HTTP API here: WAFv2
# AssociateWebACL supports ALB, API Gateway REST (v1) stages, AppSync, Cognito
# user pools, App Runner, and Verified Access — it does NOT support API Gateway
# HTTP (v2) stages, so an association targeting aws_apigatewayv2_stage.default
# fails at apply.
#
# The execute-api bypass this ACL would otherwise cover is closed at the
# application layer instead: CloudFront injects an origin-verify shared secret
# (frontend.tf random_password.edge_secret → the api-gateway origin custom_header)
# and every request-handling Lambda rejects any request missing it
# (middleware.RequireEdgeSecret). A caller hitting the raw execute-api URL skips
# CloudFront, cannot forge the secret, and gets a 403 — so only WAF-inspected,
# CloudFront-transited traffic reaches the API. The CloudFront ACL
# (frontend.tf web_acl_id) does the actual rule-group/rate-limit inspection.
#
# This regional ACL is kept ready to bind the moment the API sits behind a
# WAF-associable resource, at which point the origin-verify gate can be retired
# in favour of native regional WAF. Two supported migration paths:
#   1. Put the API behind a regional ALB (or migrate to a REST API) and
#      associate this ACL with that resource.
#   2. Add a custom domain + API mapping, point CloudFront's origin at the
#      custom domain (not the raw execute-api URL), then set
#      disable_execute_api_endpoint = true so the only ingress is CloudFront.
# Until one of those lands, do not add aws_wafv2_web_acl_association targeting
# the v2 stage — it is a non-applyable no-op that misrepresents the API as
# regionally WAF-protected.
################################################################################

resource "aws_wafv2_web_acl" "regional" {
  name        = "${local.name_prefix}-regional"
  description = "WAF rules for the regional HTTP API stage with OWASP Top 10 and rate limiting"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  # Rule 1: AWS Managed Rules - Common Rule Set (OWASP Top 10)
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RegionalCommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  # Rule 2: AWS Managed Rules - Known Bad Inputs
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RegionalKnownBadInputs"
      sampled_requests_enabled   = true
    }
  }

  # Rule 3: AWS Managed Rules - IP Reputation List
  rule {
    name     = "AWSManagedRulesAmazonIpReputationList"
    priority = 3

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAmazonIpReputationList"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RegionalIpReputationList"
      sampled_requests_enabled   = true
    }
  }

  # Rule 4: Rate limit ALL per-tenant auth endpoints.
  # The CloudFront ACL only rate-limits /saml/sso; here the scope-down widens to
  # the whole /t/ tenant prefix so every SAML *and* OIDC protocol endpoint on the
  # directly reachable API is covered, not just SAML SSO.
  rule {
    name     = "RateLimitAuthEndpoints"
    priority = 4

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 300
        aggregate_key_type = "IP"

        scope_down_statement {
          byte_match_statement {
            search_string         = "/t/"
            positional_constraint = "STARTS_WITH"

            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RegionalRateLimitAuthEndpoints"
      sampled_requests_enabled   = true
    }
  }

  # Rule 5: Rate limit Management API
  rule {
    name     = "RateLimitManagementAPI"
    priority = 5

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 200
        aggregate_key_type = "IP"

        scope_down_statement {
          byte_match_statement {
            search_string         = "/api/v1/"
            positional_constraint = "STARTS_WITH"

            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority = 0
              type     = "NONE"
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RegionalRateLimitManagementAPI"
      sampled_requests_enabled   = true
    }
  }

  # Rule 6: Body size limit on SAML POST (64KB max)
  rule {
    name     = "SAMLBodySizeLimit"
    priority = 6

    action {
      block {}
    }

    statement {
      size_constraint_statement {
        comparison_operator = "GT"
        size                = 65536

        field_to_match {
          body {
            oversize_handling = "MATCH"
          }
        }

        text_transformation {
          priority = 0
          type     = "NONE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RegionalSAMLBodySizeLimit"
      sampled_requests_enabled   = true
    }
  }

  # Rule 7: Global Rate Limit
  rule {
    name     = "GlobalRateLimit"
    priority = 7

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RegionalGlobalRateLimit"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.name_prefix}-regional-waf"
    sampled_requests_enabled   = true
  }

  tags = local.tags
}

################################################################################
# WAFv2 Association
#
# No aws_wafv2_web_acl_association is declared for the HTTP API: WAFv2 cannot
# associate a Web ACL with an API Gateway HTTP (v2) stage (see the regional ACL
# header above for the supported resource types and the two migration paths).
# The API's WAF coverage today is the CloudFront ACL in frontend.tf. Adding an
# association here targeting aws_apigatewayv2_stage.default would fail at apply.
################################################################################

################################################################################
# WAFv2 Logging — regional Web ACL
#
# Regional ACL logs to an eu-north-1 log group (same region as the ACL and the
# encryption CMK). The log group name is prefixed "aws-waf-logs-" and is CMK
# encrypted; Authorization/Cookie headers are redacted.
################################################################################

resource "aws_cloudwatch_log_group" "waf_regional" {
  name              = "aws-waf-logs-${local.name_prefix}-regional"
  retention_in_days = 365

  kms_key_id = module.kms_encryption.key_arn

  tags = merge(local.tags, {
    Component = "waf-logging"
  })
}

resource "aws_wafv2_web_acl_logging_configuration" "regional" {
  resource_arn            = aws_wafv2_web_acl.regional.arn
  log_destination_configs = [trimsuffix(aws_cloudwatch_log_group.waf_regional.arn, ":*")]

  redacted_fields {
    single_header {
      name = "authorization"
    }
  }

  redacted_fields {
    single_header {
      name = "cookie"
    }
  }
}
