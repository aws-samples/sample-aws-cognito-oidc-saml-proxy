# Tests for the gateway's infrastructure security controls.
#
# Uses mock_provider so `terraform test` exercises the whole configuration fully
# offline (no AWS creds, no network). Assertions target the security-relevant
# knobs each finding hardened.
#
# The mock defaults below give computed attributes ARN-/id-shaped values so the
# provider-side format validators in the upstream modules accept them during a
# mocked apply. These defaults exist only so the plan/apply reaches the point
# where the security assertions can evaluate.

mock_provider "aws" {
  mock_data "aws_iam_policy_document" {
    defaults = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
  mock_data "aws_cloudwatch_event_bus" {
    defaults = { arn = "arn:aws:events:eu-north-1:123456789012:event-bus/default" }
  }
  mock_resource "aws_cognito_user_pool" {
    defaults = {
      id       = "eu-north-1_abc123XYZ"
      arn      = "arn:aws:cognito-idp:eu-north-1:123456789012:userpool/eu-north-1_abc123XYZ"
      endpoint = "cognito-idp.eu-north-1.amazonaws.com/eu-north-1_abc123XYZ"
    }
  }
  mock_resource "aws_apigatewayv2_api" {
    defaults = {
      id            = "abc123"
      execution_arn = "arn:aws:execute-api:eu-north-1:123456789012:abc123"
      api_endpoint  = "https://abc123.execute-api.eu-north-1.amazonaws.com"
    }
  }
  mock_resource "aws_apigatewayv2_stage" {
    defaults = {
      arn        = "arn:aws:apigateway:eu-north-1::/apis/abc123/stages/default"
      invoke_url = "https://abc123.execute-api.eu-north-1.amazonaws.com/"
    }
  }
  mock_resource "aws_wafv2_web_acl" {
    defaults = { arn = "arn:aws:wafv2:eu-north-1:123456789012:regional/webacl/x/1111" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:eu-north-1:123456789012:log-group:aws-waf-logs-x:*" }
  }
  mock_resource "aws_cloudfront_function" {
    defaults = { arn = "arn:aws:cloudfront::123456789012:function/x" }
  }
  mock_resource "aws_cloudfront_distribution" {
    defaults = {
      arn            = "arn:aws:cloudfront::123456789012:distribution/E1"
      domain_name    = "d1.cloudfront.net"
      hosted_zone_id = "Z2FDTNDATAQYW2"
    }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::123456789012:role/x" }
  }
  mock_resource "aws_sns_topic" {
    defaults = { arn = "arn:aws:sns:eu-north-1:123456789012:x" }
  }
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws:kms:eu-north-1:123456789012:key/1111", key_id = "1111" }
  }
  mock_resource "aws_dynamodb_table" {
    defaults = { arn = "arn:aws:dynamodb:eu-north-1:123456789012:table/x" }
  }
  mock_resource "aws_s3_bucket" {
    defaults = { arn = "arn:aws:s3:::x" }
  }
  mock_resource "aws_lambda_function" {
    defaults = {
      arn           = "arn:aws:lambda:eu-north-1:123456789012:function:x"
      invoke_arn    = "arn:aws:apigateway:eu-north-1:lambda:path/2015-03-31/functions/arn:aws:lambda:eu-north-1:123456789012:function:x/invocations"
      qualified_arn = "arn:aws:lambda:eu-north-1:123456789012:function:x:1"
    }
  }
  mock_resource "aws_cloudwatch_event_rule" {
    defaults = { arn = "arn:aws:events:eu-north-1:123456789012:rule/x" }
  }
  mock_resource "aws_cloudwatch_event_bus" {
    defaults = { arn = "arn:aws:events:eu-north-1:123456789012:event-bus/default" }
  }
}

mock_provider "aws" {
  alias = "us_east_1"

  mock_data "aws_iam_policy_document" {
    defaults = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
  mock_resource "aws_wafv2_web_acl" {
    defaults = { arn = "arn:aws:wafv2:us-east-1:123456789012:global/webacl/x/2222" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:us-east-1:123456789012:log-group:aws-waf-logs-y:*" }
  }
  mock_resource "aws_acm_certificate" {
    defaults = {
      arn = "arn:aws:acm:us-east-1:123456789012:certificate/1111"
      domain_validation_options = [{
        domain_name           = "*.fedgw.test.example.test"
        resource_record_name  = "_v.fedgw.test.example.test"
        resource_record_type  = "CNAME"
        resource_record_value = "_vt.acm-validations.aws."
      }]
    }
  }
  mock_resource "aws_acm_certificate_validation" {
    defaults = { certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/1111" }
  }
}

# The gateway reads the registry stack's ECR repository URLs via remote state.
# terraform test runs offline with no applied registry state, so override the
# data source with repo URLs shaped like real ECR URLs — one per function key —
# so module.lambda_fn's image_uri resolves and the mocked plan/apply proceeds to
# the security assertions.
override_data {
  target = data.terraform_remote_state.registry
  values = {
    outputs = {
      ecr_repository_urls = {
        saml-sso       = "123456789012.dkr.ecr.eu-north-1.amazonaws.com/x-saml-sso"
        saml-slo       = "123456789012.dkr.ecr.eu-north-1.amazonaws.com/x-saml-slo"
        saml-metadata  = "123456789012.dkr.ecr.eu-north-1.amazonaws.com/x-saml-metadata"
        oidc-authorize = "123456789012.dkr.ecr.eu-north-1.amazonaws.com/x-oidc-authorize"
        oidc-token     = "123456789012.dkr.ecr.eu-north-1.amazonaws.com/x-oidc-token"
        oidc-discovery = "123456789012.dkr.ecr.eu-north-1.amazonaws.com/x-oidc-discovery"
        management-api = "123456789012.dkr.ecr.eu-north-1.amazonaws.com/x-management-api"
        health         = "123456789012.dkr.ecr.eu-north-1.amazonaws.com/x-health"
      }
    }
  }
}

variables {
  environment    = "dev"
  owner          = "sec-hardening-test"
  saml_entity_id = "https://gateway.example.test"
  alert_email    = "[email protected]"
  # state_bucket must be non-empty: the S3 backend config rejects an empty string
  # even when the data source is overridden via override_data. The actual output
  # is supplied by override_data above; this value is never contacted.
  state_bucket = "offline-test-placeholder"
  # image_digests must contain an entry for every Lambda capability. The URI is
  # assembled as <ecr_url>@<digest> with a plain index that fails closed at plan
  # when a key is absent. Supply placeholder sha256 values so the mocked
  # plan/apply can proceed to the security assertions.
  image_digests = {
    saml-sso       = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
    saml-slo       = "sha256:0000000000000000000000000000000000000000000000000000000000000002"
    saml-metadata  = "sha256:0000000000000000000000000000000000000000000000000000000000000003"
    oidc-authorize = "sha256:0000000000000000000000000000000000000000000000000000000000000004"
    oidc-token     = "sha256:0000000000000000000000000000000000000000000000000000000000000005"
    oidc-discovery = "sha256:0000000000000000000000000000000000000000000000000000000000000006"
    management-api = "sha256:0000000000000000000000000000000000000000000000000000000000000007"
    health         = "sha256:0000000000000000000000000000000000000000000000000000000000000008"
  }
  # custom_domain makes local.base_url a known literal at plan time (needed by the
  # api_endpoint assertion); dns_zone_name exercises the ACM/Route53/demo paths so
  # the mocked plan/apply covers the whole configuration.
  custom_domain = "gw.example.test"
  dns_zone_name = "test.example.test"
}

# Admin Cognito pool enforces MFA + threat protection on an adequate tier.
run "cognito_mfa_and_threat_protection" {
  command = plan

  assert {
    condition     = aws_cognito_user_pool.main.mfa_configuration == "ON"
    error_message = "Cognito user pool must require MFA (mfa_configuration = ON)."
  }

  assert {
    condition     = aws_cognito_user_pool.main.user_pool_tier == "PLUS"
    error_message = "Cognito user pool must use the PLUS tier so advanced security is supported."
  }

  assert {
    condition     = one(aws_cognito_user_pool.main.software_token_mfa_configuration).enabled
    error_message = "TOTP software-token MFA must be enabled on the Cognito user pool."
  }

  assert {
    condition     = one(aws_cognito_user_pool.main.user_pool_add_ons).advanced_security_mode == "ENFORCED"
    error_message = "Cognito threat protection (advanced_security_mode) must be ENFORCED."
  }
}

# A REGIONAL WAF ACL carrying the full rule set exists, ready to bind to a
# WAF-associable regional resource. It is deliberately NOT associated with the
# HTTP API: WAFv2 AssociateWebACL does not support API Gateway HTTP (v2) stages,
# so an association targeting the $default stage fails at apply. The API's edge
# WAF is the CloudFront ACL; the direct-execute-api bypass is addressed by the
# migration paths documented in waf.tf, not by a non-applyable association.
run "regional_waf_acl_exists_with_full_ruleset" {
  command = plan

  assert {
    condition     = aws_wafv2_web_acl.regional.scope == "REGIONAL"
    error_message = "A REGIONAL WAF web ACL must exist, ready to protect the API behind a WAF-associable resource."
  }

  # Mirrors the seven rules on the CloudFront ACL (managed rule groups + rate limits).
  assert {
    condition     = length(aws_wafv2_web_acl.regional.rule) == 7
    error_message = "Regional WAF ACL must carry the full managed-rule + rate-limit rule set."
  }

  # Rate rule covers the whole /t/ tenant prefix, not just /saml/sso.
  assert {
    condition = anytrue([
      for r in aws_wafv2_web_acl.regional.rule :
      length(r.statement) > 0 &&
      length(r.statement[0].rate_based_statement) > 0 &&
      length(r.statement[0].rate_based_statement[0].scope_down_statement) > 0 &&
      length(r.statement[0].rate_based_statement[0].scope_down_statement[0].byte_match_statement) > 0 &&
      one(one(one(r.statement).rate_based_statement).scope_down_statement).byte_match_statement[0].search_string == "/t/"
    ])
    error_message = "Regional rate rule must cover the whole /t/ tenant prefix, not just /saml/sso."
  }
}

# Every web ACL logs to an aws-waf-logs- group with sensitive headers redacted.
run "waf_logging_enabled_and_redacted" {
  command = plan

  assert {
    condition     = startswith(aws_cloudwatch_log_group.waf_cloudfront.name, "aws-waf-logs-")
    error_message = "CloudFront WAF log group name must be prefixed 'aws-waf-logs-'."
  }

  assert {
    condition     = startswith(aws_cloudwatch_log_group.waf_regional.name, "aws-waf-logs-")
    error_message = "Regional WAF log group name must be prefixed 'aws-waf-logs-'."
  }

  assert {
    condition = toset([
      for f in aws_wafv2_web_acl_logging_configuration.cloudfront.redacted_fields :
      one(f.single_header).name
    ]) == toset(["authorization", "cookie"])
    error_message = "CloudFront WAF logging must redact the authorization and cookie headers."
  }

  assert {
    condition = toset([
      for f in aws_wafv2_web_acl_logging_configuration.regional.redacted_fields :
      one(f.single_header).name
    ]) == toset(["authorization", "cookie"])
    error_message = "Regional WAF logging must redact the authorization and cookie headers."
  }
}

# The api_endpoint output publishes the CloudFront-fronted (WAF-protected) base
# URL rather than the raw execute-api invoke_url.
run "api_endpoint_output_is_fronted" {
  command = plan

  assert {
    condition     = output.api_endpoint == local.base_url
    error_message = "api_endpoint must equal the CloudFront-fronted base URL."
  }

  assert {
    condition     = output.api_endpoint == "https://gw.example.test"
    error_message = "api_endpoint must be the custom-domain URL, not the raw execute-api invoke_url."
  }
}

# The audit-write-failure signal the Go side emits is turned into a CloudWatch
# metric and alarmed. A metric filter attaches to every per-capability Lambda
# log group (the slog line lands there, not in the audit log group), publishing
# to IdentityGateway/Audit :: AuditCloudWatchWriteFailure; a single alarm sums
# across the fleet and notifies the SNS alerts topic.
run "audit_write_failure_metric_and_alarm" {
  # apply (against the mock provider, still fully offline) so the alarm module's
  # computed id output is known when the last assertion evaluates it.
  command = apply

  # A filter exists for every Lambda function, so no audit-writer is unmonitored.
  assert {
    condition     = length(aws_cloudwatch_log_metric_filter.audit_write_failure) == length(local.lambda_functions)
    error_message = "An audit-write-failure metric filter must exist for every per-capability Lambda log group."
  }

  # The saml-slo filter (the SLO revocation writer) publishes the right metric.
  assert {
    condition     = one(aws_cloudwatch_log_metric_filter.audit_write_failure["saml-slo"].metric_transformation).namespace == "IdentityGateway/Audit"
    error_message = "Audit-write-failure metric must publish to the IdentityGateway/Audit namespace."
  }

  assert {
    condition     = one(aws_cloudwatch_log_metric_filter.audit_write_failure["saml-slo"].metric_transformation).name == "AuditCloudWatchWriteFailure"
    error_message = "Audit-write-failure metric filter must publish the AuditCloudWatchWriteFailure metric."
  }

  # The alarm watches that metric and routes to the SNS alerts topic.
  assert {
    condition     = module.cloudwatch_audit_write_failure.cloudwatch_metric_alarm_id != null
    error_message = "An alarm on the audit-write-failure metric must be created."
  }

  # Every filter must resolve to a real, non-empty Lambda log-group name. The
  # /aws/lambda/ shape check is the non-vacuous guard: it fails if the module
  # output degrades to "" (the degenerate create_function=false branch, which the
  # precondition also blocks) or is severed from the module and pointed at some
  # other group. This is what the offline mock CAN verify; the auto-follow to a
  # bring-your-own log group (use_existing_cloudwatch_log_group=true) rests on the
  # module-output semantics, not reconstructable here without a root-level flip.
  assert {
    condition = alltrue([
      for f in values(aws_cloudwatch_log_metric_filter.audit_write_failure) :
      startswith(f.log_group_name, "/aws/lambda/")
    ])
    error_message = "Every audit-write-failure filter must attach to a real /aws/lambda/ log group (non-empty, module-resolved)."
  }

  # Pin the concrete resolved value end-to-end through the module chain for the
  # SLO revocation writer: proves the module output flows through
  # local.audit_lambda_log_group_names to the filter and targets the right
  # function's group. Fails on empty resolution, a wiring break, or a wrong target.
  assert {
    condition     = aws_cloudwatch_log_metric_filter.audit_write_failure["saml-slo"].log_group_name == "/aws/lambda/${local.name_prefix}-saml-slo"
    error_message = "The saml-slo audit-write-failure filter must bind to that function's own /aws/lambda/<name_prefix>-saml-slo log group."
  }
}
