################################################################################
# SNS — Alert Topic
################################################################################

module "sns_alerts" {
  source  = "terraform-aws-modules/sns/aws"
  version = "~> 7.1"

  name         = "${local.name_prefix}-alerts"
  display_name = "${local.name_prefix} Operational Alerts"

  # Only create the email subscription when an address is configured. An empty
  # alert_email (common for sandbox/dev deploys) skips it rather than failing the
  # whole apply with an SNS "Invalid parameter: Email address" error. The topic
  # is still created so CloudWatch alarm_actions remain valid.
  subscriptions = var.alert_email != "" ? {
    email = {
      protocol = "email"
      endpoint = var.alert_email
    }
  } : {}

  tags = {
    Component = "monitoring"
  }
}

################################################################################
# EventBridge — Scheduled Health Check
################################################################################

module "eventbridge" {
  source  = "terraform-aws-modules/eventbridge/aws"
  version = "~> 4.3"

  # Use default bus for schedule expressions (schedule_expression only works on default bus)
  create_bus = false

  # Do not create an IAM role. The only target is a Lambda, which is authorized
  # by the resource-based aws_lambda_permission.eventbridge_health policy below,
  # not by an EventBridge execution role (roles are only needed for targets like
  # SQS/Kinesis/ECS/Step Functions). Left at its default, the module names the
  # role coalesce(role_name, bus_name, "*") → the literal, un-prefixed,
  # account-global name "default" (bus_name defaults to "default" here because
  # create_bus = false), which collides with any other EventBridge module use in
  # the account. Disabling it removes both the needless role and the collision.
  create_role = false

  rules = {
    lambda_health_check = {
      description         = "Periodic health check for the SAML proxy"
      schedule_expression = "rate(5 minutes)"
      state               = "ENABLED"
    }
  }

  targets = {
    lambda_health_check = [
      {
        name = "saml-proxy-health-check"
        arn  = module.lambda_fn["health"].lambda_function_arn
        input = jsonencode({
          source      = "eventbridge"
          detail-type = "ScheduledHealthCheck"
        })
      }
    ]
  }

  tags = {
    Component = "monitoring"
  }
}

resource "aws_lambda_permission" "eventbridge_health" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_fn["health"].lambda_function_name
  principal     = "events.amazonaws.com"
  source_arn    = module.eventbridge.eventbridge_rule_arns["lambda_health_check"]
}

################################################################################
# CloudWatch — Alarms
#
# Per-capability Lambda alarms will be added in a future monitoring pass.
# For now, API Gateway and DynamoDB alarms cover the critical paths.
################################################################################

module "cloudwatch_api_5xx" {
  source  = "terraform-aws-modules/cloudwatch/aws//modules/metric-alarm"
  version = "~> 5.7"

  alarm_name          = "${local.name_prefix}-api-5xx"
  alarm_description   = "API Gateway 5xx error rate exceeds threshold"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  threshold           = 10

  metric_name = "5xx"
  namespace   = "AWS/ApiGateway"
  period      = 60
  statistic   = "Sum"

  dimensions = {
    ApiId = aws_apigatewayv2_api.main.id
  }

  alarm_actions = [module.sns_alerts.topic_arn]
  ok_actions    = [module.sns_alerts.topic_arn]

  tags = {
    Component = "monitoring"
  }
}

module "cloudwatch_api_4xx" {
  source  = "terraform-aws-modules/cloudwatch/aws//modules/metric-alarm"
  version = "~> 5.7"

  alarm_name          = "${local.name_prefix}-api-4xx"
  alarm_description   = "API Gateway 4xx error rate exceeds threshold"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 5
  threshold           = 50

  metric_name = "4xx"
  namespace   = "AWS/ApiGateway"
  period      = 60
  statistic   = "Sum"

  dimensions = {
    ApiId = aws_apigatewayv2_api.main.id
  }

  alarm_actions = [module.sns_alerts.topic_arn]

  tags = {
    Component = "monitoring"
  }
}

module "cloudwatch_dynamodb_throttles" {
  source  = "terraform-aws-modules/cloudwatch/aws//modules/metric-alarm"
  version = "~> 5.7"

  alarm_name          = "${local.name_prefix}-dynamodb-throttles"
  alarm_description   = "DynamoDB read/write throttling detected"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  threshold           = 0

  metric_name = "ThrottledRequests"
  namespace   = "AWS/DynamoDB"
  period      = 300
  statistic   = "Sum"

  dimensions = {
    TableName = module.dynamodb.dynamodb_table_id
  }

  alarm_actions = [module.sns_alerts.topic_arn]

  tags = {
    Component = "monitoring"
  }
}

################################################################################
# CloudWatch — Audit-trail durability alarm
#
# The audit Logger writes each event to CloudWatch Logs (the permanent record)
# and to DynamoDB (a 24h cache). If the CloudWatch write fails, the Go side
# emits a structured `audit_metric` slog record naming the
# IdentityGateway/Audit :: AuditCloudWatchWriteFailure metric (see
# internal/audit/logger.go emitWriteFailureMetric). That record is written to
# stdout, so it lands in the emitting function's own /aws/lambda/<fn> log group
# — NOT the /identity-gateway/audit group, which only ever receives the audit
# Event via PutLogEvents. The metric filter must therefore attach to the
# per-capability Lambda log groups.
#
# One filter per function keeps the wiring uniform and future-proof (a function
# that never emits the line simply never publishes a data point); every filter
# publishes to the same namespace/metric, so a single alarm sums across the
# fleet. Without this, a sustained CloudWatch Logs outage would silently erode
# the durable audit trail until the 24h DynamoDB cache expired, with no operator
# signal.
#
# Log-group binding is intentionally taken from the lambda module's
# `lambda_cloudwatch_log_group_name` output, NOT reconstructed as a
# "/aws/lambda/${name}" string. That output is defined as
#   try(data.aws_cloudwatch_log_group.lambda[0].name,      # use_existing = true
#       aws_cloudwatch_log_group.lambda[0].name,           # module creates it
#       "")                                                 # neither → empty
# so it already follows a future flip to bring-your-own log groups
# (use_existing_cloudwatch_log_group = true) or a custom logging_log_group with
# no change here. The only way it degrades is the third branch — a config where
# the module manages no log group at all (e.g. create_function = false) — which
# yields "". A metric filter on an empty log-group name fails opaquely at apply,
# so the precondition below turns that degenerate case into a loud, actionable
# error instead of a confusing provider rejection.
################################################################################

locals {
  # Resolved per-function Lambda log-group names the audit-failure filters attach
  # to. Auto-follows the lambda module's create-vs-existing logic (see above).
  audit_lambda_log_group_names = {
    for name in keys(local.lambda_functions) :
    name => module.lambda_fn[name].lambda_cloudwatch_log_group_name
  }
}

resource "aws_cloudwatch_log_metric_filter" "audit_write_failure" {
  for_each = local.lambda_functions

  name           = "${local.name_prefix}-audit-write-failure-${each.key}"
  log_group_name = local.audit_lambda_log_group_names[each.key]

  # Matches the JSON slog record emitted by emitWriteFailureMetric. Keyed on both
  # the message and the metric name so unrelated ERROR lines never count.
  pattern = "{ ($.msg = \"audit_metric\") && ($.metric = \"AuditCloudWatchWriteFailure\") }"

  metric_transformation {
    name      = "AuditCloudWatchWriteFailure"
    namespace = "IdentityGateway/Audit"
    value     = "1"
    unit      = "Count"
  }

  # Fail loud if the lambda module ever stops surfacing a log-group name for this
  # function (its output falls back to "" when it manages no group). Without this
  # the filter would attach to an empty name and the audit-failure alarm would go
  # silently blind.
  lifecycle {
    precondition {
      condition     = length(local.audit_lambda_log_group_names[each.key]) > 0
      error_message = "No CloudWatch log-group name resolved for Lambda '${each.key}'. The audit-write-failure metric filter has nothing to attach to, so the durability alarm would be blind. If the lambda module was switched to bring-your-own or unmanaged log groups, point this filter (and the alarm) at the actual audit-writer log groups."
    }
  }
}

module "cloudwatch_audit_write_failure" {
  source  = "terraform-aws-modules/cloudwatch/aws//modules/metric-alarm"
  version = "~> 5.7"

  alarm_name          = "${local.name_prefix}-audit-write-failure"
  alarm_description   = "Audit trail CloudWatch Logs write failed — the durable audit record is at risk while only the 24h DynamoDB cache remains. Investigate CloudWatch Logs availability and the audit-writing functions' logs:PutLogEvents grants."
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  threshold           = 0
  # A rare-error metric has no data points until the first failure; treat the
  # absence of failures as healthy rather than INSUFFICIENT_DATA.
  treat_missing_data = "notBreaching"

  metric_name = "AuditCloudWatchWriteFailure"
  namespace   = "IdentityGateway/Audit"
  period      = 300
  statistic   = "Sum"

  alarm_actions = [module.sns_alerts.topic_arn]
  ok_actions    = [module.sns_alerts.topic_arn]

  tags = {
    Component = "monitoring"
  }
}
