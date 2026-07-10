################################################################################
# EventBridge — Certificate Rotation Scheduling
################################################################################

resource "aws_cloudwatch_event_rule" "cert_rotation" {
  name                = "${local.name_prefix}-cert-rotation"
  description         = "Weekly certificate rotation check"
  schedule_expression = "rate(7 days)"
  state               = "ENABLED"

  tags = merge(local.tags, { Component = "cert-rotation" })
}

resource "aws_cloudwatch_event_target" "cert_rotation" {
  rule = aws_cloudwatch_event_rule.cert_rotation.name
  arn  = module.lambda_fn["saml-sso"].lambda_function_arn

  input = jsonencode({
    source      = "eventbridge"
    detail-type = "CertRotationCheck"
  })
}

resource "aws_lambda_permission" "cert_rotation" {
  statement_id  = "AllowEventBridgeCertRotation"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_fn["saml-sso"].lambda_function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.cert_rotation.arn
}

################################################################################
# CloudWatch — Certificate Expiry Alarm
################################################################################

module "cloudwatch_cert_expiry" {
  source  = "terraform-aws-modules/cloudwatch/aws//modules/metric-alarm"
  version = "~> 5.7"

  alarm_name          = "${local.name_prefix}-cert-expiry"
  alarm_description   = "Signing certificate expires in less than 14 days"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  threshold           = 14
  metric_name         = "CertDaysRemaining"
  namespace           = "IdentityGateway"
  period              = 86400
  statistic           = "Minimum"

  alarm_actions = [module.sns_alerts.topic_arn]
  ok_actions    = [module.sns_alerts.topic_arn]

  tags = merge(local.tags, { Component = "cert-rotation" })
}
