################################################################################
# Route53 — Existing Hosted Zone
################################################################################

data "aws_route53_zone" "main" {
  count        = var.dns_zone_name != "" ? 1 : 0
  name         = var.dns_zone_name
  private_zone = false
}

locals {
  zone_id         = var.dns_zone_name != "" ? data.aws_route53_zone.main[0].zone_id : ""
  wildcard_domain = var.dns_zone_name != "" ? "*.${var.demo_subdomain_prefix}.${var.dns_zone_name}" : ""
  dns_enabled     = var.dns_zone_name != ""

  # The gateway's own subdomain (re-derived here; the demo stack derives its own
  # saml./oidc. subdomains independently from the same inputs).
  demo_gateway_domain = var.dns_zone_name != "" ? "gateway.${var.demo_subdomain_prefix}.${var.dns_zone_name}" : ""
}

################################################################################
# ACM — Wildcard Certificate (us-east-1 for CloudFront)
################################################################################

resource "aws_acm_certificate" "wildcard" {
  count    = local.dns_enabled ? 1 : 0
  provider = aws.us_east_1

  domain_name       = local.wildcard_domain
  validation_method = "DNS"

  tags = merge(local.tags, {
    Component = "tls"
  })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "cert_validation" {
  for_each = local.dns_enabled ? {
    (local.wildcard_domain) = {
      name   = tolist(aws_acm_certificate.wildcard[0].domain_validation_options)[0].resource_record_name
      record = tolist(aws_acm_certificate.wildcard[0].domain_validation_options)[0].resource_record_value
      type   = tolist(aws_acm_certificate.wildcard[0].domain_validation_options)[0].resource_record_type
    }
  } : {}

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = local.zone_id
}

resource "aws_acm_certificate_validation" "wildcard" {
  count    = local.dns_enabled ? 1 : 0
  provider = aws.us_east_1

  certificate_arn         = aws_acm_certificate.wildcard[0].arn
  validation_record_fqdns = [for record in aws_route53_record.cert_validation : record.fqdn]
}

################################################################################
# Route53 — Gateway A record
################################################################################

resource "aws_route53_record" "gateway" {
  count   = local.dns_enabled ? 1 : 0
  zone_id = local.zone_id
  name    = local.demo_gateway_domain
  type    = "A"

  alias {
    name                   = aws_cloudfront_distribution.main.domain_name
    zone_id                = aws_cloudfront_distribution.main.hosted_zone_id
    evaluate_target_health = false
  }
}
