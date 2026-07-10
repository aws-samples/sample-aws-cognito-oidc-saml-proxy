################################################################################
# Route53 — Existing Hosted Zone (re-declared; demo derives its own records)
################################################################################

data "aws_route53_zone" "main" {
  count        = var.dns_zone_name != "" ? 1 : 0
  name         = var.dns_zone_name
  private_zone = false
}

locals {
  zone_id     = var.dns_zone_name != "" ? data.aws_route53_zone.main[0].zone_id : ""
  dns_enabled = var.dns_zone_name != ""
}

################################################################################
# Route53 — Demo A records
################################################################################

resource "aws_route53_record" "saml_demo" {
  count   = local.dns_enabled ? 1 : 0
  zone_id = local.zone_id
  name    = local.demo_saml_domain
  type    = "A"

  alias {
    name                   = aws_cloudfront_distribution.demo_saml.domain_name
    zone_id                = aws_cloudfront_distribution.demo_saml.hosted_zone_id
    evaluate_target_health = false
  }
}

resource "aws_route53_record" "oidc_demo" {
  count   = local.dns_enabled ? 1 : 0
  zone_id = local.zone_id
  name    = local.demo_oidc_domain
  type    = "A"

  alias {
    name                   = aws_cloudfront_distribution.demo_oidc.domain_name
    zone_id                = aws_cloudfront_distribution.demo_oidc.hosted_zone_id
    evaluate_target_health = false
  }
}
