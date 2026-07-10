output "demo_saml_sp_url" {
  description = "Demo SAML SP URL (custom domain if set, else the generated CloudFront domain)"
  value       = local.demo_saml_url
}

output "demo_oidc_rp_url" {
  description = "Demo OIDC RP URL (custom domain if set, else the generated CloudFront domain)"
  value       = local.demo_oidc_url
}
