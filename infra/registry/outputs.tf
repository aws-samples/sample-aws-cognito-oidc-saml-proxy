output "ecr_repository_urls" {
  description = "Per-capability ECR repository URLs (consumed by the gateway stack)"
  value       = { for k, v in module.ecr_fn : k => v.repository_url }
}

output "ecr_demo_saml_url" {
  description = "Demo SAML SP ECR repository URL (consumed by the demo stack)"
  value       = module.ecr_demo_saml.repository_url
}

output "ecr_demo_oidc_url" {
  description = "Demo OIDC RP ECR repository URL (consumed by the demo stack)"
  value       = module.ecr_demo_oidc.repository_url
}
