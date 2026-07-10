module "common" {
  source = "../modules/common"

  project         = var.project
  environment     = var.environment
  name_suffix     = var.name_suffix
  owner           = var.owner
  additional_tags = var.additional_tags
}

locals {
  name_prefix      = module.common.name_prefix
  tags             = module.common.tags
  lambda_functions = module.common.lambda_functions
}
