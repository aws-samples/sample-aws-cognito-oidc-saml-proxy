terraform {
  # 1.10+ is required for native S3 state locking (use_lockfile) used by the
  # S3 backend below (see env/registry.dev.backend.hcl.example).
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.28"
    }
  }

  # Remote state on a versioned, SSE-KMS-encrypted, public-access-blocked S3
  # bucket with native S3 locking. Config is supplied at init time via
  # -backend-config=../env/registry.<env>.backend.hcl (never hard-coded here).
  backend "s3" {}
}
