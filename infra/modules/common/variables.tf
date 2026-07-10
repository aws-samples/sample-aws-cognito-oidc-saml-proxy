variable "project" {
  description = "Project name used for resource naming and tagging"
  type        = string
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string
}

variable "name_suffix" {
  description = "Optional suffix appended after <project>-<environment> in name_prefix. Empty by default. Lets a second instance coexist in one account without colliding on account-global names."
  type        = string
  default     = ""

  # Mirror the root-level validation (infra/variables.tf) as defense-in-depth:
  # the suffix becomes part of resource names, so guard it here too in case the
  # module is ever consumed by a caller that does not pre-validate.
  validation {
    condition     = can(regex("^[a-z0-9-]*$", var.name_suffix))
    error_message = "name_suffix must be lowercase alphanumeric or hyphen (it becomes part of resource names)."
  }
}

variable "owner" {
  description = "Owner tag value for resource identification"
  type        = string
}

variable "additional_tags" {
  description = "Additional tags merged into the standard tag set"
  type        = map(string)
  default     = {}
}
