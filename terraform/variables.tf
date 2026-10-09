# Step 1: Define the sandbox inputs and validation rules
# terraform/variables.tf

variable "aws_region" {
  type        = string
  description = "AWS region for the starter."
  default     = "us-east-1"
}

# Used by CI, trail, and evidence naming; main.tf retains the starter
# workload name_prefix so existing resource identities remain stable.
variable "project_name" {
  type        = string
  description = "Project name used for resource naming and tags."
  default     = "acme-health-intake"
}


# Step 2: Choose evidence retention settings
# GOVERNANCE follows the lab sandbox convention. Bypass-capable principals
# can override governance retention; neither CI role receives that permission.
variable "lock_mode" {
  type        = string
  description = "GOVERNANCE for lab work; COMPLIANCE for real evidence."
  default     = "GOVERNANCE"
  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.lock_mode)
    error_message = "lock_mode must be GOVERNANCE or COMPLIANCE."
  }
}

# Default retention for new evidence versions; changing this setting does
# not retroactively change retention on versions already stored.
variable "retention_days" {
  type        = number
  description = "Default retention applied to every uploaded object."
  default     = 30
  validation {
    condition     = var.retention_days >= 1 && floor(var.retention_days) == var.retention_days
    error_message = "retention_days must be a positive whole number."
  }

}

# Step 3: Identify the repository allowed to federate through GitHub OIDC
variable "github_org" {
  type        = string
  description = "GitHub organization name."
  default     = "lkinkaid"
}

variable "github_repo" {
  type        = string
  description = "GitHub repository name."
  default     = "cgep-app-starter"
}

# Reuse the account provider when an ARN is supplied. Null selects the
# creation path in oidc-trust.tf; these paths are mutually exclusive.
variable "existing_github_oidc_provider_arn" {
  type        = string
  description = "Existing GitHub OIDC provider ARN. Leave null to create one."
  default     = null
}
