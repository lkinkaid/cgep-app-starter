variable "aws_region" {
  type        = string
  description = "AWS region for the starter."
  default     = "us-east-1"
}

variable "project_name" {
  type        = string
  description = "Project name used for resource naming and tags."
  default     = "acme-health-intake"
}


variable "lock_mode" {
  type        = string
  description = "GOVERNANCE for lab work; COMPLIANCE for real evidence."
  default     = "GOVERNANCE"
  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.lock_mode)
    error_message = "lock_mode must be GOVERNANCE or COMPLIANCE."
  }
}

variable "retention_days" {
  type        = number
  description = "Default retention applied to every uploaded object."
  default     = 30
  validation {
    condition     = var.retention_days >= 1 && floor(var.retention_days) == var.retention_days
    error_message = "retention_days must be a positive whole number."
  }

}

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

variable "existing_github_oidc_provider_arn" {
  type        = string
  description = "Existing GitHub OIDC provider ARN. Leave null to create one."
  default     = null
}
