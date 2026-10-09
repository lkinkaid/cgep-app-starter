# Step 1: Manage the existing state bucket in its own stack
# bootstrap/state-backend/main.tf
# Keep this stack outside terraform/ so workload teardown cannot remove its
# backend. Local state must be backed up securely and retained until cleanup.
terraform {
  required_version = ">= 1.10"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }

  backend "local" {
    path = "terraform.tfstate"
  }
}

provider "aws" {
  region              = "us-east-1"
  allowed_account_ids = ["420539147061"]
}

# Preserve the verified bucket name and empty tag set during adoption.
# Do not automatically purge historical state versions during destruction.
resource "aws_s3_bucket" "state" {
  bucket        = "acme-health-intake-tfstate-420539147061"
  force_destroy = false
}

# Step 2: Preserve state recovery and existing encryption settings
resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = false
  }
}

# Step 3: Match the bucket's existing public-access and ownership controls
resource "aws_s3_bucket_public_access_block" "state" {
  bucket                  = aws_s3_bucket.state.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}
