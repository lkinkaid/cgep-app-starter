# Step 1: Build the signed-evidence vault
# terraform/evidence-vault.tf

locals {
  vault_name = "${var.project_name}-grc-evidence-vault-${random_id.suffix.hex}"
}

# Keep audit evidence in a dedicated bucket with Object Lock enabled;
# workload uploads and Terraform state have separate destinations.
resource "aws_s3_bucket" "vault" {
  bucket              = local.vault_name
  object_lock_enabled = true

  # Allow cleanup during sandbox teardown, subject to Object Lock retention.
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "vault" {
  bucket = aws_s3_bucket.vault.id
  versioning_configuration { status = "Enabled" } # Object Lock requires versioning
}

# Step 2: Preserve new evidence versions for the configured retention period
# Versioning precedes retention configuration. The verification script
# checks the recorded object version and its actual retention metadata.
resource "aws_s3_bucket_object_lock_configuration" "vault" {
  bucket = aws_s3_bucket.vault.id

  rule {
    default_retention {
      mode = var.lock_mode # GOVERNANCE for labs, COMPLIANCE for production
      days = var.retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.vault]
}

# Step 3: Encrypt evidence using the dedicated CMK
# The workflow signs the evidence bundle separately; SSE-KMS protects
# stored content while the signature establishes artifact authenticity.
resource "aws_s3_bucket_server_side_encryption_configuration" "vault" {
  bucket = aws_s3_bucket.vault.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.evidence.arn
    }
  }
}

# Refuse bucket deletion from anyone except the account root.
data "aws_caller_identity" "current" {}

# Step 4: Protect the bucket and block public access
# This deny protects bucket deletion. Object Lock protects retained versions;
# an administrator able to change this bucket policy can change this deny.
resource "aws_s3_bucket_policy" "vault" {
  bucket = aws_s3_bucket.vault.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyBucketDeletion"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:DeleteBucket"
      Resource  = aws_s3_bucket.vault.arn
      Condition = {
        StringNotEquals = {
          "aws:PrincipalArn" = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
      }
    }]
  })
}
resource "aws_s3_bucket_public_access_block" "vault" {
  bucket = aws_s3_bucket.vault.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
