# Step 1: Separate workload, evidence, and audit encryption keys
# terraform/kms.tf

######################################################################
# GAP-01 — Encrypt uploads with a customer-managed KMS key.
######################################################################

resource "aws_kms_key" "uploads" {
  description             = "Customer-managed encryption key for patient intake uploads"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  # The default KMS key policy enables this account to administer the key
  # and delegate use through IAM policies, including the Lambda policy in hardening.tf.
  tags = { Name = "${local.name_prefix}-uploads-${local.suffix}" }
}

# The alias aids operator discovery; encryption and IAM use the key ARN.
resource "aws_kms_alias" "uploads" {
  name          = "alias/${local.name_prefix}-uploads-${local.suffix}"
  target_key_id = aws_kms_key.uploads.key_id
}

######################################################################
# GAP-02 — Customer-managed key for the submissions table.
######################################################################

# Step 2: Encrypt submissions with a separate customer-managed key
# GAP-02 / HIPAA 164.312(a)(2)(iv): DynamoDB and Lambda reference
# this key through the table and service-constrained IAM permissions.
resource "aws_kms_key" "intake" {
  description             = "Customer-managed encryption key for patient intake submissions"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  # The default key policy enables account administration and IAM delegation.
  tags = { Name = "${local.name_prefix}-submissions-${local.suffix}" }
}

resource "aws_kms_alias" "intake" {
  name          = "alias/${local.name_prefix}-submissions-${local.suffix}"
  target_key_id = aws_kms_key.intake.key_id
}
######################################################################
# Capstone — Customer-managed key for the evidence vault.
######################################################################

# Step 3: Encrypt signed evidence separately from workload data
# Rotation is enabled and deletion has a 30-day waiting period. Encryption
# complements the vault retention and signatures; it does not replace them.
resource "aws_kms_key" "evidence" {
  description             = "Customer-managed encryption key for signed capstone evidence"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  # The default key policy enables account administration and IAM delegation.
  tags = { Name = "${local.name_prefix}-evidence-${local.suffix}" }
}

resource "aws_kms_alias" "evidence" {
  name          = "alias/${local.name_prefix}-evidence-${local.suffix}"
  target_key_id = aws_kms_key.evidence.key_id
}

######################################################################
# Capstone — Customer-managed key for cloudtrail
######################################################################
# Step 4: Permit CloudTrail to encrypt this account trail
# SourceArn and encryption context constrain GenerateDataKey to the trail.
# In this key policy, Resource = "*" refers to the key carrying the policy.
resource "aws_kms_key" "trail" {
  description             = "Customer-managed encryption key for CloudTrail logs"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableAccountAdministrationAndIAMDelegation"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowCloudTrailEncryption"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "kms:GenerateDataKey"
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceArn" = local.trail_arn
          }
          StringLike = {
            "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/${local.trail_name}"
          }
        }
      },
      {
        Sid    = "AllowCloudTrailDescribeKey"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "kms:DescribeKey"
        Resource = "*"
      },
    ]
  })

  tags = {
    Name = "${local.name_prefix}-cloudtrail-${local.suffix}"
  }
}

resource "aws_kms_alias" "trail" {
  name          = "alias/${local.name_prefix}-cloudtrail-${local.suffix}"
  target_key_id = aws_kms_key.trail.key_id
}
