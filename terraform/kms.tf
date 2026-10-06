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

resource "aws_kms_alias" "uploads" {
  name          = "alias/${local.name_prefix}-uploads-${local.suffix}"
  target_key_id = aws_kms_key.uploads.key_id
}

######################################################################
# GAP-02 — Customer-managed key for the submissions table.
######################################################################

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
