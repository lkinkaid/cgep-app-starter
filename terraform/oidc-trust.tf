# Step 1: Configure GitHub federation for the plan gate
# terraform/oidc-trust.tf

# Create a provider only when an existing ARN was not supplied.
resource "aws_iam_openid_connect_provider" "github" {
  count = var.existing_github_oidc_provider_arn == null ? 1 : 0

  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
}

# Read the shared provider when an existing ARN was supplied.
data "aws_iam_openid_connect_provider" "github" {
  count = var.existing_github_oidc_provider_arn == null ? 0 : 1

  arn = var.existing_github_oidc_provider_arn

  lifecycle {
    postcondition {
      condition     = contains(self.client_id_list, "sts.amazonaws.com")
      error_message = "The existing provider must include sts.amazonaws.com."
    }
  }
}

# Select the ARN from whichever path is enabled.
locals {
  github_oidc_provider_arn = (
    var.existing_github_oidc_provider_arn == null
    ? aws_iam_openid_connect_provider.github[0].arn
    : data.aws_iam_openid_connect_provider.github[0].arn
  )
}

# Step 2: Allow repository runs to plan without workload mutation rights
# The subject patterns cover repository contexts including pull requests.
# The audience must be STS; deployment on main uses the separate apply role.
resource "aws_iam_role" "grc_gate" {
  name = "${var.project_name}-grc-plan"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = local.github_oidc_provider_arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = { "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com" }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = [
            "repo:${var.github_org}/${var.github_repo}:*",     # repos created before Jul 15 2026
            "repo:${var.github_org}@*/${var.github_repo}@*:*", # repos created after: GitHub adds owner + repo IDs
          ]
        }
      }
    }]
  })
}

# AWS ReadOnlyAccess is account-wide. The write exceptions below cover
# the state lock and evidence upload, not workload deployment.
resource "aws_iam_role_policy_attachment" "readonly" {
  role       = aws_iam_role.grc_gate.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# Step 3: Permit the temporary S3 state lock used during planning
# DeleteObject is scoped to the lockfile, not the Terraform state object.
resource "aws_iam_role_policy" "grc_state_lock" {
  name = "capstone-state-lock"
  role = aws_iam_role.grc_gate.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "ManageTerraformStateLock"
      Effect = "Allow"
      Action = [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
      ]
      Resource = "arn:aws:s3:::acme-health-intake-tfstate-420539147061/capstone/terraform.tfstate.tflock"
    }]
  })
}

# Step 4: Preserve evidence from both passing and failing gate runs
# Uploads are confined to runs/ in the vault; key use must pass through S3.
# These permissions do not grant retention bypass or evidence deletion.
resource "aws_iam_role_policy" "grc_evidence" {
  name = "upload-capstone-evidence"
  role = aws_iam_role.grc_gate.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "UploadEvidence"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:AbortMultipartUpload",
        ]
        Resource = "${aws_s3_bucket.vault.arn}/runs/*"
      },
      {
        Sid    = "UseEvidenceEncryptionKey"
        Effect = "Allow"
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt",
        ]
        Resource = aws_kms_key.evidence.arn
        Condition = {
          StringEquals = {
            "kms:ViaService" = "s3.${var.aws_region}.amazonaws.com"
          }
        }
      },
    ]
  })
}
