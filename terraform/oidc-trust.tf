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

resource "aws_iam_role_policy_attachment" "readonly" {
  role       = aws_iam_role.grc_gate.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

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
