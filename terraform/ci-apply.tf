resource "aws_iam_role" "grc_apply" {
  name = "${var.project_name}-grc-apply"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = local.github_oidc_provider_arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = [
            "repo:${var.github_org}/${var.github_repo}:ref:refs/heads/main",
            "repo:${var.github_org}@*/${var.github_repo}@*:ref:refs/heads/main",
          ]
        }
      }
    }]
  })
}
resource "aws_iam_role_policy_attachment" "grc_apply_readonly" {
  role       = aws_iam_role.grc_apply.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_role_policy" "grc_apply_state_evidence" {
  name = "capstone-state-and-evidence"
  role = aws_iam_role.grc_apply.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "WriteTerraformState"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
        ]
        Resource = "arn:aws:s3:::acme-health-intake-tfstate-420539147061/capstone/terraform.tfstate"
      },
      {
        Sid    = "ManageTerraformLock"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
        ]
        Resource = "arn:aws:s3:::acme-health-intake-tfstate-420539147061/capstone/terraform.tfstate.tflock"
      },
      {
        Sid    = "UploadCapstoneEvidence"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:AbortMultipartUpload",
        ]
        Resource = "${aws_s3_bucket.vault.arn}/runs/*"
      },
      {
        Sid    = "EncryptCapstoneEvidence"
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
resource "aws_iam_role_policy" "grc_apply_pass_roles" {
  name = "pass-capstone-runtime-roles"
  role = aws_iam_role.grc_apply.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "PassLambdaRole"
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${local.name_prefix}-lambda-${local.suffix}"
        Condition = {
          StringEquals = {
            "iam:PassedToService" = "lambda.amazonaws.com"
          }
        }
      },
      {
        Sid      = "PassApiLoggingRole"
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${local.name_prefix}-api-logging-${local.suffix}"
        Condition = {
          StringEquals = {
            "iam:PassedToService" = "apigateway.amazonaws.com"
          }
        }
      },
    ]
  })
}

resource "aws_iam_role_policy" "grc_apply_lambda_update" {
  name = "update-capstone-lambda"
  role = aws_iam_role.grc_apply.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "UpdateIntakeFunctionConfiguration"
      Effect   = "Allow"
      Action   = "lambda:UpdateFunctionConfiguration"
      Resource = "arn:aws:lambda:${var.aws_region}:${data.aws_caller_identity.current.account_id}:function:${local.name_prefix}-handler-${local.suffix}"
    }]
  })
}
