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
      Sid    = "MaintainIntakeFunction"
      Effect = "Allow"
      Action = [
        "lambda:UpdateFunctionConfiguration",
        "lambda:UpdateFunctionCode",
        "lambda:PublishVersion",
        "lambda:AddPermission",
        "lambda:RemovePermission",
        "lambda:PutFunctionConcurrency",
        "lambda:DeleteFunctionConcurrency",
        "lambda:TagResource",
        "lambda:UntagResource",
      ]
      Resource = "arn:aws:lambda:${var.aws_region}:${data.aws_caller_identity.current.account_id}:function:${local.name_prefix}-handler-${local.suffix}"
    }]
  })
}

# Bootstrap these attachments with the local deployment principal. The apply
# role deliberately cannot administer itself, the plan role, or shared OIDC.
# Separate managed policies avoid the aggregate 10,240-byte inline-role limit.
locals {
  ci_ec2_arn_prefix = "arn:aws:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}"
  ci_network_resources = concat([
    aws_vpc.main.arn,
    aws_security_group.lambda.arn,
    aws_route_table.private.arn,
    aws_route_table.public.arn,
    aws_vpc_endpoint.s3.arn,
    aws_vpc_endpoint.dynamodb.arn,
    "${local.ci_ec2_arn_prefix}:internet-gateway/${aws_internet_gateway.main.id}",
  ], aws_subnet.private[*].arn, aws_subnet.public[*].arn)

  ci_maintenance_policies = {
    storage = {
      Version = "2012-10-17"
      Statement = [
        {
          Sid    = "MaintainCapstoneBuckets"
          Effect = "Allow"
          Action = [
            "s3:PutEncryptionConfiguration",
            "s3:PutBucketPublicAccessBlock",
            "s3:PutBucketVersioning",
            "s3:PutBucketPolicy",
            "s3:PutBucketTagging",
          ]
          Resource = [aws_s3_bucket.uploads.arn, aws_s3_bucket.vault.arn, aws_s3_bucket.trail.arn]
        },
        {
          Sid      = "RemoveWorkloadBucketPolicies"
          Effect   = "Allow"
          Action   = "s3:DeleteBucketPolicy"
          Resource = [aws_s3_bucket.uploads.arn, aws_s3_bucket.trail.arn]
        },
        {
          Sid    = "MaintainSubmissionsTable"
          Effect = "Allow"
          Action = [
            "dynamodb:UpdateTable",
            "dynamodb:UpdateContinuousBackups",
            "dynamodb:UpdateTimeToLive",
            "dynamodb:TagResource",
            "dynamodb:UntagResource",
          ]
          Resource = aws_dynamodb_table.intake.arn
        },
        {
          Sid    = "MaintainCapstoneKeys"
          Effect = "Allow"
          Action = [
            "kms:EnableKeyRotation",
            "kms:DisableKeyRotation",
            "kms:UpdateKeyDescription",
            "kms:TagResource",
            "kms:UntagResource",
          ]
          Resource = [aws_kms_key.uploads.arn, aws_kms_key.intake.arn, aws_kms_key.evidence.arn, aws_kms_key.trail.arn]
        },
        {
          Sid      = "AllowDynamoDBEncryptionGrant"
          Effect   = "Allow"
          Action   = "kms:CreateGrant"
          Resource = aws_kms_key.intake.arn
          Condition = {
            Bool         = { "kms:GrantIsForAWSResource" = "true" }
            StringEquals = { "kms:ViaService" = "dynamodb.${var.aws_region}.amazonaws.com" }
          }
        },
        {
          Sid      = "DescribeSubmissionsEncryptionKey"
          Effect   = "Allow"
          Action   = ["kms:DescribeKey", "kms:Decrypt"]
          Resource = aws_kms_key.intake.arn
          Condition = {
            StringEquals = { "kms:ViaService" = "dynamodb.${var.aws_region}.amazonaws.com" }
          }
        },
      ]
    }
    api_network = {
      Version = "2012-10-17"
      Statement = [
        {
          Sid      = "UpdateExistingRestApi"
          Effect   = "Allow"
          Action   = "apigateway:PATCH"
          Resource = aws_api_gateway_rest_api.intake.arn
        },
        {
          Sid      = "MaintainApiChildrenAndDeployments"
          Effect   = "Allow"
          Action   = ["apigateway:POST", "apigateway:PUT", "apigateway:PATCH", "apigateway:DELETE"]
          Resource = "${aws_api_gateway_rest_api.intake.arn}/*"
        },
        {
          Sid      = "AssociateIntakeWaf"
          Effect   = "Allow"
          Action   = "apigateway:SetWebACL"
          Resource = "${aws_api_gateway_rest_api.intake.arn}/stages/${aws_api_gateway_stage.default.stage_name}"
        },
        {
          Sid      = "MaintainIntakeWebAcl"
          Effect   = "Allow"
          Action   = ["wafv2:UpdateWebACL", "wafv2:AssociateWebACL", "wafv2:DisassociateWebACL", "wafv2:TagResource", "wafv2:UntagResource"]
          Resource = aws_wafv2_web_acl.intake.arn
        },
        {
          Sid    = "MaintainExistingVpcNetworking"
          Effect = "Allow"
          Action = [
            "ec2:ModifyVpcAttribute",
            "ec2:ModifySubnetAttribute",
            "ec2:ModifyVpcEndpoint",
            "ec2:AuthorizeSecurityGroupIngress",
            "ec2:AuthorizeSecurityGroupEgress",
            "ec2:RevokeSecurityGroupIngress",
            "ec2:RevokeSecurityGroupEgress",
            "ec2:CreateRoute",
            "ec2:ReplaceRoute",
            "ec2:DeleteRoute",
            "ec2:AssociateRouteTable",
            "ec2:DisassociateRouteTable",
            "ec2:ReplaceRouteTableAssociation",
            "ec2:CreateTags",
            "ec2:DeleteTags",
          ]
          Resource = local.ci_network_resources
        },
      ]
    }
    runtime_audit = {
      Version = "2012-10-17"
      Statement = [
        {
          Sid      = "MaintainRuntimeInlinePolicies"
          Effect   = "Allow"
          Action   = ["iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:TagRole", "iam:UntagRole"]
          Resource = [aws_iam_role.lambda.arn, aws_iam_role.api_logging.arn]
        },
        {
          Sid      = "MaintainRuntimeManagedPolicyAttachments"
          Effect   = "Allow"
          Action   = ["iam:AttachRolePolicy", "iam:DetachRolePolicy"]
          Resource = [aws_iam_role.lambda.arn, aws_iam_role.api_logging.arn]
          Condition = {
            ArnEquals = {
              "iam:PolicyARN" = [
                "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
                "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs",
              ]
            }
          }
        },
        {
          Sid      = "MaintainLogRetention"
          Effect   = "Allow"
          Action   = ["logs:PutRetentionPolicy", "logs:DeleteRetentionPolicy", "logs:AssociateKmsKey", "logs:DisassociateKmsKey", "logs:TagLogGroup", "logs:UntagLogGroup"]
          Resource = [aws_cloudwatch_log_group.lambda.arn, aws_cloudwatch_log_group.api_access.arn]
        },
        {
          Sid      = "MaintainLogTags"
          Effect   = "Allow"
          Action   = ["logs:TagResource", "logs:UntagResource"]
          Resource = [trimsuffix(aws_cloudwatch_log_group.lambda.arn, ":*"), trimsuffix(aws_cloudwatch_log_group.api_access.arn, ":*")]
        },
        {
          Sid      = "MaintainAsyncFailureQueue"
          Effect   = "Allow"
          Action   = ["sqs:SetQueueAttributes", "sqs:TagQueue", "sqs:UntagQueue"]
          Resource = aws_sqs_queue.intake_dlq.arn
        },
        {
          Sid      = "MaintainManagementTrail"
          Effect   = "Allow"
          Action   = ["cloudtrail:UpdateTrail", "cloudtrail:StartLogging", "cloudtrail:PutEventSelectors", "cloudtrail:AddTags", "cloudtrail:RemoveTags"]
          Resource = aws_cloudtrail.mgmt.arn
        },
      ]
    }
  }
}

# Scoped child-resource wildcard: API Gateway creates new deployment and
# resource IDs beneath this one API; no other REST APIs are authorized.
# tfsec:ignore:aws-iam-no-policy-wildcards
resource "aws_iam_policy" "grc_apply_maintenance" {
  for_each = local.ci_maintenance_policies

  name        = "${var.project_name}-ci-${replace(each.key, "_", "-")}"
  description = "Maintain existing capstone ${each.key} resources from main"
  policy      = jsonencode(each.value)
}

resource "aws_iam_role_policy_attachment" "grc_apply_maintenance" {
  for_each = local.ci_maintenance_policies

  role       = aws_iam_role.grc_apply.name
  policy_arn = aws_iam_policy.grc_apply_maintenance[each.key].arn
}
