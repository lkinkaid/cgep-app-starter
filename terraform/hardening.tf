######################################################################
# GAP-01 — Encrypt uploads with a customer-managed KMS key.
######################################################################

resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.uploads.arn
    }
  }
}

# Manage uploads privacy explicitly rather than relying on S3 defaults.
resource "aws_s3_bucket_public_access_block" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

# The handler uses a single PutObject request and needs GenerateDataKey
# to upload with SSE-KMS. Restrict key use to S3 and this bucket's objects.
resource "aws_iam_role_policy" "lambda_uploads_kms" {
  name = "intake-uploads-kms"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "EncryptUploadsThroughS3"
      Effect   = "Allow"
      Action   = "kms:GenerateDataKey"
      Resource = aws_kms_key.uploads.arn
      Condition = {
        StringEquals = {
          "kms:ViaService" = "s3.${var.aws_region}.amazonaws.com"
        }
        StringLike = {
          "kms:EncryptionContext:aws:s3:arn" = "${aws_s3_bucket.uploads.arn}/*"
        }
      }
    }]
  })
}

# Default encryption applies to new uploads; existing objects must be
# copied/re-encrypted separately. Explicit encryption overrides require
# a bucket policy to enforce use of this key for every writer.

######################################################################
# GAP-02 — Allow Lambda to access the CMK-encrypted submissions table.
# Encryption is configured on aws_dynamodb_table.intake in main.tf;
# DynamoDB has no separate Terraform encryption configuration resource.
######################################################################

# DynamoDB decrypts its table key on behalf of the caller, including for
# PutItem. Restrict this permission to DynamoDB and this table's context.
resource "aws_iam_role_policy" "lambda_intake_kms" {
  name = "intake-submissions-kms"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "UseSubmissionsKeyThroughDynamoDB"
      Effect   = "Allow"
      Action   = "kms:Decrypt"
      Resource = aws_kms_key.intake.arn
      Condition = {
        StringEquals = {
          "kms:ViaService"                               = "dynamodb.${var.aws_region}.amazonaws.com"
          "kms:EncryptionContext:aws:dynamodb:tableName" = aws_dynamodb_table.intake.name
        }
      }
    }]
  })
}

# The Terraform deployment principal needs KMS table-management permissions
# (including CreateGrant) to configure encryption. These are deployment
# permissions, not permissions required by the Lambda PutItem handler.

######################################################################
# GAP-03 — Deny non-TLS access to the uploads bucket and its objects.
######################################################################

resource "aws_s3_bucket_policy" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        aws_s3_bucket.uploads.arn,
        "${aws_s3_bucket.uploads.arn}/*",
      ]
      Condition = {
        Bool = {
          "aws:SecureTransport" = "false"
        }
      }
    }]
  })
}

######################################################################
# GAP-04 — Preserve previous upload versions for recovery after overwrites.
######################################################################

resource "aws_s3_bucket_versioning" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  versioning_configuration {
    status = "Suspended"
  }
}

######################################################################
# GAP-05 — Attach Lambda to the starter VPC with private data-store access.
# The vpc_config block is on aws_lambda_function.intake in main.tf.
######################################################################

# Private subnets share a route table with no internet default route.
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  tags = { Name = "${local.name_prefix}-private-rt" }
}

resource "aws_route_table_association" "private" {
  count          = length(aws_subnet.private)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# Gateway endpoints keep the handler's S3 and DynamoDB calls on the AWS
# network without a NAT gateway. Endpoint policies limit workload access.
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:PutObject"
      Resource  = "${aws_s3_bucket.uploads.arn}/uploads/*"
      Condition = {
        ArnEquals = { "aws:PrincipalArn" = aws_iam_role.lambda.arn }
      }
    }]
  })

  tags = { Name = "${local.name_prefix}-s3-endpoint" }
}

resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "dynamodb:PutItem"
      Resource  = aws_dynamodb_table.intake.arn
      Condition = {
        ArnEquals = { "aws:PrincipalArn" = aws_iam_role.lambda.arn }
      }
    }]
  })

  tags = { Name = "${local.name_prefix}-dynamodb-endpoint" }
}

# No inbound rules. Permit outbound HTTPS only to the two service prefix
# lists. Security groups do not filter queries to the VPC DNS resolver.
resource "aws_security_group" "lambda" {
  name_prefix = "${local.name_prefix}-lambda-"
  description = "Lambda HTTPS access to S3 and DynamoDB only"
  vpc_id      = aws_vpc.main.id

  egress {
    description = "HTTPS to S3 and DynamoDB gateway endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    prefix_list_ids = [
      aws_vpc_endpoint.s3.prefix_list_id,
      aws_vpc_endpoint.dynamodb.prefix_list_id
    ]
  }

  tags = { Name = "${local.name_prefix}-lambda-sg" }
}

# Scoped scanner exception: AWS documents Resource = "*" for Lambda's
# six EC2 actions needed to manage VPC network interfaces.
# https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html
# tfsec:ignore:aws-iam-no-policy-wildcards
resource "aws_iam_role_policy" "lambda_vpc" {
  name = "intake-vpc-network-interfaces"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "ManageLambdaNetworkInterfaces"
      Effect = "Allow"
      Action = [
        "ec2:CreateNetworkInterface",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeSubnets",
        "ec2:DeleteNetworkInterface",
        "ec2:AssignPrivateIpAddresses",
        "ec2:UnassignPrivateIpAddresses"
      ]
      Resource = "*"
    }]
  })
}

######################################################################
# GAP-06 — Retain failed async events and permit Lambda X-Ray telemetry.
# Concurrency, dead_letter_config, and tracing_config are in main.tf.
######################################################################

# Create the default Lambda log group before invocation so Terraform
# manages retention and removes the logs during sandbox teardown.
# Keep the name in sync with aws_lambda_function.intake.function_name;
# referencing that resource here would create a dependency cycle.
resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${local.name_prefix}-handler-${local.suffix}"
  retention_in_days = 90

  tags = { Name = "${local.name_prefix}-lambda-logs" }
}

resource "aws_sqs_queue" "intake_dlq" {
  name                      = "${local.name_prefix}-dlq-${local.suffix}"
  message_retention_seconds = 1209600 # 14 days for investigation and recovery.
  sqs_managed_sse_enabled   = true

  tags = { Name = "${local.name_prefix}-dlq-${local.suffix}" }
}

# Lambda delivers DLQ events and built-in X-Ray telemetry through the
# managed service; the handler does not call SQS or X-Ray directly.
resource "aws_iam_role_policy" "lambda_observability" {
  name = "intake-dlq-and-tracing"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "SendFailedAsyncEvents"
        Effect   = "Allow"
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.intake_dlq.arn
      },
      {
        Sid    = "PublishXRayTelemetry"
        Effect = "Allow"
        Action = [
          "xray:PutTraceSegments",
          "xray:PutTelemetryRecords"
        ]
        # X-Ray ingestion actions do not support resource-level scoping.
        Resource = "*"
      }
    ]
  })
}

######################################################################
# GAP-07 — Grant only the data-store actions used by lambda/handler.py.
# Preserve the starter policy's resource address and IAM policy name.
######################################################################

data "aws_iam_policy_document" "lambda_data_access" {
  statement {
    sid       = "WriteIntakeSubmissions"
    effect    = "Allow"
    actions   = ["dynamodb:PutItem"]
    resources = [aws_dynamodb_table.intake.arn]
  }

  statement {
    sid       = "WriteIntakeUploads"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.uploads.arn}/uploads/*"]
  }
}

resource "aws_iam_role_policy" "lambda_inline" {
  name = "intake-data-access"
  role = aws_iam_role.lambda.id

  policy = data.aws_iam_policy_document.lambda_data_access.json
}

######################################################################
# GAP-08 — API access logs, throttling, and Regional WAF protection.
######################################################################

resource "aws_cloudwatch_log_group" "api_access" {
  name              = "/aws/apigateway/${local.name_prefix}-${local.suffix}/access"
  retention_in_days = 90

  tags = { Name = "${local.name_prefix}-api-access" }
}

# API Gateway's logging role setting is shared by REST APIs in this region.
resource "aws_iam_role" "api_logging" {
  name = "${local.name_prefix}-api-logging-${local.suffix}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "apigateway.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "api_logging" {
  role       = aws_iam_role.api_logging.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"
}

resource "aws_api_gateway_account" "logging" {
  cloudwatch_role_arn = aws_iam_role.api_logging.arn

  # AWS provider 5.x requires this to clear the regional logging role
  # during sandbox teardown. Revisit when upgrading the provider.
  reset_on_delete = true

  depends_on = [aws_iam_role_policy_attachment.api_logging]
}

resource "aws_api_gateway_method_settings" "intake" {
  rest_api_id = aws_api_gateway_rest_api.intake.id
  stage_name  = aws_api_gateway_stage.default.stage_name
  method_path = "*/*"

  settings {
    throttling_burst_limit = 10
    throttling_rate_limit  = 5
    metrics_enabled        = true
    logging_level          = "OFF"
    data_trace_enabled     = false
  }
}

resource "aws_wafv2_web_acl" "intake" {
  name        = "${local.name_prefix}-api-${local.suffix}"
  description = "Protect the patient intake REST API"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "AWSKnownBadInputs"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "IntakeKnownBadInputs"
      sampled_requests_enabled   = false
    }
  }

  rule {
    name     = "AWSSQLInjection"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "IntakeSQLInjection"
      sampled_requests_enabled   = false
    }
  }

  rule {
    name     = "LimitRequestsPerIP"
    priority = 3

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 1000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "IntakeRateLimit"
      sampled_requests_enabled   = false
    }
  }

  # Disable sampled request capture to avoid retaining patient payloads.
  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "IntakeWebACL"
    sampled_requests_enabled   = false
  }
}

resource "aws_wafv2_web_acl_association" "intake" {
  resource_arn = aws_api_gateway_stage.default.arn
  web_acl_arn  = aws_wafv2_web_acl.intake.arn
}
