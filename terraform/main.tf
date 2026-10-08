######################################################################
# Acme Health — Patient Intake API (CGE-P Capstone Starter)
#
# This starter workload is hardened with the controls in hardening.tf
# and the customer-managed keys in kms.tf. See GAPS.md for the original
# gaps these Terraform resources remediate.
######################################################################

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws     = { source = "hashicorp/aws", version = "~> 5.0" }
    random  = { source = "hashicorp/random", version = "~> 3.6" }
    archive = { source = "hashicorp/archive", version = "~> 2.4" }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "acme-health-intake"
      ManagedBy = "terraform"
      Workload  = "patient-intake-api"
      DataClass = "phi"
    }
  }
}

resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  name_prefix = "acme-health-intake"
  suffix      = random_id.suffix.hex
}

######################################################################
# Networking — Starter VPC used by Lambda in the private subnets.
# Two public + two private subnets across two AZs.
######################################################################

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "main" {
  cidr_block           = "10.42.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "${local.name_prefix}-vpc" }
}

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.42.${count.index}.0/24"
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = false

  tags = { Name = "${local.name_prefix}-public-${count.index}" }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.42.${count.index + 10}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = { Name = "${local.name_prefix}-private-${count.index}" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = { Name = "${local.name_prefix}-igw" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = { Name = "${local.name_prefix}-public-rt" }
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

######################################################################
# DynamoDB — submissions table.
# GAP-02: remediated with a customer-managed KMS key in kms.tf.
######################################################################

resource "aws_dynamodb_table" "intake" {
  name         = "${local.name_prefix}-submissions-${local.suffix}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "submission_id"

  attribute {
    name = "submission_id"
    type = "S"
  }

  # GAP-02: use the customer-managed key defined in kms.tf.
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.intake.arn
  }
}

######################################################################
# S3 — uploads bucket.
# GAP-01: remediated by the SSE-KMS configuration in hardening.tf,
#         using aws_kms_key.uploads defined in kms.tf.
# GAP-03: remediated by the TLS-enforcing bucket policy in hardening.tf
#         (denies requests when aws:SecureTransport is false).
# GAP-04: remediated by enabling bucket versioning in hardening.tf.
######################################################################

resource "aws_s3_bucket" "uploads" {
  bucket = "${local.name_prefix}-uploads-${local.suffix}"

  # Sandbox teardown convenience: allow Terraform to delete all objects,
  # versions, and delete markers when destroying this bucket.
  force_destroy = true
}

# Default SSE-KMS encryption, Lambda's KMS upload permission, TLS
# enforcement, public access blocking, and versioning are in hardening.tf.

######################################################################
# Lambda — the intake handler.
# GAP-05: remediated using the existing VPC and networking in hardening.tf.
# GAP-06: reserved concurrency, async DLQ, and active X-Ray tracing configured.
# GAP-07: workload data access is restricted to handler writes in hardening.tf.
######################################################################

data "archive_file" "handler" {
  type        = "zip"
  source_file = "${path.module}/lambda/handler.py"
  output_path = "${path.module}/lambda/handler.zip"
}

resource "aws_iam_role" "lambda" {
  name = "${local.name_prefix}-lambda-${local.suffix}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# GAP-07: the least-privilege lambda_inline policy is defined in hardening.tf.

resource "aws_lambda_function" "intake" {
  function_name    = "${local.name_prefix}-handler-${local.suffix}"
  role             = aws_iam_role.lambda.arn
  handler          = "handler.handler"
  runtime          = "python3.12"
  filename         = data.archive_file.handler.output_path
  source_code_hash = data.archive_file.handler.output_base64sha256
  timeout          = 10

  environment {
    variables = {
      INTAKE_TABLE  = aws_dynamodb_table.intake.name
      UPLOAD_BUCKET = aws_s3_bucket.uploads.id
    }
  }

  # GAP-06: cap parallel executions at 10 for this sandbox workload.
  reserved_concurrent_executions = 10

  # Lambda DLQs retain failed asynchronous events. API Gateway invokes
  # synchronously, so API failures return to the caller instead of this queue.
  dead_letter_config {
    target_arn = aws_sqs_queue.intake_dlq.arn
  }

  tracing_config {
    mode = "Active"
  }

  # GAP-05: use the starter's private subnets and restricted security group.
  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.lambda.id]
  }

  # IAM policies, endpoint routes, S3 protections, and the log group must
  # be ready before the handler runs.
  depends_on = [
    aws_iam_role_policy_attachment.lambda_basic,
    aws_iam_role_policy.lambda_inline,
    aws_iam_role_policy.lambda_vpc,
    aws_iam_role_policy.lambda_observability,
    aws_iam_role_policy.lambda_uploads_kms,
    aws_iam_role_policy.lambda_intake_kms,
    aws_route_table_association.private,
    aws_vpc_endpoint.s3,
    aws_vpc_endpoint.dynamodb,
    aws_s3_bucket_server_side_encryption_configuration.uploads,
    aws_s3_bucket_policy.uploads,
    aws_s3_bucket_versioning.uploads,
    aws_s3_bucket_public_access_block.uploads,
    aws_cloudwatch_log_group.lambda
  ]
}

######################################################################
# API Gateway — Regional REST API in front of the existing Lambda.
# GAP-08: access logs, throttling, and a directly associated WAF web ACL.
# REST API is used because HTTP APIs do not support direct WAF association.
######################################################################

resource "aws_api_gateway_rest_api" "intake" {
  name = "${local.name_prefix}-api-${local.suffix}"

  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

resource "aws_api_gateway_resource" "intake" {
  rest_api_id = aws_api_gateway_rest_api.intake.id
  parent_id   = aws_api_gateway_rest_api.intake.root_resource_id
  path_part   = "intake"
}

resource "aws_api_gateway_method" "intake" {
  rest_api_id   = aws_api_gateway_rest_api.intake.id
  resource_id   = aws_api_gateway_resource.intake.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "lambda" {
  rest_api_id             = aws_api_gateway_rest_api.intake.id
  resource_id             = aws_api_gateway_resource.intake.id
  http_method             = aws_api_gateway_method.intake.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.intake.invoke_arn
}

resource "aws_api_gateway_deployment" "intake" {
  rest_api_id = aws_api_gateway_rest_api.intake.id

  triggers = {
    redeployment = sha1(jsonencode({
      path          = aws_api_gateway_resource.intake.path_part
      method        = aws_api_gateway_method.intake.http_method
      authorization = aws_api_gateway_method.intake.authorization
      integration   = aws_api_gateway_integration.lambda
    }))
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_api_gateway_stage" "default" {
  rest_api_id          = aws_api_gateway_rest_api.intake.id
  deployment_id        = aws_api_gateway_deployment.intake.id
  stage_name           = "prod"
  xray_tracing_enabled = true

  # Record request metadata without logging request or response bodies.
  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_access.arn
    format = jsonencode({
      requestId      = "$context.requestId"
      sourceIp       = "$context.identity.sourceIp"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      resourcePath   = "$context.resourcePath"
      status         = "$context.status"
      responseLength = "$context.responseLength"
    })
  }

  depends_on = [aws_api_gateway_account.logging]
}

resource "aws_lambda_permission" "apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.intake.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.intake.execution_arn}/prod/POST/intake"
}
