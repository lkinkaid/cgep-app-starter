# Step 1: Expose identifiers for testing and CI configuration
# terraform/outputs.tf

# Wait for the WAF association, method settings, and invocation permission
# before presenting the endpoint used for the sandbox smoke test.
output "api_url" {
  value       = "${aws_api_gateway_stage.default.invoke_url}/intake"
  description = "WAF-protected POST /intake endpoint."
  depends_on  = [aws_wafv2_web_acl_association.intake, aws_api_gateway_method_settings.intake, aws_lambda_permission.apigw]
}

# Step 2: Expose workload names and network identifiers for inspection
output "intake_table" {
  value       = aws_dynamodb_table.intake.name
  description = "DynamoDB table holding patient submissions."
}

output "uploads_bucket" {
  value       = aws_s3_bucket.uploads.id
  description = "S3 bucket where intake attachments land."
}

output "lambda_function_name" {
  value = aws_lambda_function.intake.function_name
}

output "vpc_id" {
  value = aws_vpc.main.id
}

output "private_subnet_ids" {
  value = aws_subnet.private[*].id
}

# Step 3: Expose CI role and vault identifiers
# role_arn is the plan role; apply_role_arn is the main deployment role.
# Set repository configuration using these outputs rather than credentials.
output "role_arn" { value = aws_iam_role.grc_gate.arn }

output "evidence_vault" {
  description = "Bucket holding signed capstone evidence."
  value       = aws_s3_bucket.vault.id
}
output "apply_role_arn" {
  description = "GitHub Actions deployment role for main"
  value       = aws_iam_role.grc_apply.arn
}
