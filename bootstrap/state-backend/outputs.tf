# bootstrap/state-backend/outputs.tf
# This stack owns the bucket; the capstone backend continues to consume it.
output "state_bucket" {
  description = "Existing S3 bucket for capstone remote state."
  value       = aws_s3_bucket.state.id
}
