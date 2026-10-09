# Step 1: Connect Terraform to the shared state backend
# terraform/backend.tf

# The state bucket is bootstrapped separately from this workload and the
# evidence vault. The key identifies the shared capstone state object.
# Encryption protects stored state; the S3 lockfile coordinates writers.
# CI permissions distinguish state writes from temporary lock deletion.
terraform {
  backend "s3" {
    bucket       = "acme-health-intake-tfstate-420539147061"
    key          = "capstone/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }
}
