terraform {
  backend "s3" {
    bucket       = "acme-health-intake-tfstate-420539147061"
    key          = "capstone/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }
}
