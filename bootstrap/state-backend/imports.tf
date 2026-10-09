# Step 4: Adopt existing resources rather than creating a second bucket
# bootstrap/state-backend/imports.tf
# Review the import plan before applying; each AWS object has one state owner.
import {
  to = aws_s3_bucket.state
  id = "acme-health-intake-tfstate-420539147061"
}

import {
  to = aws_s3_bucket_versioning.state
  id = "acme-health-intake-tfstate-420539147061"
}

import {
  to = aws_s3_bucket_server_side_encryption_configuration.state
  id = "acme-health-intake-tfstate-420539147061"
}

import {
  to = aws_s3_bucket_public_access_block.state
  id = "acme-health-intake-tfstate-420539147061"
}

import {
  to = aws_s3_bucket_ownership_controls.state
  id = "acme-health-intake-tfstate-420539147061"
}
