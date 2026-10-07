# METADATA
# title: GAP-01 — Encrypt intake uploads with a customer-managed key
# description: Require the uploads bucket to use its customer-managed KMS key.
# custom:
#   control_id: 164.312(a)(2)(iv)
#   framework: hipaa
#   severity: high
#   remediation: Configure uploads SSE-KMS using aws_kms_key.uploads.arn.
package compliance.hipaa_s3_cmk

import rego.v1

uploads_resource(address, resource_type) := resource if {
	some resource in input.resource_changes
	resource.address == address
	resource.type == resource_type
	resource.mode == "managed"
	resource.change.after != null
}

uploads_bucket := uploads_resource(
	"aws_s3_bucket.uploads",
	"aws_s3_bucket",
)

uploads_encryption := uploads_resource(
	"aws_s3_bucket_server_side_encryption_configuration.uploads",
	"aws_s3_bucket_server_side_encryption_configuration",
)

uploads_key := uploads_resource(
	"aws_kms_key.uploads",
	"aws_kms_key",
)

uploads_encryption_config := resource if {
	some resource in input.configuration.root_module.resources
	resource.address == "aws_s3_bucket_server_side_encryption_configuration.uploads"
}

uploads_references_bucket if {
	references := uploads_encryption_config.expressions.bucket.references
	"aws_s3_bucket.uploads.id" in references
}

uploads_references_key if {
	references := uploads_encryption_config.expressions.rule[0].apply_server_side_encryption_by_default[0].kms_master_key_id.references
	"aws_kms_key.uploads.arn" in references
}

# Compare resolved bucket IDs when they are known.
uploads_bucket_matches if {
	bucket_id := uploads_encryption.change.after.bucket
	expected_id := uploads_bucket.change.after.id

	is_string(bucket_id)
	bucket_id != ""
	bucket_id == expected_id
}

# Accept unknown bucket IDs only with the required configuration reference.
uploads_bucket_matches if {
	uploads_encryption.change.after_unknown.bucket == true
	uploads_bucket.change.after_unknown.id == true
	uploads_references_bucket
}

# Compare resolved key ARNs when they are known.
uploads_key_matches if {
	key_arn := uploads_encryption.change.after.rule[0].apply_server_side_encryption_by_default[0].kms_master_key_id
	expected_arn := uploads_key.change.after.arn

	is_string(key_arn)
	key_arn != ""
	key_arn == expected_arn
}

# Accept unknown key ARNs only with the required configuration reference.
uploads_key_matches if {
	uploads_encryption.change.after_unknown.rule[0].apply_server_side_encryption_by_default[0].kms_master_key_id == true
	uploads_key.change.after_unknown.arn == true
	uploads_references_key
}

uploads_uses_cmk if {
	uploads_encryption.change.after.rule[0].apply_server_side_encryption_by_default[0].sse_algorithm == "aws:kms"
	uploads_key.change.after.is_enabled == true

	uploads_references_bucket
	uploads_references_key
	uploads_bucket_matches
	uploads_key_matches
}

deny contains msg if {
	not uploads_uses_cmk

	msg := "HIPAA 164.312(a)(2)(iv) / GAP-01: aws_s3_bucket.uploads must use SSE-KMS with aws_kms_key.uploads."
}
