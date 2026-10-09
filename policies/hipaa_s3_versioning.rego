# METADATA
# title: GAP-04 — Preserve intake upload versions
# description: Require versioning on the uploads bucket to support recovery from overwrites.
# custom:
#   control_id: 164.308(a)(7)
#   framework: hipaa
#   severity: high
#   remediation: Enable aws_s3_bucket_versioning.uploads and connect it to aws_s3_bucket.uploads.id.
package compliance.hipaa_s3_versioning

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

uploads_versioning := uploads_resource(
	"aws_s3_bucket_versioning.uploads",
	"aws_s3_bucket_versioning",
)

uploads_versioning_config := resource if {
	some resource in input.configuration.root_module.resources
	resource.address == "aws_s3_bucket_versioning.uploads"
}

uploads_references_bucket if {
	references := uploads_versioning_config.expressions.bucket.references
	"aws_s3_bucket.uploads.id" in references
}

# Compare bucket IDs when Terraform knows their values.
uploads_bucket_matches if {
	bucket_id := uploads_versioning.change.after.bucket
	expected_id := uploads_bucket.change.after.id

	is_string(bucket_id)
	bucket_id != ""
	bucket_id == expected_id
}

# Before creation, verify the connection through configuration references.
uploads_bucket_matches if {
	uploads_versioning.change.after_unknown.bucket == true
	uploads_bucket.change.after_unknown.id == true
	uploads_references_bucket
}

uploads_versioning_enabled if {
	uploads_versioning.change.after.versioning_configuration[0].status == "Enabled"
	uploads_references_bucket
	uploads_bucket_matches
}

deny contains message if {
	not uploads_versioning_enabled

	message := "HIPAA 164.308(a)(7) / GAP-04: uploads versioning must be Enabled and connected to aws_s3_bucket.uploads; configure aws_s3_bucket_versioning.uploads."
}
