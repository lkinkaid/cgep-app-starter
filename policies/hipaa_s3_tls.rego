# METADATA
# title: GAP-03 — Require TLS for intake uploads
# description: Require an unconditional deny of non-TLS uploads-bucket requests.
# custom:
#   control_id: 164.312(e)(1)
#   framework: hipaa
#   severity: high
#   remediation: Add an uploads bucket policy denying s3:* when aws:SecureTransport is false.
package compliance.hipaa_s3_tls

import rego.v1

uploads_bucket := resource if {
	some resource in input.resource_changes
	resource.address == "aws_s3_bucket.uploads"
	resource.type == "aws_s3_bucket"
	resource.mode == "managed"
	resource.change.after != null
}

uploads_policy := resource if {
	some resource in input.resource_changes
	resource.address == "aws_s3_bucket_policy.uploads"
	resource.type == "aws_s3_bucket_policy"
	resource.mode == "managed"
	resource.change.after != null
}

uploads_policy_references_bucket if {
	some resource in input.configuration.root_module.resources
	resource.address == "aws_s3_bucket_policy.uploads"

	"aws_s3_bucket.uploads.id" in resource.expressions.bucket.references
}

uploads_policy_bucket_matches if {
	bucket_id := uploads_policy.change.after.bucket
	expected_id := uploads_bucket.change.after.id

	is_string(bucket_id)
	bucket_id != ""
	bucket_id == expected_id
}

uploads_policy_bucket_matches if {
	uploads_policy.change.after_unknown.bucket == true
	uploads_bucket.change.after_unknown.id == true
	uploads_policy_references_bucket
}

insecure_transport(value) if value == "false"

insecure_transport(value) if value == false

uploads_denies_non_tls if {
	uploads_policy_references_bucket
	uploads_policy_bucket_matches

	document := json.unmarshal(uploads_policy.change.after.policy)
	some statement in document.Statement

	statement.Effect == "Deny"
	statement.Principal == "*"
	statement.Action == "s3:*"
	bucket_arn := uploads_bucket.change.after.arn
	is_string(bucket_arn)
	is_array(statement.Resource)
	count(statement.Resource) == 2

	{resource | some resource in statement.Resource} == {
		bucket_arn,
		sprintf("%s/*", [bucket_arn]),
	}

	insecure_transport(statement.Condition.Bool["aws:SecureTransport"])

	# Extra conditions could restrict when the deny applies.
	object.keys(statement.Condition) == {"Bool"}
	object.keys(statement.Condition.Bool) == {"aws:SecureTransport"}
}

deny contains msg if {
	not uploads_denies_non_tls

	msg := "HIPAA 164.312(e)(1) / GAP-03: aws_s3_bucket.uploads must deny all non-TLS requests through its bucket policy."
}
