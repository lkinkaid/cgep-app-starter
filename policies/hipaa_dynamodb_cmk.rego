# METADATA
# title: GAP-02 — Encrypt intake submissions with a customer-managed key
# description: Require the intake DynamoDB table to use the intake KMS key.
# custom:
#   control_id: 164.312(a)(2)(iv)
#   framework: hipaa
#   severity: high
#   remediation: Enable DynamoDB server-side encryption using aws_kms_key.intake.arn.
package compliance.hipaa_dynamodb_cmk

import rego.v1

gap02_message := "HIPAA 164.312(a)(2)(iv) / GAP-02: intake submissions must use the customer-managed intake KMS key."

intake_table := resource if {
	some resource in input.resource_changes
	resource.address == "aws_dynamodb_table.intake"
	resource.type == "aws_dynamodb_table"
	resource.mode == "managed"
}

intake_key := resource if {
	some resource in input.resource_changes
	resource.address == "aws_kms_key.intake"
	resource.type == "aws_kms_key"
	resource.mode == "managed"
}

# Verify the Terraform configuration connects the table to our key.
intake_references_cmk if {
	some resource in input.configuration.root_module.resources
	resource.address == "aws_dynamodb_table.intake"

	references := resource.expressions.server_side_encryption[0].kms_key_arn.references
	"aws_kms_key.intake.arn" in references
}

# For an existing key, compare the resolved ARNs.
intake_key_matches if {
	table_arn := intake_table.change.after.server_side_encryption[0].kms_key_arn
	key_arn := intake_key.change.after.arn

	is_string(table_arn)
	is_string(key_arn)
	table_arn != ""
	table_arn == key_arn
}

# For a new key, the ARN is unknown until apply.
intake_key_matches if {
	intake_table.change.after_unknown.server_side_encryption[0].kms_key_arn == true
	intake_key.change.after_unknown.arn == true
	intake_references_cmk
}

intake_uses_cmk if {
	intake_table.change.after.server_side_encryption[0].enabled == true
	intake_key.change.after.is_enabled == true
	intake_references_cmk
	intake_key_matches
}

deny contains gap02_message if {
	not intake_uses_cmk
}
