# METADATA
# title: GAP-07 — Restrict Lambda data-access permissions
# description: Limit the intake data policy to submission and upload writes.
# custom:
#   control_id: 164.312(a)(1)
#   framework: hipaa
#   severity: high
#   remediation: Grant only dynamodb:PutItem and s3:PutObject through the intake data-access document.
package compliance.hipaa_lambda_least_privilege

import rego.v1

data_document := resource if {
	some resource in input.resource_changes
	resource.address == "data.aws_iam_policy_document.lambda_data_access"
	resource.type == "aws_iam_policy_document"
	resource.mode == "data"
	resource.change.after != null
}

# An unchanged data source can appear only in the refreshed prior state.
data_document := {
	"change": {
		"after": resource.values,
		"after_unknown": {},
	},
} if {
	not data_document_has_change

	some resource in input.prior_state.values.root_module.resources
	resource.address == "data.aws_iam_policy_document.lambda_data_access"
	resource.type == "aws_iam_policy_document"
	resource.mode == "data"
}

data_document_has_change if {
	some resource in input.resource_changes
	resource.address == "data.aws_iam_policy_document.lambda_data_access"
}

inline_policy := resource if {
	some resource in input.resource_changes
	resource.address == "aws_iam_role_policy.lambda_inline"
	resource.type == "aws_iam_role_policy"
	resource.mode == "managed"
	resource.change.after != null
}

configuration_resource(address) := resource if {
	some resource in input.configuration.root_module.resources
	resource.address == address
}

reference_set(expression) := {ref |
	some ref in expression.references
}

empty_value(value) if value == null

empty_value(value) if value == []

policy_is_connected if {
	config := configuration_resource("aws_iam_role_policy.lambda_inline")

	reference_set(config.expressions.policy) == {
		"data.aws_iam_policy_document.lambda_data_access.json",
		"data.aws_iam_policy_document.lambda_data_access",
	}

	reference_set(config.expressions.role) == {
		"aws_iam_role.lambda.id",
		"aws_iam_role.lambda",
	}
}

# Existing plans: verify the actual inline JSON matches the checked document.
policy_document_matches if {
	is_string(inline_policy.change.after.policy)
	is_string(data_document.change.after.json)

	json.unmarshal(inline_policy.change.after.policy) == json.unmarshal(data_document.change.after.json)
}

# Creation plans: both documents are unknown, with the connection checked above.
policy_document_matches if {
	inline_policy.change.after_unknown.policy == true
	data_document.change.after_unknown.json == true

	object.get(inline_policy.change.after, "policy", null) == null
	object.get(data_document.change.after, "json", null) == null
}

# Do not permit additional policy documents to be merged into this document.
document_has_no_merges if {
	config := configuration_resource("data.aws_iam_policy_document.lambda_data_access")

	object.keys(config.expressions) - {"statement", "version"} == set()

	empty_value(object.get(data_document.change.after, "source_policy_documents", null))
	empty_value(object.get(data_document.change.after, "override_policy_documents", null))
	empty_value(object.get(data_document.change.after, "source_json", null))
	empty_value(object.get(data_document.change.after, "override_json", null))
}

expected_action("WriteIntakeSubmissions") := "dynamodb:PutItem"

expected_action("WriteIntakeUploads") := "s3:PutObject"

expected_references("WriteIntakeSubmissions") := {
	"aws_dynamodb_table.intake.arn",
	"aws_dynamodb_table.intake",
}

expected_references("WriteIntakeUploads") := {
	"aws_s3_bucket.uploads.arn",
	"aws_s3_bucket.uploads",
}

expected_resource("WriteIntakeSubmissions") := resource.change.after.arn if {
	some resource in input.resource_changes
	resource.address == "aws_dynamodb_table.intake"
	resource.type == "aws_dynamodb_table"
	resource.mode == "managed"
}

expected_resource("WriteIntakeUploads") := sprintf("%s/uploads/*", [resource.change.after.arn]) if {
	some resource in input.resource_changes
	resource.address == "aws_s3_bucket.uploads"
	resource.type == "aws_s3_bucket"
	resource.mode == "managed"
	is_string(resource.change.after.arn)
}

statement_references_resource(statement) if {
	config := configuration_resource("data.aws_iam_policy_document.lambda_data_access")

	some configured_statement in config.expressions.statement
	configured_statement.sid.constant_value == statement.sid

	reference_set(configured_statement.resources) == expected_references(statement.sid)
}

statement_resource_matches(statement, index) if {
	is_string(statement.resources[0])
	statement.resources[0] == expected_resource(statement.sid)
}

statement_resource_matches(statement, index) if {
	statement.resources[0] == null
	data_document.change.after_unknown.statement[index].resources[0] == true
	statement_references_resource(statement)
}

statement_is_allowed(statement, index) if {
	statement.effect == "Allow"
	statement.actions == [expected_action(statement.sid)]

	empty_value(object.get(statement, "not_actions", null))
	empty_value(object.get(statement, "not_resources", null))
	empty_value(object.get(statement, "principals", null))
	empty_value(object.get(statement, "not_principals", null))

	count(statement.resources) == 1
	statement_references_resource(statement)
	statement_resource_matches(statement, index)
}

# The supporting inline policies are explicitly permitted.
approved_inline_addresses := {
	"aws_iam_role_policy.lambda_inline",
	"aws_iam_role_policy.lambda_uploads_kms",
	"aws_iam_role_policy.lambda_intake_kms",
	"aws_iam_role_policy.lambda_vpc",
	"aws_iam_role_policy.lambda_observability",
}

lambda_role := resource if {
	some resource in input.resource_changes
	resource.address == "aws_iam_role.lambda"
	resource.type == "aws_iam_role"
	resource.mode == "managed"
	resource.change.after != null
}

# Creation plans: identify the role through configuration references.
attached_to_lambda(resource) if {
	config := configuration_resource(resource.address)
	"aws_iam_role.lambda" in reference_set(config.expressions.role)
}

# Existing plans: identify the role through its resolved name.
attached_to_lambda(resource) if {
	role_name := resource.change.after.role
	is_string(role_name)
	role_name != ""
	role_name == lambda_role.change.after.name
}

approved_lambda_policy(resource) if {
	resource.type == "aws_iam_role_policy"
	resource.address in approved_inline_addresses
}

approved_lambda_policy(resource) if {
	resource.type == "aws_iam_role_policy_attachment"
	resource.change.after.policy_arn == "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

lambda_policy_inventory_allowed if {
	every resource in input.resource_changes {
		lambda_policy_inventory_entry_allowed(resource)
	}
}

# Resources outside this check do not affect the result.
lambda_policy_inventory_entry_allowed(resource) if {
	resource.type != "aws_iam_role_policy"
	resource.type != "aws_iam_role_policy_attachment"
}

lambda_policy_inventory_entry_allowed(resource) if {
	resource.mode != "managed"
}

# A deleted policy grants no permissions in the planned result.
lambda_policy_inventory_entry_allowed(resource) if {
	resource.change.after == null
}

lambda_policy_inventory_entry_allowed(resource) if {
	not attached_to_lambda(resource)
}

lambda_policy_inventory_entry_allowed(resource) if {
	approved_lambda_policy(resource)
}

data_access_is_restricted if {
	policy_is_connected
	policy_document_matches
	document_has_no_merges
	lambda_policy_inventory_allowed

	statements := data_document.change.after.statement
	count(statements) == 2

	{statement.sid | some statement in statements} == {
		"WriteIntakeSubmissions",
		"WriteIntakeUploads",
	}

	every index, statement in statements {
		statement_is_allowed(statement, index)
	}
}

deny contains msg if {
	not data_access_is_restricted

	msg := "HIPAA 164.312(a)(1) / GAP-07: aws_iam_role_policy.lambda_inline must grant only intake submission and upload writes through the approved data-access document."
}

deny contains msg if {
	some resource in input.resource_changes

	resource.mode == "managed"
	resource.change.after != null
	resource.type in {
		"aws_iam_role_policy",
		"aws_iam_role_policy_attachment",
	}

	attached_to_lambda(resource)
	not approved_lambda_policy(resource)

	msg := sprintf(
		"HIPAA 164.312(a)(1) / GAP-07: %s adds an unapproved policy to the intake Lambda role.",
		[resource.address],
	)
}
