# METADATA
# title: GAP-07 — Restrict Lambda data-access permissions
# description: Restrict all Terraform-managed intake Lambda policies to approved permissions.
# custom:
#   control_id: 164.312(a)(1)
#   framework: hipaa
#   severity: high
#   remediation: Restrict data writes, KMS, networking, and telemetry policies to approved actions, resources, and conditions; resolve unknown supporting policy JSON before apply.
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

# Approved addresses identify candidates; supporting policy contents are also checked.
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
	resource.address == "aws_iam_role_policy.lambda_inline"
}

approved_lambda_policy(resource) if {
	resource.type == "aws_iam_role_policy"
	supporting_policy_allowed(resource.address, resource.change.after.policy)
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
	resource.type != "aws_iam_policy_attachment"
	resource.type != "aws_iam_role_policy_attachments_exclusive"
	resource.type != "aws_iam_role_policies_exclusive"
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
		"aws_iam_policy_attachment",
		"aws_iam_role_policy_attachments_exclusive",
		"aws_iam_role_policies_exclusive",
	}

	attached_to_lambda(resource)
	not approved_lambda_policy(resource)

	msg := sprintf(
		"HIPAA 164.312(a)(1) / GAP-07: %s has unapproved or unverifiable intake Lambda permissions; restrict actions, resources, and conditions and resolve unknown policy JSON.",
		[resource.address],
	)
}

# A resolved policy is compared semantically: scalar/list IAM forms and action
# ordering are equivalent. Additional statement fields are rejected, including
# NotAction/NotResource and conditions that broaden or replace required limits.
values_set(value) := {value} if is_string(value)
values_set(value) := {item | some item in value} if is_array(value)

planned_value(address, attribute) := value if {
	some resource in input.resource_changes
	resource.address == address
	resource.mode == "managed"
	value := resource.change.after[attribute]
	is_string(value)
	value != ""
}

supporting_statements("aws_iam_role_policy.lambda_vpc") := [{
	"Sid": "ManageLambdaNetworkInterfaces", "Effect": "Allow",
	"Action": [
		"ec2:CreateNetworkInterface", "ec2:DescribeNetworkInterfaces",
		"ec2:DescribeSubnets", "ec2:DeleteNetworkInterface",
		"ec2:AssignPrivateIpAddresses", "ec2:UnassignPrivateIpAddresses",
	],
	"Resource": "*",
}]

supporting_statements("aws_iam_role_policy.lambda_uploads_kms") := [{
	"Sid": "EncryptUploadsThroughS3", "Effect": "Allow",
	"Action": "kms:GenerateDataKey",
	"Resource": planned_value("aws_kms_key.uploads", "arn"),
	"Condition": {
		"StringEquals": {"kms:ViaService": sprintf("s3.%s.amazonaws.com", [input.variables.aws_region.value])},
		"StringLike": {"kms:EncryptionContext:aws:s3:arn": sprintf("%s/*", [planned_value("aws_s3_bucket.uploads", "arn")])},
	},
}]

supporting_statements("aws_iam_role_policy.lambda_intake_kms") := [{
	"Sid": "UseSubmissionsKeyThroughDynamoDB", "Effect": "Allow",
	"Action": "kms:Decrypt",
	"Resource": planned_value("aws_kms_key.intake", "arn"),
	"Condition": {"StringEquals": {
		"kms:ViaService": sprintf("dynamodb.%s.amazonaws.com", [input.variables.aws_region.value]),
		"kms:EncryptionContext:aws:dynamodb:tableName": planned_value("aws_dynamodb_table.intake", "name"),
	}},
}]

supporting_statements("aws_iam_role_policy.lambda_observability") := [
	{
		"Sid": "SendFailedAsyncEvents", "Effect": "Allow", "Action": "sqs:SendMessage",
		"Resource": planned_value("aws_sqs_queue.intake_dlq", "arn"),
	},
	{
		"Sid": "PublishXRayTelemetry", "Effect": "Allow",
		"Action": ["xray:PutTraceSegments", "xray:PutTelemetryRecords"], "Resource": "*",
	},
]

statement_matches(actual, expected) if {
	object.keys(actual) == object.keys(expected)
	actual.Sid == expected.Sid
	actual.Effect == expected.Effect
	values_set(actual.Action) == values_set(expected.Action)
	values_set(actual.Resource) == values_set(expected.Resource)
	object.get(actual, "Condition", {}) == object.get(expected, "Condition", {})
}

supporting_policy_allowed(address, policy) if {
	is_string(policy)
	document := json.unmarshal(policy)
	document.Version == "2012-10-17"
	object.keys(document) == {"Version", "Statement"}
	is_array(document.Statement)
	expected := supporting_statements(address)
	count(document.Statement) == count(expected)
	{s.Sid | some s in document.Statement} == {s.Sid | some s in expected}
	every actual in document.Statement {
		some approved in expected
		statement_matches(actual, approved)
	}
}

# Role attributes include provider-computed copies of standalone policies.
# Validate their contents too, without assuming every entry was configured inline.
inline_address_by_name := {
	"intake-uploads-kms": "aws_iam_role_policy.lambda_uploads_kms",
	"intake-submissions-kms": "aws_iam_role_policy.lambda_intake_kms",
	"intake-vpc-network-interfaces": "aws_iam_role_policy.lambda_vpc",
	"intake-dlq-and-tracing": "aws_iam_role_policy.lambda_observability",
}

embedded_policy_allowed(policy) if {
	address := inline_address_by_name[policy.name]
	supporting_policy_allowed(address, policy.policy)
}

embedded_policy_allowed(policy) if {
	policy.name == "intake-data-access"
	json.unmarshal(policy.policy) == json.unmarshal(data_document.change.after.json)
	data_access_is_restricted
}

basic_execution_arn := "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"

role_permissions_allowed if {
	every policy in object.get(lambda_role.change.after, "inline_policy", []) {
		embedded_policy_allowed(policy)
	}
	every arn in object.get(lambda_role.change.after, "managed_policy_arns", []) {
		arn == basic_execution_arn
	}

	# Unknown provider-computed collections cannot establish permission safety.
	object.get(object.get(lambda_role.change, "after_unknown", {}), "inline_policy", false) in {false, []}
	object.get(object.get(lambda_role.change, "after_unknown", {}), "managed_policy_arns", false) in {false, []}
}

deny contains msg if {
	lambda_role
	not role_permissions_allowed
	msg := "HIPAA 164.312(a)(1) / GAP-07: aws_iam_role.lambda contains unapproved or unverifiable inline policies or managed attachments."
}

# Generic attachments can grant a managed policy to multiple roles.
attached_to_lambda(resource) if {
	resource.type == "aws_iam_policy_attachment"
	lambda_role.change.after.name in resource.change.after.roles
}

attached_to_lambda(resource) if {
	resource.type == "aws_iam_policy_attachment"
	config := configuration_resource(resource.address)
	"aws_iam_role.lambda" in reference_set(config.expressions.roles)
}

attached_to_lambda(resource) if {
	resource.type in {"aws_iam_role_policy_attachments_exclusive", "aws_iam_role_policies_exclusive"}
	resource.change.after.role_name == lambda_role.change.after.name
}

attached_to_lambda(resource) if {
	resource.type in {"aws_iam_role_policy_attachments_exclusive", "aws_iam_role_policies_exclusive"}
	config := configuration_resource(resource.address)
	"aws_iam_role.lambda" in reference_set(config.expressions.role_name)
}

approved_lambda_policy(resource) if {
	resource.type == "aws_iam_policy_attachment"
	resource.change.after.policy_arn == basic_execution_arn
}

approved_lambda_policy(resource) if {
	resource.type == "aws_iam_role_policy_attachments_exclusive"
	is_array(resource.change.after.policy_arns)
	every arn in resource.change.after.policy_arns { arn == basic_execution_arn }
	object.get(object.get(resource.change, "after_unknown", {}), "policy_arns", false) in {false, []}
}

approved_lambda_policy(resource) if {
	resource.type == "aws_iam_role_policies_exclusive"
	is_array(resource.change.after.policy_names)
	every name in resource.change.after.policy_names {
		some policy in input.resource_changes
		policy.address in approved_inline_addresses
		policy.type == "aws_iam_role_policy"
		policy.change.after.name == name
		attached_to_lambda(policy)
		approved_inline_policy(policy)
	}
	object.get(object.get(resource.change, "after_unknown", {}), "policy_names", false) in {false, []}
}

# Also inspect resources in child modules. The approved workload remains at
# root addresses; module-based attachment resources receive no address exemption.
policy_resources contains resource if {
	walk(input.planned_values.root_module, [_, node])
	is_object(node)
	node.mode == "managed"
	node.type in {
		"aws_iam_role_policy", "aws_iam_role_policy_attachment", "aws_iam_policy_attachment",
		"aws_iam_role_policy_attachments_exclusive", "aws_iam_role_policies_exclusive",
	}
	resource := {
		"address": node.address, "type": node.type, "mode": node.mode,
		"change": {"after": node.values},
	}
}

policy_resources contains resource if {
	some resource in input.resource_changes
	resource.mode == "managed"
	resource.change.after != null
	resource.type in {
		"aws_iam_role_policy", "aws_iam_role_policy_attachment", "aws_iam_policy_attachment",
		"aws_iam_role_policy_attachments_exclusive", "aws_iam_role_policies_exclusive",
	}
}

# If an attachment's target cannot be resolved, it cannot be assumed unrelated.
known_other_target(resource) if {
	config := configuration_resource(resource.address)
	target := object.get(config.expressions, "role", object.get(config.expressions, "role_name", object.get(config.expressions, "roles", {})))
	refs := reference_set(target)
	count(refs) > 0
	some ref in refs
	parts := split(ref, ".")
	count(parts) >= 2
	parts[0] == "aws_iam_role"
	parts[1] != "lambda"
	role_address := concat(".", array.slice(parts, 0, 2))
	refs - {role_address, sprintf("%s.id", [role_address]), sprintf("%s.name", [role_address])} == set()
}

known_other_target(resource) if {
	lambda_role.change.after.name
	resource.type != "aws_iam_policy_attachment"
	target := object.get(resource.change.after, "role", object.get(resource.change.after, "role_name", null))
	is_string(target)
	target != ""
	target != lambda_role.change.after.name
}

known_other_target(resource) if {
	lambda_role.change.after.name
	resource.type == "aws_iam_policy_attachment"
	is_array(resource.change.after.roles)
	every name in resource.change.after.roles { is_string(name); name != lambda_role.change.after.name}
	object.get(object.get(resource.change, "after_unknown", {}), "roles", false) in {false, []}
}

deny contains msg if {
	some resource in policy_resources
	not known_other_target(resource)
	not approved_lambda_policy(resource)
	msg := sprintf("HIPAA 164.312(a)(1) / GAP-07: %s has unapproved or unverifiable Lambda policy contents or attachment targets.", [resource.address])
}

approved_inline_policy(policy) if {
	policy.address == "aws_iam_role_policy.lambda_inline"
}

approved_inline_policy(policy) if {
	supporting_policy_allowed(policy.address, policy.change.after.policy)
}
