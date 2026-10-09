package compliance.hipaa_lambda_least_privilege_test

import data.compliance.hipaa_lambda_least_privilege
import rego.v1

compliant_input := {
	"resource_changes": [
		{
			"address": "data.aws_iam_policy_document.lambda_data_access",
			"type": "aws_iam_policy_document",
			"mode": "data",
			"change": {
				"actions": ["read"],
				"after": {
					"statement": [
						{
							"sid": "WriteIntakeSubmissions",
							"effect": "Allow",
							"actions": ["dynamodb:PutItem"],
							"resources": [null],
						},
						{
							"sid": "WriteIntakeUploads",
							"effect": "Allow",
							"actions": ["s3:PutObject"],
							"resources": [null],
						},
					],
				},
				"after_unknown": {
					"json": true,
					"statement": [
						{"resources": [true]},
						{"resources": [true]},
					],
				},
			},
		},
		{
			"address": "aws_iam_role_policy.lambda_inline",
			"type": "aws_iam_role_policy",
			"mode": "managed",
			"change": {
				"actions": ["create"],
				"after": {},
				"after_unknown": {"policy": true},
			},
		},
	],
	"configuration": {
		"root_module": {
			"resources": [
				{
					"address": "aws_iam_role_policy.lambda_inline",
					"expressions": {
						"policy": {
							"references": [
								"data.aws_iam_policy_document.lambda_data_access.json",
								"data.aws_iam_policy_document.lambda_data_access",
							],
						},
						"role": {
							"references": [
								"aws_iam_role.lambda.id",
								"aws_iam_role.lambda",
							],
						},
					},
				},
				{
					"address": "data.aws_iam_policy_document.lambda_data_access",
					"expressions": {
						"statement": [
							{
								"sid": {"constant_value": "WriteIntakeSubmissions"},
								"resources": {
									"references": [
										"aws_dynamodb_table.intake.arn",
										"aws_dynamodb_table.intake",
									],
								},
							},
							{
								"sid": {"constant_value": "WriteIntakeUploads"},
								"resources": {
									"references": [
										"aws_s3_bucket.uploads.arn",
										"aws_s3_bucket.uploads",
									],
								},
							},
						],
					},
				},
			],
		},
	},
}

s3_wildcard_input := json.patch(compliant_input, [{
	"op": "replace",
	"path": "/resource_changes/0/change/after/statement/1/actions",
	"value": ["s3:*"],
}])

dynamodb_wildcard_input := json.patch(compliant_input, [{
	"op": "replace",
	"path": "/resource_changes/0/change/after/statement/0/actions",
	"value": ["dynamodb:*"],
}])

extra_action_input := json.patch(compliant_input, [{
	"op": "replace",
	"path": "/resource_changes/0/change/after/statement/1/actions",
	"value": ["s3:PutObject", "s3:GetObject"],
}])

wildcard_resource_input := json.patch(compliant_input, [{
	"op": "replace",
	"path": "/resource_changes/0/change/after/statement/1/resources",
	"value": ["*"],
}])

wrong_reference_input := json.patch(compliant_input, [{
	"op": "replace",
	"path": "/configuration/root_module/resources/1/expressions/statement/1/resources/references",
	"value": ["aws_s3_bucket.other.arn", "aws_s3_bucket.other"],
}])

disconnected_policy_input := json.patch(compliant_input, [{
	"op": "replace",
	"path": "/configuration/root_module/resources/0/expressions/policy/references",
	"value": [],
}])

missing_policy_input := json.patch(compliant_input, [{
	"op": "remove",
	"path": "/resource_changes/1",
}])

merged_document_input := json.patch(compliant_input, [{
	"op": "add",
	"path": "/configuration/root_module/resources/1/expressions/source_policy_documents",
	"value": {"constant_value": ["additional-policy"]},
}])

extra_statement_input := json.patch(compliant_input, [{
	"op": "add",
	"path": "/resource_changes/0/change/after/statement/-",
	"value": {
		"sid": "ExtraPermissions",
		"effect": "Allow",
		"actions": ["s3:DeleteObject"],
		"resources": ["*"],
	},
}])

test_lambda_data_access_passes if {
	count(hipaa_lambda_least_privilege.deny) == 0 with input as compliant_input
}

test_lambda_s3_wildcard_fails if {
	some msg in hipaa_lambda_least_privilege.deny with input as s3_wildcard_input
	contains(msg, "GAP-07")
}

test_lambda_dynamodb_wildcard_fails if {
	some msg in hipaa_lambda_least_privilege.deny with input as dynamodb_wildcard_input
	contains(msg, "GAP-07")
}

test_lambda_extra_action_fails if {
	some msg in hipaa_lambda_least_privilege.deny with input as extra_action_input
	contains(msg, "GAP-07")
}

test_lambda_wildcard_resource_fails if {
	some msg in hipaa_lambda_least_privilege.deny with input as wildcard_resource_input
	contains(msg, "GAP-07")
}

test_lambda_wrong_reference_fails if {
	some msg in hipaa_lambda_least_privilege.deny with input as wrong_reference_input
	contains(msg, "GAP-07")
}

test_lambda_disconnected_policy_fails if {
	some msg in hipaa_lambda_least_privilege.deny with input as disconnected_policy_input
	contains(msg, "GAP-07")
}

test_lambda_missing_policy_fails if {
	some msg in hipaa_lambda_least_privilege.deny with input as missing_policy_input
	contains(msg, "GAP-07")
}

test_lambda_merged_document_fails if {
	some msg in hipaa_lambda_least_privilege.deny with input as merged_document_input
	contains(msg, "GAP-07")
}

test_lambda_extra_statement_fails if {
	some msg in hipaa_lambda_least_privilege.deny with input as extra_statement_input
	contains(msg, "GAP-07")
}

known_table_arn := "arn:aws:dynamodb:us-east-1:123456789012:table/test-intake"

known_bucket_arn := "arn:aws:s3:::test-uploads"

known_policy_json := json.marshal({
	"Version": "2012-10-17",
	"Statement": [
		{
			"Sid": "WriteIntakeSubmissions",
			"Effect": "Allow",
			"Action": "dynamodb:PutItem",
			"Resource": known_table_arn,
		},
		{
			"Sid": "WriteIntakeUploads",
			"Effect": "Allow",
			"Action": "s3:PutObject",
			"Resource": sprintf("%s/uploads/*", [known_bucket_arn]),
		},
	],
})

known_values_input := json.patch(compliant_input, [
	{
		"op": "replace",
		"path": "/resource_changes/0/change/after/statement/0/resources",
		"value": [known_table_arn],
	},
	{
		"op": "replace",
		"path": "/resource_changes/0/change/after/statement/1/resources",
		"value": [sprintf("%s/uploads/*", [known_bucket_arn])],
	},
	{
		"op": "add",
		"path": "/resource_changes/0/change/after/json",
		"value": known_policy_json,
	},
	{
		"op": "add",
		"path": "/resource_changes/1/change/after/policy",
		"value": known_policy_json,
	},
	{
		"op": "replace",
		"path": "/resource_changes/0/change/after_unknown",
		"value": {},
	},
	{
		"op": "replace",
		"path": "/resource_changes/1/change/after_unknown",
		"value": {},
	},
	{
		"op": "add",
		"path": "/resource_changes/-",
		"value": {
			"address": "aws_dynamodb_table.intake",
			"type": "aws_dynamodb_table",
			"mode": "managed",
			"change": {
				"actions": ["no-op"],
				"after": {"arn": known_table_arn},
			},
		},
	},
	{
		"op": "add",
		"path": "/resource_changes/-",
		"value": {
			"address": "aws_s3_bucket.uploads",
			"type": "aws_s3_bucket",
			"mode": "managed",
			"change": {
				"actions": ["no-op"],
				"after": {"arn": known_bucket_arn},
			},
		},
	},
])

wrong_table_arn_input := json.patch(known_values_input, [{
	"op": "replace",
	"path": "/resource_changes/0/change/after/statement/0/resources",
	"value": ["arn:aws:dynamodb:us-east-1:123456789012:table/other-table"],
}])

whole_bucket_input := json.patch(known_values_input, [{
	"op": "replace",
	"path": "/resource_changes/0/change/after/statement/1/resources",
	"value": [sprintf("%s/*", [known_bucket_arn])],
}])

mismatched_inline_input := json.patch(known_values_input, [{
	"op": "replace",
	"path": "/resource_changes/1/change/after/policy",
	"value": json.marshal({
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "*",
			"Resource": "*",
		}],
	}),
}])

test_lambda_known_values_passes if {
	count(hipaa_lambda_least_privilege.deny) == 0 with input as known_values_input
}

test_lambda_wrong_table_arn_fails if {
	some msg in hipaa_lambda_least_privilege.deny with input as wrong_table_arn_input
	contains(msg, "GAP-07")
}

test_lambda_whole_bucket_access_fails if {
	some msg in hipaa_lambda_least_privilege.deny with input as whole_bucket_input
	contains(msg, "GAP-07")
}

test_lambda_mismatched_inline_document_fails if {
	some msg in hipaa_lambda_least_privilege.deny with input as mismatched_inline_input
	contains(msg, "GAP-07")
}

# Add an inline policy connected through a Terraform role reference.
with_extra_inline_policy(address, references) := json.patch(compliant_input, [
	{
		"op": "add",
		"path": "/resource_changes/-",
		"value": {
			"address": address,
			"type": "aws_iam_role_policy",
			"mode": "managed",
			"change": {
				"actions": ["create"],
				"after": {},
				"after_unknown": {
					"role": true,
					"policy": true,
				},
			},
		},
	},
	{
		"op": "add",
		"path": "/configuration/root_module/resources/-",
		"value": {
			"address": address,
			"expressions": {
				"role": {"references": references},
			},
		},
	},
])

extra_lambda_policy_input := with_extra_inline_policy(
	"aws_iam_role_policy.extra_data_access",
	["aws_iam_role.lambda.id", "aws_iam_role.lambda"],
)

approved_supporting_policy_input := with_extra_inline_policy(
	"aws_iam_role_policy.lambda_vpc",
	["aws_iam_role.lambda.id", "aws_iam_role.lambda"],
)

other_role_policy_input := with_extra_inline_policy(
	"aws_iam_role_policy.other_role_access",
	["aws_iam_role.other.id", "aws_iam_role.other"],
)

# Resolve the extra policy's role name instead of using a reference.
known_role_extra_policy_input := json.patch(extra_lambda_policy_input, [
	{
		"op": "add",
		"path": "/resource_changes/2/change/after/role",
		"value": "test-intake-lambda",
	},
	{
		"op": "replace",
		"path": "/resource_changes/2/change/after_unknown/role",
		"value": false,
	},
	{
		"op": "replace",
		"path": "/configuration/root_module/resources/2/expressions/role",
		"value": {"constant_value": "test-intake-lambda"},
	},
	{
		"op": "add",
		"path": "/resource_changes/-",
		"value": {
			"address": "aws_iam_role.lambda",
			"type": "aws_iam_role",
			"mode": "managed",
			"change": {
				"actions": ["no-op"],
				"after": {"name": "test-intake-lambda"},
			},
		},
	},
])

with_managed_attachment(policy_arn) := json.patch(compliant_input, [
	{
		"op": "add",
		"path": "/resource_changes/-",
		"value": {
			"address": "aws_iam_role_policy_attachment.lambda_extra",
			"type": "aws_iam_role_policy_attachment",
			"mode": "managed",
			"change": {
				"actions": ["create"],
				"after": {"policy_arn": policy_arn},
				"after_unknown": {"role": true},
			},
		},
	},
	{
		"op": "add",
		"path": "/configuration/root_module/resources/-",
		"value": {
			"address": "aws_iam_role_policy_attachment.lambda_extra",
			"expressions": {
				"role": {
					"references": [
						"aws_iam_role.lambda.id",
						"aws_iam_role.lambda",
					],
				},
			},
		},
	},
])

approved_attachment_input := with_managed_attachment("arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")

unapproved_attachment_input := with_managed_attachment("arn:aws:iam::aws:policy/AdministratorAccess")

test_lambda_extra_inline_policy_fails if {
	some msg in hipaa_lambda_least_privilege.deny with input as extra_lambda_policy_input
	contains(msg, "GAP-07")
	contains(msg, "aws_iam_role_policy.extra_data_access")
}

test_lambda_extra_policy_known_role_fails if {
	some msg in hipaa_lambda_least_privilege.deny with input as known_role_extra_policy_input
	contains(msg, "GAP-07")
	contains(msg, "aws_iam_role_policy.extra_data_access")
}

test_lambda_unknown_supporting_policy_fails if {
	some msg in hipaa_lambda_least_privilege.deny with input as approved_supporting_policy_input
	contains(msg, "GAP-07")
}

test_other_role_policy_passes if {
	count(hipaa_lambda_least_privilege.deny) == 0 with input as other_role_policy_input
}

test_lambda_basic_execution_attachment_passes if {
	count(hipaa_lambda_least_privilege.deny) == 0 with input as approved_attachment_input
}

test_lambda_unapproved_attachment_fails if {
	some msg in hipaa_lambda_least_privilege.deny with input as unapproved_attachment_input
	contains(msg, "GAP-07")
	contains(msg, "aws_iam_role_policy_attachment.lambda_extra")
}

unchanged_document_input(original) := json.patch(original, [
	{
		"op": "add",
		"path": "/prior_state",
		"value": {
			"values": {
				"root_module": {
					"resources": [{
						"address": "data.aws_iam_policy_document.lambda_data_access",
						"type": "aws_iam_policy_document",
						"mode": "data",
						"values": original.resource_changes[0].change.after,
					}],
				},
			},
		},
	},
	{
		"op": "remove",
		"path": "/resource_changes/0",
	},
])

test_lambda_unchanged_document_passes if {
	fixture := unchanged_document_input(known_values_input)
	count(hipaa_lambda_least_privilege.deny) == 0 with input as fixture
}

test_lambda_unchanged_document_mismatched_policy_fails if {
	fixture := unchanged_document_input(mismatched_inline_input)
	some msg in hipaa_lambda_least_privilege.deny with input as fixture
	contains(msg, "GAP-07")
}

# Standalone, resolved supporting-policy fixture. Values are independent of
# the production rule and include the resource identities used by the workload.
supporting_documents := {
	"lambda_vpc": {"Version": "2012-10-17", "Statement": [{
		"Sid": "ManageLambdaNetworkInterfaces", "Effect": "Allow",
		"Action": [
			"ec2:CreateNetworkInterface", "ec2:DescribeNetworkInterfaces",
			"ec2:DescribeSubnets", "ec2:DeleteNetworkInterface",
			"ec2:AssignPrivateIpAddresses", "ec2:UnassignPrivateIpAddresses",
		],
		"Resource": "*",
	}]},
	"lambda_uploads_kms": {"Version": "2012-10-17", "Statement": [{
		"Sid": "EncryptUploadsThroughS3", "Effect": "Allow", "Action": "kms:GenerateDataKey",
		"Resource": "arn:aws:kms:us-east-1:123456789012:key/uploads",
		"Condition": {
			"StringEquals": {"kms:ViaService": "s3.us-east-1.amazonaws.com"},
			"StringLike": {"kms:EncryptionContext:aws:s3:arn": "arn:aws:s3:::test-uploads/*"},
		},
	}]},
	"lambda_intake_kms": {"Version": "2012-10-17", "Statement": [{
		"Sid": "UseSubmissionsKeyThroughDynamoDB", "Effect": "Allow", "Action": "kms:Decrypt",
		"Resource": "arn:aws:kms:us-east-1:123456789012:key/intake",
		"Condition": {"StringEquals": {
			"kms:ViaService": "dynamodb.us-east-1.amazonaws.com",
			"kms:EncryptionContext:aws:dynamodb:tableName": "test-intake",
		}},
	}]},
	"lambda_observability": {"Version": "2012-10-17", "Statement": [
		{
			"Sid": "SendFailedAsyncEvents", "Effect": "Allow", "Action": "sqs:SendMessage",
			"Resource": "arn:aws:sqs:us-east-1:123456789012:test-dlq",
		},
		{
			"Sid": "PublishXRayTelemetry", "Effect": "Allow",
			"Action": ["xray:PutTraceSegments", "xray:PutTelemetryRecords"], "Resource": "*",
		},
	]},
}

supporting_plan(name, document) := json.patch(known_values_input, [
	{"op": "add", "path": "/variables", "value": {"aws_region": {"value": "us-east-1"}}},
	{"op": "add", "path": "/resource_changes/-", "value": {
		"address": "aws_iam_role.lambda", "type": "aws_iam_role", "mode": "managed",
		"change": {"after": {"name": "test-lambda", "inline_policy": [], "managed_policy_arns": []}},
	}},
	{"op": "add", "path": "/resource_changes/-", "value": {
		"address": "aws_kms_key.uploads", "type": "aws_kms_key", "mode": "managed",
		"change": {"after": {"arn": "arn:aws:kms:us-east-1:123456789012:key/uploads"}},
	}},
	{"op": "add", "path": "/resource_changes/-", "value": {
		"address": "aws_kms_key.intake", "type": "aws_kms_key", "mode": "managed",
		"change": {"after": {"arn": "arn:aws:kms:us-east-1:123456789012:key/intake"}},
	}},
	{"op": "add", "path": "/resource_changes/2/change/after/name", "value": "test-intake"},
	{"op": "add", "path": "/resource_changes/-", "value": {
		"address": "aws_sqs_queue.intake_dlq", "type": "aws_sqs_queue", "mode": "managed",
		"change": {"after": {"arn": "arn:aws:sqs:us-east-1:123456789012:test-dlq"}},
	}},
	{"op": "add", "path": "/resource_changes/-", "value": {
		"address": sprintf("aws_iam_role_policy.%s", [name]), "type": "aws_iam_role_policy", "mode": "managed",
		"change": {"after": {"role": "test-lambda", "policy": json.marshal(document)}},
	}},
])

# Each approved supporting address must pass with its actual intended contents.
test_all_supporting_policies_pass if {
	every name, document in supporting_documents {
		fixture := supporting_plan(name, document)
		count(hipaa_lambda_least_privilege.deny) == 0 with input as fixture
	}
}

# Exact reported bypass: approved lambda_vpc address with broad data access.
test_lambda_vpc_data_wildcards_fail if {
	document := {"Version": "2012-10-17", "Statement": [{
		"Effect": "Allow", "Action": ["dynamodb:*", "s3:*"], "Resource": "*",
	}]}
	fixture := supporting_plan("lambda_vpc", document)
	some msg in hipaa_lambda_least_privilege.deny with input as fixture
	contains(msg, "aws_iam_role_policy.lambda_vpc")
	contains(msg, "164.312(a)(1)")
}

test_extra_action_in_each_supporting_policy_fails if {
	every name, document in supporting_documents {
		bad := json.patch(document, [{"op": "replace", "path": "/Statement/0/Action", "value": ["*"]}])
		fixture := supporting_plan(name, bad)
		count(hipaa_lambda_least_privilege.deny) > 0 with input as fixture
	}
}

test_extra_statement_in_each_supporting_policy_fails if {
	every name, document in supporting_documents {
		bad := json.patch(document, [{"op": "add", "path": "/Statement/-", "value": {
			"Effect": "Allow", "Action": "dynamodb:*", "Resource": "*",
		}}])
		fixture := supporting_plan(name, bad)
		count(hipaa_lambda_least_privilege.deny) > 0 with input as fixture
	}
}

test_broadened_scoped_supporting_resources_fail if {
	every name in ["lambda_uploads_kms", "lambda_intake_kms", "lambda_observability"] {
		bad := json.patch(supporting_documents[name], [{"op": "replace", "path": "/Statement/0/Resource", "value": "*"}])
		fixture := supporting_plan(name, bad)
		count(hipaa_lambda_least_privilege.deny) > 0 with input as fixture
	}
}

test_removed_kms_conditions_fail if {
	every name in ["lambda_uploads_kms", "lambda_intake_kms"] {
		bad := json.patch(supporting_documents[name], [{"op": "remove", "path": "/Statement/0/Condition"}])
		fixture := supporting_plan(name, bad)
		count(hipaa_lambda_least_privilege.deny) > 0 with input as fixture
	}
}

test_wrong_kms_service_and_context_fail if {
	every condition in [
		{"StringEquals": {"kms:ViaService": "s3.us-west-2.amazonaws.com"}, "StringLike": {"kms:EncryptionContext:aws:s3:arn": "*"}},
		{"StringEquals": {"kms:ViaService": "s3.us-east-1.amazonaws.com"}, "StringLike": {"kms:EncryptionContext:aws:s3:arn": "*"}},
	] {
		bad := json.patch(supporting_documents.lambda_uploads_kms, [{"op": "replace", "path": "/Statement/0/Condition", "value": condition}])
		fixture := supporting_plan("lambda_uploads_kms", bad)
		count(hipaa_lambda_least_privilege.deny) > 0 with input as fixture
	}
}

test_not_action_in_supporting_policy_fails if {
	bad := json.patch(supporting_documents.lambda_vpc, [{"op": "add", "path": "/Statement/0/NotAction", "value": "iam:*"}])
	fixture := supporting_plan("lambda_vpc", bad)
	count(hipaa_lambda_least_privilege.deny) > 0 with input as fixture
}

test_equivalent_action_order_and_list_forms_pass if {
	bad := json.patch(supporting_documents.lambda_vpc, [
		{"op": "replace", "path": "/Statement/0/Action", "value": array.reverse(supporting_documents.lambda_vpc.Statement[0].Action)},
		{"op": "replace", "path": "/Statement/0/Resource", "value": ["*"]},
	])
	fixture := supporting_plan("lambda_vpc", bad)
	count(hipaa_lambda_least_privilege.deny) == 0 with input as fixture
}

role_plan := supporting_plan("lambda_vpc", supporting_documents.lambda_vpc)

role_with(field, value) := json.patch(role_plan, [{"op": "add", "path": sprintf("/resource_changes/4/change/after/%s", [field]), "value": value}])

test_embedded_inline_escalation_fails if {
	fixture := role_with("inline_policy", [{"name": "intake-vpc-network-interfaces", "policy": json.marshal({
		"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
	})}])
	some msg in hipaa_lambda_least_privilege.deny with input as fixture
	contains(msg, "aws_iam_role.lambda")
}

test_embedded_safe_computed_policies_pass if {
	fixture := role_with("inline_policy", [
		{"name": "intake-vpc-network-interfaces", "policy": json.marshal(supporting_documents.lambda_vpc)},
		{"name": "intake-data-access", "policy": known_policy_json},
	])
	count(hipaa_lambda_least_privilege.deny) == 0 with input as fixture
}

test_embedded_managed_admin_fails if {
	fixture := role_with("managed_policy_arns", ["arn:aws:iam::aws:policy/AdministratorAccess"])
	count(hipaa_lambda_least_privilege.deny) > 0 with input as fixture
}

test_embedded_basic_execution_passes if {
	fixture := role_with("managed_policy_arns", ["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"])
	count(hipaa_lambda_least_privilege.deny) == 0 with input as fixture
}

alternate_attachment(resource_type, after) := json.patch(role_plan, [{"op": "add", "path": "/resource_changes/-", "value": {
	"address": sprintf("%s.extra", [resource_type]), "type": resource_type, "mode": "managed", "change": {"after": after},
}}])

test_generic_managed_attachment_admin_fails if {
	fixture := alternate_attachment("aws_iam_policy_attachment", {"roles": ["test-lambda"], "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"})
	count(hipaa_lambda_least_privilege.deny) > 0 with input as fixture
}

test_generic_managed_attachment_basic_passes if {
	fixture := alternate_attachment("aws_iam_policy_attachment", {"roles": ["test-lambda"], "policy_arn": "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"})
	count(hipaa_lambda_least_privilege.deny) == 0 with input as fixture
}

test_exclusive_managed_attachment_admin_fails if {
	fixture := alternate_attachment("aws_iam_role_policy_attachments_exclusive", {"role_name": "test-lambda", "policy_arns": ["arn:aws:iam::aws:policy/AdministratorAccess"]})
	count(hipaa_lambda_least_privilege.deny) > 0 with input as fixture
}

test_exclusive_inline_unknown_name_fails if {
	fixture := alternate_attachment("aws_iam_role_policies_exclusive", {"role_name": "test-lambda", "policy_names": ["backdoor"]})
	count(hipaa_lambda_least_privilege.deny) > 0 with input as fixture
}

test_unresolved_attachment_target_fails if {
	fixture := alternate_attachment("aws_iam_role_policy_attachment", {"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"})
	count(hipaa_lambda_least_privilege.deny) > 0 with input as fixture
}

test_other_role_alternate_attachment_passes if {
	fixture := alternate_attachment("aws_iam_policy_attachment", {"roles": ["other-role"], "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"})
	count(hipaa_lambda_least_privilege.deny) == 0 with input as fixture
}

test_unknown_supporting_json_with_expected_references_fails if {
	fixture := json.patch(role_plan, [
		{"op": "remove", "path": "/resource_changes/8/change/after/policy"},
		{"op": "add", "path": "/resource_changes/8/change/after_unknown", "value": {"policy": true}},
		{"op": "add", "path": "/configuration/root_module/resources/-", "value": {
			"address": "aws_iam_role_policy.lambda_vpc", "expressions": {
				"role": {"references": ["aws_iam_role.lambda.id", "aws_iam_role.lambda"]},
				"policy": {"references": ["aws_kms_key.uploads.arn", "aws_kms_key.uploads"]},
			},
		}},
	])
	count(hipaa_lambda_least_privilege.deny) > 0 with input as fixture
}

test_deleted_attachment_grants_no_permissions if {
	fixture := json.patch(role_plan, [{"op": "add", "path": "/resource_changes/-", "value": {
		"address": "aws_iam_role_policy_attachment.deleted", "type": "aws_iam_role_policy_attachment", "mode": "managed",
		"change": {"actions": ["delete"], "after": null},
	}}])
	count(hipaa_lambda_least_privilege.deny) == 0 with input as fixture
}

test_child_module_attachment_escalation_fails if {
	fixture := json.patch(role_plan, [{"op": "add", "path": "/planned_values", "value": {
		"root_module": {"child_modules": [{"address": "module.permissions", "resources": [{
			"address": "module.permissions.aws_iam_role_policy_attachment.backdoor",
			"mode": "managed", "type": "aws_iam_role_policy_attachment",
			"values": {"role": "test-lambda", "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"},
		}]}]},
	}}])
	some msg in hipaa_lambda_least_privilege.deny with input as fixture
	contains(msg, "module.permissions.aws_iam_role_policy_attachment.backdoor")
}

test_child_module_unrelated_attachment_passes if {
	fixture := json.patch(role_plan, [{"op": "add", "path": "/planned_values", "value": {
		"root_module": {"child_modules": [{"address": "module.permissions", "resources": [{
			"address": "module.permissions.aws_iam_role_policy_attachment.other",
			"mode": "managed", "type": "aws_iam_role_policy_attachment",
			"values": {"role": "other-role", "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"},
		}]}]},
	}}])
	count(hipaa_lambda_least_privilege.deny) == 0 with input as fixture
}

test_unknown_embedded_collections_fail if {
	every field in ["inline_policy", "managed_policy_arns"] {
		fixture := json.patch(role_plan, [{"op": "add", "path": "/resource_changes/4/change/after_unknown", "value": {field: true}}])
		count(hipaa_lambda_least_privilege.deny) > 0 with input as fixture
	}
}

test_unresolved_supporting_resource_identity_fails if {
	fixture := supporting_plan("lambda_uploads_kms", supporting_documents.lambda_uploads_kms)
	unknown := json.patch(fixture, [{"op": "remove", "path": "/resource_changes/5/change/after/arn"}])
	count(hipaa_lambda_least_privilege.deny) > 0 with input as unknown
}

test_malformed_supporting_policy_json_fails if {
	fixture := json.patch(role_plan, [{"op": "replace", "path": "/resource_changes/8/change/after/policy", "value": "not-json"}])
	count(hipaa_lambda_least_privilege.deny) > 0 with input as fixture
}

test_exclusive_basic_execution_attachment_passes if {
	fixture := alternate_attachment("aws_iam_role_policy_attachments_exclusive", {"role_name": "test-lambda", "policy_arns": ["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"]})
	count(hipaa_lambda_least_privilege.deny) == 0 with input as fixture
}

test_exclusive_inline_approved_name_passes if {
	fixture := json.patch(role_plan, [{"op": "add", "path": "/resource_changes/8/change/after/name", "value": "intake-vpc-network-interfaces"}])
	exclusive := json.patch(fixture, [{"op": "add", "path": "/resource_changes/-", "value": {
		"address": "aws_iam_role_policies_exclusive.safe", "type": "aws_iam_role_policies_exclusive", "mode": "managed",
		"change": {"after": {"role_name": "test-lambda", "policy_names": ["intake-vpc-network-interfaces"]}},
	}}])
	count(hipaa_lambda_least_privilege.deny) == 0 with input as exclusive
}
