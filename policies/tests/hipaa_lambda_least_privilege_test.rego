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

test_lambda_supporting_policy_passes if {
	count(hipaa_lambda_least_privilege.deny) == 0 with input as approved_supporting_policy_input
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
