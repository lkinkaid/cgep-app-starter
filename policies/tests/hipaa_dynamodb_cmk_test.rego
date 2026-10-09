package compliance.hipaa_dynamodb_cmk_test

import data.compliance.hipaa_dynamodb_cmk
import rego.v1

# Passing fixture: a new table referencing a new customer-managed key.
compliant_input := {
	"resource_changes": [
		{
			"address": "aws_dynamodb_table.intake",
			"type": "aws_dynamodb_table",
			"mode": "managed",
			"change": {
				"actions": ["create"],
				"after": {
					"server_side_encryption": [{"enabled": true}],
				},
				"after_unknown": {
					"server_side_encryption": [{"kms_key_arn": true}],
				},
			},
		},
		{
			"address": "aws_kms_key.intake",
			"type": "aws_kms_key",
			"mode": "managed",
			"change": {
				"actions": ["create"],
				"after": {"is_enabled": true},
				"after_unknown": {"arn": true},
			},
		},
	],
	"configuration": {
		"root_module": {
			"resources": [{
				"address": "aws_dynamodb_table.intake",
				"expressions": {
					"server_side_encryption": [{
						"kms_key_arn": {
							"references": [
								"aws_kms_key.intake.arn",
								"aws_kms_key.intake",
							],
						},
					}],
				},
			}],
		},
	},
}

# Passing fixture: both key ARNs have resolved to the same value.
known_arn_input := json.patch(compliant_input, [
	{
		"op": "add",
		"path": "/resource_changes/0/change/after/server_side_encryption/0/kms_key_arn",
		"value": "arn:aws:kms:us-east-1:123456789012:key/test-key",
	},
	{
		"op": "add",
		"path": "/resource_changes/1/change/after/arn",
		"value": "arn:aws:kms:us-east-1:123456789012:key/test-key",
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
])

# Failing fixtures: change one property of the passing fixture.
encryption_disabled_input := json.patch(compliant_input, [{
	"op": "replace",
	"path": "/resource_changes/0/change/after/server_side_encryption/0/enabled",
	"value": false,
}])

encryption_missing_input := json.patch(compliant_input, [{
	"op": "remove",
	"path": "/resource_changes/0/change/after/server_side_encryption",
}])

reference_missing_input := json.patch(compliant_input, [{
	"op": "replace",
	"path": "/configuration/root_module/resources/0/expressions/server_side_encryption/0/kms_key_arn/references",
	"value": [],
}])

key_missing_input := json.patch(compliant_input, [{
	"op": "remove",
	"path": "/resource_changes/1",
}])

table_missing_input := {"resource_changes": []}

test_intake_cmk_unknown_arn_passes if {
	count(hipaa_dynamodb_cmk.deny) == 0 with input as compliant_input
}

test_intake_cmk_known_arn_passes if {
	count(hipaa_dynamodb_cmk.deny) == 0 with input as known_arn_input
}

test_intake_encryption_disabled_fails if {
	some msg in hipaa_dynamodb_cmk.deny with input as encryption_disabled_input
	contains(msg, "GAP-02")
	contains(msg, "164.312(a)(2)(iv)")
}

test_intake_encryption_missing_fails if {
	some msg in hipaa_dynamodb_cmk.deny with input as encryption_missing_input
	contains(msg, "GAP-02")
	contains(msg, "164.312(a)(2)(iv)")
}

test_intake_cmk_reference_missing_fails if {
	some msg in hipaa_dynamodb_cmk.deny with input as reference_missing_input
	contains(msg, "GAP-02")
	contains(msg, "164.312(a)(2)(iv)")
}

test_intake_cmk_resource_missing_fails if {
	some msg in hipaa_dynamodb_cmk.deny with input as key_missing_input
	contains(msg, "GAP-02")
	contains(msg, "164.312(a)(2)(iv)")
}

test_intake_table_missing_fails if {
	some msg in hipaa_dynamodb_cmk.deny with input as table_missing_input
	contains(msg, "GAP-02")
	contains(msg, "164.312(a)(2)(iv)")
}
