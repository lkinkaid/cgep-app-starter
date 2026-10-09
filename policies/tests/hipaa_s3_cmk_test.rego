package compliance.hipaa_s3_cmk_test

import data.compliance.hipaa_s3_cmk
import rego.v1

# Passing fixture: bucket ID and key ARN are unknown until apply.
compliant_input := {
	"resource_changes": [
		{
			"address": "aws_s3_bucket.uploads",
			"type": "aws_s3_bucket",
			"mode": "managed",
			"change": {
				"actions": ["create"],
				"after": {},
				"after_unknown": {"id": true},
			},
		},
		{
			"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"mode": "managed",
			"change": {
				"actions": ["create"],
				"after": {
					"rule": [{
						"apply_server_side_encryption_by_default": [{
							"sse_algorithm": "aws:kms",
						}],
					}],
				},
				"after_unknown": {
					"bucket": true,
					"rule": [{
						"apply_server_side_encryption_by_default": [{
							"kms_master_key_id": true,
						}],
					}],
				},
			},
		},
		{
			"address": "aws_kms_key.uploads",
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
				"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
				"expressions": {
					"bucket": {
						"references": [
							"aws_s3_bucket.uploads.id",
							"aws_s3_bucket.uploads",
						],
					},
					"rule": [{
						"apply_server_side_encryption_by_default": [{
							"kms_master_key_id": {
								"references": [
									"aws_kms_key.uploads.arn",
									"aws_kms_key.uploads",
								],
							},
						}],
					}],
				},
			}],
		},
	},
}

# Passing fixture: bucket ID and key ARN have resolved.
known_values_input := json.patch(compliant_input, [
	{
		"op": "add",
		"path": "/resource_changes/0/change/after/id",
		"value": "test-uploads-bucket",
	},
	{
		"op": "add",
		"path": "/resource_changes/1/change/after/bucket",
		"value": "test-uploads-bucket",
	},
	{
		"op": "add",
		"path": "/resource_changes/1/change/after/rule/0/apply_server_side_encryption_by_default/0/kms_master_key_id",
		"value": "arn:aws:kms:us-east-1:123456789012:key/test-key",
	},
	{
		"op": "add",
		"path": "/resource_changes/2/change/after/arn",
		"value": "arn:aws:kms:us-east-1:123456789012:key/test-key",
	},
	{"op": "replace", "path": "/resource_changes/0/change/after_unknown", "value": {}},
	{"op": "replace", "path": "/resource_changes/1/change/after_unknown", "value": {}},
	{"op": "replace", "path": "/resource_changes/2/change/after_unknown", "value": {}},
])

aes256_input := json.patch(compliant_input, [{
	"op": "replace",
	"path": "/resource_changes/1/change/after/rule/0/apply_server_side_encryption_by_default/0/sse_algorithm",
	"value": "AES256",
}])

encryption_missing_input := json.patch(compliant_input, [{
	"op": "remove",
	"path": "/resource_changes/1",
}])

key_missing_input := json.patch(compliant_input, [{
	"op": "remove",
	"path": "/resource_changes/2",
}])

bucket_reference_missing_input := json.patch(compliant_input, [{
	"op": "replace",
	"path": "/configuration/root_module/resources/0/expressions/bucket/references",
	"value": [],
}])

key_reference_missing_input := json.patch(compliant_input, [{
	"op": "replace",
	"path": "/configuration/root_module/resources/0/expressions/rule/0/apply_server_side_encryption_by_default/0/kms_master_key_id/references",
	"value": [],
}])

wrong_key_input := json.patch(known_values_input, [{
	"op": "replace",
	"path": "/resource_changes/1/change/after/rule/0/apply_server_side_encryption_by_default/0/kms_master_key_id",
	"value": "arn:aws:kms:us-east-1:123456789012:key/wrong-key",
}])

wrong_bucket_input := json.patch(known_values_input, [{
	"op": "replace",
	"path": "/resource_changes/1/change/after/bucket",
	"value": "wrong-bucket",
}])

test_uploads_unknown_values_passes if {
	count(hipaa_s3_cmk.deny) == 0 with input as compliant_input
}

test_uploads_known_values_passes if {
	count(hipaa_s3_cmk.deny) == 0 with input as known_values_input
}

test_uploads_aes256_fails if {
	some msg in hipaa_s3_cmk.deny with input as aes256_input
	contains(msg, "GAP-01")
	contains(msg, "aws_s3_bucket.uploads")
}

test_uploads_encryption_missing_fails if {
	some msg in hipaa_s3_cmk.deny with input as encryption_missing_input
	contains(msg, "GAP-01")
	contains(msg, "aws_s3_bucket.uploads")
}

test_uploads_key_missing_fails if {
	some msg in hipaa_s3_cmk.deny with input as key_missing_input
	contains(msg, "GAP-01")
	contains(msg, "aws_s3_bucket.uploads")
}

test_uploads_bucket_reference_missing_fails if {
	some msg in hipaa_s3_cmk.deny with input as bucket_reference_missing_input
	contains(msg, "GAP-01")
	contains(msg, "aws_s3_bucket.uploads")
}

test_uploads_key_reference_missing_fails if {
	some msg in hipaa_s3_cmk.deny with input as key_reference_missing_input
	contains(msg, "GAP-01")
	contains(msg, "aws_s3_bucket.uploads")
}

test_uploads_wrong_key_fails if {
	some msg in hipaa_s3_cmk.deny with input as wrong_key_input
	contains(msg, "GAP-01")
	contains(msg, "aws_s3_bucket.uploads")
}

test_uploads_wrong_bucket_fails if {
	some msg in hipaa_s3_cmk.deny with input as wrong_bucket_input
	contains(msg, "GAP-01")
	contains(msg, "aws_s3_bucket.uploads")
}
