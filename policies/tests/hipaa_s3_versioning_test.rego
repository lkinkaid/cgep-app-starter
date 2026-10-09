package compliance.hipaa_s3_versioning_test

import data.compliance.hipaa_s3_versioning
import rego.v1

# Passing fixture: versioning references a bucket being created.
versioning_plan(status) := {
	"resource_changes": [
		{
			"address": "aws_s3_bucket_versioning.uploads",
			"type": "aws_s3_bucket_versioning",
			"mode": "managed",
			"change": {
				"actions": ["create"],
				"after": {
					"versioning_configuration": [{"status": status}],
				},
				"after_unknown": {"bucket": true},
			},
		},
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
	],
	"configuration": {
		"root_module": {
			"resources": [{
				"address": "aws_s3_bucket_versioning.uploads",
				"expressions": {
					"bucket": {
						"references": [
							"aws_s3_bucket.uploads.id",
							"aws_s3_bucket.uploads",
						],
					},
				},
			}],
		},
	},
}

compliant_input := versioning_plan("Enabled")

noncompliant_input := versioning_plan("Suspended")

# Passing fixture: both bucket IDs are resolved and match.
known_values_input := json.patch(compliant_input, [
	{
		"op": "add",
		"path": "/resource_changes/0/change/after/bucket",
		"value": "capstone-test-uploads",
	},
	{
		"op": "add",
		"path": "/resource_changes/1/change/after/id",
		"value": "capstone-test-uploads",
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

missing_resource_input := {"resource_changes": []}

missing_status_input := json.patch(compliant_input, [{
	"op": "remove",
	"path": "/resource_changes/0/change/after/versioning_configuration/0/status",
}])

wrong_bucket_input := json.patch(known_values_input, [{
	"op": "replace",
	"path": "/resource_changes/0/change/after/bucket",
	"value": "another-bucket",
}])

wrong_reference_input := json.patch(compliant_input, [{
	"op": "replace",
	"path": "/configuration/root_module/resources/0/expressions/bucket/references",
	"value": [
		"aws_s3_bucket.vault.id",
		"aws_s3_bucket.vault",
	],
}])

missing_reference_input := json.patch(compliant_input, [{
	"op": "remove",
	"path": "/configuration/root_module/resources/0/expressions/bucket",
}])

missing_bucket_input := json.patch(compliant_input, [{
	"op": "remove",
	"path": "/resource_changes/1",
}])

test_uploads_versioning_enabled_passes if {
	count(hipaa_s3_versioning.deny) == 0 with input as compliant_input
}

test_uploads_versioning_known_bucket_passes if {
	count(hipaa_s3_versioning.deny) == 0 with input as known_values_input
}

test_uploads_versioning_suspended_fails if {
	some msg in hipaa_s3_versioning.deny with input as noncompliant_input
	contains(msg, "GAP-04")
}

test_uploads_versioning_missing_fails if {
	some msg in hipaa_s3_versioning.deny with input as missing_resource_input
	contains(msg, "GAP-04")
}

test_uploads_versioning_status_missing_fails if {
	some msg in hipaa_s3_versioning.deny with input as missing_status_input
	contains(msg, "GAP-04")
}

test_uploads_versioning_wrong_bucket_fails if {
	some msg in hipaa_s3_versioning.deny with input as wrong_bucket_input
	contains(msg, "GAP-04")
}

test_uploads_versioning_wrong_reference_fails if {
	some msg in hipaa_s3_versioning.deny with input as wrong_reference_input
	contains(msg, "GAP-04")
}

test_uploads_versioning_reference_missing_fails if {
	some msg in hipaa_s3_versioning.deny with input as missing_reference_input
	contains(msg, "GAP-04")
}

test_uploads_versioning_bucket_missing_fails if {
	some msg in hipaa_s3_versioning.deny with input as missing_bucket_input
	contains(msg, "GAP-04")
}
