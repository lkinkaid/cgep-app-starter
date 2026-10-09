package compliance.hipaa_s3_tls_test

import data.compliance.hipaa_s3_tls
import rego.v1

tls_statement := {
	"Sid": "DenyInsecureTransport",
	"Effect": "Deny",
	"Principal": "*",
	"Action": "s3:*",
	"Resource": [
		"arn:aws:s3:::test-uploads",
		"arn:aws:s3:::test-uploads/*",
	],
	"Condition": {
		"Bool": {
			"aws:SecureTransport": "false",
		},
	},
}

tls_plan(statement) := {
	"resource_changes": [
		{
			"address": "aws_s3_bucket.uploads",
			"type": "aws_s3_bucket",
			"mode": "managed",
			"change": {
				"actions": ["create"],
				"after": {"arn": "arn:aws:s3:::test-uploads"},
				"after_unknown": {"id": true},
			},
		},
		{
			"address": "aws_s3_bucket_policy.uploads",
			"type": "aws_s3_bucket_policy",
			"mode": "managed",
			"change": {
				"actions": ["create"],
				"after": {
					"policy": json.marshal({
						"Version": "2012-10-17",
						"Statement": [statement],
					}),
				},
				"after_unknown": {"bucket": true},
			},
		},
	],
	"configuration": {
		"root_module": {
			"resources": [{
				"address": "aws_s3_bucket_policy.uploads",
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

compliant_input := tls_plan(tls_statement)

boolean_false_input := tls_plan(object.union(tls_statement, {
	"Condition": {"Bool": {"aws:SecureTransport": false}},
}))

allow_input := tls_plan(object.union(tls_statement, {
	"Effect": "Allow",
}))

restricted_principal_input := tls_plan(object.union(tls_statement, {
	"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
}))

limited_action_input := tls_plan(object.union(tls_statement, {
	"Action": "s3:GetObject",
}))

limited_resource_input := tls_plan(object.union(tls_statement, {
	"Resource": "arn:aws:s3:::other-bucket/*",
}))

missing_condition_input := tls_plan(object.remove(tls_statement, {
	"Condition",
}))

extra_condition_input := tls_plan(object.union(tls_statement, {
	"Condition": {
		"Bool": {"aws:SecureTransport": "false"},
		"StringEquals": {"aws:PrincipalAccount": "123456789012"},
	},
}))

missing_policy_input := json.patch(compliant_input, [{
	"op": "remove",
	"path": "/resource_changes/1",
}])

wrong_bucket_input := json.patch(compliant_input, [{
	"op": "replace",
	"path": "/configuration/root_module/resources/0/expressions/bucket/references",
	"value": ["aws_s3_bucket.other.id", "aws_s3_bucket.other"],
}])

test_uploads_tls_deny_passes if {
	count(hipaa_s3_tls.deny) == 0 with input as compliant_input
}

test_uploads_tls_boolean_false_passes if {
	count(hipaa_s3_tls.deny) == 0 with input as boolean_false_input
}

test_uploads_tls_allow_fails if {
	some msg in hipaa_s3_tls.deny with input as allow_input
	contains(msg, "GAP-03")
	contains(msg, "aws_s3_bucket.uploads")
}

test_uploads_tls_restricted_principal_fails if {
	some msg in hipaa_s3_tls.deny with input as restricted_principal_input
	contains(msg, "GAP-03")
	contains(msg, "aws_s3_bucket.uploads")
}

test_uploads_tls_limited_action_fails if {
	some msg in hipaa_s3_tls.deny with input as limited_action_input
	contains(msg, "GAP-03")
	contains(msg, "aws_s3_bucket.uploads")
}

test_uploads_tls_limited_resource_fails if {
	some msg in hipaa_s3_tls.deny with input as limited_resource_input
	contains(msg, "GAP-03")
	contains(msg, "aws_s3_bucket.uploads")
}

test_uploads_tls_missing_condition_fails if {
	some msg in hipaa_s3_tls.deny with input as missing_condition_input
	contains(msg, "GAP-03")
	contains(msg, "aws_s3_bucket.uploads")
}

test_uploads_tls_extra_condition_fails if {
	some msg in hipaa_s3_tls.deny with input as extra_condition_input
	contains(msg, "GAP-03")
	contains(msg, "aws_s3_bucket.uploads")
}

test_uploads_tls_missing_policy_fails if {
	some msg in hipaa_s3_tls.deny with input as missing_policy_input
	contains(msg, "GAP-03")
	contains(msg, "aws_s3_bucket.uploads")
}

test_uploads_tls_wrong_bucket_fails if {
	some msg in hipaa_s3_tls.deny with input as wrong_bucket_input
	contains(msg, "GAP-03")
	contains(msg, "aws_s3_bucket.uploads")
}

test_uploads_tls_wildcard_resource_fails if {
	fixture := tls_plan(object.union(tls_statement, {"Resource": "*"}))
	some msg in hipaa_s3_tls.deny with input as fixture
	contains(msg, "GAP-03")
}

test_uploads_tls_objects_only_fails if {
	fixture := tls_plan(object.union(tls_statement, {
		"Resource": ["arn:aws:s3:::test-uploads/*"],
	}))
	some msg in hipaa_s3_tls.deny with input as fixture
	contains(msg, "GAP-03")
}
