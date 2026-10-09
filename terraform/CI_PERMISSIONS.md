# CI deployment permissions

The `grc_apply` role is assumed only by this repository on `main`. Pull-request
runs continue to use `grc_gate`. The baseline is bootstrapped locally; CI maintains
its existing resources using the reviewed, policy-checked saved Terraform plan.

## Supported maintenance

| Area          | Permitted operations                                                                              | Write scope                                                             |
| ------------- | ------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| Lambda        | Update code/configuration, publish versions, manage invocation permissions, concurrency, and tags | Existing intake function                                                |
| S3            | Update encryption, public-access blocking, versioning, bucket policies, and tags                  | Existing uploads, evidence, and CloudTrail buckets                      |
| DynamoDB      | Update table settings, continuous backups, TTL, and tags                                          | Existing submissions table                                              |
| KMS           | Manage rotation, descriptions, and tags; create DynamoDB service grants                           | Four existing keys; grants only on the submissions key through DynamoDB |
| API Gateway   | Update the REST API; maintain methods, integrations, stages, and deployments; associate WAF       | Existing REST API and its children                                      |
| WAF           | Update rules, association, and tags                                                               | Existing regional web ACL and API stage                                 |
| Networking    | Update VPC/subnet attributes, endpoints, security-group rules, routes, associations, and tags     | Existing capstone VPC resources by ARN                                  |
| Runtime IAM   | Update inline policies and tags; attach/detach approved AWS logging policies                      | Intake Lambda and API logging roles only                                |
| Observability | Update log retention/encryption/tags, DLQ attributes/tags, and management-trail settings          | Existing capstone log groups, queue, and trail                          |

Existing permissions retain exact state/lock paths, evidence uploads under
`runs/`, evidence encryption, and service-constrained passing of the two runtime
roles. The inherited AWS `ReadOnlyAccess` managed policy is account-wide;
mutation permissions added here are resource-scoped.

Runtime inline-policy maintenance delegates control of the workload roles'
permissions to reviewed Terraform changes. The five current Rego policies
include the Lambda least-privilege check. This is deployment authority, so
main's required PR and policy check remain part of the design.

## Administrative operations

CI cannot modify either CI role, its managed deployment policies, or the shared
OIDC provider. Permission changes require local administrative bootstrap.
Creating/replacing top-level infrastructure (including functions, buckets,
tables, keys, VPC resources, REST APIs, web ACLs, queues, and log groups), full
teardown, key-policy/alias changes, Object Lock configuration changes, and the
regional API Gateway account logging setting remain local operations.
API Gateway deployment replacement within the existing API is supported.

The role has no evidence-object deletion, Object Lock bypass, bucket deletion,
KMS key deletion, or CloudTrail stop-logging permission. The added IAM attachment
permission accepts only the two existing AWS service-role logging policies;
it cannot attach AdministratorAccess.

## Installing permission changes

Use the existing default-profile deployment principal and shared OIDC provider:

```bash
AWS_PROFILE=default \
TF_VAR_existing_github_oidc_provider_arn=arn:aws:iam::420539147061:oidc-provider/token.actions.githubusercontent.com \
terraform -chdir=terraform plan -input=false -out=tfplan

bash scripts/policy-gate.sh --workspace terraform --evidence-dir evidence/capstone

AWS_PROFILE=default terraform -chdir=terraform apply tfplan
```

Review the full plan before applying. This expansion adds three managed policies
and three attachments and updates the existing Lambda inline deployment policy;
it does not change workload configuration. Commit and merge the Terraform change
through the normal PR gate after bootstrap so `main` matches shared state.

The strengthened GAP-07 gate validates supporting Lambda policy contents, embedded role policies, and alternate attachments. All 87 policy tests pass. Unresolved supporting policy JSON fails closed. Resource-scoped deployment permissions can still weaken controls outside the current policy suite, including key rotation, bucket policies, and CloudTrail event selection; those changes require explicit PR review.

## Verification

Terraform validation and the saved-plan policy gate passed (59/59 OPA tests).
The four proposed policy documents passed AWS IAM Access Analyzer validation
with no findings. Twenty-five IAM simulations covered representative allowed
operations and denials for unrelated workloads, both CI roles, administrative
policy attachment, evidence deletion/bypass, and key deletion. The local reports
are under the ignored `evidence/capstone/` directory.

These simulations check identity-policy decisions. They do not prove every
service API dependency, resource policy, or organization policy permits a future
change. A real post-merge run is the final deployment check for each change.
