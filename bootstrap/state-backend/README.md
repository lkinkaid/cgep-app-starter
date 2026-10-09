# State backend bootstrap stack

This separate root stack adopts the existing
`acme-health-intake-tfstate-420539147061` bucket and its versioning, encryption,
public-access block, and ownership controls. It uses local state so its own
state does not depend on the bucket it will eventually retire. Back up that
local state securely; both state and saved plans are ignored by Git.

The 2026-10-09 AWS inventory found no bucket policy, tags, or lifecycle rules,
so no such settings are added. SSE-S3, enabled versioning, all four public
access blocks, and BucketOwnerEnforced ownership match the existing bucket.
The AWS response also includes a blocked SSE-C encryption setting, which AWS
provider 5.100.0 does not expose in this resource; it remains outside the
provider's configuration coverage. Any later encryption change must account
for that setting. This adoption does not upgrade the provider or encryption.

## Step 1: Review adoption

From the repository root:

```bash
(
  set -e
  eval "$(aws configure export-credentials --profile default --format env)"
  aws sts get-caller-identity
  terraform -chdir=bootstrap/state-backend init -input=false
  terraform -chdir=bootstrap/state-backend validate -no-color
  terraform -chdir=bootstrap/state-backend plan -input=false -out=adopt.tfplan
  terraform -chdir=bootstrap/state-backend show -no-color adopt.tfplan
)
```

The plan should import five resource addresses with no changes to existing
AWS configuration. Review any updates before proceeding. Configuration alone
does not adopt resources: the import plan must be applied to record ownership.

## Step 2: Record ownership after reviewing the plan

```bash
(
  set -e
  eval "$(aws configure export-credentials --profile default --format env)"
  terraform -chdir=bootstrap/state-backend apply adopt.tfplan
  terraform -chdir=bootstrap/state-backend plan -input=false
)
```

The follow-up plan should report no changes. Keep the import blocks as an
adoption record; do not import the same resources into the workload state.

## Step 3: Retire this stack last

First finish capstone teardown and archive its final remote state and any
required historical versions. Confirm no other stack uses the bucket. Only
then prepare a destroy plan for this bootstrap stack. `force_destroy = false`
requires deliberate removal of all object versions and delete markers before
bucket deletion; it prevents an ordinary destroy from silently purging state.

Stop active capstone workflows before teardown and use the local deployment
principal to review a saved destroy plan. Avoid the starter's `make destroy`,
which automatically approves destruction of the whole capstone stack.

Keep retained evidence and its enabled KMS key together until the evidence
requirements and all object-version retention periods are complete. Preserve
any required CloudTrail logs with their key as well; Object Lock does not
protect a decryption key from deletion.

With AWS provider 5.x and `reset_on_delete` omitted, the regional API Gateway
logging setting survives Terraform destruction. Check other REST APIs, then
clear or replace that setting before deleting its logging role.

The shared OIDC provider remains owned by the previous lab's OIDC stack.
Retire it only after neither repository nor any other role needs it. The lab's
`vault-write.tf` import must also be applied before Terraform manages that
inline policy. Keep each resource in exactly one owning state.
