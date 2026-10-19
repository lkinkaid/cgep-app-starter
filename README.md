# Acme Health: HIPAA GRC Engineering Capstone

A hardened Patient Intake API built from the CGE-P starter: API Gateway, Lambda,
DynamoDB, S3, and the existing VPC. **HIPAA Security Rule** is the primary
framework. All eight starter gaps have Terraform remediations; five also have
dedicated Rego enforcement. This sandbox demonstrates selected technical
safeguards, with partial control coverage documented in OSCAL.

| Layer | Implementation |
| --- | --- |
| 1 — Infrastructure | [Terraform](terraform/): customer-managed keys, workload hardening, a versioned GOVERNANCE evidence vault, and multi-region CloudTrail. |
| 2 — Policy | [Five Rego policies and tests](policies/) evaluated against the saved Terraform plan. |
| 3 — Pipeline | [grc-gate.yml](.github/workflows/grc-gate.yml): Plan → Policy check → Apply on main → Sign → Upload. |
| 4 — OSCAL | [Catalog](oscal/catalogs/hipaa-security-rule.json), [profile](oscal/profiles/cge-p-minimum.json), and [component](oscal/components/your-component.json) connecting controls, resources, and evidence. |

Application behavior: [WORKLOAD.md](WORKLOAD.md). Original gaps: [GAPS.md](GAPS.md).
See [WRITEUP.md](WRITEUP.md) for decisions, coverage, limitations, and Codex/Zed
disclosure; [BACKLOG.md](BACKLOG.md) tracks remaining submission and stretch work.
Course requirements: [Capstone Brief](https://github.com/GRCEngClub/cgep-labs/blob/main/guides/07_01_capstone_brief.md)
and [Companion](https://github.com/GRCEngClub/cgep-labs/blob/main/guides/07_02_capstone_companion.md).

## Start here

```bash
git clone https://github.com/lkinkaid/cgep-app-starter.git
cd cgep-app-starter
git rev-parse HEAD
```

For grading, check out the supplied submission SHA with
`git checkout --detach COMMIT_SHA` (replace `COMMIT_SHA` with the actual SHA).
Run the commands below from the repository root.

Reference tool versions: Terraform **1.16.4**, OPA **1.21.1**, Conftest **0.71.1**,
Cosign **3.1.3**, and compliance-trestle **5.1.0** (`trestle`). Also install
AWS CLI v2, Python 3, Bash, Git, jq, tar, and `sha256sum` or `shasum`;
the optional API test uses make and curl. CI pins are recorded in the workflow;
provider versions are recorded in the committed Terraform lock files.

Local policy and OSCAL checks need no AWS credentials. Live planning and evidence
verification require authorized access to the deployed resources in account
`420539147061`, region `us-east-1`. Examples use AWS profile `default`; replace
that name if your granted profile differs.

## 1. Verify policies and OSCAL locally

```bash
opa test ./policies -v --fail-on-empty

trestle partial-object-validate \
  --file oscal/catalogs/hipaa-security-rule.json --element catalog
trestle partial-object-validate \
  --file oscal/profiles/cge-p-minimum.json --element profile
trestle partial-object-validate \
  --file oscal/components/your-component.json --element component-definition
```

Expected: **87 passing tests** and `VALID` for all three OSCAL files.

Resolve the profile in a new ignored workspace, preserving any existing
authoring copies. This fetches the published catalog from GitHub:

```bash
(
  set -e
  mkdir -p .trestle-work
  OSCAL_CHECK_DIR="$(mktemp -d "$PWD/.trestle-work/verify.XXXXXX")"
  trestle init --local --trestle-root "$OSCAL_CHECK_DIR"
  trestle import --trestle-root "$OSCAL_CHECK_DIR" \
    --file "$PWD/oscal/profiles/cge-p-minimum.json" \
    --output cge-p-minimum
  trestle author profile-resolve --trestle-root "$OSCAL_CHECK_DIR" \
    --name cge-p-minimum --output cge-p-minimum-resolved
  trestle validate --trestle-root "$OSCAL_CHECK_DIR" \
    --type catalog --name cge-p-minimum-resolved
  jq -e '.catalog.controls | length == 5' \
    "$OSCAL_CHECK_DIR/catalogs/cge-p-minimum-resolved/catalog.json"
)
```

Expected: a valid resolved catalog and `true` for the five-control count.

## 2. Verify the live Terraform plan and policy gate

This uses the existing account-specific S3 backend. Access must include resource
reads and state-lock operations. The credential export also supports SSO profiles.

```bash
(
  set -e
  umask 077
  AWS_CREDS_EXPORT="$(aws configure export-credentials --profile default --format env)"
  eval "$AWS_CREDS_EXPORT"
  unset AWS_CREDS_EXPORT
  export TF_VAR_existing_github_oidc_provider_arn=arn:aws:iam::420539147061:oidc-provider/token.actions.githubusercontent.com

  aws sts get-caller-identity
  test "$(aws sts get-caller-identity --query Account --output text)" = "420539147061"

  terraform -chdir=terraform init -input=false -lockfile=readonly
  terraform -chdir=terraform fmt -check -recursive
  terraform -chdir=terraform validate -no-color
  terraform -chdir=terraform plan -input=false -lock-timeout=30s -out=tfplan
  bash scripts/policy-gate.sh --workspace terraform --evidence-dir evidence/capstone
)
```

The verified baseline reported **no changes**, **87/87 tests**, and
`policy-gate: PASS`. Investigate any new plan differences; these commands do not
apply them. The gate regenerates `plan.json` from the newly saved `tfplan`.
The known `reset_on_delete` deprecation warning is explained in the write-up.
Generated state, plans, reports, and local Trestle workspaces are ignored by Git.

## 3. Verify pipeline history and signed evidence

- **Successful merge:** [PR #9](https://github.com/lkinkaid/cgep-app-starter/pull/9)
  and [main run 39180939508](https://github.com/lkinkaid/cgep-app-starter/actions/runs/39180939508).
  Apply, Sign, and Upload succeeded at commit
  `d1f5a0e012db09a4535073b5a0cdf01f6fdd8f71`.
- **Blocked policy demo:** [PR #2](https://github.com/lkinkaid/cgep-app-starter/pull/2)
  and [run 37938505045](https://github.com/lkinkaid/cgep-app-starter/actions/runs/37938505045).
  Suspended uploads versioning failed Policy check; Apply was skipped and
  failure evidence was signed and uploaded.

Verify the latest checked main-run bundle using a profile granted vault
object/version reads, `s3:GetObjectRetention`, and KMS decryption:

```bash
bash scripts/verify-evidence.sh 39180939508 \
  --vault acme-health-intake-grc-evidence-vault-8aa64d23 \
  --profile default
```

Expected: **Integrity PASS**, **Authenticity PASS**, **Preservation PASS**, and
**CHAIN INTACT**. The script checks the receipt-selected archive version,
SHA-256, GitHub workflow signing identity, signed run metadata, and active
retention. The checked version is `BgD7.UB_Fh7NGqcIIcz.cccdKm34ygAW`, retained in
GOVERNANCE mode until `2026-11-18T00:29:28.709Z`. Preservation verification will
fail after retention expires; verify a newer retained run for a later submission.

The OSCAL component links the earlier verified baseline run `37979254813`.
To follow those links, run the same verifier with that run ID. Access to the
public repository does not grant access to the private S3 vault.

## 4. Optional API smoke test

After backend initialization, run with make, curl, Python, and the same AWS profile:

```bash
make test AWS_PROFILE=default
```

Expected: a generated `submission_id` and `"status": "received"`. This posts a
synthetic intake record and writes workload data. Use synthetic data only;
patient authentication is outside the implemented baseline.

## Deployment, ownership, and teardown

Required PRs and `grc-gate` protect `main`. Successful main pushes apply the
checked plan; PR and manual-dispatch runs do not apply. The CI role maintains
existing resources; see [CI permissions](terraform/CI_PERMISSIONS.md) for
administrative operations and [bootstrap instructions](bootstrap/state-backend/README.md)
for separate backend ownership. A fresh account requires adapting the existing
backend, shared OIDC, and CI configuration before provisioning.

The starter's `make deploy` and `make destroy` automatically approve changes.
Use reviewed saved plans for administrative deployment or teardown. Retire the
workload before its backend; preserve retained evidence and its usable KMS key,
and check shared OIDC/API logging consumers before removal. KMS, WAF, storage,
and other deployed services can continue incurring charges while resources remain.

## License and attribution

Derived from [GRCEngClub/cgep-app-starter](https://github.com/GRCEngClub/cgep-app-starter)
and the CGE-P labs. Starter license notice: MIT. Fork freely. Submissions remain
learners' own work. License-file and attribution review remain tracked in
[BACKLOG.md](BACKLOG.md).
