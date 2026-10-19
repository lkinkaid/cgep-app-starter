# Acme Health: GRC Engineering Capstone Write-up

## Primary framework

I chose the **HIPAA Security Rule** because Acme Health's patient-intake scenario
centers on electronic protected health information (ePHI). Its safeguards give
the encryption, access, recovery, and audit work a direct healthcare context.
HIPAA therefore fits this scenario more directly than SOC 2 or CMMC Level 2,
with implementation guidance from
[NIST SP 800-66 Rev. 2](https://csrc.nist.gov/pubs/sp/800/66/r2/final).

This capstone implements selected technical safeguards. The OSCAL component
marks each provision as **partial** to distinguish these protections from a
complete organizational HIPAA compliance program.

## Control coverage

All eight named gaps have Terraform remediations; five also have dedicated
Rego enforcement. “Terraform only” means the configuration is implemented but
has no dedicated regression policy in this suite.

| Gap | HIPAA provision | Implemented remediation | Enforcement |
| --- | --- | --- | --- |
| GAP-01: S3 encryption | 164.312(a)(2)(iv) | Uploads default to SSE-KMS with a customer-managed, rotating key. | **Both** — Terraform + [S3 CMK policy](policies/hipaa_s3_cmk.rego) |
| GAP-02: DynamoDB encryption | 164.312(a)(2)(iv) | Submissions table uses its own customer-managed, rotating key. | **Both** — Terraform + [DynamoDB CMK policy](policies/hipaa_dynamodb_cmk.rego) |
| GAP-03: Transport security | 164.312(e)(1) | Bucket policy explicitly denies non-TLS requests to bucket and object resources. | **Both** — Terraform + [TLS policy](policies/hipaa_s3_tls.rego) |
| GAP-04: Version recovery | 164.308(a)(7) | Uploads versioning retains prior object versions. | **Both** — Terraform + [versioning policy](policies/hipaa_s3_versioning.rego) |
| GAP-05: Network placement | 164.312(e)(1) | Lambda uses private subnets, restricted HTTPS egress, and scoped S3/DynamoDB gateway endpoints. | **Terraform only** |
| GAP-06: Failure handling and telemetry | 164.308(a)(7); 164.312(b) | Reserved concurrency of 10, encrypted asynchronous DLQ with 14-day retention, active tracing, and 90-day Lambda logs. | **Terraform only** |
| GAP-07: Runtime permissions | 164.312(a)(1) | Table-specific PutItem, uploads-prefix PutObject, and scoped supporting KMS permissions. | **Both** — Terraform + [least-privilege policy](policies/hipaa_lambda_least_privilege.rego) |
| GAP-08: API protections | 164.312(b) | REST API access logs, throttling, metrics, tracing, and an associated WAF web ACL. | **Terraform only** |

The GAP-06 HIPAA mapping is my documented interpretation of its recovery and
audit support, as recorded in [the component](oscal/components/your-component.json).
The policy suite passes **87 tests**, including positive and negative cases.
GAP-07 also checks supporting policies, embedded policies, alternate
attachments, and unresolved policy documents.

## Design decisions

I adapted the previous labs' infrastructure, policy, evidence, and OSCAL patterns,
using the
[brief](https://github.com/GRCEngClub/cgep-labs/blob/main/guides/07_01_capstone_brief.md)
and [companion](https://github.com/GRCEngClub/cgep-labs/blob/main/guides/07_02_capstone_companion.md)
to bound the work.

- **Region and account:** I retained `us-east-1` and one sandbox account to reuse
  the existing environment. Separate buckets and KMS keys isolate purposes
  within the account, while accepting shared administrative authority and no
  regional failover.
- **Evidence retention:** Versioning, a dedicated KMS key, and **30-day
  GOVERNANCE Object Lock** preserve evidence while supporting sandbox cleanup.
  CI has no bypass permission, but sufficiently privileged administrators can
  bypass GOVERNANCE retention. The encryption key must remain available too.
- **Deployment and identity:** Required PRs and `grc-gate` protect `main`.
  Successful main pushes automatically apply the checked saved plan; PR and
  manual runs do not apply. Separate OIDC plan/apply roles avoid stored AWS
  keys in CI. Workflow serialization and S3 state locking coordinate deployment.
- **Deployment scope:** CI maintains locally bootstrapped resources; most new
  infrastructure, CI permission changes, and teardown require local administration.
  Account-wide read access and runtime-policy maintenance are accepted limits in
  [CI_PERMISSIONS.md](terraform/CI_PERMISSIONS.md).
- **Terraform and policy:** Terraform establishes configuration and ownership;
  OPA/Conftest blocks selected regressions. TFLint and tfsec provide additional
  checks. I accepted the existing tfsec suppressions and HIGH severity blocking
  threshold, with exception review and Checkov deferred.
- **Network and telemetry:** Private subnets and gateway endpoints reuse the
  starter VPC without adding NAT. A Regional REST API supports direct WAF
  attachment. Metadata access logs, disabled execution/data tracing, and disabled
  WAF request sampling reduce payload exposure. CloudTrail captures management
  events with log-file validation enabled.
- **Ownership and reproducibility:** The workload uses S3 state. Its backend
  bucket and four configuration resources belong to a separate local-state
  [bootstrap stack](bootstrap/state-backend/README.md), retired last. Shared OIDC
  remains owned by the previous lab. Provider locks preserve versions; retaining
  `reset_on_delete = true` under AWS provider 5.100.0 avoids the unnecessary
  account-setting update that previously failed CI, accepting its deprecation warning.
- **OSCAL:** I retained the lab scaffolding and published a selected five-control
  HIPAA catalog. Trestle validates the documents and resolves the profile; resource
  properties and evidence links connect controls to implementation. The catalog URL follows
  `main`, accepting a mutable source reference.

## How the pipeline produces evidence

[PR #9](https://github.com/lkinkaid/cgep-app-starter/pull/9) published Layer 4.
Its PR gate passed, and merging triggered the latest run I verified:
[**39180939508**](https://github.com/lkinkaid/cgep-app-starter/actions/runs/39180939508).

1. **Plan:** Terraform initializes shared state, runs formatting/validation and
   lint checks, then saves `tfplan` and exports its JSON.
2. **Policy check:** OPA tests, Conftest, and tfsec check the proposed configuration.
3. **Apply:** On a successful `main` push, the deployment role applies that same
   saved plan.
4. **Sign:** The capture script bundles plan exports, test/scan reports,
   available logs, run outcomes, and a SHA-256 manifest. Cosign signs the archive
   using GitHub OIDC.
5. **Upload:** The archive, checksum, signature bundle, and receipt go to the
   evidence vault. The receipt records the archive's S3 version ID.

For run `39180939508`, attempt `1`:

- Commit: `d1f5a0e012db09a4535073b5a0cdf01f6fdd8f71`
- Evidence version: `BgD7.UB_Fh7NGqcIIcz.cccdKm34ygAW`
- Verification: **Integrity PASS, Authenticity PASS, Preservation PASS; CHAIN INTACT**
- Checked GOVERNANCE retention: until `2026-11-18T00:29:28.709Z`

From the repository root, with authorized vault access:

```bash
bash scripts/verify-evidence.sh 39180939508 \
  --vault acme-health-intake-grc-evidence-vault-8aa64d23 \
  --profile default
```

The verifier retrieves the recorded archive version, checks its hash and
workflow signing identity, matches signed run metadata, and checks retention.
These checks establish evidence custody; the successful workflow separately
confirms Apply passed. The component retains its earlier verified baseline
reference to run `37979254813`.

The negative demonstration is [PR #2](https://github.com/lkinkaid/cgep-app-starter/pull/2):
[run 37938505045](https://github.com/lkinkaid/cgep-app-starter/actions/runs/37938505045)
rejected suspended uploads versioning, skipped Apply, and still signed and
uploaded the failure evidence.

## Trade-offs and what I'd do with another sprint

I prioritized a working baseline, five deeply tested policies, and verifiable
evidence. Terraform-only protections can regress without a dedicated policy
denial, and checks run on PRs, main pushes, or manual requests rather than on a
schedule. The API smoke test returned `status: received`, but broader failure
and recovery exercises remain unfinished.

With another sprint, I would first add GAP-05/06/08 regression coverage and
exercise asynchronous failures, synchronous API errors, and recovery. Next, I
would implement the planned read-only `continuous-detection.yml`, distinguish
drift from check errors, and retain detection/recovery evidence. Further IAM
review would address permissions boundaries and effective permissions beyond
the current plan checks.

## What I didn't get to

[BACKLOG.md](BACKLOG.md) tracks the deferred work: network/telemetry tests,
scheduled detection, further IAM hardening, Checkov and exception review,
pipeline summaries, a reviewer index, module extraction, dependency integrity,
and bootstrap validation/previous-lab ownership follow-up. Signing currently
requires a successful plan; preserving signed evidence for earlier failures
also remains open.

Patient authentication, a complete contingency program, restore testing, and
CloudTrail data-event coverage are not claimed. The DLQ handles asynchronous
Lambda failures; API Gateway invokes synchronously. Versioning supports
recovery but is not a tested recovery plan.

Licensing/attribution, secret-history review, and verification of the final
submission commit remain completion tasks rather than stretch goals.

## AI and tooling transparency

I used **Codex as a tutor and development assistant within Zed** to modernize my
approach: explaining concepts, comparing designs, troubleshooting, reviewing code,
and drafting OSCAL and documentation. I used Zed for editing and terminal work,
checking results through Terraform plans, policy tests, Trestle validation,
the API smoke test, PR checks, and evidence verification. I remain responsible
for the implementation and claims in this submission.
