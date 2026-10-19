# Post-capstone stretch goals

Address the stretch goals below after completing the remaining capstone
submission requirements.
Keep the current Terraform remediations and the five required Rego policies in
place. This backlog does not defer or remove the existing GAP-07 policy gate.

## Current capstone scope

Use the [capstone brief](https://github.com/GRCEngClub/cgep-labs/blob/main/guides/07_01_capstone_brief.md)
and [companion](https://github.com/GRCEngClub/cgep-labs/blob/main/guides/07_02_capstone_companion.md)
to guide the remaining work. Layer 4 is complete: the HIPAA catalog, profile,
and component are validated and published on `main`, with mappings to implemented
controls, resource addresses, and verified signed evidence. WRITEUP.md now records
coverage, decisions, trade-offs, and AI assistance. The README now includes grader
verification instructions. Remaining submission checks cover licensing/attribution,
secret review, and the final commit and evidence verification.
Preserve the working Layers 1–4 and their evidence.

The bounded rubric improvements below are deferred until the capstone is
complete. Required policy gating, branch protection, control mappings,
reproducible delivery, and submission requirements remain completion checks;
listing related enhancements here does not waive those requirements.

### Submission completion checks

These checks stay in the capstone scope and are not post-capstone stretch work.

- [x] Complete and publish the HIPAA OSCAL catalog, component, and profile;
      validate the models, resolve the profile, and check control mappings,
      resource addresses, and signed evidence references (PR #9).
- [x] Complete WRITEUP.md with the primary framework, gap coverage, design
      decisions, a verified pipeline example, and remaining limitations.
- [x] Update the README with the current project scope, this repository's clone
      URL, prerequisites, and grader verification instructions for Terraform,
      policies, OSCAL, and signed evidence. Replace stale starter deployment and
      teardown guidance.
- [x] Add an AI transparency disclosure describing assistance and verification
      in WRITEUP.md.
- [ ] Resolve repository licensing and retain applicable starter attribution
      before submission.
- [x] Verify required branch protection: changes require a pull request and
      the `grc-gate` status check, including for administrators.
- [ ] Review the repository and its history for exposed secrets before submission.
- [ ] Record the final submission commit SHA and verify its successful main run
      and signed evidence after the remaining documentation changes are merged.

Layer 4 was published in [PR #9](https://github.com/lkinkaid/cgep-app-starter/pull/9)
at commit `d1f5a0e012db09a4535073b5a0cdf01f6fdd8f71`.
[Main run 39180939508](https://github.com/lkinkaid/cgep-app-starter/actions/runs/39180939508)
completed Apply, Sign, and Upload successfully. Post-merge evidence verification
reported Integrity, Authenticity, and Preservation PASS, with CHAIN INTACT.
The checked evidence version has GOVERNANCE retention until
`2026-11-18T00:29:28.709Z`.

## GAP-05: Network regression coverage

- [ ] Add policy checks for Lambda private-subnet and security-group attachment,
      endpoint routing, and the intended S3/DynamoDB endpoint-policy scope.
- [ ] Add negative fixtures that remove or broaden those protections.
- [ ] Exercise the deployed handler connectivity and confirm that writes reach
      only the intended data stores through the configured endpoints.

Current baseline: Lambda uses private subnets, restricted HTTPS egress, and S3
and DynamoDB gateway endpoints. Dedicated regression policies are stretch work.

## GAP-06: Operational failure and telemetry coverage

- [ ] Add policy checks for reserved concurrency, the asynchronous DLQ, tracing,
      and log retention, with negative fixtures for missing settings.
- [ ] Test an asynchronous failure reaching the DLQ and separately test API
      Gateway synchronous error handling; synchronous failures do not use the DLQ.
- [ ] Verify useful metrics and traces without capturing patient payloads;
      document the operator response to failures and throttling.

Current baseline: reserved concurrency, an encrypted DLQ, active tracing, and
managed log retention are configured. Failure-path exercises are stretch work.

## GAP-07: Further IAM hardening

- [ ] Review service-required wildcard permissions and opportunities to narrow
      supporting permissions without breaking the handler or its telemetry.
- [ ] Evaluate a permissions boundary for runtime roles as an additional limit
      on the deployment role's ability to change inline permissions.
- [ ] Extend effective-permission verification to relevant resource policies,
      boundaries, and organization controls where present; retain negative tests
      for alternate attachments and unresolved supporting policy documents.

Current baseline: the handler has scoped PutItem/PutObject permissions, and the
existing least-privilege gate checks supporting policies, embedded policies,
and alternate attachments. Its remediation and passing tests remain part of
capstone delivery; the items above extend that work.

## Continuous detection: Scheduled Terraform drift checks

- [ ] Add `.github/workflows/continuous-detection.yml` with a daily schedule
      and a manual trigger, checking the deployed infrastructure against `main`.
- [ ] Use the existing OIDC plan role and deployment concurrency group; the
      workflow must not apply changes or assume the deployment role.
- [ ] Run a normal Terraform plan with `-detailed-exitcode`, distinguishing
      no proposed changes (0), check failure (1), and proposed changes (2). Inspect
      plan drift information before labeling differences as out-of-band changes.
- [ ] Publish an Actions summary with affected resource addresses, changed
      settings, and remediation steps. Fail the run on detected differences or
      check errors so workflow notifications can alert the operator.
- [ ] Capture detection outcomes, commit, timestamp, and findings through the
      existing signed evidence and vault-upload process. Preserve drift findings
      independently of the policy gate, which evaluates the planned configuration.
- [ ] Test outcome classification and error handling, then demonstrate drift
      detection and recovery using a harmless workload tag change. Restore the
      original tag and retain both detected-drift and clean-state evidence.

Current baseline: the existing gate runs on pull requests, pushes to `main`,
and manual requests. Recurring drift detection is deferred until after capstone
completion.
This limits monitoring to Terraform-visible configuration; deferring it leaves
the rubric continuous-monitoring and detection category partially addressed.

## Reviewer visibility: Pipeline summaries

- [ ] Add a readable GitHub Actions summary connecting gate outcomes and
      findings to control identifiers, remediation, and evidence locations.
- [ ] Make blocked and successful run evidence easy to compare without reading
      the full job logs.

Current baseline: the workflow retains gate reports, signed bundles, and upload
receipts. Required pull-request and `grc-gate` branch protections have been
verified; enhanced summaries are deferred.

## Engineering hygiene: Bootstrap ownership and validation

- [x] Complete the capstone backend adoption imports: five resources imported
      with no infrastructure changes; follow-up plan reports no changes.
- [ ] Securely back up the local bootstrap state and retain it for future
      management and teardown.
- [ ] Reconcile the prepared previous-lab inline-policy import in its owning
      repository and state; avoid duplicate resource ownership.
- [x] Commit the capstone bootstrap configuration and provider lock files,
      with generated plans and state excluded (PRs #4 and #6).
- [ ] Review and commit the separate previous-lab adoption configuration and
      applicable provider lock file in its owning repository.
- [ ] Add formatting and validation checks for the bootstrap Terraform root
      without importing or applying resources from CI.
- [ ] Clarify historical bootstrap test counts in `terraform/CI_PERMISSIONS.md`
      so they are distinguishable from current policy-suite results.

Current baseline: the capstone bootstrap configuration and lock files are
committed on `main`. The state bucket and its four configuration resources
were imported into the separate local bootstrap state on 2026-10-09; the
follow-up plan reports no changes. Bootstrap CI validation remains deferred.
Required secret exclusion and reproducibility remain submission checks.

## Control traceability: Reviewer aids

- [ ] Extend the required Layer 4 control mappings with a compact reviewer index
      linking each control to its Terraform resources, policy, positive and
      negative tests, and evidence.
- [ ] Consider generating that index from existing metadata to reduce manual
      maintenance after the capstone.

Current baseline: policy metadata, Terraform comments, and the published Layer 4
OSCAL mappings provide traceability to implemented controls and signed evidence.
Final documentation remains in the capstone scope; the supplemental index and
its automation are deferred.

## Security scanning: Checkov integration

- [ ] Add a pinned Checkov version to the GRC workflow to scan the workload
      Terraform configuration after capstone completion.
- [ ] Review findings alongside tfsec and the existing Rego policies; select
      the checks that should block deployment and document any justified
      suppressions with their control context.
- [ ] Review existing tfsec suppressions and the HIGH severity gate threshold;
      document exception rationale, affected controls, and compensating controls.
- [ ] Include Checkov reports and scan outcomes in the signed evidence bundle
      and final gate enforcement.
- [ ] Demonstrate that a selected failing check blocks deployment and that
      the remediated configuration passes. Scanner errors must fail the check.

Current baseline: the workflow uses Terraform formatting and validation,
TFLint, OPA/Conftest, and tfsec. Checkov integration is deferred until after
capstone completion.

## Infrastructure quality: Reusable Terraform modules

- [ ] Evaluate cohesive module boundaries and document their inputs, outputs,
      and responsibilities before refactoring the workload root.
- [ ] Preserve resource ownership through reviewed address migrations; require
      a plan with no unintended resource replacement or configuration changes.
- [ ] Update address-dependent policies, tests, and OSCAL mappings together
      and verify the existing policy gate still passes.

Current baseline: the workload uses a root module with lab-style comments.
Module extraction is deferred until after capstone completion.

## Engineering hygiene: Workflow dependency integrity

- [ ] Pin GitHub Actions to verified full commit SHAs, retaining readable
      version comments alongside the pins.
- [ ] Verify directly downloaded tool binaries against trusted release
      checksums or signatures and fail installation when verification fails.
- [ ] Document a repeatable dependency-update and verification procedure.

Current baseline: provider lock files and tool versions are pinned; Actions
mostly use version tags. Additional dependency-integrity work is deferred.

## Evidence automation: Early failure coverage

- [ ] Capture lint, validation, and plan outcomes and available diagnostics
      when the pipeline fails before producing a saved plan.
- [ ] Extend signing and upload to useful failure evidence without requiring
      a successful plan or presenting absent plan results as successful checks.
- [ ] Demonstrate controlled lint, validation, and plan failures; confirm
      deployment stays blocked and failure evidence can be verified.

Current baseline: signing requires a successful plan. Policy-denial and apply
failure evidence is already preserved; earlier failure coverage is deferred.
