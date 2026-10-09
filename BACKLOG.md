# Post-capstone stretch goals

Address these after completing the capstone requirements, including Layer 4.
Keep the current Terraform remediations and the five required Rego policies in
place. This backlog does not defer or remove the existing GAP-07 policy gate.

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
