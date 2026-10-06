# Acme Health: GRC Engineering Capstone Write-up

## Primary framework

[Name your framework in the first paragraph. Three sentences on why it fits
this telehealth system better than the other two.]

## Control coverage

[For each gap from GAPS.md: which control it maps to, and whether you closed
it in Terraform, enforced it in policy, or both. A table works well here.]

## Design decisions

[Walk each decision from the brief: region, Object Lock mode, apply-on-merge
vs manual gate, single vs separate account, Terraform-vs-policy split.
For each, state what you chose and the trade-off you accepted.]

## How the pipeline produces evidence

[Trace one run end to end: PR opened → gate → apply → sign → vault.
Name the run ID an assessor can verify.]

## Trade-offs and what I'd do with another sprint

[Be specific and honest. This section earns more than a padded "everything works."]

## What I didn't get to

[Name it plainly. This costs nothing and signals judgment.]
