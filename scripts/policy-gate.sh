#!/usr/bin/env bash
# scripts/policy-gate.sh
#
# Saved Terraform plan:
#   bash scripts/policy-gate.sh --workspace terraform
#
# Existing plan JSON:
#   bash scripts/policy-gate.sh --workspace terraform \
#     --plan-json /tmp/cgep-plan.json
#
# Optional: --policy <dir> --evidence-dir <dir>
set -euo pipefail

POLICY_DIR="policies"
WORKSPACE=""
EVIDENCE_DIR="evidence/capstone"
PLAN_JSON=""

usage() {
  printf 'Usage: %s --workspace <path> [--policy <dir>] [--evidence-dir <dir>] [--plan-json <file>]\n' \
    "$0" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace|--policy|--evidence-dir|--plan-json)
      if [[ $# -lt 2 ]]; then
        printf 'ERROR: Missing value for %s\n' "$1" >&2
        usage
        exit 2
      fi

      if [[ -z "$2" || "$2" == --* ]]; then
        printf 'ERROR: Invalid value for %s\n' "$1" >&2
        usage
        exit 2
      fi

      case "$1" in
        --workspace)    WORKSPACE="$2" ;;
        --policy)       POLICY_DIR="$2" ;;
        --evidence-dir) EVIDENCE_DIR="$2" ;;
        --plan-json)    PLAN_JSON="$2" ;;
      esac

      shift 2
      ;;
    *)
      printf 'ERROR: Unknown argument: %s\n' "$1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -z "$WORKSPACE" ]]; then
  usage
  exit 2
fi

if [[ ! -d "$WORKSPACE" || ! -d "$POLICY_DIR" ]]; then
  printf 'ERROR: Workspace and policy directories must exist.\n' >&2
  exit 2
fi

for TOOL in opa conftest; do
  if ! command -v "$TOOL" >/dev/null 2>&1; then
    printf 'ERROR: Required tool is unavailable: %s\n' "$TOOL" >&2
    exit 2
  fi
done

mkdir -p "$EVIDENCE_DIR"

# Preserve the lab's saved-plan workflow.
# --plan-json lets local tests use an existing JSON fixture instead.
if [[ -z "$PLAN_JSON" ]]; then
  if ! command -v terraform >/dev/null 2>&1; then
    printf 'ERROR: Terraform is required to read the saved plan.\n' >&2
    exit 2
  fi

  if [[ ! -f "$WORKSPACE/tfplan" ]]; then
    printf 'ERROR: Missing saved plan: %s/tfplan\n' "$WORKSPACE" >&2
    exit 2
  fi

  PLAN_JSON="$WORKSPACE/plan.json"
  terraform -chdir="$WORKSPACE" show -json tfplan > "$PLAN_JSON"
fi

if [[ ! -f "$PLAN_JSON" || ! -r "$PLAN_JSON" || ! -s "$PLAN_JSON" ]]; then
  printf 'ERROR: Plan JSON must be readable and nonempty: %s\n' \
    "$PLAN_JSON" >&2
  exit 2
fi

printf 'Running policy unit tests...\n'
opa test "$POLICY_DIR" -v --fail-on-empty \
  2>&1 | tee "$EVIDENCE_DIR/opa-tests.txt"

printf '\nChecking Terraform plan: %s\n' "$PLAN_JSON"

# Capture the report even when policies fail.
# Preserve Conftest's exit code instead of deciding from report contents.
STATUS=0
conftest test "$PLAN_JSON" \
  --policy "$POLICY_DIR" \
  --all-namespaces \
  --parser json \
  --output json \
  > "$EVIDENCE_DIR/conftest-results.json" \
  || STATUS=$?

cat "$EVIDENCE_DIR/conftest-results.json"

if [[ "$STATUS" -eq 0 ]]; then
  printf '\npolicy-gate: PASS\n'
else
  printf '\npolicy-gate: FAIL\n'
fi

printf 'Report: %s/conftest-results.json\n' "$EVIDENCE_DIR"
exit "$STATUS"
