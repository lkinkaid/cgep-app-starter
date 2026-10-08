#!/usr/bin/env bash
# Verify integrity, authenticity, and preservation of CI evidence.
#
# Usage:
#   bash scripts/verify-evidence.sh <run_id> \
#     --vault <bucket> [--profile <name>] [--identity <workflow-identity>]
#
# Defaults to evidence signed by grc-gate.yml on main.
# A run's receipt selects its most recently uploaded attempt.
set -euo pipefail

usage() {
  printf 'Usage: %s <run_id> --vault <bucket> [--profile <name>] [--identity <workflow-identity>]\n' \
    "$0" >&2
}

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

if [[ $# -eq 0 || "$1" == --* ]]; then
  usage
  exit 2
fi

RUN_ID="$1"
shift

VAULT="${EVIDENCE_VAULT:-}"
PROFILE_ARGS=()
IDENTITY="https://github.com/lkinkaid/cgep-app-starter/.github/workflows/grc-gate.yml@refs/heads/main"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --vault|--profile|--identity)
      if [[ $# -lt 2 || -z "$2" || "$2" == --* ]]; then
        printf 'ERROR: Missing or invalid value for %s\n' "$1" >&2
        usage
        exit 2
      fi

      case "$1" in
        --vault)    VAULT="$2" ;;
        --profile)  PROFILE_ARGS=(--profile "$2") ;;
        --identity) IDENTITY="$2" ;;
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

if [[ -z "$VAULT" || ! "$RUN_ID" =~ ^[0-9]+$ ]]; then
  printf 'ERROR: Supply a vault and a numeric GitHub Actions run ID.\n' >&2
  usage
  exit 2
fi

for TOOL in aws cosign jq tar python3; do
  if ! command -v "$TOOL" >/dev/null 2>&1; then
    printf 'ERROR: Required tool is unavailable: %s\n' "$TOOL" >&2
    exit 2
  fi
done

if command -v sha256sum >/dev/null 2>&1; then
  SHASUM=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
  SHASUM=(shasum -a 256)
else
  printf 'ERROR: Need sha256sum or shasum.\n' >&2
  exit 2
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

PREFIX="runs/${RUN_ID}"

# The receipt selects the archive; do not choose the first matching file.
aws "${PROFILE_ARGS[@]}" s3 cp \
  "s3://${VAULT}/${PREFIX}/receipt.json" \
  "$WORK/receipt.json"

jq -e \
  --arg run_id "$RUN_ID" \
  --arg vault "$VAULT" \
  '
    .run_id == $run_id and
    .vault == $vault and
    (.run_attempt | type == "string" and test("^[0-9]+$")) and
    (.commit | type == "string" and test("^[0-9a-fA-F]{40}$")) and
    (.sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
    (.version_id | type == "string" and
      length > 0 and . != "null" and . != "None")
  ' "$WORK/receipt.json" >/dev/null \
  || fail "Invalid or mismatched receipt."

RUN_ATTEMPT=$(jq -r '.run_attempt' "$WORK/receipt.json")
COMMIT=$(jq -r '.commit' "$WORK/receipt.json")
VERSION_ID=$(jq -r '.version_id' "$WORK/receipt.json")
EXPECTED=$(jq -r '.sha256' "$WORK/receipt.json")

BUNDLE="evidence-${RUN_ID}-${RUN_ATTEMPT}-${COMMIT}.tar.gz"
KEY="${PREFIX}/${BUNDLE}"

jq -e --arg key "$KEY" '.bundle_key == $key' \
  "$WORK/receipt.json" >/dev/null \
  || fail "Receipt archive key does not match its run metadata."

# Download the exact archive version recorded by the workflow.
aws "${PROFILE_ARGS[@]}" s3api get-object \
  --bucket "$VAULT" \
  --key "$KEY" \
  --version-id "$VERSION_ID" \
  "$WORK/$BUNDLE" >/dev/null

aws "${PROFILE_ARGS[@]}" s3 cp \
  "s3://${VAULT}/${KEY}.sha256" \
  "$WORK/${BUNDLE}.sha256"

aws "${PROFILE_ARGS[@]}" s3 cp \
  "s3://${VAULT}/${KEY}.sig.bundle" \
  "$WORK/${BUNDLE}.sig.bundle"

# 1. Integrity
ACTUAL=$("${SHASUM[@]}" "$WORK/$BUNDLE" | awk '{print $1}')
SIDECAR=$(cat "$WORK/${BUNDLE}.sha256")

[[ "$ACTUAL" == "$EXPECTED" && "$ACTUAL" == "$SIDECAR" ]] \
  || fail "Archive checksum does not match the receipt and sidecar."

printf 'Integrity: PASS\n'

# 2. Authenticity
cosign verify-blob \
  --bundle "$WORK/${BUNDLE}.sig.bundle" \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer \
    "https://token.actions.githubusercontent.com" \
  "$WORK/$BUNDLE"

# Bind the receipt to metadata inside the verified, signed archive.
tar -xOzf "$WORK/$BUNDLE" ./run.json > "$WORK/run.json"

jq -e \
  --arg run_id "$RUN_ID" \
  --arg run_attempt "$RUN_ATTEMPT" \
  --arg commit "$COMMIT" \
  '
    .run_id == $run_id and
    .run_attempt == $run_attempt and
    .commit == $commit
  ' "$WORK/run.json" >/dev/null \
  || fail "Signed run metadata does not match the receipt."

printf 'Authenticity: PASS\n'

# 3. Preservation: inspect retention on the verified archive version.
aws "${PROFILE_ARGS[@]}" s3api get-object-retention \
  --bucket "$VAULT" \
  --key "$KEY" \
  --version-id "$VERSION_ID" \
  --output json > "$WORK/retention.json"

python3 - "$WORK/retention.json" <<'PY'
import json
import sys
from datetime import datetime, timezone

with open(sys.argv[1], encoding="utf-8") as file:
    retention = json.load(file).get("Retention", {})

mode = retention.get("Mode")
if mode not in {"GOVERNANCE", "COMPLIANCE"}:
    sys.exit("FAIL: Object version has no recognized retention mode.")

try:
    until = datetime.fromisoformat(
        retention["RetainUntilDate"].replace("Z", "+00:00")
    )
except (KeyError, TypeError, ValueError):
    sys.exit("FAIL: Missing or invalid retention expiration.")

if until.tzinfo is None:
    sys.exit("FAIL: Retention expiration has no timezone.")

if until <= datetime.now(timezone.utc):
    sys.exit("FAIL: Object retention has expired.")

print(f"Preservation: PASS ({mode}, until {until.isoformat()})")
PY

printf 'CHAIN INTACT for run %s, attempt %s, version %s\n' \
  "$RUN_ID" "$RUN_ATTEMPT" "$VERSION_ID"
