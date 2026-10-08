#!/usr/bin/env bash
# Capture evidence, create its manifest, and bundle it locally.
# Signing and vault upload belong to the workflow's subsequent steps.
#
# Run from the repository root:
#   bash scripts/capture-evidence.sh --workspace terraform --run-id local-test
#
# Optional:
#   --run-attempt <number> --commit <sha> --evidence-dir <path>
set -euo pipefail

WORKSPACE=""
RUN_ID=""
RUN_ATTEMPT="1"
COMMIT=""
EVIDENCE_DIR="evidence/capstone"

usage() {
  printf 'Usage: %s --workspace <path> --run-id <id> [--run-attempt <number>] [--commit <sha>] [--evidence-dir <path>]\n' \
    "$0" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace|--run-id|--run-attempt|--commit|--evidence-dir)
      if [[ $# -lt 2 || -z "$2" || "$2" == --* ]]; then
        printf 'ERROR: Missing or invalid value for %s\n' "$1" >&2
        usage
        exit 2
      fi

      case "$1" in
        --workspace)    WORKSPACE="$2" ;;
        --run-id)       RUN_ID="$2" ;;
        --run-attempt)  RUN_ATTEMPT="$2" ;;
        --commit)       COMMIT="$2" ;;
        --evidence-dir) EVIDENCE_DIR="$2" ;;
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

if [[ -z "$WORKSPACE" || -z "$RUN_ID" ]]; then
  usage
  exit 2
fi

# These values become part of the archive filename.
if [[ ! "$RUN_ID" =~ ^[A-Za-z0-9_-]+$ ||
      ! "$RUN_ATTEMPT" =~ ^[0-9]+$ ]]; then
  printf 'ERROR: Invalid run ID or run attempt.\n' >&2
  exit 2
fi

for TOOL in terraform git jq tar; do
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

if [[ ! -d "$WORKSPACE" ||
      ! -r "$WORKSPACE/plan.json" ||
      ! -s "$WORKSPACE/plan.json" ]]; then
  printf 'ERROR: Workspace must contain a readable, nonempty plan.json.\n' >&2
  exit 2
fi

jq -e 'type == "object" and has("planned_values")' \
  "$WORKSPACE/plan.json" >/dev/null

if [[ -z "$COMMIT" ]]; then
  COMMIT=$(git -C "$WORKSPACE" rev-parse HEAD)
fi

if [[ ! "$COMMIT" =~ ^[0-9a-fA-F]{40}$ ]]; then
  printf 'ERROR: Commit must be a full Git SHA.\n' >&2
  exit 2
fi

mkdir -p "$EVIDENCE_DIR"

cp "$WORKSPACE/plan.json" "$EVIDENCE_DIR/plan.json"

if [[ -f "$WORKSPACE/plan.txt" ]]; then
  cp "$WORKSPACE/plan.txt" "$EVIDENCE_DIR/plan.txt"
fi

git -C "$WORKSPACE" log -1 --pretty=full "$COMMIT" \
  > "$EVIDENCE_DIR/commit.txt"
terraform version > "$EVIDENCE_DIR/version.txt"

CAPTURED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)

jq -n \
  --arg run_id "$RUN_ID" \
  --arg run_attempt "$RUN_ATTEMPT" \
  --arg commit "$COMMIT" \
  --arg captured_at "$CAPTURED_AT" \
  '{
    run_id: $run_id,
    run_attempt: $run_attempt,
    commit: $commit,
    captured_at_utc: $captured_at
  }' > "$EVIDENCE_DIR/capture.json"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# Preserve the lab manifest fields.
# Existing scanner reports, logs, and run.json are included when present.
for FILE in "$EVIDENCE_DIR"/*; do
  [[ -f "$FILE" ]] || continue

  BASENAME=$(basename "$FILE")
  [[ "$BASENAME" == "manifest.json" ]] && continue

  HASH=$("${SHASUM[@]}" "$FILE" | awk '{print $1}')
  SIZE=$(wc -c < "$FILE" | tr -d ' ')

  jq -n \
    --arg filename "$BASENAME" \
    --arg sha256 "$HASH" \
    --argjson size "$SIZE" \
    --arg captured_at "$CAPTURED_AT" \
    '{
      filename: $filename,
      sha256: $sha256,
      size: $size,
      captured_at_utc: $captured_at
    }' >> "$WORK/manifest-entries.json"
done

jq -s '.' "$WORK/manifest-entries.json" \
  > "$EVIDENCE_DIR/manifest.json"

BUNDLE="evidence-${RUN_ID}-${RUN_ATTEMPT}-${COMMIT}.tar.gz"
tar -czf "$BUNDLE" -C "$EVIDENCE_DIR" .

"${SHASUM[@]}" "$BUNDLE" | awk '{print $1}' \
  > "${BUNDLE}.sha256"

printf 'Captured evidence: %s\n' "$BUNDLE" >&2

# stdout contains only the archive path so the workflow can capture it.
printf '%s\n' "$BUNDLE"
