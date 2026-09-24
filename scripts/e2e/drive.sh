#!/usr/bin/env bash
# drive.sh <binary> <label> <a|b>
# Set the schema configuration, run the e2e harness, then print the embedding
# verdict the harness itself does not measure.
set -uo pipefail
E="$(cd "$(dirname "$0")" && pwd)"
BIN="${1:?binary}"; LABEL="${2:?label}"; CFG="${3:?a|b}"

# OPENAI_API_KEY comes from the ENVIRONMENT only. An earlier revision read it out
# of a host-specific `epiclaw.env`, which made the harness unrunnable anywhere else
# and pulled a live credential into a path this script does not own.
export OPENAI_API_KEY="${OPENAI_API_KEY:-}"
echo "### OPENAI_API_KEY present: ${#OPENAI_API_KEY} chars"

"$E/set-config.sh" "$CFG"
"$E/run-e2e.sh" "$BIN" "$LABEL"
echo "=== EMBEDDING VERDICT ==="
"$E/embed-verdict.sh"
echo "=== scoped_write / embed log lines ==="
grep -iE "tenancy.scoped_write|embed|42501|refus" "$E/mcp.$LABEL.log" | tail -15
