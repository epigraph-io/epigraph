#!/usr/bin/env bash
# Operator-link probe (migrations 105 + 107): the stdio self-link's two
# REFUSALS, measured through the real binary.
#
#   ./probe-operator.sh <epigraph-mcp binary> <label> <a|b>
#
# `crates/epigraph-mcp/tests/operator_startup_gate_test.rs` already drives the
# real binary for the transport refusal, an HTTP listener refusing a linked
# signer, and the stdio self-link with its no-revival restart — all on the
# superuser `#[sqlx::test]` pool. What it cannot reach is the two arms below,
# because one needs the real least-privilege role and the other a database
# state the in-process fixture never builds:
#
#   OP-APP    `--operator-id` on the LEAST-PRIVILEGE DSN (E2E_APP_DSN). The
#             link function is EXECUTE-able by epigraph_maintenance only, so
#             startup must exit non-zero on a 42501 for that function (its
#             EXECUTE-grant text alone is the fallback for ANY error, so the
#             cause is matched too), and write
#             no operator_links row and no membership.
#   OP-RVK01  an operator whose OWN row in its personal group is only REVOKED.
#             105's epigraph_ensure_personal_group raises RVK01 inside the link
#             function, so startup must exit non-zero naming RVK01, write no
#             link, and leave the operator's row revoked (never revived).
#   OP-LIVE   CALIBRATION for OP-RVK01: the same shape with a LIVE operator
#             row on the same DSN must record the link, so the refusal above is
#             not a DSN that can never link.
#
# Each arm prints PASS or FAIL from the rows the database holds afterwards.

# --- credentials come from the environment, never from this file -------------
# Required:
#   E2E_SU_DSN   superuser DSN with DDL rights on the throwaway DB. OP-RVK01 and
#                OP-LIVE also run the server on it: the stdio self-link needs a
#                connection that may EXECUTE epigraph_link_operator, which is a
#                maintenance or superuser login by design.
#   E2E_APP_DSN  the least-privilege application DSN (rolbypassrls=false).
: "${E2E_SU_DSN:?set E2E_SU_DSN (superuser DSN for the throwaway e2e database)}"
: "${E2E_APP_DSN:?set E2E_APP_DSN (least-privilege app DSN; rolbypassrls MUST be false)}"
# shellcheck source=dsn-guard.sh
. "$(cd "$(dirname "$0")" && pwd)/dsn-guard.sh"
E2E_SU_PW="$(printf '%s' "$E2E_SU_DSN" | sed -E 's#.*://[^:]+:([^@]*)@.*#\1#')"
E2E_SU_USER="$(printf '%s' "$E2E_SU_DSN" | sed -E 's#.*://([^:]+):.*#\1#')"
E2E_DB="$(printf '%s' "$E2E_SU_DSN" | sed -E 's#.*/([^/?]+)$#\1#')"
# -----------------------------------------------------------------------------
set -uo pipefail
BIN="${1:?usage: probe-operator.sh <binary> <label> <a|b>}"
LABEL="${2:?label}"
CFG="${3:?a|b}"
E2E="$(cd "$(dirname "$0")" && pwd)"
# A derived, DECLARED identity per arm (stdio + --operator-id requires one).
# The prompt hash is a fixed public test value, not a secret.
PHASH="$(printf 'ab%.0s' $(seq 1 32))"

q() { PGPASSWORD="$E2E_SU_PW" psql -h "$E2E_SU_HOST" -p "$E2E_SU_PORT" -U "$E2E_SU_USER" -d "$E2E_DB" -tA -c "$1"; }

echo "### binary: $BIN"
LOCKFIFO="$E2E/.oplock.$LABEL"
rm -f "$LOCKFIFO"; mkfifo "$LOCKFIFO"
PGPASSWORD="$E2E_SU_PW" psql -h "$E2E_SU_HOST" -p "$E2E_SU_PORT" -U "$E2E_SU_USER" -d "$E2E_DB" -qtA \
  -c "SELECT pg_advisory_lock(918273645);" -f "$LOCKFIFO" >/dev/null 2>&1 &
LOCKPID=$!
exec 9>"$LOCKFIFO"
release_lock() { exec 9>&-; wait $LOCKPID 2>/dev/null; rm -f "$LOCKFIFO"; }
trap release_lock EXIT
echo "### serialized on advisory lock 918273645"

"$E2E/set-config.sh" "$CFG" >/dev/null 2>&1
echo "### $(q "SELECT 'config: ' || CASE WHEN EXISTS(SELECT 1 FROM pg_policy WHERE polname='claims_privacy') THEN 'B (prod-faithful)' ELSE 'A (clean series)' END")"

# An operator agent with its personal group, minted through 105's definer.
new_operator() {
  local id
  id="$(q "SELECT gen_random_uuid()")"
  q "INSERT INTO agents (id, public_key, agent_type, display_name)
     VALUES ('$id', decode(md5('$id') || md5('$id' || 'x'), 'hex'), 'human', 'e2e-operator-$LABEL')" >/dev/null
  q "SELECT public.epigraph_ensure_personal_group('$id')" >/dev/null
  printf '%s' "$id"
}

# Run the stdio server until it logs its link outcome or exits; print its exit
# code (or "running" when it was still serving and had to be killed).
run_stdio() {
  local dsn="$1" model="$2" op="$3" err="$4" pid rc
  : > "$err"
  env -u EPIGRAPH_OPERATOR_ID -u EPIGRAPH_MCP_EXTENSIONS -u EPIGRAPH_SESSION_GUC_MODE \
      -u OPENAI_API_KEY RUST_LOG=info \
    "$BIN" --database-url "$dsn" --agent-model "$model" \
      --agent-system-prompt-hash "$PHASH" --operator-id "$op" \
      < <(sleep 90) > /dev/null 2> "$err" &
  pid=$!
  for _ in $(seq 1 120); do
    if ! kill -0 "$pid" 2>/dev/null; then
      wait "$pid"; rc=$?; printf '%s' "$rc"; return
    fi
    if grep -qE 'operator link recorded|operator link is ' "$err"; then
      kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; printf 'running'; return
    fi
    sleep 0.5
  done
  kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; printf 'timeout'
}

agent_of_model() {
  q "SELECT count(*) FROM operator_links l WHERE l.operator_id = '$1'"
}

verdict() { if [ "$1" = true ]; then echo "   PASS: $2"; else echo "   FAIL: $2"; fi; }

# ---------------------------------------------------------------------------
echo
echo "=== OP-APP: --operator-id on the least-privilege DSN must refuse and write nothing ==="
OP1="$(new_operator)"
G1="$(q "SELECT id FROM groups WHERE did_key = 'did:epigraph:personal:$OP1'")"
M1_BEFORE="$(q "SELECT count(*) FROM group_memberships WHERE group_id = '$G1'")"
RC="$(run_stdio "$E2E_APP_DSN" "e2e-op-app-$LABEL" "$OP1" "$E2E/op.app.$LABEL.err")"
LINKS="$(agent_of_model "$OP1")"
M1_AFTER="$(q "SELECT count(*) FROM group_memberships WHERE group_id = '$G1'")"
echo "   exit=$RC links=$LINKS memberships: $M1_BEFORE -> $M1_AFTER"
grep -E 'ERROR:' "$E2E/op.app.$LABEL.err" | head -2 | cut -c1-300 | sed 's/^/   /'
# The EXECUTE-grant hint is the refusal text's FALLBACK branch, printed for any
# error that is not RVK01/RVK02, so it alone would also pass a startup that
# failed for an unrelated reason. The cause itself must be the 42501 on the
# link function.
grep -oE 'permission denied for function epigraph_link_operator' "$E2E/op.app.$LABEL.err" \
  | head -1 | sed 's/^/   cause: /'
OK=false
if [ "$RC" != "0" ] && [ "$RC" != "running" ] && [ "$LINKS" = 0 ] && [ "$M1_BEFORE" = "$M1_AFTER" ] \
   && grep -q 'EXECUTE-able by epigraph_maintenance only' "$E2E/op.app.$LABEL.err" \
   && grep -q 'permission denied for function epigraph_link_operator' "$E2E/op.app.$LABEL.err"; then
  OK=true
fi
verdict "$OK" "refused at startup by 42501 on epigraph_link_operator, +0 links, +0 memberships"

# ---------------------------------------------------------------------------
echo
echo "=== OP-RVK01: an operator whose own personal-group row is only revoked ==="
OP2="$(new_operator)"
G2="$(q "SELECT id FROM groups WHERE did_key = 'did:epigraph:personal:$OP2'")"
q "UPDATE group_memberships SET revoked_at = now() WHERE group_id = '$G2' AND agent_id = '$OP2'" >/dev/null
M2_BEFORE="$(q "SELECT count(*) || '/' || count(*) FILTER (WHERE revoked_at IS NULL) FROM group_memberships WHERE group_id = '$G2'")"
RC="$(run_stdio "$E2E_SU_DSN" "e2e-op-rvk01-$LABEL" "$OP2" "$E2E/op.rvk01.$LABEL.err")"
LINKS="$(agent_of_model "$OP2")"
M2_AFTER="$(q "SELECT count(*) || '/' || count(*) FILTER (WHERE revoked_at IS NULL) FROM group_memberships WHERE group_id = '$G2'")"
echo "   exit=$RC links=$LINKS memberships(total/live): $M2_BEFORE -> $M2_AFTER"
grep -E 'ERROR:' "$E2E/op.rvk01.$LABEL.err" | head -2 | cut -c1-300 | sed 's/^/   /'
OK=false
if [ "$RC" != "0" ] && [ "$RC" != "running" ] && [ "$LINKS" = 0 ] && [ "$M2_BEFORE" = "$M2_AFTER" ] \
   && grep -q 'RVK01' "$E2E/op.rvk01.$LABEL.err"; then OK=true; fi
verdict "$OK" "refused at startup naming RVK01, +0 links, operator row still revoked, +0 memberships"

# ---------------------------------------------------------------------------
echo
echo "=== OP-LIVE (calibration): the same DSN and shape with a LIVE operator row links ==="
OP3="$(new_operator)"
RC="$(run_stdio "$E2E_SU_DSN" "e2e-op-live-$LABEL" "$OP3" "$E2E/op.live.$LABEL.err")"
LINKS="$(agent_of_model "$OP3")"
echo "   exit=$RC links=$LINKS"
OK=false
if [ "$RC" = "running" ] && [ "$LINKS" = 1 ] \
   && grep -q 'operator link recorded' "$E2E/op.live.$LABEL.err"; then OK=true; fi
verdict "$OK" "link recorded and the process kept serving"
