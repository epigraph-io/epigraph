#!/usr/bin/env bash
# Prepare a clean Postgres database for the engine-integration test suite.
#
# Usage:   ./scripts/prepare-engine-integration-db.sh [DB_NAME]
# Default: DB_NAME=epigraph_db_repo_test
#
# Connects as the local `epigraph` superuser (required: sqlx::test elsewhere
# locks pg_namespace; see auto-memory feedback_sqlx_test_uses_superuser.md).
#
# After running, export DATABASE_URL exactly as printed at the end and run:
#   cargo test -p engine-integration-tests -- --ignored
set -euo pipefail

DB_NAME="${1:-epigraph_db_repo_test}"
DB_USER="${DB_USER:-epigraph}"
DB_PASS="${DB_PASS:-epigraph}"
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
ADMIN_DB="${ADMIN_DB:-postgres}"

export PGPASSWORD="$DB_PASS"

# Locate migrations BEFORE touching the DB — running from the wrong dir
# must not drop the existing test DB before erroring out.
shopt -s nullglob
migration_files=(migrations/*.sql)
shopt -u nullglob
if [ ${#migration_files[@]} -eq 0 ]; then
    echo "ERROR: no migrations/*.sql found. Run from repo root." >&2
    exit 1
fi

echo "→ Dropping and recreating $DB_NAME (existing data will be lost)"
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$ADMIN_DB" \
    -c "DROP DATABASE IF EXISTS \"$DB_NAME\"" >/dev/null
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$ADMIN_DB" \
    -c "CREATE DATABASE \"$DB_NAME\" OWNER \"$DB_USER\"" >/dev/null

echo "→ Applying ${#migration_files[@]} migrations from ./migrations"
for f in "${migration_files[@]}"; do
    echo "    $f"
    psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
        -v ON_ERROR_STOP=1 -q -f "$f"
done

URL="postgres://${DB_USER}:${DB_PASS}@${DB_HOST}:${DB_PORT}/${DB_NAME}"
echo
echo "✓ Ready. Run:"
echo "    export DATABASE_URL=\"$URL\""
echo "    cargo test -p engine-integration-tests -- --ignored --test-threads=1"
