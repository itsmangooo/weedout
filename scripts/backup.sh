#!/usr/bin/env sh
#
# Take a compressed, timestamped dump of the Weedout database.
#
#   scripts/backup.sh
#
# Runnable by hand — do that before a risky migration — and invoked on a
# schedule by the worker (`app/services/backup_service.py`). Everything comes
# from the environment so both paths behave identically.
#
#   DATABASE_URL                  required; the app's DSN, driver suffix and all
#   BACKUP_DIR                    where dumps land (default /var/backups/weedout)
#   BACKUP_KEEP                   how many to keep locally (default 7)
#   BACKUP_S3_BUCKET              set to also push off-box; see scripts/s3_upload.py
#
# Exits non-zero on any failure, having written nothing partial: the dump is
# built under a `.partial` name and only renamed once it has been verified.
# A truncated dump that looks like a real one is the worst possible outcome
# here, because it is indistinguishable from a good backup until the day you
# need it.

set -eu

BACKUP_DIR="${BACKUP_DIR:-/var/backups/weedout}"
BACKUP_KEEP="${BACKUP_KEEP:-7}"

if [ -z "${DATABASE_URL:-}" ]; then
    echo "backup: DATABASE_URL is not set" >&2
    exit 2
fi

# SQLAlchemy DSNs carry a driver suffix (`postgresql+psycopg://`) that libpq
# does not understand. Strip it so the same value works for both.
LIBPQ_URL=$(printf '%s' "$DATABASE_URL" | sed 's|^postgresql+[a-z0-9]*://|postgresql://|')

mkdir -p "$BACKUP_DIR"

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
NAME="weedout-${STAMP}.sql.gz"
FINAL="${BACKUP_DIR}/${NAME}"
PARTIAL="${FINAL}.partial"

cleanup_partial() {
    rm -f "$PARTIAL"
}
trap cleanup_partial EXIT INT TERM

echo "backup: dumping to ${NAME}"

# --clean --if-exists so the dump restores into a database that already has
# objects; --no-owner --no-privileges so it restores under whatever role the
# target happens to use rather than requiring the original one to exist.
#
# `set -e` does not catch a failure on the left of a pipe in POSIX sh, so the
# dump is written to an intermediate file rather than piped straight into gzip.
# Silently gzipping a half-written dump is exactly the failure this script is
# supposed to make impossible.
RAW="${BACKUP_DIR}/weedout-${STAMP}.sql.raw"
rm -f "$RAW"

if ! pg_dump --clean --if-exists --no-owner --no-privileges --file="$RAW" "$LIBPQ_URL"; then
    echo "backup: pg_dump failed" >&2
    rm -f "$RAW"
    exit 1
fi

# A complete plain-format dump always contains this marker near the end. Its
# absence means the dump was truncated — disk full, OOM, connection dropped —
# and the file must not be kept, because it would look like a backup forever.
#
# 4 KB rather than a tight window around the marker: PostgreSQL writes an
# epilogue after it (17.x emits a `\unrestrict <token>` line), and that
# epilogue has grown between minor versions. Too small a window turns a routine
# upgrade into "every backup is suddenly reported as truncated". Truncation is
# still caught either way — a dump cut off mid-stream has no marker at all.
if ! tail -c 4096 "$RAW" | grep -q "PostgreSQL database dump complete"; then
    echo "backup: dump is truncated (completion marker missing)" >&2
    rm -f "$RAW"
    exit 1
fi

gzip -c "$RAW" > "$PARTIAL"
rm -f "$RAW"

# Verify the compressed file before it is allowed to take its real name.
if ! gzip -t "$PARTIAL"; then
    echo "backup: gzip integrity check failed" >&2
    exit 1
fi

mv "$PARTIAL" "$FINAL"
trap - EXIT INT TERM

SIZE=$(wc -c < "$FINAL" | tr -d ' ')
echo "backup: wrote ${FINAL} (${SIZE} bytes)"

# ---------------------------------------------------------------------------
# Off-box copy
# ---------------------------------------------------------------------------
# A dump on the same disk as the database survives a bad migration and nothing
# else. Failure to upload is reported but does not discard the local dump — a
# local-only backup still beats none.
if [ -n "${BACKUP_S3_BUCKET:-}" ]; then
    SCRIPT_DIR=$(dirname "$0")
    if python3 "${SCRIPT_DIR}/s3_upload.py" "$FINAL"; then
        echo "backup: uploaded ${NAME} off-box"
    else
        echo "backup: OFF-BOX UPLOAD FAILED; the local dump was kept" >&2
        UPLOAD_FAILED=1
    fi
else
    echo "backup: BACKUP_S3_BUCKET unset — this dump is local-only" >&2
fi

# ---------------------------------------------------------------------------
# Retention
# ---------------------------------------------------------------------------
# Newest kept, oldest removed. The timestamp format sorts lexicographically, so
# a plain reverse sort is a chronological one. Only this script's own output is
# ever considered, so nothing else in the directory can be deleted by accident.
if [ "$BACKUP_KEEP" -gt 0 ]; then
    ls -1 "$BACKUP_DIR" 2>/dev/null \
        | grep '^weedout-.*\.sql\.gz$' \
        | sort -r \
        | tail -n "+$((BACKUP_KEEP + 1))" \
        | while read -r old; do
            echo "backup: pruning ${old}"
            rm -f "${BACKUP_DIR}/${old}"
        done
fi

# Also clear anything a previous crashed run left behind.
rm -f "${BACKUP_DIR}"/*.partial "${BACKUP_DIR}"/*.sql.raw 2>/dev/null || true

exit "${UPLOAD_FAILED:-0}"
