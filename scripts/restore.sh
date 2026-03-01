#!/usr/bin/env bash
# SecureVault Restore Script
# Restores database and MEK key from an encrypted backup.
#
# SECURITY NOTES:
# - Restores MEK key file FIRST — app cannot start without it
# - Provides a 10-second abort window before destructive operations
# - Application MUST be stopped before restore

set -euo pipefail

BACKUP_FILE="${1:-}"
PASSPHRASE_FILE="${BACKUP_PASSPHRASE_FILE:-/run/secrets/backup-passphrase}"
MEK_DEST="${SECUREVAULT_KEY_FILE:-/run/secrets/securevault-mek}"
DB_HOST="${DB_HOST:-db}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-securevault}"
DB_USER="${DB_USER:-postgres}"
WORK_DIR=$(mktemp -d)

cleanup() {
    rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

if [[ -z "${BACKUP_FILE}" ]]; then
    echo "Usage: $0 <backup-file.tar.gz.enc>" >&2
    exit 1
fi

if [[ ! -f "${BACKUP_FILE}" ]]; then
    echo "ERROR: Backup file not found: ${BACKUP_FILE}" >&2
    exit 1
fi

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║              SecureVault Restore - WARNING                   ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  This will OVERWRITE the current database and key file.      ║"
echo "║  The application MUST be stopped before proceeding.          ║"
echo "║                                                               ║"
echo "║  Backup: $(basename "${BACKUP_FILE}")"
echo "║                                                               ║"
echo "║  Aborting in 10 seconds... (Ctrl+C to cancel)                ║"
echo "╚══════════════════════════════════════════════════════════════╝"

for i in $(seq 10 -1 1); do
    printf "\r  Restoring in %d seconds...  " "${i}"
    sleep 1
done
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Step 1: Verify HMAC authenticity, then decrypt and extract
# HMAC verification MUST happen before decryption to prevent oracle attacks.
# ─────────────────────────────────────────────────────────────────────────────
HMAC_FILE="${BACKUP_FILE}.hmac"
if [[ ! -f "${HMAC_FILE}" ]]; then
    echo "ERROR: No HMAC file found at ${HMAC_FILE}. Refusing unauthenticated restore." >&2
    exit 1
fi

echo "[$(date -u +%H:%M:%S)] Verifying backup HMAC..."
EXPECTED_HMAC=$(tr -d '[:space:]' < "${HMAC_FILE}")
ACTUAL_HMAC=$(openssl dgst -sha256 -mac HMAC -macopt "key:file:${PASSPHRASE_FILE}" \
    -binary "${BACKUP_FILE}" | xxd -p -c 256)
if [[ "${EXPECTED_HMAC}" != "${ACTUAL_HMAC}" ]]; then
    echo "ERROR: Backup HMAC verification FAILED. Backup may have been tampered with." >&2
    exit 1
fi
echo "[$(date -u +%H:%M:%S)] HMAC verification passed."

echo "[$(date -u +%H:%M:%S)] Decrypting backup..."
openssl enc -d -aes-256-ctr \
    -pass "file:${PASSPHRASE_FILE}" \
    -pbkdf2 -iter 600000 \
    -in "${BACKUP_FILE}" | tar -xzf - -C "${WORK_DIR}"

echo "[$(date -u +%H:%M:%S)] Decryption complete."

# ─────────────────────────────────────────────────────────────────────────────
# Step 2: Verify manifest checksums
# ─────────────────────────────────────────────────────────────────────────────
if [[ -f "${WORK_DIR}/manifest.json" ]]; then
    EXPECTED_DB=$(python3 -c "import json; d=json.load(open('${WORK_DIR}/manifest.json')); print(d['db_checksum_sha256'])")
    ACTUAL_DB=$(sha256sum "${WORK_DIR}/database.dump" | cut -d' ' -f1)

    if [[ "${EXPECTED_DB}" != "${ACTUAL_DB}" ]]; then
        echo "ERROR: Database dump checksum mismatch!" >&2
        echo "  Expected: ${EXPECTED_DB}" >&2
        echo "  Actual:   ${ACTUAL_DB}" >&2
        exit 1
    fi
    echo "[$(date -u +%H:%M:%S)] Checksum verification passed."
fi

# ─────────────────────────────────────────────────────────────────────────────
# Step 3: Restore MEK key file FIRST
# CRITICAL: App cannot start without the key — restore key before DB
# ─────────────────────────────────────────────────────────────────────────────
echo "[$(date -u +%H:%M:%S)] Restoring MEK key file..."
cp "${WORK_DIR}/securevault-mek" "${MEK_DEST}"
chmod 400 "${MEK_DEST}"
echo "[$(date -u +%H:%M:%S)] MEK key file restored."

# ─────────────────────────────────────────────────────────────────────────────
# Step 4: Restore database
# ─────────────────────────────────────────────────────────────────────────────
echo "[$(date -u +%H:%M:%S)] Restoring database..."

# Drop and recreate the database
PGPASSWORD="${PGPASSWORD:-}" psql \
    -h "${DB_HOST}" -p "${DB_PORT}" \
    -U "${DB_USER}" postgres \
    -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='${DB_NAME}' AND pid <> pg_backend_pid();"

PGPASSWORD="${PGPASSWORD:-}" psql \
    -h "${DB_HOST}" -p "${DB_PORT}" \
    -U "${DB_USER}" postgres \
    -c "DROP DATABASE IF EXISTS ${DB_NAME}; CREATE DATABASE ${DB_NAME} OWNER securevault_app;"

PGPASSWORD="${PGPASSWORD:-}" pg_restore \
    -h "${DB_HOST}" -p "${DB_PORT}" \
    -U "${DB_USER}" \
    -d "${DB_NAME}" \
    --no-owner \
    "${WORK_DIR}/database.dump"

echo "[$(date -u +%H:%M:%S)] Database restored."

# ─────────────────────────────────────────────────────────────────────────────
# Step 5: Re-apply security constraints
# ─────────────────────────────────────────────────────────────────────────────
echo "[$(date -u +%H:%M:%S)] Reapplying security constraints..."
PGPASSWORD="${PGPASSWORD:-}" psql \
    -h "${DB_HOST}" -p "${DB_PORT}" \
    -U "${DB_USER}" \
    -d "${DB_NAME}" \
    -f "$(dirname "$0")/db-setup.sql"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                   Restore Complete!                          ║"
echo "║                                                               ║"
echo "║  1. Verify the MEK file is in place: ${MEK_DEST}"
echo "║  2. Start the application: docker compose up -d app           ║"
echo "╚══════════════════════════════════════════════════════════════╝"
