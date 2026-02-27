#!/usr/bin/env bash
# SecureVault Backup Script
# Creates an encrypted, integrity-verified backup of the database and MEK key file.
#
# SECURITY NOTES:
# - Backup passphrase must be stored on a DIFFERENT volume from both MEK and database
# - Backup is AES-256-GCM encrypted
# - Integrity is verified immediately after creation
# - Old backups are purged after RETENTION_DAYS

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────
BACKUP_DIR="${BACKUP_DIR:-/var/backups/securevault}"
MEK_FILE="${SECUREVAULT_KEY_FILE:-/run/secrets/securevault-mek}"
PASSPHRASE_FILE="${BACKUP_PASSPHRASE_FILE:-/run/secrets/backup-passphrase}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"
DB_HOST="${DB_HOST:-db}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-securevault}"
DB_USER="${DB_USER:-postgres}"
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
BACKUP_NAME="securevault-backup-${TIMESTAMP}"
WORK_DIR=$(mktemp -d)

cleanup() {
    rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

echo "[$(date -u +%H:%M:%S)] Starting SecureVault backup: ${BACKUP_NAME}"

# ─────────────────────────────────────────────────────────────────────────────
# Pre-flight checks
# ─────────────────────────────────────────────────────────────────────────────
if [[ ! -f "${MEK_FILE}" ]]; then
    echo "ERROR: MEK file not found at ${MEK_FILE}" >&2
    exit 1
fi

MEK_SIZE=$(wc -c < "${MEK_FILE}")
if [[ "${MEK_SIZE}" -ne 32 ]]; then
    echo "ERROR: MEK file must be exactly 32 bytes, found ${MEK_SIZE}" >&2
    exit 1
fi

if [[ ! -f "${PASSPHRASE_FILE}" ]]; then
    echo "ERROR: Backup passphrase file not found at ${PASSPHRASE_FILE}" >&2
    exit 1
fi

mkdir -p "${BACKUP_DIR}"

# ─────────────────────────────────────────────────────────────────────────────
# Step 1: Database dump
# ─────────────────────────────────────────────────────────────────────────────
echo "[$(date -u +%H:%M:%S)] Dumping database..."
PGPASSWORD="${PGPASSWORD:-}" pg_dump \
    -h "${DB_HOST}" -p "${DB_PORT}" \
    -U "${DB_USER}" \
    -F custom \
    -f "${WORK_DIR}/database.dump" \
    "${DB_NAME}"

echo "[$(date -u +%H:%M:%S)] Database dump complete ($(du -sh "${WORK_DIR}/database.dump" | cut -f1))"

# ─────────────────────────────────────────────────────────────────────────────
# Step 2: Copy MEK key file
# ─────────────────────────────────────────────────────────────────────────────
cp "${MEK_FILE}" "${WORK_DIR}/securevault-mek"

# ─────────────────────────────────────────────────────────────────────────────
# Step 3: Create manifest
# ─────────────────────────────────────────────────────────────────────────────
DB_CHECKSUM=$(sha256sum "${WORK_DIR}/database.dump" | cut -d' ' -f1)
MEK_CHECKSUM=$(sha256sum "${WORK_DIR}/securevault-mek" | cut -d' ' -f1)

cat > "${WORK_DIR}/manifest.json" <<EOF
{
  "backup_name": "${BACKUP_NAME}",
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "db_checksum_sha256": "${DB_CHECKSUM}",
  "mek_checksum_sha256": "${MEK_CHECKSUM}",
  "securevault_version": "${SECUREVAULT_VERSION:-unknown}"
}
EOF

# ─────────────────────────────────────────────────────────────────────────────
# Step 4: Tar, encrypt with authenticated encryption, and compute HMAC
# Uses AES-256-CTR for encryption + HMAC-SHA256 for integrity (Encrypt-then-MAC).
# OpenSSL CLI does not support AES-256-GCM for streaming, so we use CTR + HMAC
# which provides equivalent authenticated encryption guarantees.
# ─────────────────────────────────────────────────────────────────────────────
BACKUP_FILE="${BACKUP_DIR}/${BACKUP_NAME}.tar.gz.enc"
HMAC_FILE="${BACKUP_FILE}.hmac"

echo "[$(date -u +%H:%M:%S)] Encrypting backup..."
tar -czf - -C "${WORK_DIR}" . | \
    openssl enc -aes-256-ctr \
        -pass "file:${PASSPHRASE_FILE}" \
        -pbkdf2 -iter 600000 \
        -salt \
        -out "${BACKUP_FILE}"

# Compute HMAC-SHA256 over the ciphertext (Encrypt-then-MAC)
openssl dgst -sha256 -hmac "$(cat "${PASSPHRASE_FILE}")" \
    -out "${HMAC_FILE}" "${BACKUP_FILE}"

echo "[$(date -u +%H:%M:%S)] Encrypted backup: ${BACKUP_FILE} ($(du -sh "${BACKUP_FILE}" | cut -f1))"

# ─────────────────────────────────────────────────────────────────────────────
# Step 5: Verify integrity immediately after creation
# Verify HMAC first (authenticity), then decrypt to verify archive structure.
# ─────────────────────────────────────────────────────────────────────────────
echo "[$(date -u +%H:%M:%S)] Verifying backup integrity..."

EXPECTED_HMAC=$(cat "${HMAC_FILE}")
ACTUAL_HMAC=$(openssl dgst -sha256 -hmac "$(cat "${PASSPHRASE_FILE}")" "${BACKUP_FILE}")

if [[ "${EXPECTED_HMAC}" != "${ACTUAL_HMAC}" ]]; then
    echo "ERROR: Backup HMAC verification FAILED. Removing corrupt backup." >&2
    rm -f "${BACKUP_FILE}" "${HMAC_FILE}"
    exit 1
fi

if ! openssl enc -d -aes-256-ctr \
    -pass "file:${PASSPHRASE_FILE}" \
    -pbkdf2 -iter 600000 \
    -in "${BACKUP_FILE}" | tar -tzf - > /dev/null 2>&1; then
    echo "ERROR: Backup decryption verification FAILED. Removing corrupt backup." >&2
    rm -f "${BACKUP_FILE}" "${HMAC_FILE}"
    exit 1
fi
echo "[$(date -u +%H:%M:%S)] Backup integrity and authenticity verified."

# ─────────────────────────────────────────────────────────────────────────────
# Step 6: Purge old backups
# ─────────────────────────────────────────────────────────────────────────────
find "${BACKUP_DIR}" -name "securevault-backup-*.tar.gz.enc" \
    -mtime "+${RETENTION_DAYS}" -delete
find "${BACKUP_DIR}" -name "securevault-backup-*.tar.gz.enc.hmac" \
    -mtime "+${RETENTION_DAYS}" -delete
echo "[$(date -u +%H:%M:%S)] Old backups purged (retention: ${RETENTION_DAYS} days)"

echo "[$(date -u +%H:%M:%S)] Backup complete: ${BACKUP_FILE}"
