# SecureVault — Installation Guide

This guide covers prerequisites, deployment, and first-run initialization for SecureVault.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Prepare the Environment](#2-prepare-the-environment)
3. [TLS Certificates](#3-tls-certificates)
4. [Configure Environment Variables](#4-configure-environment-variables)
5. [Generate Secrets](#5-generate-secrets)
6. [Deploy with Docker Compose](#6-deploy-with-docker-compose)
7. [Run Database Migrations](#7-run-database-migrations)
8. [First-Run Initialization](#8-first-run-initialization)
9. [Verify the Deployment](#9-verify-the-deployment)
10. [Configure Backups](#10-configure-backups)
11. [LDAP / Active Directory (Optional)](#11-ldap--active-directory-optional)
12. [Local Development Setup](#12-local-development-setup)
13. [Upgrading](#13-upgrading)
14. [Uninstalling](#14-uninstalling)

---

## 1. Prerequisites

### Server Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU      | 1 vCPU  | 2+ vCPUs    |
| RAM      | 1 GB    | 2 GB        |
| Disk     | 10 GB   | 50 GB       |
| OS       | Linux (kernel 4.0+) | Ubuntu 22.04 LTS / Debian 12 |

### Software Dependencies

| Tool | Minimum Version | Notes |
|------|----------------|-------|
| Docker Engine | 24.x | [Install Docker](https://docs.docker.com/engine/install/) |
| Docker Compose | 2.x (v2 plugin) | Included with Docker Desktop; `docker compose` (not `docker-compose`) |
| OpenSSL | 3.x | For certificate and key generation |

### For Local Development (without Docker)

| Tool | Version | Notes |
|------|---------|-------|
| .NET SDK | 8.0.404 (pinned) | Must match `global.json` exactly |
| Node.js | 20.x LTS | Frontend toolchain |
| PostgreSQL | 16.x | Or use Docker for the database only |

---

## 2. Prepare the Environment

Clone the repository and move into the project directory:

```bash
git clone https://github.com/your-org/securevault.git
cd securevault
```

Create the directories Docker Compose will use for persistent data and secrets:

```bash
mkdir -p data/postgres data/mek nginx/certs
```

---

## 3. TLS Certificates

SecureVault requires HTTPS. Place your certificate files in `nginx/certs/`:

| File | Description |
|------|-------------|
| `nginx/certs/server.crt` | Certificate (PEM, full chain) |
| `nginx/certs/server.key` | Private key (PEM) |

### Option A — Trusted CA / Let's Encrypt (production)

Use your organization's CA or [Certbot](https://certbot.eff.org/) to issue a certificate, then copy the files:

```bash
cp /etc/letsencrypt/live/vault.example.com/fullchain.pem nginx/certs/server.crt
cp /etc/letsencrypt/live/vault.example.com/privkey.pem   nginx/certs/server.key
```

### Option B — Self-Signed (development / internal use)

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
  -keyout nginx/certs/server.key \
  -out    nginx/certs/server.crt \
  -subj   "/CN=vault.example.com"
```

Restrict key file permissions:

```bash
chmod 600 nginx/certs/server.key
```

---

## 4. Configure Environment Variables

Copy the example environment file and edit it for your deployment:

```bash
cp .env.example .env
```

Open `.env` and set the following values:

### Database

```env
# PostgreSQL connection string used by the application
POSTGRES_DB=securevault
POSTGRES_USER=securevault_app
POSTGRES_PASSWORD=<strong-random-password>

# Full connection string for EF Core
DATABASE_URL=Host=db;Database=securevault;Username=securevault_app;Password=<strong-random-password>
```

### Paths (inside the container)

```env
# Path where the Master Encryption Key file is mounted (do not change unless customizing docker-compose.yml)
MEK_KEY_FILE=/run/secrets/mek_key
JWT_SIGNING_KEY_FILE=/run/secrets/jwt_key
```

### Application Settings

```env
# FQDN of the server (used in TLS cert and CORS)
APP_URL=https://vault.example.com

# Log level: Debug | Information | Warning | Error
ASPNETCORE_ENVIRONMENT=Production
```

### Syslog Forwarding (optional)

```env
SYSLOG_HOST=siem.example.com
SYSLOG_PORT=514
```

---

## 5. Generate Secrets

SecureVault uses Docker Secrets for the Master Encryption Key (MEK) and JWT signing key. These are mounted read-only inside the container and never written to the database.

```bash
# Generate a 32-byte (256-bit) MEK
openssl rand -base64 32 > data/mek/mek.key
chmod 600 data/mek/mek.key

# Generate a 64-byte JWT signing key
openssl rand -base64 64 > data/mek/jwt.key
chmod 600 data/mek/jwt.key
```

> **Important:** Back up `data/mek/mek.key` immediately after generation. Losing this file makes all encrypted secrets unrecoverable.

---

## 6. Deploy with Docker Compose

Build and start all services in the background:

```bash
docker compose up -d --build
```

Docker Compose starts four services:

| Service    | Description |
|------------|-------------|
| `db`       | PostgreSQL 16 database |
| `migrator` | Runs EF Core migrations once, then exits |
| `app`      | ASP.NET Core 8 API (port 8080 inside the network) |
| `nginx`    | TLS termination and reverse proxy (ports 80 and 443) |

Check that all services are running:

```bash
docker compose ps
```

Expected output (all services except `migrator` should show `running`):

```
NAME                   STATUS
securevault-db-1       running
securevault-app-1      running
securevault-nginx-1    running
securevault-migrator-1 exited (0)   ← expected; migration is a one-time job
```

---

## 7. Run Database Migrations

The `migrator` service runs automatically on startup. To run migrations manually (e.g., after an upgrade):

```bash
docker compose run --rm migrator dotnet ef database update \
  --project src/SecureVault.Infrastructure \
  --startup-project src/SecureVault.Api
```

To also apply the security constraints (audit log permissions):

```bash
docker compose exec db psql -U postgres -d securevault -f /docker-entrypoint-initdb.d/db-setup.sql
```

---

## 8. First-Run Initialization

Before the vault can be used it must be initialized. This creates the super-admin account and generates the MEK on disk.

The setup endpoint is only available before initialization. It returns `410 Gone` once completed.

### Using curl

```bash
curl -k -X POST https://vault.example.com/api/v1/setup/initialize \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "ChangeMe!Securely123",
    "email": "admin@example.com"
  }'
```

A successful response returns HTTP `200` with an initialization confirmation message.

### Using the Web UI

Navigate to `https://vault.example.com` in a browser. If the vault has not been initialized, you will be redirected to the **First Run Setup** page. Fill in the super-admin credentials and submit.

> **Important:** Change the super-admin password immediately after first login. Use a strong password of at least 16 characters.

---

## 9. Verify the Deployment

### Health Check

```bash
curl -k https://vault.example.com/health
# Expected: {"status":"Healthy"}
```

### TLS Configuration

```bash
openssl s_client -connect vault.example.com:443 -brief
```

Verify the output shows TLSv1.3 (or TLSv1.2) and your certificate's CN/SAN.

### Login Test

```bash
curl -k -c cookies.txt -X POST https://vault.example.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"ChangeMe!Securely123"}'
```

A successful response includes a JSON body with `requiresMfa: false` (or a MFA challenge if TOTP was configured).

Remove the test cookie file afterward:

```bash
rm cookies.txt
```

---

## 10. Configure Backups

SecureVault includes `scripts/backup.sh` and `scripts/restore.sh` for encrypted, authenticated backups.

### How Backups Work

Each backup archive contains:
- A PostgreSQL database dump
- A copy of the MEK key file
- A `manifest.json` with SHA-256 checksums and metadata

The archive is encrypted with AES-256-CTR and authenticated with HMAC-SHA256 (Encrypt-then-MAC) using PBKDF2-derived keys (600,000 iterations).

### Configure and Run

```bash
# Set required variables
export BACKUP_DIR=/mnt/backup/securevault
export BACKUP_PASSPHRASE="<strong-passphrase>"
export RETENTION_DAYS=30    # How many days to keep old backups
export DB_NAME=securevault
export DB_USER=securevault_app
export MEK_KEY_FILE=/path/to/mek.key

# Run backup
bash scripts/backup.sh
```

### Schedule Automatic Backups

Add a cron job to run backups daily:

```bash
crontab -e
# Add this line (runs at 02:00 every day):
0 2 * * * /path/to/securevault/scripts/backup.sh >> /var/log/securevault-backup.log 2>&1
```

### Restore from Backup

```bash
export BACKUP_PASSPHRASE="<passphrase-used-during-backup>"
bash scripts/restore.sh /mnt/backup/securevault/backup-2026-03-01.enc
```

> **Warning:** The restore script drops and recreates the database. It will display a 10-second abort window before proceeding.

---

## 11. LDAP / Active Directory (Optional)

SecureVault supports LDAP/AD authentication in addition to local accounts. Configure via environment variables before starting the stack:

```env
AUTH_MODE=ldap

LDAP_HOST=ldap.example.com
LDAP_PORT=636
LDAP_USE_SSL=true
LDAP_BASE_DN=dc=example,dc=com
LDAP_BIND_DN=cn=securevault-svc,ou=service-accounts,dc=example,dc=com
LDAP_BIND_PASSWORD=<service-account-password>
LDAP_USER_SEARCH_FILTER=(sAMAccountName={0})
```

Set `AUTH_MODE=local` to disable LDAP and use only local accounts.

Restart the application after changing auth settings:

```bash
docker compose restart app
```

---

## 12. Local Development Setup

Use this path to run the application without Docker for backend or frontend development.

### Backend

```bash
# Ensure .NET 8.0.404 SDK is installed (must match global.json)
dotnet --version   # should output 8.0.404

dotnet restore --use-lock-file
dotnet build --configuration Release
dotnet run --project src/SecureVault.Api/SecureVault.Api.csproj
```

The API listens on `http://localhost:5000` by default.

### Frontend

```bash
cd frontend
npm ci               # install exact versions from package-lock.json
npm run dev          # Vite dev server at http://localhost:5173
```

### Running Tests

```bash
# Unit tests only (no Docker required)
dotnet test src/SecureVault.Tests/SecureVault.Tests.csproj \
  --filter "Category!=Integration&Category!=Security" \
  --collect:"XPlat Code Coverage"

# Integration + security tests (Docker required for Testcontainers)
dotnet test src/SecureVault.Tests/SecureVault.Tests.csproj \
  --filter "Category=Integration|Category=Security"

# Frontend type check and lint
cd frontend
npm run type-check
npm run lint
```

---

## 13. Upgrading

1. Pull the latest code:
   ```bash
   git pull origin main
   ```

2. Rebuild the Docker image:
   ```bash
   docker compose build app
   ```

3. Apply any new database migrations:
   ```bash
   docker compose run --rm migrator dotnet ef database update \
     --project src/SecureVault.Infrastructure \
     --startup-project src/SecureVault.Api
   ```

4. Restart the application:
   ```bash
   docker compose up -d app
   ```

5. Verify the health endpoint responds correctly.

---

## 14. Uninstalling

```bash
# Stop and remove containers, networks, and named volumes
docker compose down -v

# Remove built images
docker image rm securevault:latest

# Optionally remove persistent data (IRREVERSIBLE — deletes all secrets)
rm -rf data/
```

> **Warning:** Removing `data/mek/mek.key` before creating a backup makes all encrypted secrets permanently unrecoverable.
