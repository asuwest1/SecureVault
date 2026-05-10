# SecureVault — Installation Guide (Non-Docker)

This guide installs SecureVault directly on a Linux host without Docker.
Postgres, the .NET runtime, and Nginx are installed as native packages, and
the API runs under systemd as a dedicated service user.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Create the Service User & Directories](#2-create-the-service-user--directories)
3. [Install PostgreSQL & Initialize the Database](#3-install-postgresql--initialize-the-database)
4. [Generate Secrets](#4-generate-secrets)
5. [Build & Install the Application](#5-build--install-the-application)
6. [Configure Environment](#6-configure-environment)
7. [Install the systemd Service](#7-install-the-systemd-service)
8. [Run Database Migrations](#8-run-database-migrations)
9. [Configure Nginx (TLS Termination)](#9-configure-nginx-tls-termination)
10. [First-Run Initialization](#10-first-run-initialization)
11. [Verify the Deployment](#11-verify-the-deployment)
12. [Configure Backups](#12-configure-backups)
13. [LDAP / Active Directory (Optional)](#13-ldap--active-directory-optional)
14. [Local Development Setup](#14-local-development-setup)
15. [Upgrading](#15-upgrading)
16. [Uninstalling](#16-uninstalling)

---

## 1. Prerequisites

### Server Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU      | 1 vCPU  | 2+ vCPUs    |
| RAM      | 1 GB    | 2 GB        |
| Disk     | 10 GB   | 50 GB       |
| OS       | Linux (kernel 4.0+) | Ubuntu 22.04 LTS / Debian 12 / RHEL 9 |

### Software Dependencies

| Tool | Minimum Version | Notes |
|------|----------------|-------|
| .NET ASP.NET Runtime | 8.0.x | Required at runtime |
| .NET SDK | 8.0.404 (pinned in `global.json`) | Required at build time only |
| Node.js | 20.x LTS | Required at build time only |
| PostgreSQL | 16.x | psql 15+ for `\getenv` in `db-setup.sql` |
| Nginx | 1.26+ | TLS termination & reverse proxy |
| OpenSSL | 3.x | Certificate and key generation |
| systemd | 245+ | Service management & sandboxing |

Install on Ubuntu/Debian:

```bash
sudo apt update
sudo apt install -y postgresql-16 nginx openssl curl ca-certificates
# .NET 8 (Microsoft package repo)
sudo apt install -y dotnet-sdk-8.0 aspnetcore-runtime-8.0
# Node.js 20
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo bash -
sudo apt install -y nodejs
```

---

## 2. Create the Service User & Directories

```bash
sudo useradd --system --home-dir /opt/securevault --shell /usr/sbin/nologin securevault

sudo install -d -o securevault -g securevault -m 0750 /opt/securevault
sudo install -d -o securevault -g securevault -m 0750 /var/log/securevault
sudo install -d -o securevault -g securevault -m 0750 /var/lib/securevault
sudo install -d -o root        -g securevault -m 0750 /etc/securevault
sudo install -d -o root        -g securevault -m 0750 /etc/securevault/secrets
sudo install -d -o root        -g root        -m 0755 /etc/nginx/certs
```

`/var/lib/securevault` holds the ASP.NET Data Protection key ring;
`/var/log/securevault` is where the systemd unit's `ReadWritePaths` allows
log writes.

---

## 3. Install PostgreSQL & Initialize the Database

### 3.1 Bind PostgreSQL to localhost only

Edit `/etc/postgresql/16/main/postgresql.conf`:

```
listen_addresses = '127.0.0.1'
```

Add a `pg_hba.conf` rule for the application role
(`/etc/postgresql/16/main/pg_hba.conf`):

```
# TYPE  DATABASE     USER              ADDRESS         METHOD
host    securevault  securevault_app   127.0.0.1/32    scram-sha-256
```

Then `sudo systemctl restart postgresql`.

### 3.2 Create the database and apply `db-setup.sql`

```bash
sudo -u postgres createdb securevault

# Apply role + grants. DB_PASSWORD is read by `\getenv` inside the script
# and used as the password for the securevault_app role.
DB_PASSWORD='<strong-app-password>' \
  sudo -u postgres psql -d securevault -v ON_ERROR_STOP=1 \
  -f scripts/db-setup.sql
```

The script also contains a `REVOKE DELETE, UPDATE ON audit_log` block — it is
a no-op until migrations have created the table. **Re-run the same script
after step 8** to enforce the append-only invariant.

---

## 4. Generate Secrets

```bash
# 32 raw bytes for the Master Encryption Key (AES-256-GCM)
sudo openssl rand -out /etc/securevault/secrets/securevault-mek 32

# 2048-bit RSA private key for JWT (RS256) signing
sudo openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out /etc/securevault/secrets/jwt-signing.pem

# Strong random passphrase for backup encryption
sudo sh -c 'openssl rand -base64 48 > /etc/securevault/secrets/backup-passphrase'

# Lock down ownership and permissions — readable only by the service user
sudo chown securevault:securevault /etc/securevault/secrets/*
sudo chmod 0400 /etc/securevault/secrets/*
```

> **Important:** Back up `securevault-mek` immediately. Losing it makes all
> encrypted secrets unrecoverable.

---

## 5. Build & Install the Application

Build on the host (or on a build machine and copy the artifacts over):

```bash
# Frontend
cd frontend
npm ci
npm run build       # produces frontend/dist/
cd ..

# Backend
dotnet restore --use-lock-file
dotnet publish src/SecureVault.Api/SecureVault.Api.csproj \
    -c Release \
    -o ./publish \
    --no-restore

# Copy the SPA into wwwroot
mkdir -p ./publish/wwwroot
cp -r frontend/dist/* ./publish/wwwroot/

# Install to /opt/securevault
sudo rsync -a --delete ./publish/ /opt/securevault/
sudo chown -R securevault:securevault /opt/securevault
sudo chmod -R a-w /opt/securevault          # read-only at runtime
```

---

## 6. Configure Environment

```bash
sudo cp scripts/securevault.env.example /etc/securevault/securevault.env
sudo chown root:securevault /etc/securevault/securevault.env
sudo chmod 0640 /etc/securevault/securevault.env
sudo $EDITOR /etc/securevault/securevault.env
```

Required values:

- `ConnectionStrings__Default` — set the password to the
  `securevault_app` password from step 3.
- `AllowedHosts` — your FQDN, e.g. `vault.example.com`.
- `Auth__Mode` — `local` (default) or `ldap`.
- `Syslog__Host` — optional SIEM forwarder.

`SECUREVAULT_KEY_FILE` and `Auth__JwtSigningKeyPath` already point to
`/etc/securevault/secrets/...` — do not change unless you moved the files.

---

## 7. Install the systemd Service

```bash
sudo cp scripts/securevault.service /etc/systemd/system/securevault.service
sudo systemctl daemon-reload
sudo systemctl enable --now securevault.service
sudo systemctl status securevault.service
```

Logs:

```bash
sudo journalctl -u securevault.service -f
```

---

## 8. Run Database Migrations

EF Core migrations are applied from the source tree using the
`dotnet-ef` tool (the published binaries do not include it):

```bash
dotnet tool install --global dotnet-ef --version 8.*

# Run as a user that can read the source tree; the connection string is
# the same one the service uses.
ConnectionStrings__Default="Host=127.0.0.1;Port=5432;Database=securevault;Username=securevault_app;Password=<app-password>" \
  dotnet ef database update \
  --project src/SecureVault.Infrastructure \
  --startup-project src/SecureVault.Api
```

Then re-apply `db-setup.sql` so the `REVOKE DELETE, UPDATE ON audit_log`
block runs against the now-existing table:

```bash
DB_PASSWORD='<app-password>' \
  sudo -u postgres psql -d securevault -v ON_ERROR_STOP=1 \
  -f scripts/db-setup.sql
```

Confirm by checking the NOTICE: it should say `REVOKE DELETE, UPDATE on
audit_log from securevault_app: done`.

Restart the service so it picks up the schema:

```bash
sudo systemctl restart securevault.service
```

---

## 9. Configure Nginx (TLS Termination)

Place certificates:

| File | Description |
|------|-------------|
| `/etc/nginx/certs/server.crt` | Certificate (PEM, full chain) |
| `/etc/nginx/certs/server.key` | Private key (PEM, mode 0600) |

For development, generate a self-signed cert:

```bash
sudo openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
  -keyout /etc/nginx/certs/server.key \
  -out    /etc/nginx/certs/server.crt \
  -subj   "/CN=vault.example.com"
sudo chmod 600 /etc/nginx/certs/server.key
```

Install the bundled Nginx config:

```bash
sudo cp nginx/nginx.conf /etc/nginx/nginx.conf
sudo nginx -t
sudo systemctl reload nginx
```

The shipped `nginx.conf` proxies to `http://127.0.0.1:8080` (where the
systemd service binds Kestrel) and uses `127.0.0.53` (systemd-resolved)
for OCSP lookups. On distros that use a different stub resolver, edit
the `resolver` directive in `nginx/nginx.conf`. On Debian/Ubuntu the
Nginx user is `www-data`; change the `user nginx;` directive at the top
of the file to match your distro before reloading.

Open the firewall:

```bash
sudo ufw allow 443/tcp
sudo ufw allow 80/tcp     # for HTTP→HTTPS redirect only
```

---

## 10. First-Run Initialization

The setup endpoint is only available before initialization. It returns
`410 Gone` once completed.

```bash
curl -k -X POST https://vault.example.com/api/v1/setup/initialize \
  -H "Content-Type: application/json" \
  -d '{
    "adminUsername": "admin",
    "adminEmail": "admin@example.com",
    "adminPassword": "ChangeMe!Securely123"
  }'
```

Or browse to `https://vault.example.com` and complete the **First Run
Setup** form.

> **Important:** Change the super-admin password immediately after first
> login. Use at least 16 characters.

---

## 11. Verify the Deployment

```bash
# Service health
curl -k https://vault.example.com/health
# Expected: {"status":"Healthy"}

# TLS
openssl s_client -connect vault.example.com:443 -brief

# Login smoke test
curl -k -c cookies.txt -X POST https://vault.example.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"ChangeMe!Securely123"}'
rm cookies.txt
```

---

## 12. Configure Backups

`scripts/backup.sh` produces an AES-256-CTR + HMAC-SHA256 (encrypt-then-MAC)
archive of the database and MEK file using the passphrase generated in
step 4.

### Run a manual backup

```bash
sudo -u securevault \
  BACKUP_DIR=/var/backups/securevault \
  DB_HOST=127.0.0.1 DB_USER=postgres \
  PGPASSWORD='<postgres-superuser-password>' \
  bash scripts/backup.sh
```

(Or place a `~securevault/.pgpass` entry instead of `PGPASSWORD`.)

### Schedule with cron

```bash
sudo crontab -u securevault -e
# 0 2 * * * /opt/securevault/scripts/backup.sh >> /var/log/securevault/backup.log 2>&1
```

### Restore

```bash
sudo systemctl stop securevault.service
sudo -u postgres bash scripts/restore.sh /var/backups/securevault/securevault-backup-YYYYMMDDTHHMMSSZ.tar.gz.enc
sudo systemctl start securevault.service
```

> **Warning:** `restore.sh` drops and recreates the database. It pauses
> for a 10-second abort window before doing so.

---

## 13. LDAP / Active Directory (Optional)

In `/etc/securevault/securevault.env` set:

```
Auth__Mode=ldap
Auth__Ldap__Host=ldap.example.com
Auth__Ldap__Port=636
Auth__Ldap__UseSsl=true
Auth__Ldap__BaseDn=dc=example,dc=com
Auth__Ldap__BindDn=cn=securevault-svc,ou=service-accounts,dc=example,dc=com
Auth__Ldap__BindPassword=<service-account-password>
Auth__Ldap__UserSearchFilter=(sAMAccountName={0})
```

Then `sudo systemctl restart securevault.service`.

---

## 14. Local Development Setup

```bash
# Backend
dotnet --version            # must be 8.0.404
dotnet restore --use-lock-file
dotnet build --configuration Release
dotnet run --project src/SecureVault.Api/SecureVault.Api.csproj
# API listens on http://localhost:5000

# Frontend
cd frontend
npm ci
npm run dev                 # Vite dev server at http://localhost:5173

# Tests (unit only — no Docker required)
dotnet test src/SecureVault.Tests/SecureVault.Tests.csproj \
  --filter "Category!=Integration&Category!=Security" \
  --collect:"XPlat Code Coverage"

# Frontend type check + lint
cd frontend && npm run type-check && npm run lint
```

> The integration and security test suites use **Testcontainers** and
> still require a Docker daemon to run. They cannot run on a Docker-less
> host without modification.

---

## 15. Upgrading

```bash
git pull origin main

# Rebuild
cd frontend && npm ci && npm run build && cd ..
dotnet publish src/SecureVault.Api/SecureVault.Api.csproj -c Release -o ./publish --no-restore
mkdir -p ./publish/wwwroot && cp -r frontend/dist/* ./publish/wwwroot/

# Stop, install, migrate, restart
sudo systemctl stop securevault.service
sudo rsync -a --delete ./publish/ /opt/securevault/
sudo chown -R securevault:securevault /opt/securevault
sudo chmod -R a-w /opt/securevault

ConnectionStrings__Default="..." dotnet ef database update \
  --project src/SecureVault.Infrastructure \
  --startup-project src/SecureVault.Api

sudo systemctl start securevault.service
```

---

## 16. Uninstalling

```bash
sudo systemctl disable --now securevault.service
sudo rm /etc/systemd/system/securevault.service
sudo systemctl daemon-reload

sudo -u postgres dropdb securevault
sudo -u postgres psql -c "DROP ROLE IF EXISTS securevault_app;"

sudo rm -rf /opt/securevault /var/log/securevault /var/lib/securevault
# IRREVERSIBLE — make sure backups exist before removing secrets
sudo rm -rf /etc/securevault

sudo userdel securevault
```

> **Warning:** Removing `/etc/securevault/secrets/securevault-mek`
> without a backup makes all encrypted secrets permanently unrecoverable.
