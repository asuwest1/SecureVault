# SecureVault — User Guide

SecureVault is a role-based secrets management application. It stores credentials, API keys, certificates, and other sensitive data in AES-256 encrypted vaults with granular per-secret access control and a tamper-evident audit log.

---

## Table of Contents

1. [Concepts](#1-concepts)
2. [Logging In](#2-logging-in)
3. [Multi-Factor Authentication (MFA)](#3-multi-factor-authentication-mfa)
4. [The Vault Interface](#4-the-vault-interface)
5. [Managing Secrets](#5-managing-secrets)
6. [Folders](#6-folders)
7. [Roles and Permissions](#7-roles-and-permissions)
8. [Viewing Secrets Securely](#8-viewing-secrets-securely)
9. [Version History](#9-version-history)
10. [API Tokens](#10-api-tokens)
11. [User Management (Administrators)](#11-user-management-administrators)
12. [Audit Log](#12-audit-log)
13. [Session Security](#13-session-security)
14. [Security Best Practices](#14-security-best-practices)

---

## 1. Concepts

Understanding these terms will help you use SecureVault effectively.

| Term | Description |
|------|-------------|
| **Secret** | Any sensitive item: password, API key, certificate, SSH key, or free-form note. |
| **Folder** | A container used to organize secrets hierarchically. Permissions can be set at the folder level. |
| **Role** | A named group of permissions. Users are assigned roles; roles are granted access to secrets or folders. |
| **Permission** | One of: **View**, **Add**, **Change**, or **Delete** — granted per secret or folder to a role. |
| **Super Admin** | A built-in administrator account that can manage users, roles, and the audit log. Cannot be locked out. |
| **MEK** | Master Encryption Key — a server-side key used to protect per-secret encryption keys. Never leaves the server. |
| **DEK** | Data Encryption Key — a unique key generated for each secret, encrypted by the MEK. |
| **Audit Log** | An append-only record of every significant action in the system. Cannot be altered or deleted. |

---

## 2. Logging In

1. Navigate to your SecureVault URL (e.g., `https://vault.example.com`).
2. Enter your **username** and **password**.
3. Click **Sign In**.

### Account Lockout

After **5 consecutive failed login attempts** your account is locked for **15 minutes**. Contact your administrator to unlock it sooner.

### First-Time Setup

If SecureVault has not yet been initialized you will be redirected to the **First Run Setup** page. Fill in the super-admin credentials to initialize the vault. This page is only available once.

---

## 3. Multi-Factor Authentication (MFA)

SecureVault supports TOTP-based MFA (compatible with Google Authenticator, Authy, 1Password, and any RFC 6238 authenticator).

### Completing an MFA Prompt

If your account has MFA enabled:

1. After entering your password, you will be shown a **verification code** prompt.
2. Open your authenticator app and enter the current 6-digit code.
3. Click **Verify**.

### Enrolling MFA (if not yet enabled)

Contact your administrator to enable MFA enrollment for your account. Once enabled, you will be prompted to scan a QR code on next login.

> **Tip:** Store your TOTP backup codes in a secure location separate from SecureVault.

---

## 4. The Vault Interface

After login you land on the **Vault** page, which is divided into three areas:

```
+------------------+----------------------------------------+
|   Folder Tree    |            Secret List                 |
|                  |  [Search...]   [+ New Secret]          |
|  > My Folder     |  ----------------------------------------|
|    > Sub-folder  |  Name         Type     Folder   Actions |
|                  |  api-key-prod  API Key  Prod     ...    |
|                  |  db-password   Password Prod     ...    |
+------------------+----------------------------------------+
```

### Navigation

- **Folder tree** (left) — Click a folder to filter the secret list. Click the root to show all accessible secrets.
- **Search bar** — Full-text search across secret names and descriptions.
- **Type filter** — Filter secrets by type (Password, API Key, Certificate, SSH Key, Note).
- **+ New Secret** — Opens the secret creation form.

---

## 5. Managing Secrets

### Create a Secret

1. Click **+ New Secret**.
2. Fill in the fields:

   | Field | Required | Description |
   |-------|----------|-------------|
   | Name | Yes | Human-readable identifier (e.g., `prod-db-password`) |
   | Type | Yes | Password / API Key / Certificate / SSH Key / Note |
   | Value | Yes | The sensitive data to store |
   | Folder | No | The folder this secret belongs to |
   | Description | No | Context about what this secret is for |
   | Tags | No | Comma-separated labels for filtering |
   | Expiry Date | No | Optional expiry date; expired secrets are flagged in the UI |

3. Click **Save**. The value is encrypted client-side before being sent to the server.

### Edit a Secret

1. Locate the secret in the list.
2. Click the **...** (actions) menu and select **Edit**, or click the secret name to open its detail page, then click **Edit**.
3. Modify the fields and click **Save**.

Each save creates a new version. Up to 20 previous versions are retained (see [Version History](#9-version-history)).

### Delete a Secret

1. Open the secret's actions menu and select **Delete**.
2. Confirm the deletion in the dialog.

Deleted secrets are soft-deleted and retained for 30 days before permanent removal. Contact your administrator if you need to recover a recently deleted secret.

### Search and Filter

- Type in the **Search** field to filter by name or description.
- Use the **Type** dropdown to show only secrets of a specific type.
- Click a folder in the tree to scope results to that folder.
- Filters can be combined.

---

## 6. Folders

Folders organize secrets hierarchically (up to 10 levels deep).

### Create a Folder

1. In the folder tree, right-click a parent folder (or the root) and select **New Folder**.
2. Enter a name and click **Create**.

### Move a Secret to a Folder

Edit the secret and change the **Folder** field.

### Folder Permissions

A role's permissions can be applied at the folder level, granting access to all secrets within that folder. This is managed from the **Admin → Roles** page (see [Roles and Permissions](#7-roles-and-permissions)).

---

## 7. Roles and Permissions

Roles are named groups of permissions. A user can have multiple roles.

### Permission Types

| Permission | What it allows |
|------------|---------------|
| **View** | Read the secret's metadata; reveal its value |
| **Add** | Create new secrets in the folder or vault |
| **Change** | Update an existing secret's value or metadata |
| **Delete** | Soft-delete a secret |

### Create a Role (Administrators)

1. Go to **Admin → Roles**.
2. Click **+ New Role**.
3. Enter a **Name** and optional **Description**.
4. Click **Create**.

### Assign Permissions to a Role

1. Open the role in **Admin → Roles**.
2. Under **Secret Access Control**, select the secret or folder.
3. Toggle the desired permissions (View, Add, Change, Delete).
4. Click **Save ACL**.

### Assign a Role to a User

1. Go to **Admin → Users** and open the user's profile.
2. Under **Roles**, click **+ Add Role** and select the role.
3. Click **Save**.

### Remove a Role from a User

1. Open the user's profile in **Admin → Users**.
2. Under **Roles**, click **Remove** next to the role to revoke.

---

## 8. Viewing Secrets Securely

Secret values are never displayed automatically. You must explicitly reveal them.

### Reveal a Value

1. Navigate to the secret's detail page.
2. Click the **eye icon** (Reveal) button next to the value field.
3. The decrypted value is shown for 30 seconds, then hidden automatically.

### Copy to Clipboard

1. Click the **copy icon** next to the value field (or after revealing it).
2. The value is copied to your clipboard.
3. The clipboard is automatically cleared after **30 seconds**.

> **Note:** Always use the built-in copy feature rather than manually selecting and copying text. This ensures the clipboard is cleared promptly.

---

## 9. Version History

SecureVault keeps up to **20 previous versions** of each secret value.

### View Version History

1. Open the secret's detail page.
2. Click **Version History**.
3. A list of previous versions is shown with timestamps and the user who made each change.
4. Click a version to view its (encrypted) metadata. To restore a previous value, edit the secret and re-enter the old value manually.

---

## 10. API Tokens

API tokens allow non-interactive access to SecureVault (e.g., for CI/CD pipelines or scripts). They carry the same permissions as the user who created them.

### Create an API Token

1. Go to your **Profile** (click your username in the top-right corner).
2. Under **API Tokens**, click **+ New Token**.
3. Enter a description (e.g., `ci-pipeline-prod`) and an optional expiry date.
4. Click **Create**.
5. **Copy the token now** — it is shown only once and cannot be retrieved later.

### Use an API Token

Pass the token as a Bearer token in the `Authorization` header:

```bash
curl -H "Authorization: Bearer <your-token>" \
     https://vault.example.com/api/v1/secrets
```

### Revoke an API Token

1. Go to your **Profile → API Tokens**.
2. Click **Revoke** next to the token.

> **Security note:** Treat API tokens like passwords. Store them in your CI/CD platform's secrets store, not in source code.

---

## 11. User Management (Administrators)

Only users with the **Super Admin** flag can access the User Management section.

### Create a User

1. Go to **Admin → Users**.
2. Click **+ New User**.
3. Fill in:

   | Field | Required | Description |
   |-------|----------|-------------|
   | Username | Yes | Unique login identifier |
   | Email | Yes | Used for notifications and password reset |
   | Password | Yes | Must meet complexity requirements |
   | Super Admin | No | Grants full administrative access |

4. Click **Create**. The user can log in immediately.

### Edit a User

1. Open the user in **Admin → Users**.
2. Modify the **email**, **active status**, or **super admin** flag.
3. Click **Save**.

### Deactivate a User

1. Open the user in **Admin → Users**.
2. Toggle **Active** to off.
3. Click **Save**.

Deactivated accounts cannot log in but are retained for audit trail completeness. They are never permanently deleted.

> **Tip:** Deactivate accounts immediately when an employee leaves the organization.

### Unlock a Locked Account

If a user is locked out after 5 failed login attempts:

1. Open the user in **Admin → Users**.
2. Click **Unlock Account**.

The lockout clears and the user can log in again immediately.

---

## 12. Audit Log

Every significant action in SecureVault is recorded in an **append-only audit log**. The log cannot be modified or deleted, even by super admins. This is enforced at the database level.

### Events That Are Logged

- Login attempts (successful and failed), lockouts
- MFA verification attempts
- Secret creation, retrieval (value revealed), update, and deletion
- Role and permission changes
- User creation, deactivation, and role assignments
- API token creation and revocation

### Viewing the Audit Log

1. Go to **Admin → Audit Log** (super admin only).
2. Use the filters to narrow results:
   - **Date range** — From / To date selectors
   - **User** — Filter by specific user
   - **Event type** — Filter by action category
3. Results are shown newest-first, paginated.

### Exporting the Audit Log

1. Apply any desired filters.
2. Click **Export CSV**.
3. A CSV file is streamed to your browser containing all matching records.

The CSV includes columns for: timestamp, user, event type, target resource, IP address, and result (success/failure).

---

## 13. Session Security

SecureVault enforces several automatic security controls on your session.

### Automatic Logout

Your session expires automatically after **15 minutes of inactivity**. A warning appears at the 14-minute mark. Any mouse movement, keypress, or click resets the idle timer.

When the session expires you are redirected to the login page. Unsaved changes may be lost.

### Token Refresh

Authentication tokens are short-lived and refreshed silently in the background. If a refresh fails (e.g., server restart) you will be redirected to login.

### Clipboard Auto-Clear

When you copy a secret value using the built-in copy button, the clipboard is cleared after **30 seconds**. You will see a countdown indicator. To clear the clipboard immediately, copy any non-sensitive text.

### httpOnly Cookies

Authentication tokens are stored in `httpOnly` cookies, not in browser storage. They are not accessible to JavaScript and are protected against XSS-based token theft.

---

## 14. Security Best Practices

Follow these guidelines to use SecureVault safely:

**Accounts and Passwords**
- Use a strong, unique password for your SecureVault account (16+ characters, mixed character types).
- Enable MFA on your account and store backup codes securely.
- Never share your credentials with colleagues; create separate accounts for each person.

**Secrets**
- Use the built-in copy button rather than manually selecting text.
- Set expiry dates on secrets that rotate periodically (e.g., 90-day API keys).
- Use descriptive names and descriptions to avoid confusion.
- Organize secrets in folders and use roles to apply least-privilege access.

**API Tokens**
- Create separate API tokens for each integration (one token per pipeline/service).
- Set expiry dates on API tokens where possible.
- Revoke tokens immediately when a pipeline or integration is decommissioned.
- Never commit API tokens to source code repositories.

**Access Control**
- Apply the principle of least privilege: grant only the permissions a role actually needs.
- Review role assignments regularly, especially after team changes.
- Deactivate user accounts immediately upon employee departure.

**Monitoring**
- Review the audit log regularly for unexpected access patterns.
- Export and archive audit logs to your SIEM for long-term retention.
- Investigate any failed login bursts — they may indicate a brute-force attempt.
