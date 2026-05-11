-- SecureVault Database Setup (Microsoft SQL Server)
-- Run as a sysadmin login (e.g. sa) against the SecureVault database.
--
-- Expects two sqlcmd variables:
--   :setvar DbName       securevault
--   :setvar AppLogin     securevault_app
--   :setvar AppPassword  <password>
--
-- Example invocation:
--   sqlcmd -S localhost -U sa -P <sa_pwd> -i db-setup.sql ^
--          -v DbName="securevault" AppLogin="securevault_app" AppPassword="<pwd>"
--
-- NOTE: Run AFTER `dotnet ef database update` has created the schema —
-- the audit-log immutability triggers are created by the EF migration; this
-- script only manages the SQL login/user and least-privilege grants.

SET NOCOUNT ON;
SET XACT_ABORT ON;

:on error exit

-- ─────────────────────────────────────────────────────────────────────────────
-- 1. Ensure database exists. (For production, create with the proper data/log
--    file paths and recovery model beforehand; this is a safety net for dev.)
-- ─────────────────────────────────────────────────────────────────────────────
IF DB_ID(N'$(DbName)') IS NULL
BEGIN
    DECLARE @createDb nvarchar(max) = N'CREATE DATABASE ' + QUOTENAME(N'$(DbName)');
    EXEC (@createDb);
END
GO

USE [$(DbName)];
GO

-- ─────────────────────────────────────────────────────────────────────────────
-- 2. Create server login for the application (idempotent)
-- ─────────────────────────────────────────────────────────────────────────────
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'$(AppLogin)')
BEGIN
    DECLARE @createLogin nvarchar(max) =
        N'CREATE LOGIN ' + QUOTENAME(N'$(AppLogin)') +
        N' WITH PASSWORD = ' + QUOTENAME(N'$(AppPassword)', '''') +
        N', CHECK_POLICY = ON';
    EXEC (@createLogin);
END
GO

-- ─────────────────────────────────────────────────────────────────────────────
-- 3. Map login to a database user with least privilege
-- ─────────────────────────────────────────────────────────────────────────────
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$(AppLogin)')
BEGIN
    DECLARE @createUser nvarchar(max) =
        N'CREATE USER ' + QUOTENAME(N'$(AppLogin)') +
        N' FOR LOGIN ' + QUOTENAME(N'$(AppLogin)');
    EXEC (@createUser);
END
GO

-- Required runtime grants
EXEC sp_addrolemember N'db_datareader', N'$(AppLogin)';
EXEC sp_addrolemember N'db_datawriter', N'$(AppLogin)';
GO

-- ─────────────────────────────────────────────────────────────────────────────
-- 4. Audit-log append-only enforcement
-- The EF Core initial migration installs INSTEAD OF UPDATE/DELETE triggers
-- on dbo.audit_log. They block all UPDATEs and allow DELETE only when the
-- executing principal is a member of db_owner (used by the retention job).
-- Verify the triggers exist:
-- ─────────────────────────────────────────────────────────────────────────────
IF OBJECT_ID(N'dbo.audit_log', N'U') IS NULL
BEGIN
    RAISERROR('audit_log table not found — run "dotnet ef database update" first, then re-run this script.', 10, 1) WITH NOWAIT;
END
ELSE
BEGIN
    IF NOT EXISTS (SELECT 1 FROM sys.triggers WHERE name = N'trg_audit_log_no_update')
        RAISERROR('WARNING: trg_audit_log_no_update missing on audit_log.', 10, 1) WITH NOWAIT;
    IF NOT EXISTS (SELECT 1 FROM sys.triggers WHERE name = N'trg_audit_log_no_delete')
        RAISERROR('WARNING: trg_audit_log_no_delete missing on audit_log.', 10, 1) WITH NOWAIT;

    -- Belt-and-braces: explicitly DENY UPDATE/DELETE on audit_log to the app user.
    -- (INSTEAD OF triggers already block, but DENY makes intent explicit and
    -- protects against the triggers being dropped accidentally.)
    DECLARE @denySql nvarchar(max) =
        N'DENY UPDATE, DELETE ON dbo.audit_log TO ' + QUOTENAME(N'$(AppLogin)');
    EXEC (@denySql);
END
GO

PRINT 'SecureVault database setup complete.';
GO
