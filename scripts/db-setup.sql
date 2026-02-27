-- SecureVault Database Setup
-- Run as PostgreSQL superuser (postgres) — NOT as securevault_app
-- This script sets up roles, permissions, and append-only audit log constraint.

-- Create application role (if not exists)
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'securevault_app') THEN
        CREATE ROLE securevault_app WITH LOGIN PASSWORD 'CHANGEME_IN_ENV';
    END IF;
END $$;

-- Grant required permissions to application role
GRANT CONNECT ON DATABASE securevault TO securevault_app;
GRANT USAGE ON SCHEMA public TO securevault_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO securevault_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO securevault_app;

-- Ensure future tables are accessible
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO securevault_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO securevault_app;

-- CRITICAL: Revoke DELETE and UPDATE on audit_log from the application role
-- This enforces append-only audit log — the application user cannot delete or modify audit entries
-- This MUST be run AFTER EF Core migrations have created the audit_log table
DO $$
BEGIN
    IF EXISTS (SELECT FROM information_schema.tables
               WHERE table_schema = 'public' AND table_name = 'audit_log') THEN
        REVOKE DELETE, UPDATE ON audit_log FROM securevault_app;
        RAISE NOTICE 'REVOKE DELETE, UPDATE on audit_log from securevault_app: done';
    ELSE
        RAISE NOTICE 'audit_log table not yet created — run migrations first, then re-run this script';
    END IF;
END $$;

-- Optional: Enable pg_cron for audit log retention (1 year)
-- Uncomment if pg_cron extension is available:
-- CREATE EXTENSION IF NOT EXISTS pg_cron;
-- SELECT cron.schedule(
--   'audit-log-retention',
--   '0 0 * * *',
--   $$DELETE FROM audit_log WHERE event_time < NOW() - INTERVAL '365 days'$$
-- );
