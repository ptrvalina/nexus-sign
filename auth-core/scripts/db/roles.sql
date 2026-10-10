-- Database roles for an Auth Core deployment (NXS-015).
--
-- Run once per database as a superuser (or the cloud provider's admin role),
-- after the schema and migrations, and again after each upgrade:
--
--   psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -f scripts/db/roles.sql
--
-- Roles:
--   nexus_owner          owns every table, sequence and trigger function. NOLOGIN:
--                        migrations run with SET ROLE nexus_owner by a named DBA.
--   nexus_app            what Auth Core connects as (DATABASE_URL). No ownership,
--                        so it cannot disable or replace the append-only and
--                        lifecycle triggers; INSERT and SELECT only on the
--                        evidence and audit tables; DELETE only on
--                        push_registrations; no TRUNCATE anywhere.
--   nexus_audit_reader   read-only access to evidence and audit records, for
--                        export and archival.
--
-- Passwords are not set here: create the login with the provider's tooling or
--   ALTER ROLE nexus_app WITH LOGIN PASSWORD '<from the secrets manager>';
-- What this does not cover: a superuser (or the provider's admin role) can
-- still disable triggers; log DDL with pgaudit or the provider's audit log and
-- restrict who holds that role.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nexus_owner') THEN CREATE ROLE nexus_owner NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nexus_app') THEN CREATE ROLE nexus_app NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nexus_audit_reader') THEN CREATE ROLE nexus_audit_reader NOLOGIN; END IF;
END $$;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO nexus_app, nexus_audit_reader;
GRANT CREATE ON SCHEMA public TO nexus_owner;

-- Ownership of every table, sequence and function in the schema.
DO $$
DECLARE r RECORD;
BEGIN
  FOR r IN SELECT tablename FROM pg_tables WHERE schemaname = 'public' LOOP
    EXECUTE format('ALTER TABLE public.%I OWNER TO nexus_owner', r.tablename);
  END LOOP;
  FOR r IN SELECT sequencename FROM pg_sequences WHERE schemaname = 'public' LOOP
    EXECUTE format('ALTER SEQUENCE public.%I OWNER TO nexus_owner', r.sequencename);
  END LOOP;
  FOR r IN SELECT p.oid::regprocedure AS signature FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
           WHERE n.nspname = 'public' AND p.prokind = 'f' AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = p.oid AND d.deptype = 'e') LOOP
    EXECUTE format('ALTER FUNCTION %s OWNER TO nexus_owner', r.signature);
  END LOOP;
END $$;

-- Application: read and write the operational tables. It deletes only push
-- registrations; everything else keeps its history (and the delete triggers
-- of migration 017 refuse it anyway).
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM nexus_app;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO nexus_app;
GRANT DELETE ON push_registrations TO nexus_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO nexus_app;
-- Evidence and audit records are only ever added.
REVOKE UPDATE ON evidence_records, audit_logs FROM nexus_app;

-- Archival reads.
GRANT SELECT ON evidence_records, audit_logs TO nexus_audit_reader;

-- Tables created by later migrations (run as nexus_owner) get the same grants.
ALTER DEFAULT PRIVILEGES FOR ROLE nexus_owner IN SCHEMA public GRANT SELECT, INSERT, UPDATE ON TABLES TO nexus_app;
ALTER DEFAULT PRIVILEGES FOR ROLE nexus_owner IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO nexus_app;
