-- Hardening (audit findings C-15, C-16).
-- C-15: every function of the schema runs with a fixed search_path, so no
-- object a session creates (for example in pg_temp) can shadow a table or
-- function a trigger uses. Applied to every function in public that does not
-- set one yet; functions created later set it themselves.
DO $$
DECLARE r RECORD;
BEGIN
  FOR r IN SELECT p.oid::regprocedure AS signature FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
           WHERE n.nspname = 'public' AND p.prokind = 'f' AND p.prolang IN (SELECT oid FROM pg_language WHERE lanname IN ('plpgsql', 'sql'))
             AND pg_has_role(p.proowner, 'USAGE')
             AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = p.oid AND d.deptype = 'e')
             AND NOT EXISTS (SELECT 1 FROM unnest(coalesce(p.proconfig, '{}')) c WHERE c LIKE 'search_path=%') LOOP
    EXECUTE format('ALTER FUNCTION %s SET search_path = pg_catalog, public, pg_temp', r.signature);
  END LOOP;
END $$;

-- C-16: the tables that keep a history cannot be emptied with TRUNCATE,
-- which row triggers do not see (evidence_records, audit_logs and
-- evidence_outcomes already refuse it).
CREATE OR REPLACE FUNCTION nexus_refuse_truncate() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
  RAISE EXCEPTION '% keeps its history (TRUNCATE refused)', TG_TABLE_NAME USING ERRCODE = 'integrity_constraint_violation';
END $$;
DO $$
DECLARE t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY['offline_deferred_signatures', 'offline_challenges', 'authorization_requests', 'credentials', 'nexus_identities',
                           'authorization_attempts', 'admin_approvals', 'recovery_sessions', 'device_replacements', 'mandates', 'mandate_debits'] LOOP
    IF to_regclass('public.' || t) IS NOT NULL THEN
      EXECUTE format('DROP TRIGGER IF EXISTS %I ON public.%I', t || '_no_truncate', t);
      EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON public.%I FOR EACH STATEMENT EXECUTE FUNCTION nexus_refuse_truncate()', t || '_no_truncate', t);
    END IF;
  END LOOP;
END $$;
