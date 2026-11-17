-- Re-encryption of stored secrets is allowed only to a session that is not
-- the application role, or that also holds nexus_secret_rotator (audit
-- findings B-09, C-08). Before, any session of the application role could
-- set nexus.secret_rewrap and replace a credential's offline secret with
-- another ciphertext. Where the deployment roles of scripts/db/roles.sql do
-- not exist (development), and for superusers, the setting alone suffices.
CREATE OR REPLACE FUNCTION secret_rewrap_allowed() RETURNS boolean
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF coalesce(current_setting('nexus.secret_rewrap', true), '') <> 'on' THEN RETURN false; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nexus_app') THEN RETURN true; END IF;
  IF (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN RETURN true; END IF;
  IF NOT pg_has_role(current_user, 'nexus_app', 'MEMBER') THEN RETURN true; END IF;
  RETURN EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nexus_secret_rotator')
     AND pg_has_role(current_user, 'nexus_secret_rotator', 'MEMBER');
END $$;
