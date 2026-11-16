-- Device request nonces are deleted only after they expire (audit finding
-- C-11). The application role has DELETE on the table for the expiry sweep
-- (authorizationExpiry.ts); a GRANT cannot be limited to rows, so a session
-- with that role could delete live nonces and replay a signed device request
-- inside its timestamp window. This trigger refuses that for every role
-- (TRUNCATE is not granted to the application role).
CREATE OR REPLACE FUNCTION device_request_nonces_expired_only() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
  IF OLD.expires_at >= now() THEN
    RAISE EXCEPTION 'device request nonce of credential % has not expired (DELETE refused)', OLD.credential_id
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN OLD;
END $$;
DROP TRIGGER IF EXISTS device_request_nonces_expired_only ON device_request_nonces;
CREATE TRIGGER device_request_nonces_expired_only BEFORE DELETE ON device_request_nonces
  FOR EACH ROW EXECUTE FUNCTION device_request_nonces_expired_only();
