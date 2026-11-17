-- Audit fields are written by the server, once (audit finding C-07).
--
-- consumed_at is set together with the transition to VERIFIED and never
-- changes afterwards; bank_commit_at and bank_commit_error are set together
-- with the bank transaction's final state (COMMITTED, FAILED, CANCELLED) and
-- never change afterwards. Before, the application role could clear or
-- backdate them on a final authorization.
CREATE OR REPLACE FUNCTION authorization_audit_fields() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
  IF NEW.consumed_at IS DISTINCT FROM OLD.consumed_at
     AND NOT (OLD.consumed_at IS NULL AND NEW.state = 'VERIFIED' AND OLD.state IN ('PENDING_USER', 'OFFLINE_PROVISIONAL')) THEN
    RAISE EXCEPTION 'authorization % : consumed_at is set once, on verification', OLD.authorization_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF (NEW.bank_commit_at IS DISTINCT FROM OLD.bank_commit_at OR NEW.bank_commit_error IS DISTINCT FROM OLD.bank_commit_error)
     AND NOT (OLD.bank_transaction_state = 'COMMIT_REQUESTED' AND NEW.bank_transaction_state IN ('COMMITTED', 'FAILED', 'CANCELLED')) THEN
    RAISE EXCEPTION 'authorization % : the bank commit result is set once, with the final bank transaction state', OLD.authorization_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS authorization_audit_fields ON authorization_requests;
CREATE TRIGGER authorization_audit_fields BEFORE UPDATE ON authorization_requests
  FOR EACH ROW EXECUTE FUNCTION authorization_audit_fields();

-- An audit row carries the database's time: a supplied "timestamp" is
-- replaced, except for the table owner (who can disable triggers anyway).
CREATE OR REPLACE FUNCTION audit_logs_server_time() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
  IF NOT pg_has_role(current_user, (SELECT relowner FROM pg_class WHERE oid = TG_RELID), 'USAGE') THEN
    NEW."timestamp" := now();
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS audit_logs_server_time ON audit_logs;
CREATE TRIGGER audit_logs_server_time BEFORE INSERT ON audit_logs
  FOR EACH ROW EXECUTE FUNCTION audit_logs_server_time();
