-- 010: device authentication keys and offline confirmation.
--
-- * credentials.auth_public_key_pem: hardware key with which an enrolled
--   device signs its own requests (no bearer token after enrolment).
-- * credentials.offline_*: the device's key-agreement key, the server half of
--   the agreement and the derived per-credential key, encrypted with
--   DEVICE_SECRET_ENCRYPTION_KEY.
-- * authorization_requests.confirmation_method: DEVICE_SIGNATURE or OFFLINE_CODE.

ALTER TABLE credentials
  ADD COLUMN IF NOT EXISTS auth_public_key_pem TEXT,
  ADD COLUMN IF NOT EXISTS offline_public_key_pem TEXT,
  ADD COLUMN IF NOT EXISTS offline_server_public_key_pem TEXT,
  ADD COLUMN IF NOT EXISTS offline_secret_encrypted TEXT;

ALTER TABLE authorization_requests
  ADD COLUMN IF NOT EXISTS confirmation_method VARCHAR(16);

ALTER TABLE authorization_requests DROP CONSTRAINT IF EXISTS authorization_requests_confirmation_method_check;
ALTER TABLE authorization_requests ADD CONSTRAINT authorization_requests_confirmation_method_check
  CHECK (confirmation_method IS NULL OR confirmation_method IN ('DEVICE_SIGNATURE', 'OFFLINE_CODE'));

ALTER TABLE authorization_requests DROP CONSTRAINT IF EXISTS authorization_requests_signature_format_check;
ALTER TABLE authorization_requests ADD CONSTRAINT authorization_requests_signature_format_check
  CHECK (signature_format IS NULL OR signature_format IN ('der', 'raw', 'hmac'));

ALTER TABLE credentials DROP CONSTRAINT IF EXISTS credentials_offline_keys_check;
ALTER TABLE credentials ADD CONSTRAINT credentials_offline_keys_check
  CHECK ((offline_secret_encrypted IS NULL) = (offline_server_public_key_pem IS NULL));
