-- 007: record the signature encoding (der or raw) used by the device.
ALTER TABLE authorization_requests
  ADD COLUMN IF NOT EXISTS signature_format VARCHAR(8);
