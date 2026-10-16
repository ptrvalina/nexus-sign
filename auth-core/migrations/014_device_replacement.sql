-- 014: device replacement (NXS-002).
--
-- A new device for an identity that already has one is enrolled only with the
-- bank's replacement authorization. The replaced device receives a security
-- notice through secure push, delivered although its credential is revoked.

ALTER TABLE push_messages ADD COLUMN IF NOT EXISTS replacement_notice BOOLEAN NOT NULL DEFAULT FALSE;
