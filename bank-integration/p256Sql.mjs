// ECDSA P-256 / SHA-256 signature verification in PL/pgSQL, for the bank's
// database. PostgreSQL has no elliptic-curve primitive (pgcrypto offers none),
// and without one the database could only check the shape of the evidence a
// role handed it; the cryptographic check ran in the gateway process, so any
// code holding the gateway's login could send a payment the customer never
// signed (audit finding C-02). With this file the database itself verifies
// the customer's device signature and the bank's statement signatures before
// it records an approval or lets the gateway submit.
//
// Scope and properties:
//   - verification only: no private key, no secret, so timing does not matter;
//   - curve secp256r1 (FIPS 186-5 / SEC 2), hash SHA-256 (PostgreSQL sha256());
//   - public keys: exactly the 91-byte DER SubjectPublicKeyInfo of an
//     uncompressed P-256 point (the form every NEXUS-SIGN component exports);
//     the point must lie on the curve;
//   - signatures: strict DER ECDSA-Sig-Value (minimal integers, no trailing
//     bytes) or raw r||s (64 bytes); 1 <= r, s < n. High S is accepted, as in
//     the other NEXUS-SIGN verifiers: a second encoding of the same approval
//     changes nothing the bank decides;
//   - arithmetic on `numeric` in Jacobian coordinates, u1*G + u2*Q by Shamir's
//     trick, one modular inversion at the end.
// Tested against Node's OpenSSL on generated keys, messages and corrupted
// signatures in auth-core/test/integration/bank-p256.test.mjs.
//
// Every function is internal: installSchema grants none of them to any role.

export const P256_SQL = String.raw`
CREATE OR REPLACE FUNCTION bank.ec_from_bytes(p bytea) RETURNS numeric
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = pg_catalog, pg_temp AS $$
DECLARE v numeric := 0; i integer;
BEGIN
  FOR i IN 0 .. length(p) - 1 LOOP v := v * 256 + get_byte(p, i); END LOOP;
  RETURN v;
END $$;

CREATE OR REPLACE FUNCTION bank.ec_mod(a numeric, m numeric) RETURNS numeric
LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE WHEN a >= 0 THEN mod(a, m) ELSE mod(mod(a, m) + m, m) END
$$;

-- Inverse of a modulo a prime m (extended Euclid); a must not be 0 mod m.
CREATE OR REPLACE FUNCTION bank.ec_inv(a numeric, m numeric) RETURNS numeric
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = pg_catalog, pg_temp AS $$
DECLARE r0 numeric := m; r1 numeric := bank.ec_mod(a, m); t0 numeric := 0; t1 numeric := 1; q numeric; tmp numeric;
BEGIN
  IF r1 = 0 THEN RAISE EXCEPTION 'no inverse of 0' USING ERRCODE = 'invalid_parameter_value'; END IF;
  WHILE r1 <> 0 LOOP
    q := div(r0, r1);
    tmp := r0 - q * r1; r0 := r1; r1 := tmp;
    tmp := t0 - q * t1; t0 := t1; t1 := tmp;
  END LOOP;
  RETURN bank.ec_mod(t0, m);
END $$;

-- Curve constants: [p, n, b, Gx, Gy].
CREATE OR REPLACE FUNCTION bank.ec_p256() RETURNS numeric[]
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT ARRAY[
    bank.ec_from_bytes('\xffffffff00000001000000000000000000000000ffffffffffffffffffffffff'::bytea),
    bank.ec_from_bytes('\xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551'::bytea),
    bank.ec_from_bytes('\x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b'::bytea),
    bank.ec_from_bytes('\x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296'::bytea),
    bank.ec_from_bytes('\x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5'::bytea)]
$$;

-- Jacobian doubling for a = -3 (dbl-2001-b). Points are [X, Y, Z]; Z = 0 is infinity.
CREATE OR REPLACE FUNCTION bank.ec_double(pt numeric[], p numeric) RETURNS numeric[]
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = pg_catalog, pg_temp AS $$
DECLARE delta numeric; gamma numeric; beta numeric; alpha numeric; x3 numeric; y3 numeric; z3 numeric;
BEGIN
  IF pt[3] = 0 OR pt[2] = 0 THEN RETURN ARRAY[1, 1, 0]::numeric[]; END IF;
  delta := mod(pt[3] * pt[3], p);
  gamma := mod(pt[2] * pt[2], p);
  beta := mod(pt[1] * gamma, p);
  alpha := bank.ec_mod(3 * (pt[1] - delta) * (pt[1] + delta), p);
  x3 := bank.ec_mod(alpha * alpha - 8 * beta, p);
  z3 := bank.ec_mod((pt[2] + pt[3]) * (pt[2] + pt[3]) - gamma - delta, p);
  y3 := bank.ec_mod(alpha * (4 * beta - x3) - 8 * gamma * gamma, p);
  RETURN ARRAY[x3, y3, z3];
END $$;

-- Jacobian addition (add-2007-bl), with the equal-point and inverse cases.
CREATE OR REPLACE FUNCTION bank.ec_add(a numeric[], b numeric[], p numeric) RETURNS numeric[]
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = pg_catalog, pg_temp AS $$
DECLARE z1z1 numeric; z2z2 numeric; u1 numeric; u2 numeric; s1 numeric; s2 numeric; h numeric; r numeric; i numeric; j numeric; v numeric; x3 numeric;
BEGIN
  IF a[3] = 0 THEN RETURN b; END IF;
  IF b[3] = 0 THEN RETURN a; END IF;
  z1z1 := mod(a[3] * a[3], p);
  z2z2 := mod(b[3] * b[3], p);
  u1 := mod(a[1] * z2z2, p);
  u2 := mod(b[1] * z1z1, p);
  s1 := mod(a[2] * b[3] * z2z2, p);
  s2 := mod(b[2] * a[3] * z1z1, p);
  h := bank.ec_mod(u2 - u1, p);
  r := bank.ec_mod(2 * (s2 - s1), p);
  IF h = 0 THEN
    IF r = 0 THEN RETURN bank.ec_double(a, p); END IF;
    RETURN ARRAY[1, 1, 0]::numeric[];
  END IF;
  i := mod(4 * h * h, p);
  j := mod(h * i, p);
  v := mod(u1 * i, p);
  x3 := bank.ec_mod(r * r - j - 2 * v, p);
  RETURN ARRAY[x3,
               bank.ec_mod(r * (v - x3) - 2 * s1 * j, p),
               bank.ec_mod(((a[3] + b[3]) * (a[3] + b[3]) - z1z1 - z2z2) * h, p)];
END $$;

-- The two 32-byte coordinates of a P-256 public key given as DER
-- SubjectPublicKeyInfo (uncompressed point only), or NULL when the bytes are
-- not exactly that or the point is not on the curve.
CREATE OR REPLACE FUNCTION bank.ec_public_point(p_spki bytea) RETURNS numeric[]
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = pg_catalog, pg_temp AS $$
DECLARE c numeric[] := bank.ec_p256(); x numeric; y numeric;
BEGIN
  IF length(p_spki) <> 91 OR substring(p_spki FROM 1 FOR 27) <> '\x3059301306072a8648ce3d020106082a8648ce3d03010703420004'::bytea THEN
    RETURN NULL;
  END IF;
  x := bank.ec_from_bytes(substring(p_spki FROM 28 FOR 32));
  y := bank.ec_from_bytes(substring(p_spki FROM 60 FOR 32));
  IF x >= c[1] OR y >= c[1] THEN RETURN NULL; END IF;
  IF mod(y * y, c[1]) <> bank.ec_mod(x * x * x - 3 * x + c[3], c[1]) THEN RETURN NULL; END IF;
  RETURN ARRAY[x, y];
END $$;

-- [r, s] from a strict DER ECDSA-Sig-Value, or NULL.
CREATE OR REPLACE FUNCTION bank.ec_der_signature(p_der bytea) RETURNS numeric[]
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = pg_catalog, pg_temp AS $$
DECLARE total integer := length(p_der); pos integer := 2; result numeric[] := ARRAY[]::numeric[]; len integer; k integer;
BEGIN
  IF total < 8 OR total > 72 OR get_byte(p_der, 0) <> 48 OR get_byte(p_der, 1) <> total - 2 THEN RETURN NULL; END IF;
  FOR k IN 1 .. 2 LOOP
    IF pos + 2 > total OR get_byte(p_der, pos) <> 2 THEN RETURN NULL; END IF;
    len := get_byte(p_der, pos + 1);
    IF len < 1 OR len > 33 OR pos + 2 + len > total THEN RETURN NULL; END IF;
    -- Minimal two's-complement encoding of a positive integer.
    IF get_byte(p_der, pos + 2) >= 128 THEN RETURN NULL; END IF;
    IF len > 1 AND get_byte(p_der, pos + 2) = 0 AND get_byte(p_der, pos + 3) < 128 THEN RETURN NULL; END IF;
    result := result || bank.ec_from_bytes(substring(p_der FROM pos + 3 FOR len));
    pos := pos + 2 + len;
  END LOOP;
  IF pos <> total THEN RETURN NULL; END IF;
  RETURN result;
END $$;

-- True only when p_signature (format 'der' or 'raw') is a valid ECDSA
-- P-256/SHA-256 signature over p_message for the key p_spki. Every malformed
-- input yields false, never an error.
CREATE OR REPLACE FUNCTION bank.p256_verify(p_spki bytea, p_message bytea, p_signature bytea, p_format text) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  c numeric[] := bank.ec_p256(); p numeric; n numeric; q numeric[]; rs numeric[]; r numeric; s numeric;
  e numeric; w numeric; u1 numeric; u2 numeric; g numeric[]; qj numeric[]; gq numeric[]; acc numeric[] := ARRAY[1, 1, 0]::numeric[];
  bits1 integer[] := ARRAY[]::integer[]; bits2 integer[] := ARRAY[]::integer[]; t1 numeric; t2 numeric; i integer; zinv numeric; x numeric;
BEGIN
  IF p_spki IS NULL OR p_message IS NULL OR p_signature IS NULL OR p_format IS NULL THEN RETURN false; END IF;
  p := c[1]; n := c[2];
  q := bank.ec_public_point(p_spki);
  IF q IS NULL THEN RETURN false; END IF;
  IF p_format = 'der' THEN rs := bank.ec_der_signature(p_signature);
  ELSIF p_format = 'raw' AND length(p_signature) = 64 THEN
    rs := ARRAY[bank.ec_from_bytes(substring(p_signature FROM 1 FOR 32)), bank.ec_from_bytes(substring(p_signature FROM 33 FOR 32))];
  END IF;
  IF rs IS NULL THEN RETURN false; END IF;
  r := rs[1]; s := rs[2];
  IF r < 1 OR r >= n OR s < 1 OR s >= n THEN RETURN false; END IF;
  e := bank.ec_from_bytes(sha256(p_message));
  w := bank.ec_inv(s, n);
  u1 := mod(e * w, n);
  u2 := mod(r * w, n);
  g := ARRAY[c[4], c[5], 1];
  qj := ARRAY[q[1], q[2], 1];
  gq := bank.ec_add(g, qj, p);
  t1 := u1; t2 := u2;
  FOR i IN 1 .. 256 LOOP
    bits1 := bits1 || mod(t1, 2)::integer; t1 := div(t1, 2);
    bits2 := bits2 || mod(t2, 2)::integer; t2 := div(t2, 2);
  END LOOP;
  -- Shamir's trick: one pass over the bits of u1 and u2, most significant first.
  FOR i IN REVERSE 256 .. 1 LOOP
    acc := bank.ec_double(acc, p);
    IF bits1[i] = 1 AND bits2[i] = 1 THEN acc := bank.ec_add(acc, gq, p);
    ELSIF bits1[i] = 1 THEN acc := bank.ec_add(acc, g, p);
    ELSIF bits2[i] = 1 THEN acc := bank.ec_add(acc, qj, p);
    END IF;
  END LOOP;
  IF acc[3] = 0 THEN RETURN false; END IF;
  zinv := bank.ec_inv(acc[3], p);
  x := mod(acc[1] * zinv * zinv, p);
  RETURN mod(x, n) = r;
EXCEPTION WHEN OTHERS THEN
  RETURN false;
END $$;

-- DER SubjectPublicKeyInfo from a PEM "PUBLIC KEY" block, or NULL.
CREATE OR REPLACE FUNCTION bank.spki_from_pem(p_pem text) RETURNS bytea
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE body text;
BEGIN
  body := substring(p_pem FROM '-----BEGIN PUBLIC KEY-----(.*)-----END PUBLIC KEY-----');
  IF body IS NULL THEN RETURN NULL; END IF;
  RETURN decode(regexp_replace(body, '\s', '', 'g'), 'base64');
EXCEPTION WHEN OTHERS THEN
  RETURN NULL;
END $$;

-- The canonical JSON of a flat object as NEXUS-SIGN's canonicalJson produces
-- it (keys sorted, no whitespace, JSON.stringify escaping). Only string and
-- number values; anything else returns NULL so that the caller refuses it.
CREATE OR REPLACE FUNCTION bank.canonical_flat_json(p jsonb) RETURNS text
LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE
    WHEN jsonb_typeof(p) <> 'object' THEN NULL
    WHEN EXISTS (SELECT 1 FROM jsonb_each(p) e WHERE jsonb_typeof(e.value) NOT IN ('string', 'number')) THEN NULL
    WHEN EXISTS (SELECT 1 FROM jsonb_object_keys(p) k WHERE k !~ '^[A-Za-z][A-Za-z0-9_]*$') THEN NULL
    ELSE '{' || coalesce((SELECT string_agg(to_json(e.key)::text || ':' || CASE jsonb_typeof(e.value) WHEN 'string' THEN to_json(e.value #>> '{}')::text ELSE e.value::text END,
                                            ',' ORDER BY e.key COLLATE "C") FROM jsonb_each(p) e), '') || '}'
  END
$$;
`;
