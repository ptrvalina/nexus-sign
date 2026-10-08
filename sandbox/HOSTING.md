# Hosting the sandbox

This page covers exposing the sandbox to banks and partners over the internet. Each guest receives an access code that opens a private workspace, and HTTPS is terminated by Caddy with an automatically renewed certificate.

## Requirements

- A Linux server with a public IP: 1 vCPU and 1 GB RAM are enough.
- A DNS name pointing to that IP, for example `sandbox.example.com`.
- Docker Engine with the Compose plugin.
- Ports 80 and 443 open. Port 80 is needed for certificate issuance and the HTTP→HTTPS redirect.

## First deployment

```bash
# on the server
git clone <repository> nexus-sign && cd nexus-sign/sandbox
cp deploy/.env.example deploy/.env
python3 tools/new_access_code.py acme-bank          # one line per guest
python3 -c "import secrets; print(secrets.token_urlsafe(32))"   # session secret
nano deploy/.env                                    # fill in the three values
cd deploy && docker compose up -d --build
```

`deploy/.env`:

```ini
SANDBOX_DOMAIN=sandbox.example.com
SANDBOX_ACCESS_CODES=acme-bank:<code>,partner-x:<code>
SANDBOX_SESSION_SECRET=<random>
```

Check the deployment:

```bash
curl https://sandbox.example.com/api/v1/health     # {"status": "ok", "hosted": true, ...}
curl -o /dev/null -w '%{http_code}\n' https://sandbox.example.com/api/v1/state   # 401
```

## Guests

**Adding or revoking a guest.**
1. Edit `SANDBOX_ACCESS_CODES`.
2. Run `docker compose up -d`.

The container restarts in about two seconds, and a removed code stops working immediately. Sessions of the remaining guests stay valid because they are signed with `SANDBOX_SESSION_SECRET`.

**Sending access.** Send the URL and the access code through different channels, for example the URL by e-mail and the code by phone or a messenger.

**What a guest can do:**
- Use the browser UI: the whole demonstration, see the [demonstration script](README.md#demonstration-script).
- Call the API from scripts with `Authorization: Bearer <code>`. The API is described in `openapi.yaml`.
- Run the command-line device simulator:

  ```bash
  python3 tools/device_simulator.py enrol --base=https://sandbox.example.com --token=<code>
  ```

## Data and limits

- **State is in memory and per workspace.** A restart clears every workspace, and nothing is written to disk. The container runs with a read-only file system and no Linux capabilities.
- **Per-workspace limits:**
  - 300 authorizations; after that the guest presses **Reset environment**;
  - 100 device keys; the oldest key is retired automatically.
- **Rate limit on failed codes:** 10 per client address per 15 minutes, counting both the sign-in form and `Authorization: Bearer` requests.
- **Operating logs:** `docker compose logs -f`. For per-request logs, set `SANDBOX_ACCESS_LOG=1` in the `sandbox` service.

## Updating

```bash
git pull && cd sandbox/deploy && docker compose up -d --build
```

## Security notes

- Local mode refuses to listen on a public interface: without access codes the server exits.
- **Cookies:** sessions are HttpOnly, Secure and SameSite=Strict, expire after 12 hours, are revoked on the server when the guest signs out, and stop working once that guest's access code is changed and the service restarted.
- **Headers:** the UI is served with a strict Content-Security-Policy; Caddy adds HSTS.
- **Access codes are the only credential.** Treat them like passwords, give one code per organization, and rotate the code when a participant leaves; rotation also ends that participant's open browser sessions after the restart.
- **Scope:** the sandbox holds no customer data and no production keys; see the [security boundary](README.md#security-boundary). Do not upload real customer or account data into it.
