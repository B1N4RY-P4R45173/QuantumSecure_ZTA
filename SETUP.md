# Setup, from a fresh clone, on both laptops

Two machines, three roles.

| | Ajay's laptop | Abhinav's laptop |
| --- | --- | --- |
| **Docker** | Controller, resource node | IDP, Gateway (in WSL) |
| **Native** | — | client agent, on Windows, for Windows Hello |

The client is native on Windows deliberately: a container has no route to the
TPM, and Windows Hello is the only backend on Windows that can produce a
WebAuthn attestation. Everything else is a container.

Work through this in order. Section 3 (certificates) happens on Ajay's
laptop only, and section 4 copies the results across — doing it the other way
round produces certificates for the wrong names and a handshake failure that
looks like a policy denial.

---

## 0. Both laptops — clone and fill in the addresses

```bash
git clone <repo-url> ztna
cd ztna
cp .env.example .env
```

Find both LAN addresses:

```bash
hostname -I | awk '{print $1}'                 # Linux / WSL
```
```powershell
(Get-NetIPAddress -AddressFamily IPv4 |
  Where-Object {$_.PrefixOrigin -ne 'WellKnown'}).IPAddress   # Windows
```

Put the same two values in `.env` on **both** laptops:

```ini
AJAY_IP=192.168.1.50        # where the Controller and resource run
ABHINAV_IP=192.168.1.10     # where the IDP and Gateway run
```

Check they can see each other before going further — everything below
assumes it:

```bash
ping -c2 $AJAY_IP           # from Abhinav
ping -c2 $ABHINAV_IP        # from Ajay
```

---

## 1. Both laptops — prerequisites

Docker and Compose on both. On Abhinav's, Docker runs inside WSL2 (or Docker
Desktop with WSL integration on).

```bash
docker --version && docker compose version
```

Each component has its own virtual environment, because they have genuinely
different dependency sets and one shared env would drag the IDP's WebAuthn
stack onto the resource node.

**Ajay's laptop** needs two:

```bash
cd ~/ztna
for c in SDP_CONTROLLER resource-node; do
  python3 -m venv "$c/.venv"
  "$c/.venv/bin/pip" install -q -r "$c/requirements.txt"
done
```

**Abhinav's laptop (WSL)** needs three:

```bash
cd ~/ztna
for c in IDENTITY_PROVIDER SDP_GATEWAY SDP_CLIENT; do
  python3 -m venv "$c/.venv"
  "$c/.venv/bin/pip" install -q -r "$c/requirements.txt"
done
```

The containers build their own dependencies; these venvs are for the admin
CLI, the tests and the stepwise client.

---

## 2. Abhinav's laptop — the software TPM is NOT needed

Skip `swtpm` entirely. The client runs on Windows and uses Windows Hello,
which drives the real TPM and returns a genuine attestation — a strictly
better trust anchor than the software TPM (`vendor-root` rather than
`pinned-ak`).

What is needed, on Windows: a Hello PIN, under **Settings → Accounts →
Sign-in options**. Without one the client falls back to CNG, which cannot
attest, and the IDP will refuse to enrol the device. That refusal is correct
behaviour, not a bug to work around.

---

## 3. Abhinav's laptop — the certificates

One CA signs for the whole deployment. It lives here and `root.key` never
leaves this machine.

```bash
cd ~/ztna/IDENTITY_PROVIDER
source .venv/bin/activate
set -a; source ../.env; set +a        # so $AJAY_IP / $ABHINAV_IP expand below

python admin_cli.py init-ca

# The IDP: reached by the client (localhost) and by the Gateway (container)
python admin_cli.py issue-idp-cert \
    --host sdp-idp --host host.docker.internal \
    --host localhost --host "$ABHINAV_IP"

# The Gateway's own identity. It presents this to the IDP, to the Controller,
# and to the resource.
python admin_cli.py issue-gateway-cert --id gw-1

# What the Gateway presents to the client. The client is on the same machine,
# so it dials 127.0.0.1.
python admin_cli.py issue-proxy-cert --id gw-1 --host localhost

# The Controller and the resource, both on Ajay's laptop
python admin_cli.py issue-controller-cert --host "$AJAY_IP"
python admin_cli.py issue-resource-cert   --host "$AJAY_IP"

# Put the Gateway's bundle where its compose file looks for it
mkdir -p ../SDP_GATEWAY/certs/pki
cp certs/pki/gateways/gw-1/* ../SDP_GATEWAY/certs/pki/
```

Create the account while you are here:

```bash
python admin_cli.py create-user --username abhinav --roles employee
```

---

## 3a. Abhinav's laptop — start the IDP, so it mints its signing key

`admin_cli.py` does NOT create `idp_jwt_public.pem`. That is the RS256 key
the IDP signs access tokens with, and it is generated the first time the IDP
process itself starts — so it does not exist until the IDP has run once, and
there is nothing to copy to Ajay before then.

```bash
cd ~/ztna
docker compose -f deploy/abhinav/docker-compose.yml --env-file .env up -d --build sdp-idp
```

The container writes it through the bind mount, so it lands on the host:

```bash
ls -l IDENTITY_PROVIDER/certs/idp_jwt_public.pem      # must exist before section 4
```

No Docker, or you want it without starting anything:

```bash
cd ~/ztna/IDENTITY_PROVIDER
./.venv/bin/python -c "import sys; sys.path[:0]=['.','..']; \
from tokens import jwt_service; jwt_service.init()"
```

Either way you end up with two files in `IDENTITY_PROVIDER/certs/`:
`idp_jwt_private.pem`, which never leaves this machine, and
`idp_jwt_public.pem`, which Ajay needs.

There is a second pair, `idp_ticket_*`, for the ES256 knock tickets. Nobody
copies that one: the Gateway fetches the public half from the IDP's JWKS
over the mTLS link, so it is never pinned to a file.

---

## 4. Abhinav → Ajay: copy three bundles

```bash
cd ~/ztna/IDENTITY_PROVIDER

ssh ajay@$AJAY_IP 'mkdir -p ~/ztna/SDP_CONTROLLER/certs/pki ~/ztna/resource-node/certs/pki'

scp certs/pki/controller/*   ajay@$AJAY_IP:~/ztna/SDP_CONTROLLER/certs/pki/
scp certs/pki/resource/*     ajay@$AJAY_IP:~/ztna/resource-node/certs/pki/
scp certs/idp_jwt_public.pem ajay@$AJAY_IP:~/ztna/IDENTITY_PROVIDER/certs/
```

A USB stick does just as well; nothing in the system uses SSH at runtime.

Two of those are private keys — `controller.key` and `resource.key`. A holder
of `controller.key` can answer APPROVED to any Gateway that trusts this CA.

`idp_jwt_public.pem` is the IDP's **public** key, and handing it to the most
exposed component is safe precisely because a copy mints no tokens. It is
how the resource validates tokens offline with no route to the IDP.

---

## 5. Ajay's laptop — start the Controller and the resource

```bash
cd ~/ztna
docker compose -f deploy/ajay/docker-compose.yml --env-file .env up -d --build
docker compose -f deploy/ajay/docker-compose.yml ps
```

Check both are demanding certificates:

```bash
docker logs sdp-controller | grep -iE 'client_certificates|serving'
docker logs resource-node  | grep -iE 'Transport|Listener bound'
```

Expected:

```
client_certificates=required, project CA only
Transport: HTTPS, and a Gateway certificate is REQUIRED (mutual TLS, project CA)
```

> **If the resource says `plain HTTP`, stop.** `RESOURCE_TLS` did not reach
> the container, and the Gateway→resource leg would cross the LAN carrying
> the client's bearer token in the clear. On one machine that leg is
> cleartext on purpose; across two it must not be.

---

## 6. Abhinav's laptop — start the Gateway

The IDP is already up from section 3a; this brings up the rest.

```bash
cd ~/ztna
docker compose -f deploy/abhinav/docker-compose.yml --env-file .env up -d --build
docker compose -f deploy/abhinav/docker-compose.yml ps
```

```bash
docker logs sdp-gateway | grep -iE 'Controller:|Firewall backend|Inner leg|proxy started'
```

Expected: `Controller: REMOTE` with Ajay's address, `enforcing=True`, and
`Inner leg: HTTPS to the resource`.

If it says the Controller is unreachable, check from here:

```bash
nc -vz $AJAY_IP 9500      # Controller
nc -vz $AJAY_IP 7443      # resource
```

---

## 7. Abhinav's laptop, Windows side — the client

In **PowerShell**, not WSL:

```powershell
cd C:\path\to\ztna\SDP_CLIENT
py -m venv .venv-win
.\.venv-win\Scripts\pip install -r requirements.txt
```

Create `.env` in the repo root on the Windows side with:

```ini
IDP_BASE_URL=http://localhost:9000
GATEWAY_IP=127.0.0.1
RP_ID=ztna.example.com
CLIENT_ACCESS_PORT=443
CLIENT_ACCESS_PROTOCOL=tcp
```

`localhost` works because WSL2 forwards Windows' loopback into the distro,
where both ports are published. `RP_ID` must match the IDP exactly — it is
what the credential is bound to, and changing it invalidates every enrolment.

---

## 8. Run it, one stage at a time

Three terminals open, then drive from Windows.

**Ajay — Controller:**
```bash
docker logs -f sdp-controller 2>&1 | grep --line-buffered -E 'trust|QUARANT|DENIED|APPROVED|Decision'
```

**Ajay — resource:**
```bash
docker logs -f resource-node
```

**Abhinav, WSL — Gateway:**
```bash
docker logs -f sdp-gateway 2>&1 | grep --line-buffered -E 'SPA|Firewall|SESSION|Controller|PROXY'
```

**Abhinav, Windows — the client:**

```powershell
.\.venv-win\Scripts\python ..\demo\ztna.py login
```

Windows Hello prompts for your PIN, face or fingerprint. That is CTAP2
talking to the platform authenticator; the private key is generated inside
the TPM and cannot be exported. Expect `Attestation format: tpm` and
`Hardware-attested: True`.

**Now, before knocking**, on Abhinav's WSL:

```bash
docker exec sdp-gateway nft list table inet sdp_spa
```

Fully authenticated, hardware-attested, holding a valid token — and the
firewall is unchanged. **Authentication opened nothing.**

```powershell
.\.venv-win\Scripts\python ..\demo\ztna.py knock
```

| Watch | What appears |
| --- | --- |
| Abhinav, Gateway | `SPA knock received`, `forwarding to Controller`, `Firewall rule inserted` |
| Ajay, Controller | `Trust score computed`, `APPROVED`, `acl=LIMITED` |

One UDP packet crossed to another machine, a different computer decided, and
only then did a hole open.

```powershell
.\.venv-win\Scripts\python ..\demo\ztna.py connect
```

| Watch | What appears |
| --- | --- |
| Abhinav, Gateway | `PROXY FORWARD ... resource=<ajay>:7443` |
| Ajay, resource | the served request |
| Windows | `HTTP 200` and the resource's body |

---

## 9. The live revocation

On **Ajay's** laptop, because the Controller owns the evidence. First find
the address the Gateway dials from, in its own log (`client_ip=` on the
knock), then:

```bash
cd ~/ztna
python3 demo/telemetry.py compromised --ip <that address>
```

Within ten seconds the Controller re-scores and revokes. On Abhinav's:

```bash
docker exec sdp-gateway nft list table inet sdp_spa     # the rule is gone
```

From Windows, with the same still-valid token:

```powershell
.\.venv-win\Scripts\python ..\demo\ztna.py connect      # fails
.\.venv-win\Scripts\python ..\demo\ztna.py knock        # silence, not a refusal
```

Reset on Ajay's:

```bash
python3 demo/telemetry.py clean --ip <that address>
```

---

## 10. Tests

**Ajay:**
```bash
cd ~/ztna/SDP_CONTROLLER && python3 -m pytest tests -q
```

**Abhinav (WSL):**
```bash
cd ~/ztna
for c in SDP_GATEWAY IDENTITY_PROVIDER SDP_CLIENT; do
  (cd "$c" && ./.venv/bin/pytest tests -q)
done
```

228 pass in total. The one worth running in front of a reviewer who doubts
the ML is real:

```bash
cd ~/ztna/SDP_CONTROLLER && python3 -m pytest tests/test_detector.py -q
```

It replays 1,109 real flows and requires the numpy detector to reproduce what
the real LightGBM and real PyTorch models produced for those same rows.

---

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| Gateway: `Controller unreachable` | `AJAY_IP` wrong, 9500 blocked, or Ajay's stack down |
| Gateway: TLS error to the Controller | the Controller cert lacks `AJAY_IP`. Re-issue with `--host $AJAY_IP`, copy again |
| Gateway: `RESOURCE_TLS is on but the bundle is unusable` | `gw-1`'s bundle missing from `SDP_GATEWAY/certs/pki/` |
| Resource: `Transport: plain HTTP` | `RESOURCE_TLS` did not reach it — tokens would cross the LAN in clear |
| Resource refuses the Gateway | `gateway.crt` not signed by the CA in the resource's `ca.crt`. One CA for everything |
| Windows: `No Windows Hello platform authenticator` | no Hello PIN, or no usable TPM |
| Windows: `Hello returned NO attestation` | no TPM, so Hello used software. The IDP refuses it, correctly |
| Windows: cannot reach the IDP | check `docker port sdp-idp` in WSL; WSL2 localhost forwarding may be off |
| Knock accepted, `connect` times out | lease expired (`CONTROLLER_TTL_SECONDS`) or revoked. Read Ajay's Controller log |
| `ztna knock` silent, nothing obviously wrong | that IS the design. The reason is on the Controller, never on the wire |

Full reset, either machine:

```bash
docker compose -f deploy/<host>/docker-compose.yml down
docker compose -f deploy/<host>/docker-compose.yml --env-file .env up -d
```
