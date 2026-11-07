# Two-machine deployment

| Where | What runs | How |
| --- | --- | --- |
| **Abhinav — Windows** | Client agent, FIDO2/WebAuthn over CTAP2 with Windows Hello | native, not a container |
| **Abhinav — Docker in WSL** | Identity Provider, Gateway | `deploy/abhinav/docker-compose.yml` |
| **Ajay — Docker** | Controller, resource node | `deploy/ajay/docker-compose.yml` |

Read this section before the rest, because it changes something real.

## What splitting the hosts costs, and what pays for it

On one machine the Controller and the resource sit on `internal: true` Docker
networks. They have no route off those networks and no published port, so
most of their protection is topological — you cannot reach them to attack
them. Across two machines that is gone: both listen on the LAN.

Two things replace it, and both are mandatory here where they are nearly
optional on one host.

**Every link is mutual TLS, against this project's CA.** Reaching the
Controller's port buys nothing without a Gateway certificate the CA signed;
the same is now true of the resource. That is why the certificate step below
is not something to skip and come back to.

**The inner leg is no longer cleartext.** On one host the Gateway forwards to
the resource in plain HTTP on purpose — the resource is unreachable from
anywhere else, so a second TLS session would buy nothing but a certificate to
rotate. Between two machines that leg crosses the LAN *carrying the client's
bearer token*, so `RESOURCE_TLS=1` is set on both sides and the resource
demands a Gateway certificate. If the flag is set and the bundle is bad, both
sides refuse to start rather than fall back to plaintext.

Direction of travel is unchanged and still worth pointing at: **the Gateway
dials out to everything, and nothing ever dials the Gateway.** Ajay's PC
needs no route back to Abhinav's, and Abhinav's firewall needs no inbound
rule for Ajay.

---

## 0. Addresses

Find both machines' LAN addresses and put them in `.env` **on both machines**:

```bash
# Abhinav (WSL)
ip -4 addr show eth0 | grep -oP 'inet \K[\d.]+'      # may be the WSL address
# On Windows, the address Ajay must reach:
#   PowerShell:  (Get-NetIPAddress -AddressFamily IPv4).IPAddress
```

```ini
# .env, on BOTH machines — same values
ABHINAV_IP=192.168.1.10
AJAY_IP=192.168.1.50
```

`AJAY_IP` is required by Abhinav's compose file and it will refuse to start
without it, rather than silently defaulting to a container name that does not
resolve across machines.

> **WSL note.** WSL2 has its own NAT, so a port published inside WSL is not
> automatically reachable from another machine. It does not need to be here:
> nothing dials the Gateway except the Windows client on the same box, and
> WSL2 forwards Windows' `localhost` into the distro. If you later need Ajay
> to reach the Gateway, that is when you need `netsh interface portproxy`.

---

## 1. Certificates — on Abhinav's machine only

The CA lives wherever you create it and signs for the whole deployment. Keep
`root.key` on this machine; nothing else ever needs it.

```bash
cd IDENTITY_PROVIDER

./.venv/bin/python admin_cli.py init-ca

# The IDP, reached by the client and by the Gateway
./.venv/bin/python admin_cli.py issue-idp-cert \
    --host sdp-idp --host host.docker.internal \
    --host localhost --host ${ABHINAV_IP}

# The Gateway's own identity. It presents this to the IDP, to the
# Controller, and now to the resource as well.
./.venv/bin/python admin_cli.py issue-gateway-cert --id gw-1

# What the Gateway presents to the client. The client dials 127.0.0.1,
# because it is on the same machine.
./.venv/bin/python admin_cli.py issue-proxy-cert --id gw-1 --host localhost

# The Controller, on Ajay's machine
./.venv/bin/python admin_cli.py issue-controller-cert --host ${AJAY_IP}

# The resource, also on Ajay's machine
./.venv/bin/python admin_cli.py issue-resource-cert --host ${AJAY_IP}
```

Put the Gateway's bundle where its compose file expects it:

```bash
mkdir -p ../SDP_GATEWAY/certs/pki
cp certs/pki/gateways/gw-1/* ../SDP_GATEWAY/certs/pki/
```

### First, start the IDP once

`admin_cli.py` does not create `idp_jwt_public.pem`. That key is minted by
the IDP process on its first start, so it does not exist yet and there is
nothing to copy:

```bash
cd ..
docker compose -f deploy/abhinav/docker-compose.yml --env-file .env up -d --build sdp-idp
ls -l IDENTITY_PROVIDER/certs/idp_jwt_public.pem
cd IDENTITY_PROVIDER
```

Without Docker: `./.venv/bin/python -c "import sys; sys.path[:0]=['.','..'];
from tokens import jwt_service; jwt_service.init()"`

### Copy to Ajay

Four things travel, and only one is sensitive in the usual sense:

```bash
scp -r certs/pki/controller/*          ajay@${AJAY_IP}:~/ztna/SDP_CONTROLLER/certs/pki/
scp -r certs/pki/resource/*            ajay@${AJAY_IP}:~/ztna/resource-node/certs/pki/
scp certs/idp_jwt_public.pem           ajay@${AJAY_IP}:~/ztna/IDENTITY_PROVIDER/certs/
```

`idp_jwt_public.pem` is the IDP's **public** key. A copy mints no tokens —
that asymmetry is what makes it safe to hand to the most exposed component,
and it is how the resource validates tokens offline with no route to the IDP.

`controller.key` and `resource.key` are private. A holder of `controller.key`
can answer APPROVED to any Gateway that trusts this CA.

---

## 2. Ajay's PC — Controller and resource

```bash
cd ~/ztna
docker compose -f deploy/ajay/docker-compose.yml --env-file .env up -d
docker compose -f deploy/ajay/docker-compose.yml ps
```

Confirm both came up and are demanding certificates:

```bash
docker logs sdp-controller | grep -iE 'client_certificates|serving'
docker logs resource-node  | grep -iE 'Transport|Listener bound'
```

You want to see `client_certificates=required, project CA only` and
`https (mutual TLS, project CA)`. If the resource says `plain HTTP`,
`RESOURCE_TLS` did not reach it and the inner leg would cross the LAN in the
clear — stop and fix that before going further.

Check from Abhinav's machine that both ports answer:

```bash
nc -vz ${AJAY_IP} 9500        # Controller
nc -vz ${AJAY_IP} 7443        # resource
```

---

## 3. Abhinav's PC — IDP and Gateway

```bash
cd ~/ztna
docker compose -f deploy/abhinav/docker-compose.yml --env-file .env up -d
docker compose -f deploy/abhinav/docker-compose.yml ps
```

Confirm the Gateway found the remote Controller and is enforcing:

```bash
docker logs sdp-gateway | grep -iE 'Controller:|Firewall backend|Inner leg|proxy started'
```

You want `Controller: REMOTE`, the URL pointing at `AJAY_IP`,
`enforcing=True`, and `Inner leg: HTTPS to the resource`.

Create the account, once:

```bash
cd IDENTITY_PROVIDER
./.venv/bin/python admin_cli.py create-user --username abhinav --roles employee
```

---

## 4. Abhinav's PC, Windows — the client

Run this **on Windows**, not in WSL: WSL cannot reach Windows Hello, and
Hello is the only backend on Windows that can produce an attestation.

**Prerequisites.** A Hello PIN under *Settings → Accounts → Sign-in options*.
Without one the client falls back to CNG, which cannot attest, and the IDP
will refuse to enrol the device — correctly.

```powershell
cd C:\path\to\ztna\SDP_CLIENT
py -m venv .venv-win
.\.venv-win\Scripts\pip install -r requirements.txt
```

`.env` on Windows needs the IDP and Gateway on localhost, because both are
published from WSL and WSL2 forwards Windows' localhost into the distro:

```ini
IDP_BASE_URL=http://localhost:9000
GATEWAY_IP=127.0.0.1
RP_ID=ztna.example.com
```

`RP_ID` must match the IDP exactly. It is the relying party the credential is
bound to, and changing it invalidates every enrolled credential.

Then run the stages by hand:

```powershell
.\.venv-win\Scripts\python ..\demo\ztna.py login
.\.venv-win\Scripts\python ..\demo\ztna.py knock
.\.venv-win\Scripts\python ..\demo\ztna.py connect
```

`login` will raise a Windows Hello prompt — PIN, fingerprint or face. That
prompt is CTAP2 talking to the platform authenticator, and the private key it
uses is generated inside the TPM and cannot be exported.

Expect `Attestation format: tpm` and `Hardware-attested: True`. On real
hardware with Microsoft's roots loaded this is `vendor-root` — genuine
silicon proven, which a software TPM cannot give you.

---

## What to watch, and where

Three terminals, one per role. This is the demonstration.

**Abhinav, WSL — the Gateway:**

```bash
docker logs -f sdp-gateway 2>&1 | grep --line-buffered -E 'SPA|Firewall|SESSION|Controller|PROXY'
```

**Ajay — the Controller:**

```bash
docker logs -f sdp-controller 2>&1 | grep --line-buffered -E 'trust|QUARANT|DENIED|APPROVED|Decision'
```

**Ajay — the resource:**

```bash
docker logs -f resource-node
```

Then, on Windows, run `login`, `knock`, `connect` one at a time and narrate:

| Command | Abhinav's Gateway shows | Ajay shows |
| --- | --- | --- |
| `login` | nothing — and that is the point | nothing |
| `knock` | `SPA knock received`, `forwarding to Controller`, `Firewall rule inserted` | Controller: `Trust score computed`, `APPROVED` |
| `connect` | `PROXY FORWARD` | resource: a served request |

After `login`, before `knock`, run this on Abhinav's machine:

```bash
docker exec sdp-gateway nft list table inet sdp_spa
```

The client is fully authenticated, hardware-attested, holding a valid token —
and the firewall is unchanged. **Authentication opened nothing.** One machine
authenticated the user; a different machine, across the network, decided
whether that user gets a hole; and only then did a third machine serve the
data.

### Compromise, live

On **Ajay's** machine, because the Controller owns the evidence:

```bash
python3 demo/telemetry.py compromised --ip <the IP the Gateway dials from>
```

Find that IP in the Gateway's log (`client_ip=` on the knock). Within ten
seconds the Controller revokes, and on Abhinav's machine the pinhole is gone:

```bash
docker exec sdp-gateway nft list table inet sdp_spa
```

Then from Windows, `ztna connect` fails with the same valid token, and
`ztna knock` is met with silence.

---

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| Gateway: `Controller unreachable` | `AJAY_IP` wrong, port 9500 blocked, or Ajay's stack down. `nc -vz ${AJAY_IP} 9500` |
| Gateway: TLS error dialling the Controller | the Controller certificate does not carry `AJAY_IP`. Re-issue with `--host ${AJAY_IP}` and copy it over |
| Gateway: `RESOURCE_TLS is on but the bundle is unusable` | `gw-1`'s bundle is not in `SDP_GATEWAY/certs/pki/` |
| Resource: `Transport: plain HTTP` | `RESOURCE_TLS` did not reach the container — the inner leg would be cleartext across the LAN. Fix before demonstrating |
| Resource refuses the Gateway | the Gateway's `gateway.crt` is not signed by the CA in the resource's `ca.crt`. One CA for the whole deployment |
| Windows: `No Windows Hello platform authenticator` | no Hello PIN set, or no usable TPM |
| Windows: `Hello returned NO attestation` | no TPM, so Hello stored the key in software. The IDP refuses it, correctly |
| Windows: client cannot reach the IDP | WSL2 localhost forwarding is not working. Check the IDP is published: `docker port sdp-idp` |
| Knock accepted, `connect` times out | the lease expired (`CONTROLLER_TTL_SECONDS`), or re-evaluation revoked it. Read Ajay's Controller log |
