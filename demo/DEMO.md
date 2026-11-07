# Live demonstration runbook

Everything below is typed by hand. There is no script that runs the demo —
`demo/step` exists only as a rehearsal aid, and the real demonstration is the
commands in this file, entered one at a time, with the server-side logs
visible beside them.

The client is `demo/ztna`, which exposes one stage per command. It calls the
same modules `SDP_CLIENT/main.py` calls — `fido2_agent.client`,
`spa.token_flow`, `dataplane.session` — so nothing here is a demo-only code
path. If `ztna` worked and `main.py` did not, the demonstration would be a
lie.

---

## Before the reviewer arrives

```bash
# 1. Software TPM. Without it the client cannot sign a FIDO2 assertion.
swtpm socket --tpm2 --tpmstate dir=~/.swtpm/ztna \
  --server type=tcp,port=2321,bindaddr=127.0.0.1 \
  --ctrl type=tcp,port=2322,bindaddr=127.0.0.1 \
  --flags not-need-init,startup-clear &

# 2. The stack
docker compose up -d && docker compose ps

# 3. Clean telemetry to start from
python3 demo/telemetry.py clean

# 4. Rehearse once, end to end
./demo/ztna logout && ./demo/ztna login && ./demo/ztna knock && ./demo/ztna connect
```

If step 4 does not end in `HTTP 200`, stop and fix it before anything else.

Then **log out again** so the demo starts from nothing:

```bash
./demo/ztna logout
```

---

## The screen

```bash
./demo/layout.sh
```

Gateway logs top-left, Controller logs top-right, and your shell along the
bottom. Both log panes are filtered — an unfiltered log cannot be read at
demo speed, and the three lines that matter scroll past unseen.

Large font. Someone is reading over your shoulder.

---

## Act 1 — The door is shut

**Show the services, and read the firewall out of the running container:**

```bash
docker compose ps
docker exec sdp-gateway nft list table inet sdp_spa
```

> "Four services. The Controller is the one that decides, and it is on its
> own internal network — no published port, no route to the resource. If you
> compromise the thing that makes the decision, you still cannot reach the
> data."

Point at `tcp dport 443 drop`:

> "That is the resource port. DROP, not REJECT — nothing answers it. The line
> above is conntrack, so a session already established keeps flowing."

**Now prove it is dark.** A closed port refuses instantly; this one says
nothing:

```bash
docker run --rm --network client-net python:3.12-slim \
  python -c "import socket,time; s=socket.socket(); s.settimeout(8); t=time.time()
try:
    s.connect(('sdp-gateway',443)); print('REACHED')
except socket.timeout: print(f'TIMEOUT after {time.time()-t:.1f}s')
except ConnectionRefusedError: print('REFUSED')"
```

> "No RST, no banner, nothing. A port scanner cannot tell this host from an
> unused address."

---

## Act 2 — Identity, before anything is open

```bash
./demo/ztna login
```

This is three stages, and the output labels each. Narrate against it:

**First factor.** 
> "The password alone proves nothing — it buys a short-lived `login_token`
> that only authorises the FIDO2 ceremony."

**Hardware trust anchor.** 
> "No software fallback. If there is no anchor, the client aborts rather than
> identifying itself with a key that could be copied."

**Posture.** `os_patch_days`, `disk_encrypted`, `antivirus_active`.
> "This is a report, not a verdict. The client never scores itself. The IDP
> decides which bits the report earns, adds the three it attests itself, and
> signs all six into the knock ticket."

**FIDO2 ceremony.** Point at `Signing ... with the TPM key (ES256)` in the log.
> "The private key never leaves the chip. On first enrolment the TPM
> *certifies* its own key and the IDP verifies that certificate before it
> will enrol the credential."

Then the summary: `hardware attested True`, `amr ['pwd','fido2','hwattest']`,
`knock ticket 134 bytes`, `gateway ML-KEM key 1184 bytes`.

**The point to land:**

```bash
docker exec sdp-gateway nft list table inet sdp_spa
```

> "Fully authenticated, hardware-attested, holding a valid token — and the
> firewall is unchanged. Authentication did not open anything."

---

## Act 3 — One packet opens the door

```bash
./demo/ztna knock
```

> "One UDP packet. Inside it: the 134-byte ticket the IDP signed, sealed with
> ML-KEM-768 — post-quantum key agreement — then HKDF and AES-256-GCM."

Watch the **Gateway pane** as it arrives:

```
SPA knock received       | client_ip=172.18.0.1
SPA knock verified - forwarding to Controller | posture=device_managed,os_patched,known_device
```

> "The Gateway checked the IDP's signature and read the posture bits out of
> the ticket. It does not decide anything. It forwards to the Controller,
> over mutual TLS, on a network nothing else can reach."

Watch the **Controller pane**:

```
Trust score computed | score=59/100 | posture=40/60 | suricata=12/25 | ml=7/15
APPROVED             | acl=LIMITED  | hosts=resource-node | ttl=120s
```

> "Posture 40 of 60, because this laptop reports no disk encryption and no
> antivirus — the score is reading real posture. The detectors have no
> telemetry for this device yet, so they get half credit: 'we did not look'
> is penalised, but it is not evidence of attack."

Back in the Gateway pane:

```
Firewall rule inserted | src_ip=172.18.0.1 | port=443
SESSION OPEN           | acl=LIMITED | ttl=120s
```

**Show the hole that just appeared:**

```bash
docker exec sdp-gateway nft list table inet sdp_spa
```

> "One rule, pinned to this source address, with a lease. Nobody else gained
> anything."

---

## Act 4 — The secure connection

```bash
./demo/ztna connect
```

> "SPA_OK only proved a pinhole exists. This proves access."

```
Data path established | tls=TLSv1.3 | cipher=TLS_AES_256_GCM_SHA384 | peer_cn=sdp-gateway
HTTP 200 in 5.8 ms
body  {"resource": "resource-node", "subject": "4e3dd94d-..."}
```

Gateway pane: `PROXY FORWARD ... resource=resource-node:7443`.

> "The Gateway terminated that TLS, inspected the request, and opened a
> *separate* connection to the resource. It is an inspection point, not a
> tunnel. And the resource validated the token itself — it has no route to
> the IDP, so it checks the signature offline. It does not trust the
> Gateway."

Optionally show the claims the resource verified:

```bash
./demo/ztna whoami
```

---

## Act 5 — The device is compromised, mid-session

This is the beat that separates this from a VPN.

> "Nothing about the user is going to change. Same password, same credential,
> the TPM still holds the key, the posture bits are still attested. Only the
> evidence about the device changes."

```bash
python3 demo/telemetry.py compromised
```

The output is the detector's own, not typed in: 100% of flows labelled an
attack, the autoencoder agreeing, plus a critical Suricata signature.

> "Re-evaluation runs every ten seconds, re-scoring every live session
> against the evidence as it stands now — not as it stood at admission."

Watch the Controller pane, then:

```bash
docker exec sdp-gateway nft list table inet sdp_spa
```

The pinhole is gone. The reason is in the log:

```
SESSION CLOSED | reason=re-evaluation: trust=0; DENY by deny-untrusted-device
Re-evaluation complete | checked=1 | revoked=1
```

> "The client did nothing wrong and asked for nothing. Access was withdrawn
> because the evidence changed."

**Prove it from the client side:**

```bash
./demo/ztna connect
```

It fails now — same token, same session, no route.

---

## Act 6 — Knock again, now quarantined

```bash
./demo/ztna knock
```

Client side: silence, not a rejection.

> "Note what the client sees. Not 'denied' — nothing. An unaccepted knock is
> dropped, so an attacker learns nothing from being turned away, not even
> that anything is here. Why it was refused is on the Controller, not on the
> wire."

Controller pane:

```
trust | posture:  40/60
trust | suricata: 0/25   (5 alert(s) incl. critical)
trust | ml:       0/15   (anomaly_rate=1.00, top=Web attack)
trust | QUARANTINED: critical IDS signature: ET MALWARE Cobalt Strike Beacon
        Observed - score forced to 0 (was 40/100)
```

> "Watch the posture line. It did **not** drop — it is still 40 of 60,
> exactly what it was when this device was let in. The score was not averaged
> down, it was overridden."

The design argument, worth stating in full:

> "Posture answers 'is this device well configured?'. The detectors answer
> 'is it compromised right now?'. A weighted sum lets a confident answer to
> the first bury the second — posture is 60 of 100, so a fully managed laptop
> scored 60 with an active C2 beacon, which clears the bar to get in. So
> confirmed compromise is not a deduction, it is a disqualifier. Being well
> patched is no defence against already being owned."

**Reset:**

```bash
python3 demo/telemetry.py clean
```

---

## Optional closers

**Fail closed.** Ask what happens if the Controller dies:

```bash
docker compose stop sdp-controller
./demo/ztna knock          # denied: "no decision from the Controller"
docker compose up -d sdp-controller
```

> "The Gateway has no local policy engine left to fall back on. No decision
> is not an approval."

**Policy, edited live.** Open `SDP_CONTROLLER/policies.yaml` in another pane,
change a threshold, save, and re-run — the Controller reloads on mtime, no
restart:

```bash
cd SDP_CONTROLLER && python3 demo.py
```

---

## Questions you should expect

**"Is the ML real, or are those numbers hard-coded?"**
Real. `MODELS/trained/` holds the LightGBM and autoencoder from the final
evaluation run. Offer to run the proof:

```bash
cd SDP_CONTROLLER && python3 -m pytest tests/test_detector.py -q
```

It replays 1,109 real flows and requires this code to reproduce what the real
LightGBM and real PyTorch models produced for those same rows — probabilities
within 1e-6, anomaly flags disagreeing on 0 of 1,109.

**"Why is there no PyTorch in the Controller?"**
Deliberate. It is the service whose compromise decides access and whose job
is to answer in milliseconds. The autoencoder is six Linear layers, 20 KB of
weights, so it runs as numpy matmuls and the LightGBM trees are walked
directly. The test above is what makes that safe.

**"What is the detection accuracy?"**
Per category, measured: Normal 0% false positives, Flood 99%, Brute force
97%, C2 97%, Web attack 97%, **Scan/Recon 28%, Spoofing/MITM 46%**, and
Ransomware — *not* in the training categories — caught 100% by the
autoencoder. Volunteer the weak two before they find them.

**"What is not finished?"**
Live feature extraction: the detector scores recorded flows, not traffic it
captured. Suricata is not inline here. The TPM is a software one, so
attestation is `pinned-ak` rather than vendor-rooted. Say these unprompted.

---

## If something breaks

| Symptom | Cause | Fix |
| --- | --- | --- |
| `No session. Run: ztna login` | state file cleared | `./demo/ztna login` |
| Login aborts at first factor | no credentials | `CLIENT_USERNAME`/`CLIENT_PASSWORD` in `.env` |
| `no hardware trust anchor` | swtpm not running | restart it; `ss -ltn \| grep 2321` |
| Knock gets no reply | denied, or Controller down | read the Controller pane; `docker compose ps` |
| `connect` fails after `SPA_OK` | lease expired or revoked | `./demo/ztna knock` again; TTL is `CONTROLLER_TTL_SECONDS` |
| Edited a file, Controller ignores it | — | should not happen: the inputs are a directory mount, so a replaced file is picked up. If it recurs, `docker compose up -d --force-recreate sdp-controller` |

Full reset in under a minute:

```bash
docker compose down && docker compose up -d
python3 demo/telemetry.py clean && ./demo/ztna logout
```
