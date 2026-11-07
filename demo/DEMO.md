# Live demonstration runbook

Twelve to fifteen minutes, six beats, nothing pre-recorded. Every number on
screen is produced live by the running system; the detector output comes from
the real trained models, not from a fixture someone typed.

---

## Before the reviewer arrives

Run this ten minutes early, not during the demo. Each line can fail, and you
want to find that out alone.

```bash
# 1. Software TPM (the client cannot enrol a FIDO2 credential without one)
swtpm socket --tpm2 --tpmstate dir=~/.swtpm/ztna \
  --server type=tcp,port=2321,bindaddr=127.0.0.1 \
  --ctrl type=tcp,port=2322,bindaddr=127.0.0.1 \
  --flags not-need-init,startup-clear &

# 2. The stack
docker compose up -d
docker compose ps          # idp, controller, gateway, resource-node running

# 3. Start from clean telemetry
python3 demo/telemetry.py clean

# 4. Rehearse the whole thing once, end to end
./demo/step 1 && ./demo/step 2
```

If step 2 does not end in `http_status=200`, stop and fix it. Everything
after beat 2 depends on it.

**Have ready in case you are asked:** `SDP_CONTROLLER/policies.yaml`,
`SDP_CONTROLLER/trust_scorer.py`, and `docker-compose.yml` open in an editor.
The three questions that come up are "where is that rule written?", "who
decided the weights?" and "what stops the Controller reaching the data?".

---

## The screen

```bash
./demo/layout.sh
```

Three panes. Gateway logs top-left, Controller logs top-right, and your
driver pane along the bottom. Both log panes are filtered to the lines that
carry the story — an unfiltered log cannot be read at demo speed, and the
three lines that matter would scroll past unseen.

Make the font large. A reviewer reading over your shoulder is the normal
case, and 11pt will cost you the room.

---

## The six beats

### 0 — The system, and the door that is shut · `./demo/step 0`

Shows the four services, then reads the firewall table **out of the running
container** rather than out of a config file.

> "Four services. The Controller is the one that decides, and it sits on its
> own internal network — no published port, no route to the resource. If you
> compromise the thing that makes the decision, you still cannot reach the
> data."

Point at `tcp dport 443 drop`:

> "That is the resource port, and it is DROP, not REJECT. Nothing answers it.
> The line above is conntrack — a session already established keeps flowing."

### 1 — Prove the door is dark · `./demo/step 1`

Connects to the Gateway's 443 from inside the client network, with no knock.

> "A closed port refuses instantly and tells you it exists. Watch this one."

Eight seconds of nothing, then `TIMEOUT`.

> "No RST, no banner, nothing. A port scanner cannot tell this host from an
> unused address. That is the Software Defined Perimeter: the service is
> invisible until you have already authenticated."

### 2 — The full flow · `./demo/step 2`

The headline. Six stages, and the log names each as it happens. Let it run
and narrate against the panes.

What to point at, in order:

| On screen | Say |
| --- | --- |
| `Step 4/6: Signing … with the TPM key (ES256)` | the private key never leaves the chip; this is the TPM signing, not software |
| `Attestation format: tpm` / `Hardware-attested: True` | the IDP made the chip certify its own key, and verified that certificate before enrolling |
| `Knock ticket: 134 bytes` | the IDP's signed statement of who this is **and** what posture it attested |
| `ML-KEM encapsulated … ct_len=1088` | post-quantum key agreement, NIST ML-KEM-768 |
| `[TEE] … 1 secret(s) zeroized` | the shared secret is wiped from memory after use |
| Gateway pane: `SPA knock received` | one UDP packet, and the door is still shut at this instant |
| Controller pane: `Trust score computed … posture=40/60` | the decision is made in a **different process**, reached over mutual TLS |
| Gateway pane: `Firewall rule inserted` | the hole opens only now, pinned to this source, with a lease |
| Gateway pane: `PROXY FORWARD` | TLS is terminated and inspected here, then re-opened to the resource |
| `http_status=200` | and the resource validated the token itself — it does not trust the Gateway |

If asked why the score is 40/60 and not 60: this laptop reports
`disk_encrypted=False antivirus_active=False`. Say so. The score is reading
real posture, which is the point.

### 3 — Compromise the device mid-session · `./demo/step 3`

The beat that distinguishes this from a VPN. It opens a fresh session,
confirms the pinhole is open, then flips the device's telemetry.

> "Nothing about the user is going to change. Same password, same credential,
> the TPM still holds the key, the posture bits are still attested. The only
> thing that changes is what the detectors see."

The flip prints the detector's own output — 100% of flows labelled an attack,
autoencoder agreeing, plus a critical Suricata signature. Then:

> "Re-evaluation runs every ten seconds. It re-scores every live session
> against the evidence as it stands now, not as it stood at admission."

Watch the pinhole count fall to 0, and read the reason out of the log:

```
SESSION CLOSED | reason=re-evaluation: trust=0; DENY by deny-untrusted-device
Re-evaluation complete | checked=1 | revoked=1
```

> "The client did nothing wrong and asked for nothing. Its access was
> withdrawn because the evidence changed. That is the difference between zero
> trust and authenticate-once."

### 4 — Knock again, now quarantined · `./demo/step 4`

Same device, same credential, fresh knock.

> "Watch the posture score. It does not drop."

`posture: 40/60` is unchanged, and the score is still forced to 0:

```
QUARANTINED: critical IDS signature: ET MALWARE Cobalt Strike Beacon Observed
             - score forced to 0 (was 40/100)
```

This is the design argument, and it is worth stating plainly:

> "Posture answers 'is this device well configured?'. The detectors answer
> 'is it compromised right now?'. A weighted sum lets a confident answer to
> the first bury the second — a fully managed laptop scored 60 with an active
> C2 beacon, which cleared the bar. So confirmed compromise is not a
> deduction, it is a disqualifier. Being well patched is no defence against
> already being owned."

Also note what the client saw: silence, not a rejection. An attacker learns
nothing from being refused.

### 5 — Reset · `./demo/step 5`

Back to clean. Run it before anyone else tries the demo.

### 6 — The policy engine · `./demo/step 6`

Optional, and good if they ask about policy rather than cryptography. Eight
scenarios, deny-wins, implicit deny. Edit `SDP_CONTROLLER/policies.yaml` in
another pane, save, re-run — the decision changes with **no restart**,
because the Controller reloads on mtime.

---

## Questions you should expect

**"Is the ML real, or did you hard-code those numbers?"**
Real. `MODELS/trained/` holds the LightGBM and autoencoder from the final
evaluation run. `SDP_CONTROLLER/tests/test_detector.py` replays 1,109 real
flows and requires this code to reproduce what the real LightGBM and real
PyTorch models produced for those same rows — probabilities agree within
1e-6, anomaly flags disagree on 0 of 1,109. Offer to run it.

**"Why is there no torch in the Controller?"**
Deliberate. The Controller is the service whose compromise decides access and
whose job is to answer in milliseconds. The autoencoder is six Linear layers,
20 KB of weights, so it runs as numpy matmuls and the LightGBM trees are
walked directly. The test above is what makes that safe.

**"What is the detection accuracy?"**
Per category, measured, including the weak rows: Normal 0% false positives,
Flood 99%, Brute force 97%, C2 97%, Web attack 97%, **Scan/Recon 28%,
Spoofing/MITM 46%**, and Ransomware — which is *not* in the training
categories — caught 100% by the autoencoder. Volunteer the weak two before
they find them; it is the difference between a result and a sales pitch.

**"Could the Gateway just be told to allow everything?"**
It has no local policy engine left. If the Controller is unreachable, every
knock is DENIED. You can demonstrate it: `docker compose stop sdp-controller`
and run beat 2.

**"What is not finished?"**
Live feature extraction — the detector scores recorded flows, not traffic it
captured. Suricata is not inline here. The TPM is a software one, so
attestation is `pinned-ak` rather than vendor-rooted. Say these before you
are asked.

---

## If something breaks

| Symptom | Cause | Fix |
| --- | --- | --- |
| Client aborts at `[1/6]` | no `CLIENT_USERNAME`/`CLIENT_PASSWORD` in `.env` | set them, or pass `--username/--password` |
| `TPM ATTESTATION FAILED` | swtpm is not running | restart it (see above), check `ss -ltn \| grep 2321` |
| Knock sent, no reply | Controller is down, or telemetry says compromised | `docker compose ps`; `python3 demo/telemetry.py show` |
| `TLS handshake timed out` after `SPA_OK` | the lease expired before the request | the TTL is `CONTROLLER_TTL_SECONDS` in `.env`, 120s for the demo |
| Beat 3 never revokes | telemetry did not change, or the Controller did not reload | `python3 demo/telemetry.py show`, then check the Controller pane for `Telemetry snapshot loaded` |

Worst case, the whole thing resets in under a minute:

```bash
docker compose down && docker compose up -d && python3 demo/telemetry.py clean
```
