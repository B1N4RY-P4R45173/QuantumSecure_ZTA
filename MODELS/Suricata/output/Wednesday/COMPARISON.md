# XGBoost vs Suricata — CIC-IDS2017 Wednesday

Test flows: 191,148 (13,507 attack). Suricata: This is Suricata version 8.0.7 RELEASE, rules `/var/lib/suricata/rules/suricata.rules`, runmode single, HOME_NET `[192.168.10.0/24]`. Time offset UTC→CSV: -3 h. Flows with any alert (all splits): 341,187.

## 1. Detection (attack vs benign)

| Detector | Detection rate | False positive rate | Precision | F1 | Attack bursts detected | Median attack flows before alert |
|---|---|---|---|---|---|---|
| SURICATA_ALL | 78.63% | 21.22% | 21.98% | 0.3436 | 67.61% | 0.0 |
| SURICATA_THREATS | 0.04% | 0.08% | 3.57% | 0.0007 | 4.23% | 0.0 |
| XGB_RETRAINED | 97.42% | 0.03% | 99.59% | 0.9849 | 92.96% | 0.0 |
| SW_XGB_RETRAINED | 97.81% | 0.00% | 100.00% | 0.9889 | 87.32% | 0.0 |
| XGB_TRUSTLAB | 70.41% | 15.66% | 25.47% | 0.3741 | 74.65% | 0.0 |
| SW_XGB_TRUSTLAB | 31.18% | 10.65% | 18.21% | 0.2299 | 64.79% | 1.0 |

## 2. Share of flows flagged, per CIC-IDS2017 label

For attacks this is the detection rate; for BENIGN it is the false alarm rate.

| Label | Flows | SURICATA_ALL | SURICATA_THREATS | XGB_RETRAINED | SW_XGB_RETRAINED | XGB_TRUSTLAB | SW_XGB_TRUSTLAB |
|---|---|---|---|---|---|---|---|
| BENIGN | 177,641 | 21.22% | 0.08% | 0.03% | 0.00% | 15.66% | 10.65% |
| DoS Hulk | 9,742 | 98.39% | 0.00% | 98.92% | 99.35% | 78.60% | 36.10% |
| DoS Slowhttptest | 2,857 | 35.60% | 0.11% | 96.99% | 98.18% | 56.91% | 17.92% |
| DoS slowloris | 902 | 1.33% | 0.00% | 82.59% | 79.93% | 25.17% | 20.18% |
| Heartbleed | 6 | 100.00% | 33.33% | 83.33% | 100.00% | 0.00% | 0.00% |

## 3. Speed and resources (all measured on CPU)

| Detector | Packets/s | Flows/s | Waits for | Latency, one input | Peak RAM (MB) | Startup / training |
|---|---|---|---|---|---|---|
| Suricata | 99,922 (751 Mbit/s) | – | nothing (per packet) | inline | 963 | 22.1 s rule loading |
| XGB_RETRAINED | 1,163,354 (equiv.) | 45,370 | end of flow | 0.866 ms | 1,498 | 22 s on cuda |
| SW_XGB_RETRAINED | 1,496,811 (equiv.) | 58,375 | end of flow + last 32 flows | 0.634 ms | 2,104 | 28 s on cuda |
| XGB_TRUSTLAB | 1,148,756 (equiv.) | 44,801 | end of flow | – | 1,840 | trained on TRUST Lab |
| SW_XGB_TRUSTLAB | 532,313 (equiv.) | 20,760 | end of flow + last 32 flows | – | 2,377 | trained on TRUST Lab |

XGBoost speed does **not** include CICFlowMeter (turning packets into flows). Suricata speed includes all packet work. So the XGBoost numbers are optimistic.

## 4. Design differences

| | Suricata | XGBoost |
|---|---|---|
| Input | Packets | Finished flows (CICFlowMeter) |
| Can block the first packet of an attack | Yes (inline IPS mode) | No — waits for the flow to end |
| Explains an alert | Rule name, SID, often a CVE | Class + probability |
| Adding a new known attack | Write/update a rule (minutes) | Collect labelled data and retrain |
| Needs training data | No | Yes |

## 5. Top Suricata signatures

| Signature | Alerts | Counted as threat |
|---|---|---|
| SURICATA TCPv4 invalid checksum | 2,283,035 | no |
| SURICATA HTTP Response excessive header repetition | 8,773 | no |
| SURICATA Ethertype unknown | 7,535 | no |
| SURICATA STREAM Packet with invalid timestamp | 2,219 | no |
| SURICATA STREAM Packet with invalid ack | 1,410 | no |
| SURICATA STREAM CLOSEWAIT FIN out of window | 1,329 | no |
| SURICATA STREAM SHUTDOWN RST invalid ack | 1,323 | no |
| SURICATA STREAM FIN out of window | 779 | no |
| SURICATA Kerberos 5 weak encryption parameters | 531 | no |
| ET INFO TLS Handshake Failure | 294 | no |
| SURICATA HTTP unable to match response to request | 287 | no |
| SURICATA HTTP Request excessive header repetition | 278 | no |
| ET INFO Observed DNS Query to .biz TLD | 207 | no |
| SURICATA Applayer Detect protocol only one direction | 200 | no |
| ET DNS Query for .cc TLD | 198 | yes |

## 6. Limits

- **Use SURICATA_THREATS, not SURICATA_ALL.** 2,283,182 of 2,309,948 alerts (99%) are "invalid checksum" engine events, an artefact of how CIC-IDS2017 was captured, not attacks. They inflate both detection and false alarms of SURICATA_ALL.
- Too few test flows for reliable percentages: Heartbleed (6).
- ML peak RAM includes holding the whole day in pandas; a live detector scoring one flow at a time needs less.
- *_TRUSTLAB models were trained on a built TRUST Lab stream (attack bursts inserted into benign traffic). Real CIC-IDS2017 traffic is mixed differently, so the sliding-window statistics shift; this hits SW models hardest.
- CIC-IDS2017 has known label and flow errors (Engelen et al., 2021). Some "false positives" may be real attacks with wrong labels, and the reverse.
- CSV times have minutes only, so matching uses a time tolerance; a few matches can be wrong.
- Suricata is scored on the test flows only, so it is compared with XGBoost on exactly the same flows.
- Train/test use 10-minute time blocks (3 train : 2 test), so overlapping windows do not leak. An attack that happens only inside test blocks is never seen by the *_RETRAINED models.
- *_RETRAINED models learn from this same day (home advantage). *_TRUSTLAB models and Suricata were not trained on CIC-IDS2017, so that comparison is the fairest.
- Suricata rules are newer than 2017. Rules written after an attack became public make Suricata look better than on day one.
