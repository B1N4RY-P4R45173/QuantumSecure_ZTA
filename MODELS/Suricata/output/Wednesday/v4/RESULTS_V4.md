# TRUST Lab models vs Suricata — CIC-IDS2017 Wednesday, flows from the TRUST Lab flow tool

Flows made with the Python `cicflowmeter` (whole-packet lengths, like TRUST Lab), labelled with the attack schedule from the v3 CSV. Models are NOT retrained on CIC-IDS2017.

Feature values: 7 features recomputed with TRUST Lab's own rules; the 6 bulk features cannot be reproduced and are set to 0. SW_XGB_ROBUST is trained without the 6 bulk features.

## Test time blocks (same blocks as step 2): 154,027 flows, 12,526 attack

| Detector | Detection rate | False alarm rate | Precision | F1 | Missed attacks | False alarms |
|---|---|---|---|---|---|---|
| SW_XGB_TRUSTLAB | 0.06% | 0.15% | 3.24% | 0.0011 | 12,519 | 209 |
| SW_XGB_ROBUST | 4.96% | 5.82% | 7.01% | 0.0581 | 11,905 | 8,239 |
| XGB_TRUSTLAB | 0.06% | 0.33% | 1.70% | 0.0012 | 12,518 | 462 |
| SURICATA_THREATS | 0.02% | 0.08% | 1.72% | 0.0003 | 12,524 | 114 |
| SURICATA_ALL | 64.35% | 12.68% | 31.00% | 0.4185 | 4,465 | 17,939 |

Detected per attack (share of its flows flagged as any attack):

| Attack | Flows | SW_XGB_TRUSTLAB | SW_XGB_ROBUST | XGB_TRUSTLAB | SURICATA_THREATS | SURICATA_ALL |
|---|---|---|---|---|---|---|
| DoS Hulk | 8,001 | 0.00% | 0.10% | 0.02% | 0.00% | 93.10% |
| DoS Slowhttptest | 3,207 | 0.09% | 9.48% | 0.19% | 0.03% | 18.74% |
| DoS slowloris | 1,027 | 0.00% | 2.43% | 0.00% | 0.00% | 0.39% |
| DoS GoldenEye | 284 | 1.41% | 100.00% | 0.00% | 0.00% | 0.00% |
| Heartbleed ⚠️ | 7 | 0.00% | 0.00% | 0.00% | 14.29% | 100.00% |

## Whole day: 534,542 flows, 182,887 attack

| Detector | Detection rate | False alarm rate | Precision | F1 | Missed attacks | False alarms |
|---|---|---|---|---|---|---|
| SW_XGB_TRUSTLAB | 0.07% | 0.18% | 16.88% | 0.0014 | 182,755 | 650 |
| SW_XGB_ROBUST | 1.50% | 6.06% | 11.39% | 0.0265 | 180,148 | 21,317 |
| XGB_TRUSTLAB | 0.00% | 0.36% | 0.70% | 0.0001 | 182,878 | 1,281 |
| SURICATA_THREATS | 0.00% | 0.08% | 0.71% | 0.0000 | 182,885 | 281 |
| SURICATA_ALL | 91.15% | 12.76% | 78.79% | 0.8452 | 16,181 | 44,886 |

Detected per attack (share of its flows flagged as any attack):

| Attack | Flows | SW_XGB_TRUSTLAB | SW_XGB_ROBUST | XGB_TRUSTLAB | SURICATA_THREATS | SURICATA_ALL |
|---|---|---|---|---|---|---|
| DoS Hulk | 158,654 | 0.00% | 0.05% | 0.00% | 0.00% | 99.60% |
| DoS GoldenEye | 9,129 | 1.41% | 4.20% | 0.00% | 0.00% | 82.79% |
| DoS slowloris | 8,797 | 0.00% | 19.73% | 0.00% | 0.00% | 3.21% |
| DoS Slowhttptest | 6,295 | 0.05% | 8.71% | 0.11% | 0.02% | 13.22% |
| Heartbleed ⚠️ | 12 | 0.00% | 0.00% | 0.00% | 8.33% | 100.00% |

## Same model, old flows (v3 Java) vs new flows (TRUST Lab tool) — test blocks

| Detector | Flows | Detection rate | False alarm rate |
|---|---|---|---|
| SW_XGB_TRUSTLAB | v3 CSV (old) | 31.18% | 10.65% |
| SW_XGB_TRUSTLAB | **TRUST Lab tool (new)** | 0.06% | 0.15% |
| XGB_TRUSTLAB | v3 CSV (old) | 70.41% | 15.66% |
| XGB_TRUSTLAB | **TRUST Lab tool (new)** | 0.06% | 0.33% |

## Notes

- Attack schedule taken from the v3 labelled CSV (pairs with ≥5% of a label's flows, times ± 60 s). v3 has known label errors (Engelen et al., 2021).
- The two flow tools cut traffic into flows differently, so flow counts differ from the v3 CSV.
- Suricata: a flow counts as detected if an alert with the same endpoints falls inside the flow (± 1 s). SURICATA_THREATS ignores engine events and ET INFO / ET POLICY rules.
- ⚠️ = fewer than 30 flows, percentage not reliable.
