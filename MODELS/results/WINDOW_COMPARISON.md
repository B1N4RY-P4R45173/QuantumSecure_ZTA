# SW-XGBoost — single window vs two windows (TRUST Lab)

All models trained the same way and scored on the same test flows (from row 63).
Best model chosen on **validation** F1: **8+64**.

Model name = window sizes. `32` = one window of 32 flows. `8+64` = one model that sees the last 8 flows and the last 64 flows.

## 1. Attack vs normal (test set)

| Model | F1 | Detection rate | False alarm rate | Missed attacks | False alarms | Macro F1 (16 classes) | Val F1 |
|---|---|---|---|---|---|---|---|
| 8 | 0.9949 | 99.48% | 0.38% | 701 | 687 | 0.9282 | 0.9836 |
| 32 | 0.9957 | 99.42% | 0.21% | 786 | 375 | 0.9532 | 0.9876 |
| 64 | 0.9955 | 99.36% | 0.20% | 862 | 351 | 0.9657 | 0.9891 |
| 8+64 ⭐ | 0.9957 | 99.42% | 0.21% | 787 | 383 | 0.9678 | 0.9894 |

## 2. Detected as an attack, per class (test set)

Share of each attack's flows flagged as any attack. **Bold** = best in the row.

| Class | 8 | 32 | 64 | 8+64 |
|---|---|---|---|---|
| API | 99.90% | 99.90% | **99.98%** | 99.96% |
| Bruteforce | **94.44%** | 93.49% | 93.04% | 93.42% |
| BufferOverflow | 99.57% | 99.69% | **99.78%** | 99.76% |
| C2Beaconing | 99.69% | 99.72% | 99.72% | **99.73%** |
| DDoS | 100.00% | 100.00% | 100.00% | 100.00% |
| DNS | 100.00% | 100.00% | 100.00% | 100.00% |
| DoS | 99.99% | 99.99% | 99.99% | 99.99% |
| Evasion | 100.00% | 100.00% | 100.00% | 100.00% |
| Exfiltration | 99.94% | 99.90% | 99.92% | **99.96%** |
| Exploitation | **98.93%** | 98.63% | 98.06% | 98.56% |
| MITM | **100.00%** | **100.00%** | **100.00%** | 99.99% |
| PortScan | 99.77% | **99.99%** | 99.97% | 99.94% |
| Slowloris | 99.99% | **100.00%** | **100.00%** | **100.00%** |
| TLSSSL | 99.99% | 99.97% | **100.00%** | 99.99% |
| WebBased | **100.00%** | 99.99% | 99.97% | 99.97% |

## 3. Given the right attack name, per class (test set)

Share of each attack's flows given its own class name. **Bold** = best in the row.

| Class | 8 | 32 | 64 | 8+64 |
|---|---|---|---|---|
| API | 99.90% | 99.90% | **99.98%** | 99.96% |
| Bruteforce | 89.79% | 91.17% | 90.97% | **91.89%** |
| BufferOverflow | 96.94% | 99.58% | **99.77%** | 99.73% |
| C2Beaconing | 99.30% | 99.72% | 99.72% | **99.73%** |
| DDoS | 99.79% | **99.83%** | 99.77% | 99.76% |
| DNS | 100.00% | 100.00% | 100.00% | 100.00% |
| DoS | 74.54% | 80.86% | **91.50%** | 90.16% |
| Evasion | 98.52% | 98.52% | 98.52% | 98.52% |
| Exfiltration | 99.92% | 99.90% | 99.92% | **99.96%** |
| Exploitation | 97.08% | 97.22% | 97.29% | **97.89%** |
| MITM | 99.99% | 99.99% | **100.00%** | 99.99% |
| PortScan | 99.73% | **99.98%** | 99.97% | 99.88% |
| Slowloris | 34.71% | 58.40% | 66.61% | **70.00%** |
| TLSSSL | 99.22% | 99.19% | 99.59% | **99.68%** |
| WebBased | 99.71% | 99.80% | **99.92%** | **99.92%** |

## 4. Cost

| Model | Features | Flows/s (CPU) | Peak RAM (MB) | Train time (s) | Trees used | Model size (MB) |
|---|---|---|---|---|---|---|
| 8 | 128 | 24,947 | 3,372 | 155 (gpu) | 139 | 17.9 |
| 32 | 128 | 22,185 | 3,409 | 169 (gpu) | 157 | 16.7 |
| 64 | 128 | 18,978 | 3,404 | 195 (gpu) | 192 | 17.3 |
| 8+64 | 186 | 21,663 | 4,145 | 223 (gpu) | 150 | 15.5 |

## Notes

- Missed attacks = attack flows predicted Benign. False alarms = Benign flows predicted as any attack.
- Flows/s includes building the window features; it does not include CICFlowMeter.
- Peak RAM covers building inputs for all three splits and training, not live use.
- GPU training is not exactly repeatable, so very small differences between models are noise.
