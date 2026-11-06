# SW-XGBoost — window size sweep (TRUST Lab)

Every window is scored on the same test flows (from row 127). Best window chosen on **validation** F1: **64 flows**.

## 1. Detection (test set)

| Window | Attack/benign F1 | Detection rate | False positive rate | Missed attacks | False alarms | Macro F1 (16 classes) | Val F1 |
|---|---|---|---|---|---|---|---|
| 4 | 0.9925 | 99.46% | 0.72% | 728 | 1,302 | 0.9149 | 0.9804 |
| 8 | 0.9950 | 99.47% | 0.35% | 710 | 629 | 0.9293 | 0.9854 |
| 16 | 0.9958 | 99.46% | 0.23% | 726 | 412 | 0.9434 | 0.9864 |
| 32 | 0.9958 | 99.37% | 0.17% | 845 | 300 | 0.9594 | 0.9889 |
| 64 ⭐ | 0.9953 | 99.37% | 0.23% | 850 | 408 | 0.9621 | 0.9892 |
| 128 | 0.9938 | 99.24% | 0.36% | 1,024 | 651 | 0.9705 | 0.9876 |

## 2. Weak classes (test set)

Each cell: detected as an attack / given the right class.

| Class | W=4 | W=8 | W=16 | W=32 | W=64 | W=128 |
|---|---|---|---|---|---|---|
| Slowloris | 100.00% / 30.16% | 100.00% / 35.41% | 100.00% / 49.59% | 100.00% / 67.14% | 100.00% / 62.46% | 100.00% / 71.91% |
| DoS | 99.99% / 71.94% | 99.99% / 74.70% | 99.99% / 75.92% | 99.99% / 81.61% | 99.99% / 90.18% | 99.99% / 96.36% |
| Bruteforce | 94.82% / 87.21% | 94.60% / 90.17% | 94.11% / 90.88% | 93.04% / 90.36% | 93.24% / 91.26% | 93.62% / 91.91% |
| Exploitation | 98.68% / 95.14% | 98.76% / 97.04% | 98.64% / 97.28% | 98.46% / 97.19% | 98.03% / 97.28% | 96.06% / 94.79% |
| PortScan | 99.60% / 99.50% | 99.77% / 99.74% | 99.96% / 99.94% | 99.99% / 99.98% | 99.98% / 99.98% | 99.84% / 99.84% |
| BufferOverflow | 99.29% / 93.02% | 99.56% / 97.09% | 99.74% / 98.94% | 99.66% / 99.51% | 99.78% / 99.77% | 99.73% / 99.73% |

## 3. Cost

| Window | Features | Flows/s (CPU) | Peak RAM (MB) | Train time (s) | Trees used | Model size (MB) |
|---|---|---|---|---|---|---|
| 4 | 128 | 420,763 | 4,174 | 134 (gpu) | 142 | 18.6 |
| 8 | 128 | 405,211 | 4,219 | 151 (gpu) | 161 | 20.0 |
| 16 | 128 | 426,073 | 4,225 | 144 (gpu) | 148 | 17.7 |
| 32 | 128 | 342,741 | 4,247 | 201 (gpu) | 225 | 20.8 |
| 64 | 128 | 356,226 | 4,254 | 140 (gpu) | 150 | 15.2 |
| 128 | 128 | 317,141 | 4,258 | 99 (gpu) | 100 | 11.4 |

## Notes

- Missed attacks = attack flows predicted Benign. False alarms = Benign flows predicted as any attack.
- Flows/s includes building the window features; it does not include CICFlowMeter.
- Peak RAM covers building inputs for all three splits and training, not live use.
- Choosing the window on test would make the test numbers too optimistic, so validation is used.
