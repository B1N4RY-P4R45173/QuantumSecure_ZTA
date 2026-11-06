# Model comparison — known attacks (TRUST Lab)

## 1. Detection

| Model | Input | Attack/benign F1 | Detection rate | False positive rate | Macro F1 (16 classes) | Bursts detected | Median attack flows before alert |
|---|---|---|---|---|---|---|---|
| LIGHTGBM | one flow | 0.9825 | 98.56% | 1.56% | 0.8729 | 100.00% | 0.0000 |
| LSTM | sequence of the last 32 flows | 0.9851 | 98.97% | 1.48% | 0.9578 | 100.00% | 0.0000 |
| SW_LIGHTGBM | current flow + statistics of last 32 flows | 0.9956 | 99.36% | 0.18% | 0.9509 | 100.00% | 0.0000 |
| SW_XGBOOST | current flow + statistics of last 32 flows | 0.9958 | 99.43% | 0.21% | 0.9521 | 100.00% | 0.0000 |
| XGBOOST | one flow | 0.9818 | 98.57% | 1.67% | 0.8790 | 100.00% | 0.0000 |

## 2. Edge fitness (speed and resources)

| Model | Packets/s (equiv.) | Latency, one input (ms) | Peak RAM (MB) | Train time (s) | Waits for flow end? | Can block first packet? |
|---|---|---|---|---|---|---|
| LIGHTGBM | 2,766,274 | 1.1347 | 2,003 | 63 | yes | no |
| LSTM | 286,032 | 1.0775 | 3,197 | 73 | yes | no |
| SW_LIGHTGBM | 649,434 | 1.2722 | 2,839 | 176 | yes | no |
| SW_XGBOOST | 1,653,842 | 1.0436 | 3,193 | 102 | yes | no |
| XGBOOST | 5,413,962 | 0.6768 | 2,025 | 44 | yes | no |

## 3. Detection rate per attack class

| Class | LIGHTGBM | LSTM | SW_LIGHTGBM | SW_XGBOOST | XGBOOST |
|---|---|---|---|---|---|
| API | 99.87% | 99.22% | 99.86% | 99.89% | 99.89% |
| Bruteforce | 93.80% | 89.06% | 93.04% | 93.71% | 94.12% |
| BufferOverflow | 100.00% | 99.80% | 99.70% | 99.73% | 100.00% |
| C2Beaconing | 100.00% | 99.51% | 99.61% | 99.72% | 100.00% |
| DDoS | 100.00% | 99.98% | 99.99% | 100.00% | 100.00% |
| DNS | 100.00% | 99.98% | 100.00% | 100.00% | 100.00% |
| DoS | 99.99% | 99.99% | 99.99% | 99.99% | 99.99% |
| Evasion | 100.00% | 99.59% | 100.00% | 100.00% | 100.00% |
| Exfiltration | 99.91% | 99.91% | 99.88% | 99.90% | 99.88% |
| Exploitation | 99.96% | 99.00% | 98.43% | 98.58% | 99.78% |
| MITM | 99.98% | 99.99% | 100.00% | 99.99% | 100.00% |
| PortScan | 85.02% | 99.86% | 99.98% | 99.99% | 85.06% |
| Slowloris | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% |
| TLSSSL | 100.00% | 98.74% | 99.98% | 99.99% | 100.00% |
| WebBased | 99.94% | 99.91% | 99.98% | 99.99% | 99.91% |

## 4. Decision

### Edge gateway (inline IPS)

Weights: packets_per_s 0.25, early_block 0.20, fpr 0.15, detection_rate 0.15, peak_ram_mb 0.10, latency_ms 0.10, train_time_s 0.05

| Rank | Model | Score (0–1) | Not measured |
|---|---|---|---|
| 1 | SW_XGBOOST | 0.713 | - |
| 2 | XGBOOST | 0.700 | - |
| 3 | SW_LIGHTGBM | 0.588 | - |
| 4 | LIGHTGBM | 0.570 | - |
| 5 | LSTM | 0.361 | - |

### Controller (known-attack ML model)

Weights: macro_f1 0.35, binary_f1 0.20, fpr 0.15, bursts_detected 0.10, flows_before_alert 0.10, packets_per_s 0.10

| Rank | Model | Score (0–1) | Not measured |
|---|---|---|---|
| 1 | SW_XGBOOST | 0.833 | - |
| 2 | SW_LIGHTGBM | 0.797 | - |
| 3 | LSTM | 0.516 | - |
| 4 | XGBOOST | 0.225 | - |
| 5 | LIGHTGBM | 0.198 | - |

**Best for the edge gateway:** SW_XGBOOST
**Best ML model for the controller:** SW_XGBOOST

> Suricata has no results yet. Run `MODEL SURICATA/run_suricata.py` (see its README).

## 5. Charts

![binary_f1.png](charts/binary_f1.png)
![macro_f1.png](charts/macro_f1.png)
![fpr.png](charts/fpr.png)
![packets_per_s.png](charts/packets_per_s.png)
![latency_ms.png](charts/latency_ms.png)
![peak_ram_mb.png](charts/peak_ram_mb.png)
![flows_before_alert.png](charts/flows_before_alert.png)
