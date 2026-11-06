# SW-XGBoost trained with solo attacks (TRUST Lab)

New training stream: solo-type classes 10% solo, other classes 3% solo, solo units of 1-5 flows with at least 32 normal flows around them.
Solo-type classes: Exploitation, BufferOverflow, WebBased, API, TLSSSL, C2Beaconing, Exfiltration.

## TEST_ORIGINAL

314,969 flows. Hidden attacks (window < 25% attack): 954. Solo-unit attack flows: 0. Attack-start flows: 685. Normal flows in a 75%+ attack window: 14,457.

| Model | F1 | Detection rate | False alarm rate | Missed attacks | False alarms | Macro F1 |
|---|---|---|---|---|---|---|
| FLAT | 0.9833 | 98.68% | 1.53% | 1,786 | 2,752 | 0.8789 |
| SW_OLD | 0.9958 | 99.41% | 0.18% | 799 | 326 | 0.9516 |
| SW_SOLO | 0.9960 | 99.51% | 0.24% | 661 | 431 | 0.9423 |
| SW_SOLO_DEV | 0.9962 | 99.51% | 0.20% | 661 | 368 | 0.9434 |

| Model | Hidden attacks detected | Solo-unit attacks detected | Attack start detected | Spill-over false alarms | Exploitation hidden | BufferOverflow hidden | Bruteforce hidden | C2Beaconing hidden |
|---|---|---|---|---|---|---|---|---|
| FLAT | 99.69% | – | 99.85% | 1.74% | 100.00% | 100.00% | 98.41% | 100.00% |
| SW_OLD | 91.93% | – | 90.07% | 1.01% | 52.38% | 71.43% | 85.71% | 87.50% |
| SW_SOLO | 96.54% | – | 95.47% | 1.07% | 79.76% | 82.86% | 95.24% | 98.21% |
| SW_SOLO_DEV | 96.33% | – | 95.33% | 0.97% | 80.95% | 81.43% | 92.06% | 98.21% |

## TEST_SOLO

314,969 flows. Hidden attacks (window < 25% attack): 11,668. Solo-unit attack flows: 10,800. Attack-start flows: 11,420. Normal flows in a 75%+ attack window: 15,498.

| Model | F1 | Detection rate | False alarm rate | Missed attacks | False alarms | Macro F1 |
|---|---|---|---|---|---|---|
| FLAT | 0.9833 | 98.68% | 1.53% | 1,786 | 2,752 | 0.8789 |
| SW_OLD | 0.9919 | 98.62% | 0.18% | 1,858 | 322 | 0.9454 |
| SW_SOLO | 0.9940 | 99.09% | 0.22% | 1,232 | 393 | 0.9428 |
| SW_SOLO_DEV | 0.9941 | 99.08% | 0.19% | 1,238 | 342 | 0.9441 |

| Model | Hidden attacks detected | Solo-unit attacks detected | Attack start detected | Spill-over false alarms | Exploitation hidden | BufferOverflow hidden | Bruteforce hidden | C2Beaconing hidden |
|---|---|---|---|---|---|---|---|---|
| FLAT | 99.65% | 99.71% | 99.68% | 1.41% | 100.00% | 100.00% | 96.17% | 100.00% |
| SW_OLD | 89.90% | 89.86% | 89.83% | 0.90% | 29.51% | 66.37% | 74.71% | 90.42% |
| SW_SOLO | 94.54% | 94.54% | 94.54% | 0.79% | 59.02% | 80.03% | 88.25% | 94.64% |
| SW_SOLO_DEV | 94.45% | 94.48% | 94.46% | 0.81% | 58.63% | 80.41% | 87.74% | 94.25% |

## Training cost

| Model | Features | Train time (s) | Trees used | Peak RAM while training (MB) |
|---|---|---|---|---|
| SW_SOLO | 128 | 152 | 164 | 4,073 |
| SW_SOLO_DEV | 141 | 170 | 168 | 4,388 |

## Notes

- TEST_ORIGINAL is the old test stream: a fair test for every model.
- TEST_SOLO uses the same test flows arranged with many solo attacks. The new models were trained on this kind of arrangement and the old ones were not, so it shows how much the new training helps on hidden attacks.
- Labels were used only to build the streams. Every model gets the same kind of input in real time.
- Missed attacks = attack flows predicted Benign. False alarms = Benign flows predicted as any attack.
- Hidden-attack groups per class are small in TEST_ORIGINAL, so those percentages are rough.
