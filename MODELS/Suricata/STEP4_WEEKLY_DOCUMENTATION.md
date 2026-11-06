# CIC-IDS2017 Weekly Model and Suricata Evaluation

## 1. Objective

Evaluate the existing TRUST Lab machine-learning models against
CIC-IDS2017 traffic and compare their detections with Suricata.

The models are evaluated without retraining on CIC-IDS2017.

## 2. Workflow

1. Run Suricata on each day's original PCAP file.
2. Generate full-day flow CSVs using Python CICFlowMeter.
3. Use the original labelled CIC-IDS2017 CSV files to derive attack labels.
4. Run step4_v4flows.py for each weekday.
5. Review the generated reports and compare the metrics.

## 3. Dataset and input files

| Day | Labelled input CSVs |
|---|---|
| Monday | Monday-WorkingHours.pcap_ISCX.csv |
| Tuesday | Tuesday-WorkingHours.pcap_ISCX.csv |
| Wednesday | Wednesday-workingHours.pcap_ISCX.csv |
| Thursday | Morning-WebAttacks and Afternoon-Infilteration CSVs |
| Friday | Morning, Afternoon-PortScan and Afternoon-DDos CSVs |

Each day also requires a full-day Python CICFlowMeter flow CSV.
Sample CSVs must not be used as substitutes for full-day data.

## 4. Suricata processing

Suricata reads the original PCAP directly and applies its detection rules.
Its alerts are stored in:

    output/<DAY>/suricata/eve.json

For this server, single-thread mode successfully processed Monday's
10.1 GB PCAP. The run reported 11,709,971 packets, 1,887,229 alerts,
120,953 packets/second and 570 MB peak RAM.

These figures are Monday's observed results, not results for the other days.

## 5. Step 4 execution

Run the weekly script:

    ./run_step4_all_days.sh

The script checks input files and executes step4_v4flows.py for each
day whose required files are available.

Thursday and Friday use multiple labelled CSV files.

## 6. Models and detectors

The available detectors are:

- SW_XGB_TRUSTLAB
- SW_XGB_ROBUST
- XGB_TRUSTLAB
- SURICATA_THREATS
- SURICATA_ALL

The actual report includes only detectors that were successfully loaded
or matched. Suricata comparison requires the day's eve.json file.

## 7. Evaluation metrics

- Detection rate: fraction of labelled attack flows detected.
- False alarm rate: fraction of benign flows incorrectly flagged.
- Precision: fraction of flagged flows that are labelled attacks.
- F1 score: combined measure of precision and detection rate.
- Missed attacks: labelled attack flows not detected.
- False alarms: benign flows incorrectly flagged.

## 8. Output files

For each day:

    output/<DAY>/v4/flows_v4.parquet
    output/<DAY>/v4/predictions_v4.parquet
    output/<DAY>/v4/RESULTS_V4.md
    output/<DAY>/v4/results_v4.json

The weekly runner also creates:

    output_step4_<DAY>.log

Read RESULTS_V4.md first for the comparison tables.
The JSON file contains structured metrics and run settings.

## 9. Important limitations

1. Missing flow CSVs mean that the corresponding day is not evaluated.
2. Attack labels are inferred from IP pairs and attack time ranges in
   the original labelled CSVs; this can introduce labelling errors.
3. The flow tools may produce different flow counts and boundaries.
4. Some TRUST Lab features cannot be reproduced exactly. The default
   script recomputes selected features and sets six bulk features to zero.
5. SW_XGB_ROBUST is designed to work without those six bulk features.
6. A Suricata alert count is not the same as the number of correctly
   detected attacks. Alerts must be matched to flows and evaluated
   against the labels.
7. Small attack classes can produce unreliable percentages.

## 10. Completion checklist

- [ ] Suricata eve.json exists for Monday through Friday.
- [ ] Full-day Python flow CSV exists for each day.
- [ ] All required labelled CSVs exist.
- [ ] Weekly Step 4 script has been executed.
- [ ] Every day's status has been checked.
- [ ] RESULTS_V4.md has been reviewed for each successful day.
- [ ] Final comparisons use the same evaluation scope and metrics.

## 11. Final reporting

Do not claim that all five days were evaluated until each day has a
successful report. Summarize the observed metrics from the generated
reports; do not assume that Suricata or a particular ML model performs
best before examining the results.
