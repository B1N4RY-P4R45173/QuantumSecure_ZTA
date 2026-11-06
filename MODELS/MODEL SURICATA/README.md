# MODEL SURICATA

## Why Suricata needs extra steps

Suricata reads **packets** (pcap files or a live network card).
The TRUST Lab dataset only contains **CSV flow features** made by CICFlowMeter.
The raw pcaps are "available on request" from the dataset authors.

So you **cannot** run Suricata on the TRUST Lab CSV files.
Never copy Suricata numbers from another paper into your table. Measure them yourself.

## What you can measure

| Mode | You need | You get |
|---|---|---|
| **A. Speed only** | Any pcap file | Packets/s, Mbit/s, peak RAM, startup time |
| **B. Speed + detection** | A pcap **and** labelled flows from the **same** pcap | All of A, plus detection rate, false positive rate, detection rate per class, time to detect |

## How to get a pcap for mode B (choose one)

1. **Ask the TRUST Lab authors for the pcaps.** Their contact is in the dataset README.
   Note: the IPs in their CSV are randomised, so you also need their *un-anonymised* labels, or you need to run CICFlowMeter yourself (option 2).
2. **Make your own labelled pcap** with the dataset's attack scripts
   (`trustlab_dataset-main/Scripts/*.sh`) in an isolated virtual lab:
   - Run `tcpdump -w attack_<class>.pcap` on the victim network while one script runs.
   - Run CICFlowMeter on the pcap to get flows, then add a `Label` column (the class name).
   - Record benign traffic the same way (`Benign.sh`) and label it `Benign`.
   - Merge the pcaps with `mergecap -w all.pcap *.pcap`, and merge the CSVs.

Only run attack scripts inside an isolated lab that you own.

## Setup (Linux or WSL Ubuntu)

```bash
sudo apt install suricata          # or the OISF PPA for the newest version
sudo suricata-update               # downloads the free ET Open rules
pip install -r ../requirements.txt
```

## Run

```bash
# A) speed only
python run_suricata.py --pcap /path/traffic.pcap

# B) speed + detection
python run_suricata.py --pcap /path/all.pcap --labels /path/all_flows_labelled.csv

# one CPU core, for a fair comparison with single-thread ML numbers
python run_suricata.py --pcap /path/traffic.pcap --runmode single
```

Results are saved to `MODELS/results/SURICATA.json`, plus the full Suricata output in `output/run_<time>/`.

## How detection is matched

- A flow counts as **detected** if Suricata raised at least one alert with the same 5-tuple
  (protocol, both IPs and ports, in either direction) during the flow's lifetime (± `--tolerance` seconds).
- Suricata reports "attack / not attack", not our 16 class names. So its **macro F1 is not computed**.
  Binary metrics and the detection rate per class are computed.
- If CICFlowMeter wrote local time and Suricata wrote UTC, use `--time-offset` (for example `--time-offset -19800` for IST).

## Report these together with the numbers

- Suricata version and ruleset date (`suricata -V`, and `/var/lib/suricata/rules/`).
  Rules written *after* an attack was public make Suricata look better than it would have been on day one.
- CPU model, number of cores, and `--runmode`.
