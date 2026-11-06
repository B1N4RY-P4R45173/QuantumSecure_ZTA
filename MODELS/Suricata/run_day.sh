#!/usr/bin/env bash
# Run the full XGBoost vs Suricata comparison for one CIC-IDS2017 day (inside WSL).
#
#   source ~/pqzta-venv/bin/activate
#   bash run_day.sh Wednesday ~/cicids/Wednesday-workingHours.pcap data/csv/Wednesday-workingHours.pcap_ISCX.csv
#
# More than one CSV is allowed (Thursday and Friday have several):
#   bash run_day.sh Friday ~/cicids/Friday-WorkingHours.pcap data/csv/Friday-*.csv
set -euo pipefail
cd "$(dirname "$0")"

if [[ $# -lt 3 ]]; then
  echo "usage: bash run_day.sh <Day> <pcap> <csv> [more csv ...]"; exit 1
fi
DAY="$1"; PCAP="$2"; shift 2

python step1_suricata.py --day "$DAY" --pcap "$PCAP"
python step2_xgboost.py  --day "$DAY" --csv "$@"
python step3_compare.py  --day "$DAY"
