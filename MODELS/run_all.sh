#!/usr/bin/env bash
# Run the full experiment on Linux / macOS / WSL.
#   ./run_all.sh            full run
#   ./run_all.sh --quick    small test run (checks that everything works)
#   PCAP=/path/x.pcap LABELS=/path/flows.csv ./run_all.sh    also run Suricata
# Activate the virtual environment first:  source .venv/bin/activate
set -euo pipefail
cd "$(dirname "$0")"

PRE=""; LSTM_ARGS=()
if [[ "${1:-}" == "--quick" ]]; then PRE="--quick"; LSTM_ARGS=(--epochs 2 --samples-per-epoch 20000); fi
if [[ "${1:-}" == "--all" ]]; then PRE="--all"; fi     # every flow (slow, ~16 GB RAM)

python preprocess.py $PRE
for m in "MODEL XGBOOST" "MODEL LIGHTGBM" "MODEL SW_XGBOOST" "MODEL SW_LIGHTGBM"; do
  python "$m/train.py"
done
python "MODEL LSTM/train.py" ${LSTM_ARGS[@]+"${LSTM_ARGS[@]}"}

if [[ -n "${PCAP:-}" ]]; then
  if [[ -n "${LABELS:-}" ]]; then
    python "MODEL SURICATA/run_suricata.py" --pcap "$PCAP" --labels "$LABELS"
  else
    python "MODEL SURICATA/run_suricata.py" --pcap "$PCAP"
  fi
fi

python compare.py
