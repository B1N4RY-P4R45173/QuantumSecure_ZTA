#!/usr/bin/env bash
# One-time setup inside WSL Ubuntu (or any Ubuntu/Debian Linux).
#   wsl -d Ubuntu-24.04
#   cd /mnt/d/BTECH/ZEROTRUST/PQZTA/MODELS/Suricata
#   bash setup_wsl.sh
set -euo pipefail
cd "$(dirname "$0")"

echo ">>> Suricata (stable version from the OISF PPA)"
sudo apt-get update
sudo apt-get install -y software-properties-common python3-venv python3-pip
sudo add-apt-repository -y ppa:oisf/suricata-stable
sudo apt-get update
sudo apt-get install -y suricata

echo ">>> Free ET Open rules"
sudo suricata-update
suricata -V

echo ">>> Python environment for Linux (the Windows .venv cannot be used inside WSL)"
python3 -m venv ~/pqzta-venv
~/pqzta-venv/bin/pip install --upgrade pip
~/pqzta-venv/bin/pip install -r ../requirements.txt

echo
echo "Done. Activate the environment with:  source ~/pqzta-venv/bin/activate"
