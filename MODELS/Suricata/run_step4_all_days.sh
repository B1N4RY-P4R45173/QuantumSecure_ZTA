#!/usr/bin/env bash

set -u

# Run from MODELS/Suricata with pqzta-venv activated.
# Change these paths if your full-day Python flow CSVs are elsewhere.
DATA="../../DataSet"

declare -A FLOWS=(
  [Monday]="$DATA/cfm_py/Monday_py.csv"
  [Tuesday]="$DATA/cfm_py/Tuesday_py.csv"
  [Wednesday]="$DATA/wed_py/wed_py.csv"
  [Thursday]="$DATA/cfm_py/Thursday_py.csv"
  [Friday]="$DATA/cfm_py/Friday_py.csv"
)

declare -A STATUS

for day in Monday Tuesday Wednesday Thursday Friday; do
    echo
    echo "======================================"
    echo "Step 4: $day"
    echo "======================================"

    flow="${FLOWS[$day]}"
    labels=()

    case "$day" in
      Monday)
        labels=("$DATA/Monday-WorkingHours.pcap_ISCX.csv")
        ;;
      Tuesday)
        labels=("$DATA/Tuesday-WorkingHours.pcap_ISCX.csv")
        ;;
      Wednesday)
        labels=("$DATA/Wednesday-workingHours.pcap_ISCX.csv")
        ;;
      Thursday)
        labels=(
          "$DATA/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
          "$DATA/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv"
        )
        ;;
      Friday)
        labels=(
          "$DATA/Friday-WorkingHours-Morning.pcap_ISCX.csv"
          "$DATA/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
          "$DATA/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
        )
        ;;
    esac

    # Check the Python flow CSV.
    if [[ ! -f "$flow" ]]; then
        echo "SKIPPED: Python flow CSV missing: $flow"
        STATUS[$day]="MISSING FLOW CSV"
        continue
    fi

    # Check every labelled CSV required for this day.
    missing=0
    for file in "${labels[@]}"; do
        if [[ ! -f "$file" ]]; then
            echo "MISSING LABEL CSV: $file"
            missing=1
        fi
    done

    if [[ "$missing" -eq 1 ]]; then
        STATUS[$day]="MISSING LABEL CSV"
        continue
    fi

    # Step 4 uses Suricata alerts if eve.json exists.
    if [[ ! -f "output/$day/suricata/eve.json" ]]; then
        echo "WARNING: Suricata eve.json is missing for $day."
        echo "Step 4 may still run, but Suricata comparison will be skipped."
    fi

    if python step4_v4flows.py \
        --day "$day" \
        --flows "$flow" \
        --v3-csv "${labels[@]}" \
        2>&1 | tee "output_step4_${day}.log"; then

        if [[ -f "output/$day/v4/RESULTS_V4.md" ]]; then
            STATUS[$day]="SUCCESS"
        else
            STATUS[$day]="CHECK OUTPUT"
        fi
    else
        STATUS[$day]="FAILED"
    fi
done

echo
echo "======================================"
echo "STEP 4 SUMMARY"
echo "======================================"

for day in Monday Tuesday Wednesday Thursday Friday; do
    printf '%-12s %s\n' "$day" "${STATUS[$day]:-NOT RUN}"
done

echo
echo "Check output/<DAY>/v4/RESULTS_V4.md for each successful run."
