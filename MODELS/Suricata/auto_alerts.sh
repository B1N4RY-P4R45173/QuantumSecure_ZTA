#!/bin/bash

for day in Monday Tuesday Wednesday Thursday Friday; do
    pcap="../../DataSet/${day}-WorkingHours.pcap"

    if [ ! -f "$pcap" ]; then
        echo "WARNING: Missing $pcap — skipping"
        continue
    fi

    echo "======================================"
    echo "Running Suricata for $day"
    echo "======================================"

    python step1_suricata.py \
        --day "$day" \
        --pcap "$pcap" \
        --runmode single

    if [ $? -ne 0 ]; then
        echo "ERROR: Suricata failed for $day"
        exit 1
    fi
done

echo "All available days processed."