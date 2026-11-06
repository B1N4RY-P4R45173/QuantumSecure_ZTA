#!/usr/bin/env bash
#
# tunneling_vm3_random.sh – Tunneling / Covert Channels Traffic Generator
#
# • Duration: 600 s (10.0 min)
# • Random techniques:
#     - icmp_ptunnel   (ICMP tunneling with ptunnel)
#     - http_httptunnel (HTTP tunneling with httptunnel: htc/hts)
#     - ssh_dynamic    (SSH Dynamic Forwarding, -D)
# • Tools (VM3, attacker):
#     sudo apt update
#     sudo apt install -y ptunnel httptunnel openssh-client
#
# PREPARE VMX (victims):
#   # 1) HTTP on :80
#   sudo apt update
#   sudo apt install -y apache2
#   sudo systemctl enable apache2 --now
#
#   # 2) SSH on :22
#   sudo apt install -y openssh-server
#   sudo systemctl enable ssh --now
#
#   # 3) ptunnel server on ICMP
#   sudo apt install -y ptunnel
#   nohup ptunnel -lp 8000 -da 127.0.0.1 -dp 80 >/dev/null 2>&1 &
#
#   # 4) HTTP tunneling server (hts)
#   sudo apt install -y httptunnel
#   nohup hts -F 127.0.0.1:80 8080 >/dev/null 2>&1 &
#
# Capture on VMX (before launching script):
# sudo tcpdump -U -i enp0s3 -s0 -w - \
#   "(icmp or tcp port 22 or tcp port 80 or tcp port 8080) and net 192.168.56.0/24 \
#     and not host 192.168.56.107 and not port 9999" \
#   | nc -q 0 192.168.56.107 9999
#
# USAGE (VM3):
#   sudo ./tunneling_vm3_random.sh
#

if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo for virtual IPs" >&2
  exit 1
fi

missing=()
for cmd in ptunnel htc ssh; do
  command -v "$cmd" &>/dev/null || missing+=($cmd)
done

if (( ${#missing[@]} )); then
  echo "Missing: ${missing[*]}" >&2
  echo "Install: sudo apt update && sudo apt install -y ptunnel httptunnel openssh-client" >&2
  exit 1
fi

DURATION=1200
END=$((SECONDS + DURATION))
TARGETS=(192.168.56.101 192.168.56.102)
SRC_IPS=(192.168.56.{240..254})
iface="enp0s3"

for ip in ${SRC_IPS[@]}; do
  ip addr add "$ip"/24 dev "$iface" 2>/dev/null || :
done

techs=(icmp_ptunnel http_httptunnel ssh_dynamic)

cleanup() {
  for ip in ${SRC_IPS[@]}; do
    ip addr del "$ip"/24 dev "$iface" 2>/dev/null || :
  done
  pkill -P $$ 2>/dev/null || :
  echo "Cleanup complete."
}

trap cleanup EXIT INT TERM

worker_tunneling() {
  local worker_end=$1
  while (( SECONDS < worker_end )); do
    tech=${techs[RANDOM % ${#techs[@]}]}
    tgt=${TARGETS[RANDOM % ${#TARGETS[@]}]}
    src=${SRC_IPS[RANDOM % ${#SRC_IPS[@]}]}

    case "$tech" in
      icmp_ptunnel)
        timeout 1 ptunnel -p "$tgt" -lp $((RANDOM%10000+8000)) -da 127.0.0.1 -dp 80 >/dev/null 2>&1 &
        ;;

      http_httptunnel)
        timeout 1 htc "$tgt" 8080 >/dev/null 2>&1 &
        ;;

      ssh_dynamic)
        timeout 1 ssh -o ConnectTimeout=1 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -D $((RANDOM%10000+10000)) -N -q "user@$tgt" >/dev/null 2>&1 &
        ;;
    esac

    while (( $(jobs -r | wc -l) > 100 )); do sleep 0.1; done
    sleep 0.05
  done
}

echo "=== VM3: OPTIMIZED Tunneling (${DURATION}s) ==="

WORKERS=20
for worker in $(seq 1 $WORKERS); do
  worker_tunneling "$END" &
  echo "Worker $worker started (PID: $!)"
done

while (( SECONDS < END )); do
  sleep 0.05
done

wait
echo "=== OPTIMIZED Tunneling completed ==="
