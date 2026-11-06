#!/usr/bin/env bash
#
# bufferoverflow_vm3_random.sh – Ultimate Buffer Overflow Traffic Generator
# • Duration: 600 s (10 min)
# • Random techniques:
#     - raw_tcp       (netcat)
#     - hping3_frag   (fragmented, -f)
#     - scapy_raw     (Scapy Python)
#     - http_get      (overflow in GET)
#     - http_post     (overflow in POST)
#     - http_header   (overflow in HTTP header)
#     - ftp_login     (USER/PASS overflow in FTP:21)
#     - pop3_login    (USER/PASS overflow in POP3:110)
#     - smtp_cmd      (MAIL FROM overflow in SMTP:25)
#     - imap_login    (LOGIN overflow in IMAP:143)
# • Tools: netcat-openbsd, hping3, python3-scapy, curl, openssl
# • Virtual Source IPs: 192.168.56.240–254
# • Targets: 192.168.56.101, 192.168.56.102
# • BO traffic only, no benign or other attacks
#
# VM1 captures BO ports (21,25,80,110,143,9090) and sends them to the capture machine.
# USAGE: sudo ./bufferoverflow_vm3_random.sh

### 1) Root check
if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo to create virtual IPs" >&2
  exit 1
fi

### 2) Dependencies
missing=()
for cmd in nc hping3 python3 curl openssl; do
  command -v "$cmd" &>/dev/null || missing+=("$cmd")
done
if (( ${#missing[@]} )); then
  echo "Missing: ${missing[*]}. Install with:" >&2
  echo "  sudo apt update && sudo apt install -y netcat-openbsd hping3 python3-scapy curl openssl" >&2
  exit 1
fi

### 3) Parameters
DURATION=1200
END=$(( $(date +%s) + DURATION ))
TARGETS=(192.168.56.101 192.168.56.102)
SRC_IPS=(192.168.56.{240..254})
IFACE="enp0s3"
PORT_BO=9090
TECHS=(raw_tcp hping3_frag scapy_raw http_get http_post http_header ftp_login pop3_login smtp_cmd imap_login)
WORKERS=40
MAX_JOBS=200

### 4) Create virtual IPs
for ip in "${SRC_IPS[@]}"; do
  ip addr add "${ip}/24" dev "$IFACE" 2>/dev/null || :
done

### 5) Cleanup on exit
cleanup(){
  pkill -P $$ &>/dev/null || :
  for ip in "${SRC_IPS[@]}"; do
    ip addr del "${ip}/24" dev "$IFACE" 2>/dev/null || :
  done
  echo "Cleanup completed."
}
trap cleanup EXIT INT TERM

### 6) Payload generator
generate_payload(){
  openssl rand -hex "$1" 2>/dev/null || echo "00"
}

### 7) BufferOverflow Worker
worker_bo(){
  local end_time=$1
  # Each worker shares the same wall clock
  while (( $(date +%s) < end_time )); do
    tech=${TECHS[RANDOM % ${#TECHS[@]}]}
    tgt=${TARGETS[RANDOM % ${#TARGETS[@]}]}
    src=${SRC_IPS[RANDOM % ${#SRC_IPS[@]}]}
    len_long=$((500 + RANDOM % 1500))
    len_short=$((50 + RANDOM % 200))

    case "$tech" in

      raw_tcp)
        generate_payload "$len_long" \
          | nc -q1 -s "$src" "$tgt" "$PORT_BO" &>/dev/null || :
        ;;

      hping3_frag)
        tmpf=$(mktemp)
        generate_payload "$len_long" > "$tmpf"
        hping3 -c1 -f -p "$PORT_BO" -E "$tmpf" -a "$src" -I "$IFACE" "$tgt" &>/dev/null || :
        rm -f "$tmpf"
        ;;

      scapy_raw)
        # ignore Scapy errors
        python3 - <<EOF &>/dev/null || :
from scapy.all import IP,TCP,Raw,send
pkt = IP(src='$src',dst='$tgt')/TCP(dport=$PORT_BO,flags='PA')/Raw(b'A'*$len_long)
send(pkt, count=1, verbose=False)
EOF
        ;;

      http_get)
        payload=$(generate_payload "$len_long")
        curl -s --interface "$IFACE" "http://$tgt/?p=$payload" &>/dev/null || :
        ;;

      http_post)
        payload=$(generate_payload "$len_long")
        curl -s --interface "$IFACE" -X POST -d "$payload" "http://$tgt/" &>/dev/null || :
        ;;

      http_header)
        payload=$(generate_payload "$len_long")
        printf 'GET / HTTP/1.1\r\nHost: %s\r\nX-Overflow: %s\r\n\r\n' "$tgt" "$payload" \
          | nc -q1 -s "$src" "$tgt" 80 &>/dev/null || :
        ;;

      ftp_login)
        payload=$(generate_payload "$len_long")
        {
          echo "USER anonymous"
          echo "PASS $payload"
          echo "QUIT"
        } | nc -q1 -s "$src" "$tgt" 21 &>/dev/null || :
        ;;

      pop3_login)
        payload=$(generate_payload "$len_long")
        {
          echo "USER $payload"
          echo "PASS $payload"
          echo "QUIT"
        } | nc -q1 -s "$src" "$tgt" 110 &>/dev/null || :
        ;;

      smtp_cmd)
        payload=$(generate_payload "$len_long")
        {
          echo "HELO test"
          echo "MAIL FROM:<$payload@test.com>"
          echo "QUIT"
        } | nc -q1 -s "$src" "$tgt" 25 &>/dev/null || :
        ;;

      imap_login)
        payload=$(generate_payload "$len_long")
        printf "A001 LOGIN %s %s\r\n" "$payload" "$payload" \
          | nc -q1 -s "$src" "$tgt" 143 &>/dev/null || :
        ;;
    esac

    # Limit jobs in each worker
    while (( $(jobs -r | wc -l) > MAX_JOBS )); do
      sleep 0.01
    done
    sleep 0.01
  done
}

### 8) Launch workers and wait
echo "Starting BufferOverflow Enhanced with $WORKERS workers for ${DURATION}s"
for i in $(seq 1 $WORKERS); do
  worker_bo "$END" & 
  echo "Worker $i (PID $!)"
done

wait
echo "BufferOverflow Enhanced completed."
