#!/usr/bin/env bash
#
# c2beaconing_vm3_enhanced.sh – C2 & Beaconing Traffic Generator (Enhanced)
# • Duration: 600 s (10 min)
# • Realistic C2/Beaconing techniques:
#     - http_beacon      (curl with real User-Agents)
#     - https_beacon     (curl with SNI and certs)
#     - dns_beacon       (dig with DGA domains)
#     - mqtt_beacon      (mosquitto_pub)
#     - irc_beacon       (netcat)
#     - ws_beacon        (Python websockets)
#     - icmp_beacon      (ping with hidden data)
#     - ftp_beacon       (ftp with C2 commands)
#     - ssh_beacon       (ssh with tunnels)
#     - tcp_beacon       (netcat raw TCP)
#     - udp_beacon       (netcat raw UDP)
#     - ntp_beacon       (ntpdate with hidden data)
#     - pop3_beacon      (telnet POP3)
#     - smtp_beacon      (telnet SMTP)
#     - tftp_beacon      (tftp real RRQ)
# • Realistic features:
#     - Variable jitter in intervals
#     - Real malware User-Agents
#     - Algorithmically Generated Domains (DGA)
#     - Encoded payloads (base64, hex)
#     - Irregular beaconing patterns
#     - Different payload sizes
# • IP source spoofs: 192.168.56.240–254
# • Targets on VM1/VM2 with specific ports
#

set -euo pipefail

## CONFIGURATION ##
DURATION=5                        # total seconds
END_TIME=$(( SECONDS + DURATION ))
WORKERS=300                         # more workers for more flows
MAX_JOBS=30                         # more concurrent jobs
SRC_IPS=(192.168.56.240 192.168.56.241 192.168.56.242 192.168.56.243 192.168.56.244 192.168.56.245)
TARGETS=(192.168.56.101 192.168.56.102)
TECHS=(http_beacon https_beacon dns_beacon mqtt_beacon irc_beacon ws_beacon icmp_beacon ftp_beacon ssh_beacon tcp_beacon udp_beacon ntp_beacon pop3_beacon smtp_beacon tftp_beacon)
LOG_DIR="/tmp/c2beacons_enhanced_$(date +%Y%m%d_%H%M%S)"

# Each worker calculates its END inside the subshell for local SECONDS

# Real known malware User-Agents
USER_AGENTS=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)"
    "python-requests/2.25.1"
    "curl/7.68.0"
    "Wget/1.20.3"
    "Go-http-client/1.1"
    "Apache-HttpClient/4.5.13"
)

# Simulated DGA Domains
DGA_DOMAINS=(
    "a8f3k2x9.beacon.com"
    "m9j4l7q2.c2server.net"
    "x7k2f9m4.command.org"
    "q3n8r5t1.control.info"
    "w6y9u2i5.malware.biz"
)

mkdir -p "$LOG_DIR"
echo "=== Enhanced C2/Beaconing High-Throughput ==="
echo "DURATION=$DURATION s | WORKERS=$WORKERS | MAX_JOBS=$MAX_JOBS"
echo "Targets: ${TARGETS[*]} | Srcs: ${SRC_IPS[*]}"
echo "Techniques: ${#TECHS[@]} | Log dir: $LOG_DIR"

timestamp(){ date +"%F %T"; }

## DEPENDENCIES ##
for cmd in curl dig mosquitto_pub nc python3 ping; do
    command -v "$cmd" &>/dev/null || echo "WARNING: $cmd not found - some technique might fail"
done
# verify websockets without aborting
python3 - <<'EOF' || echo "WARNING: websockets module not found"
try: import websockets
except: import sys; sys.exit(1)
EOF

## GENERATORS ##
random_string(){ openssl rand -hex $((RANDOM % 20 + 5)); }
random_base64(){ openssl rand -base64 $((RANDOM % 50 + 10)); }
random_user_agent(){ echo "${USER_AGENTS[RANDOM % ${#USER_AGENTS[@]}]}"; }
random_dga_domain(){ echo "${DGA_DOMAINS[RANDOM % ${#DGA_DOMAINS[@]}]}"; }
random_lang(){ 
  langs=("en-US,en;q=0.9" "es-ES,es;q=0.8" "pt-BR,pt;q=0.7")
  echo "${langs[RANDOM % ${#langs[@]}]}"
}

## BEACON FUNCTIONS ##
http_beacon(){
    local payload=$(random_string)
    curl -s --interface "$SRC" \
         -A "$(random_user_agent)" \
         -H "Accept-Language: $(random_lang)" \
         "http://$TGT:8080/api/v1/check?id=$payload&ts=$(date +%s)" \
         -H "X-Session: $(random_base64)" &>/dev/null &
}
https_beacon(){
    local payload=$(random_base64)
    curl -s --interface "$SRC" \
         -A "$(random_user_agent)" \
         "https://$TGT:8443/secure/heartbeat" \
         -d "{\"data\":\"$payload\",\"ts\":$(date +%s)}" \
         -H "Content-Type: application/json" &>/dev/null &
}
dns_beacon(){
    local sub=$(random_string | cut -c1-8)
    local dom=$(random_dga_domain)
    dig @$TGT -p 5300 "$sub.$dom" A +short &>/dev/null &
}
mqtt_beacon(){
    mosquitto_pub -h "$TGT" -p 1883 -t "beacon/$(random_string | cut -c1-6)" -m "$(random_base64)" &>/dev/null &
}
irc_beacon(){
    {
      echo "NICK bot_$(random_string | cut -c1-5)"
      echo "USER bot 0 * :bot"
      echo "JOIN #c2"
      echo "PRIVMSG #c2 :$(random_base64)"
      echo "QUIT"
    } | nc -q2 "$TGT" 6667 &>/dev/null &
}
ws_beacon(){
    python3 - <<PYCODE &>/dev/null &
import asyncio, websockets
async def b():
    try:
        async with websockets.connect(f'ws://{"$TGT"}:8000') as ws:
            await ws.send('BEACON:'+ '$(random_base64)')
            await asyncio.sleep(0.1)
    except: pass
asyncio.run(b())
PYCODE
}
icmp_beacon(){
    ping -c1 -W1 -s$((RANDOM%100+32)) "$TGT" &>/dev/null &
}
ftp_beacon(){
    {
      echo "USER anon"
      echo "PASS $(random_string)"
      echo "QUIT"
    } | nc -q2 "$TGT" 21 &>/dev/null &
}
ssh_beacon(){
    timeout 2 ssh -oBatchMode=yes -oConnectTimeout=1 \
            -oStrictHostKeyChecking=no "$TGT" echo &>/dev/null &
}
tcp_beacon(){
    echo "$(random_base64)" | nc -q1 "$TGT" $((8000+RANDOM%100)) &>/dev/null &
}
udp_beacon(){
    echo "$(random_string)" | nc -u -q1 "$TGT" $((9000+RANDOM%100)) &>/dev/null &
}
ntp_beacon(){
  timeout 2 ntpdate -q "$TGT" &>/dev/null
}
pop3_beacon(){
    {
      echo "USER user"
      echo "PASS $(random_string)"
      echo "QUIT"
    } | nc -q2 "$TGT" 110 &>/dev/null &
}
smtp_beacon(){
    {
      echo "HELO $(random_string).com"
      echo "MAIL FROM:<bot@evil.com>"
      echo "RCPT TO:<c2@server.net>"
      echo "DATA"
      echo "$(random_base64)"
      echo "."
      echo "QUIT"
    } | nc -q2 "$TGT" 25 &>/dev/null &
}
tftp_beacon(){
    local fn=$(random_string|cut -c1-8)
    printf '\x00\x01%s\0octet\0' "$fn" | nc -u -w1 "$TGT" 69 &>/dev/null &
}

## CONCURRENCY CONTROL ##
check_jobs(){
  local n
  # jobs -r doesn't fail, redirect errors
  n=$(jobs -r 2>/dev/null | wc -l)
  while (( n >= MAX_JOBS )); do
    sleep 0.2
    n=$(jobs -r 2>/dev/null | wc -l)
  done
}

## ENHANCED WORKER ##
worker(){
  local id=$1 bc=0 end=$((SECONDS+DURATION))
  echo "[$(timestamp)] Worker $id started" >> "$LOG_DIR/worker$id.log"
  while (( SECONDS < end )); do
    TGT=${TARGETS[RANDOM%${#TARGETS[@]}]}
    SRC=${SRC_IPS[RANDOM%${#SRC_IPS[@]}]}
    TECH=${TECHS[RANDOM%${#TECHS[@]}]}
    echo "[$(timestamp)] W$id:$TECH->$TGT(src:$SRC)[#$bc]" | tee -a "$LOG_DIR/worker$id.log"
    if declare -f $TECH &>/dev/null; then
      $TECH &
      ((bc++))
    fi
    check_jobs
    # realistic jitter
    # realistic jitter: 5% pauses of 30–60 s, 95% of 0.5–5 s
    if (( RANDOM % 20 == 0 )); then
        jitter=$(awk 'BEGIN{srand(); printf "%.2f", 1 + rand()*20}')
    else
        jitter=$(awk 'BEGIN{srand(); printf "%.2f", 0.5 + rand()*2.5}')
    fi
    sleep "$jitter"
    (( bc % 50 == 0 )) && echo "[$(timestamp)] W$id: $bc beacons" >> "$LOG_DIR/worker$id.log"
  done
  echo "[W$id] finished: $bc beacons in $((SECONDS-end))s" | tee -a "$LOG_DIR/worker$id.log"
}

## LAUNCH WORKERS ##
echo "Starting $WORKERS workers..."
for i in $(seq 1 $WORKERS); do
  worker $i &
  echo "Worker $i PID:$!"
  sleep 0.15
done
