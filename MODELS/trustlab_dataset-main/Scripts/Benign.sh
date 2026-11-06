#!/usr/bin/env bash
#
# benign_traffic_enhanced.sh – Enhanced Benign Traffic with Multiple Workers
#
# Improvements:
#   • Multiple parallel workers (configurable)
#   • More realistic traffic patterns
#   • Different intensities per service type
#   • User session simulation
#   • Automatic maintenance traffic
#   • User-agent and pattern rotation
#   • Advanced process management
#
# Duration: 600 s (10.0 min) default
# Workers: 4 default (configurable)

export LC_NUMERIC=C
export LANG=C

# 1) Root only
if (( EUID != 0 )); then
  echo "Run with sudo" >&2
  exit 1
fi

# 2) Configuration
DURATION=${1:-12000}
NUM_WORKERS=${2:-80}
INTENSITY=${3:-high}  # low, medium, high

# Realistic configuration arrays
declare -a USER_AGENTS=(
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
  "curl/7.68.0"
  "wget/1.20.3"
)

declare -a HTTP_PATHS=(
  "/"
  "/index.html"
  "/about"
  "/contact"
  "/api/status"
  "/health"
  "/robots.txt"
  "/favicon.ico"
  "/css/style.css"
  "/js/app.js"
  "/images/logo.png"
)

declare -a DNS_QUERIES=(
  "google.com"
  "example.com"
  "wikipedia.org"
  "github.com"
  "stackoverflow.com"
  "ubuntu.com"
  "debian.org"
)

# Intensity configuration
case $INTENSITY in
  low)    MIN_DELAY=2.0; MAX_DELAY=5.0; BURST_CHANCE=5  ;;
  medium) MIN_DELAY=0.5; MAX_DELAY=3.0; BURST_CHANCE=15 ;;
  high)   MIN_DELAY=0.1; MAX_DELAY=1.5; BURST_CHANCE=25 ;;
  *)      MIN_DELAY=0.5; MAX_DELAY=3.0; BURST_CHANCE=15 ;;
esac

# 3) Host detection
#all_hosts=(192.168.56.101 192.168.56.102 192.168.56.103)
all_hosts=(192.168.56.101 192.168.56.102)
local_ip=$(hostname -I | awk '{print $1}')
hosts=()
for h in "${all_hosts[@]}"; do
  [[ $h != "$local_ip" ]] && hosts+=("$h")
done

if [[ ${#hosts[@]} -eq 0 ]]; then
  echo "Error: No remote hosts available" >&2
  exit 1
fi

# Global variables
declare -a WORKER_PIDS=()
END_TIME=$(( SECONDS + DURATION ))
MNT_BASE="/mnt/benign_tmp"
mkdir -p "$MNT_BASE"

# 4) Utility functions
random_delay() {
  awk -v min="$MIN_DELAY" -v max="$MAX_DELAY" \
    'BEGIN{srand(); printf "%.2f", min+rand()*(max-min)}'
}

random_choice() {
  local -n arr=$1
  echo "${arr[RANDOM % ${#arr[@]}]}"
}

log_activity() {
  local worker_id=$1
  local action=$2
  local target=$3
  local ts=$(date +%T)
  printf '[W%d %s] %s → %s\n' "$worker_id" "$ts" "$action" "$target"
}

# 5) Main worker function
worker_main() {
  local worker_id=$1
  local operations=(
    "ping:5"        # weight 5
    "http_get:15"   # weight 15
    "http_post:5"
    "http_head:3"
    "dns_query:10"
    "ssh_cmd:8"
    "scp_file:3"
    "ftp_list:4"
    "smtp_send:2"
    "mysql_query:3"
    "redis_ping:4"
    "snmp_get:2"
    "ntp_query:1"
  )
  
  # Create weighted operation pool
  local op_pool=()
  for op_weight in "${operations[@]}"; do
    IFS=':' read -r op weight <<< "$op_weight"
    for ((i=0; i<weight; i++)); do
      op_pool+=("$op")
    done
  done
  
  while (( SECONDS < END_TIME )); do
    local target=${hosts[RANDOM % ${#hosts[@]}]}
    local operation=$(random_choice op_pool)
    
    # Execute operation
    case $operation in
      ping)
        log_activity "$worker_id" "ping" "$target"
        timeout 3 ping -c1 -W1 "$target" &>/dev/null
        ;;
        
      http_get)
        local path=$(random_choice HTTP_PATHS)
        local ua=$(random_choice USER_AGENTS)
        log_activity "$worker_id" "http GET $path" "$target"
        timeout 5 curl -s -A "$ua" --connect-timeout 2 "http://$target$path" &>/dev/null
        ;;
        
      http_post)
        local ua=$(random_choice USER_AGENTS)
        local data="user=test$worker_id&action=submit&timestamp=$(date +%s)"
        log_activity "$worker_id" "http POST" "$target"
        timeout 5 curl -s -A "$ua" -X POST --data "$data" --max-time 3 "http://$target/api/data" &>/dev/null
        ;;
        
      http_head)
        log_activity "$worker_id" "http HEAD" "$target"
        timeout 3 curl -I -s --connect-timeout 2 "http://$target/" &>/dev/null
        ;;
        
      dns_query)
        local domain=$(random_choice DNS_QUERIES)
        log_activity "$worker_id" "DNS query $domain" "$target"
        timeout 3 dig @"$target" "$domain" A +time=1 +tries=1 &>/dev/null
        ;;
        
      ssh_cmd)
        local cmds=("uptime" "whoami" "date" "df -h" "free -m")
        local cmd=${cmds[RANDOM % ${#cmds[@]}]}
        log_activity "$worker_id" "ssh $cmd" "$target"
        timeout 10 sshpass -p benign ssh -o StrictHostKeyChecking=no \
          -o ConnectTimeout=3 benign@"$target" "$cmd" &>/dev/null
        ;;
        
      scp_file)
        log_activity "$worker_id" "scp download" "$target"
        timeout 10 scp -o StrictHostKeyChecking=no -o ConnectTimeout=3 \
          benign@"$target":/var/www/html/index.html "/tmp/w${worker_id}_file.tmp" &>/dev/null
        rm -f "/tmp/w${worker_id}_file.tmp"
        ;;
        
      ftp_list)
        log_activity "$worker_id" "ftp list" "$target"
        timeout 8 ftp -niv "$target" <<EOF &>/dev/null
user anonymous worker$worker_id@test.com
ls
quit
EOF
        ;;
        
      smtp_send)
        log_activity "$worker_id" "smtp send" "$target"
        timeout 10 bash -c "echo 'Test from worker $worker_id at $(date)' | \
          mail -s 'Benign test W$worker_id' benign@$target" &>/dev/null
        ;;
        
      mysql_query)
        local queries=("SHOW DATABASES;" "SELECT NOW();" "SHOW PROCESSLIST;")
        local query=${queries[RANDOM % ${#queries[@]}]}
        log_activity "$worker_id" "mysql query" "$target"
        timeout 5 mysql -h "$target" -e "$query" &>/dev/null
        ;;
        
      redis_ping)
        log_activity "$worker_id" "redis ping" "$target"
        timeout 3 redis-cli -h "$target" PING &>/dev/null
        ;;
        
      snmp_get)
        local oids=("SNMPv2-MIB::sysDescr.0" "SNMPv2-MIB::sysUpTime.0" "SNMPv2-MIB::sysName.0")
        local oid=${oids[RANDOM % ${#oids[@]}]}
        log_activity "$worker_id" "snmp get $oid" "$target"
        timeout 5 snmpget -v2c -c public "$target" "$oid" &>/dev/null
        ;;
        
      ntp_query)
        log_activity "$worker_id" "ntp query" "$target"
        timeout 5 ntpdate -q "$target" &>/dev/null
        ;;
    esac
    
    # Realistic pause with burst chance
    if (( RANDOM % 100 < BURST_CHANCE )); then
      # Burst: multiple fast operations
      sleep 0.1
    else
      # Normal pause
      sleep $(random_delay)
    fi
  done
  
  log_activity "$worker_id" "worker finished" "all"
}

# 6) Worker specialized in web sessions
web_session_worker() {
  local worker_id=$1
  
  while (( SECONDS < END_TIME )); do
    local target=${hosts[RANDOM % ${#hosts[@]}]}
    local ua=$(random_choice USER_AGENTS)
    
    log_activity "$worker_id" "web session start" "$target"
    
    # Simulate typical browsing session
    local session_pages=("/" "/about" "/contact" "/products" "/services")
    for page in "${session_pages[@]}"; do
      (( SECONDS >= END_TIME )) && break
      
      timeout 5 curl -s -A "$ua" --connect-timeout 2 "http://$target$page" &>/dev/null
      sleep $(awk 'BEGIN{srand(); printf "%.1f", 1+rand()*3}')  # 1-4s between pages
      
      # Chance to download static resources
      if (( RANDOM % 3 == 0 )); then
        timeout 3 curl -s -A "$ua" "http://$target/css/style.css" &>/dev/null
      fi
    done
    
    log_activity "$worker_id" "web session end" "$target"
    sleep $(awk 'BEGIN{srand(); printf "%.1f", 10+rand()*20}')  # 10-30s between sessions
  done
}

# 7) Maintenance traffic worker
maintenance_worker() {
  local worker_id=$1
  
  while (( SECONDS < END_TIME )); do
    local target=${hosts[RANDOM % ${#hosts[@]}]}
    
    # Typical maintenance activities
    local activities=(
      "health_check"
      "log_rotation"
      "backup_status"
      "disk_usage"
      "service_status"
    )
    
    local activity=${activities[RANDOM % ${#activities[@]}]}
    
    case $activity in
      health_check)
        log_activity "$worker_id" "health check" "$target"
        timeout 3 curl -s "http://$target/health" &>/dev/null
        timeout 3 curl -s "http://$target/api/status" &>/dev/null
        ;;
      log_rotation)
        log_activity "$worker_id" "log check" "$target"
        timeout 8 sshpass -p benign ssh -o StrictHostKeyChecking=no \
          benign@"$target" "ls -la /var/log/ | head -10" &>/dev/null
        ;;
      backup_status)
        log_activity "$worker_id" "backup check" "$target"
        timeout 8 sshpass -p benign ssh -o StrictHostKeyChecking=no \
          benign@"$target" "df -h /var/backups" &>/dev/null
        ;;
      disk_usage)
        log_activity "$worker_id" "disk usage" "$target"
        timeout 8 sshpass -p benign ssh -o StrictHostKeyChecking=no \
          benign@"$target" "df -h" &>/dev/null
        ;;
      service_status)
        log_activity "$worker_id" "service check" "$target"
        timeout 8 sshpass -p benign ssh -o StrictHostKeyChecking=no \
          benign@"$target" "systemctl status apache2" &>/dev/null
        ;;
    esac
    
    sleep $(awk 'BEGIN{srand(); printf "%.1f", 30+rand()*60}')  # 30-90s between activities
  done
}

# 8) Cleanup function
cleanup() {
  echo "Terminating workers..."
  for pid in "${WORKER_PIDS[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      kill -TERM "$pid" 2>/dev/null
    fi
  done
  
  # Wait for them to finish
  sleep 2
  
  # Force if necessary
  for pid in "${WORKER_PIDS[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      kill -KILL "$pid" 2>/dev/null
    fi
  done
  
  # Clean temporary mounts
  for dir in "$MNT_BASE"/*; do
    [[ -d "$dir" ]] && umount "$dir" 2>/dev/null
  done
  rmdir "$MNT_BASE" 2>/dev/null
  
  echo "=== Benign traffic completed ==="
}

# Configure signals
trap cleanup EXIT INT TERM

# 9) Launch workers
echo "=== Starting enhanced benign traffic ==="
echo "Duration: ${DURATION}s | Workers: ${NUM_WORKERS} | Intensity: ${INTENSITY}"
echo "Target hosts: ${hosts[*]}"
echo "From: $local_ip"
echo

# Main workers
for ((i=1; i<=NUM_WORKERS-2; i++)); do
  worker_main "$i" &
  WORKER_PIDS+=($!)
done

# Web session specialized worker
web_session_worker $((NUM_WORKERS-1)) &
WORKER_PIDS+=($!)

# Maintenance worker
maintenance_worker "$NUM_WORKERS" &
WORKER_PIDS+=($!)

echo "Workers launched: ${WORKER_PIDS[*]}"

# 10) Wait for completion
wait

exit 0
