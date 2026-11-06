#!/usr/bin/env bash
#
# portscan_vm3_random.sh (VERSIÓN PULIDA)
#  • Duración fija: 600 s (10 min)
#  • Técnicas aleatorias:
#      - nmap_syn, nmap_null, nmap_xmas, nmap_fin, nmap_decoy, nmap_fragment
#      - masscan_tcp, masscan_udp
#      - zmap_tcp
#      - hping3_null, hping3_xmas, hping3_fin, hping3_udp
#  • Herramientas: nmap, masscan, zmap, hping3
#  • Spoofing de IP: pool 192.168.56.240–254
#  • Targets: VM1 (192.168.56.101) y VM2 (192.168.56.102)
#  • NO benigno, NO otro tráfico mixto
#
# --- EN VM1, para capturar TODO el tráfico de la red y enviarlo a WSL ---
# sudo tcpdump -U -i enp0s3 -s0 -w - \
#   "(tcp or udp) and net 192.168.56.0/24 and not host 192.168.56.107 and not port 9999" \
#   | nc -q 0 192.168.56.107 9999
#
# Uso en VM3: sudo ./portscan_vm3_random.sh
#

# 1) Ejecutar como root
if [[ $EUID -ne 0 ]]; then
  echo "Este script debe ejecutarse con sudo"
  exit 1
fi

# 2) Verificar herramientas
MISSING=()
for t in nmap masscan zmap hping3; do
  command -v $t >/dev/null 2>&1 || MISSING+=($t)
done
if (( ${#MISSING[@]} )); then
  echo "Faltan: ${MISSING[*]}. Instalar con: sudo apt install ${MISSING[*]}"
fi

# 3) Variables
DUR=600
END=$((SECONDS + DUR))
TARGETS=(192.168.56.101 192.168.56.102)
SRC_IPS=(192.168.56.{240..254})

# 4) Técnicas según disponiblidad
TECH=()
command -v nmap    &>/dev/null && TECH+=(nmap_syn nmap_null nmap_xmas nmap_fin nmap_decoy nmap_fragment)
command -v masscan &>/dev/null && TECH+=(masscan_tcp masscan_udp)
command -v zmap    &>/dev/null && TECH+=(zmap_tcp)
command -v hping3  &>/dev/null && TECH+=(hping3_null hping3_xmas hping3_fin hping3_udp)

(( ${#TECH[@]} )) || { echo "No hay técnicas disponibles."; exit 1; }

# 5) Interfaz
IFACE=$(ip route | awk '/^default/ {print $5; exit}')
: "${IFACE:=enp0s3}"

echo "=== PortScan aleatorio (600s) en $IFACE ==="

# 6) Bucle principal
while (( SECONDS < END )); do
  T=${TECH[RANDOM % ${#TECH[@]}]}
  TG=${TARGETS[RANDOM % ${#TARGETS[@]}]}
  IP=${SRC_IPS[RANDOM % ${#SRC_IPS[@]}]}

  printf '[%(%T)T] %s → %s (%s)\n' -1 "$T" "$TG" "$IP"

  case "$T" in
    nmap_syn)
      P=$(shuf -i1-1024 -n10 | paste -sd, -)
      SP=$((1 + RANDOM%5))
      nmap -sS -T$SP -p"$P" -S "$IP" -e "$IFACE" -Pn "$TG" -oG /dev/null &;;
    nmap_null)
      P=$(shuf -i1-2000 -n8 | paste -sd, -)
      nmap -sN -p"$P" -S "$IP" -e "$IFACE" -Pn "$TG" -oG /dev/null &;;
    nmap_xmas)
      P=$(shuf -i1-443 -n6 | paste -sd, -)
      nmap -sX -p"$P" -S "$IP" -e "$IFACE" -Pn "$TG" -oG /dev/null &;;
    nmap_fin)
      P=$(shuf -i1-1024 -n12 | paste -sd, -)
      nmap -sF -p"$P" -S "$IP" -e "$IFACE" -Pn "$TG" -oG /dev/null &;;
    nmap_decoy)
      D=$(shuf -i240-254 -n3 | xargs -I{} printf "192.168.56.%s," {})
      P=$(shuf -i3000-4000 -n6 | paste -sd, -)
      nmap -sS -D "${D}${IP}" -p"$P" -e "$IFACE" -Pn "$TG" -oG /dev/null &;;
    nmap_fragment)
      P=$(shuf -i1-5000 -n7 | paste -sd, -)
      nmap -sS -f -p"$P" -S "$IP" -e "$IFACE" -Pn "$TG" -oG /dev/null &;;
    masscan_tcp)
      R=$((1000 + RANDOM%9000))
      P=$(shuf -i1-65535 -n10 | paste -sd, -)
      masscan "$TG" -p"$P" --rate "$R" --source-ip "$IP" --interface "$IFACE" > /dev/null 2>&1 &;;
    masscan_udp)
      R=$((500 + RANDOM%4500))
      P=$(shuf -i53-2000 -n8 | paste -sd, -)
      masscan "$TG" -pU:"$P" --rate "$R" --source-ip "$IP" --interface "$IFACE" > /dev/null 2>&1 &;;
    zmap_tcp)
      PR=$(shuf -i1-1024 -n1)
      BR=${RANDOM%10+1}M
      zmap -p "$PR" -B "$BR" --source-ip="$IP" --interface="$IFACE" "$TG" > /dev/null 2>&1 &;;
    hping3_null)
      PR=$(shuf -i1-1024 -n1); C=$((10+RANDOM%20))
      hping3 --count $C -p $PR --sign 0 --spoof "$IP" -I "$IFACE" "$TG" > /dev/null 2>&1 &;;
    hping3_xmas)
      PR=$(shuf -i1-1024 -n1); C=$((10+RANDOM%20))
      hping3 --count $C -p $PR -F -P -U --spoof "$IP" -I "$IFACE" "$TG" > /dev/null 2>&1 &;;
    hping3_fin)
      PR=$(shuf -i1-1024 -n1); C=$((10+RANDOM%20))
      hping3 --count $C -p $PR -F --spoof "$IP" -I "$IFACE" "$TG" > /dev/null 2>&1 &;;
    hping3_udp)
      PR=$(shuf -i1-1024 -n1); C=$((10+RANDOM%20))
      hping3 --udp --count $C -p $PR --spoof "$IP" -I "$IFACE" "$TG" > /dev/null 2>&1 &;;
  esac

  # Limitar procesos pendientes
  while (( $(jobs -r | wc -l) > 20 )); do sleep 0.1; done

  # Pausa aleatoria con punto decimal
  PAUSE=$(LC_NUMERIC=C awk -v min=0.05 -v max=0.25 'BEGIN{srand(); printf "%.3f", min+rand()*(max-min)}')
  sleep "$PAUSE"
done

wait
echo "=== PortScan finalizado ==="

