#!/usr/bin/env bash
#
# expanded_vm3_services.sh – Configures multiple receiver services for exfiltration
#
set -e

echo "=== Configuring expanded services on VM3 ==="

# 1) Anonymous FTP (port 21)
echo "Configuring FTP..."
grep -q '^anonymous_enable=YES' /etc/vsftpd.conf || echo "anonymous_enable=YES" >> /etc/vsftpd.conf
grep -q '^write_enable=YES' /etc/vsftpd.conf || echo "write_enable=YES" >> /etc/vsftpd.conf
grep -q '^anon_upload_enable=YES' /etc/vsftpd.conf || echo "anon_upload_enable=YES" >> /etc/vsftpd.conf
mkdir -p /var/ftp/pub
chmod 777 /var/ftp/pub
systemctl enable --now vsftpd

# 2) TFTP (port 69)
echo "Configuring TFTP..."
mkdir -p /var/lib/tftpboot
chown nobody:nogroup /var/lib/tftpboot
chmod 777 /var/lib/tftpboot
cat >/etc/default/tftpd-hpa <<EOF
TFTP_USERNAME="tftp"
TFTP_DIRECTORY="/var/lib/tftpboot"
TFTP_ADDRESS=":69"
TFTP_OPTIONS="--secure --create"
EOF
systemctl enable --now tftpd-hpa

# 3) NFS (port 2049)
echo "Configuring NFS..."
mkdir -p /export
chmod 777 /export
grep -q '^/export' /etc/exports || echo "/export *(rw,no_root_squash,no_subtree_check)" >> /etc/exports
exportfs -a
systemctl enable --now nfs-kernel-server

# 4) Apache2 (port 80)
echo "Configuring Apache2..."
systemctl enable --now apache2
mkdir -p /var/www/html/upload
chmod 777 /var/www/html/upload

# 5) HTTPS with self-signed certificate (port 443)
echo "Configuring HTTPS..."
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/ssl/private/apache-selfsigned.key \
  -out /etc/ssl/certs/apache-selfsigned.crt \
  -subj "/C=ES/ST=Murcia/L=Cartagena/O=TestLab/OU=Security/CN=testlab.local"

cat >/etc/apache2/sites-available/ssl-exfil.conf <<EOF
<VirtualHost *:443>
    ServerName testlab.local
    DocumentRoot /var/www/html
    
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/apache-selfsigned.crt
    SSLCertificateKeyFile /etc/ssl/private/apache-selfsigned.key
    
    <Directory "/var/www/html/upload">
        Options Indexes
        AllowOverride None
        Require all granted
    </Directory>
</VirtualHost>
EOF

a2enmod ssl
a2ensite ssl-exfil
systemctl reload apache2


# 7) Multiple HTTP listeners on different ports
echo "Configuring multiple HTTP listeners..."
for port in 9092 9093 9094 9095; do
  echo "Starting listener on port $port..."
  nohup nc -lkvp $port > ~/exf_http_recv_${port}.bin 2>&1 &
done

# 8) Simulated SMTP (port 25)
echo "Configuring simulated SMTP..."
nohup nc -lkvp 25 > ~/exf_smtp_recv.bin 2>&1 &

# 9) Simulated POP3 (port 110)
echo "Configuring simulated POP3..."
nohup nc -lkvp 110 > ~/exf_pop3_recv.bin 2>&1 &

# 10) Simulated IMAP (port 143)
echo "Configuring simulated IMAP..."
nohup nc -lkvp 143 > ~/exf_imap_recv.bin 2>&1 &

# 11) SSH enabled (port 22) - only for attempt logging
echo "Configuring SSH..."
systemctl enable --now ssh

# 12) Listeners on high random ports
echo "Configuring listeners on random ports..."
for i in {1..5}; do
  port=$((8000 + RANDOM % 2000))
  echo "Listener on port $port"
  nohup nc -lkvp $port > ~/exf_random_${port}.bin 2>&1 &
done

# 13) UDP listeners for covert channels
echo "Configuring UDP listeners..."
for port in 1234 5678 9999; do
  echo "UDP listener on port $port"
  nohup nc -lukp $port > ~/exf_udp_${port}.bin 2>&1 &
done

# 14) Configure rsyslog to capture events
echo "Configuring logging..."
cat >>/etc/rsyslog.d/50-exfil.conf <<EOF
# Exfiltration event log
local0.* /var/log/exfil.log
# DNS queries log
local1.* /var/log/dns-exfil.log
# TCP connections log
local2.* /var/log/tcp-exfil.log
EOF

systemctl restart rsyslog

# 15) Real-time monitoring script
cat >/usr/local/bin/monitor-exfil.sh <<'EOF'
#!/bin/bash
echo "=== Exfiltration Monitoring ==="
echo "Received files:"
ls -la ~/*exf* 2>/dev/null | tail -20
echo ""
echo "Active connections:"
ss -tnlp | grep -E ':(21|22|25|53|69|80|110|143|443|9092|9093|9094|9095)'
echo ""
echo "Active nc processes:"
ps aux | grep "nc -" | grep -v grep
EOF

chmod +x /usr/local/bin/monitor-exfil.sh

# 16) Create directory for structured logs
mkdir -p /var/log/exfil-analysis
chmod 755 /var/log/exfil-analysis

echo "=== VM3 configured with expanded services ==="
echo ""
echo "Active services:"
ss -tnlp | grep -E ':(21|22|25|53|69|80|110|143|443|9092|9093|9094|9095)'
echo ""
echo "UDP listeners:"
ss -unlp | grep -E ':(53|1234|5678|9999)'
echo ""
echo "To monitor: /usr/local/bin/monitor-exfil.sh"
echo "Logs in: /var/log/exfil.log and ~/exf_*"
