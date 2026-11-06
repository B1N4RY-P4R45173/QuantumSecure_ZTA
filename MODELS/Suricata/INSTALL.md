# Installing and setting up Suricata (Linux and Windows)

Suricata is free and open source (GPLv2), made by the OISF. You install it; you do not build it.
Official docs: https://docs.suricata.io

| OS | Best for |
|---|---|
| **Linux / WSL** | This project. `step1_suricata.py` and `run_day.sh` need Linux |
| **Windows (native)** | Trying Suricata, or watching a Windows PC's own network card |

---

## Linux

### 1. Install

**Kali** (Suricata is in the normal Kali repository):
```bash
sudo apt update
sudo apt install -y suricata
```

**Ubuntu / WSL Ubuntu** (the OISF PPA has the newest stable version):
```bash
sudo apt update
sudo apt install -y software-properties-common
sudo add-apt-repository -y ppa:oisf/suricata-stable
sudo apt update
sudo apt install -y suricata
```

**Debian**:
```bash
sudo apt install -y suricata
```

Check it worked:
```bash
suricata -V
```

> For this project you can skip steps 1 and 2: `bash setup_wsl.sh` does both and also builds the Python environment.

### 2. Download the rules

Suricata has no rules after install. `suricata-update` downloads the free **ET Open** rule set:
```bash
sudo suricata-update
```
Rules are saved to `/var/lib/suricata/rules/suricata.rules`. Run it again any time to get new rules.

Optional: see other free rule sources.
```bash
sudo suricata-update list-sources
sudo suricata-update enable-source <name>
sudo suricata-update
```

### 3. Configure

The main settings file is `/etc/suricata/suricata.yaml`. Check these 3 things:

| Setting | Set it to |
|---|---|
| `HOME_NET` | Your own network, e.g. `"[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"` |
| `default-rule-path` | `/var/lib/suricata/rules` |
| `rule-files` | `- suricata.rules` |

For live capture, also set your network card under `af-packet:` → `interface:` (find its name with `ip a`, e.g. `eth0`).

Test the settings (no traffic is read):
```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```

### 4. Run

**On a pcap file** (what this project does):
```bash
suricata -c /etc/suricata/suricata.yaml -r traffic.pcap -k none -l ./out
```
`-k none` stops Suricata dropping packets with bad checksums, which is common in recorded captures.

**On a live network card:**
```bash
sudo suricata -c /etc/suricata/suricata.yaml -i eth0
# or as a background service
sudo systemctl enable --now suricata      # Kali/WSL without systemd: sudo service suricata start
```

### 5. Check that alerts appear

While Suricata watches a live card, run:
```bash
curl http://testmynids.org/uid/index.html
```
Then:
```bash
sudo tail -f /var/log/suricata/fast.log
```
You should see `GPL ATTACK_RESPONSE id check returned root`. The full details are in `/var/log/suricata/eve.json`.

---

## Windows (native)

### 1. Install Npcap first

Suricata on Windows needs **Npcap** to read network cards.
- Download it from https://npcap.com
- During install, tick **"Install Npcap in WinPcap API-compatible Mode"**

### 2. Install Suricata

- Download the Windows installer (`.msi`) from https://suricata.io/download/
- Run it. The default folder is `C:\Program Files\Suricata\`

Check it worked (in PowerShell):
```powershell
cd "C:\Program Files\Suricata"
.\suricata.exe -V
```

### 3. Download the rules

`suricata-update` is not included on Windows. Choose one way:

**A. With Python (if installed):**
```powershell
pip install suricata-update
suricata-update -D "C:\Program Files\Suricata" --suricata-conf "C:\Program Files\Suricata\suricata.yaml" -o "C:\Program Files\Suricata\rules"
```

**B. By hand:** download `emerging.rules.tar.gz` for your Suricata version from
https://rules.emergingthreats.net/open/ (e.g. `suricata-7.0/`), extract it, and copy the `.rules` files into
`C:\Program Files\Suricata\rules\`.

### 4. Configure

Open `C:\Program Files\Suricata\suricata.yaml` as administrator and check:

| Setting | Set it to |
|---|---|
| `HOME_NET` | Your own network, e.g. `"[192.168.0.0/16]"` |
| `default-rule-path` | `C:\Program Files\Suricata\rules` |
| `rule-files` | `- suricata.rules` (method A) or the `.rules` files you copied (method B) |

Test the settings:
```powershell
.\suricata.exe -T -c suricata.yaml -v
```

### 5. Run

Open PowerShell **as administrator**, in `C:\Program Files\Suricata`.

**On a pcap file:**
```powershell
.\suricata.exe -c suricata.yaml -r D:\path\traffic.pcap -k none -l .\log
```

**On a live network card:** on Windows, `-i` takes the card's **IP address** (find it with `ipconfig`):
```powershell
.\suricata.exe -c suricata.yaml -i 192.168.1.10
```

### 6. Check that alerts appear

While it runs on the live card, open http://testmynids.org/uid/index.html in a browser, then look in
`C:\Program Files\Suricata\log\fast.log` for `GPL ATTACK_RESPONSE id check returned root`.

---

## Common problems

| Problem | Fix |
|---|---|
| `No rule files match` / 0 rules loaded | Run `suricata-update` (Linux) or check `default-rule-path` and `rule-files` |
| No alerts on a pcap | Add `-k none`; check `HOME_NET` covers the pcap's IPs |
| Windows: `Npcap not found` / no interfaces | Reinstall Npcap with WinPcap-compatible mode ticked |
| Windows: permission denied on log folder | Run PowerShell as administrator, or use `-l` with a folder you own |
| WSL: very slow on a big pcap | Copy the pcap into WSL (`~/cicids/`) instead of reading it from `/mnt/d` |
| WSL: `systemctl` does not work | Use `sudo service suricata start`, or just run on pcap files |

## Write these down for your report

```bash
suricata -V                                   # Suricata version
ls -l /var/lib/suricata/rules/suricata.rules  # rule set date
```
Also note the CPU model and number of cores.
