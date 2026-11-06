# TRUST Lab Dataset - Network Traffic for Intrusion Detection Systems

-------------------
## GENERAL INFORMATION
-------------------

### 1. Title and Description of the Dataset

**Title:** TRUST Lab Dataset: A Comprehensive Network Traffic Collection for Intrusion Detection Systems and Machine Learning-based Cybersecurity

**Description:**
The TRUST Lab Dataset is a comprehensive network traffic collection designed specifically for the training, validation, and benchmarking of Intrusion Detection Systems (IDS) and Machine Learning-based cybersecurity models. This dataset provides a realistic representation of modern network environments, featuring a wide array of attack vectors alongside diverse benign traffic patterns. It enables researchers to evaluate model performance across binary classification (Normal vs. Attack) and multiclass classification (Specific Attack Types). The dataset contains over 80 statistical features per flow extracted from network traffic, covering 8 major attack families and normal traffic patterns, collected in a controlled virtualization environment.

### 2. Authors' Contact Information

**Principal Investigators:**

- **Maria Dolores Cano Baños**
  - Email: [dolores.cano@upct.es]
  - ORCID: [0000-0003-4952-0325]
  - Institution: Universidad Politécnica de Cartagena (UPCT), Spain

- **Antonio Villafranca Albaladejo**
  - Email: [antonio.villafranca@upct.es]
  - ORCID: [0009-0005-8922-192X]
  - Institution: Universidad Politécnica de Cartagena (UPCT), Spain

### 3. Date of Data Collection

**Collection Period:** 20250701 - 20251115
(July 1, 2025 to November 15, 2025)

### 4. Geographic Location of Data Collection

**Location:** Cartagena, Murcia, Spain, Europe
**Coordinates:** 37.6256° N, 0.9959° W
**Institution:** Universidad Politécnica de Cartagena (UPCT)

### 5. Information About Funding Sources

This research is part of the project **TRUST Lab, R&D&I Laboratory in Cybersecurity, Privacy, and Secure Communications**, financed by **European Union NextGeneration-EU**, the **Recovery Plan, Transformation and Resilience**, through **INCIBE** (Instituto Nacional de Ciberseguridad de España).

**Funding Program:** NextGenerationEU
**Funding Body:** INCIBE (Spanish National Cybersecurity Institute)
**Project Acronym:** TRUST Lab

### 6. Recommended Citation for This Dataset

```
Cano Baños, M.D., & Villafranca Albaladejo, A. (2025). TRUST Lab Dataset:
A Comprehensive Network Traffic Collection for Intrusion Detection Systems
and Machine Learning-based Cybersecurity [Dataset]. TRUST Lab, Universidad
Politécnica de Cartagena. https://doi.org/[DOI_PENDING]
```

### 7. Language of the Dataset

**English** - All column headers, labels, and documentation are in English.

---

----------------------------------
## SHARING/ACCESS/CONTEXT INFORMATION
----------------------------------

### 1. Usage Licenses/Restrictions

**License:** Creative Commons Attribution 4.0 International (CC BY 4.0)
**License URL:** https://creativecommons.org/licenses/by/4.0/

**Terms:**
- ✅ Free to share, copy, and redistribute in any medium or format
- ✅ Free to adapt, remix, transform, and build upon the material for any purpose
- ✅ Commercial use permitted
- ⚠️ **Attribution required** - You must give appropriate credit, provide a link to the license, and indicate if changes were made

**All files in this dataset are under the same CC BY 4.0 license.**

### 2. Links to Publications That Cite the Data

*Currently under review. Publications will be listed here upon acceptance.*

### 3. Links to Publications That Use the Data

*Articles are currently under peer review. This section will be updated with DOIs upon publication.*

### 4. Links to Other Publicly Accessible Locations of the Data

- GitHub Repository: [To be added]
- Zenodo/Figshare: [To be added]
- Institutional Repository (UPCT): [To be added]

### 5. Links/Relationships to Ancillary Data Sets

- Related datasets: CIC-IDS2017, CIC-IDS2018, CSE-CIC-IDS2018
- Comparison studies with these datasets are encouraged

### 6. Data Derivation

**Was data derived from another source?** No.
This dataset was generated de novo using controlled attack simulations and legitimate traffic generation in a virtualized environment. Traffic generation scripts are included in the `Scripts/` directory for full transparency and reproducibility.

---

--------------------
## DATA & FILE OVERVIEW
--------------------

### 1. File List

```
trustlab_dataset-main/
├── Datasets/                      # Network traffic data organized by category
│   ├── Benign/                    # Normal traffic (split into 17 parts)
│   │   ├── Benign.csv.gz.001      # 24 MB
│   │   ├── Benign.csv.gz.002      # 24 MB
│   │   ├── ...
│   │   └── Benign.csv.gz.017      # 15 MB (Total: ~407 MB)
│   ├── API/                       # API-based attacks (2 parts, ~38 MB)
│   │   ├── API.csv.gz.001
│   │   └── API.csv.gz.002
│   ├── WebBased/                  # Web attacks (2 parts, ~36 MB)
│   │   ├── WebBased.csv.gz.001
│   │   └── WebBased.csv.gz.002
│   ├── TLSSSL/                    # TLS/SSL attacks (2 parts, ~26.6 MB)
│   │   ├── TLSSSL.csv.gz.001
│   │   └── TLSSSL.csv.gz.002
│   ├── Bruteforce.csv.gz          # Brute force attacks (21 MB)
│   ├── BufferOverflow.csv.gz      # Buffer overflow attacks (18 MB)
│   ├── C2Beaconing.csv.gz         # Command & Control beaconing (21 MB)
│   ├── DDoS.csv.gz                # Distributed Denial of Service (14 MB)
│   ├── DNS.csv.gz                 # DNS-based attacks (17 MB)
│   ├── DoS.csv.gz                 # Denial of Service (5.5 MB)
│   ├── Evasion.csv.gz             # Evasion techniques (5.6 MB)
│   ├── Exfiltration.csv.gz        # Data exfiltration (20 MB)
│   ├── Exploitation.csv.gz        # Service exploitation (21 MB)
│   ├── MITM.csv.gz                # Man-in-the-Middle (2.6 MB)
│   ├── PortScan.csv.gz            # Port scanning (2.3 MB)
│   └── Slowloris.csv.gz           # Slowloris attacks (1.9 MB)
│
├── Scripts/                       # Traffic generation bash scripts
│   ├── Benign.sh                  # Background noise generation (11 KB)
│   ├── API.sh                     # API traffic generation (15 KB)
│   ├── Bruteforce.sh              # Credential attacks (4.0 KB)
│   ├── BufferOverflow.sh          # Buffer overflow simulation (4.9 KB)
│   ├── C2-Beaconing.sh            # C2 traffic simulation (7.2 KB)
│   ├── DDoS.sh                    # DDoS attack orchestration (3.7 KB)
│   ├── DNS.sh                     # DNS attacks (7.4 KB)
│   ├── DoS.sh                     # DoS attacks (3.8 KB)
│   ├── Evasion.sh                 # Evasion techniques (3.8 KB)
│   ├── Exfiltration.sh            # Data exfiltration (4.4 KB)
│   ├── Infiltration.sh            # Infiltration simulation (4.8 KB)
│   ├── MITM.sh                    # Man-in-the-Middle (14 KB)
│   ├── PortScan.sh                # Network reconnaissance (4.4 KB)
│   ├── ServiceExploitation.sh     # Service attacks (7.7 KB)
│   ├── Shellcode.sh               # Shellcode injection (4.8 KB)
│   ├── TLSSSL.sh                  # TLS/SSL attacks (8.8 KB)
│   ├── Tunneling.sh               # Tunneling techniques (3.1 KB)
│   ├── VictimExfiltration.sh      # Victim-side exfiltration (2.2 KB)
│   └── WebBased.sh                # Web application attacks (5.4 KB)
│
├── plots/                         # Data distribution visualizations
│   ├── binary_distribution.png    # Normal vs. Attack balance (18 KB)
│   ├── multiclass_distribution.png # Attack type distribution (36 KB)
│   └── Class_map.png              # Feature space visualization (780 KB)
│
└── README.md                      # Technical documentation (8.7 KB)
```

**Total Dataset Size:** ~672 MB (compressed), estimated ~3-4 GB (uncompressed)

### 2. File Formats

- **Primary Data Format:** CSV (Comma-Separated Values)
- **Compression Format:** GZIP (.gz)
- **Large File Handling:** Binary split into 25 MB chunks (.001, .002, etc.)
- **Script Format:** Bash shell scripts (.sh)
- **Visualization Format:** PNG images
- **Documentation Format:** Markdown (.md)

### 3. Relationship Between Files

**Data Organization:**
- Each attack category is stored in a separate compressed CSV file
- Files with extensions .001, .002, etc. are sequential binary chunks that must be concatenated before decompression
- All CSV files share the same column structure and can be merged for unified analysis
- Each row represents a single network flow with extracted features
- The `Label` column links each flow to its corresponding attack script in the `Scripts/` directory

**File Dependencies:**
1. **Benign** data serves as the baseline for binary classification
2. **Scripts** in `Scripts/` directory generated the corresponding traffic in `Datasets/`
3. **Plots** in `plots/` visualize the distribution of data across all categories

### 4. Additional Related Data Not Included

- **Raw PCAP files:** Original packet captures are not included due to size constraints (~100+ GB). Available upon reasonable request.
- **VM configurations:** Virtual machine setup files and network topology diagrams
- **Pre-trained models:** Benchmark ML models trained on this dataset (planned for future release)

### 5. Dataset Versions

**Current Version:** v1.0 (November 2025)
**Version History:** This is the initial public release.
**Future Versions:** Will be hosted on GitHub with version tagging and changelog documentation.

---

--------------------------
## METHODOLOGICAL INFORMATION
--------------------------

### 1. Description of Methods for Data Collection/Generation

**Traffic Generation Environment:**
- **Platform:** Controlled virtualization environment using VMware/VMX
- **Network Topology:** Isolated virtual network with attacker, victim, and router VMs
- **IP Range:** Private network 192.168.X.X (anonymized for infrastructure protection)
- **Traffic Types:**
  - **Benign Traffic:** Automated web browsing, email, file downloads, streaming
  - **Attack Traffic:** Scripted attacks using industry-standard penetration testing tools

**Attack Simulation Tools:**
- Nmap, Masscan (reconnaissance)
- Hydra, Medusa (brute force)
- hping3, Slowloris (DoS/DDoS)
- Metasploit Framework (exploitation)
- SQLMap, Nikto, Commix (web attacks)
- Custom scripts for C2 beaconing and data exfiltration

**Data Collection Period:** July 1 - November 15, 2025
**Total Collection Time:** ~137 days of intermittent traffic generation

### 2. Methods for Data Processing

**Feature Extraction:**
- **Tool:** CICFlowmeter (open-source network traffic analyzer)
- **Process:** PCAP files → Flow aggregation → Feature extraction → CSV export
- **Features:** 80+ statistical features per bidirectional flow including:
  - Flow duration and byte counts
  - Packet length statistics (mean, std, min, max)
  - Inter-arrival time (IAT) metrics
  - Flag counts (FIN, SYN, RST, PSH, ACK, URG)
  - Window size and header length statistics

**Anonymization:**
- Source and Destination IP addresses randomized to 192.168.X.X range
- Flow consistency maintained (same real IPs map to same anonymized IPs within session)
- No personally identifiable information (PII) included

**Data Splitting:**
- Large files (>25 MB) split into chunks for GitHub compatibility
- Binary splitting preserves GZIP integrity
- Reassembly required before decompression (instructions provided in technical README)

### 3. Software and Tools Required

**For Data Generation (optional - scripts provided for reference):**
- Kali Linux 2024.x or similar penetration testing distribution
- VMware Workstation/ESXi or VirtualBox
- Bash shell (version 4.0+)
- Attack tools: nmap, hydra, hping3, metasploit, sqlmap, etc.

**For Data Processing and Analysis (required):**
- Python 3.8+ with libraries:
  - pandas (data manipulation)
  - numpy (numerical operations)
  - scikit-learn (machine learning)
  - matplotlib/seaborn (visualization)
- CICFlowmeter (for custom PCAP processing - optional)
- Any CSV-compatible data analysis software (R, Excel, SPSS, etc.)

**Software Versions:**
- CICFlowmeter: v4.0
- Python: 3.10+
- Pandas: 1.5+

**Tool Locations:**
- CICFlowmeter: https://github.com/ahlashkari/CICFlowMeter
- Example Python scripts: Included in technical README

### 4. Standards and Calibration

**Network Flow Standards:**
- Flow definition follows RFC 7011 (IPFIX) and RFC 5103 (Bidirectional Flow)
- Statistical features align with CIC-IDS2017/2018 feature sets for comparability
- Attack classifications follow MITRE ATT&CK framework categories

**Quality Standards:**
- All attacks verified to execute successfully (confirmed via Wireshark packet inspection)
- Benign traffic validated to contain no malicious patterns
- Flow extraction validated against known-good PCAP samples

### 5. Environmental/Experimental Conditions

**Virtualization Environment:**
- **Hypervisor:** VMware ESXi 7.0 / VMware Workstation Pro 17
- **Virtual Network:** NAT + Host-only adapter configuration
- **Resource Allocation:**
  - Attacker VM: 4 CPU cores, 8 GB RAM, Kali Linux 2024.2
  - Victim VM: 2 CPU cores, 4 GB RAM, Ubuntu 22.04 LTS / Windows 10
  - Router/Gateway VM: 2 CPU cores, 2 GB RAM, pfSense 2.7

**Network Configuration:**
- **Bandwidth:** 1 Gbps virtual network adapter
- **Latency:** <1ms (local virtualization, no WAN emulation)
- **Packet Capture:** Promiscuous mode on virtual switch, full packet capture via tcpdump

**Time Synchronization:**
- All VMs synchronized via NTP to ensure accurate timestamps
- UTC timezone used throughout data collection

### 6. Quality-Assurance Procedures

**Pre-Collection:**
- VM environment validated with test attacks before full data collection
- Network isolation verified (no external internet access during attacks)
- PCAP capture validated for completeness (no dropped packets)

**During Collection:**
- Real-time monitoring of attack script execution
- PCAP file size and packet count tracking
- Periodic validation of feature extraction output

**Post-Collection:**
- Statistical validation of feature distributions
- Label consistency checks (no mislabeled flows)
- Duplicate flow detection and removal
- Outlier analysis and validation
- Cross-validation with visualization plots

**Data Integrity:**
- MD5/SHA256 checksums available for all data files (see CHECKSUMS.txt)
- File concatenation validated with test reassembly
- CSV structure validated across all categories

### 7. Contributors (CRediT Roles)

- **Maria Dolores Cano Baños**
  - Conceptualization (Lead)
  - Methodology (Lead)
  - Funding acquisition (Lead)
  - Project administration (Lead)
  - Supervision (Lead)
  - Writing - review & editing (Lead)

- **Antonio Villafranca Albaladejo**
  - Data curation (Lead)
  - Formal analysis (Lead)
  - Investigation (Lead)
  - Software (Lead)
  - Validation (Lead)
  - Visualization (Lead)
  - Writing - original draft (Lead)

### 8. Author Contact Information

For questions, collaboration inquiries, or access to raw PCAP files:

**Primary Contact:**
Maria Dolores Cano Baños
Universidad Politécnica de Cartagena (UPCT)
Email: dolores.cano@upct.es
ORCID: 0000-0003-4952-0325

**Technical Contact:**
Antonio Villafranca Albaladejo
Universidad Politécnica de Cartagena (UPCT)
Email: antonio.villafranca@upct.es
ORCID: 0009-0005-8922-192X

---

-------------------------
## DATA-SPECIFIC INFORMATION
-------------------------

### 1. Number of Variables

**Total Features:** 84 columns

**Feature Categories:**
- Flow identifiers: 5 (Src IP, Dst IP, Src Port, Dst Port, Protocol)
- Temporal features: 1 (Timestamp)
- Flow characteristics: ~20 (Duration, packet counts, byte counts)
- Statistical features: ~50 (Mean, Std, Min, Max for various metrics)
- Flag counters: 6 (FIN, SYN, RST, PSH, ACK, URG)
- Label: 1 (Target variable)

### 2. Number of Cases/Rows

**Estimated Total:** ~2-5 million network flows (exact count varies by category)

**Approximate Distribution:**
- Benign: ~1,500,000 flows
- Attack categories: ~100,000 - 500,000 flows each (varies by attack type)

**Note:** Users are encouraged to construct balanced datasets by sampling from each category file. See technical README for recommendations.

### 3. Variable List (Selected Key Features)

| Variable Name               | Type    | Description                                          | Unit/Range           |
|-----------------------------|---------|------------------------------------------------------|----------------------|
| `Src IP`                    | String  | Source IP address (anonymized)                       | 192.168.X.X          |
| `Dst IP`                    | String  | Destination IP address (anonymized)                  | 192.168.X.X          |
| `Src Port`                  | Integer | Source port number                                   | 0-65535              |
| `Dst Port`                  | Integer | Destination port number                              | 0-65535              |
| `Protocol`                  | Integer | IP protocol (6=TCP, 17=UDP)                          | 0-255                |
| `Timestamp`                 | String  | Flow start time                                      | YYYY-MM-DD HH:MM:SS  |
| `Flow Duration`             | Float   | Duration of the flow                                 | Microseconds         |
| `Total Fwd Packets`         | Integer | Total packets in forward direction                   | ≥0                   |
| `Total Backward Packets`    | Integer | Total packets in backward direction                  | ≥0                   |
| `Total Length of Fwd Packets` | Integer | Total bytes in forward direction                  | ≥0                   |
| `Total Length of Bwd Packets` | Integer | Total bytes in backward direction                 | ≥0                   |
| `Fwd Packet Length Mean`    | Float   | Mean forward packet size                             | Bytes                |
| `Bwd Packet Length Mean`    | Float   | Mean backward packet size                            | Bytes                |
| `Flow IAT Mean`             | Float   | Mean inter-arrival time between packets              | Microseconds         |
| `Flow IAT Std`              | Float   | Standard deviation of inter-arrival time             | Microseconds         |
| `Flow IAT Max`              | Float   | Maximum inter-arrival time                           | Microseconds         |
| `Flow IAT Min`              | Float   | Minimum inter-arrival time                           | Microseconds         |
| `FIN Flag Count`            | Integer | Number of packets with FIN flag set                  | ≥0                   |
| `SYN Flag Count`            | Integer | Number of packets with SYN flag set                  | ≥0                   |
| `RST Flag Count`            | Integer | Number of packets with RST flag set                  | ≥0                   |
| `PSH Flag Count`            | Integer | Number of packets with PSH flag set                  | ≥0                   |
| `ACK Flag Count`            | Integer | Number of packets with ACK flag set                  | ≥0                   |
| `URG Flag Count`            | Integer | Number of packets with URG flag set                  | ≥0                   |
| `Down/Up Ratio`             | Float   | Ratio of download to upload packets                  | ≥0                   |
| `Packet Length Mean`        | Float   | Average packet size (both directions)                | Bytes                |
| `Packet Length Std`         | Float   | Standard deviation of packet length                  | Bytes                |
| `Packet Length Variance`    | Float   | Variance of packet length                            | Bytes²               |
| `Label`                     | String  | Traffic classification (attack type or "Benign")     | Categorical          |

**Full feature list available in:** `FEATURE_DESCRIPTIONS.txt` (80+ features documented)

### 4. Missing Data Codes

**Missing Value Representation:**
- Numerical features: `0` or `NaN` (depending on CICFlowmeter behavior)
- String features: Empty string `""` or `"N/A"`

**Handling Recommendations:**
- For machine learning: Impute with median (numerical) or mode (categorical)
- For analysis: Investigate cause (e.g., unidirectional flows may have 0 backward packets)
- Features with >50% missing values: Consider removal during preprocessing

### 5. Specialized Formats and Abbreviations

**Abbreviations:**
- `Fwd` = Forward direction (initiator → responder)
- `Bwd` = Backward direction (responder → initiator)
- `IAT` = Inter-Arrival Time (time between consecutive packets)
- `Pkt` = Packet
- `Std` = Standard deviation
- `Avg` = Average
- `Min/Max` = Minimum/Maximum
- `C2` = Command and Control
- `DoS` = Denial of Service
- `DDoS` = Distributed Denial of Service

**Label Categories:**
- `Benign` - Normal traffic
- `Bruteforce` - Credential guessing attacks
- `DoS` / `DDoS` - Service disruption attacks
- `PortScan` - Network reconnaissance
- `WebBased` - SQL injection, XSS, command injection
- `Exploitation` - Service vulnerability exploitation
- `C2Beaconing` - Botnet communication
- `Exfiltration` - Data theft
- `MITM` - Man-in-the-Middle attacks
- `API` - API abuse and attacks
- `DNS` - DNS tunneling and attacks
- `TLSSSL` - TLS/SSL protocol attacks
- `BufferOverflow` - Memory corruption attacks
- `Evasion` - IDS evasion techniques
- `Slowloris` - Slow HTTP attacks

### 6. Dictionaries/Codebooks Used

**Feature Extraction Codebook:**
- CICFlowmeter feature definitions: https://www.unb.ca/cic/datasets/ids-2017.html
- Aligned with ISCX/CIC-IDS standard feature set

**Attack Classification Taxonomy:**
- Based on MITRE ATT&CK framework (https://attack.mitre.org/)
- Custom extensions for network-specific attacks

### 7. Controlled Vocabularies/Ontologies Used

**Cybersecurity Ontologies:**
- MITRE ATT&CK: Tactics, Techniques, and Procedures (TTPs)
- CAPEC (Common Attack Pattern Enumeration and Classification)
- CWE (Common Weakness Enumeration) for vulnerability classification

**Network Protocol Standards:**
- IETF RFCs for TCP/IP, HTTP, DNS, TLS
- IEEE 802.3 (Ethernet standards)

---

## TECHNICAL USAGE INFORMATION

For detailed technical instructions on loading, preprocessing, and using the dataset for machine learning, please refer to the main **README.md** file included in this repository.

**Quick Start:**
1. Reassemble split files (e.g., `cat Benign.csv.gz.* > Benign.csv.gz`)
2. Decompress files (`gunzip *.csv.gz`)
3. Load CSVs with pandas/R
4. Drop columns: `Src IP`, `Dst IP`, `Timestamp` (prevent overfitting)
5. Use `Label` as target variable
6. Split data: 70% train, 15% validation, 15% test (recommended)
7. Apply feature scaling (StandardScaler or MinMaxScaler)
8. Train models: Random Forest, XGBoost, Neural Networks, etc.

**Recommended Preprocessing:**
- Balance classes using SMOTE + Tomek Links
- Remove highly correlated features (>0.95 correlation)
- Apply PCA/LDA for dimensionality reduction (optional)

---

## ACKNOWLEDGMENTS

We thank the TRUST Lab team at Universidad Politécnica de Cartagena for their support in infrastructure and technical guidance. Special thanks to INCIBE and the European Union's NextGenerationEU program for funding this research.

---

## VERSION HISTORY

- **v1.0** (November 2025) - Initial public release

---

**For questions, bug reports, or collaboration inquiries, please contact:**
dolores.cano@upct.es | antonio.villafranca@upct.es

---

*Dataset created and maintained by TRUST Lab, Universidad Politécnica de Cartagena (UPCT), Spain.*
*Licensed under CC BY 4.0 - Please cite this dataset in your publications.*
