# 🛡️ Sentinel — Path-Aware Network Security + DDoS Defense

A **one-stop network-security engine** that fuses **SCION-style path validation** with **lightweight, ML-assisted DDoS protection**.

---

## ✨ Features

- **🔍 Path-Aware Monitoring** — RSA-backed path signatures, hop-by-hop anomaly detection.  
- **🚫 DDoS Defense** — Token-bucket rate-limiting, Isolation-Forest traffic profiling, auto-blocking via `iptables`.  
- **📊 Real-Time Analytics** — Live packet capture with structured JSON logs.  
- **🧩 Modular Design** — Run Path Monitor, DDoS Defense, or the full stack independently.

---

## ⚡ Quick Start

```bash
# 1️⃣  Bootstrap source tree
./bootstrap.sh

# 2️⃣  Install system & Python dependencies
./setup.sh

# 3️⃣  List visible interfaces
python3 main.py --list-interfaces

```

## 🚀 Run Modes

```bash
# Integrated (recommended)
python3 main.py -i eth0 --mode integrated

# Only path-aware monitor
python3 main.py -i eth0 --mode path-only

# Only DDoS defense
python3 main.py -i eth0 --mode ddos-only

# Safe local test
python3 main.py -i lo  --mode integrated
```

## 🐳 Docker Deployment

```
docker build -t sentinel .
docker run --rm --privileged --network host \
           sentinel -i eth0 --mode integrated -t 60
```

## 🖥️ System Requirements

- **OS:** Ubuntu 18.04 + (or comparable Linux)  
- **Python:** 3.7 +  
- **Capabilities:** `CAP_NET_RAW` & `CAP_NET_ADMIN` for packet capture  
- **Networking:** An active network interface  

---

## ⚙️ Configuration

`config/config.json`:

| Section                 | Purpose                                     |
|-------------------------|---------------------------------------------|
| `network_interfaces.*`  | Choose default device, exclusions           |
| `path_validation.*`     | Key size, signature TTL                     |
| `ddos_protection.*`     | Bucket capacity, ML window, update cadence  |
| `logging.*`             | Log level, rotation size, backups           |

---

## 🔐 Security Notes

Grant capture capabilities (once):

```bash
sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)
```

- `iptables` actions require root privileges (or run inside a privileged container).  
- All security events are logged to `logs/`.

---

## 🏗️ Architecture Overview

| Module                | Core Idea                        | Tech Highlights                          |
|-----------------------|-----------------------------------|-------------------------------------------|
| **PathValidator**     | Cryptographic path integrity      | RSA-2048 ✚ SHA-256                        |
| **PathAnalyzer**      | Topology anomaly detection        | NetworkX graph DB                         |
| **TokenBucket**       | Per-IP rate limiting              | Leaky-bucket algorithm                    |
| **MLAnomalyDetector** | Behavioural DDoS detection        | Isolation Forest (Scikit-learn)           |
| **IPTablesManager**   | Active mitigation                 | On-the-fly `DROP` rules via `iptables`    |

