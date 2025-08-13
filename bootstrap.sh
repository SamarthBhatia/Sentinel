#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Bootstrap: Path-Aware Network Security Monitor & DDoS Defense System
# ==============================================================================

PROJECT_ROOT="$(pwd)"
echo "[+] Bootstrapping project into: $PROJECT_ROOT"

# Create directories
mkdir -p "$PROJECT_ROOT"/{config,logs,data,tests,path_monitor,ddos_defense}

# ------------------------------------------------------------------------------
# requirements.txt
# ------------------------------------------------------------------------------
cat > "$PROJECT_ROOT/requirements.txt" << 'EOF'
scapy==2.5.0
networkx==3.3
scikit-learn==1.5.1
numpy==1.26.4
matplotlib==3.9.0
cryptography==42.0.8
psutil==6.0.0
pandas==2.2.2
netifaces==0.11.0
EOF

# ------------------------------------------------------------------------------
# config/config.json
# ------------------------------------------------------------------------------
cat > "$PROJECT_ROOT/config/config.json" << 'EOF'
{
  "network_interfaces": {
    "default_interface": "eth0",
    "monitor_all": true,
    "excluded_interfaces": ["lo", "docker0"]
  },
  "path_validation": {
    "signature_algorithm": "SHA256",
    "key_size": 2048,
    "max_path_length": 10,
    "validation_timeout": 30
  },
  "ddos_protection": {
    "token_bucket": {
      "capacity": 100,
      "refill_rate": 10,
      "refill_period": 1.0
    },
    "ml_detection": {
      "model_type": "IsolationForest",
      "contamination": 0.1,
      "window_size": 1000,
      "update_frequency": 60
    }
  },
  "logging": {
    "level": "INFO",
    "max_file_size": "10MB",
    "backup_count": 5
  }
}
EOF

# ------------------------------------------------------------------------------
# path_monitor/__init__.py
# ------------------------------------------------------------------------------
cat > "$PROJECT_ROOT/path_monitor/__init__.py" << 'EOF'
# Package init for path_monitor
EOF

# ------------------------------------------------------------------------------
# path_monitor/path_monitor.py
# ------------------------------------------------------------------------------
cat > "$PROJECT_ROOT/path_monitor/path_monitor.py" << 'EOF'
#!/usr/bin/env python3
"""
Path-Aware Network Security Monitor
Simplified SCION-inspired path awareness with cryptographic validation
"""

import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import networkx as nx
import json
import time
import logging
import hashlib
from collections import defaultdict, deque
import argparse
import os

class PathValidator:
    """Cryptographic path validation system (simplified demo)"""

    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        self.public_key = self.private_key.public_key()

    def generate_path_signature(self, path_info):
        try:
            normalized = json.dumps(path_info, sort_keys=True, default=str)
            path_hash = hashlib.sha256(normalized.encode()).digest()
            signature = self.private_key.sign(
                path_hash,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
            return {
                "path_hash": path_hash.hex(),
                "signature": signature.hex(),
                "timestamp": time.time(),
                "path_info": path_info
            }
        except Exception as e:
            logging.error(f"[PathValidator] Sign error: {e}")
            return None

    def verify_path_signature(self, signature_data):
        try:
            path_hash = bytes.fromhex(signature_data["path_hash"])
            signature = bytes.fromhex(signature_data["signature"])
            self.public_key.verify(
                signature,
                path_hash,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
            if time.time() - signature_data["timestamp"] > 300:
                logging.warning("[PathValidator] Signature expired")
                return False
            return True
        except Exception as e:
            logging.error(f"[PathValidator] Verify error: {e}")
            return False

class PathAnalyzer:
    """Network path analysis and anomaly detection"""

    def __init__(self, max_paths=2000):
        self.network_graph = nx.DiGraph()
        self.path_history = deque(maxlen=max_paths)
        self.routing_table = defaultdict(list)
        self.normal_paths = defaultdict(set)

    def add_path_info(self, src_ip, dst_ip, path_data):
        try:
            self.network_graph.add_node(src_ip)
            self.network_graph.add_node(dst_ip)
            self.network_graph.add_edge(
                src_ip, dst_ip,
                timestamp=time.time(),
                protocol=path_data.get("protocol_name", "unknown"),
                ttl=path_data.get("ttl", 64)
            )
            route_key = f"{src_ip}->{dst_ip}"
            self.routing_table[route_key].append({"timestamp": time.time(), "path_data": path_data})
            cutoff = time.time() - 3600
            self.routing_table[route_key] = [
                e for e in self.routing_table[route_key] if e["timestamp"] > cutoff
            ]
            hops = tuple(path_data.get("hops", []))
            if self._is_normal_path(path_data) and hops:
                self.normal_paths[route_key].add(hops)
        except Exception as e:
            logging.error(f"[PathAnalyzer] add_path_info error: {e}")

    def _is_normal_path(self, path_data):
        ttl = path_data.get("ttl", 64)
        proto = path_data.get("protocol_name", "unknown")
        normal_ttls = [64, 128, 255]
        ttl_ok = any(abs(ttl - t) <= 5 for t in normal_ttls)
        return ttl_ok and proto in ["TCP", "UDP", "ICMP"]

    def detect_path_anomalies(self, current_path):
        anomalies = []
        try:
            src = current_path.get("src_ip")
            dst = current_path.get("dst_ip")
            route_key = f"{src}->{dst}"

            current_hops = tuple(current_path.get("hops", []))
            if route_key in self.normal_paths and current_hops and current_hops not in self.normal_paths[route_key]:
                anomalies.append({
                    "type": "path_deviation",
                    "severity": "medium",
                    "description": f"Unusual routing path for {route_key}"
                })

            ttl = current_path.get("ttl", 64)
            if ttl < 5 or ttl > 255:
                anomalies.append({
                    "type": "ttl_anomaly",
                    "severity": "high",
                    "description": f"Suspicious TTL: {ttl}"
                })
        except Exception as e:
            logging.error(f"[PathAnalyzer] detect_path_anomalies error: {e}")
        return anomalies

class PathMonitor:
    """Main path monitor class"""
    
    def __init__(self, interface="eth0", config_file=None):
        self.interface = interface
        self.config = self._load_config(config_file)
        self._setup_logging()
        self.validator = PathValidator(key_size=self.config["path_validation"]["key_size"])
        self.analyzer = PathAnalyzer()
        self.stats = {
            "packets_processed": 0,
            "paths_validated": 0,
            "anomalies_detected": 0,
            "start_time": time.time()
        }

    def _load_config(self, cfg):
        defaults = {
            "path_validation": {"key_size": 2048},
            "logging": {"level": "INFO"}
        }
        if cfg and os.path.exists(cfg):
            try:
                with open(cfg, "r") as f:
                    user = json.load(f)
                for k, v in defaults.items():
                    if k not in user:
                        user[k] = v
                return user
            except Exception:
                return defaults
        return defaults

    def _setup_logging(self):
        os.makedirs("logs", exist_ok=True)
        logging.basicConfig(
            level=getattr(logging, self.config["logging"]["level"]),
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[logging.FileHandler("logs/path_monitor.log"), logging.StreamHandler()],
        )

    def _simulate_hops(self, src_ip, dst_ip, ttl):
        hops = [src_ip]
        init = 64 if ttl <= 64 else (128 if ttl <= 128 else 255)
        hop_count = max(1, min(10, init - ttl if init - ttl > 0 else 1))
        for i in range(1, hop_count):
            parts = dst_ip.split(".")
            parts[-1] = str((int(parts[-1]) + i) % 254 + 1)
            hops.append(".".join(parts))
        hops.append(dst_ip)
        return hops

    def _extract_path_info(self, pkt):
        if not pkt.haslayer(IP):
            return None
        ip = pkt[IP]
        info = {
            "src_ip": ip.src,
            "dst_ip": ip.dst,
            "ttl": int(ip.ttl),
            "protocol": ip.proto,
            "packet_length": len(pkt),
            "timestamp": time.time(),
            "protocol_name": "IP"
        }
        if pkt.haslayer(TCP):
            t = pkt[TCP]
            info.update({"protocol_name": "TCP", "src_port": t.sport, "dst_port": t.dport})
        elif pkt.haslayer(UDP):
            u = pkt[UDP]
            info.update({"protocol_name": "UDP", "src_port": u.sport, "dst_port": u.dport})
        elif pkt.haslayer(ICMP):
            ic = pkt[ICMP]
            info.update({"protocol_name": "ICMP", "icmp_type": int(ic.type)})
        info["hops"] = self._simulate_hops(info["src_ip"], info["dst_ip"], info["ttl"])
        info["path_length"] = len(info["hops"])
        return info

    def _process_packet(self, pkt):
        self.stats["packets_processed"] += 1
        pinfo = self._extract_path_info(pkt)
        if not pinfo:
            return
        sig = self.validator.generate_path_signature(pinfo)
        if sig and self.validator.verify_path_signature(sig):
            self.stats["paths_validated"] += 1
        self.analyzer.add_path_info(pinfo["src_ip"], pinfo["dst_ip"], pinfo)
        anomalies = self.analyzer.detect_path_anomalies(pinfo)
        if anomalies:
            self.stats["anomalies_detected"] += len(anomalies)
            for a in anomalies:
                logging.warning(f"[PathMonitor] Anomaly: {a}")
        if self.stats["packets_processed"] % 200 == 0:
            logging.info(f"[PathMonitor] Processed {self.stats['packets_processed']} packets")

    def start(self, count=None, timeout=None):
        logging.info(f"[PathMonitor] Starting on interface {self.interface}")
        try:
            scapy.sniff(
                iface=self.interface,
                prn=self._process_packet,
                count=count,
                timeout=timeout,
                store=0
            )
        except PermissionError:
            logging.error("Permission denied. Try: sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)")
        except Exception as e:
            logging.error(f"[PathMonitor] Error during sniff: {e}")

    def stats_summary(self):
        runtime = max(1e-6, time.time() - self.stats["start_time"])
        return {
            **self.stats,
            "runtime_seconds": runtime,
            "packets_per_second": self.stats["packets_processed"] / runtime
        }

def main():
    ap = argparse.ArgumentParser(description="Path-Aware Network Security Monitor")
    ap.add_argument("-i", "--interface", default="eth0", help="Network interface")
    ap.add_argument("-c", "--config", help="Config file path")
    ap.add_argument("-t", "--timeout", type=int, help="Sniff timeout seconds")
    ap.add_argument("-n", "--count", type=int, help="Packet count limit")
    args = ap.parse_args()

    mon = PathMonitor(interface=args.interface, config_file=args.config)
    mon.start(count=args.count, timeout=args.timeout)
    s = mon.stats_summary()
    print("\n=== Path Monitor Statistics ===")
    for k, v in s.items():
        print(f"{k}: {v:.3f}" if isinstance(v, float) else f"{k}: {v}")

if __name__ == "__main__":
    main()
EOF
chmod +x "$PROJECT_ROOT/path_monitor/path_monitor.py"

# ------------------------------------------------------------------------------
# ddos_defense/__init__.py
# ------------------------------------------------------------------------------
cat > "$PROJECT_ROOT/ddos_defense/__init__.py" << 'EOF'
# Package init for ddos_defense
EOF

# ------------------------------------------------------------------------------
# ddos_defense/ddos_defense.py
# ------------------------------------------------------------------------------
cat > "$PROJECT_ROOT/ddos_defense/ddos_defense.py" << 'EOF'
#!/usr/bin/env python3
"""
Lightweight DDoS Defense System
- Token bucket rate limiting
- ML-based anomaly detection (IsolationForest)
- iptables integration for dynamic blocking
"""

import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import time
import json
import logging
import os
import subprocess
from collections import defaultdict, deque
import argparse

class TokenBucket:
    def __init__(self, capacity=100, refill_rate=10, refill_period=1.0):
        self.capacity = capacity
        self.tokens = capacity
        self.refill_rate = refill_rate
        self.refill_period = refill_period
        self.last_refill = time.time()

    def _refill(self):
        now = time.time()
        elapsed = now - self.last_refill
        if elapsed >= self.refill_period:
            to_add = int((elapsed / self.refill_period) * self.refill_rate)
            self.tokens = min(self.capacity, self.tokens + to_add)
            self.last_refill = now

    def consume(self, tokens=1):
        self._refill()
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False

class IPTablesManager:
    def __init__(self):
        self.blocked_ips = set()

    def available(self):
        try:
            subprocess.run(["iptables", "--version"], check=True, capture_output=True)
            return True
        except Exception:
            return False

    def block_ip(self, ip_address, duration=600):
        if not self.available():
            logging.warning("iptables not available")
            return False
        try:
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
            self.blocked_ips.add(ip_address)
            logging.info(f"Blocked IP {ip_address}")
            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to block IP {ip_address}: {e}")
            return False

class MLAnomalyDetector:
    def __init__(self, window_size=1000, contamination=0.1):
        self.window_size = window_size
        self.contamination = contamination
        self.model = IsolationForest(contamination=contamination, random_state=42)
        self.scaler = StandardScaler()
        self.buffer = deque(maxlen=window_size)
        self.trained = False
        self.features = [
            "packet_size", "pps", "bps", "unique_src_ips", "unique_dst_ports",
            "tcp_ratio", "udp_ratio", "icmp_ratio", "avg_ttl", "ttl_var"
        ]

    def extract_features(self, packets, window=60):
        now = time.time()
        pkts = [p for p in packets if now - p["timestamp"] <= window]
        if not pkts:
            return None
        
        sizes = [p["size"] for p in pkts]
        total = len(pkts)
        protos = [p["proto"] for p in pkts]
        ttls = [p.get("ttl", 64) for p in pkts]
        srcs = set(p["src"] for p in pkts)
        dst_ports = set(p.get("dst_port", 0) for p in pkts)
        
        features = {
            "packet_size": float(np.mean(sizes)),
            "pps": total / window,
            "bps": sum(sizes) / window,
            "unique_src_ips": len(srcs),
            "unique_dst_ports": len(dst_ports),
            "tcp_ratio": protos.count("TCP") / total if total else 0.0,
            "udp_ratio": protos.count("UDP") / total if total else 0.0,
            "icmp_ratio": protos.count("ICMP") / total if total else 0.0,
            "avg_ttl": float(np.mean(ttls)) if ttls else 64.0,
            "ttl_var": float(np.var(ttls)) if len(ttls) > 1 else 0.0
        }
        return features

    def update_model(self, packets):
        f = self.extract_features(packets)
        if not f:
            return
        self.buffer.append(f)
        if len(self.buffer) >= min(100, int(self.window_size * 0.1)):
            X = np.array([[row[k] for k in self.features] for row in self.buffer], dtype=float)
            X = self.scaler.fit_transform(X)
            self.model.fit(X)
            self.trained = True

    def detect_anomaly(self, packets):
        if not self.trained:
            return False, 0.0
        f = self.extract_features(packets)
        if not f:
            return False, 0.0
        x = np.array([[f[k] for k in self.features]], dtype=float)
        x = self.scaler.transform(x)
        score = float(self.model.decision_function(x)[0])
        is_anom = (self.model.predict(x) == -1)
        return is_anom, score

class DDoSDefense:
    def __init__(self, interface="eth0", config_file=None):
        self.interface = interface
        self.config = self._load_config(config_file)
        self._setup_logging()
        
        tb = self.config["ddos_protection"]["token_bucket"]
        self.global_bucket = TokenBucket(**tb)
        self.ip_buckets = defaultdict(lambda: TokenBucket(capacity=50, refill_rate=5))
        
        ml = self.config["ddos_protection"]["ml_detection"]
        self.detector = MLAnomalyDetector(window_size=ml["window_size"], contamination=ml["contamination"])
        self.iptables = IPTablesManager()
        
        self.packets = deque(maxlen=10000)
        self.counters = defaultdict(lambda: {"packets": 0, "bytes": 0, "last": time.time()})
        self.stats = {
            "packets_processed": 0,
            "attacks_detected": 0,
            "ips_blocked": 0,
            "start_time": time.time()
        }

    def _load_config(self, cfg):
        defaults = {
            "logging": {"level": "INFO"},
            "ddos_protection": {
                "token_bucket": {"capacity": 100, "refill_rate": 10, "refill_period": 1.0},
                "ml_detection": {"contamination": 0.1, "window_size": 1000, "update_frequency": 60}
            }
        }
        if cfg and os.path.exists(cfg):
            try:
                with open(cfg, "r") as f:
                    user = json.load(f)
                for k, v in defaults.items():
                    if k not in user:
                        user[k] = v
                return user
            except Exception:
                return defaults
        return defaults

    def _setup_logging(self):
        os.makedirs("logs", exist_ok=True)
        logging.basicConfig(
            level=getattr(logging, self.config["logging"]["level"]),
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[logging.FileHandler("logs/ddos_defense.log"), logging.StreamHandler()],
        )

    def _packet_info(self, pkt):
        if not pkt.haslayer(IP):
            return None
        ip = pkt[IP]
        info = {
            "timestamp": time.time(),
            "src": ip.src,
            "dst": ip.dst,
            "size": len(pkt),
            "ttl": int(ip.ttl),
            "proto": "IP"
        }
        if pkt.haslayer(TCP):
            t = pkt[TCP]
            info.update({"proto": "TCP", "src_port": t.sport, "dst_port": t.dport, "flags": int(t.flags)})
        elif pkt.haslayer(UDP):
            u = pkt[UDP]
            info.update({"proto": "UDP", "src_port": u.sport, "dst_port": u.dport})
        elif pkt.haslayer(ICMP):
            ic = pkt[ICMP]
            info.update({"proto": "ICMP", "icmp_type": int(ic.type)})
        return info

    def _detect_patterns(self, info):
        alerts = []
        src = info["src"]
        now = info["timestamp"]
        
        self.counters[src]["packets"] += 1
        self.counters[src]["bytes"] += info["size"]
        self.counters[src]["last"] = now

        window = 60
        recent = [p for p in self.packets if p["src"] == src and now - p["timestamp"] <= window]
        ppm = len(recent)
        bpm = sum(p["size"] for p in recent)

        if ppm > 1000:
            alerts.append({"type": "high_volume", "severity": "high", "src": src, "ppm": ppm})
        if bpm > 10 * 1024 * 1024:
            alerts.append({"type": "high_bandwidth", "severity": "high", "src": src, "bpm": bpm})

        if info["proto"] == "TCP":
            tcp_recent = [p for p in recent if p["proto"] == "TCP"]
            if len(tcp_recent) > 500:
                syns = [p for p in tcp_recent if p.get("flags", 0) & 0x02]
                if len(syns) > 0.8 * len(tcp_recent):
                    alerts.append({"type": "syn_flood", "severity": "critical", "src": src})
        elif info["proto"] == "UDP":
            udp_recent = [p for p in recent if p["proto"] == "UDP"]
            if len(udp_recent) > 500:
                alerts.append({"type": "udp_flood", "severity": "high", "src": src})
        elif info["proto"] == "ICMP":
            icmp_recent = [p for p in recent if p["proto"] == "ICMP"]
            if len(icmp_recent) > 100:
                alerts.append({"type": "icmp_flood", "severity": "medium", "src": src})

        return alerts

    def _process_packet(self, pkt):
        self.stats["packets_processed"] += 1
        info = self._packet_info(pkt)
        if not info:
            return

        if not self.ip_buckets[info["src"]].consume():
            logging.warning(f"[DDoS] Rate limit exceeded for {info['src']}")
            return

        self.packets.append(info)
        alerts = self._detect_patterns(info)
        if alerts:
            self.stats["attacks_detected"] += len(alerts)
            for a in alerts:
                logging.warning(f"[DDoS] Alert: {a}")
                if a["severity"] == "critical":
                    if self.iptables.block_ip(info["src"], duration=600):
                        self.stats["ips_blocked"] += 1

        # ML detection periodically
        if self.stats["packets_processed"] % 5000 == 0:
            self.detector.update_model(list(self.packets))
        if self.stats["packets_processed"] % 1000 == 0:
            is_anom, score = self.detector.detect_anomaly(list(self.packets))
            if is_anom:
                logging.info(f"[DDoS][ML] Anomaly detected (score={score:.3f})")

    def start(self, count=None, timeout=None):
        logging.info(f"[DDoS] Starting on interface {self.interface}")
        try:
            scapy.sniff(
                iface=self.interface,
                prn=self._process_packet,
                count=count,
                timeout=timeout,
                store=0
            )
        except PermissionError:
            logging.error("Permission denied. Try: sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)")
        except Exception as e:
            logging.error(f"[DDoS] Error during sniff: {e}")

    def stats_summary(self):
        runtime = max(1e-6, time.time() - self.stats["start_time"])
        return {
            **self.stats,
            "runtime_seconds": runtime,
            "packets_per_second": self.stats["packets_processed"] / runtime
        }

def main():
    ap = argparse.ArgumentParser(description="Lightweight DDoS Defense System")
    ap.add_argument("-i", "--interface", default="eth0", help="Network interface")
    ap.add_argument("-c", "--config", help="Config file path")
    ap.add_argument("-t", "--timeout", type=int, help="Sniff timeout seconds")
    ap.add_argument("-n", "--count", type=int, help="Packet count limit")
    args = ap.parse_args()

    dd = DDoSDefense(interface=args.interface, config_file=args.config)
    dd.start(count=args.count, timeout=args.timeout)
    s = dd.stats_summary()
    print("\n=== DDoS Defense Statistics ===")
    for k, v in s.items():
        print(f"{k}: {v:.3f}" if isinstance(v, float) else f"{k}: {v}")

if __name__ == "__main__":
    main()
EOF
chmod +x "$PROJECT_ROOT/ddos_defense/ddos_defense.py"

# ------------------------------------------------------------------------------
# main.py (integrated runner)
# ------------------------------------------------------------------------------
cat > "$PROJECT_ROOT/main.py" << 'EOF'
#!/usr/bin/env python3
import sys
import os
import time
import signal
import argparse
from pathlib import Path

# Local imports
sys.path.append(str(Path(__file__).parent))
from path_monitor.path_monitor import PathMonitor
from ddos_defense.ddos_defense import DDoSDefense

class NetworkSecuritySystem:
    def __init__(self, interface="eth0", config=None):
        self.interface = interface
        self.config = config
        self.path_monitor = None
        self.ddos = None
        self.running = False
        signal.signal(signal.SIGINT, self._sig)
        signal.signal(signal.SIGTERM, self._sig)

    def _sig(self, *_):
        print("\n[!] Signal received. Stopping...")
        self.stop()
        sys.exit(0)

    def start_path(self):
        self.path_monitor = PathMonitor(interface=self.interface, config_file=self.config)
        self.path_monitor.start()

    def start_ddos(self):
        self.ddos = DDoSDefense(interface=self.interface, config_file=self.config)
        self.ddos.start()

    def start_integrated(self):
        print(f"[+] Starting integrated system on {self.interface}")
        self.running = True
        import threading
        t1 = threading.Thread(target=self.start_path, daemon=True)
        t2 = threading.Thread(target=self.start_ddos, daemon=True)
        t1.start()
        t2.start()
        try:
            while self.running:
                time.sleep(10)
                self.print_status()
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def print_status(self):
        print("\n========== Network Security Status ==========")
        if self.path_monitor:
            s = self.path_monitor.stats_summary()
            print(f"Path Monitor: packets={s['packets_processed']}, validated={s['paths_validated']}, anomalies={s['anomalies_detected']}")
        if self.ddos:
            s = self.ddos.stats_summary()
            print(f"DDoS Defense: packets={s['packets_processed']}, attacks={s['attacks_detected']}, blocked={s['ips_blocked']}")

    def stop(self):
        self.running = False
        print("[+] System stopped")

def list_interfaces():
    try:
        import scapy.all as scapy
        return scapy.get_if_list()
    except Exception:
        return []

def main():
    ap = argparse.ArgumentParser(description="Path-Aware Network Security Monitor & DDoS Defense")
    ap.add_argument("-i", "--interface", default="eth0", help="Network interface")
    ap.add_argument("-c", "--config", help="Config file (default: config/config.json)")
    ap.add_argument("--mode", choices=["integrated", "path-only", "ddos-only"], default="integrated")
    ap.add_argument("--list-interfaces", action="store_true", help="List interfaces")
    args = ap.parse_args()

    if args.list_interfaces:
        ifaces = list_interfaces()
        print("Available interfaces:")
        for i in ifaces:
            print(f"  {i}")
        return

    if not args.config:
        cfg = Path(__file__).parent / "config" / "config.json"
        if cfg.exists():
            args.config = str(cfg)

    ns = NetworkSecuritySystem(interface=args.interface, config=args.config)
    try:
        if args.mode == "integrated":
            ns.start_integrated()
        elif args.mode == "path-only":
            ns.start_path()
        else:
            ns.start_ddos()
    except KeyboardInterrupt:
        pass
    finally:
        ns.stop()

if __name__ == "__main__":
    main()
EOF
chmod +x "$PROJECT_ROOT/main.py"

# ------------------------------------------------------------------------------
# setup.sh
# ------------------------------------------------------------------------------
cat > "$PROJECT_ROOT/setup.sh" << 'EOF'
#!/usr/bin/env bash
set -euo pipefail

echo "[+] Installing system dependencies (Ubuntu)..."
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-dev libpcap-dev tcpdump iptables build-essential

echo "[+] Installing Python requirements..."
pip3 install -r requirements.txt

echo "[+] Preparing logs/data directories..."
mkdir -p logs data

echo "[+] (Optional) Grant Python packet capture capabilities"
PY3=$(which python3 || true)
if [ -n "${PY3}" ]; then
  sudo setcap cap_net_raw,cap_net_admin+eip "${PY3}" || true
fi

echo "[+] Done. You may need to re-login for capability/group changes to take effect."
echo ""
echo "To run the system:"
echo "    python3 main.py --list-interfaces"
echo "    python3 main.py -i eth0 --mode integrated"
echo "    python3 main.py -i lo --mode integrated  # For testing on loopback"
echo ""
echo "Individual components:"
echo "    python3 path_monitor/path_monitor.py -i eth0 -t 60"
echo "    python3 ddos_defense/ddos_defense.py -i eth0 -t 300"
EOF
chmod +x "$PROJECT_ROOT/setup.sh"

# ------------------------------------------------------------------------------
# README.md
# ------------------------------------------------------------------------------
cat > "$PROJECT_ROOT/README.md" << 'EOF'
# Path-Aware Network Security Monitor & DDoS Defense System

A comprehensive network security solution combining SCION-inspired path-aware monitoring with lightweight DDoS protection mechanisms.

## Features

- **Path-Aware Monitoring**: RSA-based cryptographic path validation and routing anomaly detection
- **DDoS Defense**: Token bucket rate limiting, ML-based anomaly detection, and automatic IP blocking
- **Real-time Analysis**: Live packet capture and processing with comprehensive logging
- **Modular Design**: Run components individually or integrated together

## Quick Start

- After running bootstrap.sh
./setup.sh

List available network interfaces
python3 main.py --list-interfaces

Run integrated system (both components)
python3 main.py -i eth0 --mode integrated

Run individual components
python3 main.py -i eth0 --mode path-only
python3 main.py -i eth0 --mode ddos-only

Test on loopback interface (no special privileges needed)
python3 main.py -i lo --mode integrated


## System Requirements

- Ubuntu 18.04+ or similar Linux distribution
- Python 3.7+
- Root privileges for packet capture and iptables management
- Network interface with packet capture capabilities

## Configuration

Edit `config/config.json` to customize:
- Network interfaces and monitoring settings
- Cryptographic parameters for path validation
- Token bucket rates and ML detection thresholds
- Logging levels and output formats

## Security Notes

- Packet capture requires capabilities: `sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)`
- iptables integration requires root privileges for automatic IP blocking
- Monitor logs in `logs/` directory for security events and system status

## Architecture

- **PathValidator**: RSA-2048 signatures with SHA-256 hashing for path integrity
- **PathAnalyzer**: NetworkX-based topology analysis and anomaly detection
- **TokenBucket**: Rate limiting implementation with configurable parameters
- **MLAnomalyDetector**: Isolation Forest algorithm for traffic pattern analysis
- **IPTablesManager**: Linux firewall integration for dynamic blocking

This system demonstrates advanced network security concepts from academic research translated into practical, deployable tools.
EOF

echo "[+] Installing Python dependencies now (this may take a few minutes)..."
if pip3 install -r "$PROJECT_ROOT/requirements.txt" 2>/dev/null; then
    echo "[+] Dependencies installed successfully!"
else
    echo "[!] Some dependencies may have failed to install. Run './setup.sh' after bootstrap completes."
fi

echo ""
echo "========================================="
echo "[+] Project bootstrapped successfully!"
echo "========================================="
echo ""
echo "Next steps:"
echo "  1. ./setup.sh                              # Install system dependencies"
echo "  2. python3 main.py --list-interfaces       # See available interfaces"
echo "  3. python3 main.py -i eth0 --mode integrated  # Start full system"
echo "  4. python3 main.py -i lo --mode integrated    # Test on loopback (safer)"
echo ""
echo "Individual components:"
echo "  python3 path_monitor/path_monitor.py -i eth0 -t 60"
echo "  python3 ddos_defense/ddos_defense.py -i eth0 -t 300"
echo ""
echo "For iptables features, run with sudo privileges."
echo "Check logs/ directory for runtime logs and security events."
echo "========================================="
