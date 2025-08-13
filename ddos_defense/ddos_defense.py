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
from gnn_security_analyzer import GNNSecurityAnalyzer, NetworkFlow
GNN_CFG={"epochs":5,"hidden":32}


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
        self.gnn = GNNSecurityAnalyzer(GNN_CFG)   # train later
        self.gnn_trained=False

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
        # train GNN every 10k packets
        if self.stats["packets_processed"] % 10000 == 0 and not self.gnn_trained:
            fl=[NetworkFlow(p["src"],p["dst"],p.get("src_port",0),p.get("dst_port",0),
                            p["proto"],p["size"],0,p.get("flags",0),p["ttl"],p["timestamp"])
                for p in self.packets]
            self.gnn.train_model(fl); self.gnn_trained=True
        # use GNN every 2k packets
        if self.gnn_trained and self.stats["packets_processed"] % 2000 == 0:
            score=self.gnn.predict(fl[:200])   # quick sample
            if score>0.7:
                logging.warning("[DDoS][GNN] high attack prob %.2f",score)


    def start(self, count=None, timeout=None):
        logging.info(f"[DDoS] Starting on interface {self.interface}")
        if count is None:
            count = 0
        if timeout is None:
            timeout = 0
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
