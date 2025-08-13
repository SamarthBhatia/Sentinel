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
from zero_trust_engine import ZeroTrustEngine, EntityType
ZC_DEFAULTS={"normal_packet_rate":1000,"normal_bandwidth":10_000_000,"max_destinations":50}


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
        self.zt = ZeroTrustEngine(ZC_DEFAULTS)
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
        pinfo=self._extract_path_info(pkt);  # may be None
        if not pinfo: return
        # --- Zero-Trust check --------------------------------------------------
        lvl, _ = self.zt.evaluate_entity(pinfo["src_ip"], EntityType.DEVICE,
                                        {"behavior":{"packet_rate":1}})
        if lvl is TrustLevel.UNTRUSTED:   # drop packet
            return
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
