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

    def start_path(self, **kwargs):
        self.path_monitor = PathMonitor(interface=self.interface,
                                        config_file=self.config)
        self.path_monitor.start(**kwargs)

    def start_ddos(self, **kwargs):
        self.ddos = DDoSDefense(interface=self.interface,
                                config_file=self.config)
        self.ddos.start(**kwargs)

    def start_integrated(self, **kwargs):
        print(f"[+] Starting integrated system on {self.interface}")
        self.running = True
        import threading
        t1 = threading.Thread(target=self.start_path,  kwargs=kwargs,
                              daemon=True)
        t2 = threading.Thread(target=self.start_ddos, kwargs=kwargs,
                              daemon=True)
        t1.start(); t2.start()
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
    ap.add_argument("-t", "--timeout", type=int,
                    help="Sniff timeout in seconds (0 = run forever)")
    ap.add_argument("-n", "--count",   type=int,
                    help="Number of packets to capture (0 = unlimited)")
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
    extra = {"count": args.count, "timeout": args.timeout}
    try:
        if args.mode == "integrated":
            ns.start_integrated(**extra)
        elif args.mode == "path-only":
            ns.start_path(**extra)
        else:                      # ddos-only
            ns.start_ddos(**extra)
    except KeyboardInterrupt:
        pass
    finally:
        ns.stop()

if __name__ == "__main__":
    main()
