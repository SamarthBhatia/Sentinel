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
