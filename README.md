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
