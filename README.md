# DoS Blocker

A Python-based DoS detection and prevention tool that monitors incoming network traffic and blocks IP addresses that exceed a defined packet-per-second threshold.

---

## How It Works

- Captures incoming IP packets using `scapy`
- Tracks the number of packets received per source IP
- If an IP exceeds the packet rate threshold (default: 40 packets/sec), it is blocked using `iptables`

---

## Requirements

- Python 3
- Linux (tested on Ubuntu)
- Root access (`sudo`)
- `scapy` library
- Two VMs or machines on the same local network (one to monitor, one to send traffic)

---

## Setup

```bash
git clone https://github.com/ayubhali/DosBlocker.git
cd DosBlocker

python3 -m venv venv
source venv/bin/activate

pip install scapy
```
