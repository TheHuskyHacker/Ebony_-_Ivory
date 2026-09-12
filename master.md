# Ebony & Ivory v2.0 — Dual-Protocol Network Scanner

<img width="1376" height="768" alt="image" src="https://github.com/user-attachments/assets/7bdc8d0c-581e-459c-baad-97c7155260e5" />

A Python network enumerator built on Scapy's raw packet engine. Inspired by Dante Sparda's signature pistols from Devil May Cry — **Ivory** fires rapid TCP SYN half-open shots while **Ebony** launches UDP probes into the void. Together they map networks, grab service banners, fingerprint operating systems, and rate your scan results DMC-style.

---

## Features

- **Host Discovery** — ICMP echo with TCP SYN fallback on 443/80/22/3389 for hosts that block ping
- **Network Sweep** — parallel CIDR sweep with threaded probing
- **Ivory (TCP SYN Scan)** — stealthy half-open scans that never complete the handshake
- **Ebony (UDP Scan)** — identifies active UDP services via ICMP unreachable analysis
- **Banner Grabbing** — pulls service banners from open TCP ports (HTTP, FTP, SMTP, SSH, etc.)
- **OS Fingerprinting** — TTL-based OS guessing from probe responses
- **Custom Port Ranges** — specify exact ports, ranges, or combos (`-p 22,80,8000-9000`)
- **Threaded Scanning** — parallel TCP scans for speed (configurable thread count)
- **Service Identification** — maps ports to service names automatically
- **JSON Export** — dump results to a structured file for tool integration
- **Style Ranking** — rates your scan from *Dull* to *Smokin' Sexy Style!!!*

---

## Prerequisites

Requires root/sudo for Scapy's raw socket access.

```bash
pip install scapy
```

---

## Usage

```bash
# Full combo scan (TCP + UDP) on a single host
sudo python3 ebony_ivory.py -t 192.168.1.50

# Sweep a subnet first, then scan all live hosts
sudo python3 ebony_ivory.py -t 10.10.10.0/24

# Ivory only (TCP) with custom ports
sudo python3 ebony_ivory.py -t 192.168.1.50 --mode ivory -p 1-1024

# Ebony only (UDP)
sudo python3 ebony_ivory.py -t 192.168.1.50 --mode ebony

# Full scan with banner grabbing and 20 threads
sudo python3 ebony_ivory.py -t 10.10.10.5 -p 1-65535 --banners --threads 20

# Skip ping check and export results
sudo python3 ebony_ivory.py -t 10.10.10.5 --skip-ping --export results.json

# Custom TCP and UDP port lists
sudo python3 ebony_ivory.py -t 192.168.1.50 -p 22,80,443,8080-8090 -up 53,161,500
```

### All Options

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --target` | Target IP or CIDR subnet | required |
| `--mode` | `ivory` (TCP), `ebony` (UDP), `both` | `both` |
| `-p, --ports` | TCP ports: `80,443` / `1-1024` / mixed | curated list |
| `-up, --udp-ports` | UDP ports: same format | curated list |
| `--threads` | Parallel threads for TCP scans | 10 |
| `--timeout` | Per-port timeout (seconds) | 1.0 |
| `--banners` | Grab service banners on open TCP ports | off |
| `--show-closed` | Show closed/filtered ports in output | off |
| `--skip-ping` | Skip host discovery, scan directly | off |
| `--export FILE` | Export results to JSON | — |
| `-Pn` | Ping Flag | - | 

---

## Default Scanned Ports

**TCP (Ivory):** 21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 443, 445, 389, 636, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 8080, 8443, 8888, 9090

**UDP (Ebony):** 53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 1900, 4500, 5353

---

## Style Ranks

| Open Ports | Rank |
|-----------|------|
| 0–2 | Dull |
| 3–5 | Crazy |
| 6–9 | Blast |
| 10–14 | Atomic |
| 15+ | Smokin' Sexy Style!!! |

---

## Legal

This tool uses raw sockets for passive network enumeration. Always obtain written authorization before scanning targets you do not own.

*"Jackpot!" — Dante*
