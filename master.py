#!/usr/bin/env python3
"""
Ebony & Ivory v2.0 — Dual-Protocol Network Scanner

Dante's signature pistols reforged in Python. Ivory fires TCP SYN
half-open shots; Ebony launches UDP probes. Together they map the
demon network and grab service banners from the underworld.

Requires root privileges for raw socket access via Scapy.
"""

import argparse
import json
import os
import socket
import sys
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

# Shut up Scapy's startup noise
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, TCP, UDP, ICMP, sr1, send, conf

# Suppress Scapy's own send/recv chatter
conf.verb = 0

# ──────────────────── Dante's Arsenal ─────────────────────

DEFAULT_TCP_PORTS = [
    21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143,
    443, 445, 389, 636, 993, 995, 1433, 1521, 2049, 3306,
    3389, 5432, 5900, 5985, 5986, 6379, 8080, 8443, 8888, 9090,
]

DEFAULT_UDP_PORTS = [
    53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514,
    1900, 4500, 5353,
]

# Port → service name map (common ones for quick display)
SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP-S", 68: "DHCP-C", 69: "TFTP", 80: "HTTP", 88: "Kerberos",
    110: "POP3", 111: "RPCbind", 123: "NTP", 135: "MSRPC", 137: "NetBIOS-NS",
    138: "NetBIOS-DG", 139: "NetBIOS-SS", 143: "IMAP", 161: "SNMP",
    162: "SNMP-Trap", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    500: "IKE", 514: "Syslog", 636: "LDAPS", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 1900: "SSDP/UPnP",
    2049: "NFS", 3306: "MySQL", 3389: "RDP", 4500: "IPSec-NAT",
    5353: "mDNS", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM",
    5986: "WinRM-S", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "HTTP-Alt2", 9090: "Prometheus",
}

# TTL → OS guess (rough heuristic from ICMP/TCP responses)
OS_TTL_MAP = [
    (128, "Windows"),
    (64, "Linux/macOS/BSD"),
    (255, "Cisco/Network Device"),
    (254, "Solaris/AIX"),
]

# ───────────────── ANSI color helpers ─────────────────────

def _supports_color():
    return hasattr(sys.stderr, "isatty") and sys.stderr.isatty()

_COLOR = _supports_color()

def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if _COLOR else text

def red(t):     return _c("91", t)
def green(t):   return _c("92", t)
def yellow(t):  return _c("93", t)
def blue(t):    return _c("94", t)
def magenta(t): return _c("95", t)
def cyan(t):    return _c("96", t)
def bold(t):    return _c("1", t)
def dim(t):     return _c("2", t)

# ──────────────────── DMC banner ──────────────────────────

BANNER = f"""
{red('    ╔══════════════════════════════════════════════════════════╗')}
{red('    ║')}{bold('  ███████ █████   █████  █   █ █   █        ')}            {red('║')}
{red('    ║')}{bold('  █       █    █ █     █ ██  █  █ █         ')}            {red('║')}
{red('    ║')}{bold('  █████   █████  █     █ █ █ █   █     ┈━━  ')}            {red('║')}
{red('    ║')}{bold('  █       █    █ █     █ █  ██   █          ')}            {red('║')}
{red('    ║')}{bold('  ███████ █████   █████  █   █   █          ')}            {red('║')}
{red('    ║')}                                                          {red('║')}
{red('    ║')} {cyan('  ██ █  █  █████  █████  █   █                ')}          {red('║')}
{red('    ║')} {cyan('  ██ █  █ █     █ █    █  █ █                 ')}          {red('║')}
{red('    ║')} {cyan('  ██  █ █ █     █ █████    █    ┈━━           ')}          {red('║')}
{red('    ║')} {cyan('  ██   ██ █     █ █  █     █                  ')}          {red('║')}
{red('    ║')} {cyan('  ██    █  █████  █   █    █                  ')}          {red('║')}
{red('    ║')}                                                          {red('║')}
{red('    ║')}     {dim('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')}         {red('║')}
{red('    ║')}       {magenta('Dual-Protocol Scanner v2.0')}                        {red('║')}
{red('    ║')}       {yellow('"Jackpot!" ─ Dante Sparda')}                         {red('║')}
{red('    ╚══════════════════════════════════════════════════════════╝')}
"""

STYLE_RANKS = [
    (0,  dim("Dull")),
    (3,  "Crazy"),
    (6,  yellow("Blast")),
    (10, cyan("Atomic")),
    (15, magenta("Smokin' Sexy Style!!!")),
]

def style_rank(open_count):
    """Rate the scan results DMC-style based on open port count."""
    rank = STYLE_RANKS[0][1]
    for threshold, label in STYLE_RANKS:
        if open_count >= threshold:
            rank = label
    return rank


# ────────────────── port parsing ──────────────────────────

def parse_ports(port_str, defaults):
    """Parse port specification: '80,443', '1-1024', '22,80,8000-9000', or 'default'."""
    if not port_str or port_str.lower() == "default":
        return defaults

    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                start, end = int(start), int(end)
                if start > end:
                    start, end = end, start
                ports.update(range(start, min(end + 1, 65536)))
            except ValueError:
                print(f"  {red('[!]')} Invalid port range: {part}")
                sys.exit(1)
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                print(f"  {red('[!]')} Invalid port: {part}")
                sys.exit(1)
    return sorted(ports)


def service_name(port):
    """Look up a human-friendly service name for a port."""
    if port in SERVICE_MAP:
        return SERVICE_MAP[port]
    try:
        return socket.getservbyport(port)
    except OSError:
        return "unknown"


# ──────────────── OS fingerprinting ───────────────────────

def guess_os(ttl):
    """Rough OS guess from initial TTL value."""
    if ttl is None:
        return "Unknown"
    best_name = "Unknown"
    best_dist = 999
    for ref_ttl, name in OS_TTL_MAP:
        dist = abs(ttl - ref_ttl)
        if dist < best_dist:
            best_dist = dist
            best_name = name
    # Only guess if we're within ~10 of a known TTL
    return best_name if best_dist <= 10 else f"Unknown (TTL={ttl})"


# ──────────────── banner grabbing ─────────────────────────

def grab_banner(target, port, timeout=2.0):
    """Attempt to grab a service banner via a quick TCP connect + recv."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, port))

        # Some services send a banner immediately on connect
        # For HTTP, send a minimal request
        if port in (80, 8080, 8888, 8443, 443):
            s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + target.encode() + b"\r\n\r\n")
        elif port == 25:
            pass  # SMTP sends banner on connect
        elif port in (21,):
            pass  # FTP sends banner on connect
        else:
            # Try to recv whatever the service sends on connect
            pass

        banner = s.recv(1024)
        s.close()
        # Clean and truncate
        banner_text = banner.decode("utf-8", errors="replace").strip()
        # Take first line only
        first_line = banner_text.split("\n")[0].strip()
        return first_line[:120] if first_line else None
    except Exception:
        return None


# ──────────────── host discovery ──────────────────────────

def ping_check(target_ip, timeout=0.8):
    """ICMP echo + TCP SYN fallback for host discovery."""
    # ICMP first
    resp = sr1(IP(dst=target_ip) / ICMP(), timeout=timeout, verbose=False)
    if resp is not None:
        ttl = resp.ttl if hasattr(resp, "ttl") else None
        return True, ttl

    # TCP SYN fallback on common ports
    for port in [443, 80, 22, 3389]:
        resp = sr1(
            IP(dst=target_ip) / TCP(dport=port, flags="S"),
            timeout=0.5, verbose=False,
        )
        if resp and resp.haslayer(TCP):
            ttl = resp.ttl if hasattr(resp, "ttl") else None
            # Send RST to clean up
            send(IP(dst=target_ip) / TCP(dport=port, flags="R"), verbose=False)
            return True, ttl

    return False, None


def ping_sweep(subnet, timeout=0.8, workers=10):
    """Sweep a CIDR range for live hosts with parallel probing."""
    from scapy.utils import Net
    print(f"  {cyan('[*]')} Commencing host sweep on: {bold(subnet)}")

    targets = [str(ip) for ip in Net(subnet)]
    live_hosts = []
    host_ttls = {}

    def probe(ip):
        alive, ttl = ping_check(ip, timeout=timeout)
        return ip, alive, ttl

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(probe, ip): ip for ip in targets}
        for future in as_completed(futures):
            ip, alive, ttl = future.result()
            if alive:
                os_guess = guess_os(ttl)
                print(f"    {green('[+]')} Host detected: {bold(ip)}  {dim(os_guess)}")
                live_hosts.append(ip)
                host_ttls[ip] = ttl

    live_hosts.sort(key=lambda x: tuple(int(o) for o in x.split(".")))
    return live_hosts, host_ttls


# ────────────────── scanning ──────────────────────────────

def ivory_tcp_scan(target, port, timeout=1.0):
    """Ivory: TCP SYN half-open scan — fires a single shot and reads the flags."""
    syn = IP(dst=target) / TCP(dport=port, flags="S")
    resp = sr1(syn, timeout=timeout, verbose=False)

    if resp and resp.haslayer(TCP):
        flags = resp.getlayer(TCP).flags
        if flags == 0x12:  # SYN-ACK → open
            # Send RST to tear down (use send(), no response expected)
            send(IP(dst=target) / TCP(dport=port, flags="R"), verbose=False)
            return "OPEN"
        elif flags == 0x14:  # RST-ACK → closed
            return "CLOSED"
    return "FILTERED"


def ebony_udp_scan(target, port, timeout=2.0):
    """Ebony: UDP probe — sends a blank datagram and listens for ICMP unreachable."""
    resp = sr1(IP(dst=target) / UDP(dport=port), timeout=timeout, verbose=False)

    if resp is None:
        return "OPEN|FILTERED"
    elif resp.haslayer(UDP):
        return "OPEN"
    elif resp.haslayer(ICMP):
        icmp_type = resp.getlayer(ICMP).type
        icmp_code = resp.getlayer(ICMP).code
        if icmp_type == 3 and icmp_code == 3:
            return "CLOSED"
        elif icmp_type == 3 and icmp_code in (1, 2, 9, 10, 13):
            return "FILTERED"
    return "UNKNOWN"


def scan_ports(target, ports, scan_func, protocol, workers=1, timeout=1.0, banners=False):
    """Run a scan function across a port list, optionally with threading (TCP only)."""
    results = []

    def do_scan(port):
        state = scan_func(target, port, timeout)
        banner = None
        if banners and state == "OPEN" and protocol == "TCP":
            banner = grab_banner(target, port, timeout=2.0)
        return port, state, banner

    if workers > 1 and protocol == "TCP":
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(do_scan, p): p for p in ports}
            for future in as_completed(futures):
                results.append(future.result())
    else:
        for port in ports:
            results.append(do_scan(port))

    # Sort by port number
    results.sort(key=lambda r: r[0])
    return results


# ──────────────────── output ──────────────────────────────

def format_port_line(port, state, protocol, banner=None):
    """Format a single port result line."""
    svc = service_name(port)
    port_str = f"{protocol}/{port}"

    if state == "OPEN":
        line = f"    {green('│')} {green(f'{port_str:<12}')} {green('OPEN'):<18} {dim(svc)}"
        if banner:
            line += f"  {yellow('→')} {banner[:80]}"
        return line
    elif "OPEN" in state:
        return f"    {yellow('│')} {yellow(f'{port_str:<12}')} {yellow(state):<18} {dim(svc)}"
    return None  # Don't print closed/filtered by default


def print_scan_results(results, protocol, show_closed=False):
    """Print formatted scan results."""
    open_ports = [(p, s, b) for p, s, b in results if "OPEN" in s]
    closed = len([1 for _, s, _ in results if s == "CLOSED"])
    filtered = len([1 for _, s, _ in results if s == "FILTERED"])

    for port, state, banner in results:
        line = format_port_line(port, state, protocol, banner)
        if line:
            print(line)
        elif show_closed and state in ("CLOSED", "FILTERED"):
            svc = service_name(port)
            print(f"    {dim('│')} {dim(f'{protocol}/{port}'):<20} {dim(state):<18} {dim(svc)}")

    # Summary line
    summary_parts = [f"{green(str(len(open_ports)))} open"]
    if closed:
        summary_parts.append(f"{dim(str(closed))} closed")
    if filtered:
        summary_parts.append(f"{yellow(str(filtered))} filtered")
    print(f"    {dim('└─')} {', '.join(summary_parts)}")

    return len(open_ports)


def export_results(all_results, filepath):
    """Export scan results to JSON."""
    with open(filepath, "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    print(f"\n  {green('[+]')} Results exported to {bold(filepath)}")


# ──────────────────── CLI + main ──────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="Ebony & Ivory: Dual-Protocol Network Scanner — \"Let's rock, baby!\"",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  sudo python3 ebony_ivory.py -t 192.168.1.50\n"
            "  sudo python3 ebony_ivory.py -t 10.10.10.0/24 --mode ivory\n"
            "  sudo python3 ebony_ivory.py -t 192.168.1.50 -p 1-1024 --banners\n"
            "  sudo python3 ebony_ivory.py -t 10.10.10.5 --threads 20 --export results.json\n"
        ),
    )
    p.add_argument("-t", "--target", required=True,
                   help="Target IP or CIDR subnet (e.g. 192.168.1.50 or 10.10.10.0/24)")
    p.add_argument("--mode", choices=["ivory", "ebony", "both"], default="both",
                   help="ivory=TCP, ebony=UDP, both=full combo (default: both)")
    p.add_argument("-p", "--ports", default=None,
                   help="TCP ports: '80,443', '1-1024', '22,80,8000-9000' (default: curated list)")
    p.add_argument("-up", "--udp-ports", default=None,
                   help="UDP ports: same format as -p (default: curated list)")
    p.add_argument("--threads", type=int, default=10,
                   help="Parallel threads for TCP scans (default: 10)")
    p.add_argument("--timeout", type=float, default=1.0,
                   help="Per-port timeout in seconds (default: 1.0)")
    p.add_argument("--banners", action="store_true",
                   help="Attempt service banner grabbing on open TCP ports")
    p.add_argument("--show-closed", action="store_true",
                   help="Show closed/filtered ports in output")
    p.add_argument("--skip-ping", action="store_true",
                   help="Skip host discovery, scan target directly")
    p.add_argument("--export", metavar="FILE",
                   help="Export results to JSON file")
    return p.parse_args()


def main():
    args = parse_args()
    print(BANNER)

    target_input = args.target
    tcp_ports = parse_ports(args.ports, DEFAULT_TCP_PORTS)
    udp_ports = parse_ports(args.udp_ports, DEFAULT_UDP_PORTS)

    scan_start = time.time()
    target_hosts = []
    host_ttls = {}

    # ── Host discovery ──
    if "/" in target_input:
        target_hosts, host_ttls = ping_sweep(target_input, workers=args.threads)
        if not target_hosts:
            print(f"\n  {red('[-]')} No live hosts answered. The demons are hiding.")
            if not args.skip_ping:
                print(f"  {dim('    Try --skip-ping to scan anyway')}")
                sys.exit(0)
    else:
        if args.skip_ping:
            print(f"  {yellow('[*]')} Skipping ping check — going in blind like Dante")
            target_hosts.append(target_input)
        else:
            print(f"  {cyan('[*]')} Verifying target: {bold(target_input)}")
            alive, ttl = ping_check(target_input)
            if alive:
                os_guess = guess_os(ttl)
                print(f"    {green('[+]')} Host is up!  {dim(os_guess)}")
                target_hosts.append(target_input)
                host_ttls[target_input] = ttl
            else:
                print(f"    {red('[-]')} Target did not respond to ICMP or TCP probes")
                print(f"    {dim('    Try --skip-ping to force the scan')}")
                sys.exit(0)

    if not target_hosts:
        print(f"\n  {red('[-]')} No targets to scan. Exiting.")
        sys.exit(0)

    print(f"\n  {cyan('[*]')} Locking on to {bold(str(len(target_hosts)))} target(s)...")
    if args.mode in ("ivory", "both"):
        print(f"  {dim(f'    Ivory: {len(tcp_ports)} TCP ports')}")
    if args.mode in ("ebony", "both"):
        print(f"  {dim(f'    Ebony: {len(udp_ports)} UDP ports')}")

    all_export = []
    total_open = 0

    for target in target_hosts:
        print(f"\n  {red('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')}")
        ttl = host_ttls.get(target)
        os_guess = guess_os(ttl)
        print(f"  {bold('Target:')} {bold(target)}  {dim(os_guess)}")
        print(f"  {red('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')}")

        host_result = {"target": target, "os_guess": os_guess, "tcp": [], "udp": []}

        # ── Ivory (TCP) ──
        if args.mode in ("ivory", "both"):
            print(f"\n  {bold(cyan('[Ivory]'))} Firing TCP SYN shots...")
            tcp_results = scan_ports(
                target, tcp_ports, ivory_tcp_scan, "TCP",
                workers=args.threads, timeout=args.timeout,
                banners=args.banners,
            )
            tcp_open = print_scan_results(tcp_results, "TCP", show_closed=args.show_closed)
            total_open += tcp_open
            host_result["tcp"] = [
                {"port": p, "state": s, "service": service_name(p), "banner": b}
                for p, s, b in tcp_results if "OPEN" in s
            ]

        # ── Ebony (UDP) ──
        if args.mode in ("ebony", "both"):
            print(f"\n  {bold(magenta('[Ebony]'))} Firing UDP probe shots...")
            udp_results = scan_ports(
                target, udp_ports, ebony_udp_scan, "UDP",
                workers=1, timeout=max(args.timeout, 2.0),
            )
            udp_open = print_scan_results(udp_results, "UDP", show_closed=args.show_closed)
            total_open += udp_open
            host_result["udp"] = [
                {"port": p, "state": s, "service": service_name(p)}
                for p, s, _ in udp_results if "OPEN" in s
            ]

        all_export.append(host_result)

    # ── Final summary ──
    elapsed = time.time() - scan_start
    rank = style_rank(total_open)

    print(f"\n  {red('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')}")
    print(f"  {bold('Mission Complete!')}")
    print(f"    Hosts scanned:  {len(target_hosts)}")
    print(f"    Open ports:     {total_open}")
    print(f"    Elapsed:        {elapsed:.1f}s")
    print(f"    Style Rank:     {rank}")
    print(f"  {red('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')}")

    if args.export:
        export_results(all_export, args.export)

    print(f"\n  {yellow('\"Jackpot!\"')} {dim('─ Dante')}\n")


if __name__ == "__main__":
    if os.geteuid() != 0:
        sss = "Smokin' Sexy Style"
        print(f"\n  {red('[!]')} Ebony & Ivory require {bold(sss)} privileges!")
        print(f"  {dim('    Run with: sudo python3 ebony_ivory.py ...')}\n")
        sys.exit(1)
    main()
