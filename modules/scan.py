# Developed by Galal Noaman – RedShadow_V2
# For educational and lawful use only.

import re
import json
import os
import sys
import socket
import time
import subprocess
import dns.resolver
import nmap
from datetime import datetime
from termcolor import cprint
from multiprocessing.dummy import Pool as ThreadPool
from modules.utils import load_config

# ─────────── Exceptions ───────────
class ScanError(Exception): pass
class DNSResolutionError(Exception): pass

# ─────────── Config ───────────
try:
    config = load_config()
    scan_cfg = config.get("scan", {})
    default_ports = scan_cfg.get("nmap_ports", "21,22,80,443,8080")
    max_threads = int(scan_cfg.get("max_threads", 10))
    dns_servers = scan_cfg.get("dns_servers", ["8.8.8.8", "1.1.1.1"])
except Exception as err:
    cprint(f"[!] Failed to load config: {err}", "red")
    sys.exit(1)

fallback_dns = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"]

# ─────────── Validation ───────────
def is_valid_target(target):
    return (
        re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", target) or
        re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target)
    )

def resolve_domain(domain, log_file="outputs/scan_dns_failures.txt", dns_servers=None):
    reasons = []

    if dns_servers is None:
        dns_servers = fallback_dns

    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = dns_servers
        resolver.timeout = 3
        resolver.lifetime = 5
        answer = resolver.resolve(domain, 'A')
        return domain, answer[0].to_text()
    except Exception as e:
        reasons.append(f"A record failed: {e}")

    try:
        cname = resolver.resolve(domain, 'CNAME')
        cname_target = str(cname[0].target)
        answer = resolver.resolve(cname_target, 'A')
        return domain, answer[0].to_text()
    except Exception as e:
        reasons.append(f"CNAME fallback failed: {e}")

    try:
        answer = resolver.resolve(domain, 'AAAA')
        return domain, answer[0].to_text()
    except Exception as e:
        reasons.append(f"AAAA (IPv6) fallback failed: {e}")

    try:
        dig_result = subprocess.check_output(["dig", "+short", domain], stderr=subprocess.DEVNULL).decode().strip()
        if dig_result:
            first_ip = dig_result.split("\n")[0]
            return domain, first_ip
    except Exception as e:
        reasons.append(f"dig fallback failed: {e}")

    try:
        ip = socket.gethostbyname(domain)
        return domain, ip
    except Exception as e:
        reasons.append(f"socket fallback failed: {e}")

    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    with open(log_file, "a", encoding="utf-8") as log:
        log.write(f"{domain} - DNS resolution failed:\n")
        for r in reasons:
            log.write(f"    {r}\n")

    return domain, None

# ─────────── Nmap Scan ───────────
def scan_target(args):
    domain, ip = args
    scanner = nmap.PortScanner()
    try:
        scanner.scan(
            hosts=ip,
            arguments=f'-sS -sV -T4 -Pn -n -p {default_ports}'
        )
    except Exception as error:
        return {domain: {'ip': ip, 'error': f'Scan failed: {error}'}}

    for host in scanner.all_hosts():
        protocols = {}
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto]
            proto_ports = {}
            for port in ports:
                port_data = ports[port]
                state = port_data.get('state', 'unknown')
                if state not in ('open', 'open|filtered'):
                    continue
                proto_ports[port] = {
                    'state': state,
                    'service': port_data.get('name', ''),
                    'product': port_data.get('product', ''),
                    'version': port_data.get('version', '') or 'x',
                    'extrainfo': port_data.get('extrainfo', '')
                }
            if proto_ports:
                protocols[proto] = proto_ports

        return {
            domain: {
                'ip': ip,
                'hostname': scanner[host].hostname() or domain,
                'state': scanner[host].state(),
                'protocols': protocols,
                'ports_scanned': default_ports
            }
        }

    return {domain: {'ip': ip, 'note': 'No open ports found'}}

# ─────────── Main Scan Logic ───────────
def run_scan(input_file, output_file):
    cprint(f"[+] Reading targets from {input_file}", "cyan")
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            raw_targets = sorted(set(
                line.strip().lower() for line in f
                if line.strip() and not line.startswith("*.") and not line.startswith("#")
            ))
    except Exception as error:
        cprint(f"[!] Failed to read input file: {error}", "red")
        return

    filtered_targets = [t for t in raw_targets if is_valid_target(t)]
    if not filtered_targets:
        cprint("[!] No valid domains or IPs to scan.", "yellow")
        return

    cprint("[+] Resolving targets...", "cyan")
    if os.path.exists("outputs/scan_dns_failures.txt"):
        os.remove("outputs/scan_dns_failures.txt")

    def retry_domain(domain, attempts=3):
        for _ in range(attempts):
            d, ip = resolve_domain(domain)
            if ip:
                return d, ip
        return domain, None

    with ThreadPool(max_threads) as pool:
        resolved = pool.map(retry_domain, filtered_targets)

    failed = [d for d, ip in resolved if not ip]
    targets = [(d, ip) for d, ip in resolved if ip]

    if failed:
        cprint(f"[!] {len(failed)} domain(s) failed DNS resolution (see outputs/scan_dns_failures.txt)", "yellow")

    if not targets:
        cprint("[!] No live targets to scan.", "red")
        return

    cprint(f"[+] Starting Nmap scans on {len(targets)} target(s)...", "cyan")
    with ThreadPool(max_threads) as pool:
        results = pool.map(scan_target, targets)

    final_output = {
        "scan_timestamp": datetime.utcnow().isoformat() + "Z",
        "results": {}
    }
    for entry in results:
        if isinstance(entry, dict):
            final_output["results"].update(entry)

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(final_output, f, indent=2)
        cprint(f"[✓] Scan complete. Results saved to {output_file}", "green")
    except Exception as error:
        cprint(f"[!] Failed to write output: {error}", "red")

# ─────────── CLI Support ───────────
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 scan.py <input_file.txt> <output_file.json>")
    else:
        run_scan(sys.argv[1], sys.argv[2])
