# Developed by Galal Noaman – RedShadow_V2
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.

# RedShadow_v2/main.py

import argparse
import re
import sys
import os
from termcolor import cprint


def is_valid_domain(domain):
    return re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", domain) is not None


def is_safe_path(path):
    return not (".." in path or path.startswith("/") or path.startswith("\\"))


def main():
    parser = argparse.ArgumentParser(
        description="🛡️ RedShadow V2 – Red Team Reconnaissance and CVE Analysis Tool"
    )
    parser.add_argument('-v', '--version', action='version', version='RedShadow_V2.0')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')

    subparsers = parser.add_subparsers(dest='command', required=True)

    # ─────── auto (NEW — full pipeline) ───────
    auto_parser = subparsers.add_parser('auto', help='Run full recon pipeline automatically (recommended)')
    auto_parser.add_argument('--target', required=True, help='Target root domain (e.g. hackerone.com)')
    auto_parser.add_argument('--output-dir', default='outputs', help='Output directory for all results')
    auto_parser.add_argument('--wordlist', default=None, help='Path to custom DNS wordlist (optional)')
    auto_parser.add_argument('--insecure', action='store_true', help='Disable TLS verification')
    auto_parser.add_argument('--no-bruteforce', action='store_true', help='Skip DNS bruteforce stage')

    # ─────── scan ───────
    scan_parser = subparsers.add_parser('scan', help='Run Nmap port scan on targets')
    scan_parser.add_argument('--input', required=True, help='Input file with domains')
    scan_parser.add_argument('--output', default='outputs/scan_results.json', help='Output path for scan results')

    # ─────── domain ───────
    domain_parser = subparsers.add_parser('domain', help='Enumerate subdomains using crt.sh')
    domain_parser.add_argument('--target', required=True, help='Target root domain')
    domain_parser.add_argument('--output', default='outputs/subdomains.txt', help='Output path')

    # ─────── bruteforce ───────
    brute_parser = subparsers.add_parser('bruteforce', help='DNS bruteforce subdomain discovery')
    brute_parser.add_argument('--target', required=True, help='Target root domain')
    brute_parser.add_argument('--output', default='outputs/subdomains.txt', help='Output path (appends to existing)')
    brute_parser.add_argument('--wordlist', default=None, help='Path to wordlist (optional, uses built-in if not set)')

    # ─────── passive ───────
    passive_parser = subparsers.add_parser('passive', help='Perform passive recon (headers, HTML, tech stack)')
    passive_parser.add_argument('--input', default='outputs/subdomains.txt', help='Input subdomains file')
    passive_parser.add_argument('--output', default='outputs/passive_results.json', help='Output path')
    passive_parser.add_argument('--insecure', action='store_true', help='Disable TLS verification')
    passive_parser.add_argument('--verbose', action='store_true', help='Show verbose error details')

    # ─────── analyse ───────
    analyse_parser = subparsers.add_parser('analyse', help='Analyse scan results and match known CVEs')
    analyse_parser.add_argument('--input', default='outputs/scan_results.json', help='Input file for analysis')
    analyse_parser.add_argument('--output', default='outputs/analysis_results.json', help='Output path')

    # ─────── report ───────
    report_parser = subparsers.add_parser('report', help='Generate Markdown + HTML report from analysis results')
    report_parser.add_argument('--input', default='outputs/analysis_results.json', help='Input analysis file')
    report_parser.add_argument('--output', default='outputs/redshadow_report.md', help='Output .md report path')
    report_parser.add_argument('--html', default='outputs/redshadow_report.html', help='Output .html report path')

    args = parser.parse_args()

    try:
        # ── Path safety checks ──
        for attr in ['output', 'input', 'output_dir']:
            val = getattr(args, attr, None)
            if val and not is_safe_path(val):
                raise ValueError(f"[!] Unsafe path detected: {val}")

        # ── Command dispatch ──

        if args.command == 'auto':
            if not is_valid_domain(args.target):
                raise ValueError(f"[!] Invalid domain format: {args.target}")
            from modules.pipeline import run_pipeline
            run_pipeline(
                target=args.target,
                output_dir=args.output_dir,
                wordlist=args.wordlist,
                insecure=args.insecure,
                verbose=args.verbose,
                skip_bruteforce=args.no_bruteforce
            )

        elif args.command == 'scan':
            from modules import scan
            scan.run_scan(args.input, args.output)

        elif args.command == 'domain':
            if not is_valid_domain(args.target):
                raise ValueError(f"[!] Invalid domain format: {args.target}")
            from modules import domain
            domain.enumerate_subdomains(args.target, args.output)

        elif args.command == 'bruteforce':
            if not is_valid_domain(args.target):
                raise ValueError(f"[!] Invalid domain format: {args.target}")
            from modules.bruteforce import dns_bruteforce
            dns_bruteforce(args.target, args.output, wordlist=args.wordlist)

        elif args.command == 'passive':
            from modules import passive
            passive.passive_recon(
                input_file=args.input,
                output_file=args.output,
                insecure=args.insecure,
                verbose=args.verbose
            )

        elif args.command == 'analyse':
            from modules import analyse
            analyse.analyse_scan_results(args.input, args.output)

        elif args.command == 'report':
            from modules import report
            report.generate_report(args.input, args.output, html_output=args.html)

    except Exception as e:
        cprint(f"[!] An error occurred: {e}", "red")
        sys.exit(1)


if __name__ == "__main__":
    main()