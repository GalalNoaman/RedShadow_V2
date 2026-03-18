# Developed by Galal Noaman – RedShadow_V2
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.

# RedShadow_v2/modules/pipeline.py
# Orchestrates the full auto recon pipeline: domain → bruteforce → passive → scan → analyse → report

import os
import sys
import time
import json
from datetime import datetime
from termcolor import cprint

# ─────────────────────────────────────────
# Stage Runner — wraps each module call
# ─────────────────────────────────────────

def run_stage(stage_name, func, *args, **kwargs):
    """
    Runs a single pipeline stage. On failure, logs the error and continues.
    Returns True on success, False on failure.
    """
    cprint(f"\n{'='*60}", "cyan")
    cprint(f"  [►] Stage: {stage_name}", "cyan")
    cprint(f"{'='*60}", "cyan")
    start = time.time()

    try:
        func(*args, **kwargs)
        elapsed = round(time.time() - start, 2)
        cprint(f"  [✓] {stage_name} completed in {elapsed}s", "green")
        return True
    except Exception as e:
        elapsed = round(time.time() - start, 2)
        cprint(f"  [!] {stage_name} failed after {elapsed}s: {e}", "red")
        cprint(f"  [→] Skipping to next stage...", "yellow")
        return False


# ─────────────────────────────────────────
# Summary Printer
# ─────────────────────────────────────────

def print_summary(target, stage_results, output_dir, start_time):
    elapsed = round(time.time() - start_time, 2)
    total = len(stage_results)
    passed = sum(1 for v in stage_results.values() if v)
    failed = total - passed

    cprint(f"\n{'='*60}", "magenta")
    cprint(f"  🛡️  RedShadow Auto Scan — Complete", "magenta")
    cprint(f"{'='*60}", "magenta")
    cprint(f"  Target     : {target}", "white")
    cprint(f"  Duration   : {elapsed}s", "white")
    cprint(f"  Stages     : {passed}/{total} passed", "green" if failed == 0 else "yellow")

    cprint(f"\n  Stage Results:", "white")
    for stage, success in stage_results.items():
        icon = "✓" if success else "✗"
        colour = "green" if success else "red"
        cprint(f"    [{icon}] {stage}", colour)

    cprint(f"\n  Output Files:", "white")
    expected_files = [
        "subdomains.txt",
        "passive_results.json",
        "scan_results.json",
        "analysis_results.json",
        "redshadow_report.md",
        "redshadow_report.html",
    ]
    for fname in expected_files:
        fpath = os.path.join(output_dir, fname)
        if os.path.exists(fpath):
            size = os.path.getsize(fpath)
            cprint(f"    [✓] {fpath} ({size} bytes)", "green")
        else:
            cprint(f"    [✗] {fpath} (not generated)", "red")

    cprint(f"\n{'='*60}\n", "magenta")


# ─────────────────────────────────────────
# Subdomain Count Helper
# ─────────────────────────────────────────

def count_subdomains(filepath):
    try:
        with open(filepath, "r") as f:
            return sum(1 for line in f if line.strip())
    except Exception:
        return 0


# ─────────────────────────────────────────
# Main Pipeline Entry Point
# ─────────────────────────────────────────

def run_pipeline(target, output_dir="outputs", wordlist=None, insecure=False, verbose=False, skip_bruteforce=False):
    """
    Full auto pipeline: domain → bruteforce → passive → scan → analyse → report

    Args:
        target (str):           Root domain to scan (e.g. hackerone.com)
        output_dir (str):       Directory for all output files
        wordlist (str|None):    Path to DNS wordlist. None = use built-in
        insecure (bool):        Skip TLS verification in passive recon
        verbose (bool):         Show verbose errors
        skip_bruteforce (bool): Skip DNS bruteforce stage
    """

    os.makedirs(output_dir, exist_ok=True)
    start_time = time.time()
    stage_results = {}

    # ── File paths ──
    subdomains_file     = os.path.join(output_dir, "subdomains.txt")
    passive_file        = os.path.join(output_dir, "passive_results.json")
    scan_file           = os.path.join(output_dir, "scan_results.json")
    analysis_file       = os.path.join(output_dir, "analysis_results.json")
    report_md_file      = os.path.join(output_dir, "redshadow_report.md")
    report_html_file    = os.path.join(output_dir, "redshadow_report.html")

    cprint(f"\n{'='*60}", "magenta")
    cprint(f"  🛡️  RedShadow V2 — Auto Pipeline", "magenta")
    cprint(f"  Target: {target}", "white")
    cprint(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "white")
    cprint(f"{'='*60}", "magenta")

    # ─────────────────────────────────────
    # Stage 1: Subdomain Enumeration (crt.sh)
    # ─────────────────────────────────────
    from modules.domain import enumerate_subdomains

    stage_results["1. Subdomain Enumeration (crt.sh)"] = run_stage(
        "Subdomain Enumeration (crt.sh)",
        enumerate_subdomains,
        target,
        subdomains_file
    )

    # ─────────────────────────────────────
    # Stage 2: DNS Bruteforce
    # ─────────────────────────────────────
    if not skip_bruteforce:
        from modules.bruteforce import dns_bruteforce

        stage_results["2. DNS Bruteforce"] = run_stage(
            "DNS Bruteforce",
            dns_bruteforce,
            target,
            subdomains_file,
            wordlist=wordlist
        )
    else:
        cprint("\n  [→] Skipping DNS bruteforce (--no-bruteforce flag set)", "yellow")
        stage_results["2. DNS Bruteforce"] = None  # None = skipped (not failed)

    found = count_subdomains(subdomains_file)
    cprint(f"\n  [ℹ] Total unique subdomains found: {found}", "cyan")

    if found == 0:
        cprint("  [!] No subdomains found. Aborting pipeline.", "red")
        print_summary(target, stage_results, output_dir, start_time)
        return

    # ─────────────────────────────────────
    # Stage 3: Passive Recon
    # ─────────────────────────────────────
    from modules.passive import passive_recon

    stage_results["3. Passive Recon"] = run_stage(
        "Passive Recon",
        passive_recon,
        input_file=subdomains_file,
        output_file=passive_file,
        insecure=insecure,
        verbose=verbose
    )

    # ─────────────────────────────────────
    # Stage 4: Port Scan (Nmap)
    # ─────────────────────────────────────
    from modules.scan import run_scan

    stage_results["4. Port Scan (Nmap)"] = run_stage(
        "Port Scan (Nmap)",
        run_scan,
        subdomains_file,
        scan_file
    )

    # ─────────────────────────────────────
    # Stage 5: CVE Analysis
    # ─────────────────────────────────────
    from modules.analyse import analyse_scan_results

    stage_results["5. CVE Analysis"] = run_stage(
        "CVE Analysis",
        analyse_scan_results,
        scan_file,
        analysis_file
    )

    # ─────────────────────────────────────
    # Stage 6: Report Generation (MD + HTML)
    # ─────────────────────────────────────
    from modules.report import generate_report

    stage_results["6. Report Generation"] = run_stage(
        "Report Generation",
        generate_report,
        analysis_file,
        report_md_file,
        html_output=report_html_file
    )

    # ─────────────────────────────────────
    # Final Summary
    # ─────────────────────────────────────
    print_summary(target, stage_results, output_dir, start_time)