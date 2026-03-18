# Developed by Galal Noaman – RedShadow_V2
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.

# RedShadow_v2/modules/analyse.py

import json
import os
import re
from termcolor import cprint
from packaging import version
from modules.utils import load_config

# Load config
config = load_config(section="analyse")
cve_path = config.get("cve_source", "data/cve_map.json")

def load_cve_map(path=cve_path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[!] Failed to load CVE map: {e}")
        return {}

def version_in_range(v, range_string):
    try:
        if not v or v.lower() == "n/a":
            return False

        if range_string.strip().lower() == "x":
            return True

        if v.strip().lower() == "x":
            return "x" in range_string.lower()

        v_parsed = version.parse(v)

        for r in range_string.split(","):
            r = r.strip()
            if r.startswith("<="):
                if v_parsed <= version.parse(r[2:].strip()):
                    return True
            elif r.startswith("<"):
                if v_parsed < version.parse(r[1:].strip()):
                    return True
            elif r.startswith(">="):
                if v_parsed >= version.parse(r[2:].strip()):
                    return True
            elif r.startswith(">"):
                if v_parsed > version.parse(r[1:].strip()):
                    return True
            elif "-" in r:
                low, high = r.split("-")
                if version.parse(low.strip()) <= v_parsed <= version.parse(high.strip()):
                    return True
            elif "x" in r:
                prefix = r.replace(".x", ".")
                if v.startswith(prefix):
                    return True
            else:
                if v_parsed == version.parse(r.strip()):
                    return True
    except Exception:
        return False
    return False

def normalize_product_name(product):
    if not product:
        return ""
    product = product.strip().lower()
    product = product.replace("httpd", "").replace("-", " ").replace("_", " ").strip()

    mappings = {
        "nginx": "nginx",
        "cloudfront": "cloudfront",
        "amazon cloudfront httpd": "cloudfront",
        "microsoft iis httpd": "microsoft iis",
        "iis": "microsoft iis",
        "cloudinary": "cloudinary",
        "akamaighost": "akamai ghost",
        "akamai ghost": "akamai ghost",
        "envoy": "envoy"
    }
    return mappings.get(product, product)

def analyse_scan_results(input_file, output_file="outputs/analysis_results.json"):
    if not os.path.exists(input_file):
        print(f"[!] Input file not found: {input_file}")
        return

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            raw = json.load(f)
            data = raw.get("results", raw)
    except json.JSONDecodeError as error:
        print(f"[!] Failed to parse input JSON: {error}")
        return
    except Exception as error:
        print(f"[!] Error reading input file: {error}")
        return

    cve_map = load_cve_map()
    analysed = []

    for domain, info in data.items():
        if not isinstance(info, dict):
            continue

        tech_matches = []
        protocols = info.get("protocols", {})
        if not isinstance(protocols, dict):
            continue

        for proto, ports in protocols.items():
            if not isinstance(ports, dict):
                continue

            for port, port_data in ports.items():
                if not isinstance(port_data, dict):
                    continue

                service = port_data.get("service", "")
                product = port_data.get("product", "")
                detected_version = port_data.get("version", "")
                norm_name = normalize_product_name(product)

                if not norm_name:
                    continue

                matched_cves = []
                for tech_fp, cves in cve_map.items():
                    tech_fp_norm = tech_fp.lower().strip()
                    if tech_fp_norm in norm_name or norm_name in tech_fp_norm:
                        for cve in cves:
                            affected_versions = cve.get("affected_versions", "")
                            if version_in_range(detected_version, affected_versions):
                                matched_cves.append(cve)

                if matched_cves:
                    tech_matches.append({
                        'tech': norm_name,
                        'port': port,
                        'cves': matched_cves
                    })

        if tech_matches:
            analysed.append({
                'url': domain,
                'ip': info.get("ip", "N/A"),
                'hostname': info.get("hostname", "N/A"),
                'tech_matches': tech_matches
            })

    if not analysed:
        print("[!] No vulnerable technologies detected.")
    else:
        print(f"\n[✓] Found {len(analysed)} potentially vulnerable targets:\n")
        for entry in analysed:
            cprint(f"[→] {entry['url']} ({entry['ip']})", "cyan")
            for match in entry['tech_matches']:
                for cve in match['cves']:
                    cve_id = cve.get("cve", "N/A")
                    cvss = cve.get("cvss", "?")
                    url = cve.get("url", "")
                    cprint(f"    - {match['tech']} on port {match['port']} → CVE: {cve_id} (CVSS: {cvss})", "yellow")
                    if url:
                        print(f"      {url}")

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    try:
        with open(output_file, 'w', encoding='utf-8') as out:
            json.dump(analysed, out, indent=2)
        print(f"[✓] Analysis saved to {output_file}")
    except Exception as error:
        print(f"[!] Failed to write analysis output: {error}")
