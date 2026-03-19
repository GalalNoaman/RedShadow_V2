# Developed by Galal Noaman – RedShadow_V2
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.

# RedShadow_v2/modules/analyse.py

import json
import os
from termcolor import cprint
from modules.utils import load_config
from modules.nvd import lookup_cves

config   = load_config(section="analyse")
cve_path = config.get("cve_source", "data/cve_map.json")


def normalize_product_name(product):
    if not product:
        return ""
    product = product.strip().lower()
    product = product.replace("httpd", "").replace("-", " ").replace("_", " ").strip()

    mappings = {
        "nginx": "nginx",
        "cloudfront": "cloudfront",
        "amazon cloudfront": "cloudfront",
        "amazon cloudfront httpd": "cloudfront",
        "microsoft iis httpd": "microsoft iis",
        "iis": "microsoft iis",
        "cloudinary": "cloudinary",
        "akamaighost": "akamai ghost",
        "akamai ghost": "akamai ghost",
        "envoy": "envoy",
        "apache": "apache",
        "openssl": "openssl",
        "openssh": "openssh",
        "wordpress": "wordpress",
        "drupal": "drupal",
        "joomla": "joomla",
        "cloudflare": "cloudflare",
        "cloudflare http proxy": "cloudflare",
        "varnish": "varnish",
    }
    return mappings.get(product, product)


def deduplicate_cves(cve_list):
    """Removes duplicate CVEs by CVE ID, keeps first occurrence."""
    seen   = set()
    unique = []
    for cve in cve_list:
        cve_id = cve.get("cve", "")
        if cve_id and cve_id not in seen:
            seen.add(cve_id)
            unique.append(cve)
    return unique


def analyse_scan_results(input_file, output_file="outputs/analysis_results.json"):
    if not os.path.exists(input_file):
        print(f"[!] Input file not found: {input_file}")
        return

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            raw  = json.load(f)
        data = raw.get("results", raw)
    except json.JSONDecodeError as error:
        print(f"[!] Failed to parse input JSON: {error}")
        return
    except Exception as error:
        print(f"[!] Error reading input file: {error}")
        return

    analysed = []

    for domain, info in data.items():
        if not isinstance(info, dict):
            continue

        protocols = info.get("protocols", {})
        if not isinstance(protocols, dict):
            continue

        # ── Collect unique technologies across ALL ports ──
        tech_seen    = {}   # norm_name → set of ports
        tech_version = {}   # norm_name → detected version

        for proto, ports in protocols.items():
            if not isinstance(ports, dict):
                continue
            for port, port_data in ports.items():
                if not isinstance(port_data, dict):
                    continue

                product          = port_data.get("product", "")
                detected_version = port_data.get("version", "")
                norm_name        = normalize_product_name(product)

                if not norm_name:
                    continue

                if norm_name not in tech_seen:
                    tech_seen[norm_name]    = set()
                    tech_version[norm_name] = detected_version

                tech_seen[norm_name].add(str(port))

        if not tech_seen:
            continue

        # ── Look up CVEs once per unique technology ──
        tech_matches = []

        for norm_name, ports in tech_seen.items():
            version_str = tech_version.get(norm_name, "")
            cprint(f"  [→] Looking up CVEs for: {norm_name} {version_str or 'x'}", "cyan")

            matched_cves = lookup_cves(norm_name, version_str)
            matched_cves = deduplicate_cves(matched_cves)

            if matched_cves:
                tech_matches.append({
                    'tech':  norm_name,
                    'ports': sorted(ports),
                    'cves':  matched_cves
                })

        if tech_matches:
            analysed.append({
                'url':          domain,
                'ip':           info.get("ip", "N/A"),
                'hostname':     info.get("hostname", "N/A"),
                'tech_matches': tech_matches
            })

    if not analysed:
        print("[!] No vulnerable technologies detected.")
    else:
        print(f"\n[✓] Found {len(analysed)} potentially vulnerable targets:\n")
        for entry in analysed:
            cprint(f"[→] {entry['url']} ({entry['ip']})", "cyan")
            for match in entry['tech_matches']:
                ports_str = ", ".join(match['ports'])
                cprint(f"    [{match['tech']} — ports {ports_str}]", "white")
                for cve in match['cves'][:5]:
                    cve_id   = cve.get("cve", "N/A")
                    cvss     = cve.get("cvss", "?")
                    severity = cve.get("severity", "")
                    cprint(f"      - {cve_id} (CVSS: {cvss} | {severity})", "yellow")

    os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else ".", exist_ok=True)

    try:
        with open(output_file, 'w', encoding='utf-8') as out:
            json.dump(analysed, out, indent=2)
        print(f"\n[✓] Analysis saved to {output_file}")
    except Exception as error:
        print(f"[!] Failed to write analysis output: {error}")