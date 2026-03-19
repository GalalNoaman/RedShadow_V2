# Developed by Galal Noaman – RedShadow_V2
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.

# RedShadow_v2/modules/nvd.py
# Live CVE lookup via NVD API v2.0
# Falls back to local cve_map.json if API is unreachable

import os
import json
import time
import requests
from datetime import datetime, timedelta
from dotenv import load_dotenv
from termcolor import cprint

# ─── Load API key from .env ───
load_dotenv()
NVD_API_KEY = os.getenv("NVD_API_KEY")

# ─── Config ───
NVD_BASE_URL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_DIR     = "data/nvd_cache"
CACHE_EXPIRY  = 24  # hours before cache expires
MAX_RESULTS   = 20  # max CVEs to fetch per product


# ─────────────────────────────────────────
# Cache Helpers
# ─────────────────────────────────────────

def _cache_path(product):
    """Returns the cache file path for a given product name."""
    safe = product.replace(" ", "_").replace("/", "_")
    return os.path.join(CACHE_DIR, f"{safe}.json")


def _cache_valid(path):
    """Returns True if cache file exists and is less than CACHE_EXPIRY hours old."""
    if not os.path.exists(path):
        return False
    modified = datetime.fromtimestamp(os.path.getmtime(path))
    return datetime.now() - modified < timedelta(hours=CACHE_EXPIRY)


def _load_cache(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _save_cache(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        cprint(f"  [!] Cache write failed: {e}", "yellow")


# ─────────────────────────────────────────
# NVD API Query
# ─────────────────────────────────────────

def query_nvd(product, version_str=None, retries=3, delay=2):
    """
    Queries the NVD API for CVEs matching a product name.
    Uses cache to avoid redundant API calls.

    Args:
        product (str):      Normalised product name (e.g. "nginx", "cloudfront")
        version_str (str):  Detected version string (e.g. "1.18.0")
        retries (int):      Number of retry attempts on failure
        delay (int):        Seconds between retries

    Returns:
        list: CVE dictionaries with keys: cve, description, cvss, severity, url
    """

    cache_file = _cache_path(product)

    # ── Return cached results if fresh ──
    if _cache_valid(cache_file):
        cached = _load_cache(cache_file)
        if cached is not None:
            return cached

    headers = {"User-Agent": "RedShadowBot/2.0"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    else:
        cprint("  [!] No NVD API key found in .env — using unauthenticated (rate limited)", "yellow")

    params = {
        "keywordSearch": product,
        "resultsPerPage": MAX_RESULTS,
    }

    for attempt in range(retries):
        try:
            response = requests.get(
                NVD_BASE_URL,
                headers=headers,
                params=params,
                timeout=15
            )

            if response.status_code == 403:
                cprint("  [!] NVD API key invalid or rate limited.", "red")
                return []

            if response.status_code == 429:
                cprint(f"  [!] NVD rate limit hit. Waiting {delay * 2}s...", "yellow")
                time.sleep(delay * 2)
                continue

            response.raise_for_status()
            data = response.json()
            cves = _parse_nvd_response(data, version_str)

            # ── Cache results ──
            _save_cache(cache_file, cves)
            return cves

        except requests.exceptions.Timeout:
            cprint(f"  [!] NVD API timeout (attempt {attempt + 1}/{retries})", "yellow")
            time.sleep(delay)

        except requests.exceptions.ConnectionError:
            cprint(f"  [!] NVD API connection error (attempt {attempt + 1}/{retries})", "yellow")
            time.sleep(delay)

        except Exception as e:
            cprint(f"  [!] NVD API error: {e}", "red")
            break

    cprint(f"  [!] NVD lookup failed for '{product}' — falling back to local CVE map", "yellow")
    return []


# ─────────────────────────────────────────
# Response Parser
# ─────────────────────────────────────────

def _parse_nvd_response(data, version_str=None):
    """
    Parses the NVD API JSON response into a clean list of CVE dicts.

    Returns:
        list of dicts with keys: cve, description, cvss, severity, url
    """
    results = []

    for item in data.get("vulnerabilities", []):
        cve_data = item.get("cve", {})
        cve_id   = cve_data.get("id", "N/A")

        # ── Description ──
        descriptions = cve_data.get("descriptions", [])
        description  = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available."
        )

        # ── CVSS Score ──
        cvss   = "N/A"
        severity = "UNKNOWN"

        metrics = cve_data.get("metrics", {})

        # Try CVSS v3.1 first, then v3.0, then v2.0
        for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss      = cvss_data.get("baseScore", "N/A")
                severity  = metric_list[0].get("baseSeverity", "UNKNOWN")
                break

        # ── Affected Versions ──
        affected_versions = []
        configurations    = cve_data.get("configurations", [])

        for config in configurations:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if not match.get("vulnerable", False):
                        continue
                    version_end   = match.get("versionEndIncluding", "")
                    version_start = match.get("versionStartIncluding", "")
                    if version_end:
                        affected_versions.append(f"<={version_end}")
                    elif version_start:
                        affected_versions.append(f">={version_start}")

        results.append({
            "cve":               cve_id,
            "description":       description[:200] + "..." if len(description) > 200 else description,
            "cvss":              cvss,
            "severity":          severity,
            "affected_versions": ", ".join(affected_versions) if affected_versions else "x",
            "url":               f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        })

    # ── Sort by CVSS score descending ──
    results.sort(
        key=lambda x: float(x["cvss"]) if isinstance(x["cvss"], (int, float)) or
        (isinstance(x["cvss"], str) and x["cvss"].replace(".", "").isdigit()) else 0,
        reverse=True
    )

    return results


# ─────────────────────────────────────────
# Fallback: Local CVE Map
# ─────────────────────────────────────────

def load_local_cve_map(path="data/cve_map.json"):
    """Loads the static local CVE map as a fallback."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


# ─────────────────────────────────────────
# Main Lookup Function (used by analyse.py)
# ─────────────────────────────────────────

def lookup_cves(product, version_str=None, use_local_fallback=True):
    """
    Main entry point for CVE lookup.
    Tries NVD API first, falls back to local cve_map.json.

    Args:
        product (str):              Normalised product name
        version_str (str):          Detected version
        use_local_fallback (bool):  Use local map if API fails

    Returns:
        list of CVE dicts
    """
    if not product:
        return []

    # ── Try NVD API ──
    cves = query_nvd(product, version_str)

    # ── Fallback to local map if API returns nothing ──
    if not cves and use_local_fallback:
        local_map = load_local_cve_map()
        for key, local_cves in local_map.items():
            if key.lower() in product.lower() or product.lower() in key.lower():
                cves = local_cves
                break

    return cves