# Developed by Galal Noaman – RedShadow_V2
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.

# RedShadow_v2/modules/bruteforce.py
# DNS bruteforce subdomain discovery using a wordlist

import os
import dns.resolver
from tqdm import tqdm
from termcolor import cprint
from multiprocessing.dummy import Pool as ThreadPool

# ─────────────────────────────────────────
# Built-in wordlist (top common subdomains)
# Covers ~80% of what you'd find on bug bounty targets
# ─────────────────────────────────────────

BUILTIN_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "mx",
    "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
    "api", "api2", "api3", "apiv1", "apiv2", "rest", "graphql", "grpc",
    "app", "app1", "app2", "apps", "webapp", "web", "web1", "web2",
    "admin", "administrator", "portal", "dashboard", "control", "panel",
    "login", "auth", "sso", "oauth", "accounts", "account",
    "dev", "develop", "development", "staging", "stage", "stg",
    "test", "testing", "qa", "uat", "demo", "sandbox", "preview",
    "beta", "alpha", "canary", "internal", "int",
    "cdn", "static", "assets", "media", "img", "images", "files", "upload",
    "blog", "forum", "community", "help", "support", "docs", "documentation",
    "wiki", "kb", "status", "monitor",
    "shop", "store", "checkout", "payment", "pay", "billing",
    "vpn", "remote", "ssh", "gateway", "proxy", "lb", "loadbalancer",
    "db", "database", "mysql", "postgres", "redis", "mongo",
    "git", "gitlab", "github", "bitbucket", "ci", "jenkins", "build",
    "jira", "confluence", "slack", "chat",
    "mobile", "m", "ios", "android",
    "old", "new", "v1", "v2", "v3", "backup", "bak",
    "smtp", "mail2", "webmail2", "mx1", "mx2",
    "aws", "s3", "cloud", "azure", "gcp",
    "search", "elastic", "kibana", "grafana", "prometheus",
    "server", "server1", "server2", "node", "node1", "node2",
    "prod", "production", "live",
    "intranet", "extranet", "corp", "office",
    "security", "sec", "soc", "waf", "firewall",
]


# ─────────────────────────────────────────
# DNS Resolution
# ─────────────────────────────────────────

def resolve_subdomain(args):
    """
    Tries to resolve a subdomain. Returns the subdomain string if it resolves,
    None if it doesn't.
    """
    subdomain, dns_servers = args
    resolver = dns.resolver.Resolver()
    resolver.nameservers = dns_servers
    resolver.timeout = 2
    resolver.lifetime = 3

    try:
        resolver.resolve(subdomain, 'A')
        return subdomain
    except Exception:
        pass

    try:
        resolver.resolve(subdomain, 'CNAME')
        return subdomain
    except Exception:
        return None


# ─────────────────────────────────────────
# Main Bruteforce Entry Point
# ─────────────────────────────────────────

def dns_bruteforce(target, output_file, wordlist=None, threads=30, dns_servers=None):
    """
    Bruteforces subdomains by resolving wordlist entries against the target domain.
    Discovered subdomains are APPENDED to the output file (merging with crt.sh results).

    Args:
        target (str):           Root domain (e.g. hackerone.com)
        output_file (str):      Path to subdomains file to append results to
        wordlist (str|None):    Path to custom wordlist. None = use built-in
        threads (int):          Thread count for parallel resolution
        dns_servers (list):     DNS resolvers to use
    """

    if dns_servers is None:
        dns_servers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

    # ── Load wordlist ──
    if wordlist and os.path.exists(wordlist):
        with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
            words = [line.strip() for line in f if line.strip()]
        cprint(f"  [+] Loaded {len(words)} words from {wordlist}", "cyan")
    else:
        if wordlist:
            cprint(f"  [!] Wordlist not found at {wordlist}, using built-in list", "yellow")
        else:
            cprint(f"  [+] Using built-in wordlist ({len(BUILTIN_WORDLIST)} entries)", "cyan")
        words = BUILTIN_WORDLIST

    # ── Load existing subdomains to avoid duplicates ──
    existing = set()
    if os.path.exists(output_file):
        with open(output_file, "r", encoding="utf-8") as f:
            existing = set(line.strip().lower() for line in f if line.strip())

    # ── Build candidate list ──
    candidates = [f"{word}.{target}" for word in words]
    candidates = [c for c in candidates if c not in existing]

    if not candidates:
        cprint("  [!] No new candidates to bruteforce.", "yellow")
        return

    cprint(f"  [+] Bruteforcing {len(candidates)} candidates against {target}...", "cyan")

    args = [(c, dns_servers) for c in candidates]

    # ── Parallel resolution ──
    discovered = []
    with ThreadPool(threads) as pool:
        results = list(tqdm(
            pool.imap(resolve_subdomain, args),
            total=len(args),
            desc="  DNS Bruteforce",
            ncols=70
        ))

    discovered = [r for r in results if r is not None]
    new_found = [d for d in discovered if d not in existing]

    if not new_found:
        cprint("  [!] No new subdomains discovered via bruteforce.", "yellow")
        return

    # ── Append new subdomains to existing file ──
    os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else ".", exist_ok=True)
    with open(output_file, "a", encoding="utf-8") as f:
        for sub in sorted(new_found):
            f.write(sub + "\n")

    cprint(f"  [✓] Bruteforce found {len(new_found)} new subdomains → appended to {output_file}", "green")