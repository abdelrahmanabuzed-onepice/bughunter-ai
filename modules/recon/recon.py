"""
Recon Module — DNS, Subdomains, crt.sh, Wayback Machine, Headers, WHOIS
100% Free — no API keys needed.
"""

import requests
import dns.resolver
import whois
import json
import re
import sys, os
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from config import config
from urllib.parse import urlparse

def get_headers():
    h = {"User-Agent": config["user_agent"]}
    if config.get("custom_headers"):
        h.update(config["custom_headers"])
    return h

HEADERS = get_headers()


# ── Subdomain Enumeration ──────────────────────────────────────────────────────

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "blog", "shop", "store", "app", "portal", "vpn", "remote", "cdn",
    "static", "assets", "media", "img", "images", "upload", "download",
    "m", "mobile", "secure", "login", "auth", "oauth", "sso", "beta",
    "demo", "old", "new", "legacy", "internal", "intranet", "extranet",
    "git", "gitlab", "jenkins", "jira", "confluence", "wiki", "docs",
    "smtp", "pop", "imap", "mx", "ns1", "ns2", "dns", "cpanel", "whm",
    "webmail", "autodiscover", "autoconfig", "forum", "community", "help",
    "support", "status", "monitor", "grafana", "kibana", "elastic", "db",
    "database", "mysql", "redis", "mongo", "backup", "s3", "bucket",
]


def enumerate_subdomains_dns(domain: str, callback=None) -> list[dict]:
    """Brute-force subdomains via DNS resolution."""
    found = []
    for sub in COMMON_SUBDOMAINS:
        fqdn = f"{sub}.{domain}"
        try:
            answers = dns.resolver.resolve(fqdn, "A")
            ips = [str(r) for r in answers]
            result = {"subdomain": fqdn, "ips": ips, "source": "dns_brute"}
            found.append(result)
            if callback:
                callback(result)
        except Exception:
            pass
    return found


def enumerate_subdomains_crtsh(domain: str) -> list[dict]:
    """Find subdomains via crt.sh certificate transparency logs — FREE."""
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            headers=HEADERS,
            timeout=15
        )
        if resp.status_code == 200:
            data = resp.json()
            seen = set()
            results = []
            for entry in data:
                names = entry.get("name_value", "").split("\n")
                for name in names:
                    name = name.strip().lstrip("*.")
                    if name and name not in seen and domain in name:
                        seen.add(name)
                        results.append({
                            "subdomain": name,
                            "issuer": entry.get("issuer_name", ""),
                            "logged_at": entry.get("entry_timestamp", "")[:10],
                            "source": "crt.sh",
                        })
            return results
    except Exception as e:
        return [{"error": str(e)}]
    return []


# ── Wayback Machine ────────────────────────────────────────────────────────────

def wayback_urls(domain: str, limit: int = 100) -> list[str]:
    """Fetch historical URLs from the Wayback Machine CDX API — FREE."""
    try:
        resp = requests.get(
            "http://web.archive.org/cdx/search/cdx",
            params={
                "url": f"*.{domain}/*",
                "output": "json",
                "fl": "original",
                "collapse": "urlkey",
                "limit": limit,
            },
            headers=HEADERS,
            timeout=20
        )
        if resp.status_code == 200:
            data = resp.json()
            return [row[0] for row in data[1:] if row]  # Skip header row
    except Exception as e:
        return [f"Error: {e}"]
    return []


def wayback_interesting_urls(domain: str) -> dict:
    """Extract categorized interesting URLs from Wayback Machine."""
    all_urls = wayback_urls(domain, limit=500)
    categories = {
        "params": [],
        "js_files": [],
        "json_api": [],
        "php_asp": [],
        "admin_paths": [],
        "backups": [],
    }
    for url in all_urls:
        if "?" in url and "=" in url:
            categories["params"].append(url)
        if url.endswith(".js"):
            categories["js_files"].append(url)
        if ".json" in url or "/api/" in url:
            categories["json_api"].append(url)
        if url.endswith(".php") or url.endswith(".asp") or url.endswith(".aspx"):
            categories["php_asp"].append(url)
        if any(p in url.lower() for p in ["admin", "panel", "dashboard", "manage", "control"]):
            categories["admin_paths"].append(url)
        if any(p in url.lower() for p in [".bak", ".backup", ".old", ".zip", ".tar", ".sql"]):
            categories["backups"].append(url)
    return categories


# ── DNS Records ────────────────────────────────────────────────────────────────

def get_dns_records(domain: str) -> dict:
    """Retrieve all DNS record types for a domain."""
    records = {}
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [str(r) for r in answers]
        except Exception:
            records[rtype] = []
    return records


# ── HTTP Header Fingerprinting ─────────────────────────────────────────────────

def fingerprint_headers(url: str) -> dict:
    """Analyze HTTP headers for server, tech stack, and security misconfigs."""
    if not url.startswith("http"):
        url = f"https://{url}"
    try:
        resp = requests.get(
            url,
            headers=HEADERS,
            timeout=config["timeout"],
            verify=config["verify_ssl"],
            allow_redirects=True
        )
        h = dict(resp.headers)
        findings = {
            "status_code": resp.status_code,
            "final_url": resp.url,
            "headers": h,
            "tech_stack": _detect_tech(h, resp.text[:2000]),
            "security_headers": _check_security_headers(h),
            "server": h.get("Server", h.get("server", "Hidden")),
            "cookies": _analyze_cookies(resp.cookies),
        }
        return findings
    except Exception as e:
        return {"error": str(e)}


def _detect_tech(headers: dict, body: str) -> list[str]:
    tech = []
    h_lower = {k.lower(): v.lower() for k, v in headers.items()}
    server = h_lower.get("server", "")
    x_powered = h_lower.get("x-powered-by", "")

    for name, pattern in {
        "Apache": "apache", "Nginx": "nginx", "IIS": "iis",
        "PHP": "php", "ASP.NET": "asp.net", "Express": "express",
        "Django": "django", "Rails": "ruby", "Laravel": "laravel",
        "WordPress": "wp-content", "Drupal": "drupal", "Joomla": "joomla",
        "Cloudflare": "cloudflare", "AWS": "amazon", "Azure": "azure",
    }.items():
        if pattern in server or pattern in x_powered or pattern in body.lower():
            tech.append(name)
    return tech


def _check_security_headers(headers: dict) -> dict:
    h = {k.lower(): v for k, v in headers.items()}
    checks = {
        "X-Frame-Options": "x-frame-options" in h,
        "X-XSS-Protection": "x-xss-protection" in h,
        "X-Content-Type-Options": "x-content-type-options" in h,
        "Strict-Transport-Security": "strict-transport-security" in h,
        "Content-Security-Policy": "content-security-policy" in h,
        "Referrer-Policy": "referrer-policy" in h,
        "Permissions-Policy": "permissions-policy" in h,
    }
    missing = [k for k, v in checks.items() if not v]
    return {"present": [k for k, v in checks.items() if v], "missing": missing}


def _analyze_cookies(cookies) -> list[dict]:
    results = []
    for c in cookies:
        results.append({
            "name": c.name,
            "secure": c.secure,
            "httponly": c.has_nonstandard_attr("HttpOnly"),
            "samesite": c._rest.get("SameSite", "Not Set"),
        })
    return results


# ── WHOIS ──────────────────────────────────────────────────────────────────────

def whois_lookup(domain: str) -> dict:
    """Perform a WHOIS lookup on a domain."""
    try:
        w = whois.whois(domain)
        return {
            "registrar": str(w.registrar),
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers,
            "emails": w.emails,
            "org": str(w.org),
            "country": str(w.country),
        }
    except Exception as e:
        return {"error": str(e)}


# ── robots.txt & sitemap ───────────────────────────────────────────────────────

def get_robots_txt(base_url: str) -> dict:
    """Fetch and parse robots.txt for disallowed paths."""
    if not base_url.startswith("http"):
        base_url = f"https://{base_url}"
    try:
        resp = requests.get(f"{base_url.rstrip('/')}/robots.txt",
                            headers=HEADERS, timeout=config["timeout"],
                            verify=config["verify_ssl"])
        if resp.status_code == 200:
            lines = resp.text.splitlines()
            disallowed = [l.split(":", 1)[1].strip() for l in lines
                         if l.lower().startswith("disallow:")]
            sitemaps = [l.split(":", 1)[1].strip() for l in lines
                        if l.lower().startswith("sitemap:")]
            return {"raw": resp.text, "disallowed": disallowed, "sitemaps": sitemaps}
    except Exception as e:
        return {"error": str(e)}
    return {"raw": "", "disallowed": [], "sitemaps": []}
