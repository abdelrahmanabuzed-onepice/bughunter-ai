"""
Report Generator — Professional Bug Bounty Reports
Supports: HackerOne, Bugcrowd, Intigriti, Synack, Generic formats
Properly HTML-escapes all payload content so XSS payloads don't execute in the report.
"""

import os
import html
from datetime import datetime

SEVERITY_COLORS = {
    "CRITICAL": "#EF4444",
    "HIGH":     "#F97316",
    "MEDIUM":   "#EAB308",
    "LOW":      "#10B981",
    "INFO":     "#3B82F6",
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# ── Deduplication ──────────────────────────────────────────────────────────────

def deduplicate_findings(findings: list[dict]) -> list[dict]:
    """Remove duplicate findings — same vuln type + parameter = one finding."""
    seen = set()
    unique = []
    for f in findings:
        key = (f.get("vuln_type", ""), f.get("parameter", ""), f.get("url", "").split("?")[0])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def sort_findings(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "INFO"), 5))


# ── Safe HTML escaping ─────────────────────────────────────────────────────────

def esc(text) -> str:
    """Escape text for safe HTML embedding — prevents payloads from executing."""
    return html.escape(str(text or ""), quote=True)


# ── Markdown Generator ─────────────────────────────────────────────────────────

def generate_markdown(findings: list[dict], target: str, session_notes: str = "") -> str:
    findings = deduplicate_findings(sort_findings(findings))
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    counts = {}
    for f in findings:
        s = f.get("severity", "INFO")
        counts[s] = counts.get(s, 0) + 1

    lines = [
        f"# Bug Bounty Report — {target}",
        f"**Date:** {now}  ",
        f"**Target:** `{target}`  ",
        f"**Total Findings:** {len(findings)}  ",
        "",
        "---",
        "## Executive Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in counts:
            lines.append(f"| {sev} | {counts[sev]} |")

    if session_notes:
        lines += ["", f"**Notes:** {session_notes}"]

    lines += ["", "---", "## Findings", ""]
    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "INFO")
        lines += [
            f"### {i}. {f.get('title', f.get('vuln_type', 'Unknown'))}",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| **Severity** | {sev} |",
            f"| **Type** | {f.get('vuln_type', '')} |",
            f"| **CVSS Score** | {f.get('cvss_score', f.get('cvss', 'N/A'))} |",
            f"| **URL** | `{f.get('url', '')}` |",
            f"| **Parameter** | `{f.get('parameter', 'N/A')}` |",
            "",
            "**Description:**  ",
            f"{f.get('description', 'Vulnerability detected during automated scanning.')}",
            "",
            "**Payload Used:**  ",
            f"```\n{f.get('payload', 'N/A')}\n```",
            "",
            "**Steps to Reproduce:**  ",
            f"1. Navigate to: `{f.get('url', '')}`",
            f"2. Set parameter `{f.get('parameter', 'N/A')}` to the payload above",
            f"3. Observe: {f.get('evidence', f.get('description', 'Unexpected behavior'))}",
            "",
            "**Impact:**  ",
            _get_impact(f.get("vuln_type", "")),
            "",
            "**Remediation:**  ",
            _get_remediation(f.get("vuln_type", "")),
            "",
            "---", "",
        ]
    return "\n".join(lines)


# ── HackerOne Format ───────────────────────────────────────────────────────────

def generate_hackerone(finding: dict, target: str) -> str:
    """Generate a single HackerOne-style report for one finding."""
    sev = finding.get("severity", "MEDIUM").lower()
    cvss = finding.get("cvss_score", finding.get("cvss", "N/A"))
    vuln_type = finding.get("vuln_type", "Vulnerability")
    url = finding.get("url", target)
    param = finding.get("parameter", "N/A")
    payload = finding.get("payload", "N/A")
    evidence = finding.get("evidence", finding.get("description", ""))

    return f"""# {finding.get('title', vuln_type)}

## Summary
{_get_impact(vuln_type)}

A {vuln_type} vulnerability was discovered at `{url}` in the `{param}` parameter. This allows an attacker to {_get_attacker_action(vuln_type)}.

## Severity
**{finding.get('severity', 'MEDIUM')}** (CVSS {cvss})

## Steps To Reproduce
1. Open the following URL in a browser or HTTP client:
   ```
   {url}
   ```
2. Set the `{param}` parameter to the following payload:
   ```
   {payload}
   ```
3. Observe that {evidence or 'the application responds in a vulnerable manner'}.

## Proof of Concept
**Request:**
```http
GET {url.replace('https://', '').replace('http://', '').split('/')[0] + url[url.find('/'):]} HTTP/1.1
Host: {url.replace('https://', '').replace('http://', '').split('/')[0]}
User-Agent: Mozilla/5.0

```

**Payload:**
```
{payload}
```

**Evidence:**
{evidence}

## Impact
{_get_impact(vuln_type)}

An attacker who exploits this vulnerability can:
- {_get_attacker_action(vuln_type).capitalize()}
- Potentially escalate to further compromise of the application

## Remediation
{_get_remediation(vuln_type)}

## References
- https://owasp.org/www-community/attacks/
- https://cwe.mitre.org/
"""


# ── Bugcrowd Format ────────────────────────────────────────────────────────────

def generate_bugcrowd(finding: dict, target: str) -> str:
    """Generate a Bugcrowd-style vulnerability report."""
    vuln_type = finding.get("vuln_type", "Vulnerability")
    url = finding.get("url", target)
    param = finding.get("parameter", "N/A")
    payload = finding.get("payload", "N/A")

    return f"""**Title:** {finding.get('title', vuln_type)}

**VRT Category:** {_get_vrt_category(vuln_type)}

**Severity:** {finding.get('severity', 'MEDIUM')} (CVSS {finding.get('cvss_score', finding.get('cvss', 'N/A'))})

---

**Description:**
{_get_impact(vuln_type)}

This vulnerability exists in `{url}` via the `{param}` parameter.

---

**Steps to Reproduce:**
1. Send the following request:
```
GET {url}
Parameter: {param}={payload}
```
2. Observe the response contains evidence of the vulnerability.

**Expected Result:**
The application should reject or sanitize the malicious input.

**Actual Result:**
{finding.get('evidence', 'The application processes the input unsafely.')}

---

**Proof of Concept:**
Parameter: `{param}`
Payload: `{payload}`
Evidence: {finding.get('evidence', 'N/A')}

---

**Remediation:**
{_get_remediation(vuln_type)}
"""


# ── Intigriti Format ───────────────────────────────────────────────────────────

def generate_intigriti(finding: dict, target: str) -> str:
    """Generate an Intigriti-style vulnerability report."""
    vuln_type = finding.get("vuln_type", "Vulnerability")
    url = finding.get("url", target)
    param = finding.get("parameter", "N/A")
    payload = finding.get("payload", "N/A")

    return f"""## Vulnerability Report

**Title:** {finding.get('title', vuln_type)}
**Type:** {vuln_type}
**Severity:** {finding.get('severity', 'MEDIUM')}
**CVSS Score:** {finding.get('cvss_score', finding.get('cvss', 'N/A'))}

---

### Description
{_get_impact(vuln_type)}

### Affected Endpoint
- **URL:** `{url}`
- **Parameter:** `{param}`
- **Method:** GET

### Proof of Concept

**Payload:**
```
{payload}
```

**Steps:**
1. Navigate to `{url}`
2. Inject payload `{payload}` into the `{param}` parameter
3. Result: {finding.get('evidence', 'Vulnerability confirmed')}

### Impact
{_get_impact(vuln_type)}

### Suggested Fix
{_get_remediation(vuln_type)}

### References
- OWASP: https://owasp.org
"""


# ── Full HTML Report ───────────────────────────────────────────────────────────

def generate_html(findings: list[dict], target: str, session_notes: str = "") -> str:
    """Generate a safe, beautiful HTML bug bounty report. All payloads are HTML-escaped."""
    findings = deduplicate_findings(sort_findings(findings))
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    counts = {}
    for f in findings:
        s = f.get("severity", "INFO")
        counts[s] = counts.get(s, 0) + 1

    # Build findings HTML — ALL user content is HTML-escaped
    findings_html = ""
    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "INFO")
        color = SEVERITY_COLORS.get(sev, "#888")
        cvss = f.get("cvss_score", f.get("cvss", "N/A"))

        # CRITICAL: escape all content that came from the target/payloads
        safe_title    = esc(f.get("title", f.get("vuln_type", "Unknown")))
        safe_url      = esc(f.get("url", ""))
        safe_param    = esc(f.get("parameter", "N/A"))
        safe_payload  = esc(f.get("payload", "N/A"))
        safe_evidence = esc(f.get("evidence", f.get("description", "")))
        safe_type     = esc(f.get("vuln_type", ""))

        findings_html += f"""
        <div class="finding-card" id="finding-{i}">
            <div class="finding-header">
                <span class="finding-num">#{i}</span>
                <span class="finding-title">{safe_title}</span>
                <span class="severity-badge" style="background:{color}">{esc(sev)}</span>
            </div>
            <div class="finding-body">
                <div class="finding-meta">
                    <div class="meta-item"><label>Type</label><span>{safe_type}</span></div>
                    <div class="meta-item"><label>CVSS</label><span>{esc(str(cvss))}</span></div>
                    <div class="meta-item"><label>Parameter</label><code>{safe_param}</code></div>
                </div>
                <div class="finding-section">
                    <label>Affected URL</label>
                    <div class="code-block url-block">{safe_url}</div>
                </div>
                <div class="finding-section">
                    <label>Payload Used (escaped — safe to view)</label>
                    <div class="code-block payload-block">{safe_payload}</div>
                </div>
                <div class="finding-section">
                    <label>Evidence</label>
                    <p class="evidence-text">{safe_evidence}</p>
                </div>
                <div class="finding-grid-2">
                    <div class="finding-section">
                        <label>Impact</label>
                        <p>{esc(_get_impact(f.get("vuln_type", "")))}</p>
                    </div>
                    <div class="finding-section">
                        <label>Remediation</label>
                        <p>{esc(_get_remediation(f.get("vuln_type", "")))}</p>
                    </div>
                </div>
            </div>
        </div>"""

    # Summary bars
    summary_html = ""
    total = len(findings) or 1
    for sev, color in SEVERITY_COLORS.items():
        count = counts.get(sev, 0)
        if count:
            pct = (count / total) * 100
            summary_html += f"""
            <div class="sev-row">
                <span class="sev-label">{sev}</span>
                <div class="sev-bar-wrap">
                    <div class="sev-bar" style="width:{pct:.0f}%;background:{color}"></div>
                </div>
                <span class="sev-count" style="color:{color}">{count}</span>
            </div>"""

    stat_cards = "".join(
        f'<div class="stat-card"><div class="stat-num" style="color:{SEVERITY_COLORS.get(s,"#888")}">'
        f'{counts.get(s,0)}</div><div class="stat-label">{s}</div></div>'
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Bug Bounty Report — {esc(target)}</title>
<!-- Content Security Policy: blocks any injected scripts -->
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'none'; style-src 'unsafe-inline'; font-src https://fonts.googleapis.com https://fonts.gstatic.com;">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
  :root {{
    --bg:#080B10; --surface:#0E1117; --surface2:#131920;
    --border:#1E2A38; --text:#F1F5F9; --muted:#64748B;
    --accent:#3B82F6; --green:#10B981; --red:#EF4444;
    --orange:#F97316; --yellow:#EAB308;
  }}
  *{{margin:0;padding:0;box-sizing:border-box}}
  body{{font-family:'Inter',sans-serif;background:var(--bg);color:var(--text);padding:2rem;min-height:100vh}}
  a{{color:var(--accent)}}

  .report-header{{
    background:linear-gradient(135deg,#0E1117,#080B10);
    border:1px solid var(--border);border-radius:16px;
    padding:2rem;margin-bottom:1.5rem;position:relative;overflow:hidden;
  }}
  .report-header::before{{
    content:'';position:absolute;top:0;left:0;right:0;height:3px;
    background:linear-gradient(90deg,#EF4444,#F97316,#EAB308,#3B82F6);
  }}
  .report-header h1{{font-size:1.8rem;margin-bottom:.5rem}}
  .report-meta{{color:var(--muted);font-size:.9rem;margin-top:.5rem}}
  .report-meta span{{margin-right:1.5rem}}

  .stats-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin-bottom:1.5rem}}
  .stat-card{{background:var(--surface);border:1px solid var(--border);border-radius:12px;
    padding:1.2rem;text-align:center}}
  .stat-num{{font-size:2.2rem;font-weight:700}}
  .stat-label{{color:var(--muted);font-size:.8rem;margin-top:.3rem;font-weight:600;letter-spacing:.05em}}

  .panel{{background:var(--surface);border:1px solid var(--border);border-radius:12px;
    padding:1.5rem;margin-bottom:1.5rem}}
  .panel-title{{font-size:.85rem;font-weight:700;color:var(--muted);
    text-transform:uppercase;letter-spacing:.1em;margin-bottom:1rem}}

  .sev-row{{display:flex;align-items:center;gap:1rem;margin-bottom:.6rem}}
  .sev-label{{font-size:.8rem;font-weight:600;color:var(--muted);width:80px}}
  .sev-bar-wrap{{flex:1;background:var(--surface2);border-radius:4px;height:8px}}
  .sev-bar{{height:8px;border-radius:4px}}
  .sev-count{{font-weight:700;width:35px;text-align:right}}

  .finding-card{{background:var(--surface);border:1px solid var(--border);
    border-radius:12px;margin-bottom:1rem;overflow:hidden;
    transition:border-color .2s}}
  .finding-card:hover{{border-color:var(--accent)}}
  .finding-header{{display:flex;align-items:center;gap:1rem;
    padding:1rem 1.5rem;background:var(--surface2);border-bottom:1px solid var(--border)}}
  .finding-num{{color:var(--muted);font-size:.9rem;font-weight:600;min-width:30px}}
  .finding-title{{flex:1;font-weight:600;font-size:1rem}}
  .severity-badge{{padding:.25rem .8rem;border-radius:20px;
    font-size:.75rem;font-weight:700;color:#fff}}
  .finding-body{{padding:1.5rem}}
  .finding-meta{{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;margin-bottom:1.2rem}}
  .meta-item label{{font-size:.75rem;color:var(--muted);display:block;
    text-transform:uppercase;letter-spacing:.05em;margin-bottom:.3rem}}
  .meta-item span,.meta-item code{{font-weight:600;font-family:'JetBrains Mono',monospace;font-size:.85rem}}
  .finding-section{{margin-bottom:1.2rem}}
  .finding-section>label{{font-size:.75rem;font-weight:700;color:var(--muted);
    display:block;text-transform:uppercase;letter-spacing:.05em;margin-bottom:.5rem}}
  .finding-section p{{line-height:1.6;color:var(--text)}}
  .finding-grid-2{{display:grid;grid-template-columns:1fr 1fr;gap:1.5rem}}

  .code-block{{
    font-family:'JetBrains Mono',monospace;font-size:.85rem;
    background:var(--surface2);border:1px solid var(--border);
    border-radius:8px;padding:.8rem 1rem;
    word-break:break-all;white-space:pre-wrap;
    /* IMPORTANT: user-select all for easy copying */
    user-select:all;
  }}
  .url-block{{color:#60a5fa}}
  .payload-block{{color:#fca5a5}}  /* red-ish but safe — it's just text */
  .evidence-text{{color:var(--muted);line-height:1.6}}

  .toc{{display:flex;flex-wrap:wrap;gap:.5rem;margin-bottom:1rem}}
  .toc a{{
    padding:.3rem .8rem;border-radius:8px;font-size:.8rem;font-weight:600;
    text-decoration:none;border:1px solid var(--border);color:var(--muted);
    transition:all .2s;
  }}
  .toc a:hover{{border-color:var(--accent);color:var(--accent)}}

  footer{{text-align:center;color:var(--muted);font-size:.8rem;margin-top:3rem;
    padding-top:1rem;border-top:1px solid var(--border)}}

  @media(max-width:768px){{
    .stats-grid{{grid-template-columns:repeat(2,1fr)}}
    .finding-meta,.finding-grid-2{{grid-template-columns:1fr}}
  }}
</style>
</head>
<body>

<div class="report-header">
  <h1>Bug Bounty Report</h1>
  <div class="report-meta">
    <span>Target: <strong>{esc(target)}</strong></span>
    <span>{now}</span>
    <span>{len(findings)} Finding{'s' if len(findings)!=1 else ''} (deduplicated)</span>
  </div>
</div>

<div class="stats-grid">{stat_cards}</div>

<div class="panel">
  <div class="panel-title">Severity Distribution</div>
  {summary_html}
</div>

<div class="panel">
  <div class="panel-title">Quick Navigation</div>
  <div class="toc">
    {''.join(f'<a href="#finding-{i+1}">{esc(f.get("vuln_type","?"))} #{i+1}</a>' for i,f in enumerate(findings[:30]))}
  </div>
</div>

<div class="panel-title" style="margin-bottom:.8rem">Findings</div>
{findings_html}

<footer>
  Generated by BugHunter AI &mdash; For authorized security research only.<br>
  All payload content is HTML-escaped and safe to view. A Content Security Policy blocks script execution.
</footer>

</body>
</html>"""


# ── Export Functions ───────────────────────────────────────────────────────────

def export_report(findings: list[dict], target: str, output_dir: str,
                  session_notes: str = "", fmt: str = "html") -> dict:
    os.makedirs(output_dir, exist_ok=True)
    slug = target.replace("https://","").replace("http://","").replace("/","_").replace(".","_")
    ts = datetime.now().strftime("%Y%m%d_%H%M")

    paths = {}

    # Always generate HTML + Markdown
    md_path   = os.path.join(output_dir, f"report_{slug}_{ts}.md")
    html_path = os.path.join(output_dir, f"report_{slug}_{ts}.html")

    with open(md_path, "w", encoding="utf-8") as f:
        f.write(generate_markdown(findings, target, session_notes))
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(generate_html(findings, target, session_notes))

    paths["markdown"] = md_path
    paths["html"] = html_path

    # Generate platform-specific reports for top 10 findings
    top_findings = deduplicate_findings(sort_findings(findings))[:10]

    for platform, gen_fn in [("hackerone", generate_hackerone),
                              ("bugcrowd", generate_bugcrowd),
                              ("intigriti", generate_intigriti)]:
        platform_dir = os.path.join(output_dir, platform)
        os.makedirs(platform_dir, exist_ok=True)
        for i, f in enumerate(top_findings, 1):
            p_path = os.path.join(platform_dir, f"finding_{i:02d}_{f.get('severity','').lower()}.md")
            with open(p_path, "w", encoding="utf-8") as file:
                file.write(gen_fn(f, target))
        paths[platform] = platform_dir

    return paths


# ── Helpers ────────────────────────────────────────────────────────────────────

def _get_vrt_category(vuln_type: str) -> str:
    categories = {
        "SQL Injection": "Server-Side Injection > SQL Injection",
        "Blind SQL Injection (Time-Based)": "Server-Side Injection > SQL Injection > Blind",
        "Cross-Site Scripting (XSS)": "Cross-Site Scripting (XSS) > Reflected",
        "Server-Side Request Forgery (SSRF)": "Server-Side Request Forgery",
        "Local File Inclusion (LFI)": "Sensitive Data Exposure > File Disclosure",
        "Open Redirect": "Unvalidated Redirects and Forwards > Open Redirect",
        "Server-Side Template Injection (SSTI)": "Server-Side Injection > Server-Side Template Injection",
        "Missing Security Headers": "Misconfiguration > Application Misconfiguration",
        "Insecure Cookie": "Broken Authentication > Insecure Cookie Handling",
    }
    return categories.get(vuln_type, "Other")


def _get_attacker_action(vuln_type: str) -> str:
    actions = {
        "SQL Injection": "read, modify, or delete all data in the database",
        "Blind SQL Injection (Time-Based)": "enumerate the database through time-based inference",
        "Cross-Site Scripting (XSS)": "execute arbitrary JavaScript in a victim's browser and steal session tokens",
        "Server-Side Request Forgery (SSRF)": "make the server perform requests to internal infrastructure",
        "Local File Inclusion (LFI)": "read arbitrary files from the server filesystem",
        "Open Redirect": "redirect users to a phishing site from a trusted domain",
        "Server-Side Template Injection (SSTI)": "execute arbitrary code on the server",
    }
    return actions.get(vuln_type, "compromise the application")


def _get_impact(vuln_type: str) -> str:
    impacts = {
        "SQL Injection": "Attackers can read, modify, or delete all database contents, extract credentials and PII, and potentially achieve full database compromise and authentication bypass.",
        "Blind SQL Injection (Time-Based)": "Full database enumeration is possible through time-delay inference, despite no visible error output.",
        "Cross-Site Scripting (XSS)": "Attackers can steal session cookies, perform actions as the victim, redirect to malicious sites, deface pages, or deliver malware.",
        "Server-Side Request Forgery (SSRF)": "Attackers can access internal services, cloud metadata endpoints (stealing IAM credentials), and pivot to internal infrastructure.",
        "Local File Inclusion (LFI)": "Attackers can read sensitive server files including configuration files, source code, and private keys.",
        "Open Redirect": "Enables phishing by redirecting users from a trusted domain to a malicious site. Can chain with SSRF.",
        "Server-Side Template Injection (SSTI)": "In many template engines, SSTI leads directly to Remote Code Execution (RCE) on the server.",
        "Missing Security Headers": "Absence of security headers exposes users to clickjacking, XSS, and MIME sniffing attacks.",
        "Insecure Cookie": "Session cookies without proper flags can be stolen via XSS or network interception.",
        "Known CVE": "A publicly disclosed vulnerability exists for detected software version. Exploit code may be publicly available.",
        "Exposed Secrets on GitHub": "Credentials, API keys, or tokens referencing this domain may be publicly accessible on GitHub.",
        "Forbidden Admin Panel": "An administrative interface was detected. If access controls are misconfigured, attackers may gain unauthorized admin access.",
    }
    return impacts.get(vuln_type, "This vulnerability could compromise the confidentiality, integrity, or availability of the application.")


def _get_remediation(vuln_type: str) -> str:
    remediations = {
        "SQL Injection": "Use parameterized queries / prepared statements. Never concatenate user input into SQL. Apply input validation and use an ORM.",
        "Blind SQL Injection (Time-Based)": "Same as SQL Injection — implement parameterized queries immediately.",
        "Cross-Site Scripting (XSS)": "Encode all output with context-aware escaping. Implement a strict Content Security Policy (CSP). Validate and sanitize all user inputs.",
        "Server-Side Request Forgery (SSRF)": "Validate/whitelist allowed URLs and IPs. Block requests to private IP ranges. Use a network-level firewall to restrict outbound connections.",
        "Local File Inclusion (LFI)": "Never pass user input to file system functions. Use a whitelist of allowed paths. Disable PHP allow_url_include.",
        "Open Redirect": "Avoid user-supplied URLs for redirects. Use a whitelist of allowed destinations or signed redirect tokens.",
        "Server-Side Template Injection (SSTI)": "Never pass user input to template rendering functions. Use sandboxed templates. Prefer logic-less templating engines.",
        "Missing Security Headers": "Add: X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, Content-Security-Policy, Referrer-Policy.",
        "Insecure Cookie": "Set Secure, HttpOnly, and SameSite=Strict flags on all session cookies.",
        "Known CVE": "Update the affected software to the latest patched version immediately. Check vendor security advisories.",
        "Exposed Secrets on GitHub": "Rotate all exposed credentials immediately. Add a .gitignore and secret scanning to your CI/CD pipeline.",
        "Forbidden Admin Panel": "Ensure admin interfaces require strong authentication, are not publicly accessible, and are protected by IP allowlisting.",
    }
    return remediations.get(vuln_type, "Apply input validation, follow the principle of least privilege, and consult OWASP guidelines for this vulnerability class.")
