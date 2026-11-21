"""
Automated Hunt Pipeline — Orchestrates the full scan automatically.
Given a domain, runs: Recon → Exploit Search → Vuln Scan → AI Analysis → Report
Creates a dedicated output folder for every target.
"""

import os
import sys
import time
import json
import threading
from datetime import datetime
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import config
from db.database import new_session, add_finding, log_scan, get_findings

# ── Phase definitions ──────────────────────────────────────────────────────────

PHASES = [
    {"id": "setup",   "name": "Setting Up Target",          "icon": "📁"},
    {"id": "recon",   "name": "Reconnaissance",              "icon": "🔍"},
    {"id": "exploit", "name": "Exploit & CVE Intelligence",  "icon": "💣"},
    {"id": "scan",    "name": "Vulnerability Scanning",      "icon": "⚡"},
    {"id": "ai",      "name": "AI Analysis",                 "icon": "🤖"},
    {"id": "report",  "name": "Generating Report",           "icon": "📄"},
]


class HuntPipeline:
    """
    Fully automated hunt pipeline.
    Callbacks:
      on_phase(phase_id, status)    — 'running' | 'done' | 'error'
      on_log(message, level)        — info | success | warning | error | muted
      on_finding(finding_dict)      — new vulnerability found
      on_done(report_paths)         — hunt complete, report paths dict
    """

    def __init__(self, target: str, output_dir: str,
                 on_phase=None, on_log=None, on_finding=None, on_done=None):
        # Normalize target
        if not target.startswith("http"):
            target = f"https://{target}"
        self.target_url = target
        parsed = urlparse(target)
        self.domain = parsed.netloc or parsed.path.split("/")[0]
        self.base_url = f"{parsed.scheme}://{self.domain}"

        # Output folder: reports/<domain>_<date>/
        slug = self.domain.replace(".", "_")
        ts = datetime.now().strftime("%Y%m%d_%H%M")
        self.out_dir = os.path.join(output_dir, f"{slug}_{ts}")
        os.makedirs(self.out_dir, exist_ok=True)

        # Callbacks
        self.on_phase   = on_phase   or (lambda *a: None)
        self.on_log     = on_log     or (lambda *a: None)
        self.on_finding = on_finding or (lambda *a: None)
        self.on_done    = on_done    or (lambda *a: None)

        # State
        self.session_id = None
        self.findings = []
        self.subdomains = []
        self.urls_to_scan = []
        self.tech_stack = []
        self.stop_flag = False

    # ── Public API ─────────────────────────────────────────────────────────────

    def start(self):
        """Run the full pipeline in the current thread."""
        self.on_log(f"Target: {self.domain}", "info")
        self.on_log(f"Output: {self.out_dir}", "muted")

        try:
            self._phase_setup()
            if self.stop_flag: return
            self._phase_recon()
            if self.stop_flag: return
            self._phase_exploit_intel()
            if self.stop_flag: return
            self._phase_scan()
            if self.stop_flag: return
            self._phase_ai()
            if self.stop_flag: return
            self._phase_report()
        except Exception as e:
            self.on_log(f"Pipeline error: {e}", "error")

    def stop(self):
        self.stop_flag = True

    # ── Phase 1: Setup ─────────────────────────────────────────────────────────

    def _phase_setup(self):
        self.on_phase("setup", "running")
        self.on_log("Creating session and output directory...", "info")

        self.session_id = new_session(self.target_url)

        # Write target info file
        info = {
            "target": self.target_url,
            "domain": self.domain,
            "scan_started": datetime.now().isoformat(),
            "output_dir": self.out_dir,
        }
        with open(os.path.join(self.out_dir, "target_info.json"), "w") as f:
            json.dump(info, f, indent=2)

        self.on_log(f"Session #{self.session_id} created", "success")
        self.on_phase("setup", "done")

    # ── Phase 2: Recon ─────────────────────────────────────────────────────────

    def _phase_recon(self):
        self.on_phase("recon", "running")
        recon_data = {}

        # 1. DNS + crt.sh subdomains
        self.on_log("Enumerating subdomains via crt.sh...", "info")
        try:
            from modules.recon.recon import enumerate_subdomains_crtsh, enumerate_subdomains_dns
            crt_subs = enumerate_subdomains_crtsh(self.domain)
            dns_subs = enumerate_subdomains_dns(self.domain,
                callback=lambda r: self.on_log(f"  ✓ {r['subdomain']} → {r['ips'][0]}", "success"))
            all_subs = {s["subdomain"] for s in crt_subs if "error" not in s}
            all_subs |= {s["subdomain"] for s in dns_subs}
            self.subdomains = list(all_subs)
            recon_data["subdomains"] = self.subdomains
            self.on_log(f"Found {len(self.subdomains)} subdomains", "success")
        except Exception as e:
            self.on_log(f"Subdomain enum error: {e}", "warning")

        # 2. HTTP Header fingerprint
        self.on_log("Fingerprinting headers and tech stack...", "info")
        try:
            from modules.recon.recon import fingerprint_headers
            hfp = fingerprint_headers(self.target_url)
            if "error" not in hfp:
                self.tech_stack = hfp.get("tech_stack", [])
                recon_data["headers"] = hfp
                recon_data["tech_stack"] = self.tech_stack
                missing_hdrs = hfp.get("security_headers", {}).get("missing", [])

                self.on_log(f"Server: {hfp.get('server','?')} | Tech: {', '.join(self.tech_stack) or 'Unknown'}", "info")

                # Missing security headers = finding
                if missing_hdrs:
                    f = self._make_finding(
                        vuln_type="Missing Security Headers",
                        severity="LOW",
                        title=f"Missing Security Headers ({len(missing_hdrs)})",
                        description=f"The following security headers are absent: {', '.join(missing_hdrs)}",
                        url=self.target_url, cvss=3.1
                    )
                    self.on_log(f"Missing headers: {', '.join(missing_hdrs)}", "warning")

                # Check cookie flags
                for cookie in hfp.get("cookies", []):
                    if not cookie.get("secure") or not cookie.get("httponly"):
                        issues = []
                        if not cookie.get("secure"): issues.append("no Secure flag")
                        if not cookie.get("httponly"): issues.append("no HttpOnly flag")
                        self._make_finding(
                            vuln_type="Insecure Cookie",
                            severity="LOW",
                            title=f"Insecure Cookie: {cookie['name']}",
                            description=f"Cookie '{cookie['name']}' has: {', '.join(issues)}",
                            url=self.target_url, cvss=3.5
                        )
        except Exception as e:
            self.on_log(f"Header fingerprint error: {e}", "warning")

        # 3. DNS Records
        self.on_log("Fetching DNS records...", "info")
        try:
            from modules.recon.recon import get_dns_records
            dns_records = get_dns_records(self.domain)
            recon_data["dns_records"] = dns_records
        except Exception as e:
            self.on_log(f"DNS records error: {e}", "warning")

        # 4. Wayback Machine URLs
        self.on_log("Mining Wayback Machine for URLs...", "info")
        try:
            from modules.recon.recon import wayback_interesting_urls
            wb_cats = wayback_interesting_urls(self.domain)
            recon_data["wayback"] = wb_cats
            total_urls = sum(len(v) for v in wb_cats.values())
            self.on_log(f"Wayback: {total_urls} interesting URLs found", "success")

            # Add param URLs to scan list
            self.urls_to_scan.extend(wb_cats.get("params", [])[:20])
            self.urls_to_scan.extend(wb_cats.get("php_asp", [])[:10])
        except Exception as e:
            self.on_log(f"Wayback error: {e}", "warning")

        # Always include base URL
        if self.target_url not in self.urls_to_scan:
            self.urls_to_scan.insert(0, self.target_url)

        # 5. WHOIS
        self.on_log("Running WHOIS lookup...", "info")
        try:
            from modules.recon.recon import whois_lookup
            whois_data = whois_lookup(self.domain)
            recon_data["whois"] = whois_data
        except Exception as e:
            self.on_log(f"WHOIS error: {e}", "warning")

        # 6. robots.txt
        self.on_log("Checking robots.txt...", "info")
        try:
            from modules.recon.recon import get_robots_txt
            robots = get_robots_txt(self.target_url)
            recon_data["robots"] = robots
            if robots.get("disallowed"):
                self.on_log(f"robots.txt: {len(robots['disallowed'])} disallowed paths (interesting!)", "warning")
                # Add disallowed paths to scan list
                for path in robots["disallowed"][:5]:
                    full = self.base_url + path if path.startswith("/") else self.base_url + "/" + path
                    self.urls_to_scan.append(full)
        except Exception as e:
            self.on_log(f"robots.txt error: {e}", "warning")

        # Save recon data
        self._save_json("recon.json", recon_data)
        self.on_log(f"Recon complete. {len(self.urls_to_scan)} URLs queued for scanning.", "success")
        self.on_phase("recon", "done")

    # ── Phase 3: Exploit Intelligence ─────────────────────────────────────────

    def _phase_exploit_intel(self):
        self.on_phase("exploit", "running")
        intel_data = {}

        # Search CVEs for detected tech stack
        if self.tech_stack:
            for tech in self.tech_stack[:3]:
                self.on_log(f"Searching CVEs for: {tech}", "info")
                try:
                    from modules.intel.nvd_cve import search_cves
                    cves = search_cves(tech, results_per_page=5)
                    intel_data[f"cves_{tech}"] = cves
                    critical = [c for c in cves if c.get("cvss_score", 0) >= 9.0]
                    high     = [c for c in cves if 7.0 <= c.get("cvss_score", 0) < 9.0]
                    if critical:
                        self.on_log(f"  ⚠ {len(critical)} CRITICAL CVEs for {tech}!", "error")
                        for c in critical[:2]:
                            self._make_finding(
                                vuln_type="Known CVE",
                                severity="CRITICAL",
                                title=f"{c['id']} — {tech}",
                                description=c.get("description", "")[:300],
                                url=self.target_url,
                                cvss=c.get("cvss_score", 9.0)
                            )
                    if high:
                        self.on_log(f"  ! {len(high)} HIGH severity CVEs for {tech}", "warning")
                except Exception as e:
                    self.on_log(f"CVE search error: {e}", "warning")

        # Search Exploit-DB for tech stack
        for tech in self.tech_stack[:2]:
            self.on_log(f"Searching Exploit-DB for: {tech}", "info")
            try:
                from modules.intel.exploitdb import search_exploits
                exploits = search_exploits(tech)
                intel_data[f"exploitdb_{tech}"] = exploits[:10]
                self.on_log(f"  Found {len(exploits)} Exploit-DB entries for {tech}", "info")
            except Exception as e:
                self.on_log(f"Exploit-DB error: {e}", "warning")

        # GitHub PoC search for domain
        self.on_log(f"Searching GitHub for domain-specific findings...", "info")
        try:
            from modules.intel.github_search import search_secrets_patterns, search_repos
            secrets = search_secrets_patterns(self.domain)
            intel_data["github_secrets"] = secrets
            if secrets and "error" not in secrets[0]:
                self.on_log(f"  ⚠ Found {len(secrets)} potential secret exposures on GitHub!", "error")
                if secrets:
                    self._make_finding(
                        vuln_type="Exposed Secrets on GitHub",
                        severity="HIGH",
                        title=f"Possible credentials/secrets for {self.domain} on GitHub",
                        description=f"Found {len(secrets)} GitHub code files referencing {self.domain} with possible credentials.",
                        url=f"https://github.com/search?q={self.domain}+password&type=code",
                        cvss=7.5
                    )
        except Exception as e:
            self.on_log(f"GitHub search error: {e}", "warning")

        self._save_json("intel.json", intel_data)
        self.on_log("Exploit intelligence phase complete.", "success")
        self.on_phase("exploit", "done")

    # ── Phase 4: Vulnerability Scan ────────────────────────────────────────────

    def _phase_scan(self):
        self.on_phase("scan", "running")
        scan_data = {"findings": [], "dir_fuzz": []}

        # 1. Directory fuzzing on main target
        self.on_log(f"Directory fuzzing: {self.base_url}", "info")
        try:
            from modules.scanner.scanner import dir_fuzz
            dirs = dir_fuzz(self.base_url, callback=lambda r: (
                self.on_log(f"  [{r['status']}] {r['url']}", "success" if r["status"] == 200 else "muted")
                if r.get("interesting") else None
            ))
            found_dirs = [d for d in dirs if d["status"] in [200, 403]]
            scan_data["dir_fuzz"] = found_dirs
            self.on_log(f"Dir fuzz: {len(found_dirs)} paths found", "success")

            # 403 admin pages are interesting
            admin_403 = [d for d in dirs if d["status"] == 403 and
                         any(p in d["url"].lower() for p in ["admin", "panel", "dashboard"])]
            for d in admin_403:
                self._make_finding(
                    vuln_type="Forbidden Admin Panel",
                    severity="MEDIUM",
                    title=f"Admin panel detected (403): {d['url']}",
                    description="An admin panel was found but returned 403 Forbidden. May be bypassable.",
                    url=d["url"], cvss=5.3
                )
        except Exception as e:
            self.on_log(f"Dir fuzz error: {e}", "warning")

        # 2. Test each URL with params for vulnerabilities
        from modules.scanner.scanner import (
            test_sqli, test_sqli_time_based, test_xss,
            test_ssrf, test_lfi, test_open_redirect, test_ssti
        )

        urls_with_params = [u for u in self.urls_to_scan if "?" in u and "=" in u]
        self.on_log(f"Testing {len(urls_with_params)} parameterized URLs for vulns...", "info")

        for i, url in enumerate(urls_with_params[:30]):  # cap at 30 URLs
            if self.stop_flag:
                break
            self.on_log(f"  [{i+1}/{min(len(urls_with_params),30)}] Testing: {url[:70]}...", "muted")
            try:
                from urllib.parse import urlparse, parse_qs
                parsed = urlparse(url)
                params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
                base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

                def cb(f):
                    self._make_finding(**{
                        "vuln_type": f["type"], "severity": f["severity"],
                        "title": f"{f['type']} in {parsed.path}",
                        "description": f.get("evidence", ""),
                        "url": f["url"], "parameter": f.get("parameter",""),
                        "payload": f.get("payload",""), "cvss": f.get("cvss", 0.0)
                    })

                test_sqli(base, params, callback=cb)
                test_xss(base, params, callback=cb)
                test_ssrf(base, params, callback=cb)
                test_lfi(base, params, callback=cb)
                test_open_redirect(base, params, callback=cb)
                test_ssti(base, params, callback=cb)

            except Exception as e:
                self.on_log(f"  Scan error on {url[:50]}: {e}", "warning")

        # Also test base URL with common injectable params
        self.on_log("Testing base URL with common injectable parameters...", "info")
        common_params = [
            {"id": "1"}, {"page": "home"}, {"q": "test"},
            {"search": "test"}, {"url": "https://test.com"},
            {"redirect": "https://test.com"}, {"file": "index"},
            {"path": "/home"}, {"template": "index"},
        ]
        for params in common_params[:5]:
            if self.stop_flag:
                break
            try:
                def cb(f):
                    self._make_finding(**{
                        "vuln_type": f["type"], "severity": f["severity"],
                        "title": f"{f['type']} via common parameter",
                        "description": f.get("evidence", ""),
                        "url": f["url"], "parameter": f.get("parameter",""),
                        "payload": f.get("payload",""), "cvss": f.get("cvss", 0.0)
                    })
                test_sqli(self.base_url, params, callback=cb)
                test_xss(self.base_url, params, callback=cb)
                test_ssrf(self.base_url, params, callback=cb)
            except Exception:
                pass

        self._save_json("scan_results.json", scan_data)
        self.on_log(f"Scan complete. Total findings so far: {len(self.findings)}", "success")
        self.on_phase("scan", "done")

    # ── Phase 5: AI Analysis ───────────────────────────────────────────────────

    def _phase_ai(self):
        self.on_phase("ai", "running")
        self.on_log("Sending findings to AI for analysis and enrichment...", "info")

        try:
            from modules.ai_engine.engine import chat, check_ollama_status
            status = check_ollama_status()
            if not status["running"]:
                self.on_log("Ollama not running — skipping AI analysis", "warning")
                self.on_phase("ai", "done")
                return

            # Build context for AI
            tech = ", ".join(self.tech_stack) or "Unknown"
            subs_count = len(self.subdomains)
            findings_summary = "\n".join([
                f"- [{f['severity']}] {f['vuln_type']}: {f['title']} (CVSS: {f.get('cvss_score', f.get('cvss', 'N/A'))})"
                for f in self.findings
            ]) or "No vulnerabilities detected yet."

            prompt = f"""I ran an automated bug bounty scan on {self.domain}.

Tech Stack: {tech}
Subdomains found: {subs_count}
URLs scanned: {len(self.urls_to_scan)}

Findings:
{findings_summary}

Based on this, please:
1. Identify the highest-priority attack vectors I should test manually
2. Suggest 3-5 additional specific tests based on the tech stack
3. Rate the overall attack surface (Low/Medium/High/Critical)
4. Give me 3 specific curl commands to test manually
5. Write a 2-paragraph executive summary for the bug bounty report"""

            self.on_log("AI analyzing attack surface...", "info")
            ai_response = chat(prompt)
            self._save_text("ai_analysis.txt", ai_response)
            self.on_log("AI analysis complete.", "success")

            # Save AI analysis as a special finding
            self.findings.append({
                "vuln_type": "AI Analysis",
                "severity": "INFO",
                "title": "AI Security Analysis",
                "description": ai_response,
                "url": self.target_url,
                "cvss_score": 0,
                "ai_generated": True,
            })

        except Exception as e:
            self.on_log(f"AI analysis error: {e}", "warning")

        self.on_phase("ai", "done")

    # ── Phase 6: Report ────────────────────────────────────────────────────────

    def _phase_report(self):
        self.on_phase("report", "running")
        self.on_log("Generating comprehensive report...", "info")

        try:
            from modules.reporter import export_report, generate_html, generate_markdown

            # Exclude AI analysis from vuln findings for report
            vuln_findings = [f for f in self.findings if f.get("vuln_type") != "AI Analysis"]
            ai_analysis = next((f["description"] for f in self.findings if f.get("ai_generated")), "")

            # Save Markdown
            md = generate_markdown(vuln_findings, self.target_url)
            if ai_analysis:
                md += f"\n\n---\n\n## 🤖 AI Security Analysis\n\n{ai_analysis}\n"
            md_path = os.path.join(self.out_dir, "report.md")
            with open(md_path, "w", encoding="utf-8") as f:
                f.write(md)

            # Save HTML
            html = generate_html(vuln_findings, self.target_url)
            html_path = os.path.join(self.out_dir, "report.html")
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html)

            # Save findings JSON
            self._save_json("findings.json", vuln_findings)

            # Write summary
            summary = {
                "target": self.target_url,
                "domain": self.domain,
                "scan_completed": datetime.now().isoformat(),
                "total_findings": len(vuln_findings),
                "critical": len([f for f in vuln_findings if f.get("severity") == "CRITICAL"]),
                "high":     len([f for f in vuln_findings if f.get("severity") == "HIGH"]),
                "medium":   len([f for f in vuln_findings if f.get("severity") == "MEDIUM"]),
                "low":      len([f for f in vuln_findings if f.get("severity") == "LOW"]),
                "subdomains_found": len(self.subdomains),
                "urls_scanned": len(self.urls_to_scan),
                "tech_stack": self.tech_stack,
                "report_html": html_path,
                "report_md": md_path,
            }
            self._save_json("summary.json", summary)

            self.on_log(f"Report saved to: {self.out_dir}", "success")
            self.on_log(f"Total: {summary['total_findings']} findings | {summary['critical']} CRITICAL | {summary['high']} HIGH", "success")
            self.on_phase("report", "done")
            self.on_done({"html": html_path, "md": md_path, "dir": self.out_dir, "summary": summary})

        except Exception as e:
            self.on_log(f"Report error: {e}", "error")
            self.on_phase("report", "error")

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _make_finding(self, vuln_type, severity, title, description,
                      url, parameter="", payload="", cvss=0.0) -> dict:
        f = {
            "vuln_type": vuln_type, "severity": severity,
            "title": title, "description": description,
            "url": url, "parameter": parameter,
            "payload": payload, "cvss_score": cvss,
            "found_at": datetime.now().isoformat(),
        }
        self.findings.append(f)
        if self.session_id:
            add_finding(
                self.session_id, vuln_type=vuln_type, severity=severity,
                title=title, description=description, url=url,
                parameter=parameter, payload=payload, cvss_score=cvss
            )
        self.on_finding(f)
        return f

    def _save_json(self, filename: str, data):
        path = os.path.join(self.out_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

    def _save_text(self, filename: str, text: str):
        path = os.path.join(self.out_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
