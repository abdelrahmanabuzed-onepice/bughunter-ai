"""
BugHunter AI — Main GUI Application
Premium dark theme built with customtkinter.
"""

import customtkinter as ctk
import threading
import webbrowser
import json
import time
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from config import config, save_config
from db.database import new_session, get_sessions, add_finding, get_findings, log_scan
from modules.intel.exploitdb import search_exploits, get_exploit_code, get_recent_exploits, search_ghdb
from modules.intel.github_search import search_cve_poc, search_repos, search_code, search_secrets_patterns
from modules.intel.nvd_cve import lookup_cve, search_cves, get_recent_cves
from modules.recon.recon import (
    enumerate_subdomains_dns, enumerate_subdomains_crtsh,
    wayback_interesting_urls, get_dns_records, fingerprint_headers,
    whois_lookup, get_robots_txt
)
from modules.scanner.scanner import (
    test_sqli, test_sqli_time_based, test_xss,
    test_ssrf, test_lfi, test_open_redirect,
    test_ssti, dir_fuzz
)
from modules.payload_generator import get_payloads, get_all_categories, get_bypass_variants, context_suggest
from modules.ai_engine.engine import chat, analyze_http, explain_vulnerability, check_ollama_status
from modules.reporter import export_report

# ── Theme Setup ───────────────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

COLORS = {
    "bg":       "#0D0F14",
    "surface":  "#161B22",
    "surface2": "#1E2530",
    "border":   "#30363D",
    "accent":   "#5B8DEF",
    "green":    "#00C896",
    "red":      "#FF2D55",
    "orange":   "#FF6B35",
    "yellow":   "#FFB800",
    "text":     "#E6EDF3",
    "muted":    "#8B949E",
}

SEVERITY_COLORS = {
    "CRITICAL": COLORS["red"],
    "HIGH":     COLORS["orange"],
    "MEDIUM":   COLORS["yellow"],
    "LOW":      COLORS["green"],
    "INFO":     COLORS["accent"],
}


class TerminalWidget(ctk.CTkTextbox):
    """Scrollable terminal output widget with color support."""
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.configure(
            font=("JetBrains Mono", 12),
            fg_color=COLORS["bg"],
            text_color=COLORS["text"],
            border_color=COLORS["border"],
            border_width=1,
            state="disabled"
        )
        self.tag_config("info",    foreground=COLORS["accent"])
        self.tag_config("success", foreground=COLORS["green"])
        self.tag_config("warning", foreground=COLORS["yellow"])
        self.tag_config("error",   foreground=COLORS["red"])
        self.tag_config("muted",   foreground=COLORS["muted"])
        self.tag_config("bold",    foreground=COLORS["text"])

    def log(self, message: str, level: str = "info"):
        self.configure(state="normal")
        ts = time.strftime("%H:%M:%S")
        prefix = {"info": "ℹ", "success": "✓", "warning": "⚠", "error": "✗", "muted": "·"}.get(level, "·")
        line = f"[{ts}] {prefix} {message}\n"
        self.insert("end", line, level)
        self.see("end")
        self.configure(state="disabled")

    def append(self, text: str, tag: str = ""):
        self.configure(state="normal")
        self.insert("end", text, tag)
        self.see("end")
        self.configure(state="disabled")

    def clear(self):
        self.configure(state="normal")
        self.delete("1.0", "end")
        self.configure(state="disabled")


class ResultCard(ctk.CTkFrame):
    """A styled card widget for displaying a single result."""
    def __init__(self, master, title: str, subtitle: str = "", badge: str = "",
                 badge_color: str = None, on_click=None, **kwargs):
        super().__init__(master, fg_color=COLORS["surface2"], corner_radius=8,
                         border_color=COLORS["border"], border_width=1, **kwargs)
        self.configure(cursor="hand2" if on_click else "")

        inner = ctk.CTkFrame(self, fg_color="transparent")
        inner.pack(fill="x", padx=12, pady=10)

        left = ctk.CTkFrame(inner, fg_color="transparent")
        left.pack(side="left", fill="x", expand=True)

        ctk.CTkLabel(left, text=title, font=("Inter", 13, "bold"),
                     text_color=COLORS["text"], anchor="w").pack(fill="x")
        if subtitle:
            ctk.CTkLabel(left, text=subtitle, font=("Inter", 11),
                         text_color=COLORS["muted"], anchor="w").pack(fill="x")

        if badge:
            ctk.CTkLabel(inner, text=badge, font=("Inter", 10, "bold"),
                         text_color="white",
                         fg_color=badge_color or COLORS["accent"],
                         corner_radius=10, width=80).pack(side="right", padx=4)

        if on_click:
            for widget in [self, inner, left]:
                widget.bind("<Button-1>", lambda e: on_click())


class BugHunterApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("🐛 BugHunter AI — Maximum Power Edition")
        self.geometry("1400x900")
        self.minsize(1100, 700)
        self.configure(fg_color=COLORS["bg"])

        self.current_session_id = None
        self.current_target = ctk.StringVar(value="")
        self.ai_history = []

        self._build_header()
        self._build_main()
        self._build_terminal()

        # Initial log
        self.terminal.log("BugHunter AI started. For authorized security research only.", "success")
        self.terminal.log("Set your target URL and start recon, or search Exploit-DB / GitHub.", "muted")
        self._check_ollama_async()

    # ── Header ─────────────────────────────────────────────────────────────────
    def _build_header(self):
        hdr = ctk.CTkFrame(self, fg_color=COLORS["surface"], height=65, corner_radius=0)
        hdr.pack(fill="x", side="top")
        hdr.pack_propagate(False)

        # Logo
        logo = ctk.CTkLabel(hdr, text="  🐛 BugHunter AI",
                             font=("Inter", 18, "bold"), text_color=COLORS["text"])
        logo.pack(side="left", padx=20)

        # Target input
        ctk.CTkLabel(hdr, text="Target:", font=("Inter", 12),
                     text_color=COLORS["muted"]).pack(side="left", padx=(30, 5))
        self.target_entry = ctk.CTkEntry(
            hdr, textvariable=self.current_target,
            placeholder_text="https://target.example.com",
            width=350, font=("JetBrains Mono", 12),
            fg_color=COLORS["surface2"], border_color=COLORS["border"],
            text_color=COLORS["text"]
        )
        self.target_entry.pack(side="left", padx=5)

        ctk.CTkButton(hdr, text="▶ New Session", font=("Inter", 12, "bold"),
                      fg_color=COLORS["accent"], hover_color="#4070C0",
                      command=self._start_session, width=120).pack(side="left", padx=10)

        # Session status
        self.session_label = ctk.CTkLabel(hdr, text="No active session",
                                           font=("Inter", 11), text_color=COLORS["muted"])
        self.session_label.pack(side="left", padx=10)

        # Right buttons
        ctk.CTkButton(hdr, text="⚙ Settings", font=("Inter", 12),
                      fg_color=COLORS["surface2"], hover_color=COLORS["border"],
                      command=self._open_settings, width=100).pack(side="right", padx=5)
        ctk.CTkButton(hdr, text="📄 Export Report", font=("Inter", 12),
                      fg_color=COLORS["green"], hover_color="#00A07A",
                      command=self._export_report, width=130).pack(side="right", padx=5)

        self.ollama_indicator = ctk.CTkLabel(hdr, text="● AI: Checking...",
                                              font=("Inter", 11), text_color=COLORS["muted"])
        self.ollama_indicator.pack(side="right", padx=15)

    # ── Main Content ───────────────────────────────────────────────────────────
    def _build_main(self):
        self.tabview = ctk.CTkTabview(
            self,
            fg_color=COLORS["surface"],
            segmented_button_fg_color=COLORS["surface2"],
            segmented_button_selected_color=COLORS["accent"],
            segmented_button_unselected_color=COLORS["surface2"],
            segmented_button_selected_hover_color="#4070C0",
            text_color=COLORS["text"],
            border_color=COLORS["border"],
            border_width=1,
        )
        self.tabview.pack(fill="both", expand=True, padx=10, pady=(5, 0))

        tabs = ["🏠 Dashboard", "🔍 Recon", "💣 Exploit Search", "⚡ Scanner", "💥 Payload Lab", "🤖 AI Chat", "📄 Reports"]
        for tab in tabs:
            self.tabview.add(tab)

        self._build_dashboard()
        self._build_recon_tab()
        self._build_exploit_tab()
        self._build_scanner_tab()
        self._build_payload_tab()
        self._build_ai_tab()
        self._build_reports_tab()

    # ── Terminal ───────────────────────────────────────────────────────────────
    def _build_terminal(self):
        term_frame = ctk.CTkFrame(self, fg_color=COLORS["surface"], height=180, corner_radius=0)
        term_frame.pack(fill="x", side="bottom")
        term_frame.pack_propagate(False)

        bar = ctk.CTkFrame(term_frame, fg_color=COLORS["surface2"], height=30)
        bar.pack(fill="x")
        bar.pack_propagate(False)
        ctk.CTkLabel(bar, text="  Terminal Output", font=("Inter", 11, "bold"),
                     text_color=COLORS["muted"]).pack(side="left", padx=10, pady=5)
        ctk.CTkButton(bar, text="Clear", font=("Inter", 10),
                      fg_color="transparent", hover_color=COLORS["border"],
                      text_color=COLORS["muted"], width=60,
                      command=lambda: self.terminal.clear()).pack(side="right", padx=5)

        self.terminal = TerminalWidget(term_frame, height=150)
        self.terminal.pack(fill="both", expand=True, padx=5, pady=5)

    # ── Dashboard Tab ──────────────────────────────────────────────────────────
    def _build_dashboard(self):
        tab = self.tabview.tab("🏠 Dashboard")
        scroll = ctk.CTkScrollableFrame(tab, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=10, pady=10)

        # Stats row
        stats_frame = ctk.CTkFrame(scroll, fg_color="transparent")
        stats_frame.pack(fill="x", pady=(0, 15))

        self.stat_labels = {}
        for label, val, color in [
            ("Total Sessions", "0", COLORS["accent"]),
            ("Findings", "0", COLORS["red"]),
            ("Critical", "0", COLORS["red"]),
            ("High", "0", COLORS["orange"]),
        ]:
            card = ctk.CTkFrame(stats_frame, fg_color=COLORS["surface2"],
                                corner_radius=12, border_color=COLORS["border"], border_width=1)
            card.pack(side="left", expand=True, fill="x", padx=5)
            lbl = ctk.CTkLabel(card, text=val, font=("Inter", 32, "bold"), text_color=color)
            lbl.pack(pady=(15, 2))
            ctk.CTkLabel(card, text=label, font=("Inter", 11), text_color=COLORS["muted"]).pack(pady=(0, 15))
            self.stat_labels[label] = lbl

        # Recent sessions
        ctk.CTkLabel(scroll, text="Recent Sessions", font=("Inter", 14, "bold"),
                     text_color=COLORS["text"]).pack(anchor="w", pady=(5, 8))

        self.sessions_frame = ctk.CTkScrollableFrame(scroll, fg_color=COLORS["surface2"],
                                                      height=200, corner_radius=8)
        self.sessions_frame.pack(fill="x", pady=(0, 15))

        # Recent Exploits from EDB
        ctk.CTkLabel(scroll, text="Latest Exploit-DB Entries", font=("Inter", 14, "bold"),
                     text_color=COLORS["text"]).pack(anchor="w", pady=(5, 8))
        self.edb_feed_frame = ctk.CTkScrollableFrame(scroll, fg_color=COLORS["surface2"],
                                                      height=200, corner_radius=8)
        self.edb_feed_frame.pack(fill="x")

        ctk.CTkLabel(self.edb_feed_frame, text="Click 'Refresh Feed' to load latest exploits",
                     text_color=COLORS["muted"]).pack(pady=20)
        ctk.CTkButton(scroll, text="🔄 Refresh Dashboard", font=("Inter", 12),
                      fg_color=COLORS["accent"], command=self._refresh_dashboard).pack(pady=10)

    def _refresh_dashboard(self):
        self._update_sessions_list()
        threading.Thread(target=self._load_edb_feed, daemon=True).start()

    def _update_sessions_list(self):
        for w in self.sessions_frame.winfo_children():
            w.destroy()
        sessions = get_sessions()
        self.stat_labels["Total Sessions"].configure(text=str(len(sessions)))
        for s in sessions[:10]:
            ResultCard(
                self.sessions_frame,
                title=s["target"],
                subtitle=f"Created: {s['created_at'][:16]}  |  Findings: {s['finding_count']}",
                badge=f"{s['finding_count']} findings",
                badge_color=COLORS["accent"] if s['finding_count'] == 0 else COLORS["orange"],
                on_click=lambda sid=s["id"]: self._load_session(sid)
            ).pack(fill="x", pady=3, padx=5)

    def _load_edb_feed(self):
        exploits = get_recent_exploits(8)
        self.after(0, lambda: self._render_edb_feed(exploits))

    def _render_edb_feed(self, exploits):
        for w in self.edb_feed_frame.winfo_children():
            w.destroy()
        for e in exploits:
            if "error" in e:
                ctk.CTkLabel(self.edb_feed_frame, text=e["error"], text_color=COLORS["red"]).pack()
                return
            ResultCard(
                self.edb_feed_frame,
                title=e.get("title", "Unknown"),
                subtitle=e.get("date", ""),
                badge="EDB",
                badge_color=COLORS["red"],
                on_click=lambda url=e.get("url", ""): webbrowser.open(url) if url else None
            ).pack(fill="x", pady=2, padx=5)

    def _load_session(self, session_id: int):
        self.current_session_id = session_id
        self.session_label.configure(text=f"Session #{session_id}", text_color=COLORS["green"])
        self.terminal.log(f"Loaded session #{session_id}", "success")

    # ── Recon Tab ──────────────────────────────────────────────────────────────
    def _build_recon_tab(self):
        tab = self.tabview.tab("🔍 Recon")
        main = ctk.CTkFrame(tab, fg_color="transparent")
        main.pack(fill="both", expand=True)
        main.columnconfigure(0, weight=1)
        main.columnconfigure(1, weight=2)
        main.rowconfigure(0, weight=1)

        # Controls
        ctrl = ctk.CTkScrollableFrame(main, fg_color=COLORS["surface2"],
                                       corner_radius=10, width=300)
        ctrl.grid(row=0, column=0, sticky="nsew", padx=(5, 3), pady=5)

        ctk.CTkLabel(ctrl, text="Recon Controls", font=("Inter", 13, "bold"),
                     text_color=COLORS["text"]).pack(anchor="w", padx=10, pady=(10, 5))

        self.recon_target = ctk.CTkEntry(ctrl, placeholder_text="example.com or https://...",
                                          font=("JetBrains Mono", 12),
                                          fg_color=COLORS["surface"], border_color=COLORS["border"])
        self.recon_target.pack(fill="x", padx=10, pady=5)

        for btn_text, cmd in [
            ("🌐 Subdomains (DNS Brute)", lambda: self._run_recon("dns")),
            ("📜 Subdomains (crt.sh)", lambda: self._run_recon("crt")),
            ("🕰️ Wayback Machine URLs", lambda: self._run_recon("wayback")),
            ("📋 DNS Records", lambda: self._run_recon("dns_records")),
            ("🔧 Header Fingerprint", lambda: self._run_recon("headers")),
            ("🔍 WHOIS Lookup", lambda: self._run_recon("whois")),
            ("🤖 robots.txt / sitemap", lambda: self._run_recon("robots")),
        ]:
            ctk.CTkButton(ctrl, text=btn_text, font=("Inter", 12),
                          fg_color=COLORS["surface"], hover_color=COLORS["border"],
                          anchor="w", command=cmd).pack(fill="x", padx=10, pady=3)

        ctk.CTkButton(ctrl, text="🚀 Run Full Recon", font=("Inter", 12, "bold"),
                      fg_color=COLORS["accent"], command=lambda: self._run_recon("full")).pack(
            fill="x", padx=10, pady=10)

        # Results
        result_frame = ctk.CTkFrame(main, fg_color="transparent")
        result_frame.grid(row=0, column=1, sticky="nsew", padx=(3, 5), pady=5)

        ctk.CTkLabel(result_frame, text="Results", font=("Inter", 13, "bold"),
                     text_color=COLORS["text"]).pack(anchor="w", padx=5)

        self.recon_output = ctk.CTkTextbox(
            result_frame, font=("JetBrains Mono", 11),
            fg_color=COLORS["bg"], text_color=COLORS["text"],
            border_color=COLORS["border"], border_width=1
        )
        self.recon_output.pack(fill="both", expand=True, pady=5)

    def _run_recon(self, mode: str):
        target = self.recon_target.get() or self.current_target.get()
        if not target:
            self.terminal.log("Please enter a target first!", "error")
            return
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        self.terminal.log(f"Starting recon [{mode}] on {domain}", "info")
        threading.Thread(target=self._do_recon, args=(mode, domain, target), daemon=True).start()

    def _do_recon(self, mode: str, domain: str, url: str):
        output = ctk.CTkTextbox
        def write(text: str):
            self.after(0, lambda t=text: (
                self.recon_output.configure(state="normal"),
                self.recon_output.insert("end", t + "\n"),
                self.recon_output.see("end"),
                self.recon_output.configure(state="disabled")
            ))

        self.after(0, lambda: (self.recon_output.configure(state="normal"),
                                self.recon_output.delete("1.0", "end"),
                                self.recon_output.configure(state="disabled")))

        if mode in ("dns", "full"):
            write(f"=== DNS Subdomain Brute-Force: {domain} ===")
            results = enumerate_subdomains_dns(domain, callback=lambda r: write(f"  ✓ {r['subdomain']} → {', '.join(r['ips'])}"))
            write(f"Found {len(results)} subdomains via DNS brute-force\n")
            self.terminal.log(f"DNS brute-force: {len(results)} subdomains found", "success")

        if mode in ("crt", "full"):
            write(f"=== crt.sh Certificate Transparency: {domain} ===")
            results = enumerate_subdomains_crtsh(domain)
            for r in results:
                if "error" not in r:
                    write(f"  ✓ {r['subdomain']} (logged: {r.get('logged_at', '')})")
            write(f"Found {len(results)} entries via crt.sh\n")
            self.terminal.log(f"crt.sh: {len(results)} subdomains found", "success")

        if mode in ("wayback", "full"):
            write(f"=== Wayback Machine URL Mining: {domain} ===")
            cats = wayback_interesting_urls(domain)
            for cat, urls in cats.items():
                if urls:
                    write(f"\n[{cat.upper()}] ({len(urls)} URLs)")
                    for u in urls[:15]:
                        write(f"  {u}")
            self.terminal.log("Wayback Machine mining complete", "success")

        if mode in ("dns_records", "full"):
            write(f"=== DNS Records: {domain} ===")
            records = get_dns_records(domain)
            for rtype, values in records.items():
                if values:
                    write(f"  {rtype}: {', '.join(values)}")
            write("")

        if mode in ("headers", "full"):
            write(f"=== HTTP Header Fingerprint: {url} ===")
            data = fingerprint_headers(url)
            if "error" not in data:
                write(f"  Status: {data['status_code']}")
                write(f"  Server: {data['server']}")
                write(f"  Tech Stack: {', '.join(data['tech_stack']) or 'Unknown'}")
                write(f"  Missing Security Headers: {', '.join(data['security_headers']['missing'])}")
                write(f"  Cookies: {len(data['cookies'])} cookies found")
                for c in data["cookies"]:
                    flags = []
                    if not c["secure"]: flags.append("NO Secure")
                    if not c["httponly"]: flags.append("NO HttpOnly")
                    write(f"    ⚠ {c['name']}: {', '.join(flags) or 'OK'}")
            else:
                write(f"  Error: {data['error']}")
            write("")
            self.terminal.log("Header fingerprinting complete", "success")

        if mode in ("whois", "full"):
            write(f"=== WHOIS: {domain} ===")
            data = whois_lookup(domain)
            for k, v in data.items():
                if v and "error" not in k:
                    write(f"  {k}: {v}")
            write("")

        if mode in ("robots", "full"):
            write(f"=== robots.txt: {url} ===")
            data = get_robots_txt(url)
            if data.get("disallowed"):
                write(f"  Disallowed paths ({len(data['disallowed'])}):")
                for p in data["disallowed"][:20]:
                    write(f"    {p}")
            if data.get("sitemaps"):
                write(f"  Sitemaps: {', '.join(data['sitemaps'])}")
            write("")

        self.terminal.log(f"Recon [{mode}] complete for {domain}", "success")

    # ── Exploit Search Tab ────────────────────────────────────────────────────
    def _build_exploit_tab(self):
        tab = self.tabview.tab("💣 Exploit Search")
        main = ctk.CTkFrame(tab, fg_color="transparent")
        main.pack(fill="both", expand=True)
        main.columnconfigure(0, weight=1)
        main.columnconfigure(1, weight=2)
        main.rowconfigure(0, weight=1)

        # Search panel
        left = ctk.CTkScrollableFrame(main, fg_color=COLORS["surface2"],
                                       corner_radius=10, width=320)
        left.grid(row=0, column=0, sticky="nsew", padx=(5, 3), pady=5)

        ctk.CTkLabel(left, text="Exploit Intelligence", font=("Inter", 13, "bold"),
                     text_color=COLORS["text"]).pack(anchor="w", padx=10, pady=(10, 5))

        self.exploit_query = ctk.CTkEntry(left, placeholder_text="Search query / CVE ID / software...",
                                           font=("Inter", 12),
                                           fg_color=COLORS["surface"], border_color=COLORS["border"])
        self.exploit_query.pack(fill="x", padx=10, pady=5)
        self.exploit_query.bind("<Return>", lambda e: self._search_exploits())

        ctk.CTkLabel(left, text="Source:", font=("Inter", 11), text_color=COLORS["muted"]).pack(anchor="w", padx=10)
        self.exploit_source = ctk.CTkSegmentedButton(
            left, values=["Exploit-DB", "GitHub", "NVD/CVE", "GHDB Dorks"],
            font=("Inter", 11),
            fg_color=COLORS["surface"], selected_color=COLORS["accent"],
            unselected_color=COLORS["surface"], text_color=COLORS["text"]
        )
        self.exploit_source.set("Exploit-DB")
        self.exploit_source.pack(fill="x", padx=10, pady=5)

        ctk.CTkButton(left, text="🔍 Search", font=("Inter", 12, "bold"),
                      fg_color=COLORS["accent"], command=self._search_exploits).pack(
            fill="x", padx=10, pady=5)

        # GitHub specific
        ctk.CTkLabel(left, text="GitHub Extras", font=("Inter", 12, "bold"),
                     text_color=COLORS["text"]).pack(anchor="w", padx=10, pady=(15, 5))

        for btn_text, cmd in [
            ("🔐 Search Exposed Secrets", self._search_secrets),
            ("🛠️ Security Tools (Recon)", lambda: self._search_gh_tools("recon")),
            ("🛠️ Security Tools (SQLi)", lambda: self._search_gh_tools("sqli")),
            ("🛠️ Security Tools (Fuzzer)", lambda: self._search_gh_tools("fuzzer")),
        ]:
            ctk.CTkButton(left, text=btn_text, font=("Inter", 11),
                          fg_color=COLORS["surface"], hover_color=COLORS["border"],
                          command=cmd, anchor="w").pack(fill="x", padx=10, pady=2)

        # Results
        right = ctk.CTkFrame(main, fg_color="transparent")
        right.grid(row=0, column=1, sticky="nsew", padx=(3, 5), pady=5)

        self.exploit_results = ctk.CTkScrollableFrame(right, fg_color=COLORS["bg"],
                                                       corner_radius=8)
        self.exploit_results.pack(fill="both", expand=True, pady=(0, 5))

        self.exploit_detail = ctk.CTkTextbox(right, height=200, font=("JetBrains Mono", 11),
                                              fg_color=COLORS["bg"], text_color=COLORS["text"],
                                              border_color=COLORS["border"], border_width=1)
        self.exploit_detail.pack(fill="x")

    def _search_exploits(self):
        query = self.exploit_query.get().strip()
        if not query:
            return
        source = self.exploit_source.get()
        self.terminal.log(f"Searching {source} for: {query}", "info")
        threading.Thread(target=self._do_exploit_search, args=(query, source), daemon=True).start()

    def _do_exploit_search(self, query: str, source: str):
        if source == "Exploit-DB":
            results = search_exploits(query)
        elif source == "GitHub":
            # Check if it's a CVE ID
            if query.upper().startswith("CVE-"):
                results = search_cve_poc(query)
            else:
                results = search_repos(query)
        elif source == "NVD/CVE":
            if query.upper().startswith("CVE-"):
                cve = lookup_cve(query)
                results = [cve] if "error" not in cve else [cve]
            else:
                results = search_cves(query)
        elif source == "GHDB Dorks":
            results = search_ghdb(query)
        else:
            results = []

        self.after(0, lambda: self._render_exploit_results(results, source))

    def _render_exploit_results(self, results: list, source: str):
        for w in self.exploit_results.winfo_children():
            w.destroy()

        if not results:
            ctk.CTkLabel(self.exploit_results, text="No results found",
                         text_color=COLORS["muted"]).pack(pady=20)
            return

        self.terminal.log(f"Found {len(results)} results", "success")

        for r in results:
            if "error" in r:
                ctk.CTkLabel(self.exploit_results, text=r["error"],
                             text_color=COLORS["red"]).pack(padx=10, pady=5)
                continue

            if source == "NVD/CVE":
                score = r.get("cvss_score", 0)
                badge_color = COLORS["red"] if score >= 9 else COLORS["orange"] if score >= 7 else COLORS["yellow"]
                ResultCard(
                    self.exploit_results,
                    title=r.get("id", "Unknown"),
                    subtitle=r.get("description", "")[:100] + "...",
                    badge=f"CVSS {score}",
                    badge_color=badge_color,
                    on_click=lambda rv=r: self._show_cve_detail(rv)
                ).pack(fill="x", pady=2, padx=5)
            elif source == "GitHub":
                stars = r.get("stars", 0)
                ResultCard(
                    self.exploit_results,
                    title=r.get("name", "Unknown"),
                    subtitle=r.get("description", "")[:100],
                    badge=f"⭐ {stars}",
                    badge_color=COLORS["yellow"],
                    on_click=lambda rv=r: webbrowser.open(rv.get("url", ""))
                ).pack(fill="x", pady=2, padx=5)
            else:
                eid = str(r.get("id", ""))
                ResultCard(
                    self.exploit_results,
                    title=r.get("title", r.get("dork", "Unknown")),
                    subtitle=f"{r.get('type', '')} | {r.get('platform', '')} | {r.get('date', '')}",
                    badge=r.get("type", "EDB")[:10],
                    badge_color=COLORS["red"],
                    on_click=lambda rv=r, eid=eid: self._show_exploit_detail(rv, eid)
                ).pack(fill="x", pady=2, padx=5)

    def _show_exploit_detail(self, result: dict, exploit_id: str):
        self.exploit_detail.configure(state="normal")
        self.exploit_detail.delete("1.0", "end")
        self.exploit_detail.insert("end", f"Loading exploit #{exploit_id}...\n")
        self.exploit_detail.configure(state="disabled")
        threading.Thread(target=self._load_exploit_code, args=(exploit_id, result), daemon=True).start()

    def _load_exploit_code(self, exploit_id: str, result: dict):
        code = get_exploit_code(exploit_id) if exploit_id else ""
        def show():
            self.exploit_detail.configure(state="normal")
            self.exploit_detail.delete("1.0", "end")
            self.exploit_detail.insert("end", f"Title: {result.get('title', '')}\n")
            self.exploit_detail.insert("end", f"URL: {result.get('url', '')}\n")
            self.exploit_detail.insert("end", f"CVE: {result.get('cve', 'N/A')}\n\n")
            self.exploit_detail.insert("end", "--- EXPLOIT CODE ---\n\n")
            self.exploit_detail.insert("end", code)
            self.exploit_detail.configure(state="disabled")
        self.after(0, show)

    def _show_cve_detail(self, cve: dict):
        self.exploit_detail.configure(state="normal")
        self.exploit_detail.delete("1.0", "end")
        for k, v in cve.items():
            if isinstance(v, list):
                v = "\n  ".join(v[:5])
            self.exploit_detail.insert("end", f"{k.upper()}: {v}\n\n")
        self.exploit_detail.configure(state="disabled")

    def _search_secrets(self):
        target = self.current_target.get()
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        if not domain:
            self.terminal.log("Set a target first!", "error")
            return
        self.terminal.log(f"Searching GitHub for exposed secrets: {domain}", "warning")
        threading.Thread(target=lambda: self.after(0, lambda: self._render_exploit_results(
            search_secrets_patterns(domain), "GitHub")), daemon=True).start()

    def _search_gh_tools(self, category: str):
        from modules.intel.github_search import search_security_tools
        self.terminal.log(f"Searching GitHub for {category} tools...", "info")
        threading.Thread(target=lambda: self.after(0, lambda: self._render_exploit_results(
            search_security_tools(category), "GitHub")), daemon=True).start()

    # ── Scanner Tab ───────────────────────────────────────────────────────────
    def _build_scanner_tab(self):
        tab = self.tabview.tab("⚡ Scanner")
        main = ctk.CTkFrame(tab, fg_color="transparent")
        main.pack(fill="both", expand=True)
        main.columnconfigure(0, weight=1)
        main.columnconfigure(1, weight=2)
        main.rowconfigure(0, weight=1)

        # Controls
        left = ctk.CTkScrollableFrame(main, fg_color=COLORS["surface2"],
                                       corner_radius=10, width=300)
        left.grid(row=0, column=0, sticky="nsew", padx=(5, 3), pady=5)

        ctk.CTkLabel(left, text="Vulnerability Scanner", font=("Inter", 13, "bold"),
                     text_color=COLORS["text"]).pack(anchor="w", padx=10, pady=(10, 5))

        ctk.CTkLabel(left, text="Target URL:", font=("Inter", 11),
                     text_color=COLORS["muted"]).pack(anchor="w", padx=10)
        self.scan_url = ctk.CTkEntry(left, placeholder_text="https://target.com/page?id=1",
                                      font=("JetBrains Mono", 11),
                                      fg_color=COLORS["surface"], border_color=COLORS["border"])
        self.scan_url.pack(fill="x", padx=10, pady=5)

        ctk.CTkLabel(left, text="Parameters (JSON):", font=("Inter", 11),
                     text_color=COLORS["muted"]).pack(anchor="w", padx=10)
        self.scan_params = ctk.CTkEntry(left, placeholder_text='{"id":"1","page":"home"}',
                                         font=("JetBrains Mono", 11),
                                         fg_color=COLORS["surface"], border_color=COLORS["border"])
        self.scan_params.pack(fill="x", padx=10, pady=5)

        ctk.CTkLabel(left, text="Select Tests:", font=("Inter", 11, "bold"),
                     text_color=COLORS["text"]).pack(anchor="w", padx=10, pady=(10, 5))

        self.scan_checks = {}
        for check_name in ["SQL Injection", "Time-Based SQLi", "XSS", "SSRF",
                            "LFI", "Open Redirect", "SSTI", "Directory Fuzzing"]:
            var = ctk.BooleanVar(value=True)
            cb = ctk.CTkCheckBox(left, text=check_name, variable=var,
                                  font=("Inter", 11), text_color=COLORS["text"],
                                  checkmark_color=COLORS["accent"],
                                  fg_color=COLORS["accent"])
            cb.pack(anchor="w", padx=10, pady=2)
            self.scan_checks[check_name] = var

        ctk.CTkButton(left, text="🚀 Launch Scan", font=("Inter", 12, "bold"),
                      fg_color=COLORS["red"], hover_color="#CC0033",
                      command=self._run_scan).pack(fill="x", padx=10, pady=10)

        # Results
        right = ctk.CTkFrame(main, fg_color="transparent")
        right.grid(row=0, column=1, sticky="nsew", padx=(3, 5), pady=5)

        ctk.CTkLabel(right, text="Scan Findings", font=("Inter", 13, "bold"),
                     text_color=COLORS["text"]).pack(anchor="w", padx=5)

        self.scan_findings_frame = ctk.CTkScrollableFrame(right, fg_color=COLORS["bg"],
                                                           corner_radius=8)
        self.scan_findings_frame.pack(fill="both", expand=True, pady=5)

    def _run_scan(self):
        url = self.scan_url.get().strip()
        if not url:
            self.terminal.log("Enter a target URL to scan", "error")
            return
        try:
            params_str = self.scan_params.get().strip()
            params = json.loads(params_str) if params_str else {}
        except json.JSONDecodeError:
            self.terminal.log("Invalid JSON params. Example: {\"id\":\"1\"}", "error")
            return

        # Clear previous findings
        for w in self.scan_findings_frame.winfo_children():
            w.destroy()
        self.terminal.log(f"Starting vulnerability scan on: {url}", "warning")
        threading.Thread(target=self._do_scan, args=(url, params), daemon=True).start()

    def _do_scan(self, url: str, params: dict):
        checks = self.scan_checks
        total_findings = []

        def on_finding(f):
            total_findings.append(f)
            self.after(0, lambda fv=f: self._render_scan_finding(fv))
            self.terminal.log(f"[{f['severity']}] {f['type']} found at {f['url']}", "error")
            if self.current_session_id:
                add_finding(
                    self.current_session_id,
                    vuln_type=f["type"], severity=f["severity"],
                    title=f["type"], description=f.get("evidence", ""),
                    url=f["url"], parameter=f.get("parameter", ""),
                    payload=f.get("payload", ""), evidence=f.get("evidence", ""),
                    cvss_score=f.get("cvss", 0.0)
                )

        if checks["SQL Injection"].get():
            self.terminal.log("Testing: SQL Injection (error-based)...", "info")
            test_sqli(url, params, callback=on_finding)

        if checks["Time-Based SQLi"].get():
            self.terminal.log("Testing: SQL Injection (time-based)...", "info")
            test_sqli_time_based(url, params, callback=on_finding)

        if checks["XSS"].get():
            self.terminal.log("Testing: Cross-Site Scripting...", "info")
            test_xss(url, params, callback=on_finding)

        if checks["SSRF"].get():
            self.terminal.log("Testing: Server-Side Request Forgery...", "info")
            test_ssrf(url, params, callback=on_finding)

        if checks["LFI"].get():
            self.terminal.log("Testing: Local File Inclusion...", "info")
            test_lfi(url, params, callback=on_finding)

        if checks["Open Redirect"].get():
            self.terminal.log("Testing: Open Redirect...", "info")
            test_open_redirect(url, params, callback=on_finding)

        if checks["SSTI"].get():
            self.terminal.log("Testing: Server-Side Template Injection...", "info")
            test_ssti(url, params, callback=on_finding)

        if checks["Directory Fuzzing"].get():
            self.terminal.log("Testing: Directory Fuzzing...", "info")
            dir_fuzz(url, callback=lambda r: (
                self.terminal.log(f"[{r['status']}] {r['url']}", "success" if r["status"] == 200 else "muted")
                if r.get("interesting") else None
            ))

        count = len(total_findings)
        self.terminal.log(f"Scan complete. {count} finding{'s' if count != 1 else ''} detected.", "success" if count == 0 else "warning")

    def _render_scan_finding(self, f: dict):
        sev = f.get("severity", "INFO")
        color = SEVERITY_COLORS.get(sev, COLORS["accent"])
        ResultCard(
            self.scan_findings_frame,
            title=f.get("type", "Unknown"),
            subtitle=f"Param: {f.get('parameter', 'N/A')} | Payload: {f.get('payload', '')[:50]}",
            badge=sev,
            badge_color=color,
            on_click=lambda fv=f: self._ai_explain_finding(fv)
        ).pack(fill="x", pady=2, padx=5)

    def _ai_explain_finding(self, finding: dict):
        self.tabview.set("🤖 AI Chat")
        prompt = f"Explain this {finding['type']} vulnerability I found:\n\nURL: {finding['url']}\nParameter: {finding.get('parameter', 'N/A')}\nPayload: {finding.get('payload', 'N/A')}\nEvidence: {finding.get('evidence', 'N/A')}"
        self.ai_input.delete("1.0", "end")
        self.ai_input.insert("end", prompt)

    # ── Payload Lab ───────────────────────────────────────────────────────────
    def _build_payload_tab(self):
        tab = self.tabview.tab("💥 Payload Lab")
        main = ctk.CTkFrame(tab, fg_color="transparent")
        main.pack(fill="both", expand=True)
        main.columnconfigure(0, weight=1)
        main.columnconfigure(1, weight=2)
        main.rowconfigure(0, weight=1)

        # Controls
        left = ctk.CTkFrame(main, fg_color=COLORS["surface2"], corner_radius=10, width=280)
        left.grid(row=0, column=0, sticky="nsew", padx=(5, 3), pady=5)
        left.pack_propagate(False)

        ctk.CTkLabel(left, text="Payload Lab", font=("Inter", 13, "bold"),
                     text_color=COLORS["text"]).pack(anchor="w", padx=10, pady=(10, 5))

        ctk.CTkLabel(left, text="Category:", font=("Inter", 11),
                     text_color=COLORS["muted"]).pack(anchor="w", padx=10)
        self.payload_category = ctk.CTkOptionMenu(
            left,
            values=["xss", "sqli", "ssrf", "lfi", "ssti", "xxe", "open_redirect"],
            font=("Inter", 12),
            fg_color=COLORS["surface"], button_color=COLORS["accent"],
            command=self._load_payloads
        )
        self.payload_category.pack(fill="x", padx=10, pady=5)

        ctk.CTkLabel(left, text="Subcategory:", font=("Inter", 11),
                     text_color=COLORS["muted"]).pack(anchor="w", padx=10)
        self.payload_sub = ctk.CTkOptionMenu(
            left,
            values=["basic", "waf_bypass", "dom", "polyglot", "union_based",
                    "time_based", "error_based", "bypass", "cloud_metadata",
                    "linux", "windows", "detection", "jinja2_rce", "twig_rce"],
            font=("Inter", 12),
            fg_color=COLORS["surface"], button_color=COLORS["accent"],
            command=lambda _: self._load_payloads(self.payload_category.get())
        )
        self.payload_sub.pack(fill="x", padx=10, pady=5)

        ctk.CTkButton(left, text="📋 Load Payloads", font=("Inter", 12),
                      fg_color=COLORS["accent"],
                      command=lambda: self._load_payloads(self.payload_category.get())).pack(
            fill="x", padx=10, pady=5)

        # Encoding
        ctk.CTkLabel(left, text="Encode Payload:", font=("Inter", 11, "bold"),
                     text_color=COLORS["text"]).pack(anchor="w", padx=10, pady=(15, 5))

        self.encode_input = ctk.CTkEntry(left, placeholder_text="Paste payload to encode...",
                                          font=("JetBrains Mono", 11),
                                          fg_color=COLORS["surface"], border_color=COLORS["border"])
        self.encode_input.pack(fill="x", padx=10, pady=5)

        self.encode_type = ctk.CTkOptionMenu(
            left,
            values=["url", "url_full", "double_url", "base64", "html_ent"],
            font=("Inter", 12),
            fg_color=COLORS["surface"], button_color=COLORS["accent"]
        )
        self.encode_type.pack(fill="x", padx=10, pady=5)

        ctk.CTkButton(left, text="🔄 Encode", font=("Inter", 12),
                      fg_color=COLORS["surface2"], command=self._encode_payload).pack(
            fill="x", padx=10, pady=5)

        # Payload display
        right = ctk.CTkFrame(main, fg_color="transparent")
        right.grid(row=0, column=1, sticky="nsew", padx=(3, 5), pady=5)

        self.payload_output = ctk.CTkTextbox(
            right, font=("JetBrains Mono", 12),
            fg_color=COLORS["bg"], text_color=COLORS["text"],
            border_color=COLORS["border"], border_width=1
        )
        self.payload_output.pack(fill="both", expand=True)

    def _load_payloads(self, category: str):
        sub = self.payload_sub.get()
        payloads = get_payloads(category, sub)
        self.payload_output.configure(state="normal")
        self.payload_output.delete("1.0", "end")
        if isinstance(payloads, list):
            for p in payloads:
                self.payload_output.insert("end", p + "\n")
        elif isinstance(payloads, dict):
            for k, v in payloads.items():
                self.payload_output.insert("end", f"[{k}]\n{v}\n\n")
        else:
            self.payload_output.insert("end", str(payloads))
        self.payload_output.configure(state="disabled")
        self.terminal.log(f"Loaded {category}/{sub} payloads", "success")

    def _encode_payload(self):
        payload = self.encode_input.get()
        enc = self.encode_type.get()
        if payload:
            variants = get_bypass_variants(payload)
            self.payload_output.configure(state="normal")
            self.payload_output.delete("1.0", "end")
            for enc_name, enc_val in variants.items():
                self.payload_output.insert("end", f"[{enc_name}]\n{enc_val}\n\n")
            self.payload_output.configure(state="disabled")

    # ── AI Chat Tab ───────────────────────────────────────────────────────────
    def _build_ai_tab(self):
        tab = self.tabview.tab("🤖 AI Chat")
        main = ctk.CTkFrame(tab, fg_color="transparent")
        main.pack(fill="both", expand=True)

        # Chat display
        self.ai_chat_display = ctk.CTkTextbox(
            main, font=("Inter", 12),
            fg_color=COLORS["bg"], text_color=COLORS["text"],
            border_color=COLORS["border"], border_width=1,
            wrap="word"
        )
        self.ai_chat_display.pack(fill="both", expand=True, padx=5, pady=5)

        # Quick actions
        qa_frame = ctk.CTkFrame(main, fg_color=COLORS["surface2"], corner_radius=8)
        qa_frame.pack(fill="x", padx=5, pady=(0, 5))

        ctk.CTkLabel(qa_frame, text="Quick:", font=("Inter", 11),
                     text_color=COLORS["muted"]).pack(side="left", padx=10, pady=8)

        for label, prompt in [
            ("📋 Analyze Request", "Analyze this HTTP request for vulnerabilities:\n\nGET / HTTP/1.1\nHost: target.com\n"),
            ("🔍 OWASP Top 10", "Explain the OWASP Top 10 vulnerabilities and how to test for each one."),
            ("🎯 Recon Strategy", f"Give me a complete recon strategy for {self.current_target.get() or 'a web application target'}."),
            ("💰 Report Template", "Give me a professional bug bounty report template for a critical SQL injection finding."),
        ]:
            ctk.CTkButton(qa_frame, text=label, font=("Inter", 11),
                          fg_color=COLORS["surface"], hover_color=COLORS["border"],
                          command=lambda p=prompt: self._quick_ai(p)).pack(side="left", padx=3, pady=5)

        # Input
        input_frame = ctk.CTkFrame(main, fg_color="transparent")
        input_frame.pack(fill="x", padx=5, pady=(0, 5))

        self.ai_input = ctk.CTkTextbox(input_frame, height=80, font=("Inter", 12),
                                        fg_color=COLORS["surface"], text_color=COLORS["text"],
                                        border_color=COLORS["border"], border_width=1)
        self.ai_input.pack(side="left", fill="both", expand=True, padx=(0, 5))

        btn_frame = ctk.CTkFrame(input_frame, fg_color="transparent")
        btn_frame.pack(side="right")

        ctk.CTkButton(btn_frame, text="Send\n(Enter)", font=("Inter", 12, "bold"),
                      fg_color=COLORS["accent"], width=80,
                      command=self._send_ai_message).pack(pady=2)
        ctk.CTkButton(btn_frame, text="Clear", font=("Inter", 11),
                      fg_color=COLORS["surface2"], width=80,
                      command=self._clear_ai_chat).pack(pady=2)

        # Provider indicator
        prov = config.get("ai_provider", "ollama")
        ctk.CTkLabel(main, text=f"AI Provider: {prov.upper()} — Change in Settings",
                     font=("Inter", 10), text_color=COLORS["muted"]).pack(pady=2)

        self._ai_chat_append("🤖 **BugHunter AI** — Ask me anything about security, paste HTTP requests for analysis, or ask me to explain vulnerabilities.\n\n")

    def _quick_ai(self, prompt: str):
        self.ai_input.delete("1.0", "end")
        self.ai_input.insert("end", prompt)
        self._send_ai_message()

    def _send_ai_message(self):
        message = self.ai_input.get("1.0", "end").strip()
        if not message:
            return
        self.ai_input.delete("1.0", "end")
        self._ai_chat_append(f"\n👤 **You:** {message}\n\n")
        self._ai_chat_append("🤖 **AI:** ")
        self.ai_history.append({"role": "user", "content": message})
        threading.Thread(target=self._do_ai_chat, args=(message,), daemon=True).start()

    def _do_ai_chat(self, message: str):
        def stream_token(token: str):
            self.after(0, lambda t=token: self._ai_chat_append(t))

        response = chat(message, self.ai_history, stream_callback=stream_token)
        self.ai_history.append({"role": "assistant", "content": response})

        # If no streaming happened (gemini/openai), append all at once
        if not config.get("ai_provider", "ollama") == "ollama":
            self.after(0, lambda r=response: self._ai_chat_append(r))

        self.after(0, lambda: self._ai_chat_append("\n\n"))

    def _ai_chat_append(self, text: str):
        self.ai_chat_display.configure(state="normal")
        self.ai_chat_display.insert("end", text)
        self.ai_chat_display.see("end")
        self.ai_chat_display.configure(state="disabled")

    def _clear_ai_chat(self):
        self.ai_chat_display.configure(state="normal")
        self.ai_chat_display.delete("1.0", "end")
        self.ai_chat_display.configure(state="disabled")
        self.ai_history = []
        self._ai_chat_append("🤖 **BugHunter AI** — Chat cleared. Ready for a new session.\n\n")

    # ── Reports Tab ───────────────────────────────────────────────────────────
    def _build_reports_tab(self):
        tab = self.tabview.tab("📄 Reports")
        main = ctk.CTkFrame(tab, fg_color="transparent")
        main.pack(fill="both", expand=True)

        top = ctk.CTkFrame(main, fg_color=COLORS["surface2"], corner_radius=8, height=60)
        top.pack(fill="x", padx=5, pady=5)
        top.pack_propagate(False)

        ctk.CTkLabel(top, text="Report Builder", font=("Inter", 13, "bold"),
                     text_color=COLORS["text"]).pack(side="left", padx=15, pady=15)

        ctk.CTkButton(top, text="📊 Generate Report", font=("Inter", 12, "bold"),
                      fg_color=COLORS["accent"], command=self._generate_report).pack(
            side="right", padx=10, pady=10)

        ctk.CTkButton(top, text="🤖 AI Polish Report", font=("Inter", 12),
                      fg_color=COLORS["surface"], hover_color=COLORS["border"],
                      command=self._ai_polish_report).pack(side="right", padx=5, pady=10)

        self.report_preview = ctk.CTkTextbox(
            main, font=("JetBrains Mono", 11),
            fg_color=COLORS["bg"], text_color=COLORS["text"],
            border_color=COLORS["border"], border_width=1
        )
        self.report_preview.pack(fill="both", expand=True, padx=5, pady=5)

    def _generate_report(self):
        if not self.current_session_id:
            self.report_preview.configure(state="normal")
            self.report_preview.delete("1.0", "end")
            self.report_preview.insert("end", "⚠️ No active session. Start a session and run scans first.")
            self.report_preview.configure(state="disabled")
            return

        findings = get_findings(self.current_session_id)
        target = self.current_target.get() or "Unknown Target"

        from modules.reporter import generate_markdown, export_report
        md = generate_markdown(findings, target)

        self.report_preview.configure(state="normal")
        self.report_preview.delete("1.0", "end")
        self.report_preview.insert("end", md)
        self.report_preview.configure(state="disabled")

        # Auto-export
        output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
        paths = export_report(findings, target, output_dir)
        self.terminal.log(f"Report exported: {paths['html']}", "success")
        webbrowser.open(f"file:///{paths['html'].replace(chr(92), '/')}")

    def _ai_polish_report(self):
        if not self.current_session_id:
            return
        findings = get_findings(self.current_session_id)
        target = self.current_target.get() or "Unknown Target"
        self.terminal.log("Asking AI to polish the report...", "info")
        threading.Thread(target=lambda: self._do_ai_report(findings, target), daemon=True).start()

    def _do_ai_report(self, findings, target):
        from modules.ai_engine.engine import generate_report_text
        result = generate_report_text(findings, target)
        self.after(0, lambda: (
            self.report_preview.configure(state="normal"),
            self.report_preview.delete("1.0", "end"),
            self.report_preview.insert("end", result),
            self.report_preview.configure(state="disabled")
        ))

    # ── Settings Dialog ────────────────────────────────────────────────────────
    def _open_settings(self):
        dialog = ctk.CTkToplevel(self)
        dialog.title("⚙ Settings")
        dialog.geometry("500x620")
        dialog.configure(fg_color=COLORS["bg"])
        dialog.grab_set()

        scroll = ctk.CTkScrollableFrame(dialog, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(scroll, text="⚙ BugHunter AI Settings", font=("Inter", 15, "bold"),
                     text_color=COLORS["text"]).pack(anchor="w", pady=(0, 15))

        def add_section(title: str):
            ctk.CTkLabel(scroll, text=title, font=("Inter", 12, "bold"),
                         text_color=COLORS["accent"]).pack(anchor="w", pady=(10, 3))

        def add_field(label: str, key: str, placeholder: str = "", is_password: bool = False):
            ctk.CTkLabel(scroll, text=label, font=("Inter", 11),
                         text_color=COLORS["muted"]).pack(anchor="w")
            entry = ctk.CTkEntry(scroll, font=("JetBrains Mono", 11), show="*" if is_password else "",
                                  placeholder_text=placeholder,
                                  fg_color=COLORS["surface"], border_color=COLORS["border"])
            entry.pack(fill="x", pady=(2, 8))
            if config.get(key):
                entry.insert(0, config[key])
            return entry

        add_section("🤖 AI Provider")
        ai_provider = ctk.CTkOptionMenu(scroll, values=["ollama", "gemini", "openai"],
                                         font=("Inter", 12), fg_color=COLORS["surface"],
                                         button_color=COLORS["accent"])
        ai_provider.set(config.get("ai_provider", "ollama"))
        ai_provider.pack(fill="x", pady=5)

        ctk.CTkLabel(scroll, text="Ollama Model:", font=("Inter", 11),
                     text_color=COLORS["muted"]).pack(anchor="w")
        ollama_model = ctk.CTkEntry(scroll, font=("JetBrains Mono", 11),
                                     placeholder_text="llama3.2 | mistral | codellama",
                                     fg_color=COLORS["surface"], border_color=COLORS["border"])
        ollama_model.insert(0, config.get("ollama_model", "llama3.2"))
        ollama_model.pack(fill="x", pady=(2, 8))

        gemini_key = add_field("Gemini API Key (free at aistudio.google.com):", "gemini_api_key",
                                "AIza...", is_password=True)

        add_section("🔑 Free API Keys (Optional Enhancements)")
        github_token = add_field("GitHub Token (free — 5000 req/hr):", "github_token",
                                  "ghp_...", is_password=True)
        vt_key = add_field("VirusTotal API Key (free tier):", "virustotal_key",
                            "...", is_password=True)

        add_section("⚙ Scanner Settings")
        ctk.CTkLabel(scroll, text="Request Timeout (seconds):", font=("Inter", 11),
                     text_color=COLORS["muted"]).pack(anchor="w")
        timeout_entry = ctk.CTkEntry(scroll, font=("JetBrains Mono", 11),
                                      fg_color=COLORS["surface"], border_color=COLORS["border"])
        timeout_entry.insert(0, str(config.get("timeout", 10)))
        timeout_entry.pack(fill="x", pady=(2, 8))

        def save_settings():
            config["ai_provider"] = ai_provider.get()
            config["ollama_model"] = ollama_model.get()
            if gemini_key.get():
                config["gemini_api_key"] = gemini_key.get()
            if github_token.get():
                config["github_token"] = github_token.get()
            if vt_key.get():
                config["virustotal_key"] = vt_key.get()
            try:
                config["timeout"] = int(timeout_entry.get())
            except Exception:
                pass
            save_config(config)
            self.terminal.log("Settings saved!", "success")
            dialog.destroy()

        ctk.CTkButton(scroll, text="💾 Save Settings", font=("Inter", 12, "bold"),
                      fg_color=COLORS["accent"], command=save_settings).pack(fill="x", pady=15)

    # ── Core Actions ──────────────────────────────────────────────────────────
    def _start_session(self):
        target = self.current_target.get().strip()
        if not target:
            self.terminal.log("Enter a target URL to start a session", "error")
            return
        session_id = new_session(target)
        self.current_session_id = session_id
        self.session_label.configure(text=f"Session #{session_id}: {target[:30]}",
                                      text_color=COLORS["green"])
        self.terminal.log(f"New session #{session_id} started for: {target}", "success")
        self._update_sessions_list()

    def _export_report(self):
        self.tabview.set("📄 Reports")
        self._generate_report()

    def _check_ollama_async(self):
        threading.Thread(target=self._check_ollama, daemon=True).start()

    def _check_ollama(self):
        status = check_ollama_status()
        if status["running"]:
            models = ", ".join(status["models"][:3]) or "none"
            self.after(0, lambda: self.ollama_indicator.configure(
                text=f"● AI: Ollama ✓ ({models})", text_color=COLORS["green"]))
            self.terminal.log(f"Ollama running — models: {models}", "success")
        else:
            prov = config.get("ai_provider", "ollama")
            if prov == "gemini" and config.get("gemini_api_key"):
                self.after(0, lambda: self.ollama_indicator.configure(
                    text="● AI: Gemini ✓", text_color=COLORS["green"]))
            else:
                self.after(0, lambda: self.ollama_indicator.configure(
                    text="● AI: Offline ⚠", text_color=COLORS["yellow"]))
                self.terminal.log("Ollama not detected. Install from ollama.ai or set Gemini key.", "warning")
