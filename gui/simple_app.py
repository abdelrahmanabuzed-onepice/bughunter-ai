"""
BugHunter AI — Simple One-Click Interface
Just type a domain and press HUNT. Everything is automatic.
"""

import customtkinter as ctk
import threading
import webbrowser
import os, sys, time, subprocess

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import config, save_config
from modules.pipeline import HuntPipeline, PHASES
from modules.ai_engine.engine import check_ollama_status, chat

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

C = {
    "bg":       "#080B10",
    "surface":  "#0E1117",
    "card":     "#131920",
    "border":   "#1E2A38",
    "accent":   "#3B82F6",
    "green":    "#10B981",
    "red":      "#EF4444",
    "orange":   "#F97316",
    "yellow":   "#EAB308",
    "purple":   "#8B5CF6",
    "text":     "#F1F5F9",
    "muted":    "#64748B",
    "dim":      "#1E293B",
}

SEV_COLOR = {
    "CRITICAL": "#EF4444",
    "HIGH":     "#F97316",
    "MEDIUM":   "#EAB308",
    "LOW":      "#10B981",
    "INFO":     "#3B82F6",
}

PHASE_STATUS = {
    "pending": ("○", C["muted"]),
    "running": ("◉", C["accent"]),
    "done":    ("✓", C["green"]),
    "error":   ("✗", C["red"]),
}


class BugHunterSimple(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("BugHunter AI")
        self.geometry("1300x860")
        self.minsize(1000, 650)
        self.configure(fg_color=C["bg"])

        self.pipeline = None
        self.hunt_thread = None
        self.is_hunting = False
        self.current_report = None
        self.phase_labels = {}
        self.finding_count = 0
        self.output_base = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "reports"
        )

        self._build_ui()
        self._check_ai_status()

    # ── UI Construction ────────────────────────────────────────────────────────

    def _build_ui(self):
        # ─ Top Bar ─
        topbar = ctk.CTkFrame(self, fg_color=C["surface"], height=70, corner_radius=0,
                               border_color=C["border"], border_width=0)
        topbar.pack(fill="x")
        topbar.pack_propagate(False)

        # Gradient accent line at top
        accent_line = ctk.CTkFrame(topbar, fg_color=C["accent"], height=3, corner_radius=0)
        accent_line.pack(fill="x", side="top")

        inner_top = ctk.CTkFrame(topbar, fg_color="transparent")
        inner_top.pack(fill="both", expand=True, padx=20)

        # Logo
        ctk.CTkLabel(inner_top, text="🐛  BugHunter AI",
                     font=("Inter", 20, "bold"), text_color=C["text"]).pack(side="left", pady=15)

        # AI status badge
        self.ai_badge = ctk.CTkLabel(
            inner_top, text="  ● AI: Checking...  ",
            font=("Inter", 11, "bold"), text_color=C["muted"],
            fg_color=C["dim"], corner_radius=20
        )
        self.ai_badge.pack(side="left", padx=20, pady=15)

        # Settings button
        ctk.CTkButton(inner_top, text="⚙  Settings", font=("Inter", 12),
                      fg_color=C["card"], hover_color=C["border"],
                      border_color=C["border"], border_width=1,
                      command=self._open_settings, width=110).pack(side="right", pady=15)

        # ─ Target Input Bar ─
        input_frame = ctk.CTkFrame(self, fg_color=C["surface"],
                                    border_color=C["border"], border_width=1,
                                    corner_radius=0)
        input_frame.pack(fill="x", padx=0, pady=0)

        input_inner = ctk.CTkFrame(input_frame, fg_color="transparent")
        input_inner.pack(fill="x", padx=25, pady=15)

        ctk.CTkLabel(input_inner, text="TARGET", font=("Inter", 10, "bold"),
                     text_color=C["muted"]).pack(side="left", padx=(0, 10))

        self.target_var = ctk.StringVar()
        self.target_entry = ctk.CTkEntry(
            input_inner,
            textvariable=self.target_var,
            placeholder_text="example.com  or  https://app.example.com",
            font=("JetBrains Mono", 14),
            fg_color=C["card"],
            border_color=C["border"],
            text_color=C["text"],
            height=44,
        )
        self.target_entry.pack(side="left", fill="x", expand=True, padx=(0, 12))
        self.target_entry.bind("<Return>", lambda e: self._toggle_hunt())

        self.hunt_btn = ctk.CTkButton(
            input_inner,
            text="  🎯  START HUNT  ",
            font=("Inter", 14, "bold"),
            fg_color=C["accent"],
            hover_color="#2563EB",
            height=44,
            width=180,
            corner_radius=10,
            command=self._toggle_hunt,
        )
        self.hunt_btn.pack(side="left")

        # Platform Export Buttons (HackerOne, Bugcrowd, Intigriti)
        self.h1_btn = ctk.CTkButton(
            input_inner,
            text="🔴 HackerOne Report",
            font=("Inter", 12, "bold"),
            fg_color="#D32F2F", hover_color="#B71C1C",
            height=44, width=150, corner_radius=10,
            command=lambda: self._open_platform_folder("hackerone")
        )

        self.bugcrowd_btn = ctk.CTkButton(
            input_inner,
            text="🟠 Bugcrowd Report",
            font=("Inter", 12, "bold"),
            fg_color="#E65100", hover_color="#BF360C",
            height=44, width=150, corner_radius=10,
            command=lambda: self._open_platform_folder("bugcrowd")
        )

        self.intigriti_btn = ctk.CTkButton(
            input_inner,
            text="🔵 Intigriti Report",
            font=("Inter", 12, "bold"),
            fg_color="#1976D2", hover_color="#0D47A1",
            height=44, width=140, corner_radius=10,
            command=lambda: self._open_platform_folder("intigriti")
        )

        self.report_btn = ctk.CTkButton(
            input_inner,
            text="📄  HTML Report",
            font=("Inter", 12, "bold"),
            fg_color=C["green"], hover_color="#059669",
            height=44, width=130, corner_radius=10,
            command=self._open_report,
        )

        # ─ Main Content ─
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=12, pady=10)
        content.columnconfigure(0, weight=0)   # phases panel
        content.columnconfigure(1, weight=1)   # findings
        content.columnconfigure(2, weight=1)   # terminal
        content.rowconfigure(0, weight=1)

        # Left: Phases Panel
        self._build_phases_panel(content)

        # Middle: Findings
        self._build_findings_panel(content)

        # Right: Live Terminal
        self._build_terminal_panel(content)

        # ─ Bottom Status Bar ─
        self._build_statusbar()

    def _build_phases_panel(self, parent):
        frame = ctk.CTkFrame(parent, fg_color=C["surface"],
                              corner_radius=12, border_color=C["border"],
                              border_width=1, width=240)
        frame.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        frame.pack_propagate(False)

        ctk.CTkLabel(frame, text="SCAN PHASES",
                     font=("Inter", 10, "bold"), text_color=C["muted"]).pack(
            anchor="w", padx=18, pady=(18, 8))

        for phase in PHASES:
            row = ctk.CTkFrame(frame, fg_color="transparent")
            row.pack(fill="x", padx=12, pady=3)

            icon_lbl = ctk.CTkLabel(row, text=phase["icon"],
                                     font=("Inter", 16), width=30)
            icon_lbl.pack(side="left")

            text_col = ctk.CTkFrame(row, fg_color="transparent")
            text_col.pack(side="left", fill="x", expand=True, padx=8)

            name_lbl = ctk.CTkLabel(text_col, text=phase["name"],
                                     font=("Inter", 12), text_color=C["text"],
                                     anchor="w")
            name_lbl.pack(fill="x")

            status_lbl = ctk.CTkLabel(text_col, text="● Pending",
                                       font=("Inter", 10), text_color=C["muted"],
                                       anchor="w")
            status_lbl.pack(fill="x")

            self.phase_labels[phase["id"]] = {
                "status": status_lbl,
                "icon": icon_lbl,
                "row": row,
            }

        # Spacer + Stats
        ctk.CTkFrame(frame, fg_color=C["border"], height=1).pack(fill="x", padx=12, pady=15)

        ctk.CTkLabel(frame, text="RESULTS", font=("Inter", 10, "bold"),
                     text_color=C["muted"]).pack(anchor="w", padx=18, pady=(0, 8))

        self.stats_frame = ctk.CTkFrame(frame, fg_color="transparent")
        self.stats_frame.pack(fill="x", padx=12)

        self.stat_labels = {}
        for sev, color in [("CRITICAL", C["red"]), ("HIGH", C["orange"]),
                            ("MEDIUM", C["yellow"]), ("LOW", C["green"])]:
            row = ctk.CTkFrame(self.stats_frame, fg_color="transparent")
            row.pack(fill="x", pady=2)
            ctk.CTkLabel(row, text=sev, font=("Inter", 10, "bold"),
                         text_color=color, width=80, anchor="w").pack(side="left")
            lbl = ctk.CTkLabel(row, text="0", font=("Inter", 14, "bold"),
                               text_color=color)
            lbl.pack(side="right", padx=8)
            self.stat_labels[sev] = lbl

        # Output folder button
        self.folder_btn = ctk.CTkButton(
            frame, text="📁  Open Folder",
            font=("Inter", 11),
            fg_color=C["card"], hover_color=C["border"],
            border_color=C["border"], border_width=1,
            command=self._open_folder, state="disabled"
        )
        self.folder_btn.pack(fill="x", padx=12, pady=15)

    def _build_findings_panel(self, parent):
        frame = ctk.CTkFrame(parent, fg_color=C["surface"],
                              corner_radius=12, border_color=C["border"], border_width=1)
        frame.grid(row=0, column=1, sticky="nsew", padx=(0, 8))

        header = ctk.CTkFrame(frame, fg_color="transparent")
        header.pack(fill="x", padx=15, pady=(15, 8))

        ctk.CTkLabel(header, text="FINDINGS",
                     font=("Inter", 10, "bold"), text_color=C["muted"]).pack(side="left")

        self.findings_count_lbl = ctk.CTkLabel(
            header, text="0 vulnerabilities",
            font=("Inter", 11), text_color=C["muted"]
        )
        self.findings_count_lbl.pack(side="right")

        self.findings_scroll = ctk.CTkScrollableFrame(
            frame, fg_color="transparent", corner_radius=0
        )
        self.findings_scroll.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        # Placeholder
        self.findings_placeholder = ctk.CTkLabel(
            self.findings_scroll,
            text="🎯\n\nEnter a domain and\npress START HUNT\n\nFindings will appear here\nas they are discovered.",
            font=("Inter", 13),
            text_color=C["muted"],
            justify="center"
        )
        self.findings_placeholder.pack(expand=True, pady=60)

    def _build_terminal_panel(self, parent):
        frame = ctk.CTkFrame(parent, fg_color=C["surface"],
                              corner_radius=12, border_color=C["border"], border_width=1)
        frame.grid(row=0, column=2, sticky="nsew")

        header = ctk.CTkFrame(frame, fg_color="transparent")
        header.pack(fill="x", padx=15, pady=(15, 8))

        ctk.CTkLabel(header, text="LIVE OUTPUT",
                     font=("Inter", 10, "bold"), text_color=C["muted"]).pack(side="left")
        ctk.CTkButton(header, text="Clear", font=("Inter", 10),
                      fg_color="transparent", hover_color=C["border"],
                      text_color=C["muted"], width=50,
                      command=self._clear_terminal).pack(side="right")

        self.terminal = ctk.CTkTextbox(
            frame,
            font=("JetBrains Mono", 11),
            fg_color=C["card"],
            text_color=C["text"],
            border_color=C["border"],
            border_width=1,
            wrap="word",
            state="disabled"
        )
        self.terminal.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        # Tag colors
        self.terminal.tag_config("success", foreground=C["green"])
        self.terminal.tag_config("error",   foreground=C["red"])
        self.terminal.tag_config("warning", foreground=C["yellow"])
        self.terminal.tag_config("info",    foreground=C["accent"])
        self.terminal.tag_config("muted",   foreground=C["muted"])

    def _build_statusbar(self):
        bar = ctk.CTkFrame(self, fg_color=C["surface"], height=32, corner_radius=0,
                            border_color=C["border"], border_width=0)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)

        ctk.CTkFrame(bar, fg_color=C["border"], height=1).pack(fill="x", side="top")

        inner = ctk.CTkFrame(bar, fg_color="transparent")
        inner.pack(fill="x", padx=20)

        self.status_lbl = ctk.CTkLabel(
            inner, text="Ready — Enter a domain to begin hunting",
            font=("Inter", 11), text_color=C["muted"]
        )
        self.status_lbl.pack(side="left", pady=6)

        self.elapsed_lbl = ctk.CTkLabel(
            inner, text="", font=("Inter", 11), text_color=C["muted"]
        )
        self.elapsed_lbl.pack(side="right", pady=6)

    # ── Hunt Control ───────────────────────────────────────────────────────────

    def _toggle_hunt(self):
        if self.is_hunting:
            self._stop_hunt()
        else:
            self._start_hunt()

    def _start_hunt(self):
        target = self.target_var.get().strip()
        if not target:
            self._flash_entry()
            return

        # Reset UI
        self._reset_ui()
        self.is_hunting = True
        self.hunt_btn.configure(text="  ⬛  STOP HUNT  ", fg_color=C["red"],
                                 hover_color="#B91C1C")
        self.report_btn.pack_forget()
        self.finding_count = 0
        self.hunt_start = time.time()
        self._start_timer()

        # Hide placeholder
        self.findings_placeholder.pack_forget()

        self.log(f"Starting hunt on: {target}", "info")

        self.pipeline = HuntPipeline(
            target=target,
            output_dir=self.output_base,
            on_phase=self._on_phase,
            on_log=self._on_log,
            on_finding=self._on_finding,
            on_done=self._on_done,
        )

        self.hunt_thread = threading.Thread(target=self.pipeline.start, daemon=True)
        self.hunt_thread.start()

    def _stop_hunt(self):
        if self.pipeline:
            self.pipeline.stop()
        self.is_hunting = False
        self.hunt_btn.configure(text="  🎯  START HUNT  ", fg_color=C["accent"],
                                 hover_color="#2563EB")
        self.log("Hunt stopped by user.", "warning")
        self._set_status("Stopped.")

    def _reset_ui(self):
        # Reset phase indicators
        for pid, widgets in self.phase_labels.items():
            widgets["status"].configure(text="● Pending", text_color=C["muted"])
        # Reset stats
        for lbl in self.stat_labels.values():
            lbl.configure(text="0")
        # Clear findings
        for w in self.findings_scroll.winfo_children():
            w.destroy()
        self.findings_count_lbl.configure(text="0 vulnerabilities")
        self.folder_btn.configure(state="disabled")
        self.current_report = None

    def _flash_entry(self):
        self.target_entry.configure(border_color=C["red"])
        self.after(1000, lambda: self.target_entry.configure(border_color=C["border"]))

    # ── Pipeline Callbacks ────────────────────────────────────────────────────

    def _on_phase(self, phase_id: str, status: str):
        """Called from pipeline thread — update phase UI safely."""
        def update():
            widgets = self.phase_labels.get(phase_id)
            if not widgets:
                return
            sym, color = PHASE_STATUS.get(status, ("●", C["muted"]))
            text = {"pending": "Pending", "running": "Running...",
                    "done": "Complete", "error": "Error"}.get(status, status)
            widgets["status"].configure(text=f"{sym} {text}", text_color=color)

            phase_name = next((p["name"] for p in PHASES if p["id"] == phase_id), phase_id)
            if status == "running":
                self._set_status(f"{phase_name}...")
            elif status == "done":
                self._set_status(f"{phase_name} — Done")
        self.after(0, update)

    def _on_log(self, message: str, level: str = "info"):
        """Called from pipeline thread — log to terminal safely."""
        self.after(0, lambda: self.log(message, level))

    def _on_finding(self, finding: dict):
        """Called from pipeline thread — add finding card safely."""
        self.after(0, lambda: self._add_finding_card(finding))

    def _on_done(self, report_paths: dict):
        """Called when pipeline completes."""
        def finish():
            self.is_hunting = False
            self.current_report = report_paths
            self.hunt_btn.configure(text="  🎯  START HUNT  ", fg_color=C["accent"],
                                     hover_color="#2563EB")
            self.folder_btn.configure(state="normal")
            self.report_btn.pack(side="left", padx=(10, 0))
            self.h1_btn.pack(side="left", padx=(5, 0))
            self.bugcrowd_btn.pack(side="left", padx=(5, 0))
            self.intigriti_btn.pack(side="left", padx=(5, 0))

            summary = report_paths.get("summary", {})
            elapsed = int(time.time() - self.hunt_start)
            self.elapsed_lbl.configure(
                text=f"Completed in {elapsed//60}m {elapsed%60}s"
            )

            count = summary.get("total_findings", 0)
            self._set_status(
                f"Hunt complete! {count} findings | {summary.get('critical',0)} CRITICAL | {summary.get('high',0)} HIGH"
            )

            self.log(f"Hunt complete! Report: {report_paths.get('html','')}", "success")
            if report_paths.get("html"):
                webbrowser.open(f"file:///{report_paths['html'].replace(os.sep, '/')}")

        self.after(0, finish)

    def _open_platform_folder(self, platform_name: str):
        if self.current_report and self.current_report.get("dir"):
            target_folder = os.path.join(self.current_report["dir"], platform_name)
            if os.path.exists(target_folder):
                os.startfile(target_folder)
            else:
                os.startfile(self.current_report["dir"])

    # ── UI Updates ─────────────────────────────────────────────────────────────

    def _add_finding_card(self, finding: dict):
        sev = finding.get("severity", "INFO")
        color = SEV_COLOR.get(sev, C["accent"])

        if finding.get("ai_generated"):
            return  # AI analysis shown separately

        card = ctk.CTkFrame(self.findings_scroll, fg_color=C["card"],
                             corner_radius=8, border_color=color, border_width=1)
        card.pack(fill="x", pady=3, padx=2)

        top = ctk.CTkFrame(card, fg_color="transparent")
        top.pack(fill="x", padx=12, pady=(10, 4))

        # Severity badge
        ctk.CTkLabel(top, text=f" {sev} ",
                     font=("Inter", 9, "bold"),
                     fg_color=color, text_color="white",
                     corner_radius=4).pack(side="left")

        # CVSS score
        cvss = finding.get("cvss_score", finding.get("cvss", 0))
        if cvss:
            ctk.CTkLabel(top, text=f"CVSS {cvss}",
                         font=("Inter", 9), text_color=C["muted"]).pack(side="right")

        # Title
        ctk.CTkLabel(card, text=finding.get("title", finding.get("vuln_type", "Finding")),
                     font=("Inter", 12, "bold"), text_color=C["text"],
                     anchor="w", wraplength=350).pack(fill="x", padx=12, pady=(0, 3))

        # URL
        url = finding.get("url", "")
        if url:
            ctk.CTkLabel(card, text=url[:60] + ("..." if len(url) > 60 else ""),
                         font=("JetBrains Mono", 10), text_color=C["muted"],
                         anchor="w").pack(fill="x", padx=12, pady=(0, 8))

        # Update counters
        self.finding_count += 1
        self.findings_count_lbl.configure(
            text=f"{self.finding_count} vulnerabilit{'y' if self.finding_count == 1 else 'ies'}"
        )

        # Update severity stats
        cur = int(self.stat_labels.get(sev, ctk.CTkLabel(self, text="0")).cget("text") or "0")
        if sev in self.stat_labels:
            self.stat_labels[sev].configure(text=str(cur + 1))

    def log(self, message: str, level: str = "info"):
        ts = time.strftime("%H:%M:%S")
        icons = {"info": "ℹ", "success": "✓", "warning": "⚠", "error": "✗", "muted": "·"}
        icon = icons.get(level, "·")
        line = f"[{ts}] {icon}  {message}\n"
        self.terminal.configure(state="normal")
        self.terminal.insert("end", line, level)
        self.terminal.see("end")
        self.terminal.configure(state="disabled")

    def _clear_terminal(self):
        self.terminal.configure(state="normal")
        self.terminal.delete("1.0", "end")
        self.terminal.configure(state="disabled")

    def _set_status(self, text: str):
        self.status_lbl.configure(text=text)

    def _start_timer(self):
        def tick():
            if self.is_hunting and hasattr(self, "hunt_start"):
                elapsed = int(time.time() - self.hunt_start)
                self.elapsed_lbl.configure(text=f"Elapsed: {elapsed//60}m {elapsed%60}s")
                self.after(1000, tick)
        self.after(1000, tick)

    def _open_report(self):
        if self.current_report and self.current_report.get("html"):
            webbrowser.open(f"file:///{self.current_report['html'].replace(os.sep, '/')}")

    def _open_folder(self):
        if self.current_report and self.current_report.get("dir"):
            os.startfile(self.current_report["dir"])

    # ── AI Status ──────────────────────────────────────────────────────────────

    def _check_ai_status(self):
        def check():
            status = check_ollama_status()
            if status["running"]:
                models = status["models"]
                model = config.get("ollama_model", "qwen2.5:7b")
                self.after(0, lambda: self.ai_badge.configure(
                    text=f"  ● AI: {model}  ",
                    text_color=C["green"], fg_color="#052E16"
                ))
            else:
                self.after(0, lambda: self.ai_badge.configure(
                    text="  ● AI: Offline  ",
                    text_color=C["yellow"], fg_color="#422006"
                ))
        threading.Thread(target=check, daemon=True).start()

    # ── Settings ───────────────────────────────────────────────────────────────

    def _open_settings(self):
        dlg = ctk.CTkToplevel(self)
        dlg.title("Settings")
        dlg.geometry("480x500")
        dlg.configure(fg_color=C["bg"])
        dlg.grab_set()

        scroll = ctk.CTkScrollableFrame(dlg, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=24, pady=24)

        ctk.CTkLabel(scroll, text="⚙  Settings",
                     font=("Inter", 16, "bold"), text_color=C["text"]).pack(anchor="w", pady=(0, 20))

        def section(title):
            ctk.CTkLabel(scroll, text=title, font=("Inter", 11, "bold"),
                         text_color=C["accent"]).pack(anchor="w", pady=(12, 4))

        def field(label, key, placeholder="", password=False):
            ctk.CTkLabel(scroll, text=label, font=("Inter", 11),
                         text_color=C["muted"]).pack(anchor="w")
            e = ctk.CTkEntry(scroll, font=("JetBrains Mono", 11),
                              show="*" if password else "",
                              placeholder_text=placeholder,
                              fg_color=C["card"], border_color=C["border"],
                              height=38)
            e.pack(fill="x", pady=(2, 10))
            if config.get(key):
                e.insert(0, config[key])
            return e

        section("🤖 AI Model")
        ctk.CTkLabel(scroll, text="Ollama Model:", font=("Inter", 11),
                     text_color=C["muted"]).pack(anchor="w")
        model_var = ctk.StringVar(value=config.get("ollama_model", "qwen2.5:7b"))
        model_menu = ctk.CTkOptionMenu(
            scroll,
            variable=model_var,
            values=["qwen2.5:7b", "phi3:mini", "grok-agent:latest",
                    "grok-agent-fast:latest", "grok-agent-ultra:latest",
                    "tinyllama:latest", "llama3.2", "mistral", "codellama"],
            font=("Inter", 12), fg_color=C["card"], button_color=C["accent"]
        )
        model_menu.pack(fill="x", pady=(2, 10))

        gemini = field("Gemini API Key (free — aistudio.google.com):", "gemini_api_key",
                       "AIza...", password=True)

        section("🔑 API Keys & Platform Headers")
        h1_username = field("HackerOne Username (for X-Bug-Bounty header):", "hackerone_username",
                             "e.g. your_h1_username")
        github = field("GitHub Token (github.com/settings/tokens):", "github_token",
                       "ghp_...", password=True)

        section("⚙ Scan Settings")
        ctk.CTkLabel(scroll, text="Timeout (seconds):", font=("Inter", 11),
                     text_color=C["muted"]).pack(anchor="w")
        timeout_e = ctk.CTkEntry(scroll, font=("JetBrains Mono", 11),
                                  fg_color=C["card"], border_color=C["border"], height=38)
        timeout_e.pack(fill="x", pady=(2, 10))
        timeout_e.insert(0, str(config.get("timeout", 10)))

        def save():
            config["ollama_model"] = model_var.get()
            config["ai_provider"] = "ollama"
            if h1_username.get():
                config["hackerone_username"] = h1_username.get().strip()
                config["custom_headers"]["X-Bug-Bounty"] = f"HackerOne-{h1_username.get().strip()}"
            if gemini.get(): config["gemini_api_key"] = gemini.get()
            if github.get():  config["github_token"] = github.get()
            try: config["timeout"] = int(timeout_e.get())
            except: pass
            save_config(config)
            self.log("Settings saved!", "success")
            self._check_ai_status()
            dlg.destroy()

        ctk.CTkButton(scroll, text="💾  Save Settings",
                      font=("Inter", 13, "bold"), fg_color=C["accent"],
                      height=42, command=save).pack(fill="x", pady=16)
