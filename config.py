"""
BugHunter AI — Configuration & API Key Manager
All services used are FREE. Keys are optional enhancements.
"""

import json
import os

CONFIG_FILE = os.path.join(os.path.dirname(__file__), "config.json")

DEFAULTS = {
    # AI Settings
    "ai_provider": "ollama",          # ollama | gemini | openai
    "ollama_model": "qwen2.5:7b",      # Best available: 7.6B, tools support
    "ollama_url": "http://localhost:11434",
    "gemini_api_key": "",             # free at aistudio.google.com
    "openai_api_key": "",

    # Free API Keys (all have free tiers)
    "github_token": "",               # free at github.com/settings/tokens
    "virustotal_key": "",             # free at virustotal.com
    "urlscan_key": "",                # free at urlscan.io
    "abuseipdb_key": "",              # free at abuseipdb.com
    "greynoise_key": "",              # free at greynoise.io

    # Scanner Settings
    "threads": 10,
    "timeout": 10,
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "custom_headers": {},             # e.g. {"X-Bug-Bounty": "HackerOne-username"}
    "follow_redirects": True,
    "verify_ssl": False,

    # App Settings
    "theme": "dark",
    "font_size": 13,
}


def load_config() -> dict:
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            saved = json.load(f)
        return {**DEFAULTS, **saved}
    return DEFAULTS.copy()


def save_config(cfg: dict):
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)


# Global config instance
config = load_config()
