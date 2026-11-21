"""
GitHub Intelligence Module — 100% Free
Uses GitHub REST API (unauthenticated = 60 req/hr, with free token = 5000 req/hr)
Searches for CVE PoCs, exploit repos, and vulnerable code patterns.
"""

import requests
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from config import config

GH_API = "https://api.github.com"


def _headers() -> dict:
    h = {
        "Accept": "application/vnd.github+json",
        "User-Agent": config["user_agent"],
        "X-GitHub-Api-Version": "2022-11-28"
    }
    token = config.get("github_token", "")
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def search_cve_poc(cve_id: str) -> list[dict]:
    """Search GitHub for PoC repositories for a given CVE."""
    query = f"{cve_id} poc OR exploit OR vulnerability"
    return search_repos(query)


def search_repos(query: str, sort: str = "stars", per_page: int = 15) -> list[dict]:
    """Search GitHub repositories by query."""
    try:
        resp = requests.get(
            f"{GH_API}/search/repositories",
            headers=_headers(),
            params={"q": query, "sort": sort, "per_page": per_page},
            timeout=config["timeout"]
        )
        if resp.status_code == 200:
            items = resp.json().get("items", [])
            return [{
                "name": r["full_name"],
                "description": r.get("description") or "",
                "stars": r["stargazers_count"],
                "url": r["html_url"],
                "clone_url": r["clone_url"],
                "language": r.get("language") or "Unknown",
                "updated": r["updated_at"][:10],
                "topics": r.get("topics", []),
            } for r in items]
        elif resp.status_code == 403:
            return [{"error": "Rate limit hit. Add a free GitHub token in Settings to get 5000 req/hr."}]
        else:
            return [{"error": f"GitHub API error: HTTP {resp.status_code}"}]
    except Exception as e:
        return [{"error": str(e)}]


def search_code(query: str, language: str = "", per_page: int = 10) -> list[dict]:
    """Search GitHub code for vulnerable patterns, hardcoded secrets, etc."""
    q = query
    if language:
        q += f" language:{language}"
    try:
        resp = requests.get(
            f"{GH_API}/search/code",
            headers=_headers(),
            params={"q": q, "per_page": per_page},
            timeout=config["timeout"]
        )
        if resp.status_code == 200:
            items = resp.json().get("items", [])
            return [{
                "repo": i["repository"]["full_name"],
                "file": i["path"],
                "url": i["html_url"],
                "repo_url": i["repository"]["html_url"],
            } for i in items]
        elif resp.status_code == 403:
            return [{"error": "Rate limit. Add GitHub token in Settings."}]
        else:
            return [{"error": f"HTTP {resp.status_code}"}]
    except Exception as e:
        return [{"error": str(e)}]


def search_security_tools(category: str = "recon") -> list[dict]:
    """Search for popular security tools by category."""
    categories = {
        "recon": "reconnaissance subdomain enumeration tool",
        "sqli": "sql injection scanner tool",
        "xss": "xss scanner cross-site scripting tool",
        "fuzzer": "web fuzzer directory brute force tool",
        "exploit": "exploit framework penetration testing",
        "ssrf": "ssrf server side request forgery scanner",
    }
    query = categories.get(category, category) + " topic:security"
    return search_repos(query, sort="stars")


def get_readme(repo_full_name: str) -> str:
    """Fetch the README of a GitHub repository."""
    try:
        resp = requests.get(
            f"{GH_API}/repos/{repo_full_name}/readme",
            headers={**_headers(), "Accept": "application/vnd.github.raw+json"},
            timeout=config["timeout"]
        )
        if resp.status_code == 200:
            return resp.text[:3000]  # Limit to 3000 chars
        return f"[!] Could not fetch README (HTTP {resp.status_code})"
    except Exception as e:
        return f"[!] Error: {e}"


def get_file_content(repo_full_name: str, file_path: str) -> str:
    """Fetch raw content of a specific file in a repo."""
    try:
        resp = requests.get(
            f"{GH_API}/repos/{repo_full_name}/contents/{file_path}",
            headers={**_headers(), "Accept": "application/vnd.github.raw+json"},
            timeout=config["timeout"]
        )
        if resp.status_code == 200:
            return resp.text[:5000]
        return f"[!] HTTP {resp.status_code}"
    except Exception as e:
        return f"[!] Error: {e}"


def search_secrets_patterns(domain: str) -> list[dict]:
    """Look for exposed secrets referencing a domain on GitHub."""
    queries = [
        f'"{domain}" password',
        f'"{domain}" api_key',
        f'"{domain}" secret',
        f'"{domain}" token',
    ]
    results = []
    for q in queries[:2]:  # Limit to avoid rate limiting
        results.extend(search_code(q))
    return results
