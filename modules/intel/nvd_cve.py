"""
NVD / CVE Database Module — 100% Free
Uses the official NIST NVD REST API v2 — no API key required.
"""

import requests
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from config import config

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def lookup_cve(cve_id: str) -> dict:
    """Fetch full details for a specific CVE ID."""
    try:
        resp = requests.get(
            NVD_API,
            params={"cveId": cve_id.upper()},
            headers={"User-Agent": config["user_agent"]},
            timeout=config["timeout"]
        )
        if resp.status_code == 200:
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                return _parse_cve(vulns[0]["cve"])
        return {"error": f"CVE not found or API error (HTTP {resp.status_code})"}
    except Exception as e:
        return {"error": str(e)}


def search_cves(keyword: str, results_per_page: int = 10) -> list[dict]:
    """Search CVEs by keyword."""
    try:
        resp = requests.get(
            NVD_API,
            params={"keywordSearch": keyword, "resultsPerPage": results_per_page},
            headers={"User-Agent": config["user_agent"]},
            timeout=15
        )
        if resp.status_code == 200:
            vulns = resp.json().get("vulnerabilities", [])
            return [_parse_cve(v["cve"]) for v in vulns]
        return [{"error": f"HTTP {resp.status_code}"}]
    except Exception as e:
        return [{"error": str(e)}]


def get_recent_cves(days: int = 7, results: int = 15) -> list[dict]:
    """Get recently published/modified CVEs."""
    from datetime import datetime, timedelta
    end = datetime.utcnow()
    start = end - timedelta(days=days)
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    try:
        resp = requests.get(
            NVD_API,
            params={
                "pubStartDate": start.strftime(fmt),
                "pubEndDate": end.strftime(fmt),
                "resultsPerPage": results,
            },
            headers={"User-Agent": config["user_agent"]},
            timeout=15
        )
        if resp.status_code == 200:
            vulns = resp.json().get("vulnerabilities", [])
            return [_parse_cve(v["cve"]) for v in vulns]
    except Exception as e:
        return [{"error": str(e)}]
    return []


def _parse_cve(cve: dict) -> dict:
    cve_id = cve.get("id", "")
    descriptions = cve.get("descriptions", [])
    desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description")

    # CVSS v3 Score
    cvss_score = 0.0
    cvss_vector = ""
    severity = "UNKNOWN"
    metrics = cve.get("metrics", {})
    v31 = metrics.get("cvssMetricV31", [])
    v30 = metrics.get("cvssMetricV30", [])
    v2  = metrics.get("cvssMetricV2", [])

    if v31:
        m = v31[0]["cvssData"]
        cvss_score = m.get("baseScore", 0.0)
        cvss_vector = m.get("vectorString", "")
        severity = m.get("baseSeverity", "UNKNOWN")
    elif v30:
        m = v30[0]["cvssData"]
        cvss_score = m.get("baseScore", 0.0)
        cvss_vector = m.get("vectorString", "")
        severity = m.get("baseSeverity", "UNKNOWN")
    elif v2:
        m = v2[0]["cvssData"]
        cvss_score = m.get("baseScore", 0.0)
        severity = v2[0].get("baseSeverity", "UNKNOWN")

    # References
    refs = [r["url"] for r in cve.get("references", [])[:5]]

    # Affected products
    configs = cve.get("configurations", [])
    affected = []
    for cfg in configs:
        for node in cfg.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if cpe_match.get("vulnerable"):
                    affected.append(cpe_match.get("criteria", ""))

    return {
        "id": cve_id,
        "description": desc,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "severity": severity,
        "published": cve.get("published", "")[:10],
        "modified": cve.get("lastModified", "")[:10],
        "references": refs,
        "affected_products": affected[:10],
        "exploitability": _get_exploitability(cvss_vector),
    }


def _get_exploitability(vector: str) -> str:
    if not vector:
        return "Unknown"
    if "AV:N" in vector and "AC:L" in vector:
        return "High — Network accessible, low complexity"
    if "AV:N" in vector:
        return "Medium — Network accessible"
    return "Low — Local access required"
