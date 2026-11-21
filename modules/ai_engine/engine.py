"""
AI Engine — Ollama Local LLM (100% Free, Runs Offline)
Falls back to Gemini API (free tier) or OpenAI if configured.
"""

import requests
import json
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from config import config


SYSTEM_PROMPT = """You are BugHunter AI, an expert penetration tester and bug bounty hunter.
You specialize in web application security, CVE analysis, and vulnerability research.

When analyzing HTTP requests/responses:
1. Identify all potential injection points and attack surfaces
2. Look for information disclosure, misconfigurations, weak headers
3. Suggest specific payloads to test
4. Assign realistic CVSS scores
5. Explain the business impact clearly

Format your responses with clear sections:
- 🎯 **Attack Surface** — what you found
- 💥 **Potential Vulnerabilities** — ranked by severity
- 🔧 **Recommended Payloads** — specific to test
- 📊 **CVSS Score** — with justification
- 📝 **Report Template** — ready to submit to bug bounty

Always be specific, technical, and actionable. Think like a senior bug bounty hunter."""


def chat(user_message: str, history: list[dict] = None, stream_callback=None) -> str:
    """Send a message to the configured AI provider and return the response."""
    provider = config.get("ai_provider", "ollama")

    if provider == "ollama":
        return _ollama_chat(user_message, history or [], stream_callback)
    elif provider == "gemini":
        return _gemini_chat(user_message, history or [])
    elif provider == "openai":
        return _openai_chat(user_message, history or [])
    else:
        return _ollama_chat(user_message, history or [], stream_callback)


def _ollama_chat(message: str, history: list, stream_callback=None) -> str:
    """Use local Ollama instance — completely free and private."""
    base_url = config.get("ollama_url", "http://localhost:11434")
    model = config.get("ollama_model", "llama3.2")

    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    for h in history:
        messages.append(h)
    messages.append({"role": "user", "content": message})

    try:
        resp = requests.post(
            f"{base_url}/api/chat",
            json={"model": model, "messages": messages, "stream": bool(stream_callback)},
            timeout=120,
            stream=bool(stream_callback)
        )
        resp.raise_for_status()

        if stream_callback:
            full_response = ""
            for line in resp.iter_lines():
                if line:
                    chunk = json.loads(line)
                    token = chunk.get("message", {}).get("content", "")
                    full_response += token
                    stream_callback(token)
                    if chunk.get("done"):
                        break
            return full_response
        else:
            return resp.json()["message"]["content"]

    except requests.ConnectionError:
        return (
            "⚠️ **Ollama not running.**\n\n"
            "To use the free local AI:\n"
            "1. Install Ollama: https://ollama.ai\n"
            "2. Run: `ollama pull llama3.2`\n"
            "3. Run: `ollama serve`\n\n"
            "Or set a Gemini API key (free) in Settings."
        )
    except Exception as e:
        return f"❌ Ollama error: {e}"


def _gemini_chat(message: str, history: list) -> str:
    """Use Gemini API — free tier available at aistudio.google.com."""
    key = config.get("gemini_api_key", "")
    if not key:
        return "⚠️ No Gemini API key set. Get a free key at aistudio.google.com"

    try:
        # Build Gemini contents format
        contents = []
        for h in history:
            role = "model" if h["role"] == "assistant" else "user"
            contents.append({"role": role, "parts": [{"text": h["content"]}]})
        contents.append({"role": "user", "parts": [{"text": message}]})

        resp = requests.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={key}",
            json={
                "system_instruction": {"parts": [{"text": SYSTEM_PROMPT}]},
                "contents": contents,
            },
            timeout=60
        )
        if resp.status_code == 200:
            data = resp.json()
            return data["candidates"][0]["content"]["parts"][0]["text"]
        return f"❌ Gemini API error: HTTP {resp.status_code} — {resp.text[:200]}"
    except Exception as e:
        return f"❌ Gemini error: {e}"


def _openai_chat(message: str, history: list) -> str:
    """Use OpenAI API."""
    key = config.get("openai_api_key", "")
    if not key:
        return "⚠️ No OpenAI API key set in Settings."

    try:
        messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        messages.extend(history)
        messages.append({"role": "user", "content": message})

        resp = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            json={"model": "gpt-4o-mini", "messages": messages},
            timeout=60
        )
        if resp.status_code == 200:
            return resp.json()["choices"][0]["message"]["content"]
        return f"❌ OpenAI error: HTTP {resp.status_code}"
    except Exception as e:
        return f"❌ OpenAI error: {e}"


def analyze_http(request_text: str, response_text: str = "") -> str:
    """Analyze an HTTP request/response pair for vulnerabilities."""
    prompt = f"""Analyze this HTTP request for security vulnerabilities:

## HTTP REQUEST:
```
{request_text}
```
"""
    if response_text:
        prompt += f"""
## HTTP RESPONSE:
```
{response_text[:2000]}
```
"""
    prompt += "\nProvide a complete security analysis with specific payloads to test."
    return chat(prompt)


def explain_vulnerability(vuln_type: str, evidence: str, url: str) -> str:
    """Get a detailed explanation of a found vulnerability."""
    prompt = f"""I found a {vuln_type} vulnerability.

URL: {url}
Evidence: {evidence}

Please:
1. Explain the severity and impact
2. Provide advanced exploitation payloads
3. Suggest a CVSS v3 score with vector string  
4. Write a professional bug bounty report for this finding
5. Suggest remediation steps"""
    return chat(prompt)


def generate_report_text(findings: list[dict], target: str) -> str:
    """Use AI to generate a polished bug bounty report from raw findings."""
    findings_text = "\n\n".join([
        f"- Type: {f['type']}\n  Severity: {f['severity']}\n  URL: {f['url']}\n  Payload: {f.get('payload', '')}\n  Evidence: {f.get('evidence', '')}"
        for f in findings
    ])
    prompt = f"""Generate a professional bug bounty report for the following findings on {target}:

{findings_text}

Format as a complete, submission-ready bug bounty report with:
- Executive Summary
- Findings (sorted by severity, with CVSS scores)
- Steps to Reproduce for each finding
- Business Impact
- Remediation Recommendations"""
    return chat(prompt)


def check_ollama_status() -> dict:
    """Check if Ollama is running and what models are available."""
    base_url = config.get("ollama_url", "http://localhost:11434")
    try:
        resp = requests.get(f"{base_url}/api/tags", timeout=5)
        if resp.status_code == 200:
            models = [m["name"] for m in resp.json().get("models", [])]
            return {"running": True, "models": models}
    except Exception:
        pass
    return {"running": False, "models": []}
