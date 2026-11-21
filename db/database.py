"""
Database module — SQLite backend for BugHunter AI
Stores sessions, findings, scan history, and AI analysis results.
"""

import sqlite3
import json
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "bughunter.db")


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            notes TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER,
            vuln_type TEXT,
            severity TEXT,
            title TEXT,
            description TEXT,
            url TEXT,
            parameter TEXT,
            payload TEXT,
            evidence TEXT,
            cvss_score REAL,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER,
            module TEXT,
            target TEXT,
            result TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS exploit_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            query TEXT,
            source TEXT,
            result TEXT,
            cached_at TEXT DEFAULT (datetime('now'))
        )
    """)

    conn.commit()
    conn.close()


def new_session(target: str, notes: str = "") -> int:
    conn = get_conn()
    c = conn.cursor()
    c.execute("INSERT INTO sessions (target, notes) VALUES (?, ?)", (target, notes))
    conn.commit()
    sid = c.lastrowid
    conn.close()
    return sid


def add_finding(session_id: int, vuln_type: str, severity: str, title: str,
                description: str, url: str, parameter: str = "", payload: str = "",
                evidence: str = "", cvss_score: float = 0.0) -> int:
    conn = get_conn()
    c = conn.cursor()
    c.execute("""
        INSERT INTO findings
        (session_id, vuln_type, severity, title, description, url, parameter, payload, evidence, cvss_score)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (session_id, vuln_type, severity, title, description, url, parameter, payload, evidence, cvss_score))
    conn.commit()
    fid = c.lastrowid
    conn.close()
    return fid


def log_scan(session_id: int, module: str, target: str, result: dict):
    conn = get_conn()
    c = conn.cursor()
    c.execute("""
        INSERT INTO scan_history (session_id, module, target, result)
        VALUES (?, ?, ?, ?)
    """, (session_id, module, target, json.dumps(result)))
    conn.commit()
    conn.close()


def get_findings(session_id: int) -> list:
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM findings WHERE session_id=? ORDER BY cvss_score DESC", (session_id,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def get_sessions() -> list:
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT s.*, COUNT(f.id) as finding_count FROM sessions s LEFT JOIN findings f ON f.session_id=s.id GROUP BY s.id ORDER BY s.created_at DESC")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def cache_exploit(query: str, source: str, result: dict):
    conn = get_conn()
    c = conn.cursor()
    c.execute("INSERT INTO exploit_cache (query, source, result) VALUES (?, ?, ?)",
              (query, source, json.dumps(result)))
    conn.commit()
    conn.close()


def get_cached_exploit(query: str, source: str) -> dict | None:
    conn = get_conn()
    c = conn.cursor()
    c.execute("""
        SELECT result FROM exploit_cache
        WHERE query=? AND source=?
        AND cached_at > datetime('now', '-1 hour')
        ORDER BY cached_at DESC LIMIT 1
    """, (query, source))
    row = c.fetchone()
    conn.close()
    if row:
        return json.loads(row["result"])
    return None


# Initialize on import
init_db()
