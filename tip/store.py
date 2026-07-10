"""Modelo de dados e armazenamento de IOCs em SQLite."""

from __future__ import annotations

import ipaddress
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone

_SCHEMA = """
CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    value TEXT NOT NULL,
    type TEXT NOT NULL,          -- ip | domain | url | md5 | sha1 | sha256 | email
    threat TEXT,                 -- ex.: 'C2', 'phishing', 'ransomware'
    source TEXT,
    confidence INTEGER DEFAULT 50,   -- 0-100
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    tags TEXT,
    UNIQUE(value, type)
);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type);
"""

_HASH_LENS = {32: "md5", 40: "sha1", 64: "sha256"}
_URL_RE = re.compile(r"^https?://", re.I)
_DOMAIN_RE = re.compile(r"^(?:[a-z0-9-]{1,63}\.)+[a-z]{2,}$", re.I)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$", re.I)
_HASH_RE = re.compile(r"^[a-fA-F0-9]+$")


def detect_type(value: str) -> str:
    v = value.strip()
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if _URL_RE.match(v):
        return "url"
    if _EMAIL_RE.match(v):
        return "email"
    if _HASH_RE.match(v) and len(v) in _HASH_LENS:
        return _HASH_LENS[len(v)]
    if _DOMAIN_RE.match(v):
        return "domain"
    return "unknown"


@dataclass
class IOC:
    value: str
    type: str
    threat: str = ""
    source: str = ""
    confidence: int = 50
    tags: str = ""


class TIPStore:
    def __init__(self, path: str = "tip.db"):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)

    def add(self, ioc: IOC) -> int:
        now = datetime.now(timezone.utc).isoformat()
        typ = ioc.type or detect_type(ioc.value)
        cur = self.conn.cursor()
        existing = cur.execute(
            "SELECT id FROM iocs WHERE value=? AND type=?", (ioc.value, typ)
        ).fetchone()
        if existing:
            cur.execute(
                "UPDATE iocs SET last_seen=?, threat=COALESCE(NULLIF(?,''),threat),"
                " source=COALESCE(NULLIF(?,''),source), confidence=?,"
                " tags=COALESCE(NULLIF(?,''),tags) WHERE id=?",
                (now, ioc.threat, ioc.source, ioc.confidence, ioc.tags, existing["id"]),
            )
            self.conn.commit()
            return existing["id"]
        cur.execute(
            "INSERT INTO iocs (value, type, threat, source, confidence,"
            " first_seen, last_seen, tags) VALUES (?,?,?,?,?,?,?,?)",
            (ioc.value, typ, ioc.threat, ioc.source, ioc.confidence, now, now, ioc.tags),
        )
        self.conn.commit()
        return cur.lastrowid

    def lookup(self, value: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM iocs WHERE value=?", (value.strip(),)
        ).fetchall()
        return [dict(r) for r in rows]

    def search(self, *, type: str | None = None, threat: str | None = None,
               min_confidence: int = 0, limit: int = 100) -> list[dict]:
        q = "SELECT * FROM iocs WHERE confidence >= ?"
        params: list = [min_confidence]
        if type:
            q += " AND type = ?"
            params.append(type)
        if threat:
            q += " AND threat LIKE ?"
            params.append(f"%{threat}%")
        q += " ORDER BY last_seen DESC LIMIT ?"
        params.append(limit)
        return [dict(r) for r in self.conn.execute(q, params).fetchall()]

    def stats(self) -> dict:
        cur = self.conn.cursor()
        total = cur.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
        by_type = dict(cur.execute(
            "SELECT type, COUNT(*) FROM iocs GROUP BY type").fetchall())
        by_threat = dict(cur.execute(
            "SELECT threat, COUNT(*) FROM iocs WHERE threat!='' GROUP BY threat"
        ).fetchall())
        return {"total": total, "by_type": by_type, "by_threat": by_threat}

    def import_bulk(self, values: list[str], threat: str = "", source: str = "",
                    confidence: int = 50) -> int:
        count = 0
        for v in values:
            v = v.strip()
            if not v or v.startswith("#"):
                continue
            self.add(IOC(value=v, type=detect_type(v), threat=threat,
                         source=source, confidence=confidence))
            count += 1
        return count

    def close(self) -> None:
        self.conn.close()
