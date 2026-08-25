"""Request/Response history logger with SQLite storage.

Logs every intercepted HTTP transaction to a local SQLite database for
later inspection, replay, and analysis.  Supports search/filter by URL,
status code, and content type.  Can export to HAR (HTTP Archive) format
for compatibility with Burp Suite, ZAP, and browser dev tools.
"""

import json
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from scanner.log import logger

# Default history database location
HISTORY_DIR = Path.home() / ".reconstrike" / "proxy"
HISTORY_DB = HISTORY_DIR / "history.db"


@dataclass
class HttpTransaction:
    """A complete HTTP request/response pair."""
    id: int = 0
    timestamp: float = 0.0
    method: str = ""
    url: str = ""
    request_headers: dict = field(default_factory=dict)
    request_body: str = ""
    status_code: int = 0
    response_headers: dict = field(default_factory=dict)
    response_body: str = ""
    content_type: str = ""
    latency_ms: float = 0.0
    content_length: int = 0
    host: str = ""
    path: str = ""


class HistoryDB:
    """SQLite-backed request/response history database."""

    def __init__(self, db_path: Path | str | None = None):
        self.db_path = Path(db_path) if db_path else HISTORY_DB
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = None
        self._init_db()

    def _init_db(self):
        """Initialize the database schema."""
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                method TEXT NOT NULL,
                url TEXT NOT NULL,
                host TEXT NOT NULL DEFAULT '',
                path TEXT NOT NULL DEFAULT '',
                request_headers TEXT DEFAULT '{}',
                request_body TEXT DEFAULT '',
                status_code INTEGER DEFAULT 0,
                response_headers TEXT DEFAULT '{}',
                response_body TEXT DEFAULT '',
                content_type TEXT DEFAULT '',
                content_length INTEGER DEFAULT 0,
                latency_ms REAL DEFAULT 0.0
            )
        """)
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_url ON transactions(url)
        """)
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_status ON transactions(status_code)
        """)
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_host ON transactions(host)
        """)
        self._conn.commit()

    def log_transaction(self, txn: HttpTransaction) -> int:
        """Log a complete HTTP transaction. Returns the assigned ID."""
        with self._lock:
            cursor = self._conn.execute("""
                INSERT INTO transactions
                    (timestamp, method, url, host, path, request_headers, request_body,
                     status_code, response_headers, response_body, content_type,
                     content_length, latency_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                txn.timestamp or time.time(),
                txn.method,
                txn.url,
                txn.host,
                txn.path,
                json.dumps(txn.request_headers),
                txn.request_body[:100_000],  # Cap stored body at 100KB
                txn.status_code,
                json.dumps(txn.response_headers),
                txn.response_body[:500_000],  # Cap at 500KB
                txn.content_type,
                txn.content_length,
                txn.latency_ms,
            ))
            self._conn.commit()
            return cursor.lastrowid

    def get_transaction(self, txn_id: int) -> HttpTransaction | None:
        """Retrieve a single transaction by ID."""
        row = self._conn.execute(
            "SELECT * FROM transactions WHERE id = ?", (txn_id,)
        ).fetchone()
        if not row:
            return None
        return self._row_to_txn(row)

    def search(self, url_pattern: str = "", status_code: int = 0,
               method: str = "", host: str = "",
               limit: int = 100) -> list[HttpTransaction]:
        """Search transactions with filters."""
        conditions = []
        params = []

        if url_pattern:
            conditions.append("url LIKE ?")
            params.append(f"%{url_pattern}%")
        if status_code:
            conditions.append("status_code = ?")
            params.append(status_code)
        if method:
            conditions.append("method = ?")
            params.append(method.upper())
        if host:
            conditions.append("host LIKE ?")
            params.append(f"%{host}%")

        where = "WHERE " + " AND ".join(conditions) if conditions else ""
        query = f"SELECT * FROM transactions {where} ORDER BY id DESC LIMIT ?"
        params.append(limit)

        rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_txn(r) for r in rows]

    def get_count(self) -> int:
        """Get the total number of logged transactions."""
        row = self._conn.execute("SELECT COUNT(*) FROM transactions").fetchone()
        return row[0] if row else 0

    def export_har(self, output_path: str | Path, limit: int = 10000) -> str:
        """Export history to HAR (HTTP Archive) format.

        HAR is a JSON-based format supported by all major browser dev tools,
        Burp Suite, and OWASP ZAP.
        """
        rows = self._conn.execute(
            "SELECT * FROM transactions ORDER BY id LIMIT ?", (limit,)
        ).fetchall()

        entries = []
        for row in rows:
            txn = self._row_to_txn(row)
            entry = {
                "startedDateTime": time.strftime(
                    "%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(txn.timestamp)
                ),
                "time": txn.latency_ms,
                "request": {
                    "method": txn.method,
                    "url": txn.url,
                    "httpVersion": "HTTP/1.1",
                    "headers": [{"name": k, "value": v}
                                for k, v in txn.request_headers.items()],
                    "queryString": [],
                    "postData": {
                        "mimeType": txn.request_headers.get("Content-Type", ""),
                        "text": txn.request_body,
                    } if txn.request_body else {},
                    "headersSize": -1,
                    "bodySize": len(txn.request_body),
                },
                "response": {
                    "status": txn.status_code,
                    "statusText": "",
                    "httpVersion": "HTTP/1.1",
                    "headers": [{"name": k, "value": v}
                                for k, v in txn.response_headers.items()],
                    "content": {
                        "size": txn.content_length,
                        "mimeType": txn.content_type,
                        "text": txn.response_body[:50000],
                    },
                    "headersSize": -1,
                    "bodySize": txn.content_length,
                },
                "cache": {},
                "timings": {"send": 0, "wait": txn.latency_ms, "receive": 0},
            }
            entries.append(entry)

        har = {
            "log": {
                "version": "1.2",
                "creator": {"name": "ReconStrike-ng DAST Proxy", "version": "1.0"},
                "entries": entries,
            }
        }

        output_path = Path(output_path)
        output_path.write_text(json.dumps(har, indent=2))
        logger.info("DAST: Exported %d transactions to %s", len(entries), output_path)
        return str(output_path)

    def clear(self):
        """Clear all history."""
        with self._lock:
            self._conn.execute("DELETE FROM transactions")
            self._conn.commit()

    def close(self):
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    def _row_to_txn(self, row) -> HttpTransaction:
        """Convert a database row to an HttpTransaction."""
        return HttpTransaction(
            id=row[0],
            timestamp=row[1],
            method=row[2],
            url=row[3],
            host=row[4],
            path=row[5],
            request_headers=json.loads(row[6]) if row[6] else {},
            request_body=row[7] or "",
            status_code=row[8],
            response_headers=json.loads(row[9]) if row[9] else {},
            response_body=row[10] or "",
            content_type=row[11] or "",
            content_length=row[12],
            latency_ms=row[13],
        )
