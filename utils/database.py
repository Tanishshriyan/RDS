"""
Async SQLite logger for events, predictions, and alerts.
Uses aiosqlite if available (async), falls back to sqlite3 sync implementation.

Schema:
- events (id, timestamp, pid, process, event_json)
- predictions (id, timestamp, pid, process, features_json, prediction_json)
- alerts (id, timestamp, pid, process, alert_json)
- model_metadata (id, key, value_json)
"""

import os
import json
import time
from typing import Optional, List, Dict, Any

try:
    import aiosqlite
    ASYNC_DB = True
except Exception:
    import sqlite3
    ASYNC_DB = False

DB_PATH_DEFAULT = "data/ransomguard.db"
os.makedirs(os.path.dirname(DB_PATH_DEFAULT), exist_ok=True)

CREATE_EVENTS = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL,
    pid INTEGER,
    process TEXT,
    event_json TEXT
);
"""

CREATE_PREDICTIONS = """
CREATE TABLE IF NOT EXISTS predictions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL,
    pid INTEGER,
    process TEXT,
    features_json TEXT,
    prediction_json TEXT
);
"""

CREATE_ALERTS = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL,
    pid INTEGER,
    process TEXT,
    alert_json TEXT
);
"""

CREATE_META = """
CREATE TABLE IF NOT EXISTS model_metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE,
    value_json TEXT
);
"""

class Database:
    def __init__(self, db_path: str = DB_PATH_DEFAULT):
        self.db_path = db_path
        self._conn = None

    # ---------------- Async API using aiosqlite -----------------------------
    async def init_db(self):
        if ASYNC_DB:
            self._conn = await aiosqlite.connect(self.db_path)
            await self._conn.execute(CREATE_EVENTS)
            await self._conn.execute(CREATE_PREDICTIONS)
            await self._conn.execute(CREATE_ALERTS)
            await self._conn.execute(CREATE_META)
            await self._conn.commit()
        else:
            # sync fallback
            self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cur = self._conn.cursor()
            cur.execute(CREATE_EVENTS)
            cur.execute(CREATE_PREDICTIONS)
            cur.execute(CREATE_ALERTS)
            cur.execute(CREATE_META)
            self._conn.commit()

    async def close(self):
        if not self._conn:
            return
        if ASYNC_DB:
            await self._conn.close()
        else:
            self._conn.close()

    async def log_event(self, event: Dict[str, Any]):
        ts = time.time()
        pid = int(event.get("pid") or 0)
        process = event.get("process") or ""
        payload = json.dumps(event, default=str)
        if ASYNC_DB:
            await self._conn.execute("INSERT INTO events (ts, pid, process, event_json) VALUES (?, ?, ?, ?)", (ts, pid, process, payload))
            await self._conn.commit()
        else:
            cur = self._conn.cursor()
            cur.execute("INSERT INTO events (ts, pid, process, event_json) VALUES (?, ?, ?, ?)", (ts, pid, process, payload))
            self._conn.commit()

    async def log_prediction(self, pid: int, process: str, features: Dict[str, Any], prediction: Dict[str, Any]):
        ts = time.time()
        fs = json.dumps(features, default=str)
        pred = json.dumps(prediction, default=str)
        if ASYNC_DB:
            await self._conn.execute("INSERT INTO predictions (ts, pid, process, features_json, prediction_json) VALUES (?, ?, ?, ?, ?)", (ts, pid, process, fs, pred))
            await self._conn.commit()
        else:
            cur = self._conn.cursor()
            cur.execute("INSERT INTO predictions (ts, pid, process, features_json, prediction_json) VALUES (?, ?, ?, ?, ?)", (ts, pid, process, fs, pred))
            self._conn.commit()

    async def log_alert(self, pid: int, process: str, alert: Dict[str, Any]):
        ts = time.time()
        payload = json.dumps(alert, default=str)
        if ASYNC_DB:
            await self._conn.execute("INSERT INTO alerts (ts, pid, process, alert_json) VALUES (?, ?, ?, ?)", (ts, pid, process, payload))
            await self._conn.commit()
        else:
            cur = self._conn.cursor()
            cur.execute("INSERT INTO alerts (ts, pid, process, alert_json) VALUES (?, ?, ?, ?)", (ts, pid, process, payload))
            self._conn.commit()

    async def save_model_metadata(self, key: str, value: Dict[str, Any]):
        v = json.dumps(value, default=str)
        if ASYNC_DB:
            await self._conn.execute("INSERT OR REPLACE INTO model_metadata (key, value_json) VALUES (?, ?)", (key, v))
            await self._conn.commit()
        else:
            cur = self._conn.cursor()
            cur.execute("INSERT OR REPLACE INTO model_metadata (key, value_json) VALUES (?, ?)", (key, v))
            self._conn.commit()

    async def get_recent_logs(self, limit: int = 50):
        if ASYNC_DB:
            cur = await self._conn.execute("SELECT id, ts, pid, process, event_json FROM events ORDER BY id DESC LIMIT ?", (limit,))
            rows = await cur.fetchall()
        else:
            cur = self._conn.cursor()
            cur.execute("SELECT id, ts, pid, process, event_json FROM events ORDER BY id DESC LIMIT ?", (limit,))
            rows = cur.fetchall()
        result = []
        for r in rows:
            result.append({
                "id": r[0],
                "timestamp": r[1],
                "pid": r[2],
                "process": r[3],
                "event": json.loads(r[4]) if r[4] else {}
            })
        return result
