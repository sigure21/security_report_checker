from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Iterable, Optional
from datetime import datetime

APP_NAME = "GitHubVulnTracker"


def app_dir() -> Path:
    base = Path(os.getenv("APPDATA", Path.home()))
    path = base / APP_NAME
    path.mkdir(parents=True, exist_ok=True)
    return path


def db_path() -> Path:
    return app_dir() / "tracker.db"


class Database:
    def __init__(self, path: Optional[Path] = None):
        self.path = path or db_path()
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.init_schema()

    def init_schema(self):
        self.conn.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repository TEXT NOT NULL,
                title TEXT NOT NULL,
                ghsa_id TEXT,
                cve_id TEXT,
                state TEXT NOT NULL DEFAULT 'local',
                severity TEXT,
                html_url TEXT,
                submitted_at TEXT,
                updated_at TEXT,
                notes TEXT DEFAULT '',
                source TEXT NOT NULL DEFAULT 'manual',
                vendor_response TEXT DEFAULT '',
                vendor_response_at TEXT,
                last_change_at TEXT,
                synced_at TEXT,
                UNIQUE(repository, ghsa_id)
            );
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS repositories (
                repository TEXT PRIMARY KEY,
                enabled INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                old_value TEXT,
                new_value TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(report_id) REFERENCES reports(id) ON DELETE CASCADE
            );
        """)
        # Migrate databases created by v0.1.
        cols = {r["name"] for r in self.conn.execute("PRAGMA table_info(reports)").fetchall()}
        for name, ddl in {
            "vendor_response": "TEXT DEFAULT ''",
            "vendor_response_at": "TEXT",
            "last_change_at": "TEXT",
            "synced_at": "TEXT",
        }.items():
            if name not in cols:
                self.conn.execute(f"ALTER TABLE reports ADD COLUMN {name} {ddl}")
        self.conn.commit()

    def close(self):
        self.conn.close()

    def list_reports(self):
        return self.conn.execute("""
            SELECT * FROM reports
            ORDER BY COALESCE(last_change_at, updated_at, submitted_at, '') DESC, id DESC
        """).fetchall()

    def get_report(self, report_id: int):
        return self.conn.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()

    def list_events(self, report_id: int, limit: int = 30):
        return self.conn.execute(
            "SELECT * FROM events WHERE report_id=? ORDER BY id DESC LIMIT ?",
            (report_id, limit),
        ).fetchall()

    def _event(self, report_id: int, event_type: str, old_value, new_value):
        self.conn.execute(
            "INSERT INTO events(report_id,event_type,old_value,new_value,created_at) VALUES(?,?,?,?,?)",
            (report_id, event_type, old_value, new_value, datetime.now().isoformat(timespec="seconds")),
        )

    def upsert_report(self, data: dict):
        ghsa = data.get("ghsa_id") or None
        repo = (data.get("repository") or "").strip()
        existing = None
        if ghsa:
            existing = self.conn.execute(
                "SELECT * FROM reports WHERE repository=? AND ghsa_id=?", (repo, ghsa)
            ).fetchone()

        now = datetime.now().isoformat(timespec="seconds")
        fields = {
            "repository": repo,
            "title": (data.get("title") or "(제목 없음)").strip(),
            "ghsa_id": ghsa,
            "cve_id": data.get("cve_id") or None,
            "state": data.get("state") or "local",
            "severity": data.get("severity") or None,
            "html_url": data.get("html_url") or None,
            "submitted_at": data.get("submitted_at") or None,
            "updated_at": data.get("updated_at") or None,
            "notes": data.get("notes") or "",
            "source": data.get("source") or "manual",
            "synced_at": now if data.get("source") == "github" else data.get("synced_at"),
        }

        if existing:
            changes = []
            for key, etype in [("state", "status"), ("cve_id", "cve"), ("severity", "severity"), ("updated_at", "github_update")]:
                old, new = existing[key], fields[key]
                if (old or "") != (new or ""):
                    changes.append((etype, old, new))
            self.conn.execute("""
                UPDATE reports SET title=:title,cve_id=:cve_id,state=:state,severity=:severity,
                    html_url=:html_url,submitted_at=:submitted_at,updated_at=:updated_at,
                    source=:source,synced_at=COALESCE(:synced_at,synced_at),
                    last_change_at=CASE WHEN :changed=1 THEN :now ELSE last_change_at END
                WHERE id=:id
            """, {**fields, "id": existing["id"], "changed": 1 if changes else 0, "now": now})
            report_id = existing["id"]
            for etype, old, new in changes:
                self._event(report_id, etype, old, new)
        else:
            cur = self.conn.execute("""
                INSERT INTO reports(repository,title,ghsa_id,cve_id,state,severity,html_url,
                    submitted_at,updated_at,notes,source,last_change_at,synced_at)
                VALUES(:repository,:title,:ghsa_id,:cve_id,:state,:severity,:html_url,
                    :submitted_at,:updated_at,:notes,:source,:last_change_at,:synced_at)
            """, {**fields, "last_change_at": now})
            report_id = cur.lastrowid
            self._event(report_id, "created", None, fields["state"])
        self.conn.commit()
        return report_id

    def update_notes(self, report_id: int, notes: str):
        self.conn.execute("UPDATE reports SET notes=? WHERE id=?", (notes, report_id))
        self.conn.commit()

    def update_vendor_response(self, report_id: int, text: str):
        now = datetime.now().isoformat(timespec="seconds")
        old = self.get_report(report_id)["vendor_response"] or ""
        self.conn.execute(
            "UPDATE reports SET vendor_response=?,vendor_response_at=?,last_change_at=? WHERE id=?",
            (text, now if text.strip() else None, now, report_id),
        )
        if old != text:
            self._event(report_id, "vendor_response", old[:200], text[:200])
        self.conn.commit()

    def delete_report(self, report_id: int):
        self.conn.execute("DELETE FROM events WHERE report_id=?", (report_id,))
        self.conn.execute("DELETE FROM reports WHERE id=?", (report_id,))
        self.conn.commit()

    def set_setting(self, key: str, value: str):
        self.conn.execute(
            "INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        self.conn.commit()

    def get_setting(self, key: str, default: str = "") -> str:
        row = self.conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    def add_repository(self, repository: str):
        repository = repository.strip().strip("/")
        if repository:
            self.conn.execute("INSERT OR IGNORE INTO repositories(repository,enabled) VALUES(?,1)", (repository,))
            self.conn.commit()

    def remove_repository(self, repository: str):
        self.conn.execute("DELETE FROM repositories WHERE repository=?", (repository,))
        self.conn.commit()

    def list_repositories(self) -> list[str]:
        rows = self.conn.execute("SELECT repository FROM repositories WHERE enabled=1 ORDER BY repository").fetchall()
        return [r["repository"] for r in rows]

    def import_repositories(self, repos: Iterable[str]):
        for repo in repos:
            self.add_repository(repo)
