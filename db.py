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
        self.conn.execute("PRAGMA journal_mode=WAL")
        with self.conn:
            self.conn.execute("BEGIN IMMEDIATE")
            self.conn.execute("""CREATE TABLE IF NOT EXISTS reports (
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
                platform TEXT DEFAULT '',
                program TEXT DEFAULT '',
                report_reference TEXT DEFAULT '',
                UNIQUE(repository, ghsa_id)
            )""")
            self.conn.execute("""CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )""")
            self.conn.execute("""CREATE TABLE IF NOT EXISTS repositories (
                repository TEXT PRIMARY KEY,
                enabled INTEGER NOT NULL DEFAULT 1
            )""")
            self.conn.execute("""CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                old_value TEXT,
                new_value TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(report_id) REFERENCES reports(id) ON DELETE CASCADE
            )""")
            # Add columns in place; existing rows, IDs and related data are retained.
            cols = {r["name"] for r in self.conn.execute("PRAGMA table_info(reports)").fetchall()}
            for name, ddl in {
                "vendor_response": "TEXT DEFAULT ''",
                "vendor_response_at": "TEXT",
                "last_change_at": "TEXT",
                "synced_at": "TEXT",
                "platform": "TEXT DEFAULT ''",
                "program": "TEXT DEFAULT ''",
                "report_reference": "TEXT DEFAULT ''",
            }.items():
                if name not in cols:
                    self.conn.execute(f"ALTER TABLE reports ADD COLUMN {name} {ddl}")

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

    @staticmethod
    def _report_fields(data: dict) -> dict:
        source = data.get("source") or "manual"
        if source not in {"github", "manual", "bug_bounty"}:
            raise ValueError("지원하지 않는 제보 출처입니다.")
        return {
            "repository": (data.get("repository") or "").strip(),
            "title": (data.get("title") or "").strip() or "(제목 없음)",
            # GHSA is a GitHub identity. Bounty references use report_reference.
            "ghsa_id": None if source == "bug_bounty" else data.get("ghsa_id") or None,
            "cve_id": data.get("cve_id") or None,
            "state": data.get("state") or "local",
            "severity": data.get("severity") or None,
            "html_url": data.get("html_url") or None,
            "submitted_at": data.get("submitted_at") or None,
            "updated_at": data.get("updated_at") or None,
            "notes": data.get("notes") or "",
            "source": source,
            "platform": data.get("platform") or "",
            "program": data.get("program") or "",
            "report_reference": data.get("report_reference") or "",
        }

    def _record_changes(self, report_id: int, existing, fields: dict,
                        include_notes: bool = False) -> bool:
        event_types = {
            "repository": "target", "title": "title", "ghsa_id": "ghsa",
            "cve_id": "cve", "state": "status", "severity": "severity",
            "html_url": "url", "source": "source", "platform": "platform",
            "program": "program", "report_reference": "report_reference",
            "updated_at": "github_update",
        }
        if include_notes:
            event_types["notes"] = "notes"
        changed = False
        for key, event_type in event_types.items():
            if key not in fields:
                continue
            old, new = existing[key], fields[key]
            if (old or "") != (new or ""):
                if key == "notes":
                    old, new = (old or "")[:200], (new or "")[:200]
                self._event(report_id, event_type, old, new)
                changed = True
        return changed

    def upsert_report(self, data: dict):
        now = datetime.now().isoformat(timespec="seconds")
        fields = self._report_fields(data)
        fields["synced_at"] = now if fields["source"] == "github" else data.get("synced_at")
        with self.conn:
            self.conn.execute("BEGIN IMMEDIATE")
            existing = None
            if fields["ghsa_id"]:
                existing = self.conn.execute("""
                    SELECT * FROM reports WHERE repository=? AND ghsa_id=?
                    AND source IN ('github', 'manual')
                """, (fields["repository"], fields["ghsa_id"])).fetchone()
            if existing:
                # Registration must not overwrite an existing local or synced row.
                # Local edits use update_report with an explicitly selected ID.
                if fields["source"] != "github":
                    raise ValueError("같은 저장소와 GHSA의 제보가 이미 있습니다. 기존 항목에서 정보를 수정하세요.")
                # GitHub supplies remote fields, while local annotations stay intact.
                fields["notes"] = existing["notes"]
                for key in ("platform", "program", "report_reference"):
                    fields[key] = existing[key]
                changed = self._record_changes(existing["id"], existing, fields)
                self.conn.execute("""
                    UPDATE reports SET title=:title,cve_id=:cve_id,state=:state,severity=:severity,
                        html_url=:html_url,submitted_at=:submitted_at,updated_at=:updated_at,
                        source=:source,synced_at=COALESCE(:synced_at,synced_at),
                        last_change_at=CASE WHEN :changed=1 THEN :now ELSE last_change_at END
                    WHERE id=:id
                """, {**fields, "id": existing["id"], "changed": int(changed), "now": now})
                report_id = existing["id"]
            else:
                cur = self.conn.execute("""
                    INSERT INTO reports(repository,title,ghsa_id,cve_id,state,severity,html_url,
                        submitted_at,updated_at,notes,source,last_change_at,synced_at,
                        platform,program,report_reference)
                    VALUES(:repository,:title,:ghsa_id,:cve_id,:state,:severity,:html_url,
                        :submitted_at,:updated_at,:notes,:source,:last_change_at,:synced_at,
                        :platform,:program,:report_reference)
                """, {**fields, "last_change_at": now})
                report_id = cur.lastrowid
                self._event(report_id, "created", None, fields["state"])
        return report_id

    def update_report(self, report_id: int, data: dict):
        """Edit a local report by its stable ID without resetting its submission date."""
        editable = {
            "repository", "title", "ghsa_id", "cve_id", "state", "severity",
            "html_url", "notes", "source", "platform", "program", "report_reference",
        }
        now = datetime.now().isoformat(timespec="seconds")
        with self.conn:
            self.conn.execute("BEGIN IMMEDIATE")
            existing = self.get_report(report_id)
            if existing is None:
                raise ValueError("제보를 찾을 수 없습니다.")
            if existing["source"] == "github" or data.get("source") == "github":
                raise ValueError("GitHub 동기화 제보는 수동으로 수정할 수 없습니다.")
            merged = dict(existing)
            merged.update({key: value for key, value in data.items() if key in editable})
            fields = {key: value for key, value in self._report_fields(merged).items()
                      if key in editable}
            changed = self._record_changes(report_id, existing, fields, include_notes=True)
            if changed:
                self.conn.execute("""
                    UPDATE reports SET repository=:repository,title=:title,ghsa_id=:ghsa_id,
                        cve_id=:cve_id,state=:state,severity=:severity,html_url=:html_url,
                        notes=:notes,source=:source,platform=:platform,program=:program,
                        report_reference=:report_reference,updated_at=:now,last_change_at=:now
                    WHERE id=:id
                """, {**fields, "id": report_id, "now": now})
        return report_id

    def update_notes(self, report_id: int, notes: str):
        with self.conn:
            self.conn.execute("BEGIN IMMEDIATE")
            existing = self.get_report(report_id)
            if existing is None:
                raise ValueError("제보를 찾을 수 없습니다.")
            old = existing["notes"] or ""
            if old != notes:
                now = datetime.now().isoformat(timespec="seconds")
                self.conn.execute("UPDATE reports SET notes=?,last_change_at=? WHERE id=?",
                                  (notes, now, report_id))
                self._event(report_id, "notes", old[:200], notes[:200])

    def update_vendor_response(self, report_id: int, text: str):
        now = datetime.now().isoformat(timespec="seconds")
        with self.conn:
            self.conn.execute("BEGIN IMMEDIATE")
            existing = self.get_report(report_id)
            if existing is None:
                raise ValueError("제보를 찾을 수 없습니다.")
            old = existing["vendor_response"] or ""
            if old != text:
                self.conn.execute(
                    "UPDATE reports SET vendor_response=?,vendor_response_at=?,last_change_at=? WHERE id=?",
                    (text, now if text.strip() else None, now, report_id),
                )
                self._event(report_id, "vendor_response", old[:200], text[:200])

    def delete_report(self, report_id: int):
        with self.conn:
            self.conn.execute("DELETE FROM events WHERE report_id=?", (report_id,))
            self.conn.execute("DELETE FROM reports WHERE id=?", (report_id,))

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
