import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from db import Database


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.path = Path(self.temp_dir.name) / "tracker.db"
        self.db = Database(self.path)

    def tearDown(self):
        self.db.close()
        self.temp_dir.cleanup()

    def bounty(self, **overrides):
        data = {
            "repository": "https://app.example.test",
            "title": "Private report",
            "source": "bug_bounty",
            "platform": "HackerOne",
            "program": "Example program",
            "report_reference": "123456",
            "state": "submitted",
            "severity": "high",
            "submitted_at": "2026-01-01T12:00:00",
            "updated_at": "2026-01-01T12:00:00",
            "notes": "Original private notes",
        }
        data.update(overrides)
        return data

    def advisory(self, **overrides):
        data = {
            "repository": "example/project",
            "title": "GitHub advisory",
            "ghsa_id": "GHSA-aaaa-bbbb-cccc",
            "source": "github",
            "state": "triage",
            "severity": "moderate",
            "submitted_at": "2025-12-01T09:00:00Z",
            "updated_at": "2026-01-01T09:00:00Z",
            "html_url": "https://github.com/example/project/security/advisories/GHSA-aaaa-bbbb-cccc",
        }
        data.update(overrides)
        return data

    def test_bounty_create_update_status_and_reopen_preserve_identity(self):
        report_id = self.db.upsert_report(self.bounty())
        original = dict(self.db.get_report(report_id))
        self.db.update_vendor_response(report_id, "Acknowledged by triage")
        self.db.update_report(report_id, {
            "repository": "api.example.test",
            "title": "Updated report title",
            "state": "accepted",
            "severity": "critical",
            "platform": "Bugcrowd",
            "program": "Changed program",
            "report_reference": "BC-100",
            "html_url": "https://example.test/reports/BC-100",
            "notes": "Updated local notes",
            "submitted_at": "2099-01-01T00:00:00",
            "updated_at": "2099-01-01T00:00:00",
        })
        row = dict(self.db.get_report(report_id))
        self.assertEqual(row["id"], report_id)
        self.assertEqual(row["submitted_at"], original["submitted_at"])
        self.assertNotEqual(row["updated_at"], "2099-01-01T00:00:00")
        self.assertEqual(row["repository"], "api.example.test")
        self.assertEqual(row["title"], "Updated report title")
        self.assertEqual(row["state"], "accepted")
        self.assertEqual(row["severity"], "critical")
        self.assertEqual(row["platform"], "Bugcrowd")
        self.assertEqual(row["program"], "Changed program")
        self.assertEqual(row["report_reference"], "BC-100")
        self.assertEqual(row["notes"], "Updated local notes")
        self.assertEqual(row["vendor_response"], "Acknowledged by triage")
        self.assertEqual(row["source"], "bug_bounty")
        self.assertIsNone(row["ghsa_id"])
        event_types = {event["event_type"] for event in self.db.list_events(report_id)}
        self.assertTrue({"created", "target", "title", "status", "severity", "platform",
                         "program", "report_reference", "url", "notes", "vendor_response"}
                        <= event_types)
        saved_events = [dict(event) for event in self.db.list_events(report_id)]
        self.db.close()
        self.db = Database(self.path)
        self.assertEqual(dict(self.db.get_report(report_id)), row)
        self.assertEqual([dict(event) for event in self.db.list_events(report_id)], saved_events)

    def test_identical_edit_does_not_change_history_or_dates(self):
        report_id = self.db.upsert_report(self.bounty())
        self.db.update_vendor_response(report_id, "Accepted")
        before = dict(self.db.get_report(report_id))
        events = [dict(event) for event in self.db.list_events(report_id)]
        self.db.update_report(report_id, dict(before))
        self.db.update_notes(report_id, before["notes"])
        self.db.update_vendor_response(report_id, before["vendor_response"])
        self.assertEqual(dict(self.db.get_report(report_id)), before)
        self.assertEqual([dict(event) for event in self.db.list_events(report_id)], events)

    def test_github_sync_preserves_bounty_and_local_annotations(self):
        bounty_id = self.db.upsert_report(self.bounty(
            repository="example/project", ghsa_id="GHSA-aaaa-bbbb-cccc"))
        bounty_before = dict(self.db.get_report(bounty_id))
        github_id = self.db.upsert_report(self.advisory())
        self.db.update_notes(github_id, "Research notes")
        self.db.update_vendor_response(github_id, "Vendor confirmed")
        response_at = self.db.get_report(github_id)["vendor_response_at"]
        updated_data = self.advisory(state="published", cve_id="CVE-2026-1234",
                                     title="Updated remote summary", notes="Remote notes ignored")
        self.assertEqual(self.db.upsert_report(updated_data), github_id)
        events_before_repeat = len(self.db.list_events(github_id))
        self.assertEqual(self.db.upsert_report(updated_data), github_id)
        github = self.db.get_report(github_id)
        self.assertEqual(len(self.db.list_reports()), 2)
        self.assertEqual(github["state"], "published")
        self.assertEqual(github["cve_id"], "CVE-2026-1234")
        self.assertEqual(github["title"], "Updated remote summary")
        self.assertEqual(github["notes"], "Research notes")
        self.assertEqual(github["vendor_response"], "Vendor confirmed")
        self.assertEqual(github["vendor_response_at"], response_at)
        self.assertEqual(len(self.db.list_events(github_id)), events_before_repeat)
        self.assertEqual(dict(self.db.get_report(bounty_id)), bounty_before)

    def test_manual_advisory_sync_reuses_id_and_preserves_annotations(self):
        manual_id = self.db.upsert_report(self.advisory(
            source="manual", notes="Pre-sync notes", program="Local program"))
        self.db.update_vendor_response(manual_id, "Pre-sync response")
        self.assertEqual(self.db.upsert_report(self.advisory()), manual_id)
        row = self.db.get_report(manual_id)
        self.assertEqual(len(self.db.list_reports()), 1)
        self.assertEqual(row["source"], "github")
        self.assertEqual(row["notes"], "Pre-sync notes")
        self.assertEqual(row["program"], "Local program")
        self.assertEqual(row["vendor_response"], "Pre-sync response")

    def test_manual_editor_cannot_overwrite_github_report(self):
        github_id = self.db.upsert_report(self.advisory())
        before = dict(self.db.get_report(github_id))
        for change in ({"title": "Overwrite"}, {"source": "bug_bounty"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.db.update_report(github_id, change)
        with self.assertRaises(ValueError):
            self.db.upsert_report(self.advisory(source="manual", title="Overwrite"))
        bounty_id = self.db.upsert_report(self.bounty())
        with self.assertRaises(ValueError):
            self.db.update_report(bounty_id, {"source": "github"})
        self.assertEqual(dict(self.db.get_report(github_id)), before)
        self.assertEqual(len(self.db.list_events(github_id)), 1)

    def test_duplicate_manual_registration_does_not_overwrite_existing_report(self):
        report_id = self.db.upsert_report(self.advisory(source="manual", notes="Keep original notes"))
        self.db.update_vendor_response(report_id, "Keep original response")
        before = dict(self.db.get_report(report_id))
        events = [dict(event) for event in self.db.list_events(report_id)]
        with self.assertRaises(ValueError):
            self.db.upsert_report(self.advisory(
                source="manual", title="Accidental overwrite", state="closed",
                notes="New notes", submitted_at="2099-01-01T00:00:00"))
        self.assertEqual(len(self.db.list_reports()), 1)
        self.assertEqual(dict(self.db.get_report(report_id)), before)
        self.assertEqual([dict(event) for event in self.db.list_events(report_id)], events)
        self.db.update_report(report_id, {"title": "Explicit selected edit"})
        self.assertEqual(self.db.get_report(report_id)["title"], "Explicit selected edit")

    def test_failed_mutations_roll_back_rows_and_events(self):
        with patch.object(self.db, "_event", side_effect=RuntimeError("Event write failed")):
            with self.assertRaises(RuntimeError):
                self.db.upsert_report(self.bounty())
        self.assertEqual(self.db.list_reports(), [])
        report_id = self.db.upsert_report(self.bounty())
        before = dict(self.db.get_report(report_id))
        with patch.object(self.db, "_event", side_effect=RuntimeError("Event write failed")):
            with self.assertRaises(RuntimeError):
                self.db.update_vendor_response(report_id, "Failed response")
            with self.assertRaises(RuntimeError):
                self.db.update_report(report_id, {"state": "accepted"})
        self.assertEqual(dict(self.db.get_report(report_id)), before)
        self.assertEqual(len(self.db.list_events(report_id)), 1)

    def test_unique_conflict_rolls_back_edit_and_history(self):
        first_id = self.db.upsert_report(self.advisory(source="manual"))
        second_id = self.db.upsert_report(self.advisory(
            source="manual", ghsa_id="GHSA-dddd-eeee-ffff"))
        before = dict(self.db.get_report(second_id))
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.update_report(second_id, {"ghsa_id": self.db.get_report(first_id)["ghsa_id"]})
        self.assertEqual(dict(self.db.get_report(second_id)), before)
        self.assertEqual(len(self.db.list_events(second_id)), 1)

    def test_multiple_bounties_for_same_target_are_independent(self):
        first_id = self.db.upsert_report(self.bounty())
        second_id = self.db.upsert_report(self.bounty(report_reference="654321"))
        self.assertNotEqual(first_id, second_id)
        self.db.update_report(first_id, {"state": "resolved"})
        self.assertEqual(self.db.get_report(second_id)["state"], "submitted")

    def test_unknown_source_and_missing_report_are_rejected(self):
        with self.assertRaises(ValueError):
            self.db.upsert_report(self.bounty(source="unknown"))
        with self.assertRaises(ValueError):
            self.db.update_report(987654, {"state": "accepted"})
        self.assertEqual(self.db.list_reports(), [])


class MigrationTests(unittest.TestCase):
    LEGACY_COLUMNS = {
        "id": "INTEGER PRIMARY KEY AUTOINCREMENT",
        "repository": "TEXT NOT NULL", "title": "TEXT NOT NULL",
        "ghsa_id": "TEXT", "cve_id": "TEXT", "state": "TEXT NOT NULL DEFAULT 'local'",
        "severity": "TEXT", "html_url": "TEXT", "submitted_at": "TEXT",
        "updated_at": "TEXT", "notes": "TEXT DEFAULT ''",
        "source": "TEXT NOT NULL DEFAULT 'manual'",
    }
    V03_COLUMNS = {
        "vendor_response": "TEXT DEFAULT ''", "vendor_response_at": "TEXT",
        "last_change_at": "TEXT", "synced_at": "TEXT",
    }

    def test_additive_migration_preserves_all_existing_values_and_related_data(self):
        for version in ("0.1", "0.3"):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as temp_dir:
                path = Path(temp_dir) / "tracker.db"
                columns = dict(self.LEGACY_COLUMNS)
                if version == "0.3":
                    columns.update(self.V03_COLUMNS)
                conn = sqlite3.connect(path)
                conn.row_factory = sqlite3.Row
                conn.execute("CREATE TABLE reports (" + ",".join(
                    name + " " + ddl for name, ddl in columns.items())
                    + ",UNIQUE(repository,ghsa_id))")
                conn.executescript("""
                    CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                    CREATE TABLE repositories (repository TEXT PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 1);
                    CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, report_id INTEGER NOT NULL,
                        event_type TEXT NOT NULL, old_value TEXT, new_value TEXT, created_at TEXT NOT NULL,
                        FOREIGN KEY(report_id) REFERENCES reports(id) ON DELETE CASCADE);
                """)
                for report_id, source in ((7, "github"), (11, "manual")):
                    row = {
                        "id": report_id, "repository": "owner/project-" + str(report_id),
                        "title": "기존 제보 " + str(report_id), "ghsa_id": "GHSA-existing-" + str(report_id),
                        "cve_id": None if report_id == 11 else "CVE-2025-1234", "state": "triage",
                        "severity": "high", "html_url": "https://example.test/report/" + str(report_id),
                        "submitted_at": "2025-01-02T03:04:05Z", "updated_at": "2025-02-03T04:05:06Z",
                        "notes": "메모\nSecond line", "source": source,
                        "vendor_response": "기존 답변", "vendor_response_at": "2025-03-04T05:06:07Z",
                        "last_change_at": "2025-04-05T06:07:08Z", "synced_at": "2025-05-06T07:08:09Z",
                    }
                    keys = list(columns)
                    conn.execute("INSERT INTO reports (" + ",".join(keys) + ") VALUES ("
                                 + ",".join("?" for _ in keys) + ")", [row[key] for key in keys])
                conn.execute("INSERT INTO settings VALUES (?,?)", ("theme", "dark"))
                conn.execute("INSERT INTO settings VALUES (?,?)", ("login", "example-researcher"))
                conn.execute("INSERT INTO repositories VALUES (?,?)", ("owner/project-7", 1))
                conn.execute("INSERT INTO repositories VALUES (?,?)", ("owner/disabled-project", 0))
                conn.execute("INSERT INTO events VALUES (?,?,?,?,?,?)",
                             (19, 7, "status", "draft", "triage", "2025-02-03T04:05:06Z"))
                conn.commit()
                old_reports = [dict(row) for row in conn.execute("SELECT * FROM reports ORDER BY id")]
                old_tables = {table: [dict(row) for row in conn.execute("SELECT * FROM " + table)]
                              for table in ("settings", "repositories", "events")}
                conn.close()
                db = Database(path)
                try:
                    new_reports = [dict(row) for row in db.conn.execute("SELECT * FROM reports ORDER BY id")]
                    for before, after in zip(old_reports, new_reports):
                        self.assertEqual({key: after[key] for key in before}, before)
                        for key in ("platform", "program", "report_reference"):
                            self.assertEqual(after[key], "")
                    for table, before in old_tables.items():
                        self.assertEqual([dict(row) for row in db.conn.execute("SELECT * FROM " + table)], before)
                    snapshot = [dict(row) for row in db.conn.execute("SELECT * FROM reports ORDER BY id")]
                    db.close()
                    db = Database(path)
                    self.assertEqual([dict(row) for row in db.conn.execute("SELECT * FROM reports ORDER BY id")], snapshot)
                    new_id = db.upsert_report({"repository": "app.example.test", "title": "New bounty",
                                               "source": "bug_bounty", "program": "New program"})
                    self.assertGreater(new_id, 11)
                    self.assertEqual(db.get_setting("theme"), "dark")
                    self.assertEqual(db.list_repositories(), ["owner/project-7"])
                finally:
                    db.close()


if __name__ == "__main__":
    unittest.main()
