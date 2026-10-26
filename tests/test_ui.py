"""Offline integration checks for manual and bug bounty report workflows."""

import csv
import os
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

# Set before importing PySide6, including through main.
os.environ["QT_QPA_PLATFORM"] = "offscreen"

from openpyxl import load_workbook
from PySide6.QtCore import QSettings
from PySide6.QtGui import QFont, QFontDatabase
from PySide6.QtWidgets import QApplication, QDialog

import main
from db import Database


class UiIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.db = Database(Path(self.temp_dir.name) / "tracker.db")
        self.addCleanup(self.db.close)
        self.patches = ExitStack()
        self.addCleanup(self.patches.close)
        self.patches.enter_context(patch.object(main, "Database", return_value=self.db))
        settings_path = str(Path(self.temp_dir.name) / "settings.ini")
        self.patches.enter_context(patch.object(
            main, "QSettings", side_effect=lambda *args: QSettings(settings_path, QSettings.IniFormat)))
        self.patches.enter_context(patch.object(main.MainWindow, "refresh_connection_status"))
        self.patches.enter_context(patch.object(
            main.keyring, "get_password", side_effect=AssertionError("Unexpected credential access")))
        self.patches.enter_context(patch.object(
            main, "GitHubClient", side_effect=AssertionError("Unexpected network client")))
        self.window = main.MainWindow()
        self.addCleanup(self.window.close)
        self.window.show_page(1)

    def bounty(self, **overrides):
        data = {
            "repository": "app.example.test", "title": "Account export access issue",
            "source": "bug_bounty", "platform": "HackerOne", "program": "Example program",
            "report_reference": "H1-2048", "state": "submitted", "severity": "high",
            "html_url": "https://example.test/reports/H1-2048",
            "submitted_at": "2026-01-02T03:04:05", "updated_at": "2026-01-03T04:05:06",
            "notes": "Synthetic research notes",
        }
        data.update(overrides)
        return data

    def github(self, **overrides):
        data = {
            "repository": "example/project", "title": "Dependency advisory",
            "source": "github", "ghsa_id": "GHSA-aaaa-bbbb-cccc", "state": "triage",
            "severity": "moderate", "cve_id": "CVE-2026-1234",
            "html_url": "https://github.com/example/project/security/advisories/GHSA-aaaa-bbbb-cccc",
            "submitted_at": "2025-12-01T09:00:00Z", "updated_at": "2026-01-03T04:05:06Z",
        }
        data.update(overrides)
        return data

    def seed_mixed_reports(self):
        bounty_id = self.db.upsert_report(self.bounty())
        github_id = self.db.upsert_report(self.github())
        manual_id = self.db.upsert_report(self.github(
            source="manual", repository="example/second-project", title="Manual advisory",
            ghsa_id="GHSA-dddd-eeee-ffff", state="draft", cve_id=None))
        self.window.refresh_all()
        return bounty_id, github_id, manual_id

    def visible_ids(self):
        return [int(self.window.report_table.item(row, main.REPORT_ID_COLUMN).text())
                for row in range(self.window.report_table.rowCount())]

    def select_report(self, report_id):
        row = self.visible_ids().index(report_id)
        self.window.report_table.selectRow(row)
        self.app.processEvents()
        self.assertEqual(self.window.selected_report_id(), report_id)

    def test_dialog_source_switch_exposes_bounty_fields_and_clears_github_identity(self):
        dialog = main.ReportDialog(self.window)
        self.assertFalse(dialog.form.isRowVisible(dialog.platform))
        self.assertTrue(dialog.form.isRowVisible(dialog.ghsa))
        self.assertEqual([dialog.state.itemText(i) for i in range(dialog.state.count())],
                         main.GITHUB_STATES)
        dialog.ghsa.setText("GHSA-aaaa-bbbb-cccc")
        dialog.source.setCurrentIndex(dialog.source.findData("bug_bounty"))
        for field in (dialog.platform, dialog.program, dialog.report_reference):
            self.assertTrue(dialog.form.isRowVisible(field))
        self.assertFalse(dialog.form.isRowVisible(dialog.ghsa))
        self.assertEqual([dialog.state.itemText(i) for i in range(dialog.state.count())],
                         main.BOUNTY_STATES)
        dialog.repo.setText("  app.example.test  ")
        dialog.title.setText("  Synthetic report  ")
        dialog.platform.setCurrentText("Independent program portal")
        dialog.program.setText(" Example program ")
        dialog.report_reference.setText(" BB-42 ")
        dialog.state.setCurrentText("accepted")
        dialog.accept()
        self.assertEqual(dialog.result(), QDialog.Accepted)
        data = dialog.data()
        self.assertEqual(data["source"], "bug_bounty")
        self.assertEqual(data["repository"], "app.example.test")
        self.assertEqual(data["platform"], "Independent program portal")
        self.assertEqual(data["program"], "Example program")
        self.assertEqual(data["report_reference"], "BB-42")
        self.assertEqual(data["state"], "accepted")
        self.assertIsNone(data["ghsa_id"])

    def test_manual_dialog_normalizes_github_url_and_discards_bounty_metadata(self):
        dialog = main.ReportDialog(self.window, source="bug_bounty")
        dialog.platform.setCurrentText("Bugcrowd")
        dialog.program.setText("Old program")
        dialog.report_reference.setText("BC-100")
        dialog.source.setCurrentIndex(dialog.source.findData("manual"))
        dialog.repo.setText("https://github.com/example/project/security/advisories/GHSA-aaaa-bbbb-cccc")
        dialog.title.setText("Manual report")
        dialog.accept()
        self.assertEqual(dialog.result(), QDialog.Accepted)
        self.assertEqual(dialog.data()["repository"], "example/project")
        self.assertEqual(dialog.data()["source"], "manual")
        for key in ("platform", "program", "report_reference"):
            self.assertEqual(dialog.data()[key], "")

    def test_edit_dialog_prefills_metadata_and_preserves_original_submission_date(self):
        report_id = self.db.upsert_report(self.bounty(state="custom_program_status"))
        report = self.db.get_report(report_id)
        dialog = main.ReportDialog(self.window, report=report)
        self.assertEqual(dialog.source.currentData(), "bug_bounty")
        self.assertEqual(dialog.repo.text(), report["repository"])
        self.assertEqual(dialog.platform.currentText(), "HackerOne")
        self.assertEqual(dialog.program.text(), "Example program")
        self.assertEqual(dialog.report_reference.text(), "H1-2048")
        self.assertEqual(dialog.title.text(), report["title"])
        self.assertEqual(dialog.url.text(), report["html_url"])
        self.assertEqual(dialog.notes.toPlainText(), report["notes"])
        self.assertEqual(dialog.state.currentText(), "custom_program_status")
        dialog.state.setCurrentText("resolved")
        self.assertEqual(dialog.data()["submitted_at"], report["submitted_at"])

    def test_add_bounty_action_saves_record_without_adding_target_to_github_repositories(self):
        self.db.add_repository("existing/project")
        self.window.search.setText("no results")
        self.window.source_filter.setCurrentIndex(self.window.source_filter.findData("github"))
        self.window.state_filter.setCurrentText("closed")

        def fill_and_accept(dialog):
            self.assertEqual(dialog.source.currentData(), "bug_bounty")
            dialog.repo.setText("api.example.test")
            dialog.title.setText("Synthetic bounty report")
            dialog.platform.setCurrentText("Bugcrowd")
            dialog.program.setText("Example enterprise")
            dialog.report_reference.setText("BC-100")
            dialog.state.setCurrentText("submitted")
            dialog.accept()
            return dialog.result()

        with patch.object(main.ReportDialog, "exec", new=fill_and_accept):
            self.window.add_report(source="bug_bounty")
        self.assertEqual(len(self.db.list_reports()), 1)
        report = self.db.list_reports()[0]
        self.assertEqual(report["source"], "bug_bounty")
        self.assertEqual(report["platform"], "Bugcrowd")
        self.assertEqual(report["report_reference"], "BC-100")
        self.assertEqual(self.db.list_repositories(), ["existing/project"])
        self.assertEqual(self.window.selected_report_id(), report["id"])
        self.assertEqual(self.window.source_filter.currentData(), "")
        self.assertEqual(self.window.state_filter.currentText(), "전체")
        self.assertEqual(self.window.search.text(), "")
        self.assertEqual(self.window.stack.currentIndex(), 1)
        self.assertEqual(self.window.card_bounty.text(), "1")

    def test_manual_add_still_registers_normalized_github_repository(self):
        def fill_and_accept(dialog):
            dialog.repo.setText("https://github.com/example/manual-project")
            dialog.title.setText("Manual GitHub report")
            dialog.accept()
            return dialog.result()

        with patch.object(main.ReportDialog, "exec", new=fill_and_accept):
            self.window.add_report()
        report = self.db.list_reports()[0]
        self.assertEqual(report["source"], "manual")
        self.assertEqual(report["repository"], "example/manual-project")
        self.assertEqual(self.db.list_repositories(), ["example/manual-project"])

    def test_edit_selected_updates_in_place_and_preserves_dates_and_annotations(self):
        report_id = self.db.upsert_report(self.bounty())
        self.db.update_vendor_response(report_id, "Acknowledged by program")
        self.window.refresh_all()
        self.select_report(report_id)
        before = dict(self.db.get_report(report_id))

        def modify_and_accept(dialog):
            self.assertEqual(dialog.report["id"], report_id)
            self.assertEqual(dialog.state.currentText(), "submitted")
            dialog.title.setText("Updated bounty title")
            dialog.state.setCurrentText("accepted")
            dialog.report_reference.setText("H1-2048-updated")
            dialog.accept()
            return dialog.result()

        with patch.object(main.ReportDialog, "exec", new=modify_and_accept):
            self.window.edit_selected()
        report = self.db.get_report(report_id)
        self.assertEqual(len(self.db.list_reports()), 1)
        self.assertEqual(report["id"], report_id)
        self.assertEqual(report["title"], "Updated bounty title")
        self.assertEqual(report["state"], "accepted")
        self.assertEqual(report["submitted_at"], before["submitted_at"])
        self.assertEqual(report["notes"], before["notes"])
        self.assertEqual(report["vendor_response"], before["vendor_response"])
        self.assertEqual(self.window.selected_report_id(), report_id)
        self.assertIn("accepted", self.window.detail_meta.text())
        status_events = [event for event in self.db.list_events(report_id) if event["event_type"] == "status"]
        self.assertEqual([(event["old_value"], event["new_value"]) for event in status_events],
                         [("submitted", "accepted")])
        self.assertEqual(self.db.list_repositories(), [])

    def test_bounty_published_is_distinct_from_accepted_and_uses_shared_filter(self):
        report_id = self.db.upsert_report(self.bounty(state="accepted"))
        github_id = self.db.upsert_report(self.github(state="published"))
        self.window.refresh_all()
        self.assertEqual(self.window.card_published.text(), "1")

        dialog = main.ReportDialog(self.window, report=self.db.get_report(report_id))
        self.assertIn("published", [dialog.state.itemText(i) for i in range(dialog.state.count())])
        dialog.state.setCurrentText("published")
        dialog.accept()
        self.assertEqual(dialog.result(), QDialog.Accepted)
        self.db.update_report(report_id, dialog.data())
        self.window.refresh_all()

        self.assertEqual(self.db.get_report(report_id)["state"], "published")
        self.assertEqual(self.window.card_published.text(), "2")
        self.window.state_filter.setCurrentText("published")
        self.assertEqual(set(self.visible_ids()), {report_id, github_id})
        self.window.source_filter.setCurrentIndex(self.window.source_filter.findData("github"))
        self.assertEqual(self.visible_ids(), [github_id])
        self.window.source_filter.setCurrentIndex(self.window.source_filter.findData("bug_bounty"))
        self.assertEqual(self.visible_ids(), [report_id])
        status_events = [event for event in self.db.list_events(report_id)
                         if event["event_type"] == "status"]
        self.assertEqual([(event["old_value"], event["new_value"]) for event in status_events],
                         [("accepted", "published")])

    def test_source_state_and_metadata_search_filters_compose(self):
        bounty_id, github_id, manual_id = self.seed_mixed_reports()
        self.assertEqual(set(self.visible_ids()), {bounty_id, github_id, manual_id})
        self.window.source_filter.setCurrentIndex(self.window.source_filter.findData("github"))
        self.assertEqual(set(self.visible_ids()), {github_id, manual_id})
        self.window.state_filter.setCurrentText("draft")
        self.assertEqual(self.visible_ids(), [manual_id])
        self.window.state_filter.setCurrentText("전체")
        self.window.source_filter.setCurrentIndex(self.window.source_filter.findData("bug_bounty"))
        self.window.state_filter.setCurrentText("submitted")
        for query in ("hackerone", "EXAMPLE PROGRAM", "H1-2048", "research notes"):
            with self.subTest(query=query):
                self.window.search.setText(query)
                self.assertEqual(self.visible_ids(), [bounty_id])
        self.window.state_filter.setCurrentText("accepted")
        self.assertEqual(self.visible_ids(), [])

    def test_hidden_id_selection_survives_refresh_and_filter_clears_detail(self):
        bounty_id, github_id, _ = self.seed_mixed_reports()
        self.assertTrue(self.window.report_table.isColumnHidden(main.REPORT_ID_COLUMN))
        self.assertTrue(self.window.recent_table.isColumnHidden(main.REPORT_ID_COLUMN))
        self.select_report(bounty_id)
        self.assertEqual(self.window.current_report_id, bounty_id)
        self.assertTrue(self.window.edit_button.isEnabled())
        self.assertIn("HackerOne", self.window.detail_meta.text())
        self.assertIn("H1-2048", self.window.detail_meta.text())
        self.assertEqual(self.window.detail_notes.toPlainText(), "Synthetic research notes")
        self.window.refresh_all()
        self.assertEqual(self.window.current_report_id, bounty_id)
        self.assertEqual(self.window.selected_report_id(), bounty_id)
        self.window.search.setText("Dependency advisory")
        self.assertEqual(self.visible_ids(), [github_id])
        self.assertIsNone(self.window.current_report_id)
        self.assertIsNone(self.window.selected_report_id())
        self.assertEqual(self.window.detail_title.text(), "항목을 선택하세요")
        self.assertEqual(self.window.detail_meta.text(), "")
        for field in (self.window.detail_notes, self.window.detail_vendor, self.window.detail_history):
            self.assertEqual(field.toPlainText(), "")
        self.assertFalse(self.window.edit_button.isEnabled())

    def test_existing_github_rows_render_default_metadata_and_disable_core_edit(self):
        _, github_id, _ = self.seed_mixed_reports()
        row = self.db.get_report(github_id)
        for field in ("platform", "program", "report_reference"):
            self.assertEqual(row[field], "")
        self.select_report(github_id)
        selected_row = self.window.report_table.currentRow()
        self.assertEqual(self.window.report_table.item(selected_row, 0).text(), "GitHub (동기화)")
        self.assertEqual(self.window.report_table.item(selected_row, 6).text(), "-")
        self.assertEqual(self.window.report_table.item(selected_row, 7).text(), "GHSA-aaaa-bbbb-cccc")
        self.assertIn("GHSA-aaaa-bbbb-cccc", self.window.detail_meta.text())
        self.assertFalse(self.window.edit_button.isEnabled())
        before = dict(row)
        with patch.object(main, "ReportDialog") as dialog, patch.object(main.QMessageBox, "information") as info:
            self.window.edit_selected()
        dialog.assert_not_called()
        info.assert_called_once()
        self.assertEqual(dict(self.db.get_report(github_id)), before)

    def test_filtered_csv_and_excel_include_bounty_metadata_and_only_matching_history(self):
        bounty_id, github_id, manual_id = self.seed_mixed_reports()
        self.db.update_report(bounty_id, {"state": "accepted"})
        self.db.update_vendor_response(bounty_id, "Program accepted the report")
        self.db.update_notes(github_id, "Other report event")
        self.db.update_notes(manual_id, "Another excluded event")
        self.window.source_filter.setCurrentIndex(self.window.source_filter.findData("bug_bounty"))
        self.window.state_filter.setCurrentText("accepted")
        self.window.search.setText("H1-2048")
        csv_path = Path(self.temp_dir.name) / "filtered.csv"
        xlsx_path = Path(self.temp_dir.name) / "filtered.xlsx"
        with patch.object(main.QFileDialog, "getSaveFileName", return_value=(str(csv_path), "CSV (*.csv)")):
            self.window.export_csv()
        with csv_path.open(newline="", encoding="utf-8-sig") as handle:
            exported = list(csv.DictReader(handle))
        self.assertEqual(len(exported), 1)
        for key, expected in {
            "source": "bug_bounty", "platform": "HackerOne", "program": "Example program",
            "report_reference": "H1-2048", "state": "accepted",
            "vendor_response": "Program accepted the report",
        }.items():
            self.assertEqual(exported[0][key], expected)
        with patch.object(main.QFileDialog, "getSaveFileName", return_value=(str(xlsx_path), "Excel (*.xlsx)")):
            self.window.export_xlsx()
        workbook = load_workbook(xlsx_path, read_only=True, data_only=True)
        try:
            rows = list(workbook["Vulnerability Reports"].values)
            self.assertEqual(len(rows), 2)
            excel_report = dict(zip(rows[0], rows[1]))
            for key, expected in {"Source": "bug_bounty", "Platform": "HackerOne",
                                  "Program": "Example program", "Report Reference": "H1-2048",
                                  "Status": "accepted"}.items():
                self.assertEqual(excel_report[key], expected)
            history_rows = list(workbook["Change History"].values)
            history = [dict(zip(history_rows[0], values)) for values in history_rows[1:]]
            self.assertEqual(len(history), len(self.db.list_events(bounty_id, 1000)))
            self.assertEqual({event["Report ID"] for event in history}, {bounty_id})
            self.assertEqual({event["Source"] for event in history}, {"bug_bounty"})
            self.assertEqual({event["Report Reference"] for event in history}, {"H1-2048"})
            self.assertTrue({"created", "status", "vendor_response"} <= {event["Event"] for event in history})
        finally:
            workbook.close()

    def test_optional_offscreen_preview_uses_synthetic_data(self):
        preview_dir = os.getenv("VULN_TRACKER_UI_PREVIEW_DIR")
        if not preview_dir:
            self.skipTest("Set VULN_TRACKER_UI_PREVIEW_DIR to capture offline preview images")
        directory = Path(preview_dir)
        directory.mkdir(parents=True, exist_ok=True)
        # Windows' offscreen plugin does not discover installed fonts itself.
        font_directory = Path(os.getenv("WINDIR", "C:/Windows")) / "Fonts"
        for filename in ("malgun.ttf", "malgunbd.ttf", "segoeui.ttf", "segoeuib.ttf"):
            font_path = font_directory / filename
            if font_path.exists():
                QFontDatabase.addApplicationFont(str(font_path))
        self.app.setFont(QFont("Malgun Gothic", 10))
        self.window.setFont(self.app.font())
        bounty_id, _, _ = self.seed_mixed_reports()
        self.db.update_report(bounty_id, {"state": "accepted"})
        self.db.update_vendor_response(bounty_id, "Synthetic response: accepted, remediation in progress.")
        self.window.refresh_all()
        self.window.show()
        self.select_report(bounty_id)
        self.app.processEvents()
        self.assertTrue(self.window.grab().save(str(directory / "reports-window.png")))
        self.window.show_page(0)
        self.app.processEvents()
        self.assertTrue(self.window.grab().save(str(directory / "dashboard-window.png")))
        dialog = main.ReportDialog(self.window, report=self.db.get_report(bounty_id))
        dialog.show()
        self.app.processEvents()
        self.assertTrue(dialog.grab().save(str(directory / "bounty-dialog.png")))
        dialog.close()


if __name__ == "__main__":
    unittest.main()
