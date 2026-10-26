"""Offline checks for the report list and detail editing workflow."""

import os
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QApplication, QDialog, QMessageBox

import main
from db import Database


class UsabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.db = Database(Path(self.directory.name) / "tracker.db")
        self.addCleanup(self.db.close)
        patches = ExitStack()
        self.addCleanup(patches.close)
        patches.enter_context(patch.object(main, "Database", return_value=self.db))
        settings_path = str(Path(self.directory.name) / "settings.ini")
        patches.enter_context(patch.object(
            main, "QSettings", side_effect=lambda *args: QSettings(settings_path, QSettings.IniFormat)))
        patches.enter_context(patch.object(main.MainWindow, "refresh_connection_status"))
        patches.enter_context(patch.object(
            main.keyring, "get_password", side_effect=AssertionError("Unexpected credential access")))
        self.window = main.MainWindow()
        self.addCleanup(self.window.close)
        self.window.show_page(1)

    def add_bounty(self, title, state="submitted"):
        return self.db.upsert_report({
            "repository": "example.test", "title": title,
            "source": "bug_bounty", "state": state,
            "submitted_at": "2026-01-02T03:04:05", "updated_at": "2026-01-03T04:05:06",
        })

    def select(self, report_id):
        for row in range(self.window.report_table.rowCount()):
            if int(self.window.report_table.item(row, main.REPORT_ID_COLUMN).text()) == report_id:
                self.window.report_table.selectRow(row)
                self.app.processEvents()
                return
        self.fail(f"Report {report_id} is not visible")

    def test_source_filter_only_offers_relevant_states(self):
        self.add_bounty("Published report", "published")
        self.window.refresh_all()
        self.window.source_filter.setCurrentIndex(self.window.source_filter.findData("bug_bounty"))
        self.assertIn("published", [self.window.state_filter.itemText(i)
                                    for i in range(self.window.state_filter.count())])
        self.window.state_filter.setCurrentText("accepted")
        self.window.source_filter.setCurrentIndex(self.window.source_filter.findData("github"))
        self.assertEqual(self.window.state_filter.currentText(), "전체")
        self.assertNotIn("accepted", [self.window.state_filter.itemText(i)
                                      for i in range(self.window.state_filter.count())])
        self.assertIn("검색 결과 0건", self.window.result_count.text())

    def test_detail_edits_autosave_on_pause_selection_and_close(self):
        first = self.add_bounty("First report")
        second = self.add_bounty("Second report")
        self.window.refresh_all()
        self.select(first)
        self.window.detail_notes.setPlainText("First note")
        self.window.detail_vendor.setPlainText("Vendor response")
        self.assertEqual(self.db.get_report(first)["notes"], "")
        self.window._autosave_detail()
        self.assertEqual(self.db.get_report(first)["notes"], "First note")
        self.assertEqual(self.db.get_report(first)["vendor_response"], "Vendor response")
        self.assertIn("저장됨", self.window.detail_save_status.text())
        self.window.detail_notes.setPlainText("Updated first note")
        self.select(second)
        self.assertEqual(self.db.get_report(first)["notes"], "Updated first note")
        self.window.detail_notes.setPlainText("Second note")
        self.window.close()
        reopened = Database(Path(self.directory.name) / "tracker.db")
        try:
            self.assertEqual(reopened.get_report(second)["notes"], "Second note")
        finally:
            reopened.close()

    def test_recent_report_opens_detail_and_clears_filters(self):
        first = self.add_bounty("First report")
        second = self.add_bounty("Second report")
        self.window.refresh_all()
        self.select(first)
        self.window.detail_notes.setPlainText("Pending note")
        self.window.search.setText("nothing matches")
        self.assertEqual(self.db.get_report(first)["notes"], "Pending note")
        self.window.source_filter.setCurrentIndex(self.window.source_filter.findData("github"))
        recent_row = next(row for row in range(self.window.recent_table.rowCount())
                          if int(self.window.recent_table.item(row, main.REPORT_ID_COLUMN).text()) == second)
        self.window.open_recent_report(recent_row, 0)
        self.assertEqual(self.window.stack.currentIndex(), 1)
        self.assertEqual(self.window.selected_report_id(), second)
        self.assertEqual(self.window.current_report_id, second)
        self.assertEqual(self.window.search.text(), "")
        self.assertEqual(self.window.source_filter.currentData(), "")

    def test_edit_dialog_receives_pending_detail_notes(self):
        report_id = self.add_bounty("Editable report")
        self.window.refresh_all()
        self.select(report_id)
        self.window.detail_notes.setPlainText("Pending analysis")

        def inspect_dialog(dialog):
            self.assertEqual(dialog.notes.toPlainText(), "Pending analysis")
            return QDialog.Rejected

        with patch.object(main.ReportDialog, "exec", new=inspect_dialog):
            self.window.edit_selected()
        self.assertEqual(self.db.get_report(report_id)["notes"], "Pending analysis")

    def test_delete_pending_detail_does_not_write_to_next_report(self):
        first = self.add_bounty("Delete this report")
        second = self.add_bounty("Keep this report")
        self.window.refresh_all()
        self.select(first)
        self.window.detail_notes.setPlainText("Must not migrate")
        with patch.object(main.QMessageBox, "question", return_value=QMessageBox.Yes):
            self.window.delete_selected()
        self.assertIsNone(self.db.get_report(first))
        self.select(second)
        self.window._autosave_detail()
        self.assertEqual(self.db.get_report(second)["notes"] or "", "")


if __name__ == "__main__":
    unittest.main()
