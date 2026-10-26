"""Checks for what a person sees while navigating, deleting, and exporting."""

import os
import re
import sqlite3
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

os.environ["QT_QPA_PLATFORM"] = "offscreen"

from openpyxl import load_workbook
from PySide6.QtCore import QSettings, Qt
from PySide6.QtWidgets import QApplication, QDialog, QDialogButtonBox, QLabel, QMessageBox, QPushButton

import main
from db import Database


class HumanWorkflowTests(unittest.TestCase):
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

    def add_report(self, title, *, source="bug_bounty", state="submitted", url=None):
        return self.db.upsert_report({
            "repository": "example.test" if source == "bug_bounty" else "example/project",
            "title": title,
            "source": source,
            "ghsa_id": "GHSA-aaaa-bbbb-cccc" if source == "github" else None,
            "state": state,
            "html_url": url,
            "submitted_at": "2026-01-02T03:04:05",
            "updated_at": "2026-01-03T04:05:06",
        })

    def select(self, report_id):
        for row in range(self.window.report_table.rowCount()):
            item = self.window.report_table.item(row, main.REPORT_ID_COLUMN)
            if int(item.text()) == report_id:
                self.window.report_table.selectRow(row)
                self.app.processEvents()
                return row
        self.fail(f"Report {report_id} is not visible")

    def test_dashboard_export_includes_all_reports_after_list_was_filtered(self):
        self.add_report("Accepted bounty", state="accepted")
        self.add_report("Published bounty", state="published")
        self.window.refresh_all()
        self.window.state_filter.setCurrentText("accepted")
        self.assertEqual(self.window.report_table.rowCount(), 1)
        for page_index, name in ((0, "dashboard"), (2, "settings")):
            with self.subTest(page=name):
                self.window.show_page(page_index)
                path = Path(self.directory.name) / f"{name}-export.xlsx"
                with patch.object(main.QFileDialog, "getSaveFileName", return_value=(str(path), "Excel (*.xlsx)")):
                    self.window.export_xlsx()
                workbook = load_workbook(path, read_only=True, data_only=True)
                try:
                    rows = list(workbook["Vulnerability Reports"].values)
                    self.assertEqual(len(rows), 3, "Non-list export should include every report")
                    self.assertEqual({row[1] for row in rows[1:]},
                                     {"Accepted bounty", "Published bounty"})
                finally:
                    workbook.close()

    def test_narrow_window_stacks_list_and_detail(self):
        self.window.show()
        self.app.processEvents()
        self.window.resize(980, 620)
        self.app.processEvents()
        self.assertEqual(self.window.report_splitter.orientation(), Qt.Vertical)
        self.window.resize(1220, 700)
        self.app.processEvents()
        self.assertEqual(self.window.report_splitter.orientation(), Qt.Horizontal)

    def test_failed_autosave_restores_visible_selection(self):
        first = self.add_report("First report")
        second = self.add_report("Second report")
        self.window.refresh_all()
        self.select(first)
        self.window.detail_notes.setPlainText("Still unsaved")
        with patch.object(self.db, "update_notes", side_effect=sqlite3.Error("disk full")), \
             patch.object(main.QMessageBox, "warning"):
            self.select(second)
        self.assertEqual(self.window.current_report_id, first)
        self.assertEqual(self.window.selected_report_id(), first)
        self.assertEqual(self.window.detail_title.text(), "First report")
        self.assertIsNotNone(self.db.get_report(first))
        self.assertIsNotNone(self.db.get_report(second))

    def test_dashboard_published_card_opens_matching_reports_and_reset_restores_all(self):
        self.add_report("Accepted bounty", state="accepted")
        published_id = self.add_report("Published bounty", state="published")
        self.window.refresh_all()
        self.window.show_page(0)

        self.window.card_published.parentWidget().click()

        self.assertEqual(self.window.stack.currentIndex(), 1)
        self.assertEqual(self.window.state_filter.currentText(), "published")
        self.assertEqual(self.window.report_table.rowCount(), 1)
        self.assertEqual(int(self.window.report_table.item(0, main.REPORT_ID_COLUMN).text()),
                         published_id)
        self.window.clear_filters()
        self.assertEqual(self.window.state_filter.currentText(), "전체")
        self.assertEqual(self.window.report_table.rowCount(), 2)

    def test_no_selection_disables_detail_editors(self):
        report_id = self.add_report("Selectable bounty")
        self.window.refresh_all()
        self.assertFalse(self.window.detail_notes.isEnabled())
        self.assertFalse(self.window.detail_vendor.isEnabled())

        self.select(report_id)
        self.assertTrue(self.window.detail_notes.isEnabled())
        self.assertTrue(self.window.detail_vendor.isEnabled())
        self.window.search.setText("no matching reports")
        self.assertFalse(self.window.detail_notes.isEnabled())
        self.assertFalse(self.window.detail_vendor.isEnabled())

    def test_new_bounty_dialog_starts_submitted_with_korean_actions(self):
        dialog = main.ReportDialog(self.window, source="bug_bounty")
        self.addCleanup(dialog.close)
        self.assertEqual(dialog.source.currentData(), "bug_bounty")
        self.assertEqual(dialog.state.currentText(), "submitted")
        button_box = dialog.findChild(QDialogButtonBox)
        self.assertEqual(button_box.button(QDialogButtonBox.Save).text(), "저장")
        self.assertEqual(button_box.button(QDialogButtonBox.Cancel).text(), "취소")

    def test_duplicate_github_identity_keeps_typed_dialog_fields_for_retry(self):
        self.db.upsert_report({
            "repository": "example/project", "title": "Existing report",
            "source": "manual", "ghsa_id": "GHSA-aaaa-bbbb-cccc", "state": "draft",
        })
        typed_title = "Work in progress with evidence"
        calls = []

        def enter_then_cancel(dialog):
            calls.append(dialog)
            if len(calls) == 1:
                dialog.repo.setText("example/project")
                dialog.title.setText(typed_title)
                dialog.ghsa.setText("GHSA-aaaa-bbbb-cccc")
                dialog.accept()
                return dialog.result()
            self.assertIs(dialog, calls[0])
            self.assertEqual(dialog.repo.text(), "example/project")
            self.assertEqual(dialog.title.text(), typed_title)
            self.assertEqual(dialog.ghsa.text(), "GHSA-aaaa-bbbb-cccc")
            return QDialog.Rejected

        with patch.object(main.ReportDialog, "exec", new=enter_then_cancel), \
                patch.object(main.QMessageBox, "warning") as warning:
            self.window.add_report()

        self.assertEqual(len(calls), 2)
        warning.assert_called_once()
        self.assertEqual(len(self.db.list_reports()), 1)

    def test_report_list_double_click_keeps_detail_without_opening_browser(self):
        report_id = self.add_report(
            "Report with link", url="https://example.test/reports/123")
        self.window.refresh_all()
        row = self.select(report_id)

        with patch.object(main.webbrowser, "open") as browser_open:
            self.window.report_table.cellDoubleClicked.emit(row, 2)

        browser_open.assert_not_called()
        self.assertEqual(self.window.stack.currentIndex(), 1)
        self.assertEqual(self.window.current_report_id, report_id)
        self.assertEqual(self.window.detail_title.text(), "Report with link")

    def test_synced_github_delete_is_blocked_or_warns_about_reappearance(self):
        report_id = self.add_report("Synced advisory", source="github")
        self.window.refresh_all()
        self.select(report_id)

        if self.window.delete_button.isEnabled():
            with patch.object(main.QMessageBox, "question", return_value=QMessageBox.No) as confirm:
                self.window.delete_selected()
            self.assertTrue(confirm.called)
            message = " ".join(str(arg) for arg in confirm.call_args.args)
            self.assertIn("동기화", message)
            self.assertRegex(message, r"다시|재등록|재생성|복원")
        self.assertIsNotNone(self.db.get_report(report_id))

    def test_filtered_export_count_is_visible_before_export(self):
        self.add_report("Matching bounty", state="accepted")
        self.add_report("Other bounty", state="published")
        self.window.refresh_all()
        self.window.state_filter.setCurrentText("accepted")
        self.assertEqual(self.window.report_table.rowCount(), 1)

        self.window.show()
        self.app.processEvents()
        page = self.window.stack.currentWidget()
        texts = [widget.text() for widget in page.findChildren(QLabel) if widget.isVisible()]
        texts.extend(widget.text() for widget in page.findChildren(QPushButton)
                     if widget.isVisible())
        self.assertTrue(
            any("1건" in text and re.search(r"내보내기|CSV|Excel|저장", text) for text in texts),
            f"The filtered export scope should be visible near the controls: {texts}",
        )


if __name__ == "__main__":
    unittest.main()
