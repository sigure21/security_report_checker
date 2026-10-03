from __future__ import annotations

import csv
import sys
import webbrowser
from datetime import datetime
from pathlib import Path

import keyring
from openpyxl import Workbook
from openpyxl.styles import Font
from PySide6.QtCore import QThread, Signal, Qt, QSettings
from PySide6.QtGui import QAction, QColor, QBrush, QFont
from PySide6.QtWidgets import (
    QApplication, QAbstractItemView, QComboBox, QDialog, QDialogButtonBox,
    QFileDialog, QFormLayout, QFrame, QHBoxLayout, QHeaderView, QLabel,
    QLineEdit, QListWidget, QMainWindow, QMessageBox, QPushButton,
    QPlainTextEdit, QSplitter, QStackedWidget, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

from db import Database
from github_api import GitHubClient, repository_from_input, request_device_code, poll_device_token

KEYRING_SERVICE = "GitHubVulnTracker"
KEYRING_USER = "github_oauth_token"
KEYRING_REFRESH = "github_oauth_refresh_token"
OAUTH_SCOPE = "repo"


def fmt_date(value: str | None) -> str:
    if not value:
        return "-"
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return value


class SyncWorker(QThread):
    progress = Signal(str)
    item = Signal(dict)
    done = Signal(int, int)
    failed = Signal(str)

    def __init__(self, token: str, repos: list[str]):
        super().__init__()
        self.token = token
        self.repos = repos

    def run(self):
        try:
            client = GitHubClient(self.token)
            login = client.current_user()
            total = failures = 0
            for repo in self.repos:
                self.progress.emit(f"동기화 중: {repo}")
                try:
                    for report in client.sync_repository(repo, login):
                        self.item.emit(report)
                        total += 1
                except Exception as e:
                    failures += 1
                    self.progress.emit(f"실패: {repo} ({e})")
            self.done.emit(total, failures)
        except Exception as e:
            self.failed.emit(str(e))


class OAuthWorker(QThread):
    code_ready = Signal(str, str, int)
    authenticated = Signal(str, str, str)
    failed = Signal(str)

    def __init__(self, client_id: str):
        super().__init__()
        self.client_id = client_id
        self._stop = False

    def cancel(self):
        self._stop = True

    def run(self):
        try:
            device = request_device_code(self.client_id, OAUTH_SCOPE)
            self.code_ready.emit(device["verification_uri"], device["user_code"], int(device.get("expires_in", 900)))
            token_data = poll_device_token(
                self.client_id, device["device_code"], int(device.get("interval", 5)),
                int(device.get("expires_in", 900)), should_stop=lambda: self._stop
            )
            token = token_data["access_token"]
            login = GitHubClient(token).current_user()
            self.authenticated.emit(login, token, token_data.get("refresh_token") or "")
        except Exception as e:
            self.failed.emit(str(e))


class ReportDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("취약점 제보 추가")
        self.setMinimumWidth(520)
        form = QFormLayout(self)
        self.repo = QLineEdit(); self.repo.setPlaceholderText("owner/repository")
        self.title = QLineEdit()
        self.ghsa = QLineEdit()
        self.cve = QLineEdit()
        self.state = QComboBox(); self.state.addItems(["local", "triage", "draft", "published", "closed"])
        self.severity = QComboBox(); self.severity.addItems(["", "low", "moderate", "high", "critical"])
        self.url = QLineEdit()
        self.notes = QPlainTextEdit(); self.notes.setMaximumHeight(100)
        for label, widget in [("Repository", self.repo), ("제목", self.title), ("GHSA", self.ghsa),
                              ("CVE", self.cve), ("상태", self.state), ("Severity", self.severity),
                              ("URL", self.url), ("메모", self.notes)]:
            form.addRow(label, widget)
        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept); buttons.rejected.connect(self.reject)
        form.addRow(buttons)

    def data(self):
        now = datetime.now().isoformat(timespec="seconds")
        return {
            "repository": self.repo.text().strip(), "title": self.title.text().strip(),
            "ghsa_id": self.ghsa.text().strip() or None, "cve_id": self.cve.text().strip() or None,
            "state": self.state.currentText(), "severity": self.severity.currentText() or None,
            "html_url": self.url.text().strip() or None, "notes": self.notes.toPlainText(),
            "submitted_at": now, "updated_at": now, "source": "manual",
        }


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.db = Database()
        self.worker = None
        self.current_report_id = None
        self.settings = QSettings("LocalTools", "GitHubVulnTracker")
        self.auth_worker = None
        self.setWindowTitle("GitHub Vulnerability Tracker v0.3")
        self.resize(1480, 880)
        self._build_ui(); self._apply_style(); self.refresh_all()

    def _build_ui(self):
        root = QWidget(); self.setCentralWidget(root)
        outer = QHBoxLayout(root); outer.setContentsMargins(0, 0, 0, 0); outer.setSpacing(0)
        nav = QFrame(); nav.setObjectName("nav"); nav.setFixedWidth(220)
        nl = QVBoxLayout(nav)
        brand = QLabel("VULN\nTRACKER"); brand.setObjectName("brand"); nl.addWidget(brand)
        self.btn_dashboard = QPushButton("대시보드")
        self.btn_reports = QPushButton("제보 목록")
        self.btn_settings = QPushButton("GitHub 설정")
        for i, b in enumerate([self.btn_dashboard, self.btn_reports, self.btn_settings]):
            b.setCheckable(True); b.clicked.connect(lambda _, idx=i: self.show_page(idx)); nl.addWidget(b)
        nl.addStretch(1); nl.addWidget(QLabel("Local-first · SQLite · v0.3")); outer.addWidget(nav)
        self.stack = QStackedWidget(); self.stack.addWidget(self._dashboard_page()); self.stack.addWidget(self._reports_page()); self.stack.addWidget(self._settings_page())
        outer.addWidget(self.stack, 1); self.show_page(0)
        a = QAction("취약점 추가", self); a.setShortcut("Ctrl+N"); a.triggered.connect(self.add_report); self.addAction(a)
        e = QAction("Excel 내보내기", self); e.setShortcut("Ctrl+E"); e.triggered.connect(self.export_xlsx); self.addAction(e)

    def _dashboard_page(self):
        w = QWidget(); l = QVBoxLayout(w); l.setContentsMargins(28,24,28,24)
        title = QLabel("Security Advisory Dashboard"); title.setObjectName("pageTitle"); l.addWidget(title)
        cards = QHBoxLayout()
        self.card_total = self._stat_card(cards, "전체")
        self.card_triage = self._stat_card(cards, "Triage")
        self.card_draft = self._stat_card(cards, "Draft")
        self.card_published = self._stat_card(cards, "Published")
        self.card_cve = self._stat_card(cards, "CVE 발급")
        self.card_changed = self._stat_card(cards, "최근 변경")
        l.addLayout(cards)
        h = QHBoxLayout()
        for text, fn in [("+ 수동 등록", self.add_report), ("GitHub 링크 추가", self.add_repo_from_link_dialog), ("GitHub 동기화", self.sync_github), ("Excel 내보내기", self.export_xlsx)]:
            b = QPushButton(text); b.clicked.connect(fn); h.addWidget(b)
        h.addStretch(); l.addLayout(h)
        lab = QLabel("최근 업데이트"); lab.setObjectName("sectionTitle"); l.addWidget(lab)
        self.recent_table = self._make_table(); l.addWidget(self.recent_table)
        return w

    def _stat_card(self, layout, label):
        f = QFrame(); f.setObjectName("card"); fl = QVBoxLayout(f)
        value = QLabel("0"); value.setObjectName("statValue"); fl.addWidget(value); fl.addWidget(QLabel(label)); layout.addWidget(f); return value

    def _make_table(self):
        t = QTableWidget(0, 9)
        t.setHorizontalHeaderLabels(["Repo", "Title", "Status", "Severity", "CVE", "GHSA", "Updated", "Change", "ID"])
        t.setColumnHidden(8, True); t.setSelectionBehavior(QAbstractItemView.SelectRows); t.setEditTriggers(QAbstractItemView.NoEditTriggers); t.verticalHeader().setVisible(False)
        t.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents); t.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        for c in range(2,8): t.horizontalHeader().setSectionResizeMode(c, QHeaderView.ResizeToContents)
        return t

    def _reports_page(self):
        w = QWidget(); l = QVBoxLayout(w); l.setContentsMargins(28,24,28,24)
        title = QLabel("제보 목록"); title.setObjectName("pageTitle"); l.addWidget(title)
        controls = QHBoxLayout()
        self.search = QLineEdit(); self.search.setPlaceholderText("repo / GHSA / CVE / 제목 검색"); self.search.textChanged.connect(self.refresh_reports)
        self.state_filter = QComboBox(); self.state_filter.addItems(["전체","triage","draft","published","closed","local"]); self.state_filter.currentTextChanged.connect(self.refresh_reports)
        controls.addWidget(self.search,1); controls.addWidget(self.state_filter)
        for text, fn in [("+ 추가", self.add_report), ("링크 추가", self.add_repo_from_link_dialog), ("동기화", self.sync_github), ("CSV", self.export_csv), ("Excel", self.export_xlsx)]:
            b = QPushButton(text); b.clicked.connect(fn); controls.addWidget(b)
        l.addLayout(controls)
        splitter = QSplitter(Qt.Horizontal)
        self.report_table = self._make_table(); self.report_table.itemSelectionChanged.connect(self.show_selected_report); self.report_table.cellDoubleClicked.connect(lambda r,c:self.open_selected_url()); splitter.addWidget(self.report_table)
        detail = QFrame(); detail.setObjectName("detail"); dl = QVBoxLayout(detail)
        self.detail_title = QLabel("항목을 선택하세요"); self.detail_title.setWordWrap(True); self.detail_title.setObjectName("sectionTitle")
        self.detail_meta = QLabel(""); self.detail_meta.setWordWrap(True)
        self.detail_history = QPlainTextEdit(); self.detail_history.setReadOnly(True); self.detail_history.setMaximumHeight(150)
        self.detail_vendor = QPlainTextEdit(); self.detail_vendor.setPlaceholderText("GitHub advisory에서 확인한 벤더 답변을 붙여넣으세요. (REST API 자동 수집 불가)"); self.detail_vendor.setMaximumHeight(120)
        self.detail_notes = QPlainTextEdit(); self.detail_notes.setPlaceholderText("분석 메모, 재현 조건, 후속 계획 등")
        for widget in [self.detail_title, self.detail_meta, QLabel("변경 이력"), self.detail_history, QLabel("벤더 답변"), self.detail_vendor, QLabel("개인 메모"), self.detail_notes]: dl.addWidget(widget)
        br = QHBoxLayout()
        for text, fn in [("저장", self.save_detail), ("GitHub에서 열기", self.open_selected_url), ("삭제", self.delete_selected)]:
            b=QPushButton(text); b.clicked.connect(fn); br.addWidget(b)
        dl.addLayout(br); splitter.addWidget(detail); splitter.setSizes([980,420]); l.addWidget(splitter)
        return w

    def _settings_page(self):
        w=QWidget(); l=QVBoxLayout(w); l.setContentsMargins(28,24,28,24)
        title=QLabel("GitHub 연결"); title.setObjectName("pageTitle"); l.addWidget(title)
        info=QLabel(
            "브라우저에서 GitHub OAuth Device Flow로 로그인합니다. Client Secret은 필요하지 않습니다.\n"
            "미공개 Repository Security Advisory 조회를 위해 OAuth 'repo' 권한을 요청합니다. 이 권한은 저장소 접근 범위가 넓으므로 개인용 OAuth App만 사용하세요."
        ); info.setWordWrap(True); l.addWidget(info)

        oauth_box=QFrame(); oauth_box.setObjectName("card"); ob=QVBoxLayout(oauth_box)
        self.connection_label=QLabel("연결 상태 확인 중..."); self.connection_label.setObjectName("sectionTitle"); ob.addWidget(self.connection_label)
        form=QFormLayout()
        self.client_id_input=QLineEdit(); self.client_id_input.setPlaceholderText("예: Ov23li...")
        saved_client_id=self.settings.value("github/client_id", "", type=str); self.client_id_input.setText(saved_client_id)
        form.addRow("OAuth Client ID", self.client_id_input); ob.addLayout(form)
        auth_buttons=QHBoxLayout()
        login_btn=QPushButton("GitHub 로그인"); login_btn.clicked.connect(self.start_oauth_login)
        logout_btn=QPushButton("연결 해제"); logout_btn.clicked.connect(self.logout_github)
        register_btn=QPushButton("OAuth App 등록 페이지"); register_btn.clicked.connect(lambda: webbrowser.open("https://github.com/settings/applications/new"))
        auth_buttons.addWidget(login_btn); auth_buttons.addWidget(logout_btn); auth_buttons.addWidget(register_btn); auth_buttons.addStretch(1); ob.addLayout(auth_buttons)
        self.oauth_help=QLabel(
            "최초 1회: GitHub → Settings → Developer settings → OAuth Apps → New OAuth App에서 앱을 만들고 'Enable Device Flow'를 켠 뒤 Client ID만 입력하세요. "
            "Authorization callback URL은 Device Flow에서는 사용하지 않지만 등록 화면의 필수값이면 http://127.0.0.1 을 넣어도 됩니다."
        ); self.oauth_help.setWordWrap(True); ob.addWidget(self.oauth_help); l.addWidget(oauth_box)

        l.addWidget(QLabel("동기화할 저장소")); self.repo_list=QListWidget(); l.addWidget(self.repo_list,1)
        rr=QHBoxLayout(); self.repo_input=QLineEdit(); self.repo_input.setPlaceholderText("owner/repo 또는 https://github.com/owner/repo/security/advisories/GHSA-...")
        add=QPushButton("추가"); add.clicked.connect(self.add_repo); rem=QPushButton("선택 삭제"); rem.clicked.connect(self.remove_repo); rr.addWidget(self.repo_input,1); rr.addWidget(add); rr.addWidget(rem); l.addLayout(rr)
        self.sync_status=QLabel("준비"); l.addWidget(self.sync_status); test=QPushButton("연결 테스트 / 동기화"); test.clicked.connect(self.sync_github); l.addWidget(test)
        self.refresh_connection_status()
        return w

    def _apply_style(self):
        self.setStyleSheet("""
            QWidget { background:#101317; color:#e8edf2; font-size:13px; }
            #nav { background:#171b21; border-right:1px solid #2a3038; }
            #nav QPushButton { text-align:left; padding:12px; border:none; border-radius:6px; }
            #nav QPushButton:hover, #nav QPushButton:checked { background:#252c35; }
            #brand { font-size:24px; font-weight:800; padding:16px 6px 24px 6px; }
            #pageTitle { font-size:24px; font-weight:700; margin-bottom:8px; }
            #sectionTitle { font-size:16px; font-weight:700; }
            #card { background:#171b21; border:1px solid #2a3038; border-radius:10px; }
            #statValue { font-size:30px; font-weight:800; }
            #detail { background:#171b21; border:1px solid #2a3038; border-radius:8px; }
            QPushButton { background:#242b33; border:1px solid #343d48; padding:8px 12px; border-radius:6px; }
            QPushButton:hover { background:#303945; }
            QLineEdit,QPlainTextEdit,QComboBox,QListWidget,QTableWidget { background:#0d1014; border:1px solid #303741; border-radius:5px; padding:6px; }
            QHeaderView::section { background:#171b21; color:#cfd7df; padding:7px; border:none; border-bottom:1px solid #303741; }
            QTableWidget { gridline-color:#20262d; }
        """)

    def show_page(self, idx):
        self.stack.setCurrentIndex(idx)
        for i,b in enumerate([self.btn_dashboard,self.btn_reports,self.btn_settings]): b.setChecked(i==idx)
        if idx==2: self.refresh_repos()

    def refresh_all(self): self.refresh_reports(); self.refresh_dashboard(); self.refresh_repos()

    def filtered_reports(self):
        rows=self.db.list_reports(); q=self.search.text().strip().lower() if hasattr(self,"search") else ""; st=self.state_filter.currentText() if hasattr(self,"state_filter") else "전체"; out=[]
        for r in rows:
            hay=" ".join(str(r[k] or "") for k in ["repository","title","ghsa_id","cve_id","state","severity","vendor_response"]).lower()
            if q and q not in hay: continue
            if st!="전체" and r["state"]!=st: continue
            out.append(r)
        return out

    def change_label(self, r):
        events=self.db.list_events(r["id"],1)
        if not events: return "-"
        e=events[0]; m={"status":"STATUS","cve":"CVE","severity":"SEVERITY","github_update":"UPDATE","vendor_response":"VENDOR","created":"NEW"}
        return m.get(e["event_type"], e["event_type"].upper())

    def fill_table(self, table, rows):
        table.setRowCount(0)
        for r in rows:
            row=table.rowCount(); table.insertRow(row); change=self.change_label(r)
            vals=[r["repository"],r["title"],r["state"],r["severity"] or "-",r["cve_id"] or "-",r["ghsa_id"] or "-",fmt_date(r["updated_at"]),change,str(r["id"])]
            for col,val in enumerate(vals):
                item=QTableWidgetItem(str(val)); table.setItem(row,col,item)
                if col==7 and change in {"STATUS","CVE","VENDOR"}: item.setFont(QFont("Segoe UI",10,QFont.Bold))
            if r["state"]=="published": table.item(row,2).setForeground(QBrush(QColor("#69db7c")))
            elif r["state"]=="closed": table.item(row,2).setForeground(QBrush(QColor("#ff8787")))
            elif r["state"] in {"triage","draft"}: table.item(row,2).setForeground(QBrush(QColor("#ffd43b")))
            if r["cve_id"]: table.item(row,4).setForeground(QBrush(QColor("#74c0fc")))

    def refresh_reports(self):
        if hasattr(self,"report_table"): self.fill_table(self.report_table,self.filtered_reports())

    def refresh_dashboard(self):
        rows=self.db.list_reports(); self.card_total.setText(str(len(rows))); self.card_triage.setText(str(sum(r["state"]=="triage" for r in rows))); self.card_draft.setText(str(sum(r["state"]=="draft" for r in rows))); self.card_published.setText(str(sum(r["state"]=="published" for r in rows))); self.card_cve.setText(str(sum(bool(r["cve_id"]) for r in rows)))
        changed=sum(1 for r in rows if self.change_label(r) in {"STATUS","CVE","VENDOR"}); self.card_changed.setText(str(changed)); self.fill_table(self.recent_table,rows[:12])

    def add_report(self):
        d=ReportDialog(self)
        if d.exec()==QDialog.Accepted:
            data=d.data()
            if not data["repository"] or not data["title"]: QMessageBox.warning(self,"필수값","Repository와 제목은 필수입니다."); return
            self.db.upsert_report(data); self.db.add_repository(data["repository"]); self.refresh_all(); self.show_page(1)

    def add_repo_from_link_dialog(self):
        self.show_page(2); self.repo_input.setFocus()

    def selected_report_id(self):
        if not self.report_table.selectedItems(): return None
        return int(self.report_table.item(self.report_table.currentRow(),8).text())

    def show_selected_report(self):
        rid=self.selected_report_id(); self.current_report_id=rid
        if not rid: return
        r=self.db.get_report(rid); self.detail_title.setText(r["title"])
        self.detail_meta.setText(f"{r['repository']}\nStatus: {r['state']}  |  Severity: {r['severity'] or '-'}\nGHSA: {r['ghsa_id'] or '-'}\nCVE: {r['cve_id'] or '-'}\nGitHub Updated: {fmt_date(r['updated_at'])}\nLast Sync: {fmt_date(r['synced_at'])}\nSource: {r['source']}")
        self.detail_notes.setPlainText(r["notes"] or ""); self.detail_vendor.setPlainText(r["vendor_response"] or "")
        lines=[]
        for e in self.db.list_events(rid,30):
            old=(e["old_value"] or "-").replace("\n"," ")[:80]; new=(e["new_value"] or "-").replace("\n"," ")[:80]
            lines.append(f"{fmt_date(e['created_at'])}  {e['event_type']}: {old} → {new}")
        self.detail_history.setPlainText("\n".join(lines) if lines else "변경 이력 없음")

    def save_detail(self):
        if not self.current_report_id: return
        self.db.update_notes(self.current_report_id,self.detail_notes.toPlainText()); self.db.update_vendor_response(self.current_report_id,self.detail_vendor.toPlainText()); self.refresh_all(); self.sync_status.setText("상세 정보 저장됨")

    def open_selected_url(self):
        rid=self.selected_report_id() or self.current_report_id
        if not rid: return
        r=self.db.get_report(rid)
        if r["html_url"]: webbrowser.open(r["html_url"])
        else: QMessageBox.information(self,"URL 없음","등록된 GitHub URL이 없습니다.")

    def delete_selected(self):
        rid=self.selected_report_id() or self.current_report_id
        if rid and QMessageBox.question(self,"삭제","이 항목을 삭제하시겠습니까?")==QMessageBox.Yes:
            self.db.delete_report(rid); self.current_report_id=None; self.refresh_all()

    def refresh_connection_status(self):
        try:
            token=keyring.get_password(KEYRING_SERVICE,KEYRING_USER)
        except Exception:
            token=None
        if not hasattr(self, "connection_label"):
            return
        if not token:
            self.connection_label.setText("● GitHub 연결 안 됨")
            return
        try:
            login=GitHubClient(token, timeout=8).current_user()
            self.connection_label.setText(f"● GitHub 연결됨: @{login}")
        except Exception:
            self.connection_label.setText("● 저장된 로그인 정보 확인 필요 — 다시 로그인하세요")

    def start_oauth_login(self):
        client_id=self.client_id_input.text().strip()
        if not client_id:
            QMessageBox.warning(self,"Client ID","GitHub OAuth App의 Client ID를 입력하세요.")
            return
        self.settings.setValue("github/client_id", client_id)
        if self.auth_worker and self.auth_worker.isRunning():
            return
        self.sync_status.setText("GitHub 로그인 코드 요청 중...")
        self.auth_worker=OAuthWorker(client_id)
        self.auth_worker.code_ready.connect(self._oauth_code_ready)
        self.auth_worker.authenticated.connect(self._oauth_authenticated)
        self.auth_worker.failed.connect(self._oauth_failed)
        self.auth_worker.start()

    def _oauth_code_ready(self, verification_uri, user_code, expires_in):
        QApplication.clipboard().setText(user_code)
        webbrowser.open(verification_uri)
        self.sync_status.setText(f"브라우저에서 인증하세요. 코드 {user_code} (클립보드 복사됨)")
        QMessageBox.information(
            self,"GitHub 로그인",
            f"브라우저에서 GitHub 인증 페이지를 열었습니다.\n\n인증 코드: {user_code}\n\n코드는 클립보드에 복사했습니다. {expires_in//60}분 안에 승인하세요."
        )

    def _oauth_authenticated(self, login, token, refresh_token):
        try:
            keyring.set_password(KEYRING_SERVICE,KEYRING_USER,token)
            if refresh_token:
                keyring.set_password(KEYRING_SERVICE,KEYRING_REFRESH,refresh_token)
        except Exception as e:
            QMessageBox.critical(self,"저장 실패",f"OAuth 토큰을 Windows 자격 증명 저장소에 저장하지 못했습니다.\n{e}")
            return
        self.connection_label.setText(f"● GitHub 연결됨: @{login}")
        self.sync_status.setText(f"GitHub 로그인 완료: @{login}")
        QMessageBox.information(self,"GitHub 연결 완료",f"@{login} 계정과 연결했습니다.\n이제 저장소를 추가하고 동기화하면 됩니다.")

    def _oauth_failed(self, message):
        self.sync_status.setText("GitHub 로그인 실패")
        QMessageBox.critical(self,"GitHub OAuth 오류",message)

    def logout_github(self):
        try:
            keyring.delete_password(KEYRING_SERVICE,KEYRING_USER)
        except Exception:
            pass
        try:
            keyring.delete_password(KEYRING_SERVICE,KEYRING_REFRESH)
        except Exception:
            pass
        self.connection_label.setText("● GitHub 연결 안 됨")
        self.sync_status.setText("GitHub 연결 해제됨")

    def add_repo(self):
        raw=self.repo_input.text().strip(); repo=repository_from_input(raw)
        if not repo: QMessageBox.warning(self,"형식","owner/repository 또는 GitHub repository/advisory URL을 입력하세요."); return
        self.db.add_repository(repo); self.repo_input.clear(); self.refresh_repos(); self.sync_status.setText(f"저장소 추가: {repo}")

    def remove_repo(self):
        item=self.repo_list.currentItem()
        if item: self.db.remove_repository(item.text()); self.refresh_repos()

    def refresh_repos(self):
        if hasattr(self,"repo_list"): self.repo_list.clear(); self.repo_list.addItems(self.db.list_repositories())

    def sync_github(self):
        try: token=keyring.get_password(KEYRING_SERVICE,KEYRING_USER)
        except Exception: token=None
        repos=self.db.list_repositories()
        if not token: self.show_page(2); QMessageBox.information(self,"GitHub 연결","먼저 GitHub 로그인 버튼으로 계정을 연결하세요."); return
        if not repos: self.show_page(2); QMessageBox.information(self,"저장소","동기화할 저장소를 하나 이상 추가하세요."); return
        if self.worker and self.worker.isRunning(): return
        self.sync_status.setText("GitHub 연결 중..."); self.worker=SyncWorker(token,repos); self.worker.progress.connect(self.sync_status.setText); self.worker.item.connect(self._receive_sync_item); self.worker.done.connect(self._sync_done); self.worker.failed.connect(self._sync_failed); self.worker.start()

    def _receive_sync_item(self,data): self.db.upsert_report(data)
    def _sync_done(self,total,failures):
        self.refresh_all(); self.sync_status.setText(f"완료: {total}건 반영 / 실패 {failures}개"); QMessageBox.information(self,"동기화 완료",f"내 advisory {total}건을 반영했습니다.\n저장소 오류: {failures}개")
    def _sync_failed(self,message): self.sync_status.setText("동기화 실패"); QMessageBox.critical(self,"GitHub 오류",message)

    def _export_rows(self): return self.filtered_reports() if hasattr(self,"report_table") else self.db.list_reports()

    def export_csv(self):
        path,_=QFileDialog.getSaveFileName(self,"CSV 내보내기","github_vulnerability_reports.csv","CSV (*.csv)")
        if not path: return
        fields=["repository","title","state","severity","cve_id","ghsa_id","submitted_at","updated_at","last_change_at","vendor_response_at","vendor_response","notes","html_url","source"]
        with open(path,"w",newline="",encoding="utf-8-sig") as f:
            w=csv.writer(f); w.writerow(fields)
            for r in self._export_rows(): w.writerow([r[k] if k in r.keys() else "" for k in fields])
        self.sync_status.setText(f"CSV 저장: {path}")

    def export_xlsx(self):
        path,_=QFileDialog.getSaveFileName(self,"Excel 내보내기","github_vulnerability_reports.xlsx","Excel (*.xlsx)")
        if not path: return
        wb=Workbook(); ws=wb.active; ws.title="Vulnerability Reports"
        fields=["Repository","Title","Status","Severity","CVE","GHSA","Submitted","GitHub Updated","Last Change","Vendor Response At","Vendor Response","Notes","URL","Source"]
        ws.append(fields)
        for c in ws[1]: c.font=Font(bold=True)
        keys=["repository","title","state","severity","cve_id","ghsa_id","submitted_at","updated_at","last_change_at","vendor_response_at","vendor_response","notes","html_url","source"]
        for r in self._export_rows(): ws.append([r[k] if k in r.keys() else "" for k in keys])
        ws.freeze_panes="A2"; ws.auto_filter.ref=ws.dimensions
        widths=[28,52,14,12,20,24,22,22,22,22,45,45,55,12]
        for i,w in enumerate(widths,1): ws.column_dimensions[chr(64+i)].width=w
        ev=wb.create_sheet("Change History"); ev.append(["Report ID","Repository","GHSA","Event","Old","New","Time"])
        for c in ev[1]: c.font=Font(bold=True)
        for r in self.db.list_reports():
            for e in reversed(self.db.list_events(r["id"],1000)):
                ev.append([r["id"],r["repository"],r["ghsa_id"],e["event_type"],e["old_value"],e["new_value"],e["created_at"]])
        ev.freeze_panes="A2"; wb.save(path); self.sync_status.setText(f"Excel 저장: {path}")

    def closeEvent(self,event):
        if self.auth_worker and self.auth_worker.isRunning(): self.auth_worker.cancel()
        self.db.close(); super().closeEvent(event)


def main():
    app=QApplication(sys.argv); app.setApplicationName("GitHub Vulnerability Tracker"); app.setFont(QFont("Segoe UI",10)); win=MainWindow(); win.show(); sys.exit(app.exec())


if __name__=="__main__": main()
