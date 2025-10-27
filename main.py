# -*- coding: utf-8 -*-
import sys
import os
import io
import json
import uuid
import time
import threading
import tempfile
import secrets
import re
import subprocess
import random
import socket
import socks
import qrcode
import importlib.util
from datetime import datetime
from pathlib import Path
from functools import partial
from urllib.parse import urlparse, parse_qs
import webbrowser
from packaging import version

import paramiko
import requests
from PySide6.QtWidgets import (
    QApplication, QWizard, QWizardPage, QLabel, QLineEdit, QPushButton, QVBoxLayout,
    QHBoxLayout, QFileDialog, QTextEdit, QMessageBox, QPlainTextEdit, QCheckBox, QComboBox,
    QProgressBar, QDialogButtonBox, QListWidget, QGroupBox, QWidget, QTabWidget, QDialog, QFrame,
    QRadioButton, QButtonGroup
)
from PySide6.QtCore import Qt, Signal, QObject, QTimer, QEvent, Signal, QThread, Slot, QTranslator, QLocale, QLibraryInfo, QMetaObject, Qt, QEventLoop, Q_ARG
from PySide6.QtGui import QClipboard, QTextCursor, QPixmap, QShortcut, QKeySequence

if sys.stdout is None:
    sys.stdout = io.TextIOWrapper(io.BytesIO(), encoding='utf-8')
if sys.stderr is None:
    sys.stderr = io.TextIOWrapper(io.BytesIO(), encoding='utf-8')
if sys.stdin is None:
    sys.stdin = io.TextIOWrapper(io.BytesIO(), encoding='utf-8')

import speedtest


def resource_path(relative_path: str) -> Path:
    if hasattr(sys, "_MEIPASS"):
        base_path = Path(sys._MEIPASS)
    else:
        base_path = Path(getattr(sys, 'frozen', False) and Path(sys.executable).parent or Path(__file__).parent)
    return base_path / relative_path

class SSHManager:
    def __init__(self):
        self.client = None
        self.sftp = None
        self.host = None
        self.port = 22
        self.username = None
        self.password = None
        self.pkey_path = None

    def connect(self, host, port=22, username=None, password=None, pkey_path=None, timeout=10):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.pkey_path = pkey_path
        
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if pkey_path:
            key = paramiko.RSAKey.from_private_key_file(pkey_path)
            self.client.connect(hostname=host, port=port, username=username, pkey=key, timeout=timeout)
        else:
            self.client.connect(hostname=host, port=port, username=username, password=password, timeout=timeout)
        self.sftp = self.client.open_sftp()
        return True

    def reconnect(self, timeout=10):
        if not all([self.host, self.username]):
            return False
            
        try:
            self.close()
            time.sleep(1)
            return self.connect(self.host, self.port, self.username, self.password, self.pkey_path, timeout)
        except Exception as e:
            return False

    def is_connected(self):
        try:
            if self.client and self.client.get_transport() and self.client.get_transport().is_active():
                self.client.exec_command("echo test", timeout=5)
                return True
        except Exception:
            pass
        return False

    def ensure_connection(self, max_retries=3, retry_delay=2):
        for attempt in range(max_retries):
            if self.is_connected():
                return True
                
            if attempt > 0:
                time.sleep(retry_delay)
                
            try:
                if self.reconnect():
                    return True
            except Exception as e:
                print(f"Попытка переподключения {attempt + 1} не удалась: {e}")
                
        return False

    def close(self):
        try:
            if self.sftp:
                self.sftp.close()
        except Exception:
            pass
        try:
            if self.client:
                self.client.close()
        except Exception:
            pass
        self.client = None
        self.sftp = None

    def exec_command_stream(self, command, callback_stdout=None, callback_stderr=None, timeout=None, get_pty=False, env=None):
        if not self.ensure_connection():
            raise RuntimeError("SSH соединение потеряно и не может быть восстановлено")
            
        transport = self.client.get_transport()
        chan = transport.open_session()
        if get_pty:
            chan.get_pty()
        if env:
            env_str = " ".join(f"{k}='{v}'" for k, v in env.items())
            command = f"{env_str} {command}"
        chan.exec_command(command)
        def _read_loop():
            try:
                stdout = chan.makefile('r', -1)
                stderr = chan.makefile_stderr('r', -1)
                for line in stdout:
                    if callback_stdout:
                        callback_stdout(line.rstrip("\n"))
                for line in stderr:
                    if callback_stderr:
                        callback_stderr(line.rstrip("\n"))
                chan.close()
            except Exception as e:
                if callback_stderr:
                    callback_stderr(f"[SSH stream error] {e}")
        t = threading.Thread(target=_read_loop, daemon=True)
        t.start()
        return chan

    def exec_command(self, command, timeout=30):
        if not self.ensure_connection():
            raise RuntimeError("SSH соединение потеряно и не может быть восстановлено")
            
        stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
        out = stdout.read().decode(errors="ignore")
        err = stderr.read().decode(errors="ignore")
        exit_status = stdout.channel.recv_exit_status()
        return exit_status, out, err

    def upload_file(self, local_path, remote_path):
        if not self.ensure_connection():
            raise RuntimeError("SSH соединение потеряно и не может быть восстановлено")
            
        if not self.sftp:
            self.sftp = self.client.open_sftp()
        self.sftp.put(local_path, remote_path)
        self.exec_command(f"chmod +x {remote_path}")

    def download_file(self, remote_path, local_path):
        if not self.ensure_connection():
            raise RuntimeError("SSH соединение потеряно и не может быть восстановлено")
            
        if not self.sftp:
            self.sftp = self.client.open_sftp()
        self.sftp.get(remote_path, local_path)

import re
from urllib.request import urlopen, Request

PATTERN_BLACKLIST = [
    r'(^|\.)(sberbank|vtb|alfabank|tbank)\.ru$',
    r'(^|\.)pay\..*',
    r'(^|\.)secure.*',
    r'(^|\.)online\.sberbank\.ru$',
    r'(^|\.)bfds\..*',
    r'(^|\.)gosuslugi\.ru$',
    r'(^|\.)rzd\.ru$',
    r'(^|\.)login\..*',
    r'(^|\.)id\..*',
    r'(^|\.)sso\..*',
    r'(^|\.)oauth.*',
    r'(^|\.)admin\..*',
    r'(^|\.)dev\..*',
    r'(^|\.)adm\..*',
    r'(^|\.)cms-.*',
    r'(^|\.)receive-sentry\..*',
    r'(^|\.)metrics\..*',
    r'(^|\.)sun\d+-\d+\.userapi\.com$',
    r'(^|\.)avatars\.mds\..*',
    r'(^|\.)tile\d+\.maps\..*',
    r'(^|\.)i\d+\..*',
    r'(^|\.)\d+\.img\.avito\.st$',
    r'(^|\.)vk\.ru$',
    r'(^|\.).*\.vk\.ru$',
    r'(^|\.)yandex\.ru$',
    r'(^|\.)yandex\.com$',
    r'(^|\.)yandex\.net$',
    r'(^|\.).*\.yandex\.ru$',
    r'(^|\.).*\.yandex\.com$',
    r'(^|\.).*\.yandex\.net$',
]
TOKEN_BLACKLIST = {
    "bank", "pay", "secure", "id", "sso", "login", "auth", "admin", "dev",
    "corp", "intranet", "cloudcdn", "ticket", "market", "lk", "esia",
    "contract", "pos", "gosuslugi", "rzd", "oauth", "metrics", "sentry",
    "userapi", "sun", "avatars", "mail", "autodiscover", "vk", "yandex"
}
_COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in PATTERN_BLACKLIST]

def normalize_host(line: str) -> str:
    if not line:
        return ""
    line = line.strip()
    if line.startswith(("http://", "https://")):
        try:
            p = urlparse(line)
            host = p.hostname or line
        except Exception:
            host = line
    else:
        host = re.split(r'[/:]', line, maxsplit=1)[0]
    return (host or "").strip().lower().rstrip('.')

def should_exclude(host: str) -> bool:
    if not host or "." not in host:
        return True
    if ":" in host:
        host = host.split(":", 1)[0]
    for pattern in _COMPILED_PATTERNS:
        if pattern.search(host):
            return True
    for token in TOKEN_BLACKLIST:
        if token in host:
            return True
    return False

def get_sni_whitelist(raw_url: str = "https://raw.githubusercontent.com/yukikras/vless-wizard/main/sni.txt"):
    try:
        req = Request(raw_url, headers={"User-Agent": "sni-filter/1.0"})
        with urlopen(req, timeout=20) as resp:
            data = resp.read().decode(errors="ignore")
    except Exception as e:
        print("Ошибка загрузки списка sni:", e)
        return []
    hosts = []
    for line in data.splitlines():
        host = normalize_host(line)
        if host:
            hosts.append(host)
    unique_hosts = list(dict.fromkeys(hosts))
    filtered = [h for h in unique_hosts if not should_exclude(h)]
    random.shuffle(filtered)
    return filtered

class SNIManager:
    
    def __init__(self):
        self.used_sni = set()
        self.available_sni = []
        self.current_index = 0
        
    def load_available_sni(self):
        if not self.available_sni:
            self.available_sni = get_sni_whitelist()
        
        available = [sni for sni in self.available_sni if sni not in self.used_sni]
        
        if not available:
            self.used_sni.clear()
            available = self.available_sni.copy()
        
        random.shuffle(available)
        return available
    
    def get_next_sni(self):
        available = self.load_available_sni()
        
        if not available:
            return None
            
        if self.current_index >= len(available):
            self.current_index = 0
            
        sni = available[self.current_index]
        self.current_index += 1
        return sni
    
    def mark_sni_used(self, sni):
        if sni and sni not in self.used_sni:
            self.used_sni.add(sni)
    
    def get_used_count(self):
        return len(self.used_sni)
    
    def get_available_count(self):
        available = self.load_available_sni()
        return len(available)

class LoggerSignal(QObject):
    new_line = Signal(str)

class LogWindow(QTabWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Логи Vless Wizard")
        self.setMinimumSize(700, 500)
        
        self.main_logs = QPlainTextEdit()
        self.main_logs.setReadOnly(True)
        
        self.xray_logs = QPlainTextEdit()
        self.xray_logs.setReadOnly(True)
        
        self.curl_logs = QPlainTextEdit()
        self.curl_logs.setReadOnly(True)
        
        #self.speedtest_logs = QPlainTextEdit()
        #self.speedtest_logs.setReadOnly(True)
        
        self.addTab(self.main_logs, "Основные логи")
        self.addTab(self.xray_logs, "Логи Xray")
        self.addTab(self.curl_logs, "Логи Curl")
        #self.addTab(self.speedtest_logs, "Логи Speedtest")
        
    def append_main_log(self, line):
        self.main_logs.appendPlainText(line)
        self._scroll_to_end(self.main_logs)
        
    def append_xray_log(self, line):
        self.xray_logs.appendPlainText(line)
        self._scroll_to_end(self.xray_logs)
        
    def append_curl_log(self, line):
        self.curl_logs.appendPlainText(line)
        self._scroll_to_end(self.curl_logs)
        
    #def append_speedtest_log(self, line):
    #    self.speedtest_logs.appendPlainText(line)
    #    self._scroll_to_end(self.speedtest_logs)
        
    def _scroll_to_end(self, text_edit):
        cursor = text_edit.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        text_edit.setTextCursor(cursor)
        text_edit.ensureCursorVisible()
    
    def append_log(self, line):
        self.append_main_log(line)

class SpeedtestLogWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle("Логи Speedtest")
        self.setMinimumSize(600, 400)
        
        layout = QVBoxLayout()
        
        self.log_display = QPlainTextEdit()
        self.log_display.setReadOnly(True)
        
        clear_btn = QPushButton("Очистить логи")
        clear_btn.clicked.connect(self.clear_logs)
        
        layout.addWidget(QLabel("Логи тестирования скорости:"))
        layout.addWidget(self.log_display)
        layout.addWidget(clear_btn)
        
        self.setLayout(layout)
        
    def append_log(self, message):
        self.log_display.appendPlainText(f"{datetime.now().strftime('%H:%M:%S')} - {message}")
        cursor = self.log_display.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        self.log_display.setTextCursor(cursor)
        
    def clear_logs(self):
        self.log_display.clear()

class BaseWizardPage(QWizardPage):
    def __init__(self, ssh_mgr: SSHManager, logger_sig: LoggerSignal, log_window: LogWindow, sni_manager: SNIManager):
        super().__init__()
        self.ssh_mgr = ssh_mgr
        self.logger_sig = logger_sig
        self.log_window = log_window
        self.sni_manager = sni_manager

    def log_message(self, message):
        self.logger_sig.new_line.emit(message)

    def ensure_ssh_connection(self, max_retries=5, retry_delay=3):
        for attempt in range(max_retries):
            if self.ssh_mgr.is_connected():
                return True
                
            if attempt == 0:
                self.log_message(f"[SSH] Проверка соединения...")
            else:
                self.log_message(f"[SSH] Попытка восстановления {attempt}/{max_retries-1}...")
                time.sleep(retry_delay)
                
            try:
                if self.ssh_mgr.reconnect():
                    self.log_message("[SSH] Соединение восстановлено!")
                    return True
            except Exception as e:
                self.log_message(f"[SSH] Ошибка восстановления: {e}")
                
        self.log_message("[SSH] Не удалось восстановить соединение")
        return False

class PageSSH(BaseWizardPage):
    def __init__(self, ssh_mgr: SSHManager, logger_sig: LoggerSignal, log_window: LogWindow, sni_manager: SNIManager):
        super().__init__(ssh_mgr, logger_sig, log_window, sni_manager)
        self.setTitle("Шаг 1 — параметры SSH")
        self.setSubTitle("Введите данные для подключения к серверу по SSH")
        
        layout = QVBoxLayout()

        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText("IP адрес сервера")
        self.port_input = QLineEdit("22")
        self.user_input = QLineEdit("root")
        self.pass_input = QLineEdit()
        self.pass_input.setPlaceholderText("Пароль")
        self.pass_input.setEchoMode(QLineEdit.Password)
        
        self.pkey_input = QLineEdit()
        self.pkey_input.setVisible(False)
        self.pkey_btn = QPushButton("Выбрать файл ключа")
        self.pkey_btn.setVisible(False)
        
        self.status_lbl = QLabel("Не подключено")
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)

        layout.addWidget(QLabel("IP:"))
        layout.addWidget(self.host_input)
        layout.addWidget(QLabel("Порт (по умолчанию 22):"))
        layout.addWidget(self.port_input)
        layout.addWidget(QLabel("Имя пользователя:"))
        layout.addWidget(self.user_input)
        layout.addWidget(QLabel("Пароль:"))
        layout.addWidget(self.pass_input)
        
        help_label = QLabel(
            'Если вы используете сервер от <b>Aeza</b>, то IP и пароль можно взять, '
            'следуя <a href="https://github.com/YukiKras/vless-wizard/wiki#%D0%B2%D0%B2%D0%BE%D0%B4-%D0%BD%D0%B5%D0%BE%D0%B1%D1%85%D0%BE%D0%B4%D0%B8%D0%BC%D1%8B%D1%85-%D0%B4%D0%B0%D0%BD%D0%BD%D1%8B%D1%85-%D0%B4%D0%BE%D1%81%D1%82%D1%83%D0%BF%D0%B0">этой инструкции</a>.'
        )
        help_label.setOpenExternalLinks(True)
        layout.addWidget(help_label)

        h = QHBoxLayout()
        h.addWidget(QLabel("Private key (опционально):"))
        h.addWidget(self.pkey_input)
        h.addWidget(self.pkey_btn)
        h.setContentsMargins(0, 0, 0, 0)
        for i in range(h.count()):
            item = h.itemAt(i)
            if item.widget():
                item.widget().setVisible(False)
        layout.addLayout(h)
        
        layout.addWidget(self.status_lbl)
        layout.addWidget(self.progress_bar)
        self.setLayout(layout)
        
        self.host_input.textChanged.connect(self.check_complete)
        self.user_input.textChanged.connect(self.check_complete)

    def choose_key(self):
        path, _ = QFileDialog.getOpenFileName(self, "Выберите приватный ключ", str(Path.home()))
        if path:
            self.pkey_input.setText(path)

    def initializePage(self):
        self.status_lbl.setText("Не подключено")
        self.progress_bar.setVisible(False)

    def validatePage(self):
        self.status_lbl.setText("Подключение...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        
        host = self.host_input.text().strip()
        port = int(self.port_input.text().strip() or 22)
        user = self.user_input.text().strip()
        password = self.pass_input.text()
        pkey = self.pkey_input.text().strip() or None
        
        success = [False]
        error_msg = [None]
        
        def _do():
            try:
                self.ssh_mgr.connect(host, port, user, password if password else None, pkey)
                success[0] = True
            except Exception as e:
                error_msg[0] = str(e)
        
        t = threading.Thread(target=_do, daemon=True)
        t.start()
        t.join(timeout=15)
        
        if success[0]:
            self.status_lbl.setText("Подключено успешно!")
            self.progress_bar.setVisible(False)
            self.log_message(f"[SSH] Успешное подключение к {host}:{port}")
            return True
        else:
            self.status_lbl.setText(f"Ошибка подключения: {error_msg[0] or 'Таймаут'}")
            self.progress_bar.setVisible(False)
            self.log_message(f"[SSH] Ошибка подключения: {error_msg[0] or 'Таймаут'}")
            QMessageBox.warning(self, "Ошибка подключения", 
                              f"Не удалось подключиться к серверу:\n{error_msg[0] or 'Таймаут'}")
            return False

    def check_complete(self):
        host_filled = bool(self.host_input.text().strip())
        user_filled = bool(self.user_input.text().strip())
        self.completeChanged.emit()

    def isComplete(self):
        return bool(self.host_input.text().strip() and self.user_input.text().strip())

class PageInstallXUI(BaseWizardPage):
    def __init__(self, ssh_mgr: SSHManager, logger_sig: LoggerSignal, log_window: LogWindow, sni_manager: SNIManager):
        super().__init__(ssh_mgr, logger_sig, log_window, sni_manager)
        self.setTitle("Шаг 2 — проверка и установка 3x-ui")
        self.setSubTitle("Автоматическая проверка и установка 3x-ui панели")
        
        layout = QVBoxLayout()
        
        self.status_label = QLabel("Проверка установки 3x-ui...")
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        
        self.credentials_label = QLabel("")
        self.credentials_label.setWordWrap(True)
        
        self.copy_btn = QPushButton("Копировать данные")
        self.copy_btn.clicked.connect(self.copy_credentials)
        self.copy_btn.setVisible(False)
        
        self.save_btn = QPushButton("Сохранить в файл")
        self.save_btn.clicked.connect(self.save_credentials)
        self.save_btn.setVisible(False)
        
        self.reinstall_btn = QPushButton("Переустановить 3x-ui")
        self.reinstall_btn.clicked.connect(self.force_reinstall)
        self.reinstall_btn.setVisible(False)
        
        layout.addWidget(self.status_label)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.credentials_label)
        
        btn_layout = QHBoxLayout()
        btn_layout.addWidget(self.copy_btn)
        btn_layout.addWidget(self.save_btn)
        btn_layout.addWidget(self.reinstall_btn)
        layout.addLayout(btn_layout)
        
        self.setLayout(layout)
        
        self.xui_installed = False
        self.panel_credentials = {}
        self.installation_complete = False
        self.force_install = False
        self.install_thread = None
        self.stop_installation = False

    def copy_credentials(self):
        if self.panel_credentials:
            text = "Данные для входа в 3x-ui панель:\n\n"
            if 'url' in self.panel_credentials:
                text += f"URL: {self.panel_credentials['url']}\n"
            if 'username' in self.panel_credentials:
                text += f"Username: {self.panel_credentials['username']}\n"
            if 'password' in self.panel_credentials:
                text += f"Password: {self.panel_credentials['password']}\n"
            
            clipboard = QApplication.clipboard()
            clipboard.setText(text)
            
            original_text = self.copy_btn.text()
            self.copy_btn.setText("Скопировано!")
            QTimer.singleShot(2000, lambda: self.copy_btn.setText(original_text))

    def save_credentials(self):
        if self.panel_credentials:
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Сохранить данные 3x-ui", "xui_credentials.txt", "Text Files (*.txt)"
            )
            if file_path:
                try:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write("Данные для входа в 3x-ui панель:\n\n")
                        if 'url' in self.panel_credentials:
                            f.write(f"URL: {self.panel_credentials['url']}\n")
                        if 'username' in self.panel_credentials:
                            f.write(f"Username: {self.panel_credentials['username']}\n")
                        if 'password' in self.panel_credentials:
                            f.write(f"Password: {self.panel_credentials['password']}\n")
                    
                    original_text = self.save_btn.text()
                    self.save_btn.setText("Сохранено!")
                    QTimer.singleShot(2000, lambda: self.save_btn.setText(original_text))
                    
                    self.log_message(f"[save] Данные сохранены в {file_path}")
                except Exception as e:
                    QTimer.singleShot(0, lambda: QMessageBox.warning(self, "Ошибка", f"Не удалось сохранить файл: {e}"))

    def force_reinstall(self):
        QTimer.singleShot(0, self._show_reinstall_dialog)

    def _show_reinstall_dialog(self):
        reply = QMessageBox.question(self, "Переустановка 3x-ui", 
                                   "Вы уверены, что хотите переустановить 3x-ui панель?\n\n"
                                   "Это может занять несколько минут.",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            self.force_install = True
            self.installation_complete = False
            self.xui_installed = False
            self.panel_credentials = {}
            self.credentials_label.setText("")
            self.copy_btn.setVisible(False)
            self.save_btn.setVisible(False)
            self.reinstall_btn.setVisible(False)
            self.start_xui_installation()

    def initializePage(self):
        self.check_and_install_xui()

    def check_and_install_xui(self):
        if self.force_install:
            self.start_xui_installation()
            return
            
        self.safe_update_status("Проверка 3x-ui...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
    
        def _check_install():
            try:
                if not self.ensure_ssh_connection():
                    self.log_message("[SSH] Не удалось восстановить соединение для проверки 3x-ui")
                    self.safe_update_status("Ошибка: SSH соединение потеряно")
                    self.safe_hide_progress()
                    return
    
                try:
                    code, out, err = self.ssh_mgr.exec_command("command -v x-ui || which x-ui || echo '__XUI_NOT_FOUND__'")
                except Exception as e:
                    if "10054" in str(e) or "удаленный хост" in str(e).lower():
                        self.log_message("[SSH] Соединение разорвано, пробуем переподключиться...")
                        if not self.ensure_ssh_connection():
                            self.safe_update_status("Ошибка: SSH соединение потеряно")
                            self.safe_hide_progress()
                            return
                        code, out, err = self.ssh_mgr.exec_command("command -v x-ui || which x-ui || echo '__XUI_NOT_FOUND__'")
                    else:
                        raise
    
                if "__XUI_NOT_FOUND__" in out or not out.strip():
                    self.safe_show_install_dialog()
                else:
                    self.xui_installed = True
                    self.log_message(f"[check] x-ui найден: {out.strip()}")
                    self.safe_update_status("3x-ui уже установлен")
                    self.safe_hide_progress()
                    self.installation_complete = True
                    self.safe_show_reinstall_btn()
                    self.completeChanged.emit()
    
            except Exception as e:
                self.log_message(f"[check error] {e}")
                self.safe_update_status(f"Ошибка проверки: {e}")
                self.safe_hide_progress()
    
        t = threading.Thread(target=_check_install, daemon=True)
        t.start()

    def start_xui_installation(self):
        """Запуск установки 3x-ui (используется при обычной установке и принудительной переустановке)"""
        self.log_message("[install] Начинаем установку 3x-ui...")
        self.safe_update_status("Запуск установки 3x-ui...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        
        self.force_install = False
        self.stop_installation = False
        
        if self.install_thread and self.install_thread.is_alive():
            self.log_message("[install] Предыдущая установка еще выполняется, ожидаем...")
            return
            
        self.install_thread = threading.Thread(target=self.install_xui, daemon=True)
        self.install_thread.start()

    def safe_show_install_dialog(self):
        QMetaObject.invokeMethod(self, "_show_install_dialog_impl")

    @Slot()
    def _show_install_dialog_impl(self):
        ret = QMessageBox.question(
            self, "Установка 3x-ui",
            "3x-ui панель не обнаружена.\n\nОна будет установлена автоматически.\n\nПродолжить?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if ret != QMessageBox.StandardButton.Yes:
            self.log_message("[check] Пользователь отказался от установки 3x-ui. Мастер завершает работу.")
            self.safe_update_status("Установка отменена пользователем")
            self.safe_hide_progress()
            self.installation_complete = True
            self.completeChanged.emit()
            return
        
        self.start_xui_installation()

    def install_xui(self):
        """Основной метод установки с улучшенной обработкой ошибок"""
        try:
            self.safe_update_status("Подготовка к установке 3x-ui...")
            self.log_message("[install] Начинаем установку 3x-ui...")
        
            # Проверяем соединение перед началом
            if not self.ensure_ssh_connection():
                self.log_message("[install] Ошибка: нет SSH соединения")
                self.safe_update_status("Ошибка: нет SSH соединения")
                self.safe_hide_progress()
                return
        
            script_path = resource_path("3xinstall.sh")
            if not script_path.exists():
                self.log_message("[install] Ошибка: файл 3xinstall.sh не найден")
                self.safe_update_status("Ошибка: 3xinstall.sh не найден")
                self.safe_hide_progress()
                return
        
            remote_script = f"/tmp/3xinstall_{secrets.token_hex(4)}.sh"
            remote_log = f"/tmp/xui_install_{secrets.token_hex(4)}.log"
        
            # Загружаем файл с повторными попытками
            if not self.upload_with_retry(str(script_path), remote_script):
                self.log_message("[install] Ошибка загрузки скрипта установки")
                self.safe_update_status("Ошибка загрузки скрипта")
                self.safe_hide_progress()
                return
        
            # Даем права на выполнение
            self.ssh_mgr.exec_command(f"chmod +x {remote_script}")
        
            # Проверяем наличие screen и устанавливаем если нужно
            exit_code, out, err = self.ssh_mgr.exec_command("command -v screen || echo 'NO_SCREEN'")
            if "NO_SCREEN" in out:
                self.log_message("[install] Устанавливаем screen...")
                self.ssh_mgr.exec_command("apt-get update && apt-get install -y screen || yum install -y screen || dnf install -y screen")
        
            # Запускаем установку в screen
            screen_name = f"xui_{secrets.token_hex(3)}"
            self.log_message(f"[install] Запускаем установку в screen сессии {screen_name}...")
            
            cmd = f"screen -dmS {screen_name} bash -c 'bash {remote_script} > {remote_log} 2>&1; echo __XUI_DONE__ >> {remote_log}'"
            self.ssh_mgr.exec_command(cmd)
        
            # Мониторим лог установки
            self.follow_install_log(remote_log, screen_name)
            
        except Exception as e:
            self.log_message(f"[install error] Критическая ошибка: {e}")
            self.safe_update_status(f"Ошибка установки: {e}")
            self.safe_hide_progress()

    def upload_with_retry(self, local_path, remote_path, max_retries=3):
        """Загрузка файла с повторными попытками при разрыве соединения"""
        for attempt in range(max_retries):
            try:
                if not self.ensure_ssh_connection():
                    self.log_message(f"[upload] Попытка {attempt + 1}: нет соединения")
                    continue
                    
                self.log_message(f"[upload] Попытка {attempt + 1} загрузки {local_path}...")
                self.ssh_mgr.upload_file(local_path, remote_path)
                self.log_message(f"[upload] Файл успешно загружен как {remote_path}")
                return True
                
            except Exception as e:
                self.log_message(f"[upload] Ошибка попытки {attempt + 1}: {e}")
                if attempt < max_retries - 1:
                    time.sleep(2)
                    continue
                else:
                    self.log_message("[upload] Все попытки загрузки провалились")
                    return False
        return False

    def follow_install_log(self, remote_log, screen_name):
        """Мониторинг лога установки с обработкой разрывов соединения"""
        seen_lines = set()
        last_size = 0
        consecutive_errors = 0
        max_errors = 5
        
        self.log_message("[log] Начинаем мониторинг лога установки...")
        
        while not self.stop_installation and consecutive_errors < max_errors:
            try:
                if not self.ensure_ssh_connection():
                    self.log_message("[log] Нет соединения, пробуем переподключиться...")
                    consecutive_errors += 1
                    time.sleep(3)
                    continue
                
                # Проверяем статус screen сессии
                exit_code, out, err = self.ssh_mgr.exec_command(f"screen -list | grep {screen_name} || echo 'NOT_FOUND'")
                
                if "NOT_FOUND" in out:
                    self.log_message("[log] Screen сессия завершена, проверяем результат...")
                    break
                
                # Читаем лог
                exit_code, out, err = self.ssh_mgr.exec_command(f"tail -c +{last_size + 1} {remote_log} 2>/dev/null || echo ''")
                
                if out:
                    lines = out.splitlines()
                    for line in lines:
                        if line and line not in seen_lines:
                            seen_lines.add(line)
                            self.safe_parse_credentials(line)
                            self.log_message(line)
                            
                            if "__XUI_DONE__" in line:
                                self.log_message("[log] Обнаружен маркер завершения установки")
                                break
                    
                    # Обновляем размер для следующего чтения
                    exit_code, size_out, err = self.ssh_mgr.exec_command(f"stat -c%s {remote_log} 2>/dev/null || wc -c < {remote_log} 2>/dev/null || echo '0'")
                    if size_out.strip().isdigit():
                        last_size = int(size_out.strip())
                
                consecutive_errors = 0  # Сброс счетчика ошибок при успешной операции
                time.sleep(2)
                
            except Exception as e:
                consecutive_errors += 1
                self.log_message(f"[log error] Ошибка чтения лога ({consecutive_errors}/{max_errors}): {e}")
                time.sleep(3)
        
        if consecutive_errors >= max_errors:
            self.log_message("[log] Превышено максимальное количество ошибок, завершаем мониторинг")
            self.safe_update_status("Ошибка: слишком много разрывов соединения")
        
        # Финальная проверка и завершение
        self.finalize_installation_check(remote_log, screen_name)

    def finalize_installation_check(self, remote_log, screen_name):
        """Финальная проверка результатов установки"""
        try:
            self.log_message("[finalize] Завершаем установку...")
            
            # Читаем полный лог для поиска credentials
            if self.ensure_ssh_connection():
                exit_code, out, err = self.ssh_mgr.exec_command(f"cat {remote_log} 2>/dev/null || echo 'NO_LOG'")
                if "NO_LOG" not in out:
                    lines = out.splitlines()
                    for line in lines:
                        self.safe_parse_credentials(line)
            
            # Очистка
            if self.ensure_ssh_connection():
                self.ssh_mgr.exec_command(f"rm -f {remote_log} 2>/dev/null || true")
                self.ssh_mgr.exec_command(f"screen -S {screen_name} -X quit 2>/dev/null || true")
            
            self.finalize_installation()
            
        except Exception as e:
            self.log_message(f"[finalize error] Ошибка завершения: {e}")
            self.finalize_installation()

    def safe_parse_credentials(self, line):
        try:
            clean_line = line.strip()
            if not clean_line:
                return
                
            line_lower = clean_line.lower()
            
            if "http" in line_lower and ("://" in clean_line or "panel" in line_lower):
                try:
                    urls = re.findall(r'https?://[^\s<>"\'{}|\\^`\[\]]+', clean_line)
                    if urls and 'url' not in self.panel_credentials:
                        url = urls[0].strip()
                        if url and len(url) > 10:
                            self.panel_credentials['url'] = url
                            self.log_message(f"[creds] Найден URL: {url}")
                except Exception as e:
                    self.log_message(f"[creds error] Ошибка парсинга URL: {e}")
            
            username_keywords = ['username', 'user', 'логин', 'login']
            if any(keyword in line_lower for keyword in username_keywords):
                try:
                    for separator in [':', '=', '-']:
                        if separator in clean_line:
                            parts = clean_line.split(separator, 1)
                            if len(parts) > 1 and 'username' not in self.panel_credentials:
                                username = parts[1].strip()
                                if username and 1 < len(username) < 50 and not username.startswith('http'):
                                    self.panel_credentials['username'] = username
                                    self.log_message(f"[creds] Найден username: {username}")
                                    break
                except Exception as e:
                    self.log_message(f"[creds error] Ошибка парсинга username: {e}")
            
            password_keywords = ['password', 'pass', 'пароль']
            if any(keyword in line_lower for keyword in password_keywords):
                try:
                    for separator in [':', '=', '-']:
                        if separator in clean_line:
                            parts = clean_line.split(separator, 1)
                            if len(parts) > 1 and 'password' not in self.panel_credentials:
                                password = parts[1].strip()
                                if password and 3 < len(password) < 100 and not password.startswith('http'):
                                    self.panel_credentials['password'] = password
                                    self.log_message(f"[creds] Найден password: {'*' * len(password)}")
                                    break
                except Exception as e:
                    self.log_message(f"[creds error] Ошибка парсинга password: {e}")
                    
        except Exception as e:
            self.log_message(f"[parse critical error] {e}")

    def finalize_installation(self):
        self.xui_installed = True
        self.installation_complete = True
        self.safe_hide_progress()
        
        cred_text = "Установка 3x-ui завершена!\n\n"
        if self.panel_credentials:
            cred_text += "Данные для входа в панель:\n"
            if 'url' in self.panel_credentials:
                cred_text += f"URL: {self.panel_credentials['url']}\n"
            if 'username' in self.panel_credentials:
                cred_text += f"Username: {self.panel_credentials['username']}\n"
            if 'password' in self.panel_credentials:
                cred_text += f"Password: {self.panel_credentials['password']}\n"
        else:
            cred_text += "Учетные данные не найдены в выводе установки.\nПроверьте логи для получения информации.\n"
        
        cred_text += "\nСохраните эти данные для входа в панель!"
        self.safe_update_credentials_label(cred_text)
        self.safe_update_status("Установка завершена")
        self.safe_show_buttons()
        
        self.completeChanged.emit()

    def safe_update_status(self, text):
        QMetaObject.invokeMethod(self.status_label, "setText", Qt.ConnectionType.QueuedConnection, 
                               Q_ARG(str, text))
    
    def safe_hide_progress(self):
        QMetaObject.invokeMethod(self.progress_bar, "setVisible", Qt.ConnectionType.QueuedConnection, 
                               Q_ARG(bool, False))
    
    def safe_update_credentials_label(self, text):
        QMetaObject.invokeMethod(self.credentials_label, "setText", Qt.ConnectionType.QueuedConnection, 
                               Q_ARG(str, text))
    
    def safe_show_buttons(self):
        QMetaObject.invokeMethod(self.copy_btn, "setVisible", Qt.ConnectionType.QueuedConnection, 
                               Q_ARG(bool, True))
        QMetaObject.invokeMethod(self.save_btn, "setVisible", Qt.ConnectionType.QueuedConnection, 
                               Q_ARG(bool, True))
        QMetaObject.invokeMethod(self.reinstall_btn, "setVisible", Qt.ConnectionType.QueuedConnection, 
                               Q_ARG(bool, True))
    
    def safe_show_reinstall_btn(self):
        QMetaObject.invokeMethod(self.reinstall_btn, "setVisible", Qt.ConnectionType.QueuedConnection, 
                               Q_ARG(bool, True))

    def get_credentials(self):
        return self.panel_credentials

    def isComplete(self):
        return self.installation_complete

class PagePanelAuth(BaseWizardPage):
    def __init__(self, ssh_mgr: SSHManager, logger_sig: LoggerSignal, page_install: PageInstallXUI, log_window: LogWindow, sni_manager: SNIManager):
        super().__init__(ssh_mgr, logger_sig, log_window, sni_manager)
        self.page_install = page_install
        self.setTitle("Шаг 3 — авторизация в 3x-ui панели")
        self.setSubTitle("Введите данные для входа в 3x-ui панели")
        
        layout = QVBoxLayout()
        
        self.url_label = QLabel("URL адрес панели:")
        self.panel_url_input = QLineEdit()
        self.panel_url_input.setPlaceholderText("URL адрес 3x-ui панели")
        
        self.username_label = QLabel("Логин:")
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Логин")
        
        self.password_label = QLabel("Пароль:")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Пароль")
        self.password_input.setEchoMode(QLineEdit.Password)
        
        self.cancel_auto_fill_btn = QPushButton("Отменить автозаполнение")
        self.cancel_auto_fill_btn.clicked.connect(self.cancel_auto_fill)
        self.cancel_auto_fill_btn.setVisible(False)
        
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        self.status_label.setText(
            "Предупреждение! Wizard на следующему шагу будет<br>"
            "менять некоторые настройки в 3x-ui панели!<br><br>"
            "Если у вас настроена 2FA аутентификация в 3x-ui, пожалуйста, временно отключите её.<br><br>"
            "В случае Aéza логин и пароль для 3x-ui панели можно найти следуя инструкциям "
            "<a href='https://wiki.aeza.net/aezawiki/razvertyvanie-proksi-protokola-vless-s-pomoshyu-3x-ui#id-2.-vkhod-v-panel-3x-ui-i-sozdanie-klyucha-polzovatelya'>отсюда</a>."
        )
        self.status_label.setOpenExternalLinks(True)

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        
        layout.addWidget(self.url_label)
        layout.addWidget(self.panel_url_input)
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.cancel_auto_fill_btn)
        layout.addWidget(self.status_label)
        layout.addWidget(self.progress_bar)
        
        self.setLayout(layout)
        
        self.auth_successful = False
        self.panel_info = {}
        self.auto_fill_thread = None
        self.stop_auto_fill = False

    def cancel_auto_fill(self):
        self.stop_auto_fill = True
        if self.auto_fill_thread and self.auto_fill_thread.is_alive():
            self.auto_fill_thread = None
        self.progress_bar.setVisible(False)
        self.cancel_auto_fill_btn.setVisible(False)
        self._show_input_fields(True)
        self._restore_wizard_buttons()
        self.show_input_prompt()

    def show_input_prompt(self):
        prompt_text = (
            "Пожалуйста, введите данные для входа в 3x-ui панель:\n\n"
            "• URL адрес панели (например: http://ip-адрес:порт/путь)\n"
            "• Логин администратора\n"
            "• Пароль администратора\n\n"
            "Эти данные обычно создаются при установке 3x-ui и могут быть найдены:\n"
            "- В файле /root/3x-ui.txt на сервере\n"
            "- В выводе установки 3x-ui\n"
            "- В письме от хостинг-провайдера (для Aéza и подобных)"
        )
        self.status_label.setText(prompt_text)

    def initializePage(self):
        creds = self.page_install.get_credentials()
        if 'url' in creds:
            self.panel_url_input.setText(creds['url'])
        if 'username' in creds:
            self.username_input.setText(creds['username'])
        if 'password' in creds:
            self.password_input.setText(creds['password'])
        
        self.auth_successful = False
        self.stop_auto_fill = False
        QTimer.singleShot(500, self.try_auto_fill)

    def try_auto_fill(self):
        self.status_label.setText("Попытка автоматического заполнения из файла...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self.cancel_auto_fill_btn.setVisible(True)
        self._show_input_fields(False)
        self._hide_wizard_buttons()
        
        if self.auto_fill_thread and self.auto_fill_thread.is_alive():
            return
            
        self.auto_fill_thread = threading.Thread(target=self._auto_fill_worker, daemon=True)
        self.auto_fill_thread.start()

    def _show_input_fields(self, show):
        self.url_label.setVisible(show)
        self.panel_url_input.setVisible(show)
        self.username_label.setVisible(show)
        self.username_input.setVisible(show)
        self.password_label.setVisible(show)
        self.password_input.setVisible(show)

    def _hide_wizard_buttons(self):
        self.wizard().button(QWizard.NextButton).setVisible(False)
        self.wizard().button(QWizard.BackButton).setVisible(False)
        self.wizard().button(QWizard.CancelButton).setVisible(False)

    def _restore_wizard_buttons(self):
        self.wizard().button(QWizard.NextButton).setVisible(True)
        self.wizard().button(QWizard.BackButton).setVisible(True)
        self.wizard().button(QWizard.CancelButton).setVisible(True)

    def _auto_fill_worker(self):
        try:
            credentials = self._read_credentials_file()
            
            if self.stop_auto_fill:
                return
                
            if credentials:
                auth_success = self._try_auto_auth(credentials)
                if auth_success:
                    QMetaObject.invokeMethod(self, "_on_auto_fill_success", Qt.QueuedConnection)
                    return
                else:
                    QMetaObject.invokeMethod(self, "_on_auto_fill_auth_failed", Qt.QueuedConnection)
            else:
                QMetaObject.invokeMethod(self, "_on_auto_fill_failed", Qt.QueuedConnection)
                
        except Exception as e:
            if not self.stop_auto_fill:
                QMetaObject.invokeMethod(self, "_on_auto_fill_error", Qt.QueuedConnection, Q_ARG(str, str(e)))

    def _read_credentials_file(self):
        try:
            if not self.ensure_ssh_connection():
                return None
            
            exit_code, out, err = self.ssh_mgr.exec_command("ls /root/3x-ui.txt 2>/dev/null || echo 'NOT_FOUND'")
            if "NOT_FOUND" in out:
                return None
            
            exit_code, content, err = self.ssh_mgr.exec_command("cat /root/3x-ui.txt")
            if not content:
                return None
            
            return self.parse_credentials_from_content(content)
                
        except Exception as e:
            return None

    def _try_auto_auth(self, credentials):
        try:
            if not credentials.get('url') or not credentials.get('username') or not credentials.get('password'):
                return False
                
            url = credentials['url']
            username = credentials['username']
            password = credentials['password']
            
            parsed = urlparse(url)
            hostname = parsed.hostname or "127.0.0.1"
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            full_path = parsed.path.strip('/')
            
            clean_path = re.sub(r'(\/panel.*$)', '', f"/{full_path}").strip('/')
            
            use_https = parsed.scheme == 'https'
            protocol = "https" if use_https else "http"
            
            cookie_jar = f"/tmp/xui_cookie_{secrets.token_hex(4)}.jar"
            login_url = f"{protocol}://127.0.0.1:{port}"
            if clean_path:
                login_url += f"/{clean_path}"
            login_url += "/login"
            
            login_json = json.dumps({"username": username, "password": password}).replace('"', '\\"')
            ssl_options = "-k" if use_https else ""
            
            host_header = f'-H "Host: {hostname}"' if use_https else ""
            
            cmd = (
                f'COOKIE_JAR={cookie_jar} && '
                f'LOGIN_RESPONSE=$(curl -s {ssl_options} -c "$COOKIE_JAR" -X POST "{login_url}" '
                f'{host_header} -H "Content-Type: application/json" -d "{login_json}") && '
                f'if echo "$LOGIN_RESPONSE" | grep -q \'"success":true\'; then '
                f'  echo "AUTH_SUCCESS"; '
                f'else '
                f'  echo "AUTH_FAILED"; '
                f'fi'
            )
            
            exit_code, out, err = self.ssh_mgr.exec_command(cmd, timeout=20)
            
            if "AUTH_SUCCESS" in out:
                self.panel_info = {
                    'port': port,
                    'webpath': clean_path,
                    'base_url': f"{protocol}://127.0.0.1:{port}" + (f"/{clean_path}" if clean_path else ""),
                    'use_https': use_https,
                    'cookie_jar': cookie_jar
                }
                return True
            else:
                return False
                
        except Exception as e:
            return False

    @Slot()
    def _on_auto_fill_success(self):
        self.progress_bar.setVisible(False)
        self.cancel_auto_fill_btn.setVisible(False)
        self._show_input_fields(True)
        self._restore_wizard_buttons()
        self.auth_successful = True
        self.status_label.setText("Автоматическая авторизация успешна! Данные найдены в файле /root/3x-ui.txt")
        self.completeChanged.emit()
        
        QTimer.singleShot(1000, self._go_to_next_page)
    
    @Slot()
    def _go_to_next_page(self):
        current_page = self.wizard().currentPage()
        current_id = self.wizard().currentId()
        
        if self.wizard().page(current_id) == current_page:
            self.wizard().next()


    @Slot()
    def _on_auto_fill_auth_failed(self):
        self.progress_bar.setVisible(False)
        self.cancel_auto_fill_btn.setVisible(False)
        self._show_input_fields(True)
        self._restore_wizard_buttons()
        self.show_input_prompt()

    @Slot()
    def _on_auto_fill_failed(self):
        self.progress_bar.setVisible(False)
        self.cancel_auto_fill_btn.setVisible(False)
        self._show_input_fields(True)
        self._restore_wizard_buttons()
        self.show_input_prompt()

    @Slot(str)
    def _on_auto_fill_error(self, error_msg):
        self.progress_bar.setVisible(False)
        self.cancel_auto_fill_btn.setVisible(False)
        self._show_input_fields(True)
        self._restore_wizard_buttons()
        self.status_label.setText(f"Ошибка при автоматическом заполнении\n\nПожалуйста, введите данные для входа вручную.")
        self.show_input_prompt()

    def parse_credentials_from_content(self, content):
        credentials = {}
        
        try:
            content = content.replace('\r\n', '\n').replace('\r', '\n')
            
            url_patterns = [
                r'http://[^\s<>"\'{}|\\^`\[\]]+',
                r'https://[^\s<>"\'{}|\\^`\[\]]+',
                r'Панель.*?доступна.*?(http[^\s]+)',
                r'URL[:\-\s]+(http[^\s]+)',
                r'Ссылка[:\-\s]+(http[^\s]+)',
                r'Адрес панели[:\-\s]+(http[^\s]+)'
            ]
            
            for pattern in url_patterns:
                urls = re.findall(pattern, content, re.IGNORECASE)
                if urls:
                    credentials['url'] = urls[0].strip()
                    break
            
            login_patterns = [
                r'Логин[:\-\s]+([^\s\n]+)',
                r'Login[:\-\s]+([^\s\n]+)',
                r'Username[:\-\s]+([^\s\n]+)',
                r'логин[:\-\s]+([^\s\n]+)'
            ]
            
            for pattern in login_patterns:
                logins = re.findall(pattern, content, re.IGNORECASE)
                if logins:
                    login = logins[0].strip()
                    if not login.startswith('http') and len(login) > 1:
                        credentials['username'] = login
                        break
            
            password_patterns = [
                r'Пароль[:\-\s]+([^\s\n]+)',
                r'Password[:\-\s]+([^\s\n]+)',
                r'пароль[:\-\s]+([^\s\n]+)'
            ]
            
            for pattern in password_patterns:
                passwords = re.findall(pattern, content, re.IGNORECASE)
                if passwords:
                    password = passwords[0].strip()
                    if not password.startswith('http') and len(password) >= 3:
                        credentials['password'] = password
                        break
            
        except Exception as e:
            pass
        
        return credentials

    def validatePage(self):
        if self.auth_successful:
            return True
            
        url = self.panel_url_input.text().strip()
        username = self.username_input.text().strip()
        password = self.password_input.text()
        
        if not url or not username or not password:
            QMessageBox.warning(self, "Ошибка", "Заполните все поля")
            return False
            
        self.status_label.setText("Авторизация...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        
        success = [False]
        error_msg = [None]
        
        def _do_auth():
            try:
                if not self.ensure_ssh_connection():
                    error_msg[0] = "SSH соединение потеряно"
                    return
                    
                parsed = urlparse(url)
                hostname = parsed.hostname or "127.0.0.1"
                port = parsed.port or (443 if parsed.scheme == 'https' else 80)
                full_path = parsed.path.strip('/')
                
                clean_path = re.sub(r'(\/panel.*$)', '', f"/{full_path}").strip('/')
                
                use_https = parsed.scheme == 'https'
                protocol = "https" if use_https else "http"
                
                self.panel_info = {
                    'port': port,
                    'webpath': clean_path,
                    'base_url': f"{protocol}://127.0.0.1:{port}" + (f"/{clean_path}" if clean_path else ""),
                    'use_https': use_https
                }
                
                cookie_jar = f"/tmp/xui_cookie_{secrets.token_hex(4)}.jar"
                login_url = f"{protocol}://127.0.0.1:{port}"
                if clean_path:
                    login_url += f"/{clean_path}"
                login_url += "/login"
                
                login_json = json.dumps({"username": username, "password": password}).replace('"', '\\"')
                ssl_options = "-k" if use_https else ""
                
                host_header = f'-H "Host: {hostname}"' if use_https else ""
                
                cmd = (
                    f'COOKIE_JAR={cookie_jar} && '
                    f'LOGIN_RESPONSE=$(curl -s {ssl_options} -c "$COOKIE_JAR" -X POST "{login_url}" '
                    f'{host_header} -H "Content-Type: application/json" -d "{login_json}") && '
                    f'if echo "$LOGIN_RESPONSE" | grep -q \'"success":true\'; then '
                    f'  echo "AUTH_SUCCESS"; '
                    f'else '
                    f'  echo "AUTH_FAILED"; '
                    f'fi'
                )
                
                exit_code, out, err = self.ssh_mgr.exec_command(cmd, timeout=30)
                
                if "AUTH_SUCCESS" in out:
                    success[0] = True
                    self.panel_info['cookie_jar'] = cookie_jar
                else:
                    success[0] = False
                    error_msg[0] = "Неверные учетные данные"
                
            except Exception as e:
                success[0] = False
                error_msg[0] = str(e)
        
        t = threading.Thread(target=_do_auth, daemon=True)
        t.start()
        t.join(timeout=30)
        
        self.progress_bar.setVisible(False)
        
        if success[0]:
            self.auth_successful = True
            self.status_label.setText("Авторизация успешна!")
            return True
        else:
            self.auth_successful = False
            self.status_label.setText(f"Ошибка авторизации: {error_msg[0] or 'Таймаут'}")
            QMessageBox.warning(self, "Ошибка авторизации", 
                                f"Не удалось авторизоваться в 3x-ui панели:\n{error_msg[0] or 'Таймаут'}")
            return False

    def get_panel_info(self):
        return self.panel_info

    def isComplete(self):
        return self.auth_successful
    
    def nextId(self):
        return 3

class PageBackupPanel(BaseWizardPage):
    def __init__(self, ssh_mgr: SSHManager, logger_sig: LoggerSignal, log_window: LogWindow, sni_manager: SNIManager):
        super().__init__(ssh_mgr, logger_sig, log_window, sni_manager)
        self.setTitle("Шаг 4 — резервная копия настроек 3x-ui")
        self.setSubTitle("Рекомендуется сохранить резервную копию настроек перед продолжением")
        
        layout = QVBoxLayout()
        
        info_label = QLabel(
            "Перед внесением изменений в настройки 3x-ui настоятельно рекомендуется\n"
            "сохранить резервную копию всех настроек панели.\n\n"
            "Резервная копия содержит все настройки пользователей, серверов и конфигураций."
        )
        info_label.setWordWrap(True)
        
        self.backup_button = QPushButton("Создать и сохранить резервную копию")
        self.backup_button.clicked.connect(self.create_backup)
        
        self.status_label = QLabel("Нажмите кнопку для создания резервной копии")
        self.status_label.setWordWrap(True)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        
        self.file_path_label = QLabel("Файл не сохранен")
        self.file_path_label.setWordWrap(True)
        
        layout.addWidget(info_label)
        layout.addWidget(self.backup_button)
        layout.addWidget(self.status_label)
        layout.addWidget(self.progress_bar)
        layout.addWidget(QLabel("Сохраненный файл:"))
        layout.addWidget(self.file_path_label)
        
        self.setLayout(layout)
        
        self.backup_data = None
        self.backup_created = False
        self.panel_info = {}

    def initializePage(self):
        wizard = self.wizard()
        if wizard:
            auth_page_id = wizard.currentId() - 1
            auth_page = wizard.page(auth_page_id)
            if hasattr(auth_page, 'get_panel_info'):
                self.panel_info = auth_page.get_panel_info()
                self.log_message(f"[backup] Получена информация о панели: {self.panel_info.get('base_url', 'unknown')}")
            else:
                self.log_message("[backup] Предыдущая страница не содержит информации о панели")
                self.panel_info = {}
        else:
            self.panel_info = {}
            
        self.backup_created = False
        self.backup_data = None
        self.status_label.setText("Нажмите кнопку для создания резервной копии")
        self.file_path_label.setText("Файл не сохранен")

    def create_backup(self):
        if not hasattr(self, 'panel_info') or not self.panel_info:
            QMessageBox.warning(self, "Ошибка", "Информация о панели не найдена. Вернитесь на предыдущий шаг.")
            return
            
        required_fields = ['base_url', 'cookie_jar', 'use_https']
        for field in required_fields:
            if field not in self.panel_info:
                QMessageBox.warning(self, "Ошибка", f"Недостающая информация о панели: {field}")
                return
            
        self.backup_button.setEnabled(False)
        self.status_label.setText("Создание резервной копии...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        
        success = [False]
        error_msg = [None]
        
        def _do_backup():
            try:
                if not self.ensure_ssh_connection():
                    error_msg[0] = "SSH соединение потеряно и не может быть восстановлено"
                    return
                    
                backup_url = f"{self.panel_info['base_url']}/server/getDb"
                
                hostname = "127.0.0.1"
                ssl_options = "-k" if self.panel_info.get('use_https', False) else ""
                host_header = f'-H "Host: {hostname}"' if self.panel_info.get('use_https', False) else ""
                cookie_jar = self.panel_info.get('cookie_jar', '')
                
                if not cookie_jar:
                    error_msg[0] = "Файл cookies не найден"
                    return
                
                cmd = (
                    f'curl -s {ssl_options} -b "{cookie_jar}" "{backup_url}" '
                    f'{host_header} -H "Accept: application/octet-stream"'
                )
                
                self.log_message("[backup] Запрашиваем резервную копию базы данных")
                self.log_message(f"[backup] URL: {backup_url}")
                
                exit_code, out, err = self.ssh_mgr.exec_command(cmd, timeout=30)
                
                if exit_code == 0 and out:
                    if len(out) > 100 and not out.startswith('<!DOCTYPE') and not out.startswith('<html'):
                        success[0] = True
                        self.backup_data = out
                        self.log_message(f"[backup] Резервная копия получена успешно, размер: {len(out)} байт")
                    else:
                        success[0] = False
                        error_msg[0] = "Получен некорректный ответ (возможно, требуется повторная авторизация)"
                        self.log_message("[backup] Получен HTML вместо бинарных данных")
                        if len(out) < 500:
                            self.log_message(f"[backup] Ответ: {out[:200]}...")
                else:
                    success[0] = False
                    error_msg[0] = f"Ошибка выполнения команды: {err}"
                    self.log_message(f"[backup] Ошибка: exit_code={exit_code}, err={err}")
                    
            except Exception as e:
                success[0] = False
                error_msg[0] = str(e)
                self.log_message(f"[backup error] {e}")
        
        t = threading.Thread(target=_do_backup, daemon=True)
        t.start()
        t.join(timeout=45)
        
        self.progress_bar.setVisible(False)
        self.backup_button.setEnabled(True)
        
        if success[0] and self.backup_data:
            self.backup_created = True
            self.status_label.setText("Резервная копия успешно создана! Сохраняем файл...")
            
            self.save_backup_file()
        else:
            self.backup_created = False
            self.status_label.setText(f"Ошибка создания резервной копии: {error_msg[0] or 'Таймаут'}")
            QMessageBox.warning(self, "Ошибка", 
                               f"Не удалось создать резервную копию:\n{error_msg[0] or 'Таймаут'}")

    def save_backup_file(self):
        if not self.backup_data:
            QMessageBox.warning(self, "Ошибка", "Нет данных для сохранения")
            return
            
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"xui_backup_{timestamp}.db"
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Сохранить резервную копию 3x-ui",
            default_filename,
            "Database Files (*.db);;All Files (*)"
        )
        
        if file_path:
            try:
                if isinstance(self.backup_data, str):
                    file_data = self.backup_data.encode('latin-1')
                else:
                    file_data = self.backup_data
                
                with open(file_path, 'wb') as f:
                    f.write(file_data)
                
                self.file_path_label.setText(f"Файл сохранен: {file_path}")
                self.status_label.setText("Резервная копия успешно сохранена!")
                
                file_size = os.path.getsize(file_path)
                self.log_message(f"[backup] Файл сохранен: {file_path} ({file_size} байт)")
                
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить файл:\n{str(e)}")
                self.log_message(f"[backup error] Ошибка сохранения файла: {e}")
        else:
            self.backup_created = False
            self.status_label.setText("Сохранение отменено")
            self.file_path_label.setText("Файл не сохранен")

    def validatePage(self):
        return True

    def isComplete(self):
        return True

    def nextId(self):
        return self.wizard().currentId() + 1

class QRCodeWindow(QWidget):
    def __init__(self, vless_config):
        super().__init__()
        self.vless_config = vless_config
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle("QR Code - Vless Configuration")
        self.setFixedSize(400, 450)
        
        layout = QVBoxLayout()
        
        title_label = QLabel("QR код Vless конфигурации")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("font-size: 16px; font-weight: bold; margin: 10px;")
        
        self.qr_label = QLabel()
        self.qr_label.setAlignment(Qt.AlignCenter)
        self.qr_label.setMinimumSize(300, 300)
        
        self.config_display = QTextEdit()
        self.config_display.setMaximumHeight(80)
        self.config_display.setText(self.vless_config)
        self.config_display.setReadOnly(True)
        
        btn_layout = QHBoxLayout()
        save_btn = QPushButton("Сохранить QR код")
        save_btn.clicked.connect(self.save_qr_code)
        
        btn_layout.addWidget(save_btn)
        
        layout.addWidget(title_label)
        layout.addWidget(self.qr_label)
        layout.addLayout(btn_layout)
        
        self.setLayout(layout)
        self.generate_qr_code()
        
    def generate_qr_code(self):
        try:
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=8,
                border=2,
            )
            qr.add_data(self.vless_config)
            qr.make(fit=True)
            
            qr_img = qr.make_image(fill_color="black", back_color="white")
            qr_img = qr_img.resize((280, 280))
            
            img_data = io.BytesIO()
            qr_img.save(img_data, format='PNG')
            img_data = img_data.getvalue()
            
            pixmap = QPixmap()
            pixmap.loadFromData(img_data)
            self.qr_label.setPixmap(pixmap)
            
        except Exception as e:
            self.qr_label.setText(f"Ошибка генерации QR: {e}")
            
    def copy_config(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.vless_config)
        
    def save_qr_code(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self, 
            "Сохранить QR код", 
            "vless_qr_code.png", 
            "PNG Images (*.png)"
        )
        
        if file_path:
            try:
                qr = qrcode.QRCode(
                    version=1,
                    error_correction=qrcode.constants.ERROR_CORRECT_L,
                    box_size=10,
                    border=2,
                )
                qr.add_data(self.vless_config)
                qr.make(fit=True)
                
                qr_img = qr.make_image(fill_color="black", back_color="white")
                qr_img.save(file_path)
                
                QMessageBox.information(self, "Успех", f"QR код сохранен: {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить: {e}")

class TestWorker(QObject):
    finished = Signal()
    log_message = Signal(str)
    test_completed = Signal(dict)
    xray_log = Signal(str)
    curl_log = Signal(str)
    speedtest_log = Signal(str)
    
    def __init__(self, generated_config, test_type):
        super().__init__()
        self.generated_config = generated_config
        self.test_type = test_type
        self._is_running = True
        self.xray_process = None
        self.temp_config = None
        
    def stop(self):
        self._is_running = False
        if self.xray_process:
            try:
                self.xray_process.terminate()
                self.xray_process.wait(timeout=3)
            except:
                try:
                    self.xray_process.kill()
                except:
                    pass
        
    def run_test(self):
        try:
            self.log_message.emit("Начинаем тестирование конфигурации...")
            
            if not self.generated_config:
                self.log_message.emit("Ошибка: нет конфигурации для тестирования")
                self.test_completed.emit({'success': False, 'speed_ok': False})
                self.finished.emit()
                return
            
            vless_url = self.generated_config
            parsed = urlparse(vless_url)
            server_address = parsed.hostname
            server_port = parsed.port or 443
            user_id = parsed.username
            query_params = parse_qs(parsed.query)
            sni = query_params.get('sni', [''])[0]
            public_key = query_params.get('pbk', [''])[0]
            short_id = query_params.get('sid', [''])[0]
            flow = query_params.get('flow', [''])[0]

            self.log_message.emit(f"Тестируем подключение с SNI: {sni}...")

            config = {
                "log": {
                    "loglevel": "debug"
                },
                "inbounds": [
                    {
                        "port": 3080,
                        "listen": "127.0.0.1",
                        "protocol": "socks",
                        "settings": {
                            "udp": True,
                            "auth": "noauth"
                        }
                    }
                ],
                "outbounds": [
                    {
                        "tag": "vless-reality",
                        "protocol": "vless",
                        "settings": {
                            "vnext": [
                                {
                                    "address": server_address,
                                    "port": server_port,
                                    "users": [
                                        {
                                            "id": user_id,
                                            "flow": flow,
                                            "encryption": "none",
                                            "level": 0
                                        }
                                    ]
                                }
                            ]
                        },
                        "streamSettings": {
                            "network": "tcp",
                            "security": "reality",
                            "realitySettings": {
                                "publicKey": public_key,
                                "fingerprint": "chrome",
                                "serverName": sni,
                                "shortId": short_id,
                                "spiderX": "/"
                            }
                        }
                    },
                    {
                        "tag": "direct",
                        "protocol": "freedom",
                        "settings": {}
                    },
                    {
                        "tag": "block",
                        "protocol": "blackhole",
                        "settings": {
                            "response": {
                                "type": "http"
                            }
                        }
                    }
                ],
                "routing": {
                    "rules": [
                        {
                            "type": "field",
                            "ip": ["geoip:private"],
                            "outboundTag": "block"
                        }
                    ]
                }
            }

            self.temp_config = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8')
            json.dump(config, self.temp_config, indent=2)
            self.temp_config.flush()
            self.temp_config.close()

            xray_path = self.find_xray()
            if not xray_path:
                self.log_message.emit("Ошибка: xray не найден")
                self.test_completed.emit({'success': False, 'speed_ok': False})
                self.finished.emit()
                return

            startupinfo = None
            if os.name == 'nt':
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = 0

            self.xray_process = subprocess.Popen(
                [xray_path, "run", "-config", self.temp_config.name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8',
                errors='ignore',
                startupinfo=startupinfo,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )

            def read_xray_output():
                while self.xray_process and self.xray_process.poll() is None and self._is_running:
                    try:
                        line = self.xray_process.stdout.readline()
                        if not line:
                            break
                        if line.strip():
                            self.xray_log.emit(line.strip())
                    except Exception:
                        break

            output_thread = threading.Thread(target=read_xray_output, daemon=True)
            output_thread.start()

            def read_xray_errors():
                while self.xray_process and self.xray_process.poll() is None and self._is_running:
                    try:
                        line = self.xray_process.stderr.readline()
                        if not line:
                            break
                        if line.strip():
                            self.xray_log.emit(f"STDERR: {line.strip()}")
                    except Exception:
                        break

            error_thread = threading.Thread(target=read_xray_errors, daemon=True)
            error_thread.start()

            time.sleep(3)

            if not self._is_running:
                self.cleanup()
                self.finished.emit()
                return

            stats = {
                'ping': 0,
                'success': False,
                'download': 0,
                'upload': 0,
                'speed_ok': False
            }

            if self.test_type == "speed":
                speed_result = self.run_speedtest()
                if speed_result:
                    download_speed = speed_result.get('download', 0)
                    upload_speed = speed_result.get('upload', 0)
                    ping = speed_result.get('ping', 0)
                    
                    stats['ping'] = ping
                    stats['download'] = download_speed
                    stats['upload'] = upload_speed
                    stats['speed_ok'] = download_speed > 10 and upload_speed > 10
                    stats['success'] = True
                    
                    if stats['speed_ok']:
                        self.log_message.emit("Скорость в норме.")
                    else:
                        if download_speed <= 10:
                            self.log_message.emit(f"Скорость скачивания не в норме")
                        if upload_speed <= 10:
                            self.log_message.emit(f"Скорость загрузки не в норме")
                else:
                    self.log_message.emit("Ошибка измерения скорости")
                    stats['success'] = False
            else:
                test_cmd = [
                    "curl", 
                    "--socks5", "127.0.0.1:3080",
                    "--connect-timeout", "10",
                    "--max-time", "15",
                    "--verbose",
                    "http://cp.cloudflare.com/"
                ]

                start_time = time.time()
                try:
                    result = subprocess.run(
                        test_cmd, 
                        timeout=20, 
                        capture_output=True, 
                        text=True,
                        encoding='utf-8',
                        errors='ignore',
                        startupinfo=startupinfo,
                        creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
                    )
                    
                    if result.stderr:
                        self.curl_log.emit(result.stderr)
                    if result.stdout:
                        self.curl_log.emit(result.stdout)
                    
                    ping_time = round((time.time() - start_time) * 1000)
                    
                    if result.returncode == 0:
                        self.log_message.emit("URL тест: подключение успешно")
                        stats['ping'] = ping_time
                        stats['success'] = True
                        self.log_message.emit("URL тест завершен успешно")
                    else:
                        self.log_message.emit("URL тест: подключение не установлено")
                        stats['success'] = False
                        
                except subprocess.TimeoutExpired:
                    self.log_message.emit("URL тест: таймаут подключения")
                    stats['success'] = False
                except Exception as e:
                    self.log_message.emit(f"URL тест: ошибка подключения - {e}")
                    stats['success'] = False

            self.test_completed.emit(stats)

        except Exception as e:
            self.log_message.emit(f"Критическая ошибка тестирования: {e}")
            self.test_completed.emit({'success': False, 'speed_ok': False})
        finally:
            self.cleanup()
            self.finished.emit()

    def cleanup(self):
        try:
            if self.xray_process:
                self.xray_process.terminate()
                try:
                    self.xray_process.wait(timeout=3)
                except:
                    self.xray_process.kill()
                self.xray_process = None
        except:
            pass
        
        try:
            if self.temp_config:
                os.unlink(self.temp_config.name)
                self.temp_config = None
        except:
            pass

    def run_speedtest(self):
        try:
            self.speedtest_log.emit("=== НАЧАЛО ТЕСТА СКОРОСТИ ===")
            self.speedtest_log.emit("Настраиваем SOCKS5 прокси для speedtest (127.0.0.1:3080)...")
    
            os.environ['ALL_PROXY'] = 'socks5://127.0.0.1:3080'
            os.environ['HTTP_PROXY'] = 'socks5://127.0.0.1:3080'
            os.environ['HTTPS_PROXY'] = 'socks5://127.0.0.1:3080'
    
            self.speedtest_log.emit("Создаем объект Speedtest...")
            st = speedtest.Speedtest()
    
            self.speedtest_log.emit("Ищем лучший сервер...")
            best = st.get_best_server()
            ping = best.get('latency', 0) if best else 0
            if best:
                self.speedtest_log.emit(f"Найден сервер: {best.get('host')} ({best.get('sponsor')})")
                self.speedtest_log.emit(f"Локация: {best.get('name', 'N/A')}, {best.get('country', 'N/A')}")
            else:
                self.speedtest_log.emit("Не удалось найти сервер")
                return None
    
            self.speedtest_log.emit("Измеряем скорость СКАЧИВАНИЯ...")
            download_bps = st.download()
            download_mbps = download_bps / 1_000_000
            self.speedtest_log.emit(f"Download: {download_mbps:.2f} Мбит/с")
    
            self.speedtest_log.emit("Измеряем скорость ЗАГРУЗКИ...")
            upload_bps = st.upload(pre_allocate=False)
            upload_mbps = upload_bps / 1_000_000
            self.speedtest_log.emit(f"Upload: {upload_mbps:.2f} Мбит/с")
    
            self.speedtest_log.emit(f"Пинг: {ping:.2f} мс")
            self.speedtest_log.emit("=== ТЕСТ ЗАВЕРШЕН ===")
    
            return {
                "ping": ping,
                "download": download_mbps,
                "upload": upload_mbps
            }
    
        except Exception as e:
            self.speedtest_log.emit(f"Ошибка Speedtest: {e}")
            import traceback
            self.speedtest_log.emit(traceback.format_exc())
            return None
        finally:
            for var in ['ALL_PROXY', 'HTTP_PROXY', 'HTTPS_PROXY']:
                if var in os.environ:
                    del os.environ[var]

    def find_xray(self):
        possible_paths = [
            Path("xray") / "xray.exe",
            Path("xray.exe"),
            Path(sys.executable).parent / "xray.exe",
            Path(__file__).parent / "xray.exe",
            Path(".") / "xray.exe"
        ]
        
        for path in possible_paths:
            if path.exists():
                return str(path)
        
        try:
            result = subprocess.run(["where" if os.name == "nt" else "which", "xray"], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip().split('\n')[0]
        except:
            pass
            
        return None

class PageInbound(BaseWizardPage):
    test_log_signal = Signal(str)
    test_completed_signal = Signal(dict)
    xray_log_signal = Signal(str)
    curl_log_signal = Signal(str)
    
    def __init__(self, ssh_mgr: SSHManager, logger_sig: LoggerSignal, log_window: LogWindow, sni_manager: SNIManager, page_auth):
        super().__init__(ssh_mgr, logger_sig, log_window, sni_manager)
        self.page_auth = page_auth
        self.setTitle("Шаг 5 — настройка Vless")
        self.setSubTitle("Автоматическая настройка Vless Reality подключения с подбором SNI")
        
        self.is_first_configuration = True
        self.test_log_signal.connect(self.add_test_log)
        self.test_completed_signal.connect(self.on_test_completed)
        self.xray_log_signal.connect(self.log_window.append_xray_log)
        self.curl_log_signal.connect(self.log_window.append_curl_log)
        
        self.speedtest_log_window = SpeedtestLogWindow()
        
        layout = QVBoxLayout()
        
        self.info_label = QLabel(
            "Инструкции по настройке и использованию VPN-приложений доступны "
            "<a href='https://wiki.yukikras.net/ru/nastroikavpn'>здесь</a>.<br>"
            "Автоподбор настроек находится в статусе БЕТА, рекомендуется подбирать SNI вручную."
        )
        self.info_label.setOpenExternalLinks(True)
        
        layout.addWidget(self.info_label)
        
        self.status_label = QLabel("Настройка Vless Reality подключения")
        layout.addWidget(self.status_label)
        
        auto_test_layout = QHBoxLayout()
        auto_test_label = QLabel("Статус автоподбора:")
        self.auto_test_status = QLabel("ОЖИДАНИЕ")
        self.auto_test_status.setStyleSheet("""
            QLabel {
                padding: 4px 8px;
                border-radius: 4px;
                background-color: #6c757d;
                color: white;
                font-weight: bold;
            }
        """)
        self.auto_test_status.setAlignment(Qt.AlignCenter)
        self.auto_test_status.setMinimumWidth(120)
        
        auto_test_layout.addWidget(auto_test_label)
        auto_test_layout.addWidget(self.auto_test_status)
        auto_test_layout.addStretch()
        
        layout.addLayout(auto_test_layout)
        
        self.sni_info_label = QLabel("")
        self.sni_info_label.setWordWrap(True)
        layout.addWidget(self.sni_info_label)
        
        self.vless_label = QLabel("VLESS конфигурация:")
        self.vless_display = QPlainTextEdit()
        self.vless_display.setMaximumHeight(80)
        self.vless_display.setReadOnly(True)
        
        btn_layout1 = QHBoxLayout()
        self.copy_btn = QPushButton("Скопировать")
        self.copy_btn.clicked.connect(self.copy_vless)
        
        self.qr_btn = QPushButton("Показать QR код")
        self.qr_btn.clicked.connect(self.show_qr_code)
        
        self.regenerate_btn = QPushButton("Сгенерировать ключ")
        self.regenerate_btn.clicked.connect(self.regenerate_vless)
        
        self.test_btn = QPushButton("Протестировать")
        self.test_btn.clicked.connect(self.test_vless_config)
        
        btn_layout1.addWidget(self.copy_btn)
        btn_layout1.addWidget(self.qr_btn)
        btn_layout1.addWidget(self.regenerate_btn)
        btn_layout1.addWidget(self.test_btn)
        
        self.test_group = QGroupBox("Тестирование конфигурации")
        test_layout = QVBoxLayout(self.test_group)
        
        test_options_layout = QHBoxLayout()
        self.test_type_group = QButtonGroup(self)
        
        self.speed_test_radio = QRadioButton("Тест скорости")
        self.speed_test_radio.setChecked(True)
        self.url_test_radio = QRadioButton("URL тест")
        
        self.test_type_group.addButton(self.speed_test_radio)
        self.test_type_group.addButton(self.url_test_radio)
        
        test_options_layout.addWidget(self.speed_test_radio)
        test_options_layout.addWidget(self.url_test_radio)
        test_options_layout.addStretch()
        
        self.test_log_display = QPlainTextEdit()
        self.test_log_display.setMaximumHeight(150)
        self.test_log_display.setReadOnly(True)
        
        test_layout.addLayout(test_options_layout)
        test_layout.addWidget(self.test_log_display)
        
        self.test_actions_layout = QHBoxLayout()
        #self.work_btn = QPushButton("Работает - завершить работу мастера")
        #self.work_btn.clicked.connect(self.config_works)
        self.not_work_btn = QPushButton("Настроить (VPN) Vless автоматически")
        self.not_work_btn.clicked.connect(self.start_auto_configuration)
        
        #self.test_actions_layout.addWidget(self.work_btn)
        self.test_actions_layout.addWidget(self.not_work_btn)
        
        layout.addWidget(self.vless_label)
        layout.addWidget(self.vless_display)
        layout.addLayout(btn_layout1)
        layout.addWidget(self.test_group)
        layout.addLayout(self.test_actions_layout)
        
        self.setLayout(layout)
        
        self.current_inbound_id = None
        self.generated_config = None
        self.panel_info = None
        self.cookie_jar = None
        self.server_host = None
        self.existing_clients = []
        self.current_sni = None
        self.test_thread = None
        self.test_worker = None
        self.testing_in_progress = False
        self.auto_config_in_progress = False
        self.auto_config_stop = False
        self.current_stats = {
            'ping': 0,
            'download': 0,
            'upload': 0,
            'success': False,
            'speed_ok': False
        }

        self.setup_shortcuts()

    def update_auto_test_status(self, status, color):
        """Обновляет статус автотестирования с указанным цветом"""
        status_texts = {
            "waiting": "ОЖИДАНИЕ",
            "testing": "Идёт автоматический подбор настроек, пожалуйста ожидайте.",
            "success": "УСПЕХ"
        }
        
        self.auto_test_status.setText(status_texts[status])
        self.auto_test_status.setStyleSheet(f"""
            QLabel {{
                padding: 4px 8px;
                border-radius: 4px;
                background-color: {color};
                color: white;
                font-weight: bold;
            }}
        """)

    def setup_shortcuts(self):
        shortcut = QShortcut(QKeySequence("Ctrl+L"), self)
        shortcut.activated.connect(self.show_speedtest_logs)

    def show_speedtest_logs(self):
        self.speedtest_log_window.show()
        self.speedtest_log_window.raise_()
        self.speedtest_log_window.activateWindow()

    def show_qr_code(self):
        if self.generated_config:
            self.qr_window = QRCodeWindow(self.generated_config)
            self.qr_window.show()
        else:
            QMessageBox.warning(self, "Ошибка", "Нет конфигурации для отображения QR кода")

    def regenerate_vless(self):
        if not self.panel_info:
            QMessageBox.warning(self, "Ошибка", "Нет данных панели для генерации ключа")
            return
            
        self.status_label.setText("Генерация нового Vless ключа...")
        self.clear_test_log()
        self.add_test_log("Генерируем новый Vless ключ...")
        
        threading.Thread(target=self._regenerate_vless_worker, daemon=True).start()

    def _regenerate_vless_worker(self):
        try:
            priv_key, pub_key = self._get_keys()
            if not priv_key or not pub_key:
                self._emit_test_log("Не удалось получить ключи")
                return
                
            sni = self.get_next_sni()
            if not sni:
                self._emit_test_log("Нет доступных SNI")
                return
                
            if self.current_inbound_id:
                success = self._update_inbound_with_keys(priv_key, pub_key, sni)
            else:
                success = self._create_inbound_with_keys(priv_key, pub_key, sni)
                
            if success:
                self._emit_test_log("Vless ключ успешно сгенерирован")
                QMetaObject.invokeMethod(self, "_update_status_success", 
                                       Qt.QueuedConnection,
                                       Q_ARG(str, "Vless ключ сгенерирован"))
            else:
                self._emit_test_log("Ошибка генерации Vless ключа")
                
        except Exception as e:
            self._emit_test_log(f"Ошибка генерации: {e}")

    @Slot(str)
    def _update_status_success(self, message):
        self.status_label.setText(message)

    @Slot(str)
    def add_test_log(self, message):
        current_text = self.test_log_display.toPlainText()
        new_text = current_text + f"{datetime.now().strftime('%H:%M:%S')} - {message}\n"
        self.test_log_display.setPlainText(new_text)
        cursor = self.test_log_display.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.test_log_display.setTextCursor(cursor)

    def clear_test_log(self):
        self.test_log_display.clear()

    def start_auto_configuration(self):
        if self.auto_config_in_progress:
            self.auto_config_stop = True
            self.not_work_btn.setText("Настроить (VPN) Vless")
            self.auto_config_in_progress = False
            self.update_auto_test_status("waiting", "#6c757d")  # Серый - ожидание
            self.add_test_log("Авто-подбор остановлен")
            
            if self.test_worker:
                self.test_worker.stop()
            return
            
        if not self.panel_info:
            self.add_test_log("Ошибка: нет данных панели. Вернитесь на предыдущие шаги.")
            return
            
        self.auto_config_in_progress = True
        self.auto_config_stop = False
        self.not_work_btn.setText("Остановить авто-подбор")
        self.update_auto_test_status("testing", "#ffc107")  # Желтый - подбор
        self.clear_test_log()
        self.add_test_log("Запуск автоматического подбора SNI...")
        self.add_test_log("Ищем рабочий SNI")
        
        threading.Thread(target=self._run_auto_configuration, daemon=True).start()

    def _run_auto_configuration(self):
        test_count = 0
        
        while not self.auto_config_stop and self.auto_config_in_progress:
            test_count += 1
            self._emit_test_log(f"Попытка #{test_count}")
            
            sni = self.get_next_sni()
            if not sni:
                self._emit_test_log("Нет доступных SNI для тестирования")
                break
                
            self._emit_test_log(f"Тестируем SNI: {sni}")
            
            config_updated = self._update_configuration_with_sni(sni)
            if not config_updated:
                self._emit_test_log(f"Ошибка обновления конфигурации для SNI: {sni}")
                continue
                
            time.sleep(3)
            
            if self.auto_config_stop:
                break
                
            speed_ok = self._test_configuration_speed()
            
            if speed_ok:
                download_speed = self.current_stats.get('download', 0)
                upload_speed = self.current_stats.get('upload', 0)
                self._emit_test_log(f"Найден рабочий SNI: {sni}")
                
                self._emit_auto_config_success(sni)
                break
            else:
                download_speed = self.current_stats.get('download', 0)
                upload_speed = self.current_stats.get('upload', 0)
                if download_speed > 0 or upload_speed > 0:
                    self._emit_test_log(f"Скорость ниже средней")
                else:
                    self._emit_test_log("Подключение не работает")
        
        self._emit_auto_config_finished()

    def _emit_test_log(self, message):
        self.test_log_signal.emit(message)

    def _emit_auto_config_success(self, sni):
        QMetaObject.invokeMethod(self, "_on_auto_config_success", 
                               Qt.QueuedConnection,
                               Q_ARG(str, sni))

    def _emit_auto_config_finished(self):
        QMetaObject.invokeMethod(self, "_on_auto_config_finished", 
                               Qt.QueuedConnection)

    @Slot(str)
    def _on_auto_config_success(self, sni):
        download_speed = self.current_stats.get('download', 0)
        upload_speed = self.current_stats.get('upload', 0)
        self.status_label.setText(f"Авто-подбор успешно завершен, скопируйте Vless ключ")
        self.update_auto_test_status("success", "#28a745")  # Зеленый - успех
        self.auto_config_in_progress = False
        self.not_work_btn.setText("Настроить (VPN) Vless")
        self.add_test_log("Авто-подбор успешно завершен!")

    @Slot()
    def _on_auto_config_finished(self):
        self.auto_config_in_progress = False
        self.not_work_btn.setText("Настроить (VPN) Vless")
        self.update_auto_test_status("waiting", "#6c757d")  # Серый - ожидание
        self.status_label.setText("Авто-подбор завершен")
        self.add_test_log("Авто-подбор завершен")

    def _update_configuration_with_sni(self, sni):
        try:
            priv_key, pub_key = self._get_keys()
            if not priv_key or not pub_key:
                self._emit_test_log("Не удалось получить ключи")
                return False
            
            if self.current_inbound_id:
                success = self._update_inbound_with_keys(priv_key, pub_key, sni)
            else:
                success = self._create_inbound_with_keys(priv_key, pub_key, sni)
            
            if success:
                for i in range(10):
                    if self.generated_config and self.current_sni == sni:
                        return True
                    time.sleep(1)
                    if self.auto_config_stop:
                        return False
            
            return False
            
        except Exception as e:
            self._emit_test_log(f"Ошибка обновления конфигурации: {e}")
            return False

    def _get_keys(self):
        try:
            base_url = self.panel_info['base_url']
            use_https = self.panel_info.get('use_https', False)
            ssl_options = "-k" if use_https else ""
            
            cmd_get_keys = f'curl -s {ssl_options} -b "{self.cookie_jar}" -X POST "{base_url}/server/getNewX25519Cert" -H "Content-Type: application/x-www-form-urlencoded; charset=UTF-8" -H "X-Requested-With: XMLHttpRequest"'
            
            self._emit_test_log("Получаем ключи...")
            
            exit_code, out, err = self.ssh_mgr.exec_command(cmd_get_keys)
            
            if exit_code != 0:
                raise Exception(f"Ошибка curl: {err}")
            
            cleaned_out = self.clean_json_response(out)
            keys_data = json.loads(cleaned_out)
                
            if not keys_data.get('success'):
                raise Exception(f"API ошибка: {keys_data.get('msg', 'Unknown error')}")
                
            priv_key = keys_data['obj']['privateKey']
            pub_key = keys_data['obj']['publicKey']
            self._emit_test_log("Ключи получены успешно")
            return priv_key, pub_key
            
        except Exception as e:
            self._emit_test_log(f"Ошибка получения ключей: {e}")
            return None, None

    def _create_inbound_with_keys(self, priv_key, pub_key, sni):
        try:
            base_url = self.panel_info['base_url']
            use_https = self.panel_info.get('use_https', False)
            ssl_options = "-k" if use_https else ""
            
            short_id = secrets.token_hex(8)
            client_id = str(uuid.uuid4())
            
            settings = {
                "clients": [
                    {
                        "id": client_id,
                        "flow": "xtls-rprx-vision",
                        "email": f"client-{secrets.token_hex(4)}",
                        "limitIp": 0,
                        "totalGB": 0,
                        "expiryTime": 0,
                        "enable": True,
                        "tgId": "",
                        "subId": secrets.token_hex(16),
                        "comment": "",
                        "reset": 0
                    }
                ],
                "decryption": "none",
                "fallbacks": []
            }
            
            stream_settings = {
                "network": "tcp",
                "security": "reality",
                "externalProxy": [],
                "realitySettings": {
                    "show": False,
                    "xver": 0,
                    "dest": f"{sni}:443",
                    "serverNames": [sni],
                    "privateKey": priv_key,
                    "minClientVer": "",
                    "maxClientVer": "",
                    "maxTimediff": 0,
                    "shortIds": [short_id],
                    "mldsa65Seed": "",
                    "settings": {
                        "publicKey": pub_key,
                        "fingerprint": "chrome",
                        "serverName": "",
                        "spiderX": "/",
                        "mldsa65Verify": ""
                    }
                },
                "tcpSettings": {
                    "acceptProxyProtocol": False,
                    "header": {"type": "none"}
                }
            }
            
            sniffing = {
                "enabled": True,
                "destOverride": ["http", "tls"],
                "metadataOnly": False,
                "routeOnly": False
            }
            
            from urllib.parse import quote_plus
            settings_enc = quote_plus(json.dumps(settings, indent=2))
            stream_enc = quote_plus(json.dumps(stream_settings, indent=2))
            sniffing_enc = quote_plus(json.dumps(sniffing, indent=2))
            
            cmd_add = (
                f'curl -s {ssl_options} -b "{self.cookie_jar}" -X POST "{base_url}/panel/inbound/add" -d '
                f'"up=0&down=0&total=0&remark=reality443-auto&enable=true&expiryTime=0&listen=&port=443&protocol=vless&'
                f'settings={settings_enc}&streamSettings={stream_enc}&sniffing={sniffing_enc}"'
            )
            
            self._emit_test_log(f"Создаем inbound с SNI: {sni}")
            
            exit_code, out, err = self.ssh_mgr.exec_command(cmd_add)
            
            cleaned_out = self.clean_json_response(out)
            result = json.loads(cleaned_out)
            
            if result.get('success'):
                self._emit_test_log("Inbound создан успешно")
                self.current_inbound_id = result.get('obj', {}).get('id')
                self._generate_and_show_vless(client_id, sni, pub_key, short_id)
                return True
            else:
                raise Exception(f"API ошибка: {result.get('msg', 'Unknown error')}")
                
        except Exception as e:
            self._emit_test_log(f"Ошибка создания инбаунда: {e}")
            return False

    def _update_inbound_with_keys(self, priv_key, pub_key, sni):
        try:
            base_url = self.panel_info['base_url']
            use_https = self.panel_info.get('use_https', False)
            ssl_options = "-k" if use_https else ""
            
            short_id = secrets.token_hex(8)
            
            if self.existing_clients:
                settings = {
                    "clients": self.existing_clients,
                    "decryption": "none", 
                    "fallbacks": []
                }
                client_id = self.existing_clients[0].get('id', str(uuid.uuid4()))
            else:
                client_id = str(uuid.uuid4())
                settings = {
                    "clients": [
                        {
                            "id": client_id,
                            "flow": "xtls-rprx-vision",
                            "email": f"client-{secrets.token_hex(4)}",
                            "limitIp": 0,
                            "totalGB": 0,
                            "expiryTime": 0,
                            "enable": True,
                            "tgId": "",
                            "subId": secrets.token_hex(16),
                            "comment": "",
                            "reset": 0
                        }
                    ],
                    "decryption": "none",
                    "fallbacks": []
                }
            
            stream_settings = {
                "network": "tcp",
                "security": "reality",
                "externalProxy": [],
                "realitySettings": {
                    "show": False,
                    "xver": 0,
                    "dest": f"{sni}:443",
                    "serverNames": [sni],
                    "privateKey": priv_key,
                    "minClientVer": "",
                    "maxClientVer": "",
                    "maxTimediff": 0,
                    "shortIds": [short_id],
                    "mldsa65Seed": "",
                    "settings": {
                        "publicKey": pub_key,
                        "fingerprint": "chrome",
                        "serverName": "",
                        "spiderX": "/",
                        "mldsa65Verify": ""
                    }
                },
                "tcpSettings": {
                    "acceptProxyProtocol": False,
                    "header": {"type": "none"}
                }
            }
            
            sniffing = {
                "enabled": True,
                "destOverride": ["http", "tls"],
                "metadataOnly": False,
                "routeOnly": False
            }
            
            from urllib.parse import quote_plus
            settings_enc = quote_plus(json.dumps(settings, indent=2))
            stream_enc = quote_plus(json.dumps(stream_settings, indent=2))
            sniffing_enc = quote_plus(json.dumps(sniffing, indent=2))
            
            cmd_update = (
                f'curl -s {ssl_options} -b "{self.cookie_jar}" -X POST "{base_url}/panel/inbound/update/{self.current_inbound_id}" -d '
                f'"up=0&down=0&total=0&remark=reality443-auto&enable=true&expiryTime=0&listen=&port=443&protocol=vless&'
                f'settings={settings_enc}&streamSettings={stream_enc}&sniffing={sniffing_enc}"'
            )
            
            self._emit_test_log(f"Обновляем inbound с SNI: {sni}")
            
            exit_code, out, err = self.ssh_mgr.exec_command(cmd_update)
            
            cleaned_out = self.clean_json_response(out)
            result = json.loads(cleaned_out)
            
            if result.get('success'):
                self._emit_test_log("Inbound обновлен успешно")
                self._generate_and_show_vless(client_id, sni, pub_key, short_id)
                return True
            else:
                raise Exception(f"API ошибка: {result.get('msg', 'Unknown error')}")
                
        except Exception as e:
            self._emit_test_log(f"Ошибка обновления инбаунда: {e}")
            return False

    def _generate_and_show_vless(self, client_id, sni, public_key, short_id):
        if not self.server_host:
            self.server_host = "127.0.0.1"
            
        vless_config = f"vless://{client_id}@{self.server_host}:443?type=tcp&security=reality&sni={sni}&fp=chrome&pbk={public_key}&sid={short_id}&flow=xtls-rprx-vision#reality-443"
        
        QMetaObject.invokeMethod(self, "_update_vless_display", 
                               Qt.QueuedConnection,
                               Q_ARG(str, vless_config),
                               Q_ARG(str, sni))
        
        self.generated_config = vless_config
        self.current_sni = sni

    @Slot(str, str)
    def _update_vless_display(self, vless_config, sni):
        self.vless_display.setPlainText(vless_config)
        self.status_label.setText(f"Конфигурация создана с SNI: {sni}")

    def _test_configuration_speed(self):
        if not self.generated_config:
            return False
            
        loop = QEventLoop()
        test_success = [False]
        
        def on_test_completed(stats):
            test_success[0] = stats.get('speed_ok', False) and stats.get('success', False)
            loop.quit()
        
        self.test_completed_signal.connect(on_test_completed, Qt.QueuedConnection)
        
        QTimer.singleShot(0, lambda: self._safe_start_test_thread("speed"))
        
        QTimer.singleShot(60000, loop.quit)
        loop.exec()
        
        try:
            self.test_completed_signal.disconnect(on_test_completed)
        except:
            pass
        
        return test_success[0]

    def _safe_start_test_thread(self, test_type):
        if self.testing_in_progress or self.auto_config_stop:
            return
            
        self.start_test_thread(test_type)

    def start_test_thread(self, test_type):
        if self.testing_in_progress:
            return
            
        self.testing_in_progress = True
        self.test_btn.setEnabled(False)
        
        self.test_thread = QThread()
        self.test_worker = TestWorker(self.generated_config, test_type)
        self.test_worker.moveToThread(self.test_thread)
        
        self.test_thread.started.connect(self.test_worker.run_test)
        self.test_worker.finished.connect(self.test_thread.quit)
        self.test_worker.finished.connect(self.test_worker.deleteLater)
        self.test_thread.finished.connect(self._on_test_thread_finished)
        self.test_worker.log_message.connect(self.test_log_signal.emit)
        self.test_worker.test_completed.connect(self.test_completed_signal.emit)
        self.test_worker.xray_log.connect(self.xray_log_signal.emit)
        self.test_worker.curl_log.connect(self.curl_log_signal.emit)
        self.test_worker.speedtest_log.connect(self.speedtest_log_window.append_log)
        
        self.test_thread.start()

    def _on_test_thread_finished(self):
        self.test_thread.deleteLater()
        self.testing_in_progress = False
        self.test_btn.setEnabled(True)

    @Slot(dict)
    def on_test_completed(self, stats):
        self.current_stats.update(stats)

    def initializePage(self):
        self.update_sni_info()
        self.panel_info = self.page_auth.get_panel_info()
        self.cookie_jar = self.panel_info.get('cookie_jar', '')
        
        self.update_auto_test_status("waiting", "#6c757d")  # Серый - ожидание
        
        if self.ssh_mgr.client:
            transport = self.ssh_mgr.client.get_transport()
            if transport:
                self.server_host = transport.getpeername()[0]
                self.log_message(f"IP сервера: {self.server_host}")

        self.start_configuration()

    def update_sni_info(self):
        used_count = self.sni_manager.get_used_count()
        available_count = self.sni_manager.get_available_count()
        self.sni_info_label.setText(f"Использовано SNI: {used_count}, Доступно: {available_count}")

    def get_next_sni(self):
        sni = self.sni_manager.get_next_sni()
        if sni:
            self.current_sni = sni
            self.sni_manager.mark_sni_used(sni)
            self.update_sni_info()
            self.log_message(f"Используем SNI: {sni}")
        return sni

    def start_configuration(self):
        self.status_label.setText("Начинаем настройку подключения...")
        self.clear_test_log()
        self.current_stats = {'ping': 0, 'download': 0, 'upload': 0, 'success': False, 'speed_ok': False}
        self.check_existing_inbound()

    def check_existing_inbound(self):
        self.log_message("Проверяем существующие inbound...")
        
        if not self.ensure_ssh_connection():
            self.status_label.setText("Ошибка: SSH соединение потеряно")
            return
            
        base_url = self.panel_info['base_url']
        use_https = self.panel_info.get('use_https', False)
        ssl_options = "-k" if use_https else ""
        
        cmd_list = f'curl -s {ssl_options} -b "{self.cookie_jar}" -X POST "{base_url}/panel/inbound/list"'
        
        try:
            exit_code, out, err = self.ssh_mgr.exec_command(cmd_list)
            
            if exit_code != 0:
                raise Exception(f"Ошибка curl: {err}")
            
            cleaned_out = self.clean_json_response(out)
            result = json.loads(cleaned_out)
            
            if result.get('success'):
                inbounds = result.get('obj', [])
                inbound_found = False
                
                for inbound in inbounds:
                    if inbound.get('port') == 443:
                        self.current_inbound_id = inbound.get('id')
                        inbound_found = True
                        self.log_message(f"Найден inbound-443 с ID: {self.current_inbound_id}")
                        self.existing_clients = self.get_existing_clients(inbound)
                        self.log_message(f"Найдено клиентов: {len(self.existing_clients)}")
                        break
                
                if inbound_found:
                    self.status_label.setText("Найден существующий инбаунд. Нажмите 'Настроить (VPN) Vless' для подбора SNI")
                else:
                    self.status_label.setText("Инбаунд не найден. Нажмите 'Настроить (VPN) Vless' для создания")
            else:
                raise Exception(f"API ошибка: {result.get('msg', 'Unknown error')}")
                
        except Exception as e:
            self.log_message(f"Ошибка проверки: {e}")
            if "10054" in str(e):
                self.log_message("Повторяем запрос...")
                time.sleep(2)
                self.check_existing_inbound()
            else:
                self.handle_api_error(str(e))

    def get_existing_clients(self, inbound):
        try:
            settings_str = inbound.get('settings', '{}')
            settings = json.loads(settings_str)
            clients = settings.get('clients', [])
            return clients
        except Exception as e:
            self.log_message(f"Ошибка парсинга клиентов: {e}")
            return []

    def handle_api_error(self, error_message):
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Ошибка API")
        msg_box.setTextFormat(Qt.TextFormat.RichText)
        msg_box.setText(
            f"Произошла ошибка при обращении к 3x-ui панели:<br><br>"
            f"{error_message}<br><br>"
            "Вероятнее всего используется не совместимая с утилитой версия 3x-ui панели.<br>"
            "Подробнее об этой ошибки написано <a href='https://github.com/YukiKras/vless-wizard/wiki#%D0%BE%D1%88%D0%B8%D0%B1%D0%BA%D0%B0-api-%D1%87%D1%82%D0%BE-%D0%B4%D0%B5%D0%BB%D0%B0%D1%82%D1%8C'>в инструкции, в разделе FAQ</a>.<br><br>"
            "Хотите переустановить 3x-ui панель?"
        )
        msg_box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        msg_box.setTextInteractionFlags(Qt.TextBrowserInteraction)
        reply = msg_box.exec()
        if reply == QMessageBox.Yes:
            self.wizard().back()
            self.wizard().back()
            self.wizard().currentPage().force_reinstall()
        else:
            self.status_label.setText(f"Ошибка: {error_message}")

    def test_vless_config(self):
        if not self.generated_config:
            self.add_test_log("Ошибка: нет конфигурации для тестирования")
            return
    
        if self.testing_in_progress:
            self.add_test_log("Тестирование уже выполняется...")
            return
    
        test_type = "speed" if self.speed_test_radio.isChecked() else "url"
        self.start_test_thread(test_type)

    def config_works(self):
        self.auto_config_stop = True
        self.auto_config_in_progress = False
        
        if self.test_worker:
            self.test_worker.stop()
            
        self.not_work_btn.setText("Настроить (VPN) Vless")
        self.update_auto_test_status("success", "#28a745")  # Зеленый - успех
        self.status_label.setText("Конфигурация работает! Настройка завершена.")
        self.add_test_log("Конфигурация подтверждена - работает корректно")
        self.log_message("Настройка завершена успешно!")

    def clean_json_response(self, response):
        cleaned = response.strip()
        start_idx = cleaned.find('{')
        end_idx = cleaned.rfind('}') + 1
        
        if start_idx != -1 and end_idx != -1:
            return cleaned[start_idx:end_idx]
        return cleaned

    def copy_vless(self):
        if self.generated_config:
            clipboard = QApplication.clipboard()
            clipboard.setText(self.generated_config)
            
            original_text = self.copy_btn.text()
            self.copy_btn.setText("Скопировано!")
            QTimer.singleShot(2000, lambda: self.copy_btn.setText(original_text))

    def isComplete(self):
        return True

CURRENT_VERSION = "1.1.1"
GITHUB_USER = "yukikras"
GITHUB_REPO = "vless-wizard"

def check_for_update(parent=None):
    try:
        url = f"https://api.github.com/repos/{GITHUB_USER}/{GITHUB_REPO}/releases/latest"
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        data = response.json()

        latest_version = data["tag_name"].lstrip("v")
        assets = data.get("assets", [])
        download_url = assets[0]["browser_download_url"] if assets else data["html_url"]

        if version.parse(latest_version) > version.parse(CURRENT_VERSION):
            msg = QMessageBox(parent)
            msg.setIcon(QMessageBox.Information)
            msg.setWindowTitle("Обновление доступно")
            msg.setText(f"Доступна новая версия: {latest_version}\n"
                        f"Текущая версия: {CURRENT_VERSION}")
            msg.setInformativeText("Во избежание ошибок работы утилиты рекомендуется установить обновление, вы хотите его установить?")
            msg.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
            if msg.exec() == QMessageBox.Yes:
                webbrowser.open(download_url)
                return True
    except Exception as e:
        print(f"[update] Ошибка проверки обновлений: {e}")
    return False

class XUIWizard(QWizard):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Vless Wizard")
        self.resize(590, 510)
        
        self.log_window = LogWindow()
        self.ssh_mgr = SSHManager()
        self.logger_sig = LoggerSignal()
        self.sni_manager = SNIManager()
        
        self.page_ssh = PageSSH(self.ssh_mgr, self.logger_sig, self.log_window, self.sni_manager)
        self.page_install = PageInstallXUI(self.ssh_mgr, self.logger_sig, self.log_window, self.sni_manager)
        self.page_auth = PagePanelAuth(self.ssh_mgr, self.logger_sig, self.page_install, self.log_window, self.sni_manager)
        self.page_backup = PageBackupPanel(self.ssh_mgr, self.logger_sig, self.log_window, self.sni_manager)
        self.page_inbound = PageInbound(self.ssh_mgr, self.logger_sig, self.log_window, self.sni_manager, self.page_auth)
        
        self.addPage(self.page_ssh)
        self.addPage(self.page_install)
        self.addPage(self.page_auth)
        self.addPage(self.page_backup)
        self.addPage(self.page_inbound)
        
        self.setOption(QWizard.IndependentPages, False)
        self.setWizardStyle(QWizard.ModernStyle)
        self.setOption(QWizard.NoBackButtonOnStartPage, True)
        self.setOption(QWizard.HaveCustomButton1, True)
        self.setButtonText(QWizard.CustomButton1, "Логи")
        self.customButtonClicked.connect(self.toggle_logs)
        
        self.logger_sig.new_line.connect(self.log_window.append_main_log)

    def toggle_logs(self):
        if self.log_window.isVisible():
            self.log_window.hide()
        else:
            self.log_window.show()
            self.log_window.raise_()
            self.log_window.activateWindow()

    def closeEvent(self, event):
        try:
            if hasattr(self.page_inbound, 'stop_xray'):
                self.page_inbound.stop_xray()
            self.ssh_mgr.close()
            self.log_window.close()
        except Exception:
            pass
        super().closeEvent(event)

def main():
    app = QApplication(sys.argv)

    translator = QTranslator()
    locale = QLocale.system().name()

    if translator.load(f"qt_{locale}", QLibraryInfo.path(QLibraryInfo.TranslationsPath)):
       app.installTranslator(translator)

    if check_for_update():
        sys.exit(0)

    wiz = XUIWizard()
    wiz.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()