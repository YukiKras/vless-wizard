# -*- coding: utf-8 -*-
import sys
import os
import json
import uuid
import time
import threading
import tempfile
import secrets
import re
import subprocess
import random
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
    QProgressBar, QDialogButtonBox, QListWidget
)
from PySide6.QtCore import Qt, Signal, QObject, QTimer
from PySide6.QtGui import QClipboard


def resource_path(relative_path: str) -> Path:
    """Возвращает путь к ресурсу (совместимо с PyInstaller --onefile и --onedir)."""
    if hasattr(sys, "_MEIPASS"):  # режим onefile
        base_path = Path(sys._MEIPASS)
    else:  # режим onedir или IDE
        base_path = Path(getattr(sys, 'frozen', False) and Path(sys.executable).parent or Path(__file__).parent)
    return base_path / relative_path

class SSHManager:
    def __init__(self):
        self.client = None
        self.sftp = None

    def connect(self, host, port=22, username=None, password=None, pkey_path=None, timeout=10):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if pkey_path:
            key = paramiko.RSAKey.from_private_key_file(pkey_path)
            self.client.connect(hostname=host, port=port, username=username, pkey=key, timeout=timeout)
        else:
            self.client.connect(hostname=host, port=port, username=username, password=password, timeout=timeout)
        self.sftp = self.client.open_sftp()
        return True

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
        if not self.client:
            raise RuntimeError("SSH not connected")
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
        if not self.client:
            raise RuntimeError("SSH not connected")
        stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
        out = stdout.read().decode(errors="ignore")
        err = stderr.read().decode(errors="ignore")
        exit_status = stdout.channel.recv_exit_status()
        return exit_status, out, err

    def upload_file(self, local_path, remote_path):
        if not self.sftp:
            raise RuntimeError("SFTP not connected")
        self.sftp.put(local_path, remote_path)
        self.exec_command(f"chmod +x {remote_path}")

    def download_file(self, remote_path, local_path):
        if not self.sftp:
            raise RuntimeError("SFTP not connected")
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
    domain_groups = {}
    for host in filtered:
        parts = host.split('.')
        if len(parts) >= 2:
            tld = f"{parts[-2]}.{parts[-1]}"
        else:
            tld = host
        domain_groups.setdefault(tld, []).append(host)
    
    # Собираем все хосты без повторений и перемешиваем весь список
    result = []
    for tld, hosts_list in domain_groups.items():
        # Добавляем все хосты из группы (они уже уникальные благодаря filtered)
        result.extend(hosts_list)
    
    import random
    random.shuffle(result)
    return result

def test_vless_config_with_curl(vless_url, timeout=10):
    try:
        parsed = urlparse(vless_url)
        server_address = parsed.hostname
        server_port = parsed.port or 443
        user_id = parsed.username
        query_params = parse_qs(parsed.query)
        sni = query_params.get('sni', [''])[0]
        public_key = query_params.get('pbk', [''])[0]
        short_id = query_params.get('sid', [''])[0]

        config = {
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "port": 1080,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True}
            }],
            "outbounds": [{
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": server_address,
                        "port": server_port,
                        "users": [{"id": user_id, "encryption": "none"}]
                    }]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "serverName": sni,
                        "publicKey": public_key,
                        "shortId": short_id,
                        "fingerprint": "chrome"
                    }
                }
            }]
        }

        temp_config = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8')
        json.dump(config, temp_config, indent=2)
        temp_config.flush()
        temp_config.close()

        xray_path = Path("xray") / "xray.exe"
        if not xray_path.exists():
            xray_path = Path("xray.exe")
            if not xray_path.exists():
                return False, "xray.exe не найден"

        process = subprocess.Popen(
            [str(xray_path), "run", "-config", temp_config.name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        time.sleep(3)

        test_cmd = [
            "curl", "-s", "--socks5", "127.0.0.1:1080",
            "--connect-timeout", str(timeout),
            "--max-time", str(timeout),
            "http://cp.cloudflare.com/"
        ]

        try:
            result = subprocess.run(test_cmd, timeout=timeout+5, capture_output=True, text=True)
            if result.returncode == 0:
                return True, "Успешно подключено к cp.cloudflare.com"
            else:
                return False, f"Curl вернул код {result.returncode}: {result.stderr.strip() or result.stdout.strip()}"
        except subprocess.TimeoutExpired:
            return False, "Таймаут при тестировании curl"
        finally:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
            try:
                os.unlink(temp_config.name)
            except:
                pass

    except Exception as e:
        return False, f"Ошибка подготовки теста: {e}"

class LoggerSignal(QObject):
    new_line = Signal(str)

class LogWindow(QPlainTextEdit):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Логи Vless Wizard")
        self.setReadOnly(True)
        self.setMinimumSize(600, 400)
        
    def append_log(self, line):
        self.appendPlainText(line)
        cursor = self.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        self.setTextCursor(cursor)
        self.ensureCursorVisible()

class BaseWizardPage(QWizardPage):
    def __init__(self, ssh_mgr: SSHManager, logger_sig: LoggerSignal, log_window: LogWindow):
        super().__init__()
        self.ssh_mgr = ssh_mgr
        self.logger_sig = logger_sig
        self.log_window = log_window

    def log_message(self, message):
        self.logger_sig.new_line.emit(message)

class PageSSH(BaseWizardPage):
    def __init__(self, ssh_mgr: SSHManager, logger_sig: LoggerSignal, log_window: LogWindow):
        super().__init__(ssh_mgr, logger_sig, log_window)
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
        layout.addWidget(QLabel("Порт:"))
        layout.addWidget(self.port_input)
        layout.addWidget(QLabel("Имя пользователя:"))
        layout.addWidget(self.user_input)
        layout.addWidget(QLabel("Пароль:"))
        layout.addWidget(self.pass_input)
        
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
    def __init__(self, ssh_mgr: SSHManager, logger_sig: LoggerSignal, log_window: LogWindow):
        super().__init__(ssh_mgr, logger_sig, log_window)
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
                    QMessageBox.warning(self, "Ошибка", f"Не удалось сохранить файл: {e}")

    def force_reinstall(self):
        reply = QMessageBox.question(self, "Переустановка 3x-ui", 
                                   "Вы уверены, что хотите переустановить 3x-ui панель?\n\n"
                                   "Это может занять несколько минут.",
                                   QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            self.force_install = True
            self.installation_complete = False
            self.xui_installed = False
            self.panel_credentials = {}
            self.credentials_label.setText("")
            self.copy_btn.setVisible(False)
            self.save_btn.setVisible(False)
            self.reinstall_btn.setVisible(False)
            self.check_and_install_xui()

    def initializePage(self):
        self.check_and_install_xui()

    def check_and_install_xui(self):
        self.status_label.setText("Проверка 3x-ui...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        
        def _check_install():
            try:
                if self.force_install:
                    self.log_message("[check] Принудительная переустановка...")
                    self.install_xui()
                    return
                    
                code, out, err = self.ssh_mgr.exec_command("command -v x-ui || which x-ui || echo '__XUI_NOT_FOUND__'")
                if "__XUI_NOT_FOUND__" in out or not out.strip():
                    self.log_message("[check] x-ui не найден, начинаем установку...")
                    self.install_xui()
                else:
                    self.xui_installed = True
                    self.log_message(f"[check] x-ui найден: {out.strip()}")
                    self.status_label.setText("3x-ui уже установлен")
                    self.progress_bar.setVisible(False)
                    self.installation_complete = True
                    self.reinstall_btn.setVisible(True)
                    self.completeChanged.emit()
                    
            except Exception as e:
                self.log_message(f"[check error] {e}")
                self.status_label.setText(f"Ошибка проверки: {e}")
                self.progress_bar.setVisible(False)

        t = threading.Thread(target=_check_install, daemon=True)
        t.start()

    def install_xui(self):
        self.status_label.setText("Установка 3x-ui...")
        self.log_message("[install] Начинаем установку 3x-ui...")
    
        script_path = resource_path("3xinstall.sh")
        self.log_message(f"[install] Путь к скрипту: {script_path}")
    
        if not script_path.exists():
            self.log_message("[install] Ошибка: файл 3xinstall.sh не найден")
            self.status_label.setText("Ошибка: 3xinstall.sh не найден")
            self.progress_bar.setVisible(False)
            return

        remote_script = f"/tmp/3xinstall_{secrets.token_hex(4)}.sh"
        try:
            self.ssh_mgr.upload_file(str(script_path), remote_script)
            self.log_message(f"[install] Скрипт загружен на сервер: {remote_script}")
        except Exception as e:
            self.log_message(f"[install error] Не удалось загрузить скрипт: {e}")
            self.status_label.setText("Ошибка загрузки скрипта")
            self.progress_bar.setVisible(False)
            return

        def stdout_cb(line):
            self.log_message(line)
            self.parse_credentials(line)

        def stderr_cb(line):
            self.log_message("[ERR] " + line)

        try:
            cmd = f"bash {remote_script}"
            chan = self.ssh_mgr.exec_command_stream(cmd, 
                                              callback_stdout=stdout_cb, 
                                              callback_stderr=stderr_cb, 
                                              get_pty=True,
                                              env={"OUTPUT_FILE": "/tmp/xui_install.log"})
            
            def _wait_install():
                while not chan.exit_status_ready():
                    time.sleep(0.5)
                
                self.read_install_log()
                
            t = threading.Thread(target=_wait_install, daemon=True)
            t.start()
            
        except Exception as e:
            self.log_message(f"[install error] {e}")
            self.status_label.setText(f"Ошибка установки: {e}")
            self.progress_bar.setVisible(False)

    def parse_credentials(self, line):
        line_lower = line.lower()
        
        if "http" in line_lower and ("://" in line or "panel" in line_lower):
            urls = re.findall(r'https?://[^\s<>"\'{}|\\^`\[\]]+', line)
            if urls and 'url' not in self.panel_credentials:
                self.panel_credentials['url'] = urls[0]
                self.log_message(f"[creds] Найден URL: {urls[0]}")
        
        if any(keyword in line_lower for keyword in ['username', 'user', 'логин', 'login']):
            parts = re.split(r'[:=]', line, maxsplit=1)
            if len(parts) > 1 and 'username' not in self.panel_credentials:
                username = parts[1].strip()
                if username and len(username) > 1:
                    self.panel_credentials['username'] = username
                    self.log_message(f"[creds] Найден username: {username}")
        
        if any(keyword in line_lower for keyword in ['password', 'pass', 'пароль']):
            parts = re.split(r'[:=]', line, maxsplit=1)
            if len(parts) > 1 and 'password' not in self.panel_credentials:
                password = parts[1].strip()
                if password and len(password) > 1:
                    self.panel_credentials['password'] = password
                    self.log_message(f"[creds] Найден password: {password}")

    def read_install_log(self):
        try:
            exit_code, out, err = self.ssh_mgr.exec_command("cat /tmp/xui_install.log 2>/dev/null || echo 'NO_LOG_FILE'")
            
            if "NO_LOG_FILE" not in out:
                self.log_message("[log] Читаем лог установки...")
                lines = out.splitlines()
                
                for line in lines:
                    if "http" in line.lower() and "панель" in line.lower():
                        urls = re.findall(r'https?://[^\s<>"\'{}|\\^`\[\]]+', line)
                        if urls and 'url' not in self.panel_credentials:
                            self.panel_credentials['url'] = urls[0]
                            self.log_message(f"[log] Найден URL из лога: {urls[0]}")
                    
                    if "логин:" in line.lower() or "login:" in line.lower():
                        parts = line.split(":", 1)
                        if len(parts) > 1 and 'username' not in self.panel_credentials:
                            username = parts[1].strip()
                            if username:
                                self.panel_credentials['username'] = username
                                self.log_message(f"[log] Найден username из лога: {username}")
                    
                    if "пароль:" in line.lower() or "password:" in line.lower():
                        parts = line.split(":", 1)
                        if len(parts) > 1 and 'password' not in self.panel_credentials:
                            password = parts[1].strip()
                            if password:
                                self.panel_credentials['password'] = password
                                self.log_message(f"[log] Найден password из лога: {password}")
            
            self.check_exported_variables()
            
        except Exception as e:
            self.log_message(f"[log error] Ошибка чтения лога: {e}")
            self.check_exported_variables()

    def check_exported_variables(self):
        try:
            cmd = "echo \"URL=$url; USERNAME=$username; PASSWORD=$password\""
            exit_code, out, err = self.ssh_mgr.exec_command(cmd)
            
            for line in out.splitlines():
                if 'URL=' in line:
                    match = re.search(r'URL=([^;]+)', line)
                    if match and match.group(1).strip() and 'url' not in self.panel_credentials:
                        self.panel_credentials['url'] = match.group(1).strip()
                        self.log_message(f"[export] Найден URL: {self.panel_credentials['url']}")
                if 'USERNAME=' in line:
                    match = re.search(r'USERNAME=([^;]+)', line)
                    if match and match.group(1).strip() and 'username' not in self.panel_credentials:
                        self.panel_credentials['username'] = match.group(1).strip()
                        self.log_message(f"[export] Найден username: {self.panel_credentials['username']}")
                if 'PASSWORD=' in line:
                    match = re.search(r'PASSWORD=([^;]+)', line)
                    if match and match.group(1).strip() and 'password' not in self.panel_credentials:
                        self.panel_credentials['password'] = match.group(1).strip()
                        self.log_message(f"[export] Найден password: {self.panel_credentials['password']}")
            
            self.finalize_installation()
            
        except Exception as e:
            self.log_message(f"[export error] {e}")
            self.finalize_installation()

    def finalize_installation(self):
        self.xui_installed = True
        self.installation_complete = True
        self.progress_bar.setVisible(False)
        
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
        self.credentials_label.setText(cred_text)
        self.status_label.setText("Установка завершена")
        self.copy_btn.setVisible(True)
        self.save_btn.setVisible(True)
        self.reinstall_btn.setVisible(True)
        
        self.completeChanged.emit()

    def get_credentials(self):
        return self.panel_credentials

    def isComplete(self):
        return self.installation_complete

class PagePanelAuth(BaseWizardPage):
    def __init__(self, ssh_mgr: SSHManager, logger_sig: LoggerSignal, page_install: PageInstallXUI, log_window: LogWindow):
        super().__init__(ssh_mgr, logger_sig, log_window)
        self.page_install = page_install
        self.setTitle("Шаг 3 — авторизация в 3x-ui панели")
        self.setSubTitle("Введите данные для входа в 3x-ui панель")
        
        layout = QVBoxLayout()
        
        self.panel_url_input = QLineEdit()
        self.panel_url_input.setPlaceholderText("URL панели 3x-ui")
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Логин")
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Пароль")
        self.password_input.setEchoMode(QLineEdit.Password)
        
        self.status_label = QLabel("Предупреждение! Wizard на следующем шагу будет\nменять некоторые настройки в 3x-ui панели!\nЕсли у вас настроен 2FA, пожалуйста, временно отключите его.")
        self.status_label.setWordWrap(True)
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        
        layout.addWidget(QLabel("URL адрес панели:"))
        layout.addWidget(self.panel_url_input)
        layout.addWidget(QLabel("Логин:"))
        layout.addWidget(self.username_input)
        layout.addWidget(QLabel("Пароль:"))
        layout.addWidget(self.password_input)
        layout.addWidget(self.status_label)
        layout.addWidget(self.progress_bar)
        
        self.setLayout(layout)
        
        self.auth_successful = False
        self.panel_info = {}

    def initializePage(self):
        creds = self.page_install.get_credentials()
        if 'url' in creds:
            self.panel_url_input.setText(creds['url'])
        if 'username' in creds:
            self.username_input.setText(creds['username'])
        if 'password' in creds:
            self.password_input.setText(creds['password'])
        
        self.auth_successful = False

    def validatePage(self):
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
                parsed = urlparse(url)
                hostname = parsed.hostname or "127.0.0.1"
                port = parsed.port or (443 if parsed.scheme == 'https' else 80)
                webpath = parsed.path.strip('/')
                
                self.panel_info = {
                    'port': port,
                    'webpath': webpath,
                    'base_url': f"http://127.0.0.1:{port}" + (f"/{webpath}" if webpath else "")
                }
                
                cookie_jar = f"/tmp/xui_cookie_{secrets.token_hex(4)}.jar"
                login_url = f"http://127.0.0.1:{port}"
                if webpath:
                    login_url += f"/{webpath}"
                login_url += "/login"
                
                login_json = json.dumps({"username": username, "password": password}).replace('"', '\\"')
                
                cmd = (
                    f'COOKIE_JAR={cookie_jar} && '
                    f'LOGIN_RESPONSE=$(curl -s -c "$COOKIE_JAR" -X POST "{login_url}" '
                    f'-H "Content-Type: application/json" -d "{login_json}") && '
                    f'echo "=== LOGIN RESPONSE ===" && '
                    f'echo "$LOGIN_RESPONSE" && '
                    f'echo "=== END LOGIN RESPONSE ===" && '
                    f'if echo "$LOGIN_RESPONSE" | grep -q \'"success":true\'; then '
                    f'  echo "AUTH_SUCCESS"; '
                    f'else '
                    f'  echo "AUTH_FAILED"; '
                    f'fi'
                )
                
                self.log_message(f"[auth] Выполняем авторизацию:")
                self.log_message(f"[auth] URL: {login_url}")
                self.log_message(f"[auth] Команда: curl -s -c cookie_jar -X POST {login_url} -H 'Content-Type: application/json' -d '{{\"username\": \"{username}\", \"password\": \"***\"}}'")
                
                exit_code, out, err = self.ssh_mgr.exec_command(cmd, timeout=30)
                
                self.log_message(f"[auth] Статус выполнения: {exit_code}")
                if "AUTH_SUCCESS" in out:
                    success[0] = True
                    self.panel_info['cookie_jar'] = cookie_jar
                    self.log_message("[auth] Авторизация прошла успешно")
                else:
                    success[0] = False
                    error_msg[0] = "Неверные учетные данные или недоступна панель"
                    self.log_message("[auth] Ошибка авторизации")
                
            except Exception as e:
                success[0] = False
                error_msg[0] = str(e)
                self.log_message(f"[auth error] {e}")
        
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
        return True

class PageInbound(BaseWizardPage):
    def __init__(self, ssh_mgr: SSHManager, logger_sig: LoggerSignal, page_auth: PagePanelAuth, log_window: LogWindow):
        super().__init__(ssh_mgr, logger_sig, log_window)
        self.page_auth = page_auth
        self.setTitle("Шаг 4 — настройка Vless")
        self.setSubTitle("Создание и настройка Vless Reality подключения с автоматическим подбором SNI")
        
        layout = QVBoxLayout()
        
        self.status_label = QLabel("Нажмите 'Начать настройку' для автоматической настройки Vless")
        self.start_btn = QPushButton("Начать настройку")
        self.start_btn.clicked.connect(self.start_configuration)
        
        self.vless_label = QLabel("VLESS конфигурация:")
        self.vless_display = QPlainTextEdit()
        self.vless_display.setMaximumHeight(100)
        self.vless_display.setReadOnly(True)
        self.copy_btn = QPushButton("Скопировать в буфер обмена")
        self.copy_btn.clicked.connect(self.copy_vless)
        self.copy_btn.setVisible(False)
        
        self.test_label = QLabel("Проверьте работу конфигурации и нажмите соответствующую кнопку:")
        self.work_btn = QPushButton("Работает - Завершить работу мастера")
        self.work_btn.clicked.connect(self.config_works)
        self.not_work_btn = QPushButton("Не работает - Попробовать другой SNI")
        self.not_work_btn.clicked.connect(self.config_not_works)
        
        self.work_btn.setVisible(False)
        self.not_work_btn.setVisible(False)
        
        layout.addWidget(self.status_label)
        layout.addWidget(self.start_btn)
        layout.addWidget(self.vless_label)
        layout.addWidget(self.vless_display)
        layout.addWidget(self.copy_btn)
        layout.addWidget(self.test_label)
        layout.addWidget(self.work_btn)
        layout.addWidget(self.not_work_btn)
        
        self.setLayout(layout)
        
        self.current_inbound_id = None
        self.generated_config = None
        self.sni_list = []
        self.current_sni_index = 0
        self.panel_info = None
        self.cookie_jar = None
        self.server_host = None
        self.existing_clients = []

    def initializePage(self):
        self.load_sni_list()
        self.panel_info = self.page_auth.get_panel_info()
        self.cookie_jar = self.panel_info.get('cookie_jar', '')
        
        if self.ssh_mgr.client:
            transport = self.ssh_mgr.client.get_transport()
            if transport:
                self.server_host = transport.getpeername()[0]
                self.log_message(f"[info] IP сервера: {self.server_host}")

    def load_sni_list(self):
        self.log_message("[sni] Загрузка списка SNI...")
        try:
            self.sni_list = get_sni_whitelist()
            self.log_message(f"[sni] Загружено {len(self.sni_list)} SNI доменов")
        except Exception as e:
            self.log_message(f"[sni error] {e}")

    def get_next_sni(self):
        if not self.sni_list:
            self.load_sni_list()
        if self.current_sni_index >= len(self.sni_list):
            self.current_sni_index = 0
        sni = self.sni_list[self.current_sni_index]
        self.current_sni_index += 1
        return sni

    def start_configuration(self):
        self.status_label.setText("Начинаем настройку инбаунда...")
        self.start_btn.setVisible(False)
        
        self.check_existing_inbound()

    def check_existing_inbound(self):
        self.log_message("[check] Проверяем существующие inbound...")
        
        base_url = self.panel_info['base_url']
        cmd_list = f'curl -s -b "{self.cookie_jar}" -X POST "{base_url}/panel/inbound/list"'
        
        try:
            exit_code, out, err = self.ssh_mgr.exec_command(cmd_list)
            self.log_message(f"[check] Статус: {exit_code}")
            
            if exit_code != 0:
                raise Exception(f"Ошибка curl: {err}")
            
            cleaned_out = self.clean_json_response(out)
            result = json.loads(cleaned_out)
            
            if result.get('success'):
                inbounds = result.get('obj', [])
                self.current_inbound_id = None
                self.existing_clients = []
                
                for inbound in inbounds:
                    if inbound.get('port') == 443:
                        self.current_inbound_id = inbound.get('id')
                        self.log_message(f"[check] Найден inbound-443 с ID: {self.current_inbound_id}")
                        
                        self.existing_clients = self.get_existing_clients(inbound)
                        self.log_message(f"[check] Найдено клиентов: {len(self.existing_clients)}")
                        break
                
                if self.current_inbound_id:
                    self.update_inbound_sni()
                else:
                    self.create_new_inbound()
            else:
                raise Exception(f"API ошибка: {result.get('msg', 'Unknown error')}")
                
        except json.JSONDecodeError as e:
            self.log_message(f"[check error] Ошибка парсинга JSON: {e}")
            self.handle_api_error("Ошибка парсинга ответа от панели")
        except Exception as e:
            self.log_message(f"[check error] {e}")
            self.handle_api_error(str(e))

    def handle_api_error(self, error_message):
        reply = QMessageBox.question(self, "Ошибка API", 
                                   f"Произошла ошибка при обращении к 3x-ui панели:\n\n{error_message}\n\n"
                                   "Возможно, панель работает некорректно или требует переустановки.\n"
                                   "Хотите переустановить 3x-ui панель?",
                                   QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            self.wizard().back()
            self.wizard().back()
            self.wizard().currentPage().force_reinstall()
        else:
            self.status_label.setText(f"Ошибка: {error_message}")
            self.start_btn.setVisible(True)

    def get_existing_clients(self, inbound):
        try:
            settings_str = inbound.get('settings', '{}')
            settings = json.loads(settings_str)
            clients = settings.get('clients', [])
            self.log_message(f"[clients] Найдено {len(clients)} клиентов")
            return clients
        except Exception as e:
            self.log_message(f"[clients error] Ошибка парсинга клиентов: {e}")
            return []

    def create_new_inbound(self):
        self.log_message("[create] Создаем новый inbound на порту 443...")
        
        priv_key, pub_key = self.get_keys()
        if not priv_key or not pub_key:
            return
        
        sni = self.get_next_sni()
        
        self.create_inbound_with_keys(priv_key, pub_key, sni)

    def update_inbound_sni(self):
        self.log_message("[update] Обновляем SNI у существующего inbound...")
        
        priv_key, pub_key = self.get_keys()
        if not priv_key or not pub_key:
            return
        
        sni = self.get_next_sni()
        
        self.update_inbound_with_keys(priv_key, pub_key, sni)

    def get_keys(self):
        base_url = self.panel_info['base_url']
        cmd_get_keys = f'curl -s -b "{self.cookie_jar}" -X POST "{base_url}/server/getNewX25519Cert" -H "Content-Type: application/x-www-form-urlencoded; charset=UTF-8" -H "X-Requested-With: XMLHttpRequest"'
        
        self.log_message("[keys] Получаем ключи...")
        
        try:
            exit_code, out, err = self.ssh_mgr.exec_command(cmd_get_keys)
            self.log_message(f"[keys] Статус: {exit_code}")
            
            if exit_code != 0:
                raise Exception(f"Ошибка curl: {err}")
            
            cleaned_out = self.clean_json_response(out)
            keys_data = json.loads(cleaned_out)
                
            if not keys_data.get('success'):
                raise Exception(f"API ошибка: {keys_data.get('msg', 'Unknown error')}")
                
            priv_key = keys_data['obj']['privateKey']
            pub_key = keys_data['obj']['publicKey']
            self.log_message("[keys] Ключи получены успешно")
            return priv_key, pub_key
            
        except json.JSONDecodeError as e:
            self.log_message(f"[keys error] Ошибка парсинга JSON ключей: {e}")
            self.handle_api_error("Ошибка парсинга ключей от панели")
            return None, None
        except Exception as e:
            self.log_message(f"[keys error] {e}")
            self.handle_api_error(f"Ошибка получения ключей: {e}")
            return None, None

    def create_inbound_with_keys(self, priv_key, pub_key, sni):
        base_url = self.panel_info['base_url']
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
            f'curl -s -b "{self.cookie_jar}" -X POST "{base_url}/panel/inbound/add" -d '
            f'"up=0&down=0&total=0&remark=reality443-auto&enable=true&expiryTime=0&listen=&port=443&protocol=vless&'
            f'settings={settings_enc}&streamSettings={stream_enc}&sniffing={sniffing_enc}"'
        )
        
        self.log_message(f"[create] Создаем inbound с SNI: {sni}")
        
        try:
            exit_code, out, err = self.ssh_mgr.exec_command(cmd_add)
            self.log_message(f"[create] Статус: {exit_code}")
            
            cleaned_out = self.clean_json_response(out)
            result = json.loads(cleaned_out)
            
            if result.get('success'):
                self.log_message("[create] Inbound создан успешно")
                self.current_inbound_id = result.get('obj', {}).get('id')
                self.generate_and_show_vless(client_id, sni, pub_key, short_id)
            else:
                raise Exception(f"API ошибка: {result.get('msg', 'Unknown error')}")
                
        except json.JSONDecodeError as e:
            self.log_message(f"[create error] Ошибка парсинга JSON: {e}")
            self.handle_api_error("Ошибка парсинга ответа при создании инбаунда")
        except Exception as e:
            self.log_message(f"[create error] {e}")
            self.handle_api_error(f"Ошибка создания инбаунда: {e}")

    def update_inbound_with_keys(self, priv_key, pub_key, sni):
        base_url = self.panel_info['base_url']
        short_id = secrets.token_hex(8)
        
        if self.existing_clients:
            settings = {
                "clients": self.existing_clients,
                "decryption": "none", 
                "fallbacks": []
            }
            client_id = self.existing_clients[0].get('id', str(uuid.uuid4()))
            self.log_message(f"[update] Используем существующих клиентов: {len(self.existing_clients)}")
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
            self.log_message("[update] Создаем нового клиента")
        
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
            f'curl -s -b "{self.cookie_jar}" -X POST "{base_url}/panel/inbound/update/{self.current_inbound_id}" -d '
            f'"up=0&down=0&total=0&remark=reality443-auto&enable=true&expiryTime=0&listen=&port=443&protocol=vless&'
            f'settings={settings_enc}&streamSettings={stream_enc}&sniffing={sniffing_enc}"'
        )
        
        self.log_message(f"[update] Обновляем inbound с SNI: {sni}")
        
        try:
            exit_code, out, err = self.ssh_mgr.exec_command(cmd_update)
            self.log_message(f"[update] Статус: {exit_code}")
            
            cleaned_out = self.clean_json_response(out)
            result = json.loads(cleaned_out)
            
            if result.get('success'):
                self.log_message("[update] Inbound обновлен успешно")
                self.generate_and_show_vless(client_id, sni, pub_key, short_id)
            else:
                raise Exception(f"API ошибка: {result.get('msg', 'Unknown error')}")
                
        except json.JSONDecodeError as e:
            self.log_message(f"[update error] Ошибка парсинга JSON: {e}")
            self.handle_api_error("Ошибка парсинга ответа при обновлении инбаунда")
        except Exception as e:
            self.log_message(f"[update error] {e}")
            self.handle_api_error(f"Ошибка обновления инбаунда: {e}")

    def generate_and_show_vless(self, client_id, sni, public_key, short_id):
        if not self.server_host:
            self.server_host = "127.0.0.1"
            
        vless_config = f"vless://{client_id}@{self.server_host}:443?type=tcp&security=reality&sni={sni}&fp=chrome&pbk={public_key}&sid={short_id}&flow=xtls-rprx-vision#reality-443"
        
        self.vless_display.setPlainText(vless_config)
        self.generated_config = vless_config
        
        self.status_label.setText(f"Конфигурация создана с SNI: {sni}")
        self.copy_btn.setVisible(True)
        self.work_btn.setVisible(True)
        self.not_work_btn.setVisible(True)
        
        self.log_message(f"[config] VLESS конфигурация создана с SNI: {sni}")

    def config_works(self):
        self.status_label.setText("Конфигурация работает! Настройка завершена.")
        self.work_btn.setVisible(False)
        self.not_work_btn.setVisible(False)
        
        self.log_message("[success] Настройка завершена успешно!")

    def config_not_works(self):
        self.status_label.setText("Пробуем другой SNI...")
        self.work_btn.setVisible(False)
        self.not_work_btn.setVisible(False)
        
        if self.current_inbound_id:
            self.update_inbound_sni()
        else:
            self.create_new_inbound()

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

import sys
import requests
import webbrowser
from packaging import version
from PySide6.QtWidgets import QApplication, QMessageBox, QWizard

# ======= Константы обновлений =======
CURRENT_VERSION = "1.0.0"
GITHUB_USER = "yukikras"
GITHUB_REPO = "vless-wizard"
# ===================================

def check_for_update(parent=None):
    """Проверяет наличие новой версии на GitHub."""
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
            msg.setInformativeText("Хотите скачать обновление?")
            msg.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
            if msg.exec() == QMessageBox.Yes:
                webbrowser.open(download_url)
                return True
    except Exception as e:
        print(f"[update] Ошибка проверки обновлений: {e}")
    return False


# ======= Твой класс визарда =======
class XUIWizard(QWizard):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Vless Wizard")
        self.resize(500, 500)
        
        self.log_window = LogWindow()
        self.ssh_mgr = SSHManager()
        self.logger_sig = LoggerSignal()
        
        self.page_ssh = PageSSH(self.ssh_mgr, self.logger_sig, self.log_window)
        self.page_install = PageInstallXUI(self.ssh_mgr, self.logger_sig, self.log_window)
        self.page_auth = PagePanelAuth(self.ssh_mgr, self.logger_sig, self.page_install, self.log_window)
        self.page_inbound = PageInbound(self.ssh_mgr, self.logger_sig, self.page_auth, self.log_window)
        
        self.addPage(self.page_ssh)
        self.addPage(self.page_install)
        self.addPage(self.page_auth)
        self.addPage(self.page_inbound)
        
        self.setOption(QWizard.IndependentPages, False)
        self.setWizardStyle(QWizard.ModernStyle)
        self.setOption(QWizard.NoBackButtonOnStartPage, True)
        self.setOption(QWizard.HaveCustomButton1, True)
        self.setButtonText(QWizard.CustomButton1, "Логи")
        self.customButtonClicked.connect(self.toggle_logs)
        
        self.logger_sig.new_line.connect(self.log_window.append_log)

    def toggle_logs(self):
        if self.log_window.isVisible():
            self.log_window.hide()
        else:
            self.log_window.show()
            self.log_window.raise_()
            self.log_window.activateWindow()

    def closeEvent(self, event):
        try:
            self.ssh_mgr.close()
            self.log_window.close()
        except Exception:
            pass
        super().closeEvent(event)

def main():
    app = QApplication(sys.argv)

    if check_for_update():
        sys.exit(0)

    wiz = XUIWizard()
    wiz.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()