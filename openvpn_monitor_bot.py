# -*- coding: utf-8 -*-
"""
OpenVPN Telegram Monitor Bot

Новый функционал (было):
 - Массовое удаление ключей через ввод номеров/диапазонов (all | 1,2,5-9)
 - Массовая отправка ключей (multi-select)
 - Массовое включение заблокированных клиентов (multi-select)
 - Массовое отключение активных клиентов (multi-select)
 - Списки через Telegraph
 - Продление: опция не пересоздавать .ovpn (SEND_NEW_OVPN_ON_RENEW = False)
 - Бэкап: исключение *.tar.gz / *.tgz из /root при создании бэкапа
 - Меню бэкапов с удалением

Добавлено (логические сроки):
 - Логический срок клиента хранится в JSON (clients_meta.json), сертификат НЕ переissue при продлении
 - Disable/Enable через запись 'disable' / 'enable' в ccd/<client>
 - Энфорсер истечения каждые 12 часов (можно вручную ускорить для отладки)
 - Продление устанавливает новый срок (кол-во дней от текущего момента) и снимает блокировку
 - Сессия отключается точечно через management (client-kill), если настроено
"""

import os
import subprocess
import time
from datetime import datetime, timedelta
from typing import Optional, Tuple, List, Dict
from html import escape
import glob
import json
import math
import traceback
import re
import requests
import shutil
import socket

from OpenSSL import crypto
import pytz

from telegram import (
    Update, InlineKeyboardButton, InlineKeyboardMarkup, InputFile
)
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler, ContextTypes, MessageHandler, filters
)

from config import TOKEN, ADMIN_ID
from backup_restore import (
    create_backup as br_create_backup,
    apply_restore,
    BACKUP_OUTPUT_DIR,
    MANIFEST_NAME
)

# -------- Версия / обновление --------
BOT_VERSION = "2025-09-18-logical-expiry"
UPDATE_SOURCE_URL = "https://raw.githubusercontent.com/XSFORM/update_bot/main/openvpn_monitor_bot.py"
SIMPLE_UPDATE_CMD = (
    "curl -L -o /root/monitor_bot/openvpn_monitor_bot.py "
    f"{UPDATE_SOURCE_URL} && systemctl restart vpn_bot.service"
)

# Telegraph
TELEGRAPH_TOKEN_FILE = "/root/monitor_bot/telegraph_token.txt"
TELEGRAPH_SHORT_NAME = "vpn-bot"
TELEGRAPH_AUTHOR = "VPN Bot"

# Пути
KEYS_DIR = "/root"
OPENVPN_DIR = "/etc/openvpn"
EASYRSA_DIR = "/etc/openvpn/easy-rsa"
STATUS_LOG = "/var/log/openvpn/status.log"
CCD_DIR = "/etc/openvpn/ccd"

# Режимы продления (исторический флаг — сейчас фактически не используется)
SEND_NEW_OVPN_ON_RENEW = False

TM_TZ = pytz.timezone("Asia/Ashgabat")

# Старый unix-сокет (если был настроен):  (например через --management /var/run/openvpn.sock unix)
MGMT_SOCKET = "/var/run/openvpn.sock"

# TCP management (рекомендуется настроить в server.conf: management 127.0.0.1 7505)
MANAGEMENT_HOST = "127.0.0.1"
MANAGEMENT_PORT = 7505
MANAGEMENT_TIMEOUT = 3  # секунд

# Порог тревоги
MIN_ONLINE_ALERT = 15
ALERT_INTERVAL_SEC = 300
last_alert_time = 0
clients_last_online = set()

# Трафик
TRAFFIC_DB_PATH = "/root/monitor_bot/traffic_usage.json"
traffic_usage: Dict[str, Dict[str, int]] = {}
_last_session_state = {}
_last_traffic_save_time = 0
TRAFFIC_SAVE_INTERVAL = 60

# Логические сроки клиентов
CLIENT_META_PATH = "/root/monitor_bot/clients_meta.json"
client_meta: Dict[str, Dict[str, str]] = {}  # name -> {"expire": "YYYY-MM-DDTHH:MM:SSZ"}

# Интервал проверки истечения (12 часов)
ENFORCE_INTERVAL_SECONDS = 43200  # 12 * 3600

# Глоб для исключения архивов из /root при бэкапе
ROOT_ARCHIVE_EXCLUDE_GLOBS = ["/root/*.tar.gz", "/root/*.tgz"]
EXCLUDE_TEMP_DIR = "/root/monitor_bot/.excluded_root_archives"

# Пагинация (если будет нужно)
PAGE_SIZE_KEYS = 40

# ---------- Логические сроки ----------
def load_client_meta():
    global client_meta
    try:
        if os.path.exists(CLIENT_META_PATH):
            with open(CLIENT_META_PATH, "r") as f:
                client_meta = json.load(f)
        else:
            client_meta = {}
    except Exception as e:
        print(f"[meta] load error: {e}")
        client_meta = {}

def save_client_meta():
    try:
        tmp = CLIENT_META_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump(client_meta, f)
        os.replace(tmp, CLIENT_META_PATH)
    except Exception as e:
        print(f"[meta] save error: {e}")

def set_client_expiry_days_from_now(name: str, days: int) -> str:
    if days < 1:
        days = 1
    dt = datetime.utcnow() + timedelta(days=days)
    iso = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    if name not in client_meta:
        client_meta[name] = {}
    client_meta[name]["expire"] = iso
    save_client_meta()
    unblock_client_ccd(name)  # снимаем блокировку
    return iso

def get_client_expiry(name: str) -> Tuple[Optional[str], Optional[int]]:
    data = client_meta.get(name)
    if not data:
        return None, None
    iso = data.get("expire")
    if not iso:
        return None, None
    try:
        dt = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ")
        days_left = (dt - datetime.utcnow()).days
        return iso, days_left
    except Exception:
        return iso, None

def enforce_client_expiries():
    """
    Если срок истёк — disable + выбиваем сессию.
    """
    now = datetime.utcnow()
    changed = False
    for name, data in list(client_meta.items()):
        iso = data.get("expire")
        if not iso:
            continue
        try:
            dt = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            continue
        if now > dt:
            # Истёк
            if not is_client_ccd_disabled(name):
                block_client_ccd(name)
                disconnect_client_sessions(name)
                changed = True
    if changed:
        print("[meta] enforced expiries -> disabled some clients")

# ---- Уведомления об истечении (за 1 день) ----
# Запоминаем, чтобы не слать повторно для той же даты истечения
_notified_expiry: Dict[str, str] = {}  # name -> expire_iso

UPCOMING_EXPIRY_DAYS = 1  # за сколько дней предупреждать (сейчас 1)

def check_and_notify_expiring(bot):
    """
    Проходит по client_meta и отправляет админу уведомление,
    если до истечения ровно 1 день (days_left == 1) и ещё не слали.
    Работает совместно с ENFORCE_INTERVAL_SECONDS (каждые 12 ч).
    """
    if not client_meta:
        return
    now = datetime.utcnow()
    for name, data in client_meta.items():
        iso = data.get("expire")
        if not iso:
            continue
        try:
            dt = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            continue
        days_left = (dt - now).days
        if days_left == UPCOMING_EXPIRY_DAYS and not is_client_ccd_disabled(name):
            # Уже уведомляли для этой exact даты истечения?
            if _notified_expiry.get(name) == iso:
                continue
            # Шлём уведомление
            try:
                bot.send_message(
                    ADMIN_ID,
                    f"⚠️ Клиент {name} истекает через {days_left} день (до {iso}). "
                    f"Продли через меню: ⌛ Обновить ключ."
                )
                _notified_expiry[name] = iso
            except Exception as e:
                print(f"[notify_expiring] send fail {name}: {e}")
        # Если срок изменился назад/вперёд — позволим послать новое уведомление для новой даты
        elif _notified_expiry.get(name) and _notified_expiry.get(name) != iso and days_left >= 0:
            _notified_expiry.pop(name, None)

# ---------- Управление через management ----------
def _mgmt_tcp_command(cmd: str) -> str:
    """
    Отправляет команду в TCP management (если настроено).
    Возвращает вывод или бросает исключение.
    """
    data = b""
    with socket.create_connection((MANAGEMENT_HOST, MANAGEMENT_PORT), MANAGEMENT_TIMEOUT) as s:
        s.settimeout(MANAGEMENT_TIMEOUT)
        try:
            data += s.recv(4096)
        except Exception:
            pass
        s.sendall((cmd.strip() + "\n").encode())
        time.sleep(0.15)
        try:
            while True:
                chunk = s.recv(65535)
                if not chunk:
                    break
                data += chunk
                if len(chunk) < 65535:
                    break
        except Exception:
            pass
        try:
            s.sendall(b"quit\n")
        except Exception:
            pass
    return data.decode(errors="ignore")

def disconnect_client_sessions(client_name: str) -> bool:
    """
    Пытается отключить клиента через management.
    1) TCP management (client-kill <name>)
    2) Fallback: unix socket (MGMT_SOCKET) командой kill <name>
    Возвращает True если что-то отправлено (даже если не уверены в SUCCESS).
    """
    # TCP
    try:
        out = _mgmt_tcp_command(f"client-kill {client_name}")
        if out:
            print(f"[mgmt] client-kill {client_name} -> {out.strip()[:120]}")
            return True
    except Exception as e:
        pass

    # Unix socket fallback
    if os.path.exists(MGMT_SOCKET):
        try:
            subprocess.run(f'echo "kill {client_name}" | nc -U {MGMT_SOCKET}', shell=True)
            print(f"[mgmt] unix kill {client_name}")
            return True
        except Exception as e:
            print(f"[mgmt] unix kill failed {client_name}: {e}")

    return False

# ------------- Обновление -------------
async def show_update_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return
    await update.message.reply_text(
        f"<b>Команда обновления:</b>\n<code>{SIMPLE_UPDATE_CMD}</code>\n\n"
        "Скопируй и выполни по SSH.",
        parse_mode="HTML",
        disable_web_page_preview=True,
        reply_markup=get_main_keyboard()
    )

async def send_simple_update_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    if q.from_user.id != ADMIN_ID:
        await q.answer("Нет доступа", show_alert=True)
        return
    await q.answer()
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("📋 Копия", callback_data="copy_update_cmd")],
        [InlineKeyboardButton("⬅️ В меню", callback_data="home")]
    ])
    await context.bot.send_message(
        chat_id=q.message.chat_id,
        text=f"<b>Команда обновления (версия {BOT_VERSION}):</b>\n"
             f"<code>{SIMPLE_UPDATE_CMD}</code>\n\n"
             "Нажми и удерживай для копирования.",
        parse_mode="HTML",
        disable_web_page_preview=True,
        reply_markup=kb
    )

async def resend_update_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    if q.from_user.id != ADMIN_ID:
        await q.answer("Нет доступа", show_alert=True)
        return
    await q.answer("Отправлено")
    await context.bot.send_message(
        chat_id=q.message.chat_id,
        text=f"<code>{SIMPLE_UPDATE_CMD}</code>",
        parse_mode="HTML",
        disable_web_page_preview=True
    )

# ------------- Вспомогательные -------------
def get_ovpn_files():
    return [f for f in os.listdir(KEYS_DIR) if f.endswith(".ovpn")]

def is_client_ccd_disabled(client_name):
    ccd_path = os.path.join(CCD_DIR, client_name)
    if not os.path.exists(ccd_path):
        return False
    try:
        with open(ccd_path, "r") as f:
            content = f.read().strip()
        return "disable" in content.lower()
    except Exception:
        return False

def block_client_ccd(client_name):
    """
    Пишем disable + пробуем выбить сессию.
    """
    os.makedirs(CCD_DIR, exist_ok=True)
    with open(os.path.join(CCD_DIR, client_name), "w") as f:
        f.write("disable\n")
    disconnect_client_sessions(client_name)

def unblock_client_ccd(client_name):
    """
    Пишем enable (не удаляем файл).
    """
    os.makedirs(CCD_DIR, exist_ok=True)
    p = os.path.join(CCD_DIR, client_name)
    with open(p, "w") as f:
        f.write("enable\n")

def kill_openvpn_session(client_name):
    return disconnect_client_sessions(client_name)

def bytes_to_mb(b):
    try:
        return f"{int(b)/1024/1024:.2f} MB"
    except:
        return "0 MB"

def format_tm_time(dt_str):
    try:
        dt = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
        dt = pytz.utc.localize(dt).astimezone(TM_TZ)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return dt_str

def split_message(text, max_length=4000):
    lines = text.split('\n')
    messages = []
    current = ""
    for line in lines:
        if len(current) + len(line) + 1 < max_length:
            current += line + '\n'
        else:
            messages.append(current)
            current = line + '\n'
    if current:
        messages.append(current)
    return messages

def format_clients_by_certs():
    cert_dir = f"{EASYRSA_DIR}/pki/issued/"
    if not os.path.isdir(cert_dir):
        return "<b>Список клиентов:</b>\n\nКаталог issued отсутствует."
    certs = [f for f in os.listdir(cert_dir) if f.endswith(".crt")]
    result = "<b>Список клиентов (по сертификатам):</b>\n\n"
    idx = 1
    for f in sorted(certs):
        client_name = f[:-4]
        if client_name.startswith("server_"):
            continue
        mark = "⛔" if is_client_ccd_disabled(client_name) else "🟢"
        result += f"{idx}. {mark} <b>{client_name}</b>\n"
        idx += 1
    if idx == 1:
        result += "Нет выданных сертификатов клиентов."
    return result

def get_cert_days_left(client_name: str) -> Optional[int]:
    cert_path = f"{EASYRSA_DIR}/pki/issued/{client_name}.crt"
    if not os.path.exists(cert_path):
        return None
    try:
        with open(cert_path, "rb") as f:
            cert_data = f.read()
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
        not_after = cert.get_notAfter().decode("ascii")
        expiry_date = datetime.strptime(not_after, "%Y%m%d%H%M%SZ")
        return (expiry_date - datetime.utcnow()).days
    except Exception:
        return None

def parse_remote_proto_from_ovpn(path: str):
    remote = ""
    proto = ""
    try:
        with open(path, "r") as f:
            for line in f:
                ls = line.strip()
                if ls.startswith("remote "):
                    parts = ls.split()
                    if len(parts) >= 3:
                        remote = f"{parts[2]}"
                elif ls.startswith("proto "):
                    proto = ls.split()[1]
                if remote and proto:
                    break
    except:
        pass
    return f"{remote}:{proto}" if remote or proto else ""

def gather_key_metadata():
    files = sorted(get_ovpn_files())
    rows = []
    for f in files:
        name = f[:-5]
        days = get_cert_days_left(name)
        days_str = str(days) if days is not None else "-"
        ovpn_path = os.path.join(KEYS_DIR, f)
        cfg = parse_remote_proto_from_ovpn(ovpn_path)
        crt_path = f"{EASYRSA_DIR}/pki/issued/{name}.crt"
        ctime = "-"
        try:
            if os.path.exists(crt_path):
                ts = os.path.getmtime(crt_path)
                ctime = datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d")
            else:
                ts = os.path.getmtime(ovpn_path)
                ctime = datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d")
        except:
            pass
        rows.append({"name": name, "days": days_str, "cfg": cfg, "created": ctime})
    return rows

def build_keys_table_text(rows: List[Dict]):
    name_w = max([len(r["name"]) for r in rows] + [4])
    cfg_w = max([len(r["cfg"]) for r in rows] + [6])
    days_w = max([len(r["days"]) for r in rows] + [4])
    created_w = 10
    header = f"N | {'Имя'.ljust(name_w)} | {'СерДн'.ljust(days_w)} | {'Конфиг'.ljust(cfg_w)} | {'Создан'.ljust(created_w)}"
    lines = [header]
    for i, r in enumerate(rows, 1):
        lines.append(
            f"{i} | {r['name'].ljust(name_w)} | {r['days'].ljust(days_w)} | {r['cfg'].ljust(cfg_w)} | {r['created'].ljust(created_w)}"
        )
    return "\n".join(lines)

# ---------- Telegraph ----------
def get_telegraph_token() -> Optional[str]:
    try:
        if os.path.exists(TELEGRAPH_TOKEN_FILE):
            with open(TELEGRAPH_TOKEN_FILE, "r") as f:
                tok = f.read().strip()
                if tok:
                    return tok
        resp = requests.post("https://api.telegra.ph/createAccount", data={
            "short_name": TELEGRAPH_SHORT_NAME,
            "author_name": TELEGRAPH_AUTHOR
        }, timeout=10)
        data = resp.json()
        token = data.get("result", {}).get("access_token")
        if token:
            os.makedirs(os.path.dirname(TELEGRAPH_TOKEN_FILE), exist_ok=True)
            with open(TELEGRAPH_TOKEN_FILE, "w") as f:
                f.write(token)
            return token
    except Exception as e:
        print(f"[telegraph] token error: {e}")
    return None

def create_telegraph_pre_page(title: str, text: str) -> Optional[str]:
    token = get_telegraph_token()
    if not token:
        return None
    content_nodes = json.dumps([{"tag": "pre", "children": [text]}], ensure_ascii=False)
    try:
        resp = requests.post("https://api.telegra.ph/createPage", data={
            "access_token": token,
            "title": title,
            "author_name": TELEGRAPH_AUTHOR,
            "content": content_nodes,
            "return_content": "false"
        }, timeout=15)
        data = resp.json()
        return data.get("result", {}).get("url")
    except Exception as e:
        print(f"[telegraph] create page error: {e}")
        return None

def create_keys_detailed_page():
    rows = gather_key_metadata()
    if not rows:
        return None
    text = "Полный список ключей (СерДн = остаток по сертификату, не логический срок)\n\n" + build_keys_table_text(rows)
    return create_telegraph_pre_page("Список ключей", text)

def create_names_telegraph_page(names: List[str], title: str, caption: str) -> Optional[str]:
    if not names:
        return None
    lines = [caption, ""]
    for i, n in enumerate(sorted(names), 1):
        lines.append(f"{i}. {n}")
    return create_telegraph_pre_page(title, "\n".join(lines))

# ---------- Парсер множественного выбора ----------
def parse_bulk_selection(text: str, max_index: int) -> Tuple[List[int], List[str]]:
    text = text.strip().lower()
    if not text:
        return [], ["Пустой ввод."]
    if text == "all":
        return list(range(1, max_index + 1)), []
    parts = re.split(r"[,\s]+", text)
    chosen = set()
    errors = []
    for p in parts:
        if not p:
            continue
        if re.fullmatch(r"\d+", p):
            idx = int(p)
            if 1 <= idx <= max_index:
                chosen.add(idx)
            else:
                errors.append(f"Число вне диапазона: {p}")
        elif re.fullmatch(r"\d+-\d+", p):
            a, b = p.split('-')
            a, b = int(a), int(b)
            if a > b:
                a, b = b, a
            if a < 1 or b > max_index:
                errors.append(f"Диапазон вне диапазона: {p}")
                continue
            for i in range(a, b + 1):
                chosen.add(i)
        else:
            errors.append(f"Неверный фрагмент: {p}")
    return sorted(chosen), errors

# ---------- Массовое УДАЛЕНИЕ ----------
def revoke_and_collect(names: List[str]) -> Tuple[List[str], List[str]]:
    revoked = []
    failed = []
    for name in names:
        cert_path = f"{EASYRSA_DIR}/pki/issued/{name}.crt"
        if not os.path.exists(cert_path):
            revoked.append(name)
            continue
        try:
            subprocess.run(f"cd {EASYRSA_DIR} && ./easyrsa --batch revoke {name}", shell=True, check=True)
            revoked.append(name)
        except subprocess.CalledProcessError as e:
            failed.append(f"{name}: revoke error {e}")
    return revoked, failed

def generate_crl_once() -> Optional[str]:
    try:
        subprocess.run(f"cd {EASYRSA_DIR} && EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl", shell=True, check=True)
        crl_src = f"{EASYRSA_DIR}/pki/crl.pem"
        crl_dst = "/etc/openvpn/crl.pem"
        if os.path.exists(crl_src):
            subprocess.run(f"cp {crl_src} {crl_dst}", shell=True, check=True)
            os.chmod(crl_dst, 0o644)
        return "OK"
    except Exception as e:
        return f"CRL error: {e}"

def remove_client_files(name: str):
    """
    Полное удаление клиента: .ovpn, cert, key, req, ccd, логический срок, трафик.
    """
    paths = [
        os.path.join(KEYS_DIR, f"{name}.ovpn"),
        f"{EASYRSA_DIR}/pki/issued/{name}.crt",
        f"{EASYRSA_DIR}/pki/private/{name}.key",
        f"{EASYRSA_DIR}/pki/reqs/{name}.req",
        os.path.join(CCD_DIR, name)
    ]
    for p in paths:
        try:
            if os.path.exists(p):
                os.remove(p)
        except Exception as e:
            print(f"[delete] cannot remove {p}: {e}")

    if name in client_meta:
        client_meta.pop(name, None)
        save_client_meta()

    if name in traffic_usage:
        traffic_usage.pop(name, None)
        save_traffic_db(force=True)

# ---------- Утилиты бэкапа (скрытие лишних архивов) ----------
EXCLUDE_TEMP_DIR = "/tmp/._exclude_root_archives"

def _temporarily_hide_root_backup_stuff() -> List[Tuple[str, str, str]]:
    os.makedirs(EXCLUDE_TEMP_DIR, exist_ok=True)
    moved: List[Tuple[str, str, str]] = []
    for pattern in ("/root/*.tar.gz", "/root/*.tgz"):
        for src in glob.glob(pattern):
            dst = os.path.join(EXCLUDE_TEMP_DIR, os.path.basename(src))
            try:
                if os.path.abspath(src) != os.path.abspath(dst):
                    if os.path.exists(dst):
                        os.remove(dst)
                    shutil.move(src, dst)
                    moved.append(("file", src, dst))
            except Exception as e:
                print(f"[backup exclude] cannot move {src}: {e}")
    backups_dir = "/root/backups"
    if os.path.isdir(backups_dir):
        dst_dir = os.path.join(EXCLUDE_TEMP_DIR, "__backups_dir__")
        try:
            if os.path.exists(dst_dir):
                shutil.rmtree(dst_dir, ignore_errors=True)
            shutil.move(backups_dir, dst_dir)
            moved.append(("dir", backups_dir, dst_dir))
        except Exception as e:
            print(f"[backup exclude] cannot move {backups_dir}: {e}")
    return moved

def _restore_hidden_root_backup_stuff(moved: List[Tuple[str, str, str]]):
    for kind, src, dst in reversed(moved):
        try:
            if os.path.exists(src):
                if kind == "dir":
                    shutil.rmtree(dst, ignore_errors=True)
                else:
                    if os.path.exists(dst):
                        os.remove(dst)
                continue
            if os.path.exists(dst):
                os.makedirs(os.path.dirname(src), exist_ok=True)
                shutil.move(dst, src)
        except Exception as e:
            print(f"[backup exclude] cannot restore {src} from {dst}: {e}")

def create_backup_in_root_excluding_archives() -> str:
    moved = _temporarily_hide_root_backup_stuff()
    try:
        path = br_create_backup()
        if not path or not os.path.exists(path):
            raise RuntimeError("Backup creation failed (no path returned)")
        dest = os.path.join("/root", os.path.basename(path))
        if os.path.abspath(path) != os.path.abspath(dest):
            if os.path.exists(dest):
                os.remove(dest)
            shutil.move(path, dest)
        else:
            dest = path
        return dest
    finally:
        _restore_hidden_root_backup_stuff(moved)

# ================== BULK HANDLERS (ВОССТАНОВЛЕНО) ==================
# (Код массовых операций находится далее — без изменений)

async def start_bulk_delete(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    rows = gather_key_metadata()
    if not rows:
        await q.edit_message_text("Нет ключей.", reply_markup=get_main_keyboard())
        return
    url = create_keys_detailed_page()
    if not url:
        await q.edit_message_text("Ошибка Telegraph.", reply_markup=get_main_keyboard())
        return
    keys_order = [r["name"] for r in rows]
    context.user_data['bulk_delete_keys'] = keys_order
    context.user_data['await_bulk_delete_numbers'] = True
    text = (
        "<b>Удаление ключей</b>\n"
        "Формат: all | 1 | 1,2,5 | 3-7 | 1,2,5-9\n"
        f"<a href=\"{url}\">Полный список</a>\n\n"
        "Отправьте строку с номерами."
    )
    await q.edit_message_text(text, parse_mode="HTML", reply_markup=InlineKeyboardMarkup([
        [InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_delete")],
        [InlineKeyboardButton("⬅️ Меню", callback_data="home")]
    ]))

async def process_bulk_delete_numbers(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.user_data.get('await_bulk_delete_numbers'):
        return
    keys_order: List[str] = context.user_data.get('bulk_delete_keys', [])
    if not keys_order:
        await update.message.reply_text("Список потерян. Начните снова.", reply_markup=get_main_keyboard())
        context.user_data.pop('await_bulk_delete_numbers', None)
        return
    selection_text = update.message.text.strip()
    idxs, errs = parse_bulk_selection(selection_text, len(keys_order))
    if errs:
        await update.message.reply_text("Ошибки:\n" + "\n".join(errs) + "\nПовторите ввод.",
                                        reply_markup=InlineKeyboardMarkup([
                                            [InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_delete")]
                                        ]))
        return
    if not idxs:
        await update.message.reply_text("Ничего не выбрано.", reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_delete")]
        ]))
        return
    selected_names = [keys_order[i - 1] for i in idxs]
    context.user_data['bulk_delete_selected'] = selected_names
    context.user_data['await_bulk_delete_numbers'] = False
    preview = "\n".join(selected_names[:25])
    if len(selected_names) > 25:
        preview += f"\n... ещё {len(selected_names)-25}"
    await update.message.reply_text(
        f"<b>Удалить ключи ({len(selected_names)}):</b>\n<code>{preview}</code>\nПодтвердить?",
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("✅ Да", callback_data="bulk_delete_confirm")],
            [InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_delete")]
        ])
    )

async def bulk_delete_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    selected: List[str] = context.user_data.get('bulk_delete_selected', [])
    if not selected:
        await q.edit_message_text("Пусто.", reply_markup=get_main_keyboard())
        return
    revoked, failed = revoke_and_collect(selected)
    crl_status = generate_crl_once()
    for name in revoked:
        remove_client_files(name)
        disconnect_client_sessions(name)
    context.user_data.pop('bulk_delete_selected', None)
    context.user_data.pop('bulk_delete_keys', None)
    summary = (
        f"<b>Удаление завершено</b>\n"
        f"Запрошено: {len(selected)}\n"
        f"Revoked: {len(revoked)}\n"
        f"Ошибок: {len(failed)}\n"
        f"CRL: {crl_status}"
    )
    if failed:
        summary += "\n\n<b>Ошибки:</b>\n" + "\n".join(failed[:10])
        if len(failed) > 10:
            summary += f"\n... ещё {len(failed)-10}"
    await q.edit_message_text(summary, parse_mode="HTML", reply_markup=get_main_keyboard())

async def bulk_delete_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer("Отменено")
    for k in ['bulk_delete_selected', 'bulk_delete_keys', 'await_bulk_delete_numbers']:
        context.user_data.pop(k, None)
    await q.edit_message_text("Массовое удаление отменено.", reply_markup=get_main_keyboard())

# ---------- Массовая ОТПРАВКА ----------
async def start_bulk_send(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    files = sorted(get_ovpn_files())
    if not files:
        await q.edit_message_text("Нет ключей.", reply_markup=get_main_keyboard())
        return
    names = [f[:-5] for f in files]
    url = create_names_telegraph_page(names, "Отправка ключей", "Список ключей")
    if not url:
        await q.edit_message_text("Ошибка Telegraph.", reply_markup=get_main_keyboard())
        return
    context.user_data['bulk_send_keys'] = names
    context.user_data['await_bulk_send_numbers'] = True
    text = (
        "<b>Отправить ключи</b>\n"
        "Формат: all | 1 | 1,2,5 | 3-7 | 1,2,5-9\n"
        f"<a href=\"{url}\">Список</a>\n\nПришлите строку."
    )
    await q.edit_message_text(text, parse_mode="HTML", reply_markup=InlineKeyboardMarkup([
        [InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_send")],
        [InlineKeyboardButton("⬅️ Меню", callback_data="home")]
    ]))

async def process_bulk_send_numbers(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.user_data.get('await_bulk_send_numbers'):
        return
    names: List[str] = context.user_data.get('bulk_send_keys', [])
    if not names:
        await update.message.reply_text("Список потерян. Начните заново.", reply_markup=get_main_keyboard())
        context.user_data.pop('await_bulk_send_numbers', None)
        return
    idxs, errs = parse_bulk_selection(update.message.text.strip(), len(names))
    if errs:
        await update.message.reply_text("Ошибки:\n" + "\n".join(errs),
                                        reply_markup=InlineKeyboardMarkup([
                                            [InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_send")]
                                        ]))
        return
    if not idxs:
        await update.message.reply_text("Ничего не выбрано.",
                                        reply_markup=InlineKeyboardMarkup([
                                            [InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_send")]
                                        ]))
        return
    selected = [names[i - 1] for i in idxs]
    context.user_data['bulk_send_selected'] = selected
    context.user_data['await_bulk_send_numbers'] = False
    preview = "\n".join(selected[:25])
    if len(selected) > 25:
        preview += f"\n... ещё {len(selected)-25}"
    await update.message.reply_text(
        f"<b>Отправить ({len(selected)}) ключей:</b>\n<code>{preview}</code>\nПодтвердить?",
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("✅ Да", callback_data="bulk_send_confirm")],
            [InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_send")]
        ])
    )

async def bulk_send_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE):
    import asyncio
    q = update.callback_query
    await q.answer()
    selected: List[str] = context.user_data.get('bulk_send_selected', [])
    if not selected:
        await q.edit_message_text("Список пуст.", reply_markup=get_main_keyboard())
        return
    await q.edit_message_text(f"Отправляю {len(selected)} ключ(ов)...", reply_markup=get_main_keyboard())
    sent = 0
    for name in selected:
        path = os.path.join(KEYS_DIR, f"{name}.ovpn")
        if os.path.exists(path):
            try:
                with open(path, "rb") as f:
                    await context.bot.send_document(
                        chat_id=q.message.chat_id,
                        document=InputFile(f),
                        filename=f"{name}.ovpn"
                    )
                sent += 1
                await asyncio.sleep(0.25)
            except Exception as e:
                print(f"[bulk_send] error sending {name}: {e}")
    for k in ['bulk_send_selected', 'bulk_send_keys', 'await_bulk_send_numbers']:
        context.user_data.pop(k, None)
    await context.bot.send_message(
        chat_id=q.message.chat_id,
        text=f"✅ Отправлено: {sent} / {len(selected)}",
        reply_markup=get_main_keyboard()
    )

async def bulk_send_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer("Отменено")
    for k in ['bulk_send_selected', 'bulk_send_keys', 'await_bulk_send_numbers']:
        context.user_data.pop(k, None)
    await q.edit_message_text("Массовая отправка отменена.", reply_markup=get_main_keyboard())

# ---------- Массовое ВКЛЮЧЕНИЕ ----------
async def start_bulk_enable(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    files = sorted(get_ovpn_files())
    disabled = [f[:-5] for f in files if is_client_ccd_disabled(f[:-5])]
    if not disabled:
        await q.edit_message_text("Нет заблокированных клиентов.", reply_markup=get_main_keyboard())
        return
    url = create_names_telegraph_page(disabled, "Включение клиентов", "Заблокированные клиенты")
    if not url:
        await q.edit_message_text("Ошибка Telegraph.", reply_markup=get_main_keyboard())
        return
    context.user_data['bulk_enable_keys'] = disabled
    context.user_data['await_bulk_enable_numbers'] = True
    text = (
        "<b>Включить клиентов</b>\n"
        "Формат: all | 1 | 1,2 | 3-7 ...\n"
        f"<a href=\"{url}\">Список</a>\n\nПришлите строку."
    )
    await q.edit_message_text(text, parse_mode="HTML", reply_markup=InlineKeyboardMarkup([
        [InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_enable")],
        [InlineKeyboardButton("⬅️ Меню", callback_data="home")]
    ]))

async def process_bulk_enable_numbers(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.user_data.get('await_bulk_enable_numbers'):
        return
    names: List[str] = context.user_data.get('bulk_enable_keys', [])
    if not names:
        await update.message.reply_text("Список потерян.", reply_markup=get_main_keyboard())
        context.user_data.pop('await_bulk_enable_numbers', None)
        return
    idxs, errs = parse_bulk_selection(update.message.text.strip(), len(names))
    if errs:
        await update.message.reply_text("Ошибки:\n" + "\n".join(errs),
                                        reply_markup=InlineKeyboardMarkup([
                                            [InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_enable")]
                                        ]))
        return
    if not idxs:
        await update.message.reply_text("Ничего не выбрано.",
                                        reply_markup=InlineKeyboardMarkup([
                                            [InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_enable")]
                                        ]))
        return
    selected = [names[i - 1] for i in idxs]
    context.user_data['bulk_enable_selected'] = selected
    context.user_data['await_bulk_enable_numbers'] = False
    preview = "\n".join(selected[:30])
    if len(selected) > 30:
        preview += f"\n... ещё {len(selected)-30}"
    await update.message.reply_text(
        f"<b>Включить ({len(selected)}):</b>\n<code>{preview}</code>\nПодтвердить?",
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("✅ Да", callback_data="bulk_enable_confirm")],
            [InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_enable")]
        ])
    )

async def bulk_enable_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    selected: List[str] = context.user_data.get('bulk_enable_selected', [])
    if not selected:
        await q.edit_message_text("Пусто.", reply_markup=get_main_keyboard())
        return
    done = 0
    for name in selected:
        unblock_client_ccd(name)
        done += 1
    for k in ['bulk_enable_selected', 'bulk_enable_keys', 'await_bulk_enable_numbers']:
        context.user_data.pop(k, None)
    await q.edit_message_text(f"✅ Включено клиентов: {done}", reply_markup=get_main_keyboard())

async def bulk_enable_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer("Отменено")
    for k in ['bulk_enable_selected', 'bulk_enable_keys', 'await_bulk_enable_numbers']:
        context.user_data.pop(k, None)
    await q.edit_message_text("Массовое включение отменено.", reply_markup=get_main_keyboard())

# ---------- Массовое ОТКЛЮЧЕНИЕ ----------
async def start_bulk_disable(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    files = sorted(get_ovpn_files())
    active = [f[:-5] for f in files if not is_client_ccd_disabled(f[:-5])]
    if not active:
        await q.edit_message_text("Нет активных клиентов.", reply_markup=get_main_keyboard())
        return
    url = create_names_telegraph_page(active, "Отключение клиентов", "Активные клиенты")
    if not url:
        await q.edit_message_text("Ошибка Telegraph.", reply_markup=get_main_keyboard())
        return
    context.user_data['bulk_disable_keys'] = active
    context.user_data['await_bulk_disable_numbers'] = True
    text = (
        "<b>Отключить клиентов</b>\n"
        "Формат: all | 1 | 1,2,7 | 3-10 ...\n"
        f"<a href=\"{url}\">Список</a>\n\nПришлите строку."
    )
    await q.edit_message_text(text, parse_mode="HTML", reply_markup=InlineKeyboardMarkup([
        [InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_disable")],
        [InlineKeyboardButton("⬅️ Меню", callback_data="home")]
    ]))

async def process_bulk_disable_numbers(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.user_data.get('await_bulk_disable_numbers'):
        return
    names: List[str] = context.user_data.get('bulk_disable_keys', [])
    if not names:
        await update.message.reply_text("Список потерян.", reply_markup=get_main_keyboard())
        context.user_data.pop('await_bulk_disable_numbers', None)
        return
    idxs, errs = parse_bulk_selection(update.message.text.strip(), len(names))
    if errs:
        await update.message.reply_text("Ошибки:\n" + "\n".join(errs),
                                        reply_markup=InlineKeyboardMarkup([
                                            [InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_disable")]
                                        ]))
        return
    if not idxs:
        await update.message.reply_text("Ничего не выбрано.",
                                        reply_markup=InlineKeyboardMarkup([
                                            [InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_disable")]
                                        ]))
        return
    selected = [names[i - 1] for i in idxs]
    context.user_data['bulk_disable_selected'] = selected
    context.user_data['await_bulk_disable_numbers'] = False
    preview = "\n".join(selected[:30])
    if len(selected) > 30:
        preview += f"\n... ещё {len(selected)-30}"
    await update.message.reply_text(
        f"<b>Отключить ({len(selected)}):</b>\n<code>{preview}</code>\nПодтвердить?",
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("✅ Да", callback_data="bulk_disable_confirm")],
            [InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_disable")]
        ])
    )

async def bulk_disable_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    selected: List[str] = context.user_data.get('bulk_disable_selected', [])
    if not selected:
        await q.edit_message_text("Пусто.", reply_markup=get_main_keyboard())
        return
    done = 0
    for name in selected:
        block_client_ccd(name)
        disconnect_client_sessions(name)
        done += 1
    for k in ['bulk_disable_selected', 'bulk_disable_keys', 'await_bulk_disable_numbers']:
        context.user_data.pop(k, None)
    await q.edit_message_text(f"⚠️ Отключено клиентов: {done}", reply_markup=get_main_keyboard())

async def bulk_disable_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer("Отменено")
    for k in ['bulk_disable_selected', 'bulk_disable_keys', 'await_bulk_disable_numbers']:
        context.user_data.pop(k, None)
    await q.edit_message_text("Массовое отключение отменено.", reply_markup=get_main_keyboard())

# ================== UPDATE REMOTE ==================
CLIENT_TEMPLATE_CANDIDATES = [
    "/etc/openvpn/client-template.txt",
    "/root/openvpn/client-template.txt"
]

def find_client_template_path() -> Optional[str]:
    for p in CLIENT_TEMPLATE_CANDIDATES:
        if os.path.exists(p):
            return p
    return None

def replace_remote_line_in_text(text: str, new_host: str, new_port: str) -> str:
    lines = []
    replaced = False
    for line in text.splitlines():
        if line.strip().startswith("remote "):
            lines.append(f"remote {new_host} {new_port}")
            replaced = True
        else:
            lines.append(line)
    if not replaced:
        lines.append(f"remote {new_host} {new_port}")
    return "\n".join(lines) + "\n"

def update_template_and_ovpn(new_host: str, new_port: str) -> Dict[str, int]:
    stats = {"template_updated": 0, "ovpn_updated": 0, "errors": 0}
    tpl = find_client_template_path()
    if tpl:
        try:
            with open(tpl, "r") as f:
                old = f.read()
            new = replace_remote_line_in_text(old, new_host, new_port)
            if new != old:
                backup = tpl + ".bak_" + datetime.utcnow().strftime("%Y%m%d%H%M%S")
                shutil.copy2(tpl, backup)
                with open(tpl, "w") as f:
                    f.write(new)
                stats["template_updated"] = 1
        except Exception as e:
            print(f"[update_remote] template error: {e}")
            stats["errors"] += 1
    else:
        print("[update_remote] template not found")

    for f in get_ovpn_files():
        path = os.path.join(KEYS_DIR, f)
        try:
            with open(path, "r") as fr:
                oldc = fr.read()
            newc = replace_remote_line_in_text(oldc, new_host, new_port)
            if newc != oldc:
                bak = path + ".bak_" + datetime.utcnow().strftime("%Y%m%d%H%M%S")
                shutil.copy2(path, bak)
                with open(path, "w") as fw:
                    fw.write(newc)
                stats["ovpn_updated"] += 1
        except Exception as e:
            print(f"[update_remote] file {f} error: {e}")
            stats["errors"] += 1
    return stats

async def start_update_remote_dialog(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    tpl = find_client_template_path()
    tpl_info = tpl if tpl else "не найден"
    await q.edit_message_text(
        "Введите новый remote в формате host:port\n"
        f"(Обнаруженный шаблон: {tpl_info})\nПример: vpn.example.com:1194",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("❌ Отмена", callback_data="cancel_update_remote")],
            [InlineKeyboardButton("⬅️ Меню", callback_data="home")]
        ])
    )
    context.user_data['await_remote_input'] = True

async def process_remote_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.user_data.get('await_remote_input'):
        return
    raw = update.message.text.strip()
    if ':' not in raw:
        await update.message.reply_text("Формат неверный. Нужно host:port. Пример: myvpn.com:1194")
        return
    host, port = raw.split(':', 1)
    host = host.strip()
    port = port.strip()
    if not host or not port.isdigit():
        await update.message.reply_text("Некорректные host или port.")
        return
    stats = update_template_and_ovpn(host, port)
    context.user_data.pop('await_remote_input', None)
    await update.message.reply_text(
        f"✅ Обновление завершено.\n"
        f"Шаблон: {stats['template_updated']}\n"
        f".ovpn изменено: {stats['ovpn_updated']}\n"
        f"Ошибок: {stats['errors']}",
        reply_markup=get_main_keyboard()
    )

# ---------- HELP ----------
HELP_TEXT = """❓ Справка (обновлено: логические сроки)

Теперь срок действия клиентов управляется ЛОГИЧЕСКИ:
- Сертификат может быть длинным, но доступ отключается, когда истекает логический срок (запись disable в ccd/<client>).
- Продление просто задаёт новый срок (X дней от сейчас) и пишет enable.
- .ovpn файл не нужно пересылать при продлении.

Основные пункты:
⏳ Сроки ключей — показывает логический срок (если нет — “нет срока”).
⌛ Обновить ключ — установить новый срок (от текущего момента) и разблокировать.

(Для обычных пользователей и админа)

Как выбирать клиентов (когда бот просит номера):
Форматы: all | 1 | 1,2,5 | 3-7 | 1,2,5-9
Можно смешивать: 1,2,5-7,10
Пробелы и запятые игнорируются. Диапазон a-b включает оба конца.
'ALL' (или all) = все клиенты.

────────────────────────
🔄 Список клиентов
Показывает все созданные ключи (клиентские .ovpn). Отмечает кто сейчас онлайн (например, зелёным) и общее количество. Используется для понимания текущей картины подключений.

📊 Статистика
Сводка: сколько клиентов онлайн / всего, возможно аптайм сервера, суммарный трафик (если реализовано), время последнего обновления статуса. Нужна для быстрой оценки состояния.

🛠 Тунель
Показывает соответствие: имя клиента → его туннельный (виртуальный) VPN‑IP. Удобно для диагностики маршрутов и конфликтов адресов.

📶 Трафик
Отчёт по объёму полученных/отправленных данных для каждого клиента и суммарно. Помогает увидеть «тяжёлых» пользователей или аномалии.

🔗 Обновление
Показывает или выдаёт команду для обновления бота/скрипта до свежей версии. Используй только если доверяешь источнику обновлений.

🧹 Очистить трафик
Сбрасывает накопленную статистику трафика (обнуление счётчиков) не трогая сами ключи. Полезно перед началом нового расчётного периода.

🌐 Обновить адрес
Обновляет IP/домен сервера внутри клиентских .ovpn (или показывает текущий внешний адрес). Используй после смены публичного IP или доменного имени, чтобы клиенты могли подключаться без ручного редактирования.

⏳ Сроки ключей
Показывает дату истечения сертификатов/ключей. Обычно подсвечивает те, что скоро истекают, чтобы вовремя продлить.

⏳ Обновить ключ
Перегенерирует (заменяет) выбранные клиентские ключи/сертификаты. Старый становится недействительным (если добавляется в CRL). После операции нужно заново выдать новый .ovpn пользователю.

✅ Вкл.клиента
Снимает блокировку клиента, если он был отключён (удаляет из списка отозванных / возвращает файл / разрешает подключение).

⚠️ Откл.клиента
Отключает (блокирует) клиента: добавляет в CRL или иным способом запрещает его подключение. Можно включить обратно через «Вкл.клиента».

➕ Создать ключ
Создаёт новый клиентский сертификат и .ovpn файл. Используй для подключения нового пользователя или устройства.

🗑 Удалить ключ
Полностью удаляет выбранные ключ/сертификат и конфиг. Действие обычно необратимо: клиент больше не сможет подключаться (нужно будет создать заново).

📤 Отправить ключи
Отправляет выбранные клиентские .ovpn (по одному или архивом). Можно указать список/диапазон или all. Не пересылай ключи в открытые/недоверенные чаты.

🧺 Просмотр лога
Вывод последних строк лога (OpenVPN или системного/бота — зависит от реализации). Нужен для быстрой диагностики ошибок.

📦 Бэкап OpenVPN
Создаёт резервную копию: ключи, конфиги, (возможно) БД трафика и служебные файлы. Имя файла обычно содержит дату/время. Храни бэкапы в безопасном месте.

🔄 Восстан.бэкап
Восстанавливает из выбранного бэкапа (перезапишет существующие файлы). Перед применением убедись, что выбрал правильный архив. Может потребоваться рестарт сервиса после восстановления.

🚨 Тревога блокировки
Служебная функция: отображает/тестирует состояние механизма оповещений (например, если все клиенты пропали, подозрение на блокировку). Реализация зависит от версии бота.

❓ Помощь
Показывает этот текст со всеми пояснениями.

🏠 В главное меню
Возврат к основной панели кнопок.

────────────────────────
Безопасность:
• Не публикуй клиентские .ovpn и сертификаты в открытом доступе.
• Если токен бота стал известен посторонним — сразу /revoke в BotFather и задай новый.
• Перед восстановлением бэкапа желательно сделать свежий текущий бэкап.

Советы:
• Делай регулярные бэкапы (особенно перед массовыми изменениями).
• Следи за истечением сертификатов чтобы не потерять подключение внезапно.
• После смены IP сервера используй «Обновить адрес» и заново раздай обновлённые .ovpn файлы (если файл адрес внутри не обновляется автоматически).

Автор / связь: @XS_FORM
Удачной работы!"""

def build_help_messages():
    """
    Делит HELP_TEXT на части, каждая часть — валидный законченный HTML:
    <b>Помощь</b>
    <pre>...</pre>
    """
    raw = HELP_TEXT
    esc = escape(raw)  # экранируем < > &
    lines = esc.splitlines()

    parts = []
    block = []
    current_len = 0
    # Максимум ~3500 символов содержания внутри <pre>, чтобы уложиться в лимиты (4096 с запасом)
    # Учтём служебный оверхед тегов (<b>...</b>\n<pre></pre>)
    LIMIT = 3500

    for line in lines:
        line_len = len(line) + 1  # +\n
        # Если добавление строки превысит лимит — завершаем текущий блок
        if block and current_len + line_len > LIMIT:
            content = "\n".join(block)
            parts.append(f"<b>Помощь</b>\n<pre>{content}</pre>")
            block = [line]
            current_len = line_len
        else:
            block.append(line)
            current_len += line_len

    if block:
        content = "\n".join(block)
        parts.append(f"<b>Помощь</b>\n<pre>{content}</pre>")

    return parts

# NEW: отправка помощи (чтобы избежать 'Message is not modified')
async def send_help_messages(context: ContextTypes.DEFAULT_TYPE, chat_id: int):
    parts = build_help_messages()
    # Первое сообщение с клавиатурой
    await context.bot.send_message(chat_id=chat_id,
                                   text=parts[0],
                                   parse_mode="HTML",
                                   reply_markup=get_main_keyboard())
    # Остальные (если есть)
    for p in parts[1:]:
        await context.bot.send_message(chat_id=chat_id,
                                       text=p,
                                       parse_mode="HTML",
                                       reply_markup=get_main_keyboard())

# ---------- MAIN KEYBOARD ----------
def get_main_keyboard():
    keyboard = [
        [InlineKeyboardButton("🔄 Список клиентов", callback_data='refresh')],
        [InlineKeyboardButton("📊 Статистика", callback_data='stats'),
         InlineKeyboardButton("🛣️ Тунель", callback_data='send_ipp')],
        [InlineKeyboardButton("📶 Трафик", callback_data='traffic'),
         InlineKeyboardButton("🔗 Обновление", callback_data='update_info')],
        [InlineKeyboardButton("🧹 Очистить трафик", callback_data='traffic_clear'),
         InlineKeyboardButton("🌐 Обновить адрес", callback_data='update_remote')],
        [InlineKeyboardButton("⏳ Сроки ключей", callback_data='keys_expiry'),
         InlineKeyboardButton("⌛ Обновить ключ", callback_data='renew_key')],
        [InlineKeyboardButton("✅ Вкл.клиента", callback_data='bulk_enable_start'),
         InlineKeyboardButton("⚠️ Откл.клиента", callback_data='bulk_disable_start')],
        [InlineKeyboardButton("➕ Создать ключ", callback_data='create_key'),
         InlineKeyboardButton("🗑️ Удалить ключ", callback_data='bulk_delete_start')],
        [InlineKeyboardButton("📤 Отправить ключи", callback_data='bulk_send_start'),
         InlineKeyboardButton("📜 Просмотр лога", callback_data='log')],
        [InlineKeyboardButton("📦 Бэкап OpenVPN", callback_data='backup_menu'),
         InlineKeyboardButton("🔄 Восстан.бэкап", callback_data='restore_menu')],
        [InlineKeyboardButton("🚨 Тревога блокировки", callback_data='block_alert')],
        [InlineKeyboardButton("❓ Помощь", callback_data='help'),
         InlineKeyboardButton("🏠 В главное меню", callback_data='home')],
    ]
    return InlineKeyboardMarkup(keyboard)

# ---------- Генерация OVPN ----------
def extract_pem_cert(cert_path: str) -> str:
    with open(cert_path, "r") as f:
        lines = f.read().splitlines()
    in_pem = False
    pem_lines = []
    for line in lines:
        if "-----BEGIN CERTIFICATE-----" in line:
            in_pem = True
        if in_pem:
            pem_lines.append(line)
        if "-----END CERTIFICATE-----" in line:
            break
    return "\n".join(pem_lines).strip()

def generate_ovpn_for_client(
    client_name,
    output_dir=KEYS_DIR,
    template_path=f"{OPENVPN_DIR}/client-template.txt",
    ca_path=f"{EASYRSA_DIR}/pki/ca.crt",
    cert_path=None,
    key_path=None,
    tls_crypt_path=f"{OPENVPN_DIR}/tls-crypt.key",
    tls_auth_path=f"{OPENVPN_DIR}/tls-auth.key",
    server_conf_path=f"{OPENVPN_DIR}/server.conf"
):
    if cert_path is None:
        cert_path = f"{EASYRSA_DIR}/pki/issued/{client_name}.crt"
    if key_path is None:
        key_path = f"{EASYRSA_DIR}/pki/private/{client_name}.key"

    ovpn_file = os.path.join(output_dir, f"{client_name}.ovpn")
    TLS_SIG = None
    if os.path.exists(server_conf_path):
        with open(server_conf_path, "r") as f:
            conf = f.read()
            if "tls-crypt" in conf:
                TLS_SIG = 1
            elif "tls-auth" in conf:
                TLS_SIG = 2

    with open(template_path, "r") as f:
        template_content = f.read().rstrip()
    with open(ca_path, "r") as f:
        ca_content = f.read().strip()
    cert_content = extract_pem_cert(cert_path)
    with open(key_path, "r") as f:
        key_content = f.read().strip()

    content = template_content + "\n"
    content += "<ca>\n" + ca_content + "\n</ca>\n"
    content += "<cert>\n" + cert_content + "\n</cert>\n"
    content += "<key>\n" + key_content + "\n</key>\n"

    if TLS_SIG == 1 and os.path.exists(tls_crypt_path):
        with open(tls_crypt_path, "r") as f:
            tls_crypt_content = f.read().strip()
        content += "<tls-crypt>\n" + tls_crypt_content + "\n</tls-crypt>\n"
    elif TLS_SIG == 2 and os.path.exists(tls_auth_path):
        content += "key-direction 1\n"
        with open(tls_auth_path, "r") as f:
            tls_auth_content = f.read().strip()
        content += "<tls-auth>\n" + tls_auth_content + "\n</tls-auth>\n"

    with open(ovpn_file, "w") as f:
        f.write(content)
    return ovpn_file

# ---------- Создание ключа ----------
async def create_key_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if context.user_data.get('await_key_name'):
        key_name = update.message.text.strip()
        ovpn_file = os.path.join(KEYS_DIR, f"{key_name}.ovpn")
        if os.path.exists(ovpn_file):
            await update.message.reply_text("Такой клиент существует, введите другое имя.")
            return
        context.user_data['new_key_name'] = key_name
        context.user_data['await_key_name'] = False
        context.user_data['await_key_expiry'] = True
        await update.message.reply_text("Введите логический срок (дней, по умолчанию 30):")
        return

    if context.user_data.get('await_key_expiry'):
        try:
            days = int(update.message.text.strip())
        except:
            days = 30
        context.user_data['new_key_expiry'] = days
        context.user_data['await_key_expiry'] = False
        key_name = context.user_data['new_key_name']
        try:
            subprocess.run(
                f"EASYRSA_CERT_EXPIRE=3650 {EASYRSA_DIR}/easyrsa --batch build-client-full {key_name} nopass",
                shell=True, check=True, cwd=EASYRSA_DIR
            )
        except subprocess.CalledProcessError as e:
            await update.message.reply_text(f"Ошибка генерации: {e}")
            context.user_data.clear()
            return
        ovpn_path = generate_ovpn_for_client(key_name)
        iso = set_client_expiry_days_from_now(key_name, days)
        await update.message.reply_text(
            f"Клиент {key_name} создан.\nЛогический срок до: {iso} (~{days} дн)\nФайл: {ovpn_path}"
        )
        with open(ovpn_path, "rb") as f:
            await context.bot.send_document(
                chat_id=update.effective_chat.id,
                document=InputFile(f),
                filename=f"{key_name}.ovpn"
            )
        context.user_data.clear()
        return

# ---------- Renew (логический) ----------
async def renew_key_request(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    if q.from_user.id != ADMIN_ID:
        await q.answer("Нет доступа", show_alert=True)
        return
    await q.answer()
    rows = gather_key_metadata()
    if not rows:
        await q.edit_message_text("Нет ключей.", reply_markup=get_main_keyboard())
        return
    url = create_keys_detailed_page()
    if not url:
        await q.edit_message_text("Ошибка Telegraph.", reply_markup=get_main_keyboard())
        return
    order = [r["name"] for r in rows]
    context.user_data['renew_keys_order'] = order
    context.user_data['await_renew_number'] = True
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("❌ Отмена", callback_data="cancel_renew")],
        [InlineKeyboardButton("⬅️ Меню", callback_data="home")]
    ])
    await q.edit_message_text(
        f"<b>Установить новый логический срок</b>\n"
        f"Открой список и введи НОМЕР клиента:\n"
        f"<a href=\"{url}\">Список (Telegraph)</a>\n\nПример: 5",
        parse_mode="HTML",
        reply_markup=kb
    )

async def process_renew_number(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.user_data.get('await_renew_number'):
        return
    text = update.message.text.strip()
    if not re.fullmatch(r"\d+", text):
        await update.message.reply_text("Нужно ввести один номер клиента (целое число).",
                                        reply_markup=InlineKeyboardMarkup([
                                            [InlineKeyboardButton("❌ Отмена", callback_data="cancel_renew")]
                                        ]))
        return
    idx = int(text)
    order: List[str] = context.user_data.get('renew_keys_order', [])
    if not order:
        await update.message.reply_text("Список потерян. Начните заново.", reply_markup=get_main_keyboard())
        context.user_data.pop('await_renew_number', None)
        return
    if idx < 1 or idx > len(order):
        await update.message.reply_text(f"Номер вне диапазона 1..{len(order)}.",
                                        reply_markup=InlineKeyboardMarkup([
                                            [InlineKeyboardButton("❌ Отмена", callback_data="cancel_renew")]
                                        ]))
        return
    key_name = order[idx - 1]
    context.user_data['renew_key_name'] = key_name
    context.user_data['await_renew_number'] = False
    context.user_data['await_renew_expiry'] = True
    await update.message.reply_text(f"Введите НОВЫЙ срок (дней от текущего момента) для {key_name}:")

async def renew_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer("Отменено")
    for k in ['await_renew_number', 'await_renew_expiry', 'renew_keys_order', 'renew_key_name']:
        context.user_data.pop(k, None)
    await q.edit_message_text("Продление отменено.", reply_markup=get_main_keyboard())

async def renew_key_select_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    if q.from_user.id != ADMIN_ID:
        await q.answer("Нет доступа", show_alert=True)
        return
    await q.answer()
    data = q.data
    key_name = data.split('_', 1)[1]
    context.user_data['renew_key_name'] = key_name
    context.user_data['await_renew_expiry'] = True
    await q.edit_message_text(f"Введите НОВЫЙ срок (дней) для {key_name}:")

async def renew_key_expiry_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.user_data.get('await_renew_expiry'):
        return
    key_name = context.user_data['renew_key_name']
    try:
        days = int(update.message.text.strip())
        if days < 1:
            raise ValueError
    except Exception:
        await update.message.reply_text("Некорректное число дней.")
        return
    iso = set_client_expiry_days_from_now(key_name, days)
    await update.message.reply_text(
        f"Логический срок для {key_name} установлен до: {iso} (~{days} дн). Клиент разблокирован."
    )
    context.user_data.clear()

# ---------- Лог ----------
def get_status_log_tail(n=40):
    try:
        with open(STATUS_LOG, "r") as f:
            lines = f.readlines()
        return "".join(lines[-n:])
    except Exception as e:
        return f"Ошибка чтения status.log: {e}"

# ---------- BACKUP / RESTORE UI ----------
def list_backups() -> List[str]:
    items = [os.path.basename(p) for p in glob.glob("/root/openvpn_full_backup_*.tar.gz")]
    return sorted(items, reverse=True)

async def perform_backup_and_send(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return
    try:
        path = create_backup_in_root_excluding_archives()
        size = os.path.getsize(path)
        await update.callback_query.edit_message_text(
            f"✅ Бэкап создан: <code>{os.path.basename(path)}</code>\nРазмер: {size/1024/1024:.2f} MB",
            parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("📤 Отправить", callback_data=f"backup_send_{os.path.basename(path)}")],
                [InlineKeyboardButton("📦 Список", callback_data="backup_list")],
                [InlineKeyboardButton("⬅️ Назад", callback_data="home")]
            ])
        )
    except Exception as e:
        await update.callback_query.edit_message_text(f"Ошибка бэкапа: {e}", reply_markup=get_main_keyboard())

async def send_backup_file(update: Update, context: ContextTypes.DEFAULT_TYPE, fname: str):
    full = os.path.join("/root", fname)
    if not os.path.exists(full):
        await update.callback_query.edit_message_text("Файл не найден.", reply_markup=get_main_keyboard())
        return
    with open(full, "rb") as f:
        await context.bot.send_document(chat_id=update.effective_chat.id, document=InputFile(f), filename=fname)
    await update.callback_query.edit_message_text("Отправлен.", reply_markup=get_main_keyboard())

async def show_backup_list(update: Update, context: ContextTypes.DEFAULT_TYPE):
    bl = list_backups()
    if not bl:
        await update.callback_query.edit_message_text("Бэкапов нет.", reply_markup=get_main_keyboard())
        return
    kb = []
    for b in bl[:15]:
        kb.append([InlineKeyboardButton(b, callback_data=f"backup_info_{b}")])
    kb.append([InlineKeyboardButton("⬅️ Назад", callback_data="home")])
    await update.callback_query.edit_message_text("Список бэкапов:", reply_markup=InlineKeyboardMarkup(kb))

async def show_backup_info(update: Update, context: ContextTypes.DEFAULT_TYPE, fname: str):
    full = os.path.join("/root", fname)
    staging = f"/tmp/info_{int(time.time())}"
    os.makedirs(staging, exist_ok=True)
    try:
        import tarfile
        with tarfile.open(full, "r:gz") as tar:
            tar.extractall(staging)
        manifest_path = os.path.join(staging, MANIFEST_NAME)
        if not os.path.exists(manifest_path):
            await update.callback_query.edit_message_text("manifest.json отсутствует.", reply_markup=get_main_keyboard())
            return
        with open(manifest_path, "r") as f:
            m = json.load(f)
        clients = m.get("openvpn_pki", {}).get("clients", [])
        v_count = sum(1 for c in clients if c.get("status") == "V")
        r_count = sum(1 for c in clients if c.get("status") == "R")
        txt = (f"<b>{fname}</b>\nСоздан: {m.get('created_at')}\n"
               f"Файлов: {len(m.get('files', []))}\n"
               f"Клиентов V: {v_count} / R: {r_count}\nПоказать diff?")
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("🧪 Diff", callback_data=f"restore_dry_{fname}")],
            [InlineKeyboardButton("📤 Отправить", callback_data=f"backup_send_{fname}")],
            [InlineKeyboardButton("🗑️ Удалить", callback_data=f"backup_delete_{fname}")],
            [InlineKeyboardButton("⬅️ Назад", callback_data="backup_list")]
        ])
        await update.callback_query.edit_message_text(txt, parse_mode="HTML", reply_markup=kb)
    finally:
        shutil.rmtree(staging, ignore_errors=True)

async def restore_dry_run(update: Update, context: ContextTypes.DEFAULT_TYPE, fname: str):
    full = os.path.join("/root", fname)
    try:
        report = apply_restore(full, dry_run=True)
        diff = report["diff"]
        def lim(lst):
            return lst[:6] + [f"... ещё {len(lst)-6}"] if len(lst) > 6 else lst
        text = (
            f"<b>Diff {fname}</b>\n"
            f"Extra: {len(diff['extra'])}\n" + "\n".join(lim(diff['extra'])) + "\n\n"
            f"Missing: {len(diff['missing'])}\n" + "\n".join(lim(diff['missing'])) + "\n\n"
            f"Changed: {len(diff['changed'])}\n" + "\n".join(lim(diff['changed'])) + "\n\n"
            "Применить restore?"
        )
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("⚠️ Применить", callback_data=f"restore_apply_{fname}")],
            [InlineKeyboardButton("⬅️ Назад", callback_data=f"backup_info_{fname}")]
        ])
        await update.callback_query.edit_message_text(text, parse_mode="HTML", reply_markup=kb)
    except Exception as e:
        await update.callback_query.edit_message_text(f"Ошибка dry-run: {e}", reply_markup=get_main_keyboard())

async def restore_apply(update: Update, context: ContextTypes.DEFAULT_TYPE, fname: str):
    full = os.path.join(BACKUP_OUTPUT_DIR, fname)
    try:
        report = apply_restore(full, dry_run=False)
        diff = report["diff"]
        text = (
            f"<b>Restore:</b> {fname}\n"
            f"Удалено extra: {len(diff['extra'])}\n"
            f"Missing: {len(diff['missing'])}\n"
            f"Changed: {len(diff['changed'])}\n"
            f"CRL: {report.get('crl_action')}\n"
            f"OpenVPN restart: {report.get('service_restart')}"
        )
        await update.callback_query.edit_message_text(text, parse_mode="HTML", reply_markup=get_main_keyboard())
    except Exception as e:
        tb = traceback.format_exc()
        await update.callback_query.edit_message_text(f"Ошибка restore: {e}\n<pre>{tb[-800:]}</pre>", parse_mode="HTML")

async def backup_delete_prompt(update: Update, context: ContextTypes.DEFAULT_TYPE, fname: str):
    full = os.path.join("/root", fname)
    if not os.path.exists(full):
        await update.callback_query.edit_message_text("Файл не найден.", reply_markup=get_main_keyboard())
        return
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("✅ Да, удалить", callback_data=f"backup_delete_confirm_{fname}")],
        [InlineKeyboardButton("❌ Нет", callback_data=f"backup_info_{fname}")]
    ])
    await update.callback_query.edit_message_text(
        f"Удалить бэкап <b>{fname}</b>?", parse_mode="HTML", reply_markup=kb
    )

async def backup_delete_apply(update: Update, context: ContextTypes.DEFAULT_TYPE, fname: str):
    full = os.path.join("/root", fname)
    try:
        if os.path.exists(full):
            os.remove(full)
            await update.callback_query.edit_message_text("🗑️ Бэкап удалён.", reply_markup=get_main_keyboard())
            await show_backup_list(update, context)
        else:
            await update.callback_query.edit_message_text("Файл не найден.", reply_markup=get_main_keyboard())
    except Exception as e:
        await update.callback_query.edit_message_text(f"Ошибка удаления: {e}", reply_markup=get_main_keyboard())

async def backup_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("🆕 Создать бэкап", callback_data="backup_create")],
        [InlineKeyboardButton("📦 Список бэкапов", callback_data="backup_list")],
        [InlineKeyboardButton("⬅️ Назад", callback_data="home")]
    ])
    await q.edit_message_text("Меню бэкапов:", reply_markup=kb)

async def restore_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("📦 Список бэкапов", callback_data="backup_list")],
        [InlineKeyboardButton("⬅️ Назад", callback_data="home")]
    ])
    await q.edit_message_text("Восстановление: выбери бэкап → Diff → Применить.", reply_markup=kb)

# ---------- Трафик ----------
def load_traffic_db():
    global traffic_usage
    try:
        if os.path.exists(TRAFFIC_DB_PATH):
            with open(TRAFFIC_DB_PATH, "r") as f:
                raw = json.load(f)
            migrated = {}
            changed = False
            for k, v in raw.items():
                if isinstance(v, dict) and 'rx' in v and 'tx' in v:
                    migrated[k] = {'rx': int(v.get('rx', 0)), 'tx': int(v.get('tx', 0))}
                else:
                    migrated[k] = {
                        'rx': int(v.get('rx', 0)) if isinstance(v, dict) else (int(v) if isinstance(v, int) else 0),
                        'tx': int(v.get('tx', 0)) if isinstance(v, dict) else 0
                    }
            traffic_usage = migrated
            if changed:
                save_traffic_db(force=True)
        else:
            traffic_usage = {}
    except Exception as e:
        print(f"[traffic] load error: {e}")
        traffic_usage = {}

def save_traffic_db(force=False):
    global _last_traffic_save_time
    now = time.time()
    if not force and now - _last_traffic_save_time < TRAFFIC_SAVE_INTERVAL:
        return
    try:
        tmp = TRAFFIC_DB_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump(traffic_usage, f)
        os.replace(tmp, TRAFFIC_DB_PATH)
        _last_traffic_save_time = now
    except Exception as e:
        print(f"[traffic] save error: {e}")

def build_traffic_report():
    if not traffic_usage:
        return "<b>Трафик:</b>\nНет данных."
    items = sorted(
        traffic_usage.items(),
        key=lambda x: x[1]['rx'] + x[1]['tx'],
        reverse=True
    )
    lines = ["<b>Использование трафика:</b>"]
    for name, val in items:
        total = val['rx'] + val['tx']
        lines.append(f"• {name}: {total/1024/1024/1024:.2f} GB")
    return "\n".join(lines)

def update_traffic_from_status(clients):
    global traffic_usage, _last_session_state
    changed = False
    for c in clients:
        name = c['name']
        try:
            recv = int(c.get('bytes_recv', 0))
            sent = int(c.get('bytes_sent', 0))
        except:
            continue
        connected_since = c.get('connected_since', '')
        prev = _last_session_state.get(name)
        if name not in traffic_usage:
            traffic_usage[name] = {'rx': 0, 'tx': 0}
        if prev is None or prev['connected_since'] != connected_since:
            _last_session_state[name] = {
                'connected_since': connected_since,
                'rx': recv,
                'tx': sent
            }
            continue
        delta_rx = recv - prev['rx']
        delta_tx = sent - prev['tx']
        if delta_rx > 0:
            traffic_usage[name]['rx'] += delta_rx
            prev['rx'] = recv
            changed = True
        else:
            prev['rx'] = recv
        if delta_tx > 0:
            traffic_usage[name]['tx'] += delta_tx
            prev['tx'] = sent
            changed = True
        else:
            prev['tx'] = sent
    if changed:
        save_traffic_db()

def clear_traffic_stats():
    global traffic_usage, _last_session_state
    try:
        if os.path.exists(TRAFFIC_DB_PATH):
            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            subprocess.run(f"cp {TRAFFIC_DB_PATH} {TRAFFIC_DB_PATH}.bak_{ts}", shell=True)
    except:
        pass
    traffic_usage = {}
    _last_session_state = {}
    save_traffic_db(force=True)

# ---------- Monitoring loop ----------
async def check_new_connections(app: Application):
    import asyncio
    global clients_last_online, last_alert_time
    if not hasattr(check_new_connections, "_last_enforce"):
        check_new_connections._last_enforce = 0
    while True:
        try:
            clients, online_names, tunnel_ips = parse_openvpn_status()
            update_traffic_from_status(clients)

            now_t = time.time()
            if now_t - check_new_connections._last_enforce > ENFORCE_INTERVAL_SECONDS:
                enforce_client_expiries()
                check_and_notify_expiring(app.bot)
                check_new_connections._last_enforce = now_t

            online_count = len(online_names)
            total_keys = len(get_ovpn_files())
            now = time.time()
            if online_count == 0 and total_keys > 0:
                if now - last_alert_time > ALERT_INTERVAL_SEC:
                    await app.bot.send_message(ADMIN_ID, "❌ Все клиенты оффлайн!", parse_mode="HTML")
                    last_alert_time = now
            elif 0 < online_count < MIN_ONLINE_ALERT:
                if now - last_alert_time > ALERT_INTERVAL_SEC:
                    await app.bot.send_message(ADMIN_ID, f"⚠️ Онлайн мало: {online_count}/{total_keys}", parse_mode="HTML")
                    last_alert_time = now
            else:
                if online_count >= MIN_ONLINE_ALERT:
                    last_alert_time = 0
            clients_last_online = set(online_names)
            await asyncio.sleep(10)
        except Exception as e:
            print(f"[monitor] {e}")
            await asyncio.sleep(10)

def parse_openvpn_status(status_path=STATUS_LOG):
    clients = []
    online_names = set()
    tunnel_ips = {}
    try:
        with open(status_path, "r") as f:
            lines = f.readlines()
        client_list_section = False
        routing_table_section = False
        for line in lines:
            line = line.strip()
            if line.startswith("OpenVPN CLIENT LIST"):
                client_list_section = True
                continue
            if client_list_section and line.startswith("Common Name,Real Address"):
                continue
            if client_list_section and not line:
                client_list_section = False
                continue
            if client_list_section and "," in line:
                parts = line.split(",")
                if len(parts) >= 5:
                    common_name = parts[0]
                    real_addr = parts[1]
                    bytes_recv = parts[2]
                    bytes_sent = parts[3]
                    connected_since = parts[4]
                    clients.append({
                        "name": common_name,
                        "ip": real_addr.split(":")[0],
                        "port": real_addr.split(":")[1] if ":" in real_addr else "",
                        "bytes_recv": bytes_recv,
                        "bytes_sent": bytes_sent,
                        "connected_since": connected_since,
                    })
            if line.startswith("ROUTING TABLE"):
                routing_table_section = True
                continue
            if routing_table_section and line.startswith("Virtual Address,Common Name"):
                continue
            if routing_table_section and not line:
                routing_table_section = False
                continue
            if routing_table_section and "," in line:
                parts = line.split(",")
                if len(parts) >= 2:
                    tunnel_ip = parts[0]
                    cname = parts[1]
                    tunnel_ips[cname] = tunnel_ip
                    online_names.add(cname)
    except Exception as e:
        print(f"[parse_openvpn_status] {e}")
    return clients, online_names, tunnel_ips

# ---------- Универсальный текстовый ввод ----------
async def universal_text_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return
    if context.user_data.get('await_bulk_delete_numbers'):
        await process_bulk_delete_numbers(update, context)
        return
    if context.user_data.get('await_bulk_send_numbers'):
        await process_bulk_send_numbers(update, context)
        return
    if context.user_data.get('await_bulk_enable_numbers'):
        await process_bulk_enable_numbers(update, context)
        return
    if context.user_data.get('await_bulk_disable_numbers'):
        await process_bulk_disable_numbers(update, context)
        return
    if context.user_data.get('await_renew_number'):
        await process_renew_number(update, context)
        return
    if context.user_data.get('await_renew_expiry'):
        await renew_key_expiry_handler(update, context)
        return
    if context.user_data.get('await_key_name') or context.user_data.get('await_key_expiry'):
        await create_key_handler(update, context)
        return
    if context.user_data.get('await_remote_input'):
        await process_remote_input(update, context)
        return
    await update.message.reply_text("Неизвестный ввод. Используй меню.", reply_markup=get_main_keyboard())

# ---------- HELP / START ----------
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return
    await update.message.reply_text(f"Добро пожаловать! Версия: {BOT_VERSION}", reply_markup=get_main_keyboard())

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return
    await send_help_messages(context, update.effective_chat.id)

async def clients_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return
    await update.message.reply_text(format_clients_by_certs(), parse_mode="HTML", reply_markup=get_main_keyboard())

async def view_keys_expiry_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    files = get_ovpn_files()
    names = sorted([f[:-5] for f in files])
    text = "<b>Логические сроки клиентов:</b>\n"
    if not names:
        text += "Нет."
    else:
        rows = []
        for name in names:
            iso, days_left = get_client_expiry(name)
            if iso is None:
                status = "нет срока"
            else:
                if days_left is not None:
                    if days_left < 0:
                        status = f"❌ истёк ({iso})"
                    elif days_left == 0:
                        status = f"⚠️ сегодня ({iso})"
                    else:
                        status = f"{days_left}д (до {iso})"
                else:
                    status = iso
            mark = "⛔" if is_client_ccd_disabled(name) else "🟢"
            rows.append(f"{mark} {name}: {status}")
        text += "\n".join(rows)
    if update.callback_query:
        await update.callback_query.edit_message_text(text, parse_mode="HTML", reply_markup=get_main_keyboard())
    else:
        await update.message.reply_text(text, parse_mode="HTML", reply_markup=get_main_keyboard())

def _html_escape(s: str) -> str:
    return (s
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;"))

async def log_request(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    log_text = get_status_log_tail()
    safe = _html_escape(log_text)
    msgs = split_message(f"<b>status.log (хвост):</b>\n<pre>{safe}</pre>")
    await q.edit_message_text(msgs[0], parse_mode="HTML", reply_markup=get_main_keyboard())
    for m in msgs[1:]:
        await context.bot.send_message(chat_id=q.message.chat_id, text=m, parse_mode="HTML")

# ---------- BUTTON HANDLER ----------
async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    if q.from_user.id != ADMIN_ID:
        await q.answer("Доступ запрещён.", show_alert=True)
        return
    await q.answer()
    data = q.data
    print("DEBUG callback_data:", data)

    if data == 'refresh':
        await q.edit_message_text(format_clients_by_certs(), parse_mode="HTML", reply_markup=get_main_keyboard())

    elif data == 'stats':
        clients, online_names, tunnel_ips = parse_openvpn_status()
        files = get_ovpn_files()
        lines = ["<b>Статус всех ключей:</b>"]
        for f in sorted(files):
            name = f[:-5]
            st = "⛔" if is_client_ccd_disabled(name) else ("🟢" if name in online_names else "🔴")
            lines.append(f"{st} {name}")
        text = "\n".join(lines)
        msgs = split_message(text)
        await q.edit_message_text(msgs[0], parse_mode="HTML", reply_markup=get_main_keyboard())
        for m in msgs[1:]:
            await context.bot.send_message(chat_id=q.message.chat_id, text=m, parse_mode="HTML")

    elif data == 'traffic':
        save_traffic_db(force=True)
        await q.edit_message_text(build_traffic_report(), parse_mode="HTML", reply_markup=get_main_keyboard())

    elif data == 'traffic_clear':
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("✅ Да", callback_data="confirm_clear_traffic")],
            [InlineKeyboardButton("❌ Нет", callback_data="cancel_clear_traffic")]
        ])
        await q.edit_message_text("Очистить накопленный трафик?", reply_markup=kb)

    elif data == 'confirm_clear_traffic':
        clear_traffic_stats()
        await q.edit_message_text("Очищено.", reply_markup=get_main_keyboard())

    elif data == 'cancel_clear_traffic':
        await q.edit_message_text("Отменено.", reply_markup=get_main_keyboard())

    elif data == 'update_remote':
        await start_update_remote_dialog(update, context)

    elif data == 'cancel_update_remote':
        context.user_data.pop('await_remote_input', None)
        await q.edit_message_text("Отменено.", reply_markup=get_main_keyboard())

    # Renew
    elif data == 'renew_key':
        await renew_key_request(update, context)
    elif data.startswith('renew_'):
        await renew_key_select_handler(update, context)
    elif data == 'cancel_renew':
        await renew_cancel(update, context)

    # Backup / Restore
    elif data == 'backup_menu':
        await backup_menu(update, context)
    elif data == 'restore_menu':
        await restore_menu(update, context)
    elif data == 'backup_create':
        await perform_backup_and_send(update, context)
    elif data == 'backup_list':
        await show_backup_list(update, context)
    elif data.startswith('backup_info_'):
        fname = data.replace('backup_info_', '', 1)
        await show_backup_info(update, context, fname)
    elif data.startswith('backup_send_'):
        fname = data.replace('backup_send_', '', 1)
        await send_backup_file(update, context, fname)
    elif data.startswith('restore_dry_'):
        fname = data.replace('restore_dry_', '', 1)
        await restore_dry_run(update, context, fname)
    elif data.startswith('restore_apply_'):
        fname = data.replace('restore_apply_', '', 1)
        await restore_apply(update, context, fname)
    elif data.startswith('backup_delete_confirm_'):
        fname = data.replace('backup_delete_confirm_', '', 1)
        await backup_delete_apply(update, context, fname)
    elif data.startswith('backup_delete_'):
        fname = data.replace('backup_delete_', '', 1)
        await backup_delete_prompt(update, context, fname)

    # Bulk Delete
    elif data == 'bulk_delete_start':
        await start_bulk_delete(update, context)
    elif data == 'bulk_delete_confirm':
        await bulk_delete_confirm(update, context)
    elif data == 'cancel_bulk_delete':
        await bulk_delete_cancel(update, context)

    # Bulk Send
    elif data == 'bulk_send_start':
        await start_bulk_send(update, context)
    elif data == 'bulk_send_confirm':
        await bulk_send_confirm(update, context)
    elif data == 'cancel_bulk_send':
        await bulk_send_cancel(update, context)

    # Bulk Enable
    elif data == 'bulk_enable_start':
        await start_bulk_enable(update, context)
    elif data == 'bulk_enable_confirm':
        await bulk_enable_confirm(update, context)
    elif data == 'cancel_bulk_enable':
        await bulk_enable_cancel(update, context)

    # Bulk Disable
    elif data == 'bulk_disable_start':
        await start_bulk_disable(update, context)
    elif data == 'bulk_disable_confirm':
        await bulk_disable_confirm(update, context)
    elif data == 'cancel_bulk_disable':
        await bulk_disable_cancel(update, context)

    elif data == 'update_info':
        await send_simple_update_command(update, context)
    elif data == 'copy_update_cmd':
        await resend_update_command(update, context)

    elif data == 'keys_expiry':
        await view_keys_expiry_handler(update, context)

    elif data == 'send_ipp':
        ipp_path = "/etc/openvpn/ipp.txt"
        if os.path.exists(ipp_path):
            with open(ipp_path, "rb") as f:
                await context.bot.send_document(chat_id=q.message.chat_id, document=InputFile(f), filename="ipp.txt")
            await q.edit_message_text("ipp.txt отправлен.", reply_markup=get_main_keyboard())
        else:
            await q.edit_message_text("ipp.txt не найден.", reply_markup=get_main_keyboard())

    elif data == 'block_alert':
        await q.edit_message_text(
            "🔔 Мониторинг блокировки включен.\n"
            f"Порог MIN_ONLINE_ALERT = {MIN_ONLINE_ALERT}\n"
            "Оповещения, если:\n"
            " • Все клиенты оффлайн\n"
            " • Онлайн меньше порога\n"
            "Проверка статуса: каждые 10 секунд.\n"
            "Проверка истечения логических сроков: каждые 12 часов.",
            reply_markup=get_main_keyboard()
        )

    elif data == 'help':
        await send_help_messages(context, q.message.chat_id)

    elif data == 'log':
        await log_request(update, context)

    elif data == 'create_key':
        await q.edit_message_text("Введите имя нового клиента:")
        context.user_data['await_key_name'] = True

    elif data == 'home':
        await q.edit_message_text("Главное меню.", reply_markup=get_main_keyboard())
    else:
        await q.edit_message_text("Неизвестная команда.", reply_markup=get_main_keyboard())

# ---------- Команды (CLI) ----------
async def traffic_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return
    save_traffic_db(force=True)
    await update.message.reply_text(build_traffic_report(), parse_mode="HTML", reply_markup=get_main_keyboard())

async def cmd_backup_now(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return
    try:
        path = create_backup_in_root_excluding_archives()
        await update.message.reply_text(f"✅ Бэкап: {os.path.basename(path)}", reply_markup=get_main_keyboard())
    except Exception as e:
        await update.message.reply_text(f"Ошибка: {e}", reply_markup=get_main_keyboard())

async def cmd_backup_list(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return
    items = list_backups()
    if not items:
        await update.message.reply_text("Бэкапов нет.", reply_markup=get_main_keyboard())
        return
    await update.message.reply_text("<b>Бэкапы:</b>\n" + "\n".join(items), parse_mode="HTML", reply_markup=get_main_keyboard())

async def cmd_backup_restore(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return
    if not context.args:
        await update.message.reply_text("Использование: /backup_restore <архив>")
        return
    fname = context.args[0]
    path = os.path.join(BACKUP_OUTPUT_DIR, fname)
    if not os.path.exists(path):
        await update.message.reply_text("Файл не найден.")
        return
    report = apply_restore(path, dry_run=True)
    diff = report["diff"]
    await update.message.reply_text(
        f"Dry-run {fname}:\nExtra={len(diff['extra'])} Missing={len(diff['missing'])} Changed={len(diff['changed'])}\n"
        f"Применить: /backup_restore_apply {fname}"
    )

async def cmd_backup_restore_apply(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return
    if not context.args:
        await update.message.reply_text("Использование: /backup_restore_apply <архив>")
        return
    fname = context.args[0]
    path = os.path.join(BACKUP_OUTPUT_DIR, fname)
    if not os.path.exists(path):
        await update.message.reply_text("Файл не найден.")
        return
    report = apply_restore(path, dry_run=False)
    diff = report["diff"]
    await update.message.reply_text(
        f"Restore {fname}:\nExtra удалено: {len(diff['extra'])}\nMissing: {len(diff['missing'])}\nChanged: {len(diff['changed'])}"
    )

# ---------- MAIN ----------
def main():
    app = Application.builder().token(TOKEN).build()
    load_traffic_db()
    load_client_meta()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("clients", clients_command))
    app.add_handler(CommandHandler("traffic", traffic_command))
    app.add_handler(CommandHandler("show_update_cmd", show_update_cmd))
    app.add_handler(CommandHandler("backup_now", cmd_backup_now))
    app.add_handler(CommandHandler("backup_list", cmd_backup_list))
    app.add_handler(CommandHandler("backup_restore", cmd_backup_restore))
    app.add_handler(CommandHandler("backup_restore_apply", cmd_backup_restore_apply))

    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, universal_text_handler))
    app.add_handler(CallbackQueryHandler(button_handler))

    import asyncio
    loop = asyncio.get_event_loop()
    loop.create_task(check_new_connections(app))

    app.run_polling()

if __name__ == '__main__':
    main()