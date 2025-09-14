# -*- coding: utf-8 -*-
"""
OpenVPN Telegram Monitor Bot

Новый функционал:
 - Массовое удаление ключей через ввод номеров/диапазонов (all | 1,2,5-9)
 - Массовая отправка ключей (multi-select)
 - Массовое включение заблокированных клиентов (multi-select)
 - Массовое отключение активных клиентов (multi-select)
 - Все списки показываются через Telegraph (таблица или список), ввод одной строкой.
"""

import os
import subprocess
import time
from datetime import datetime, timedelta
from typing import Optional, Tuple, List, Dict
import glob
import json
import math
import traceback
import re
import requests

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
BOT_VERSION = "2025-09-12-bulkselect2"
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

TM_TZ = pytz.timezone("Asia/Ashgabat")
MGMT_SOCKET = "/var/run/openvpn.sock"

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

# Пагинация (пока оставлена для stats текста, но не для выборов)
PAGE_SIZE_KEYS = 40

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
        return "disable" in content
    except Exception:
        return False

def block_client_ccd(client_name):
    with open(os.path.join(CCD_DIR, client_name), "w") as f:
        f.write("disable\n")

def unblock_client_ccd(client_name):
    p = os.path.join(CCD_DIR, client_name)
    if os.path.exists(p):
        os.remove(p)

def kill_openvpn_session(client_name):
    if os.path.exists(MGMT_SOCKET):
        try:
            subprocess.run(f'echo "kill {client_name}" | nc -U {MGMT_SOCKET}', shell=True)
            return True
        except Exception as e:
            print(f"[kill_openvpn_session] Ошибка: {e}")
    return False

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
        result += f"{idx}. <b>{client_name}</b>\n"
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
    header = f"N | {'Имя'.ljust(name_w)} | {'Дней'.ljust(days_w)} | {'Конфиг'.ljust(cfg_w)} | {'Создан'.ljust(created_w)}"
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

def create_keys_detailed_page() -> Optional[str]:
    rows = gather_key_metadata()
    if not rows:
        return None
    text = "Полный список ключей\n\n" + build_keys_table_text(rows)
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
        "<b>Ваши ключи</b>\n"
        "Выберите для удаления: all | 1 | 1,2,5 | 3-7 | 1,2,5-9\n"
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
        kill_openvpn_session(name)
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
        "Выберите: all | 1 | 1,2,5 | 3-7 | 1,2,5-9\n"
        f"<a href=\"{url}\">Список (Telegraph)</a>\n\n"
        "Пришлите строку."
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
        await q.edit_message_text("Нет заблокированных.", reply_markup=get_main_keyboard())
        return
    url = create_names_telegraph_page(disabled, "Включение клиентов", "Заблокированные клиенты")
    if not url:
        await q.edit_message_text("Ошибка Telegraph.", reply_markup=get_main_keyboard())
        return
    context.user_data['bulk_enable_keys'] = disabled
    context.user_data['await_bulk_enable_numbers'] = True
    text = (
        "<b>Включить клиентов</b>\n"
        "Выберите: all | 1 | 1,2 | 3-7 ...\n"
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
        "Выберите: all | 1 | 1,2,7 | 3-10 ...\n"
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
        kill_openvpn_session(name)
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

# ---------- HELP ----------
HELP_TEXT = f"""
<b>VPN Бот (версия {BOT_VERSION})</b>

Массовые операции:
 - Удаление: кнопка 🗑️ → ввод номеров/диапазонов → подтверждение
 - Отправка: 📤 → ввод номеров → файлы приходят
 - Включить: ✅ → (заблокированные) ввод номеров
 - Отключить: ⚠️ → (активные) ввод номеров

Форматы: all | 1 | 1,2,5 | 3-7 | 1,2,5-9 (пробелы/запятые допустимы, диапазоны a-b)
"""

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

# ---------- Генерация OVPN / создание / обновление ----------
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
        template_content = f.read()
    with open(ca_path, "r") as f:
        ca_content = f.read()
    with open(cert_path, "r") as f:
        cert_content = f.read()
    with open(key_path, "r") as f:
        key_content = f.read()

    content = template_content + "\n"
    content += "<ca>\n" + ca_content + "\n</ca>\n"
    content += "<cert>\n" + cert_content + "\n</cert>\n"
    content += "<key>\n" + key_content + "\n</key>\n"

    if TLS_SIG == 1 and os.path.exists(tls_crypt_path):
        with open(tls_crypt_path, "r") as f:
            tls_crypt_content = f.read()
        content += "<tls-crypt>\n" + tls_crypt_content + "\n</tls-crypt>\n"
    elif TLS_SIG == 2 and os.path.exists(tls_auth_path):
        content += "key-direction 1\n"
        with open(tls_auth_path, "r") as f:
            tls_auth_content = f.read()
        content += "<tls-auth>\n" + tls_auth_content + "\n</tls-auth>\n"

    with open(ovpn_file, "w") as f:
        f.write(content)
    return ovpn_file

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
        await update.message.reply_text("Введите срок действия (дней, по умолчанию 825):")
        return

    if context.user_data.get('await_key_expiry'):
        try:
            days = int(update.message.text.strip())
        except:
            days = 825
        context.user_data['new_key_expiry'] = days
        context.user_data['await_key_expiry'] = False
        key_name = context.user_data['new_key_name']
        try:
            subprocess.run(
                f"EASYRSA_CERT_EXPIRE={days} {EASYRSA_DIR}/easyrsa --batch build-client-full {key_name} nopass",
                shell=True, check=True, cwd=EASYRSA_DIR
            )
        except subprocess.CalledProcessError as e:
            await update.message.reply_text(f"Ошибка генерации: {e}")
            context.user_data.clear()
            return
        ovpn_path = generate_ovpn_for_client(key_name)
        await update.message.reply_text(
            f"Клиент {key_name} создан. Срок {days} дней.\nФайл: {ovpn_path}"
        )
        with open(ovpn_path, "rb") as f:
            await context.bot.send_document(chat_id=update.effective_chat.id, document=InputFile(f), filename=f"{key_name}.ovpn")
        context.user_data.clear()
        return

# ---------- Renew (оставлен без изменений) ----------
async def renew_key_expiry_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.user_data.get('await_renew_expiry'):
        return
    key_name = context.user_data['renew_key_name']
    cert_path = f"{EASYRSA_DIR}/pki/issued/{key_name}.crt"
    if not os.path.exists(cert_path):
        await update.message.reply_text("Сертификат не найден.")
        context.user_data.clear()
        return
    try:
        days_to_add = int(update.message.text.strip())
    except Exception:
        await update.message.reply_text("Некорректное число.")
        return

    # Определяем старую дату окончания
    from OpenSSL import crypto
    from datetime import datetime, timedelta
    with open(cert_path, "rb") as f:
        cert_data = f.read()
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
        expiry_old = datetime.strptime(cert.get_notAfter().decode("ascii"), "%Y%m%d%H%M%SZ")

    new_expiry_date = expiry_old + timedelta(days=days_to_add)
    days_total = (new_expiry_date - datetime.utcnow()).days
    if days_total < 1:
        await update.message.reply_text("Срок действия не может быть в прошлом.")
        context.user_data.clear()
        return

    # Продлеваем сертификат через easyrsa renew (НЕ трогаем .key/.req)
    try:
        subprocess.run(
            f"EASYRSA_CERT_EXPIRE={days_total} {EASYRSA_DIR}/easyrsa --batch renew {key_name}",
            shell=True, check=True, cwd=EASYRSA_DIR
        )
    except subprocess.CalledProcessError as e:
        await update.message.reply_text(f"Ошибка продления: {e}")
        context.user_data.clear()
        return

    ovpn_path = generate_ovpn_for_client(key_name)
    await update.message.reply_text(f"Срок действия ключа {key_name} продлён на {days_to_add} дней. Новый общий срок: {days_total} дней. Старый .ovpn можно использовать.")
    with open(ovpn_path, "rb") as f:
        await context.bot.send_document(chat_id=update.effective_chat.id, document=InputFile(f), filename=f"{key_name}.ovpn")
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
    if not os.path.exists(BACKUP_OUTPUT_DIR):
        return []
    items = []
    for fn in os.listdir(BACKUP_OUTPUT_DIR):
        if fn.startswith("openvpn_full_backup_") and fn.endswith(".tar.gz"):
            items.append(fn)
    return sorted(items, reverse=True)

async def perform_backup_and_send(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return
    try:
        path = br_create_backup()
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
    full = os.path.join(BACKUP_OUTPUT_DIR, fname)
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
    full = os.path.join(BACKUP_OUTPUT_DIR, fname)
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
            [InlineKeyboardButton("⬅️ Назад", callback_data="backup_list")]
        ])
        await update.callback_query.edit_message_text(txt, parse_mode="HTML", reply_markup=kb)
    finally:
        import shutil
        shutil.rmtree(staging, ignore_errors=True)

async def restore_dry_run(update: Update, context: ContextTypes.DEFAULT_TYPE, fname: str):
    full = os.path.join(BACKUP_OUTPUT_DIR, fname)
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
                    migrated[k] = {'rx': int(v.get('rx', 0)) if isinstance(v, dict) else (int(v) if isinstance(v, int) else 0),
                                   'tx': int(v.get('tx', 0)) if isinstance(v, dict) else 0}
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
    while True:
        try:
            clients, online_names, tunnel_ips = parse_openvpn_status()
            update_traffic_from_status(clients)
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
    # приоритет bulk состояний
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
    if context.user_data.get('await_key_name') or context.user_data.get('await_key_expiry'):
        await create_key_handler(update, context)
        return
    if context.user_data.get('await_renew_expiry'):
        await renew_key_expiry_handler(update, context)
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
    await update.message.reply_text(HELP_TEXT, parse_mode="HTML", reply_markup=get_main_keyboard())

async def clients_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return
    await update.message.reply_text(format_clients_by_certs(), parse_mode="HTML", reply_markup=get_main_keyboard())

async def view_keys_expiry_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    cert_dir = f"{EASYRSA_DIR}/pki/issued"
    cert_files = glob.glob(f"{cert_dir}/*.crt")
    text = "<b>Сроки сертификатов:</b>\n"
    if not cert_files:
        text += "Нет."
    else:
        rows = []
        for cert_file in cert_files:
            name = os.path.basename(cert_file)[:-4]
            if name.startswith("server_"):
                continue
            with open(cert_file, "rb") as f:
                cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
            not_after = cert.get_notAfter().decode("ascii")
            expiry_date = datetime.strptime(not_after, "%Y%m%d%H%M%SZ")
            days_left = (expiry_date - datetime.utcnow()).days
            status = "❌ истёк" if days_left < 0 else (f"⚠️ {days_left}д" if days_left < 7 else f"{days_left}д")
            rows.append(f"{name}: {status} (до {expiry_date.strftime('%Y-%m-%d')})")
        text += "\n".join(sorted(rows))
    if update.callback_query:
        await update.callback_query.edit_message_text(text, parse_mode="HTML", reply_markup=get_main_keyboard())
    else:
        await update.message.reply_text(text, parse_mode="HTML", reply_markup=get_main_keyboard())

async def log_request(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    log_text = get_status_log_tail()
    msgs = split_message(f"<b>status.log (хвост):</b>\n<pre>{log_text}</pre>")
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

    if data == 'refresh':
        await q.edit_message_text(format_clients_by_certs(), parse_mode="HTML", reply_markup=get_main_keyboard())

    elif data == 'stats':
        clients, online_names, tunnel_ips = parse_openvpn_status()
        # компактный статус всех
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
        # (оставлен прежний функционал если нужен — можно добавить позже)
        await q.edit_message_text("Функция массового обновления remote перенесена (в предыдущих версиях).", reply_markup=get_main_keyboard())

    # Renew
    elif data == 'renew_key':
        await renew_key_request(update, context)
    elif data.startswith('renew_'):
        await renew_key_select_handler(update, context)

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

    elif data == 'help':
        await q.edit_message_text(HELP_TEXT, parse_mode="HTML", reply_markup=get_main_keyboard())

    # Backup / Restore
    elif data == 'backup_menu':
        await backup_menu(update, context)
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
    elif data == 'restore_menu':
        await restore_menu(update, context)
    elif data.startswith('restore_dry_'):
        fname = data.replace('restore_dry_', '', 1)
        await restore_dry_run(update, context, fname)
    elif data.startswith('restore_apply_'):
        fname = data.replace('restore_apply_', '', 1)
        await restore_apply(update, context, fname)

    elif data == 'block_alert':
        await q.edit_message_text(
            f"Тревога активна в фоне.\nПорог < {MIN_ONLINE_ALERT}, антиспам {ALERT_INTERVAL_SEC}s.",
            reply_markup=get_main_keyboard()
        )

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
        path = br_create_backup()
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

    # Команды
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("clients", clients_command))
    app.add_handler(CommandHandler("traffic", traffic_command))
    app.add_handler(CommandHandler("show_update_cmd", show_update_cmd))
    app.add_handler(CommandHandler("backup_now", cmd_backup_now))
    app.add_handler(CommandHandler("backup_list", cmd_backup_list))
    app.add_handler(CommandHandler("backup_restore", cmd_backup_restore))
    app.add_handler(CommandHandler("backup_restore_apply", cmd_backup_restore_apply))

    # Текст / Документы
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, universal_text_handler))

    # Callback
    app.add_handler(CallbackQueryHandler(button_handler))

    import asyncio
    loop = asyncio.get_event_loop()
    loop.create_task(check_new_connections(app))

    app.run_polling()

if __name__ == '__main__':
    main()