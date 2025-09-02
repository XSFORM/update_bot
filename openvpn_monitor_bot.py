# -*- coding: utf-8 -*-
import os
import subprocess
import time
from datetime import date, datetime, timedelta
import glob
import json
from OpenSSL import crypto
import pytz

from telegram import (
    Update, InlineKeyboardButton, InlineKeyboardMarkup, InputFile
)
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler, ContextTypes, MessageHandler, filters
)

from config import TOKEN, ADMIN_ID

# ---------------- Версия и обновление (вывод команд) ----------------
BOT_VERSION = "2025-09-02"
UPDATE_SOURCE_URL = "https://raw.githubusercontent.com/XSFORM/update_bot/main/openvpn_monitor_bot.py"

def build_update_commands():
    short_cmd = f"curl -L -o /root/monitor_bot/openvpn_monitor_bot.py {UPDATE_SOURCE_URL} && systemctl restart vpn_bot.service"
    safe_cmd = (
        "cd /root/monitor_bot && "
        "cp openvpn_monitor_bot.py openvpn_monitor_bot.py.bak_$(date +%Y%m%d_%H%M%S) && "
        f"curl -L -o openvpn_monitor_bot.py {UPDATE_SOURCE_URL} && "
        "python3 -m py_compile openvpn_monitor_bot.py && "
        "systemctl restart vpn_bot.service"
    )
    return short_cmd, safe_cmd

async def show_update_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        await update.message.reply_text("Доступ запрещён.")
        return
    short_cmd, safe_cmd = build_update_commands()
    text = (
        f"<b>Команды обновления (версия {BOT_VERSION})</b>\n\n"
        "Простая:\n<code>" + short_cmd + "</code>\n\n"
        "С бэкапом и проверкой:\n<code>" + safe_cmd + "</code>\n\n"
        "Откат (пример):\n<code>cp /root/monitor_bot/openvpn_monitor_bot.py.bak_YYYYMMDD_HHMMSS "
        "/root/monitor_bot/openvpn_monitor_bot.py && systemctl restart vpn_bot.service</code>"
    )
    await update.message.reply_text(text, parse_mode="HTML", disable_web_page_preview=True, reply_markup=get_main_keyboard())

async def send_update_cmd_via_button(chat_id: int, bot):
    short_cmd, safe_cmd = build_update_commands()
    text = (
        f"<b>Обновление бота</b>\nВерсия: <code>{BOT_VERSION}</code>\n\n"
        "Простая:\n<code>" + short_cmd + "</code>\n\n"
        "Расширенная (с бэкапом):\n<code>" + safe_cmd + "</code>"
    )
    await bot.send_message(chat_id=chat_id, text=text, parse_mode="HTML", disable_web_page_preview=True)

# --- Константы путей ---
KEYS_DIR = "/root"
OPENVPN_DIR = "/etc/openvpn"
EASYRSA_DIR = "/etc/openvpn/easy-rsa"
IPTABLES_DIR = "/etc/iptables"
BACKUP_DIR = "/root"
STATUS_LOG = "/var/log/openvpn/status.log"
CCD_DIR = "/etc/openvpn/ccd"

NOTIFY_FILE = "/root/monitor_bot/notify.flag"
TM_TZ = pytz.timezone("Asia/Ashgabat")
MGMT_SOCKET = "/var/run/openvpn.sock"

# --- Порог тревоги и антиспам ---
MIN_ONLINE_ALERT = 15
ALERT_INTERVAL_SEC = 300
last_alert_time = 0
clients_last_online = set()

# --- Учёт трафика ---
TRAFFIC_DB_PATH = "/root/monitor_bot/traffic_usage.json"
traffic_usage = {}              # client_name -> total_bytes
_last_session_state = {}        # client_name -> {'connected_since': str, 'total': int}
_last_traffic_save_time = 0
TRAFFIC_SAVE_INTERVAL = 60      # сек между автосохранениями

# ================== Базовые вспомогательные ==================

def get_cert_expiry_info():
    cert_dir = f"{EASYRSA_DIR}/pki/issued"
    cert_files = glob.glob(f"{cert_dir}/*.crt")
    result = []
    for cert_file in cert_files:
        client_name = os.path.basename(cert_file).replace(".crt", "")
        with open(cert_file, "rb") as f:
            cert_data = f.read()
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
            not_after = cert.get_notAfter().decode("ascii")
            expiry_date = datetime.strptime(not_after, "%Y%m%d%H%M%SZ")
            days_left = (expiry_date - datetime.utcnow()).days
            result.append((client_name, days_left, expiry_date))
    return result

def format_clients_by_certs():
    cert_dir = f"{EASYRSA_DIR}/pki/issued/"
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

def format_all_keys_with_status_compact(keys_dir=KEYS_DIR, clients_online=set(), clients=[], tunnel_ips={}, ipp_map={}):
    files = [f for f in os.listdir(keys_dir) if f.endswith(".ovpn")]
    result = "<b>Статус всех ключей:</b>\n"
    for idx, f in enumerate(sorted(files), 1):
        key_name = f[:-5]
        status = "🟢" if key_name in clients_online and not is_client_ccd_disabled(key_name) else "🔴"
        if is_client_ccd_disabled(key_name):
            status = "⛔"
        tunnel_ip = tunnel_ips.get(key_name) or ipp_map.get(key_name, "Н/Д")
        client_info = next((c for c in clients if c['name'] == key_name), None)
        if client_info and key_name in clients_online and not is_client_ccd_disabled(key_name):
            real_ip = client_info.get('ip', 'Н/Д')
        else:
            real_ip = "Н/Д"
        result += f"{idx}. | {status} | <b>{key_name}</b> | <code>{tunnel_ip}</code> | <code>{real_ip}</code>\n"
    if not files:
        result += "Нет ключей."
    return result

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
        print(f"[parse_openvpn_status] Ошибка чтения status.log: {e}")
    return clients, online_names, tunnel_ips

def read_ipp_file(ipp_file="/etc/openvpn/ipp.txt"):
    ipp_map = {}
    try:
        with open(ipp_file, "r") as f:
            for line in f:
                if ',' in line:
                    name, ip = line.strip().split(',', 1)
                    ipp_map[name] = ip
    except Exception:
        pass
    return ipp_map

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
    ccd_path = os.path.join(CCD_DIR, client_name)
    with open(ccd_path, "w") as f:
        f.write("disable\n")

def unblock_client_ccd(client_name):
    ccd_path = os.path.join(CCD_DIR, client_name)
    if os.path.exists(ccd_path):
        os.remove(ccd_path)

def kill_openvpn_session(client_name):
    if os.path.exists(MGMT_SOCKET):
        try:
            subprocess.run(f'echo "kill {client_name}" | nc -U {MGMT_SOCKET}', shell=True)
            return True
        except Exception as e:
            print(f"[kill_openvpn_session] Ошибка: {e}")
    return False

# ================== Трафик ==================

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
                    # нормальный новый формат
                    migrated[k] = {
                        'rx': int(v.get('rx', 0)),
                        'tx': int(v.get('tx', 0))
                    }
                elif isinstance(v, int):
                    # старый total -> в RX, TX=0 (или можно поделить/оставить в total)
                    migrated[k] = {'rx': v, 'tx': 0}
                    changed = True
                else:
                    # неизвестно — обнуляем
                    migrated[k] = {'rx': 0, 'tx': 0}
                    changed = True
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

def format_bytes_gb(b):
    try:
        return f"{int(b)/1024/1024/1024:.2f} GB"
    except:
        return "0 GB"

def build_traffic_report():
    if not traffic_usage:
        return "<b>Трафик:</b>\nПока нет накопленных данных."
    # сортируем по сумме rx+tx
    items = sorted(
        traffic_usage.items(),
        key=lambda x: (x[1]['rx'] + x[1]['tx']) if isinstance(x[1], dict) else x[1],
        reverse=True
    )
    lines = ["<b>Использование трафика:</b>"]
    for name, val in items:
        if isinstance(val, dict):
            rx = val.get('rx', 0)
            tx = val.get('tx', 0)
            total = rx + tx
            lines.append(
                f"• <b>{name}</b>: ↓{format_gb(rx)} ↑{format_gb(tx)} (Σ 🟢{format_gb(total)}🟢)"
            )
        else:
            # fallback если внезапно старый формат
            lines.append(f"• <b>{name}</b>: --{format_bytes_gb(total)}--")
    return "\n".join(lines)

def update_traffic_from_status(clients):
    """
    Пересчитывает накопительный трафик (раздельно RX/TX) на основе дельт текущей сессии.
    При новой сессии (connected_since изменился) — baseline обновляется без добавления.
    """
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

        # новая сессия или нет baseline
        if prev is None or prev['connected_since'] != connected_since:
            _last_session_state[name] = {
                'connected_since': connected_since,
                'rx': recv,
                'tx': sent
            }
            continue

        # старая сессия — считаем дельты
        delta_rx = recv - prev['rx']
        delta_tx = sent - prev['tx']

        if delta_rx > 0:
            traffic_usage[name]['rx'] += delta_rx
            prev['rx'] = recv
            changed = True
        else:
            prev['rx'] = recv  # обновляем baseline (обнуление или rollback счётчика OpenVPN)

        if delta_tx > 0:
            traffic_usage[name]['tx'] += delta_tx
            prev['tx'] = sent
            changed = True
        else:
            prev['tx'] = sent

    if changed:
        save_traffic_db()

# ================== UI / HELP ==================

HELP_TEXT = f"""
<b>📖 Помощь по VPN Боту (версия {BOT_VERSION}):</b>

Функции:
• Статистика / Онлайн / Лог
• Создание, обновление, удаление ключей
• Включение / отключение клиента (CCD)
• Бэкап / восстановление
• Тревога по количеству онлайн
• Накопительный трафик (кнопка 📶 Трафик / команда /traffic)
• Вывод команд обновления (🔗 Обновление / /show_update_cmd)

Все команды доступны только администратору.
"""

def get_main_keyboard():
    keyboard = [
        [InlineKeyboardButton("🔄 Список клиентов", callback_data='refresh')],
        [InlineKeyboardButton("📊 Статистика", callback_data='stats'),
         InlineKeyboardButton("🟢 Онлайн клиенты", callback_data='online')],
        [InlineKeyboardButton("📶 Трафик", callback_data='traffic'),
         InlineKeyboardButton("🔗 Обновление", callback_data='update_info')],
        [InlineKeyboardButton("⏳ Сроки ключей", callback_data='keys_expiry'),
         InlineKeyboardButton("⌛ Обновить ключ", callback_data='renew_key')],
        [InlineKeyboardButton("✅ Вкл.клиента", callback_data='enable'),
         InlineKeyboardButton("⚠️ Откл.клиента", callback_data='disable')],
        [InlineKeyboardButton("➕ Создать ключ", callback_data='create_key'),
         InlineKeyboardButton("🗑️ Удалить ключ", callback_data='delete_key')],
        [InlineKeyboardButton("📤 Отправить ключи", callback_data='send_keys'),
         InlineKeyboardButton("📜 Просмотр лога", callback_data='log')],
        [InlineKeyboardButton("📦 Бэкап OpenVPN", callback_data='backup'),
         InlineKeyboardButton("🔄 Восстан.бэкап", callback_data='restore')],
        [InlineKeyboardButton("🚨 Тревога блокировки", callback_data='block_alert')],
        [InlineKeyboardButton("❓ Помощь", callback_data='help'),
         InlineKeyboardButton("🏠 В главное меню", callback_data='home')],
    ]
    return InlineKeyboardMarkup(keyboard)

def get_keys_keyboard(keys):
    keyboard = []
    for i, fname in enumerate(keys, 1):
        keyboard.append([InlineKeyboardButton(f"{i}. {fname}", callback_data=f"key_{i}")])
    keyboard.append([InlineKeyboardButton("⬅️ Назад", callback_data='home')])
    return InlineKeyboardMarkup(keyboard)

def get_delete_keys_keyboard(keys):
    keyboard = []
    for i, fname in enumerate(keys, 1):
        keyboard.append([InlineKeyboardButton(f"{i}. {fname}", callback_data=f"delete_{fname}")])
    keyboard.append([InlineKeyboardButton("⬅️ Назад", callback_data='home')])
    return InlineKeyboardMarkup(keyboard)

def get_confirm_delete_keyboard(fname):
    keyboard = [
        [InlineKeyboardButton("✅ Да, удалить", callback_data=f"confirm_delete_{fname}")],
        [InlineKeyboardButton("❌ Нет, отмена", callback_data="cancel_delete")],
    ]
    return InlineKeyboardMarkup(keyboard)

# ================== Генерация OVPN / Ключи ==================

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

    ovpn_content = template_content + "\n"
    ovpn_content += "<ca>\n" + ca_content + "\n</ca>\n"
    ovpn_content += "<cert>\n" + cert_content + "\n</cert>\n"
    ovpn_content += "<key>\n" + key_content + "\n</key>\n"

    if TLS_SIG == 1 and os.path.exists(tls_crypt_path):
        with open(tls_crypt_path, "r") as f:
            tls_crypt_content = f.read()
        ovpn_content += "<tls-crypt>\n" + tls_crypt_content + "\n</tls-crypt>\n"
    elif TLS_SIG == 2 and os.path.exists(tls_auth_path):
        ovpn_content += "key-direction 1\n"
        with open(tls_auth_path, "r") as f:
            tls_auth_content = f.read()
        ovpn_content += "<tls-auth>\n" + tls_auth_content + "\n</tls-auth>\n"

    with open(ovpn_file, "w") as f:
        f.write(ovpn_content)
    return ovpn_file

# --- Create / Renew key handlers (как раньше) ---

async def create_key_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if context.user_data.get('await_key_name'):
        key_name = update.message.text.strip()
        ovpn_file = os.path.join(KEYS_DIR, f"{key_name}.ovpn")
        if os.path.exists(ovpn_file):
            await update.message.reply_text(
                f"Клиент <b>{key_name}</b> уже существует! Введите другое имя.",
                parse_mode="HTML"
            )
            return
        context.user_data['new_key_name'] = key_name
        context.user_data['await_key_name'] = False
        context.user_data['await_key_expiry'] = True
        await update.message.reply_text("Введите срок действия ключа в днях (по умолчанию 825):")
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
            await update.message.reply_text(f"Ошибка генерации сертификата: {e}", parse_mode="HTML")
            context.user_data.clear()
            return

        ovpn_path = generate_ovpn_for_client(key_name)
        await update.message.reply_text(
            f"Клиент <b>{key_name}</b> успешно создан!\nСрок действия: {days} дней.\nФайл: {ovpn_path}",
            parse_mode="HTML"
        )
        with open(ovpn_path, "rb") as f:
            await context.bot.send_document(
                chat_id=update.effective_chat.id,
                document=InputFile(f),
                filename=f"{key_name}.ovpn"
            )
        context.user_data.clear()
        return

async def renew_key_request(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keys = get_ovpn_files()
    if not keys:
        await update.callback_query.edit_message_text("Нет ключей для обновления.", reply_markup=get_main_keyboard())
        return
    keyboard = []
    for i, fname in enumerate(keys, 1):
        keyboard.append([InlineKeyboardButton(f"{i}. {fname[:-5]}", callback_data=f"renew_{fname}")])
    keyboard.append([InlineKeyboardButton("⬅️ Назад", callback_data='home')])
    await update.callback_query.edit_message_text(
        "Выберите ключ для обновления:",
        reply_markup=InlineKeyboardMarkup(keyboard)
    )

async def renew_key_select_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    fname = query.data.split('_', 1)[1]
    key_name = fname[:-5] if fname.endswith('.ovpn') else fname
    context.user_data['renew_key_name'] = key_name
    context.user_data['await_renew_expiry'] = True
    await query.edit_message_text(
        f"Введите сколько дней добавить к сроку действия ключа <b>{key_name}</b>:",
        parse_mode="HTML"
    )

async def renew_key_expiry_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.user_data.get('await_renew_expiry'):
        return
    key_name = context.user_data['renew_key_name']
    cert_path = f"{EASYRSA_DIR}/pki/issued/{key_name}.crt"
    key_path = f"{EASYRSA_DIR}/pki/private/{key_name}.key"
    req_path = f"{EASYRSA_DIR}/pki/reqs/{key_name}.req"
    if not os.path.exists(cert_path):
        await update.message.reply_text("Сертификат не найден!")
        context.user_data.clear()
        return
    try:
        days_to_add = int(update.message.text.strip())
    except:
        await update.message.reply_text("Некорректное число дней. Попробуйте ещё раз.")
        return

    with open(cert_path, "rb") as f:
        cert_data = f.read()
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
        expiry_old = datetime.strptime(cert.get_notAfter().decode("ascii"), "%Y%m%d%H%M%SZ")

    new_expiry_date = expiry_old + timedelta(days=days_to_add)
    total_days = (new_expiry_date - datetime.utcnow()).days

    for p in [cert_path, key_path, req_path]:
        if os.path.exists(p):
            os.remove(p)

    try:
        subprocess.run(
            f"EASYRSA_CERT_EXPIRE={total_days} {EASYRSA_DIR}/easyrsa --batch build-client-full {key_name} nopass",
            shell=True, check=True, cwd=EASYRSA_DIR
        )
    except subprocess.CalledProcessError as e:
        await update.message.reply_text(f"Ошибка обновления: {e}", parse_mode="HTML")
        context.user_data.clear()
        return

    ovpn_path = generate_ovpn_for_client(key_name)
    await update.message.reply_text(
        f"Ключ <b>{key_name}</b> обновлён!\nНовый срок: {total_days} дней.\nФайл: {ovpn_path}",
        parse_mode="HTML"
    )
    with open(ovpn_path, "rb") as f:
        await context.bot.send_document(
            chat_id=update.effective_chat.id,
            document=InputFile(f),
            filename=f"{key_name}.ovpn"
        )
    context.user_data.clear()

# ================== Прочее (лог, бэкап, восстановление) ==================

def get_status_log_tail(n=40):
    try:
        with open(STATUS_LOG, "r") as f:
            lines = f.readlines()
        return "".join(lines[-n:])
    except Exception as e:
        return f"Ошибка чтения status.log: {e}"

def create_backup():
    backup_file = f"{BACKUP_DIR}/vpn_backup_{date.today().strftime('%Y%m%d')}.tar.gz"
    ovpn_files = [os.path.join(KEYS_DIR, f) for f in os.listdir(KEYS_DIR) if f.endswith(".ovpn")]
    files_to_backup = ovpn_files + [OPENVPN_DIR, IPTABLES_DIR]
    cmd = ["tar", "-czvf", backup_file] + files_to_backup
    subprocess.run(cmd)
    return backup_file

async def send_backup(update: Update, context: ContextTypes.DEFAULT_TYPE):
    backup_file = create_backup()
    with open(backup_file, "rb") as f:
        await context.bot.send_document(
            chat_id=update.effective_chat.id,
            document=InputFile(f),
            filename=os.path.basename(backup_file)
        )

async def restore_request(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.callback_query.answer()
    await update.callback_query.edit_message_text("Отправьте архив (.tar.gz) сюда.")
    context.user_data['restore_wait_file'] = True

async def document_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        await update.message.reply_text("Доступ запрещён.")
        return
    if context.user_data.get('restore_wait_file'):
        file = update.message.document
        if file and (
            file.mime_type in ['application/gzip', 'application/x-gzip', 'application/x-tar', 'application/octet-stream']
            or file.file_name.endswith(('.tar.gz', '.tgz', '.tar'))
        ):
            file_id = file.file_id
            file_name = file.file_name
            new_path = f"/root/{file_name}"
            new_file = await context.bot.get_file(file_id)
            await new_file.download_to_drive(new_path)
            context.user_data['restore_wait_file'] = False
            context.user_data['restore_file_path'] = new_path
            kb = InlineKeyboardMarkup([
                [InlineKeyboardButton("✅ Да, восстановить", callback_data='restore_confirm')],
                [InlineKeyboardButton("❌ Нет, отменить", callback_data='restore_cancel')],
            ])
            await update.message.reply_text(
                f"Файл получен: <code>{file_name}</code>\nВосстановить?",
                parse_mode="HTML",
                reply_markup=kb
            )
        else:
            await update.message.reply_text("Нужен архив .tar.gz")
    else:
        await update.message.reply_text("Сначала нажмите 'Восстан.бэкап' в меню.")

async def restore_confirm_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    file_path = context.user_data.get('restore_file_path')
    if file_path and os.path.exists(file_path):
        subprocess.run(f"tar -xzvf {file_path} -C /", shell=True)
        await update.callback_query.answer("Готово!")
        await update.callback_query.edit_message_text("✅ Восстановлено.", reply_markup=get_main_keyboard())
        context.user_data['restore_file_path'] = None
    else:
        await update.callback_query.answer("Файл не найден!", show_alert=True)
        await update.callback_query.edit_message_text("❌ Ошибка: файл не найден.", reply_markup=get_main_keyboard())

async def restore_cancel_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data['restore_file_path'] = None
    await update.callback_query.answer("Отменено.")
    await update.callback_query.edit_message_text("Восстановление отменено.", reply_markup=get_main_keyboard())

# ================== Трафик хендлер ==================

async def traffic_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        await update.message.reply_text("Доступ запрещён.")
        return
    save_traffic_db(force=True)
    report = build_traffic_report()
    await update.message.reply_text(report, parse_mode="HTML", reply_markup=get_main_keyboard())

# ================== Мониторинг (цикл) ==================

async def check_new_connections(app: Application):
    global clients_last_online, last_alert_time
    import asyncio
    while True:
        try:
            clients, online_names, tunnel_ips = parse_openvpn_status()
            # учёт трафика
            update_traffic_from_status(clients)

            online_count = len(online_names)
            total_keys = len(get_ovpn_files())
            now = time.time()

            if online_count == 0 and total_keys > 0:
                if now - last_alert_time > ALERT_INTERVAL_SEC:
                    await app.bot.send_message(
                        chat_id=ADMIN_ID,
                        text="❌ Все клиенты оффлайн! Возможна блокировка IP или падение OpenVPN.",
                        parse_mode="HTML"
                    )
                    last_alert_time = now
            elif 0 < online_count < MIN_ONLINE_ALERT:
                if now - last_alert_time > ALERT_INTERVAL_SEC:
                    await app.bot.send_message(
                        chat_id=ADMIN_ID,
                        text=f"⚠️ Онлайн мало: {online_count} из {total_keys}.",
                        parse_mode="HTML"
                    )
                    last_alert_time = now
            else:
                if online_count >= MIN_ONLINE_ALERT:
                    last_alert_time = 0

            clients_last_online = set(online_names)
            await asyncio.sleep(10)
        except Exception as e:
            print(f"[check_new_connections] Ошибка цикла: {e}")
            await asyncio.sleep(10)

# ================== Прочие хендлеры ==================

async def universal_text_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        await update.message.reply_text("Доступ запрещён.")
        return
    if context.user_data.get('await_key_name') or context.user_data.get('await_key_expiry'):
        await create_key_handler(update, context)
    elif context.user_data.get('await_renew_expiry'):
        await renew_key_expiry_handler(update, context)
    else:
        await update.message.reply_text("Неизвестный ввод. Используй меню.", reply_markup=get_main_keyboard())

async def enable_request(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    all_keys = get_ovpn_files()
    keyboard = []
    for fname in sorted(all_keys):
        cname = fname[:-5]
        if is_client_ccd_disabled(cname):
            keyboard.append([InlineKeyboardButton(f"✅ Включить {cname}", callback_data=f"enable_{cname}")])
    if not keyboard:
        keyboard.append([InlineKeyboardButton("Нет заблокированных клиентов", callback_data="home")])
    keyboard.append([InlineKeyboardButton("⬅️ Назад", callback_data="home")])
    await query.edit_message_text("Выбери клиента для включения:", reply_markup=InlineKeyboardMarkup(keyboard))

async def disable_request(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    all_keys = get_ovpn_files()
    keyboard = []
    for fname in sorted(all_keys):
        cname = fname[:-5]
        if not is_client_ccd_disabled(cname):
            keyboard.append([InlineKeyboardButton(f"⚠️ Отключить {cname}", callback_data=f"disable_{cname}")])
    if not keyboard:
        keyboard.append([InlineKeyboardButton("Нет клиентов для отключения", callback_data="home")])
    keyboard.append([InlineKeyboardButton("⬅️ Назад", callback_data="home")])
    await query.edit_message_text("Выбери клиента для отключения:", reply_markup=InlineKeyboardMarkup(keyboard))

async def enable_client_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    cname = query.data.split('_', 1)[1]
    unblock_client_ccd(cname)
    await query.edit_message_text(f"Клиент <b>{cname}</b> включён.", parse_mode="HTML", reply_markup=get_main_keyboard())

async def disable_client_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    cname = query.data.split('_', 1)[1]
    block_client_ccd(cname)
    killed = kill_openvpn_session(cname)
    msg = f"Клиент <b>{cname}</b> отключён."
    msg += "\nСессия завершена." if killed else "\nАктивная сессия завершится при переподключении."
    await query.edit_message_text(msg, parse_mode="HTML", reply_markup=get_main_keyboard())

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        await update.message.reply_text("Доступ запрещён.")
        return
    await update.message.reply_text(f"Добро пожаловать в VPN бот! Версия: {BOT_VERSION}", reply_markup=get_main_keyboard())

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        await update.message.reply_text("Доступ запрещён.")
        return
    await update.message.reply_text(HELP_TEXT, parse_mode="HTML", reply_markup=get_main_keyboard())

async def clients_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        await update.message.reply_text("Доступ запрещён.")
        return
    msg = format_clients_by_certs()
    await update.message.reply_text(msg, parse_mode="HTML", reply_markup=get_main_keyboard())

async def view_keys_expiry_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keys_info = get_cert_expiry_info()
    text = "<b>Сроки действия клиентских ключей:</b>\n"
    if not keys_info:
        text += "Нет активных ключей."
    else:
        for client_name, days_left, expiry_date in sorted(keys_info):
            if days_left < 0:
                status = "❌ истёк"
            elif days_left < 7:
                status = f"⚠️ {days_left} дней"
            else:
                status = f"{days_left} дней"
            text += f"• <b>{client_name}</b>: {status} (до {expiry_date.strftime('%Y-%m-%d')})\n"
    if update.callback_query:
        await update.callback_query.edit_message_text(text, parse_mode="HTML", reply_markup=get_main_keyboard())
    else:
        await update.message.reply_text(text, parse_mode="HTML", reply_markup=get_main_keyboard())

async def online_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        await update.message.reply_text("Доступ запрещён.")
        return
    clients, online_names, tunnel_ips = parse_openvpn_status()
    res = []
    for c in clients:
        if c['name'] in online_names and not is_client_ccd_disabled(c['name']):
            tunnel_ip = tunnel_ips.get(c['name'], 'нет')
            res.append(
                f"🟢 <b>{c['name']}</b>\n"
                f"🌐 <code>{c.get('ip','нет')}</code>\n"
                f"🛡️ Tunnel: <code>{tunnel_ip}</code>\n"
                f"📥 {bytes_to_mb(c.get('bytes_recv',0))} | 📤 {bytes_to_mb(c.get('bytes_sent',0))}\n"
                f"🕒 {format_tm_time(c.get('connected_since',''))}\n"
                + "-"*15
            )
    text = "<b>Онлайн клиенты:</b>\n\n" + ("\n".join(res) if res else "Нет активных клиентов.")
    await update.message.reply_text(text, parse_mode="HTML", reply_markup=get_main_keyboard())

async def log_request(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    log_text = get_status_log_tail()
    msgs = split_message(f"<b>Последние строки status.log:</b>\n\n<pre>{log_text}</pre>", 4000)
    await query.edit_message_text(msgs[0], parse_mode="HTML", reply_markup=get_main_keyboard())
    for msg in msgs[1:]:
        await context.bot.send_message(chat_id=update.effective_chat.id, text=msg, parse_mode="HTML")

async def send_keys_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        await update.message.reply_text("Доступ запрещён.")
        return
    keys = get_ovpn_files()
    await update.message.reply_text("Выберите номер ключа для отправки:", reply_markup=get_keys_keyboard(keys))

async def send_ovpn_file(update: Update, context: ContextTypes.DEFAULT_TYPE, filename):
    file_path = os.path.join(KEYS_DIR, filename)
    if not os.path.exists(file_path):
        if update.callback_query:
            await update.callback_query.edit_message_text(f"Файл {filename} не найден!", reply_markup=get_main_keyboard())
        else:
            await update.message.reply_text(f"Файл {filename} не найден!", reply_markup=get_main_keyboard())
        return
    with open(file_path, "rb") as f:
        await context.bot.send_document(chat_id=update.effective_chat.id, document=InputFile(f), filename=filename)

async def delete_key_request(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keys = get_ovpn_files()
    if not keys:
        await update.callback_query.edit_message_text("Нет ключей для удаления.", reply_markup=get_main_keyboard())
        return
    await update.callback_query.edit_message_text("Выберите ключ для удаления:", reply_markup=get_delete_keys_keyboard(keys))

async def ask_key_name(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.callback_query.edit_message_text("Введите имя для нового клиента (например, vpnuser1):")
    context.user_data['await_key_name'] = True

async def delete_key_select_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    fname = query.data.split('_', 1)[1]
    await query.edit_message_text(
        f"Удалить ключ <b>{fname}</b>? Это необратимо!",
        parse_mode="HTML",
        reply_markup=get_confirm_delete_keyboard(fname)
    )

async def delete_key_confirm_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    fname = query.data.split('_', 2)[2]
    client_name = fname[:-5] if fname.endswith(".ovpn") else fname
    try:
        kill_openvpn_session(client_name)
        subprocess.run(f"cd {EASYRSA_DIR} && ./easyrsa --batch revoke {client_name}", shell=True, check=True)
        subprocess.run(f"cd {EASYRSA_DIR} && EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl", shell=True, check=True)
        crl_src = f"{EASYRSA_DIR}/pki/crl.pem"
        crl_dst = "/etc/openvpn/crl.pem"
        if os.path.exists(crl_src):
            subprocess.run(f"cp {crl_src} {crl_dst}", shell=True, check=True)
            os.chmod(crl_dst, 0o644)
        paths = [
            os.path.join(KEYS_DIR, fname),
            f"{EASYRSA_DIR}/pki/issued/{client_name}.crt",
            f"{EASYRSA_DIR}/pki/private/{client_name}.key",
            f"{EASYRSA_DIR}/pki/reqs/{client_name}.req",
            os.path.join(CCD_DIR, client_name)
        ]
        for p in paths:
            if os.path.exists(p):
                os.remove(p)
    except Exception as e:
        await query.edit_message_text(f"Ошибка удаления: {e}", reply_markup=get_main_keyboard())
        return
    await query.edit_message_text(f"Ключ <b>{fname}</b> удалён.", parse_mode="HTML", reply_markup=get_main_keyboard())

async def delete_key_cancel_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.callback_query.edit_message_text("Удаление отменено.", reply_markup=get_main_keyboard())

# ================== Button Handler ==================

def format_online_clients(clients, online_names, tunnel_ips):
    res = []
    for c in clients:
        if c['name'] in online_names and not is_client_ccd_disabled(c['name']):
            tunnel_ip = tunnel_ips.get(c['name'], 'нет')
            res.append(
                f"🟢 <b>{c['name']}</b>\n"
                f"🌐 <code>{c.get('ip','нет')}</code>\n"
                f"🛡️ <b>Tunnel:</b> <code>{tunnel_ip}</code>\n"
                f"📥 {bytes_to_mb(c.get('bytes_recv',0))} | 📤 {bytes_to_mb(c.get('bytes_sent',0))}\n"
                f"🕒 {format_tm_time(c.get('connected_since',''))}\n"
                + "-"*15
            )
    return "<b>Онлайн клиенты:</b>\n\n" + ("\n".join(res) if res else "Нет активных клиентов.")

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    if query.from_user.id != ADMIN_ID:
        await query.answer("Доступ запрещён.", show_alert=True)
        return
    await query.answer()
    data = query.data

    if data == 'refresh':
        msg = format_clients_by_certs()
        await query.edit_message_text(msg, parse_mode="HTML", reply_markup=get_main_keyboard())

    elif data == 'renew_key':
        await renew_key_request(update, context)
    elif data.startswith('renew_'):
        await renew_key_select_handler(update, context)

    elif data == 'stats':
        clients, online_names, tunnel_ips = parse_openvpn_status()
        ipp_map = read_ipp_file("/etc/openvpn/ipp.txt")
        message = format_all_keys_with_status_compact(KEYS_DIR, online_names, clients, tunnel_ips, ipp_map)
        msgs = split_message(message)
        await query.edit_message_text(msgs[0], parse_mode="HTML", reply_markup=get_main_keyboard())
        for msg in msgs[1:]:
            await context.bot.send_message(chat_id=update.effective_chat.id, text=msg, parse_mode="HTML")

    elif data == 'online':
        clients, online_names, tunnel_ips = parse_openvpn_status()
        text = format_online_clients(clients, online_names, tunnel_ips)
        msgs = split_message(text)
        await query.edit_message_text(msgs[0], parse_mode="HTML", reply_markup=get_main_keyboard())
        for m in msgs[1:]:
            await context.bot.send_message(chat_id=update.effective_chat.id, text=m, parse_mode="HTML")

    elif data == 'traffic':
        save_traffic_db(force=True)
        report = build_traffic_report()
        await query.edit_message_text(report, parse_mode="HTML", reply_markup=get_main_keyboard())

    elif data == 'update_info':
        await send_update_cmd_via_button(update.effective_chat.id, context.bot)

    elif data == 'keys_expiry':
        await view_keys_expiry_handler(update, context)

    elif data == 'help':
        msgs = split_message(HELP_TEXT)
        await query.edit_message_text(msgs[0], parse_mode="HTML", reply_markup=get_main_keyboard())
        for m in msgs[1:]:
            await context.bot.send_message(chat_id=update.effective_chat.id, text=m, parse_mode="HTML")

    elif data == 'restore_confirm':
        await restore_confirm_handler(update, context)
    elif data == 'restore_cancel':
        await restore_cancel_handler(update, context)

    elif data == 'send_keys':
        keys = get_ovpn_files()
        await query.edit_message_text("Выберите ключ:", reply_markup=get_keys_keyboard(keys))

    elif data.startswith('key_'):
        idx = int(data.split('_')[1]) - 1
        keys = get_ovpn_files()
        if 0 <= idx < len(keys):
            await send_ovpn_file(update, context, keys[idx])

    elif data == 'delete_key':
        await delete_key_request(update, context)

    elif data.startswith('delete_'):
        await delete_key_select_handler(update, context)

    elif data.startswith('confirm_delete_'):
        await delete_key_confirm_handler(update, context)

    elif data == 'cancel_delete':
        await delete_key_cancel_handler(update, context)

    elif data == 'create_key':
        await ask_key_name(update, context)

    elif data == 'backup':
        await send_backup(update, context)

    elif data == 'restore':
        await restore_request(update, context)

    elif data == 'home':
        await query.edit_message_text("Добро пожаловать в VPN бот!", reply_markup=get_main_keyboard())

    elif data == 'enable':
        await enable_request(update, context)
    elif data.startswith('enable_'):
        await enable_client_handler(update, context)

    elif data == 'disable':
        await disable_request(update, context)
    elif data.startswith('disable_'):
        await disable_client_handler(update, context)

    elif data == 'log':
        await log_request(update, context)

    elif data == 'block_alert':
        await query.edit_message_text(
            "Тревога активна в фоне.\n"
            f"Порог: < {MIN_ONLINE_ALERT}, антиспам: {ALERT_INTERVAL_SEC}s.",
            reply_markup=get_main_keyboard()
        )
    else:
        await query.edit_message_text("Команда не реализована.", reply_markup=get_main_keyboard())

# ================== MAIN ==================

def main():
    app = Application.builder().token(TOKEN).build()

    # загрузка трафика
    load_traffic_db()

    # Команды
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("clients", clients_command))
    app.add_handler(CommandHandler("online", online_command))
    app.add_handler(CommandHandler("traffic", traffic_command))
    app.add_handler(CommandHandler("show_update_cmd", show_update_cmd))

    # Сообщения
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, universal_text_handler))
    app.add_handler(MessageHandler(filters.Document.ALL, document_handler))

    # Callback
    app.add_handler(CallbackQueryHandler(button_handler))

    import asyncio
    loop = asyncio.get_event_loop()
    loop.create_task(check_new_connections(app))

    app.run_polling()

if __name__ == '__main__':
    main()