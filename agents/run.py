# -*- coding: utf-8 -*-
import subprocess
import os
import re
import sqlite3
import signal
import json
import atexit
from pathlib import Path

from app.agent import app
from app import db
from models.local_state import General

# Инициализация базы данных
with app.app_context():
    try:
        db.create_all()
        print("✅ База данных агента инициализирована")
    except Exception as e:
        print(f"❌ Ошибка инициализации базы данных: {e}")
        print(f"   Проверьте права на запись в директорию database/")
        print(f"   Текущая рабочая директория: {os.getcwd()}")
        print(f"   Путь к базе данных: {app.config.get('SQLALCHEMY_DATABASE_URI', 'не задан')}")
        raise

CONF_DIR = "setup"
BOOTSTRAP_PATH = os.path.join(CONF_DIR, "bootstrap_config.json")

def get_conf_name_from_bootstrap():
    try:
        if not os.path.exists(BOOTSTRAP_PATH):
            print(f"⚠️ Файл bootstrap_config.json не найден: {BOOTSTRAP_PATH}")
            print(f"   Текущая рабочая директория: {os.getcwd()}")
            print(f"   CONF_DIR: {CONF_DIR}")
            return None
        with open(BOOTSTRAP_PATH, "r") as f:
            data = json.load(f)
            node_name = data.get('name') or data.get('node_name')
            if not node_name:
                print(f"⚠️ В bootstrap_config.json не найден ключ 'name' или 'node_name'")
                print(f"   Доступные ключи: {list(data.keys())}")
                return None
            return f"{node_name}.conf"
    except json.JSONDecodeError as e:
        print(f"❌ Ошибка парсинга JSON в bootstrap_config.json: {e}")
        return None
    except Exception as e:
        print(f"❌ Ошибка чтения bootstrap_config.json: {e}")
        import traceback
        print(f"   Traceback: {traceback.format_exc()}")
        return None

CONF_NAME = get_conf_name_from_bootstrap()
CONF_PATH = os.path.join(CONF_DIR, CONF_NAME) if CONF_NAME else None

if not CONF_PATH:
    print("⚠️ Не удалось определить путь к конфигурации WireGuard")
    print("   Агент будет запущен без автоматического поднятия WireGuard интерфейса")


def bring_up_wg():
    if not CONF_PATH:
        print("⚠️ Путь к конфигурации WireGuard не определен.")
        return
    
    if not os.path.exists(CONF_PATH):
        print(f"⚠️ Файл конфигурации WireGuard не найден: {CONF_PATH}")
        print(f"   Текущая рабочая директория: {os.getcwd()}")
        return

    try:
        # Сначала проверяем существование интерфейса и останавливаем его если нужно
        # Извлекаем имя интерфейса из имени конфигурации
        interface_name = os.path.splitext(os.path.basename(CONF_PATH))[0] if CONF_PATH else None
        
        if interface_name:
            # Проверяем существование интерфейса
            check_cmd = ["sudo", "wg", "show", interface_name]
            check_result = subprocess.run(check_cmd, capture_output=True, text=True)
            
            if check_result.returncode == 0:
                # Интерфейс существует, сначала останавливаем
                print(f"⚠️ Интерфейс {interface_name} уже существует, останавливаем...")
                try:
                    subprocess.run(["sudo", "wg-quick", "down", CONF_PATH], check=False)
                    import time
                    time.sleep(1)  # Даем время на остановку
                except Exception as down_error:
                    print(f"⚠️ Ошибка при остановке интерфейса: {down_error}")
        
        # Теперь поднимаем интерфейс
        subprocess.run(["sudo", "wg-quick", "up", CONF_PATH], check=True)
        print(f"? Интерфейс WireGuard поднят из {CONF_PATH}")
    except subprocess.CalledProcessError as e:
        print("? Ошибка запуска wg-quick:", e)


def bring_down_wg():
    if not CONF_PATH:
        return
    try:
        subprocess.run(["sudo", "wg-quick", "down", CONF_PATH], check=True)
        print(f"?? Интерфейс WireGuard остановлен: {CONF_NAME}")
    except subprocess.CalledProcessError as e:
        print("? Ошибка остановки wg-quick:", e)


def extract_ip_from_conf():
    if not CONF_PATH:
        return None

    try:
        with open(CONF_PATH, 'r') as f:
            content = f.read()

        match = re.search(r'Address\s*=\s*([\d\.]+)', content)
        if match:
            return match.group(1)
    except Exception as e:
        print(f"? Ошибка извлечения IP из конфигурации: {e}")

    return None


def get_ip_from_db():
    try:
        conn = sqlite3.connect("database/retra.db")
        cursor = conn.cursor()
        cursor.execute("SELECT ip_pool, role FROM general LIMIT 1")
        row = cursor.fetchone()
        conn.close()

        if row and row[1] == 'Magos':
            return row[0].split('/')[0]
    except Exception as e:
        print(f"? Ошибка при чтении из БД: {e}")

    return None


# === Поднятие интерфейса и запуск Flask ===
bring_up_wg()
atexit.register(bring_down_wg)

#wg_ip = extract_ip_from_conf() or get_ip_from_db() or '127.0.0.1'
wg_ip = '0.0.0.0'
port = 5001

# Проверяем не занят ли порт другим процессом
import socket
def is_port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) == 0

if is_port_in_use(port):
    print(f"⚠️ Порт {port} уже занят, пробуем остановить процесс...")
    try:
        # Находим процесс использующий порт
        result = subprocess.run(
            ["lsof", "-ti", f":{port}"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0 and result.stdout.strip():
            pid = result.stdout.strip()
            print(f"⚠️ Найден процесс с PID {pid}, останавливаем...")
            subprocess.run(["kill", "-9", pid], check=False, timeout=5)
            import time
            time.sleep(1)  # Даем время процессу завершиться
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
        print(f"⚠️ Не удалось освободить порт {port}: {e}")
        # Пробуем использовать другой порт
        port = 5002
        print(f"⚠️ Используем альтернативный порт {port}")

print(f"?? Запускаем Flask на IP: {wg_ip}, порт: {port}")

app.run(host=wg_ip, port=port)
