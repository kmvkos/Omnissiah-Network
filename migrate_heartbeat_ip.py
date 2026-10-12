#!/usr/bin/env python3
"""
Миграция: добавление поля heartbeat_ip в таблицу general
"""
import sqlite3
import sys
from pathlib import Path

db_path = Path('instance/vpngate.db')

if not db_path.exists():
    print(f"❌ База данных не найдена: {db_path}")
    sys.exit(1)

try:
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    
    # Проверяем, существует ли колонка
    cursor.execute("PRAGMA table_info(general)")
    columns = [col[1] for col in cursor.fetchall()]
    
    if 'heartbeat_ip' in columns:
        print("✅ Колонка heartbeat_ip уже существует")
    else:
        print("📝 Добавляем колонку heartbeat_ip...")
        cursor.execute("ALTER TABLE general ADD COLUMN heartbeat_ip VARCHAR(50)")
        conn.commit()
        print("✅ Колонка heartbeat_ip успешно добавлена")
    
    conn.close()
    print("✅ Миграция завершена успешно!")
    
except Exception as e:
    print(f"❌ Ошибка миграции: {e}")
    sys.exit(1)

