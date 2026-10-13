#!/usr/bin/env python3
"""
Скрипт миграции для добавления колонок priority и group_id в таблицу access_policy_rules
и создания таблицы policy_groups
"""
import sqlite3
import sys
from pathlib import Path

# Путь к базе данных
db_path = Path(__file__).parent / 'instance' / 'vpngate.db'
if not db_path.exists():
    db_path = Path(__file__).parent / 'vpngate.db'

if not db_path.exists():
    print(f"❌ База данных не найдена: {db_path}")
    sys.exit(1)

print(f"📦 Подключение к БД: {db_path}")

conn = sqlite3.connect(str(db_path))
cursor = conn.cursor()

try:
    # Проверяем существование колонки priority
    cursor.execute("PRAGMA table_info(access_policy_rules)")
    columns = [col[1] for col in cursor.fetchall()]
    
    if 'priority' not in columns:
        print("➕ Добавляем колонку priority в access_policy_rules...")
        cursor.execute("ALTER TABLE access_policy_rules ADD COLUMN priority INTEGER DEFAULT 100")
        print("✅ Колонка priority добавлена")
    else:
        print("✅ Колонка priority уже существует")
    
    if 'group_id' not in columns:
        print("➕ Добавляем колонку group_id в access_policy_rules...")
        cursor.execute("ALTER TABLE access_policy_rules ADD COLUMN group_id INTEGER")
        print("✅ Колонка group_id добавлена")
    else:
        print("✅ Колонка group_id уже существует")
    
    # Проверяем существование таблицы policy_groups
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='policy_groups'")
    if cursor.fetchone() is None:
        print("➕ Создаем таблицу policy_groups...")
        cursor.execute("""
            CREATE TABLE policy_groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name VARCHAR(100) NOT NULL UNIQUE,
                description VARCHAR(500),
                is_active BOOLEAN DEFAULT 1,
                priority INTEGER DEFAULT 100,
                created_at DATETIME,
                created_by INTEGER,
                FOREIGN KEY(created_by) REFERENCES base_users(id)
            )
        """)
        print("✅ Таблица policy_groups создана")
    else:
        print("✅ Таблица policy_groups уже существует")
    
    conn.commit()
    print("\n✅ Миграция завершена успешно!")
    
except sqlite3.Error as e:
    conn.rollback()
    print(f"❌ Ошибка миграции: {e}")
    sys.exit(1)
finally:
    conn.close()

