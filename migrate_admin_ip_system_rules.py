#!/usr/bin/env python3
"""
Миграция: добавление колонок admin_ip, is_system_rule, direction
"""
import sqlite3
import shutil
from pathlib import Path
from datetime import datetime

DB_PATH = Path("instance/vpngate.db")

def check_column_exists(conn, table, column):
    """Проверяет существование колонки в таблице"""
    cursor = conn.cursor()
    cursor.execute(f"PRAGMA table_info({table})")
    columns = [row[1] for row in cursor.fetchall()]
    return column in columns

def migrate_database():
    """Добавляет колонки admin_ip, is_system_rule, direction в соответствующие таблицы"""
    
    if not DB_PATH.exists():
        print(f"❌ База данных не найдена: {DB_PATH}")
        return False
    
    # Создаем резервную копию
    backup_path = DB_PATH.with_suffix(f".db.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    shutil.copy2(DB_PATH, backup_path)
    print(f"✅ Резервная копия создана: {backup_path}")
    
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()
    
    try:
        # Добавляем колонку admin_ip в таблицу general
        if not check_column_exists(conn, 'general', 'admin_ip'):
            print("➕ Добавляем колонку admin_ip в таблицу general...")
            cursor.execute("ALTER TABLE general ADD COLUMN admin_ip VARCHAR(50)")
            print("✅ Колонка admin_ip добавлена")
        else:
            print("ℹ️  Колонка admin_ip уже существует")
        
        # Добавляем колонку is_system_rule в таблицу access_policy_rules
        if not check_column_exists(conn, 'access_policy_rules', 'is_system_rule'):
            print("➕ Добавляем колонку is_system_rule в таблицу access_policy_rules...")
            cursor.execute("ALTER TABLE access_policy_rules ADD COLUMN is_system_rule BOOLEAN DEFAULT 0")
            print("✅ Колонка is_system_rule добавлена")
        else:
            print("ℹ️  Колонка is_system_rule уже существует")
        
        # Добавляем колонку direction в таблицу access_policy_rules
        if not check_column_exists(conn, 'access_policy_rules', 'direction'):
            print("➕ Добавляем колонку direction в таблицу access_policy_rules...")
            cursor.execute("ALTER TABLE access_policy_rules ADD COLUMN direction VARCHAR(20) DEFAULT 'FORWARD'")
            print("✅ Колонка direction добавлена")
        else:
            print("ℹ️  Колонка direction уже существует")
        
        conn.commit()
        print("\n✅ Миграция завершена успешно!")
        return True
        
    except sqlite3.Error as e:
        conn.rollback()
        print(f"❌ Ошибка миграции: {e}")
        print(f"⚠️  Восстановите базу данных из резервной копии: {backup_path}")
        return False
    finally:
        conn.close()

if __name__ == "__main__":
    print("🔄 Запуск миграции базы данных...")
    print(f"📁 База данных: {DB_PATH.absolute()}\n")
    
    success = migrate_database()
    
    if success:
        print("\n✅ Миграция выполнена успешно!")
        exit(0)
    else:
        print("\n❌ Миграция завершилась с ошибками!")
        exit(1)

