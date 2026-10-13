#!/usr/bin/env python3
"""
Скрипт миграции: Добавление колонок nginx в таблицу general
"""
import sqlite3
import shutil
from pathlib import Path
from datetime import datetime

DB_PATH = Path("instance/vpngate.db")

def migrate_nginx_columns():
    """Добавляет колонки для nginx конфигурации в таблицу general"""
    
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
        # Получаем список существующих колонок
        cursor.execute("PRAGMA table_info(general)")
        existing_columns = [row[1] for row in cursor.fetchall()]
        
        # Определяем колонки для добавления
        nginx_columns = {
            'nginx_enabled': 'BOOLEAN DEFAULT 0',
            'nginx_domain': 'VARCHAR(255)',
            'nginx_cert_type': 'VARCHAR(50) DEFAULT "self-signed"',
            'nginx_cert_path': 'VARCHAR(500)',
            'nginx_key_path': 'VARCHAR(500)',
            'nginx_https_port': 'INTEGER DEFAULT 443',
            'nginx_redirect_http': 'BOOLEAN DEFAULT 1'
        }
        
        # Добавляем только те колонки, которых еще нет
        for column_name, column_def in nginx_columns.items():
            if column_name not in existing_columns:
                try:
                    cursor.execute(f"ALTER TABLE general ADD COLUMN {column_name} {column_def}")
                    print(f"✅ Добавлена колонка: {column_name}")
                except sqlite3.OperationalError as e:
                    print(f"⚠️ Ошибка при добавлении колонки {column_name}: {e}")
            else:
                print(f"ℹ️ Колонка {column_name} уже существует")
        
        conn.commit()
        print("\n✅ Миграция завершена успешно!")
        return True
        
    except Exception as e:
        conn.rollback()
        print(f"❌ Ошибка миграции: {e}")
        print(f"💾 Восстановите базу из резервной копии: {backup_path}")
        return False
    finally:
        conn.close()

if __name__ == "__main__":
    print("🚀 Начало миграции: Добавление колонок nginx")
    print("=" * 50)
    success = migrate_nginx_columns()
    print("=" * 50)
    if success:
        print("✅ Миграция выполнена успешно!")
    else:
        print("❌ Миграция не выполнена. Проверьте ошибки выше.")

