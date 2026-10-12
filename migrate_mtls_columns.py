#!/usr/bin/env python3
"""
Миграция: добавление колонок для mTLS в таблицу general
"""
import sqlite3
from pathlib import Path
import shutil
from datetime import datetime

# Путь к базе данных
db_path = Path("instance/vpngate.db")
backup_path = Path(f"instance/vpngate.db.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}")

def migrate():
    """Добавляет колонки для mTLS в таблицу general"""
    
    if not db_path.exists():
        print(f"❌ База данных не найдена: {db_path}")
        return False
    
    # Создаем резервную копию
    print(f"📦 Создание резервной копии БД: {backup_path}")
    shutil.copy2(db_path, backup_path)
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Проверяем существующие колонки
        cursor.execute("PRAGMA table_info(general)")
        columns = [col[1] for col in cursor.fetchall()]
        
        # Колонки для добавления
        new_columns = [
            ('mtls_enabled', 'BOOLEAN', '0'),  # default False
            ('mtls_ca_cert_path', 'VARCHAR(500)', 'NULL'),
            ('mtls_ca_key_path', 'VARCHAR(500)', 'NULL'),
            ('mtls_server_cert_path', 'VARCHAR(500)', 'NULL'),
            ('mtls_server_key_path', 'VARCHAR(500)', 'NULL'),
        ]
        
        added = []
        for col_name, col_type, default in new_columns:
            if col_name not in columns:
                if default == 'NULL':
                    sql = f"ALTER TABLE general ADD COLUMN {col_name} {col_type}"
                else:
                    sql = f"ALTER TABLE general ADD COLUMN {col_name} {col_type} DEFAULT {default}"
                
                print(f"➕ Добавляем колонку: {col_name}")
                cursor.execute(sql)
                added.append(col_name)
            else:
                print(f"⏭️  Колонка {col_name} уже существует, пропускаем")
        
        conn.commit()
        
        if added:
            print(f"✅ Успешно добавлено колонок: {len(added)}")
            print(f"   Колонки: {', '.join(added)}")
        else:
            print("ℹ️  Все колонки уже существуют")
        
        return True
        
    except sqlite3.Error as e:
        conn.rollback()
        print(f"❌ Ошибка миграции: {e}")
        print(f"📦 Восстановление из резервной копии...")
        shutil.copy2(backup_path, db_path)
        return False
    finally:
        conn.close()

if __name__ == "__main__":
    print("🔄 Миграция базы данных: добавление колонок для mTLS")
    print("=" * 60)
    
    if migrate():
        print("\n✅ Миграция завершена успешно!")
    else:
        print("\n❌ Миграция завершилась с ошибкой")

