#!/usr/bin/env python3
"""
Миграция для добавления полей мастера развёртывания WARP
"""
import sqlite3
import sys
from pathlib import Path

def migrate():
    db_path = Path(__file__).parent / 'instance' / 'vpngate.db'
    
    if not db_path.exists():
        print(f"База данных не найдена: {db_path}")
        return False
    
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    
    try:
        # Проверяем существование колонок
        cursor.execute("PRAGMA table_info(general)")
        columns = [row[1] for row in cursor.fetchall()]
        
        # Добавляем новые колонки если их нет
        if 'allow_cognitor_to_cognitor' not in columns:
            cursor.execute("ALTER TABLE general ADD COLUMN allow_cognitor_to_cognitor INTEGER DEFAULT 0")
            print("✓ Добавлена колонка allow_cognitor_to_cognitor")
        
        if 'ssh_ip' not in columns:
            cursor.execute("ALTER TABLE general ADD COLUMN ssh_ip VARCHAR(50)")
            print("✓ Добавлена колонка ssh_ip")
        
        if 'ssh_user' not in columns:
            cursor.execute("ALTER TABLE general ADD COLUMN ssh_user VARCHAR(100)")
            print("✓ Добавлена колонка ssh_user")
        
        if 'ssh_password' not in columns:
            cursor.execute("ALTER TABLE general ADD COLUMN ssh_password TEXT")
            print("✓ Добавлена колонка ssh_password")
        
        if 'ssh_key_path' not in columns:
            cursor.execute("ALTER TABLE general ADD COLUMN ssh_key_path VARCHAR(500)")
            print("✓ Добавлена колонка ssh_key_path")
        
        conn.commit()
        print("\n✅ Миграция успешно завершена!")
        return True
        
    except Exception as e:
        conn.rollback()
        print(f"\n❌ Ошибка миграции: {e}")
        return False
    finally:
        conn.close()

if __name__ == '__main__':
    success = migrate()
    sys.exit(0 if success else 1)

