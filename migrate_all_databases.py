#!/usr/bin/env python3
"""
Миграция для добавления полей мастера развёртывания WARP во все базы данных
"""
import sqlite3
import sys
from pathlib import Path

def migrate_database(db_path):
    """Мигрирует одну базу данных"""
    if not db_path.exists():
        print(f"⚠️  База данных не найдена: {db_path}")
        return False
    
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    
    try:
        # Проверяем существование колонок
        cursor.execute("PRAGMA table_info(general)")
        columns = [row[1] for row in cursor.fetchall()]
        
        added = []
        
        # Добавляем новые колонки если их нет
        if 'allow_cognitor_to_cognitor' not in columns:
            cursor.execute("ALTER TABLE general ADD COLUMN allow_cognitor_to_cognitor INTEGER DEFAULT 0")
            added.append("allow_cognitor_to_cognitor")
        
        if 'ssh_ip' not in columns:
            cursor.execute("ALTER TABLE general ADD COLUMN ssh_ip VARCHAR(50)")
            added.append("ssh_ip")
        
        if 'ssh_user' not in columns:
            cursor.execute("ALTER TABLE general ADD COLUMN ssh_user VARCHAR(100)")
            added.append("ssh_user")
        
        if 'ssh_password' not in columns:
            cursor.execute("ALTER TABLE general ADD COLUMN ssh_password TEXT")
            added.append("ssh_password")
        
        if 'ssh_key_path' not in columns:
            cursor.execute("ALTER TABLE general ADD COLUMN ssh_key_path VARCHAR(500)")
            added.append("ssh_key_path")
        
        conn.commit()
        
        if added:
            print(f"✓ {db_path}: добавлены колонки {', '.join(added)}")
        else:
            print(f"✓ {db_path}: все колонки уже существуют")
        
        return True
        
    except Exception as e:
        conn.rollback()
        print(f"❌ Ошибка миграции {db_path}: {e}")
        return False
    finally:
        conn.close()

def main():
    base_path = Path(__file__).parent
    databases = [
        base_path / 'instance' / 'vpngate.db',
        base_path / 'src' / 'instance' / 'vpngate.db'
    ]
    
    success_count = 0
    for db_path in databases:
        if migrate_database(db_path):
            success_count += 1
    
    if success_count > 0:
        print(f"\n✅ Миграция завершена для {success_count} баз данных!")
    else:
        print("\n⚠️  Миграция не выполнена")
    
    return success_count > 0

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)

