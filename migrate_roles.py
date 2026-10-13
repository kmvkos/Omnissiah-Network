#!/usr/bin/env python3
"""
Миграция базы данных: обновление ролей в таблице general
NMC WGg -> Omnissiah, NMC WGr -> Magos, NMC WGc -> Cognitor
"""

import sqlite3
import sys
from pathlib import Path

DB_PATH = Path(__file__).parent / "instance" / "vpngate.db"

def migrate_roles():
    """Обновляет роли в базе данных"""
    if not DB_PATH.exists():
        print(f"❌ База данных не найдена: {DB_PATH}")
        return False
    
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()
    
    try:
        # Проверяем текущие роли
        cursor.execute("SELECT DISTINCT role FROM general")
        roles = [row[0] for row in cursor.fetchall()]
        
        print(f"📊 Найденные роли: {roles}")
        
        # Подсчитываем записи для каждой старой роли
        old_roles = {
            'NMC WGg': 'Omnissiah',
            'NMC WGr': 'Magos',
            'NMC WGc': 'Cognitor'
        }
        
        updates_made = 0
        for old_role, new_role in old_roles.items():
            cursor.execute("SELECT COUNT(*) FROM general WHERE role = ?", (old_role,))
            count = cursor.fetchone()[0]
            if count > 0:
                cursor.execute("UPDATE general SET role = ? WHERE role = ?", (new_role, old_role))
                print(f"✅ Обновлено {cursor.rowcount} записей: {old_role} -> {new_role}")
                updates_made += cursor.rowcount
        
        if updates_made > 0:
            conn.commit()
            print(f"\n✅ Всего обновлено {updates_made} записей")
        else:
            print("\n✅ Роли уже актуальны или таблица пуста")
        
        # Показываем финальное состояние
        cursor.execute("SELECT role, COUNT(*) FROM general GROUP BY role")
        final_roles = cursor.fetchall()
        if final_roles:
            print("\n📊 Текущие роли в базе:")
            for role, count in final_roles:
                print(f"   {role}: {count} записей")
        
        return True
        
    except Exception as e:
        conn.rollback()
        print(f"❌ Ошибка при миграции ролей: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        conn.close()

if __name__ == "__main__":
    success = migrate_roles()
    sys.exit(0 if success else 1)

