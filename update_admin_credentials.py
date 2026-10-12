#!/usr/bin/env python3
"""
Обновление учетных данных администратора в базе данных
Используется для изменения логина и пароля существующего пользователя
"""

import sqlite3
import sys
from pathlib import Path
from werkzeug.security import generate_password_hash

DB_PATH = Path(__file__).parent / "instance" / "vpngate.db"

def update_admin_credentials():
    """Обновляет учетные данные администратора"""
    if not DB_PATH.exists():
        print(f"❌ База данных не найдена: {DB_PATH}")
        return False
    
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()
    
    try:
        # Проверяем наличие старого пользователя
        cursor.execute("SELECT id, email FROM base_users WHERE email = ?", ('nmc-admin@nmcwg.loc',))
        old_user = cursor.fetchone()
        
        cursor.execute("SELECT id, email FROM base_users WHERE email = ?", ('Adeptus',))
        new_user = cursor.fetchone()
        
        if old_user:
            print(f"📝 Найден пользователь: {old_user[1]} (ID: {old_user[0]})")
            # Обновляем email и пароль
            new_password_hash = generate_password_hash('Mechanicus')
            cursor.execute(
                "UPDATE base_users SET email = ?, password_hash = ? WHERE id = ?",
                ('Adeptus', new_password_hash, old_user[0])
            )
            print("✅ Учетные данные обновлены:")
            print(f"   Email: nmc-admin@nmcwg.loc -> Adeptus")
            print(f"   Password: nmcwg -> Mechanicus")
            conn.commit()
            
        elif new_user:
            print("✅ Пользователь Adeptus уже существует")
            # Обновляем только пароль на случай если он был изменен
            new_password_hash = generate_password_hash('Mechanicus')
            cursor.execute(
                "UPDATE base_users SET password_hash = ? WHERE email = ?",
                (new_password_hash, 'Adeptus')
            )
            conn.commit()
            print("✅ Пароль обновлен на значение по умолчанию")
            
        else:
            print("⚠️ Пользователи не найдены. Создайте пользователя через веб-интерфейс при первом запуске.")
            return False
        
        return True
        
    except Exception as e:
        conn.rollback()
        print(f"❌ Ошибка при обновлении: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        conn.close()

if __name__ == "__main__":
    success = update_admin_credentials()
    sys.exit(0 if success else 1)

