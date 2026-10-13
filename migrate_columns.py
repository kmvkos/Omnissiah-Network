#!/usr/bin/env python3
"""
Миграция базы данных: переименование колонок sent_to_relay и ack_from_relay
в sent_to_magos и ack_from_magos
"""

import sqlite3
import sys
import os
from pathlib import Path

DB_PATH = Path(__file__).parent / "instance" / "vpngate.db"

def check_column_exists(conn, table, column):
    """Проверяет существование колонки в таблице"""
    cursor = conn.execute(f"PRAGMA table_info({table})")
    columns = [row[1] for row in cursor.fetchall()]
    return column in columns

def migrate_database():
    """Выполняет миграцию базы данных"""
    if not DB_PATH.exists():
        print(f"❌ База данных не найдена: {DB_PATH}")
        return False
    
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()
    
    try:
        # Проверяем наличие старых колонок
        has_sent_to_relay = check_column_exists(conn, "general", "sent_to_relay")
        has_ack_from_relay = check_column_exists(conn, "general", "ack_from_relay")
        has_sent_to_magos = check_column_exists(conn, "general", "sent_to_magos")
        has_ack_from_magos = check_column_exists(conn, "general", "ack_from_magos")
        
        print(f"📊 Статус колонок:")
        print(f"   sent_to_relay: {'✅' if has_sent_to_relay else '❌'}")
        print(f"   ack_from_relay: {'✅' if has_ack_from_relay else '❌'}")
        print(f"   sent_to_magos: {'✅' if has_sent_to_magos else '❌'}")
        print(f"   ack_from_magos: {'✅' if has_ack_from_magos else '❌'}")
        print()
        
        # Если старые колонки есть, а новых нет - выполняем миграцию
        if (has_sent_to_relay or has_ack_from_relay) and not (has_sent_to_magos and has_ack_from_magos):
            print("🔄 Начинаем миграцию...")
            
            # SQLite поддерживает RENAME COLUMN с версии 3.25.0
            # Используем более универсальный метод через создание новой таблицы
            
            # Получаем текущую схему
            cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='general'")
            schema = cursor.fetchone()
            if not schema:
                print("❌ Не удалось найти схему таблицы general")
                return False
            
            original_sql = schema[0]
            print(f"📝 Оригинальная схема: {original_sql[:100]}...")
            
            # Создаем резервную копию
            backup_path = DB_PATH.parent / f"vpngate.db.backup_{int(os.path.getmtime(DB_PATH))}"
            import shutil
            shutil.copy2(DB_PATH, backup_path)
            print(f"💾 Создана резервная копия: {backup_path}")
            
            # Переименовываем таблицу
            cursor.execute("ALTER TABLE general RENAME TO general_old")
            print("✅ Таблица general переименована в general_old")
            
            # Создаем новую таблицу с правильными именами колонок
            new_sql = original_sql.replace("sent_to_relay", "sent_to_magos")
            new_sql = new_sql.replace("ack_from_relay", "ack_from_magos")
            new_sql = new_sql.replace("CREATE TABLE general", "CREATE TABLE general")
            
            cursor.execute(new_sql)
            print("✅ Создана новая таблица general с обновленными колонками")
            
            # Копируем данные
            # Определяем все колонки кроме переименованных
            cursor.execute("PRAGMA table_info(general_old)")
            old_columns = [row[1] for row in cursor.fetchall()]
            
            # Формируем список колонок для копирования
            select_cols = []
            insert_cols = []
            
            for col in old_columns:
                if col == "sent_to_relay":
                    select_cols.append("sent_to_relay AS sent_to_magos")
                    insert_cols.append("sent_to_magos")
                elif col == "ack_from_relay":
                    select_cols.append("ack_from_relay AS ack_from_magos")
                    insert_cols.append("ack_from_magos")
                else:
                    select_cols.append(col)
                    insert_cols.append(col)
            
            # Вставляем данные
            select_cols_str = ", ".join(select_cols)
            insert_cols_str = ", ".join(insert_cols)
            
            cursor.execute(f"""
                INSERT INTO general ({insert_cols_str})
                SELECT {select_cols_str}
                FROM general_old
            """)
            print(f"✅ Данные скопированы ({cursor.rowcount} записей)")
            
            # Удаляем старую таблицу
            cursor.execute("DROP TABLE general_old")
            print("✅ Старая таблица удалена")
            
            # Сохраняем изменения
            conn.commit()
            print()
            print("✅ Миграция успешно завершена!")
            return True
            
        elif has_sent_to_magos and has_ack_from_magos:
            print("✅ База данных уже мигрирована (колонки sent_to_magos и ack_from_magos существуют)")
            return True
        else:
            print("⚠️ Не найдено ни старых, ни новых колонок. Возможно, таблица пуста или имеет другую структуру.")
            return False
            
    except Exception as e:
        conn.rollback()
        print(f"❌ Ошибка при миграции: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        conn.close()

if __name__ == "__main__":
    success = migrate_database()
    sys.exit(0 if success else 1)

