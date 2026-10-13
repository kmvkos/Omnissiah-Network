#!/usr/bin/env python3
"""
Скрипт миграции для создания таблицы traffic_logs
"""
import sqlite3
import sys
from pathlib import Path

# Путь к базе данных
db_path = Path(__file__).parent / 'vpngate.db'

if not db_path.exists():
    print(f"❌ База данных не найдена: {db_path}")
    sys.exit(1)

try:
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    
    # Проверяем, существует ли таблица
    cursor.execute("""
        SELECT name FROM sqlite_master 
        WHERE type='table' AND name='traffic_logs'
    """)
    
    if cursor.fetchone():
        print("✅ Таблица traffic_logs уже существует")
    else:
        # Создаем таблицу
        cursor.execute("""
            CREATE TABLE traffic_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL,
                node_id INTEGER NOT NULL,
                source_ip VARCHAR(50),
                destination_ip VARCHAR(50),
                source_port INTEGER,
                destination_port INTEGER,
                protocol VARCHAR(10),
                action VARCHAR(20),
                bytes_sent BIGINT DEFAULT 0,
                bytes_received BIGINT DEFAULT 0,
                packets_sent INTEGER DEFAULT 0,
                packets_received INTEGER DEFAULT 0,
                interface VARCHAR(50),
                direction VARCHAR(10),
                connection_state VARCHAR(20),
                FOREIGN KEY (node_id) REFERENCES general (id)
            )
        """)
        
        # Создаем индексы
        cursor.execute("CREATE INDEX idx_traffic_logs_timestamp ON traffic_logs(timestamp)")
        cursor.execute("CREATE INDEX idx_traffic_logs_node_id ON traffic_logs(node_id)")
        cursor.execute("CREATE INDEX idx_traffic_logs_source_ip ON traffic_logs(source_ip)")
        cursor.execute("CREATE INDEX idx_traffic_logs_destination_ip ON traffic_logs(destination_ip)")
        
        conn.commit()
        print("✅ Таблица traffic_logs успешно создана")
        print("✅ Индексы созданы")
    
    conn.close()
    print("✅ Миграция завершена успешно")
    
except Exception as e:
    print(f"❌ Ошибка миграции: {e}")
    sys.exit(1)






