#!/bin/bash

# Скрипт запуска NMC WG без виртуального окружения
# Использование: ./start.sh

cd "$(dirname "$0")"

# Проверка наличия .env файла
if [ ! -f ".env" ]; then
    echo "Ошибка: Файл .env не найден!"
    echo "Создайте файл .env со следующим содержимым:"
    echo "  WG_MASTER_KEY=<сгенерированный_ключ>"
    echo "  SUDO_PASSWORD=<ваш_пароль_sudo>"
    echo ""
    echo "Для генерации ключа выполните:"
    echo "  python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'"
    exit 1
fi

# Загружаем переменные из .env (убираем кавычки и комментарии)
while IFS='=' read -r key value || [ -n "$key" ]; do
    # Пропускаем комментарии и пустые строки
    [[ "$key" =~ ^#.*$ ]] && continue
    [[ -z "$key" ]] && continue
    
    # Убираем пробелы и кавычки
    key=$(echo "$key" | xargs)
    value=$(echo "$value" | xargs | sed 's/^"\(.*\)"$/\1/' | sed "s/^'\(.*\)'$/\1/")
    
    # Экспортируем переменную
    export "$key=$value"
done < <(grep -v '^#' .env | grep '=')

# Проверка обязательных переменных
if [ -z "$WG_MASTER_KEY" ]; then
    echo "Ошибка: WG_MASTER_KEY не установлен в .env"
    exit 1
fi

if [ -z "$SUDO_PASSWORD" ]; then
    echo "Ошибка: SUDO_PASSWORD не установлен в .env"
    exit 1
fi

# Проверка Python
if ! command -v python3 &> /dev/null; then
    echo "Ошибка: python3 не найден!"
    exit 1
fi

# Проверка основных зависимостей
echo "Проверка зависимостей..."
python3 -c "import flask, flask_sqlalchemy, flask_login, flask_wtf, sqlalchemy, cryptography, qrcode, apscheduler" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "Ошибка: Не все зависимости установлены!"
    echo "Установите зависимости:"
    echo "  pip3 install -r requirements.txt"
    exit 1
fi

echo "Запуск NMC WG..."
echo "Веб-интерфейс будет доступен по адресу: http://$(hostname -I | awk '{print $1}'):33787"
echo ""
echo "Учетные данные по умолчанию:"
echo "  Email: nmc-admin@nmcwg.loc"
echo "  Password: nmcwg"
echo ""
echo "Для остановки нажмите Ctrl+C"
echo ""

# Проверка и освобождение порта 33787
PORT=33787
echo "Проверка порта $PORT..."
if command -v lsof &> /dev/null; then
    PID=$(lsof -ti :$PORT 2>/dev/null)
    if [ ! -z "$PID" ]; then
        echo "⚠️  Порт $PORT занят процессом PID $PID, останавливаем..."
        kill -9 $PID 2>/dev/null
        sleep 1
        # Проверяем что порт освободился
        if lsof -ti :$PORT &>/dev/null; then
            echo "❌ Не удалось освободить порт $PORT"
            exit 1
        else
            echo "✅ Порт $PORT освобожден"
        fi
    else
        echo "✅ Порт $PORT свободен"
    fi
elif command -v fuser &> /dev/null; then
    fuser -k $PORT/tcp 2>/dev/null
    sleep 1
    echo "✅ Проверка порта завершена"
fi

# Перезапуск WireGuard для Omnissiah с синхронизацией пиров
echo "🔄 Проверка и перезапуск WireGuard..."
# Используем динамическое определение интерфейса из БД
python3 -c "
import sys
sys.path.insert(0, 'src')
from app import app, db, General
from app import sync_wireguard_peers, init_db
import subprocess
from sqlalchemy import inspect as sqlalchemy_inspect

with app.app_context():
    try:
        # КРИТИЧНО: Инициализируем БД перед использованием
        try:
            init_db()
        except Exception as init_err:
            print(f'⚠️  Ошибка инициализации БД: {init_err}')
        
        # Проверяем существование таблицы general
        inspector = sqlalchemy_inspect(db.engine)
        tables = inspector.get_table_names()
        
        if 'general' not in tables:
            print('ℹ️  Таблица general не найдена в БД, пропускаем восстановление WireGuard')
            print('ℹ️  Это нормально при первом запуске - БД будет инициализирована при запуске приложения')
            sys.exit(0)
        
        omnissiah = General.query.filter_by(role='Omnissiah').first()
        if not omnissiah:
            print('ℹ️  Omnissiah узел не найден в БД')
            print('ℹ️  Это нормально при первом запуске - создайте Omnissiah через веб-интерфейс')
            sys.exit(0)
        
        interface_name = omnissiah.name
        config_path = f'/etc/wireguard/{interface_name}.conf'
        
        # Проверяем существует ли конфигурационный файл
        import os
        if not os.path.exists(config_path):
            print(f'ℹ️  Конфигурационный файл {config_path} не найден')
            sys.exit(0)
        
        # Проверяем существует ли интерфейс
        result = subprocess.run(['sudo', '-n', 'wg', 'show', interface_name], 
                              capture_output=True, text=True, timeout=5)
        is_active = result.returncode == 0
        
        # КРИТИЧНО: Восстанавливаем конфигурацию из БД перед запуском
        # Это гарантирует что конфигурационный файл содержит всех пиров
        from app import restore_wg_config_from_db
        import tempfile
        import os
        
        print(f'🔄 Восстановление конфигурации WireGuard из БД...')
        restored_config = restore_wg_config_from_db(omnissiah)
        if restored_config:
            # Проверяем что Address присутствует в конфигурации
            import re
            if not re.search(r'\[Interface\][\s\S]*?Address\s*=', restored_config):
                print('❌ ОШИБКА: Address отсутствует в восстановленной конфигурации!')
                print('Первые 200 символов конфигурации:')
                print(restored_config[:200])
            else:
                print('✅ Address присутствует в восстановленной конфигурации')
            
            # Сохраняем восстановленную конфигурацию в файл
            temp_config = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf')
            temp_config.write(restored_config)
            temp_config.close()
            
            try:
                # Копируем восстановленную конфигурацию
                subprocess.run(['sudo', '-n', 'cp', temp_config.name, config_path], 
                             check=True, timeout=10)
                subprocess.run(['sudo', '-n', 'chmod', '600', config_path], 
                             check=True, timeout=5)
                print(f'✅ Конфигурация восстановлена из БД и сохранена в {config_path}')
                
                # Проверяем что файл содержит Address
                check_result = subprocess.run(['sudo', '-n', 'grep', '-q', 'Address', config_path], 
                                             capture_output=True, timeout=5)
                if check_result.returncode == 0:
                    print('✅ Подтверждено: Address присутствует в файле конфигурации')
                else:
                    print('❌ ОШИБКА: Address отсутствует в файле конфигурации после сохранения!')
            except Exception as restore_err:
                print(f'⚠️  Ошибка восстановления конфигурации: {restore_err}')
            finally:
                if os.path.exists(temp_config.name):
                    os.unlink(temp_config.name)
        else:
            print('❌ ОШИБКА: Не удалось восстановить конфигурацию из БД!')
        
        if is_active:
            print(f'🔄 Интерфейс WireGuard {interface_name} активен, перезапускаем для синхронизации пиров...')
            # Останавливаем интерфейс
            subprocess.run(['sudo', '-n', 'wg-quick', 'down', interface_name], 
                         capture_output=True, timeout=10)
            import time
            time.sleep(2)
            # Запускаем интерфейс
            up_result = subprocess.run(['sudo', '-n', 'wg-quick', 'up', interface_name], 
                                     capture_output=True, text=True, timeout=10)
            if up_result.returncode != 0:
                print(f'⚠️  Не удалось запустить WireGuard: {up_result.stderr}')
                sys.exit(1)
            
            time.sleep(1)
            
            # Проверяем что интерфейс запустился
            check_result = subprocess.run(['sudo', '-n', 'wg', 'show', interface_name], 
                                         capture_output=True, text=True, timeout=5)
            if check_result.returncode == 0:
                print(f'✅ WireGuard интерфейс {interface_name} перезапущен')
                
                # Синхронизируем пиры из БД (на случай если что-то изменилось)
                print('🔄 Синхронизация пиров WireGuard...')
                sync_result = sync_wireguard_peers(omnissiah)
                if sync_result:
                    print('✅ Пиры синхронизированы и сохранены')
                else:
                    print('⚠️  Не удалось синхронизировать пиры')
            else:
                print(f'⚠️  Не удалось перезапустить WireGuard интерфейс {interface_name}')
        elif omnissiah.status == 'active':
            # Интерфейс не активен, но в БД статус active - запускаем
            print(f'🔄 Запуск WireGuard интерфейса {interface_name}...')
            up_result = subprocess.run(['sudo', '-n', 'wg-quick', 'up', interface_name], 
                                     capture_output=True, text=True, timeout=10)
            if up_result.returncode == 0:
                print(f'✅ WireGuard интерфейс {interface_name} запущен')
                import time
                time.sleep(1)
                
                # Синхронизируем пиры из БД
                print('🔄 Синхронизация пиров WireGuard...')
                sync_result = sync_wireguard_peers(omnissiah)
                if sync_result:
                    print('✅ Пиры синхронизированы и сохранены')
                else:
                    print('⚠️  Не удалось синхронизировать пиры')
            else:
                print(f'⚠️  Не удалось запустить WireGuard: {up_result.stderr}')
        else:
            print(f'ℹ️  Интерфейс WireGuard {interface_name} не активен (VPN выключен в БД)')
    except Exception as e:
        import traceback
        print(f'⚠️  Ошибка при проверке WireGuard: {e}')
        traceback.print_exc()
" || echo "⚠️  Не удалось выполнить проверку WireGuard"

# Запуск приложения
python3 src/app.py

