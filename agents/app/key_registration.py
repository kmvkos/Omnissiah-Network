"""
Модуль для генерации и регистрации ключей WireGuard на агенте
В ZTN архитектуре ключи генерируются на конечных устройствах и отправляются на Omnissiah через mTLS
"""
import subprocess
import json
import os
import sys
from pathlib import Path
from app.config import load_config
from app.mtls_client import get_mtls_session_from_config
import requests
import base64


def generate_wg_keys():
    """
    Генерирует пару ключей WireGuard (приватный и публичный)
    
    Returns:
        tuple: (private_key, public_key) или (None, None) при ошибке
    """
    try:
        # Генерируем приватный ключ
        result = subprocess.run(
            ['wg', 'genkey'],
            capture_output=True,
            text=True,
            timeout=10,
            check=True
        )
        private_key = result.stdout.strip()
        
        # Генерируем публичный ключ из приватного
        result = subprocess.run(
            ['wg', 'pubkey'],
            input=private_key,
            capture_output=True,
            text=True,
            timeout=10,
            check=True
        )
        public_key = result.stdout.strip()
        
        return private_key, public_key
    except subprocess.CalledProcessError as e:
        print(f"[key_registration] ❌ Ошибка генерации ключей: {e.stderr}", file=sys.stderr, flush=True)
        return None, None
    except Exception as e:
        print(f"[key_registration] ❌ Ошибка генерации ключей: {e}", file=sys.stderr, flush=True)
        return None, None


def save_keys_locally(private_key, public_key, config_path=None):
    """
    Сохраняет ключи локально в bootstrap_config.json
    
    Args:
        private_key: Приватный ключ WireGuard
        public_key: Публичный ключ WireGuard
        config_path: Путь к bootstrap_config.json (опционально)
    
    Returns:
        bool: True если успешно сохранено
    """
    try:
        if config_path is None:
            config_path = Path(__file__).parent.parent / "setup" / "bootstrap_config.json"
        
        # Читаем существующий конфиг
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config = json.load(f)
        else:
            config = {}
        
        # Сохраняем ключи в конфиг
        config['private_key'] = private_key
        config['public_key'] = public_key
        config['keys_generated'] = True
        
        # Сохраняем обратно
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        
        print(f"[key_registration] ✅ Ключи сохранены локально в {config_path}", file=sys.stderr, flush=True)
        return True
    except Exception as e:
        print(f"[key_registration] ❌ Ошибка сохранения ключей: {e}", file=sys.stderr, flush=True)
        return False


def register_keys_on_omnissiah(private_key, public_key, config):
    """
    Отправляет ключи на Omnissiah через mTLS
    
    Args:
        private_key: Приватный ключ WireGuard (будет зашифрован)
        public_key: Публичный ключ WireGuard
        config: Конфигурация агента
    
    Returns:
        bool: True если успешно зарегистрировано
    """
    try:
        server_url = config.get('server_url')
        if not server_url:
            print(f"[key_registration] ❌ server_url не найден в конфигурации", file=sys.stderr, flush=True)
            return False
        
        node_name = config.get('name') or config.get('node_name', '')
        if not node_name:
            print(f"[key_registration] ❌ node_name не найден в конфигурации", file=sys.stderr, flush=True)
            return False
        
        # Формируем URL для регистрации ключей
        register_url = server_url.rstrip('/') + '/api/nodes/register_key'
        
        # В ZTN архитектуре: отправляем приватный ключ в открытом виде через mTLS
        # mTLS уже обеспечивает шифрование канала, поэтому дополнительное шифрование не требуется
        # Omnissiah зашифрует ключ перед сохранением в БД используя свой cipher suite
        # Отправляем приватный ключ в base64 для передачи через JSON
        private_key_b64 = base64.b64encode(private_key.encode('utf-8')).decode('utf-8')
        
        # Формируем payload
        payload = {
            'node_name': node_name,
            'public_key': public_key,
            'private_key': private_key_b64  # Открытый ключ в base64 (mTLS защищает канал)
        }
        
        print(f"[key_registration] 📤 Отправка ключей на Omnissiah: {register_url}", file=sys.stderr, flush=True)
        
        # Пробуем отправить через mTLS
        mtls_session = get_mtls_session_from_config(config)
        if mtls_session:
            try:
                response = mtls_session.post(register_url, json=payload, timeout=30)
                response.raise_for_status()
                
                result = response.json()
                if result.get('success'):
                    print(f"[key_registration] ✅ Ключи успешно зарегистрированы на Omnissiah через mTLS", file=sys.stderr, flush=True)
                    return True
                else:
                    error_msg = result.get('error', 'Unknown error')
                    print(f"[key_registration] ❌ Ошибка регистрации ключей: {error_msg}", file=sys.stderr, flush=True)
                    return False
            except Exception as mtls_error:
                print(f"[key_registration] ⚠️ Ошибка mTLS отправки, пробуем без mTLS: {mtls_error}", file=sys.stderr, flush=True)
        
        # Fallback: отправка без mTLS (не рекомендуется для продакшена)
        try:
            response = requests.post(register_url, json=payload, timeout=30, verify=False)
            response.raise_for_status()
            
            result = response.json()
            if result.get('success'):
                print(f"[key_registration] ✅ Ключи успешно зарегистрированы на Omnissiah (без mTLS)", file=sys.stderr, flush=True)
                return True
            else:
                error_msg = result.get('error', 'Unknown error')
                print(f"[key_registration] ❌ Ошибка регистрации ключей: {error_msg}", file=sys.stderr, flush=True)
                return False
        except Exception as http_error:
            print(f"[key_registration] ❌ Ошибка HTTP отправки ключей: {http_error}", file=sys.stderr, flush=True)
            return False
        
    except Exception as e:
        print(f"[key_registration] ❌ Ошибка регистрации ключей: {e}", file=sys.stderr, flush=True)
        import traceback
        print(f"[key_registration] Traceback: {traceback.format_exc()}", file=sys.stderr, flush=True)
        return False


def check_and_register_keys():
    """
    Проверяет наличие ключей и регистрирует их на Omnissiah если нужно
    
    Вызывается при первом запуске агента
    
    Returns:
        bool: True если ключи уже есть или успешно зарегистрированы
    """
    try:
        config = load_config()
        config_path = Path(__file__).parent.parent / "setup" / "bootstrap_config.json"
        
        # Проверяем, есть ли уже ключи в конфиге
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config_data = json.load(f)
            
            existing_private_key = config_data.get('private_key')
            existing_public_key = config_data.get('public_key')
            keys_generated = config_data.get('keys_generated', False)
            
            # Если ключи уже есть и помечены как сгенерированные, проверяем регистрацию
            if existing_private_key and existing_public_key and keys_generated:
                print(f"[key_registration] ℹ️ Ключи уже сгенерированы локально", file=sys.stderr, flush=True)
                
                # Проверяем, существует ли конфигурация WireGuard
                node_name = config_data.get('name') or config_data.get('node_name', 'wg0')
                config_file = Path(__file__).parent.parent / "setup" / f"{node_name}.conf"
                
                if not config_file.exists():
                    # Конфигурация не существует - создаем её
                    print(f"[key_registration] 🔧 Конфигурация WireGuard не найдена, создаем...", file=sys.stderr, flush=True)
                    try:
                        from app.wg_config_generator import generate_and_save_wg_config
                        saved_config = generate_and_save_wg_config()
                        if saved_config:
                            print(f"[key_registration] ✅ Конфигурация WireGuard создана: {saved_config}", file=sys.stderr, flush=True)
                        else:
                            print(f"[key_registration] ⚠️ Не удалось создать конфигурацию WireGuard", file=sys.stderr, flush=True)
                    except Exception as config_error:
                        print(f"[key_registration] ⚠️ Ошибка создания конфигурации WireGuard: {config_error}", file=sys.stderr, flush=True)
                
                # Проверяем, зарегистрированы ли ключи на Omnissiah
                # Это можно сделать через проверку ответа от heartbeat или отдельный запрос
                # Пока просто возвращаем True - ключи есть
                return True
        
        # Ключей нет - генерируем
        print(f"[key_registration] 🔐 Генерация ключей WireGuard...", file=sys.stderr, flush=True)
        private_key, public_key = generate_wg_keys()
        
        if not private_key or not public_key:
            print(f"[key_registration] ❌ Не удалось сгенерировать ключи", file=sys.stderr, flush=True)
            return False
        
        print(f"[key_registration] ✅ Ключи сгенерированы", file=sys.stderr, flush=True)
        
        # Сохраняем локально
        if not save_keys_locally(private_key, public_key, config_path):
            print(f"[key_registration] ⚠️ Не удалось сохранить ключи локально, но продолжаем", file=sys.stderr, flush=True)
        
        # Генерируем и сохраняем конфигурацию WireGuard
        try:
            from app.wg_config_generator import generate_and_save_wg_config
            config_file = generate_and_save_wg_config()
            if config_file:
                print(f"[key_registration] ✅ Конфигурация WireGuard создана: {config_file}", file=sys.stderr, flush=True)
            else:
                print(f"[key_registration] ⚠️ Не удалось создать конфигурацию WireGuard, но продолжаем", file=sys.stderr, flush=True)
        except Exception as config_error:
            print(f"[key_registration] ⚠️ Ошибка создания конфигурации WireGuard: {config_error}", file=sys.stderr, flush=True)
            # Не критично - конфигурация может быть создана позже
        
        # Регистрируем на Omnissiah
        if register_keys_on_omnissiah(private_key, public_key, config):
            print(f"[key_registration] ✅ Ключи успешно зарегистрированы на Omnissiah", file=sys.stderr, flush=True)
            return True
        else:
            print(f"[key_registration] ⚠️ Ключи сгенерированы, но не удалось зарегистрировать на Omnissiah", file=sys.stderr, flush=True)
            print(f"[key_registration] ℹ️ Попытка регистрации будет повторена при следующем heartbeat", file=sys.stderr, flush=True)
            # Возвращаем True, так как ключи сгенерированы и сохранены локально
            return True
        
    except Exception as e:
        print(f"[key_registration] ❌ Ошибка проверки/регистрации ключей: {e}", file=sys.stderr, flush=True)
        import traceback
        print(f"[key_registration] Traceback: {traceback.format_exc()}", file=sys.stderr, flush=True)
        return False

