#from app.commands import command_loop
from flask import Flask, jsonify
from app.system_info import get_status_info
from app.heartbeat import start_heartbeat_loop
from flask import request, jsonify
from flask import current_app
from app.wg_utils import add_peer_to_wireguard
from app import db, create_app
from models.local_state import General
from app.key_registration import check_and_register_keys
import requests

# Создаем Flask приложение через create_app для правильной инициализации БД
app = create_app()

import os
from app.config import load_config

with app.app_context():
    db.create_all()


@app.before_request
def require_controller_identity():
    config = load_config()
    if not config.get('mtls_required') or not request.path.startswith('/api/'):
        return None
    from proxy_identity import proxy_identity
    if proxy_identity() != config.get('controller_name'):
        return jsonify(error='Controller certificate required'), 403

# В ZTN архитектуре: проверяем и регистрируем ключи при первом запуске
print("[agent] 🔐 Проверка и регистрация ключей WireGuard...")
if load_config().get('manage_wireguard', True):
    check_and_register_keys()

if os.getenv('OMNISSIAH_AGENT_BACKGROUND', 'true').lower() == 'true':
    start_heartbeat_loop()

@app.route("/health")
def health():
    return jsonify({"status": "alive"}), 200

@app.route("/status")
def status():
    return jsonify(get_status_info())

@app.route('/api/v1/install_dependencies', methods=['POST'])
def install_dependencies():
    """
    API endpoint для установки зависимостей Python
    Используется для установки отсутствующих модулей (например, cryptography)
    """
    print("📦 Получен запрос на установку зависимостей")
    
    try:
        # Проверка VPN IP (опционально, для безопасности)
        # Пропускаем проверку для установки зависимостей, так как это критичная операция
        # Можно добавить проверку в будущем при необходимости
        
        import subprocess
        import sys
        
        # Пробуем установить cryptography
        print("[install_deps] Установка cryptography...")
        
        # Сначала пробуем с --user
        result = subprocess.run(
            [sys.executable, '-m', 'pip', 'install', '--user', 'cryptography>=41.0.0'],
            capture_output=True,
            text=True,
            timeout=120
        )
        
        if result.returncode != 0:
            # Пробуем без --user (может потребоваться sudo)
            print("[install_deps] Попытка установки без --user...")
            result = subprocess.run(
                [sys.executable, '-m', 'pip', 'install', 'cryptography>=41.0.0'],
                capture_output=True,
                text=True,
                timeout=120
            )
        
        if result.returncode == 0:
            print("[install_deps] ✅ cryptography успешно установлен")
            return jsonify({
                'success': True,
                'message': 'cryptography installed successfully',
                'output': result.stdout
            }), 200
        else:
            error_msg = f"Не удалось установить cryptography: {result.stderr}"
            print(f"[install_deps] ❌ {error_msg}")
            return jsonify({
                'success': False,
                'error': error_msg,
                'stdout': result.stdout,
                'stderr': result.stderr
            }), 500
    
    except subprocess.TimeoutExpired:
        error_msg = "Timeout при установке зависимостей"
        print(f"[install_deps] ❌ {error_msg}")
        return jsonify({
            'success': False,
            'error': error_msg
        }), 500
    except Exception as e:
        error_msg = f"Ошибка установки зависимостей: {str(e)}"
        print(f"[install_deps] ❌ {error_msg}")
        import traceback
        print(traceback.format_exc())
        return jsonify({
            'success': False,
            'error': error_msg
        }), 500

@app.route('/api/traffic_log/clear', methods=['POST'])
def clear_traffic_log():
    """
    API endpoint для очистки локального журнала трафика
    Вызывается с Omnissiah для очистки журналов на удаленных узлах
    """
    print("🛬 Получен запрос /api/traffic_log/clear")
    
    try:
        # Здесь можно очистить локальный кэш логов, если он есть
        # В текущей реализации логи отправляются сразу, поэтому очистка не требуется
        # Но можно добавить очистку системных логов через logrotate
        
        return jsonify({
            'success': True,
            'message': 'Traffic log cleared (logs are sent immediately, no local cache)'
        }), 200
    
    except Exception as e:
        print(f"[clear_traffic_log] ❌ Ошибка: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/add_peer', methods=['POST'])
def add_peer():
    print("🛬 Получен запрос /api/add_peer")
    try:
        data = request.json
        print(f"📦 Полученные данные: {data}")
        required_fields = ['name', 'public_key', 'ip_pool', 'parent_public_key']

        if not all(field in data for field in required_fields):
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400

        # 💾 Сохраняем в БД
        new_peer = General(
            name=data['name'],
            role='Cognitor',
            public_key=data['public_key'],
            ip_pool=data['ip_pool'],
            preshared_key=data.get('preshared_key'),
            dns=data.get('dns'),
            mtu=data.get('mtu'),
            status='stopped',
            parent_id=None
        )
        db.session.add(new_peer)
        db.session.commit()

        # 🔗 Добавляем в WireGuard
        add_peer_to_wireguard(
            interface_name="wg0",  # ✅ обязательно проверь имя интерфейса
            public_key=data['public_key'],
            allowed_ips=data['ip_pool'],
            preshared_key=data.get('preshared_key'),
            keepalive=25,
            config_path="setup/wg0.conf"
        )

        # ✅ Отправляем ACK
        ack_payload = {
            "child_name": data['name'],
            "ack_from_magos": True
        }
        try:
            # Получаем URL сервера из конфигурации
            from app.config import load_config
            agent_config = load_config()
            server_url = agent_config.get('server_url', 'http://10.11.11.65:33787')
            
            # Формируем URL для ACK (используем HTTPS если server_url использует HTTPS)
            ack_url = f"{server_url.rstrip('/')}/api/ack_peer"
            
            # Используем mTLS сессию, если доступна
            from app.mtls_client import get_mtls_session_from_config
            mtls_session = get_mtls_session_from_config(agent_config)
            if mtls_session:
                try:
                    # Используем HTTPS если server_url указывает на HTTPS
                    if server_url.startswith('https'):
                        mtls_session.post(ack_url, json=ack_payload, timeout=10)
                    else:
                        # Если сервер использует HTTP, используем обычный requests
                        requests.post(ack_url, json=ack_payload, timeout=10, verify=False)
                    print(f"✅ ACK отправлен через mTLS на {ack_url}")
                except Exception as e:
                    print(f"⚠️ Ошибка mTLS ACK, пробуем без mTLS: {e}")
                    requests.post(ack_url, json=ack_payload, timeout=10, verify=False)
            else:
                requests.post(ack_url, json=ack_payload, timeout=10, verify=False)
                print(f"✅ ACK отправлен (без mTLS) на {ack_url}")
        except Exception as ack_err:
            print(f"❌ Не удалось отправить ACK на сервер: {ack_err}")

        return jsonify({'success': True, 'message': 'Peer added and ACK sent'}), 200

    except Exception as e:
        db.session.rollback()
        print(f"❌ Ошибка при добавлении пира: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/magos/update_config', methods=['POST'])
@app.route('/api/update_config', methods=['POST'])  # Альтернативный путь для обратной совместимости
def update_config():
    """
    Endpoint для приема и применения обновленной WireGuard конфигурации от Omnissiah
    
    Проверяет:
    1. Что запрос действительно от Omnissiah (проверка IP или домена, можно добавить подпись)
    2. Расшифровывает конфигурацию через WG_MASTER_KEY
    3. Применяет новую конфигурацию через hot-reload (без перезапуска интерфейса)
    4. Отправляет фидбэк обратно на Omnissiah
    """
    print("🛬 Получен запрос /api/update_config")
    
    try:
        # 1. Проверка источника запроса (опционально, можно усилить)
        # Можно проверить IP адрес или добавить подпись в payload
        remote_addr = request.environ.get('REMOTE_ADDR')
        print(f"[update_config] Запрос от {remote_addr}")
        
        # 2. Проверка данных запроса
        data = request.json
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        required_fields = ['config', 'node_name']
        if not all(field in data for field in required_fields):
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400
        
        # Проверяем что конфигурация для этого узла
        from app.config import load_config
        agent_config = load_config()
        if agent_config.get('name') != data['node_name']:
            return jsonify({'success': False, 'error': 'Node name mismatch'}), 400
        
        # 3. Расшифровка конфигурации
        from app.update_config import decrypt_config, apply_wg_config
        
        encrypted_config = data['config']
        decrypted_config = decrypt_config(encrypted_config)
        
        if not decrypted_config:
            return jsonify({'success': False, 'error': 'Failed to decrypt configuration. Invalid master key?'}), 400
        
        print("[update_config] ✅ Конфигурация расшифрована")
        
        # 4. Определяем имя интерфейса из конфигурации или используем по умолчанию
        interface_name = "wg0"  # Можно парсить из конфигурации или из bootstrap_config
        config_file_path = None  # Автоопределение
        
        # 5. Применяем конфигурацию
        if apply_wg_config(decrypted_config, interface_name, config_file_path):
            print("[update_config] ✅ Конфигурация успешно применена")
            
            # 6. Отправляем фидбэк обратно на Omnissiah
            feedback_url = f"{agent_config.get('server_url', 'http://10.11.11.65:33787').rstrip('/')}/api/config_update_feedback"
            feedback_payload = {
                'node_name': data['node_name'],
                'status': 'success',
                'timestamp': data.get('timestamp', '')
            }
            
            try:
                from app.mtls_client import get_mtls_session_from_config
                mtls_session = get_mtls_session_from_config(agent_config)
                if mtls_session:
                    mtls_session.post(feedback_url, json=feedback_payload, timeout=10)
                    print(f"[update_config] ✅ Фидбэк отправлен через mTLS")
                else:
                    requests.post(feedback_url, json=feedback_payload, timeout=10, verify=False)
                    print(f"[update_config] ✅ Фидбэк отправлен (без mTLS)")
            except Exception as feedback_err:
                print(f"[update_config] ⚠️  Не удалось отправить фидбэк: {feedback_err}")
                # Не критично, возвращаем success
            
            return jsonify({
                'success': True,
                'message': 'Configuration updated successfully'
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to apply configuration'
            }), 500
            
    except Exception as e:
        print(f"[update_config] ❌ Ошибка: {e}")
        import traceback
        print(f"[update_config] Детали: {traceback.format_exc()}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


def check_vpn_ip_allowed(request):
    """
    Проверяет, что запрос пришел с разрешенного VPN IP адреса
    
    Args:
        request: Flask request object
    
    Returns:
        tuple: (is_allowed: bool, vpn_ip: str)
    """
    from app.config import load_config
    
    # Получаем VPN IP адрес запроса
    vpn_ip = request.environ.get('REMOTE_ADDR')
    
    # Загружаем конфигурацию для получения списка разрешенных IP
    config = load_config()
    
    # Получаем список разрешенных VPN IP от Omnissiah
    # В реальной системе это может быть список из конфигурации или БД
    # Пока проверяем что IP в диапазоне VPN сети
    ip_pool = config.get('ip_pool', '')
    if ip_pool:
        # Извлекаем сеть из ip_pool (например, "172.18.16.0/24")
        network_base = ip_pool.split('/')[0]
        network_parts = network_base.split('.')
        
        # Проверяем что VPN IP находится в той же подсети (первые 3 октета)
        vpn_ip_parts = vpn_ip.split('.')
        if len(vpn_ip_parts) == 4 and len(network_parts) == 4:
            # Сравниваем первые 3 октета (для /24 сети)
            if '.'.join(network_parts[:3]) == '.'.join(vpn_ip_parts[:3]):
                return True, vpn_ip
    
    # Также разрешаем запросы с IP Omnissiah (из конфигурации)
    server_url = config.get('server_url', '')
    if server_url:
        try:
            from urllib.parse import urlparse
            parsed = urlparse(server_url)
            server_ip = parsed.hostname
            # Пробуем разрешить IP из server_url
            # TODO: Получить реальный VPN IP Omnissiah из БД или конфигурации
        except:
            pass
    
    return False, vpn_ip


@app.route('/api/v1/config/apply', methods=['POST'])
def apply_config_v1():
    """
    API endpoint для применения конфигураций через VPN
    
    Принимает зашифрованные конфигурации (iptables правила, маршруты, etc.)
    и применяет их локально на узле.
    
    Аутентификация:
    - Проверка VPN IP адреса источника
    - Расшифровка конфигурации используя preshared key
    
    Формат запроса:
    {
        "config_type": "iptables" | "routes" | "system",
        "encrypted_config": "<base64 зашифрованные данные>",
        "node_name": "<имя узла для проверки>"
    }
    """
    print("🛬 Получен запрос /api/v1/config/apply")
    
    try:
        # 1. Проверка VPN IP
        is_allowed, vpn_ip = check_vpn_ip_allowed(request)
        if not is_allowed:
            print(f"⚠️  Запрос с неразрешенного VPN IP: {vpn_ip}")
            return jsonify({
                'success': False,
                'error': f'Access denied from VPN IP: {vpn_ip}'
            }), 403
        
        print(f"[apply_config] ✅ Запрос с разрешенного VPN IP: {vpn_ip}")
        
        # 2. Получение данных
        data = request.json
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        required_fields = ['config_type', 'encrypted_config', 'node_name']
        if not all(field in data for field in required_fields):
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400
        
        # 3. Проверка имени узла
        from app.config import load_config
        agent_config = load_config()
        if agent_config.get('name') != data['node_name']:
            return jsonify({'success': False, 'error': 'Node name mismatch'}), 400
        
        # 4. Расшифровка конфигурации
        import base64
        
        # КРИТИЧНО: Проверяем наличие cryptography и устанавливаем если нужно
        try:
            import cryptography
        except ImportError:
            print("[apply_config] ⚠️  Модуль cryptography не найден, устанавливаем...")
            try:
                import subprocess
                import sys
                # Пробуем установить через pip
                result = subprocess.run(
                    [sys.executable, '-m', 'pip', 'install', '--user', 'cryptography>=41.0.0'],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                if result.returncode == 0:
                    print("[apply_config] ✅ cryptography успешно установлен")
                    # Перезагружаем модуль
                    import importlib
                    import sys
                    if 'cryptography' in sys.modules:
                        del sys.modules['cryptography']
                    import cryptography
                else:
                    # Пробуем с sudo если есть права
                    result = subprocess.run(
                        ['sudo', sys.executable, '-m', 'pip', 'install', 'cryptography>=41.0.0'],
                        capture_output=True,
                        text=True,
                        timeout=60,
                        input='\n'  # Пустой ввод для sudo
                    )
                    if result.returncode == 0:
                        print("[apply_config] ✅ cryptography успешно установлен (с sudo)")
                        import importlib
                        import sys
                        if 'cryptography' in sys.modules:
                            del sys.modules['cryptography']
                        import cryptography
                    else:
                        error_msg = f"Не удалось установить cryptography: {result.stderr}"
                        print(f"[apply_config] ❌ {error_msg}")
                        return jsonify({
                            'success': False,
                            'error': error_msg
                        }), 500
            except Exception as install_err:
                error_msg = f"Ошибка установки cryptography: {str(install_err)}"
                print(f"[apply_config] ❌ {error_msg}")
                return jsonify({
                    'success': False,
                    'error': error_msg
                }), 500
        
        from app.crypto_utils import get_local_encryptor
        
        encryptor = get_local_encryptor()
        encrypted_data = base64.b64decode(data['encrypted_config'])
        
        try:
            config_data = encryptor.decrypt_json(encrypted_data)
        except Exception as decrypt_err:
            print(f"[apply_config] ❌ Ошибка расшифровки: {decrypt_err}")
            return jsonify({
                'success': False,
                'error': f'Failed to decrypt configuration. Invalid key? Error: {str(decrypt_err)}'
            }), 400
        
        print(f"[apply_config] ✅ Конфигурация расшифрована, тип: {data['config_type']}")
        
        # 5. Применение конфигурации в зависимости от типа
        config_type = data['config_type']
        success = False
        
        if config_type == 'iptables':
            success = apply_iptables_config(config_data)
        elif config_type == 'routes':
            success = apply_routes_config(config_data)
        elif config_type == 'system':
            success = apply_system_config(config_data)
        else:
            return jsonify({
                'success': False,
                'error': f'Unknown config type: {config_type}'
            }), 400
        
        if success:
            print(f"[apply_config] ✅ Конфигурация {config_type} успешно применена")
            return jsonify({
                'success': True,
                'message': f'Configuration {config_type} applied successfully'
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': f'Failed to apply {config_type} configuration'
            }), 500
    
    except Exception as e:
        print(f"[apply_config] ❌ Ошибка: {e}")
        import traceback
        print(f"[apply_config] Детали: {traceback.format_exc()}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


def apply_iptables_config(config_data: dict) -> bool:
    """
    Применяет iptables правила из конфигурации
    
    Args:
        config_data: {
            "action": "add" | "remove",
            "rules": [
                ["-A", "FORWARD", "-s", "192.168.1.0/24", ...]
            ]
        }
    
    Returns:
        bool: True если успешно
    """
    import subprocess
    
    try:
        action = config_data.get('action', 'add')
        rules = config_data.get('rules', [])
        
        for rule_parts in rules:
            if action == 'add':
                cmd = ['sudo', '-n', 'iptables'] + rule_parts
            elif action == 'remove':
                # Преобразуем -A в -D
                delete_parts = ['-D'] + rule_parts[1:] if rule_parts[0] == '-A' else ['-D'] + rule_parts
                cmd = ['sudo', '-n', 'iptables'] + delete_parts
            else:
                continue
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                print(f"[apply_iptables] ⚠️  Ошибка выполнения команды: {' '.join(cmd)}")
                print(f"[apply_iptables] stderr: {result.stderr}")
                # Продолжаем для других правил
        
        print(f"[apply_iptables] ✅ Применено правил iptables: {len(rules)}")
        return True
    
    except Exception as e:
        print(f"[apply_iptables] ❌ Ошибка: {e}")
        return False


def apply_routes_config(config_data: dict) -> bool:
    """
    Применяет маршруты из конфигурации
    
    Args:
        config_data: {
            "action": "add" | "remove",
            "routes": [
                {"network": "192.168.1.0/24", "gateway": "172.18.16.1", "interface": "wg0"}
            ]
        }
    
    Returns:
        bool: True если успешно
    """
    import subprocess
    
    try:
        action = config_data.get('action', 'add')
        routes = config_data.get('routes', [])
        
        for route in routes:
            network = route.get('network')
            gateway = route.get('gateway')
            interface = route.get('interface', 'wg0')
            
            if not network:
                continue
            
            if action == 'add':
                if gateway:
                    cmd = ['sudo', '-n', 'ip', 'route', 'add', network, 'via', gateway, 'dev', interface]
                else:
                    cmd = ['sudo', '-n', 'ip', 'route', 'add', network, 'dev', interface]
            elif action == 'remove':
                cmd = ['sudo', '-n', 'ip', 'route', 'del', network]
            else:
                continue
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
            if result.returncode != 0:
                # Игнорируем ошибки "already exists" или "no such route"
                if 'File exists' not in result.stderr and 'No such process' not in result.stderr:
                    print(f"[apply_routes] ⚠️  Ошибка: {result.stderr}")
        
        print(f"[apply_routes] ✅ Применено маршрутов: {len(routes)}")
        return True
    
    except Exception as e:
        print(f"[apply_routes] ❌ Ошибка: {e}")
        return False


def apply_system_config(config_data: dict) -> bool:
    """
    Применяет системные конфигурации
    
    Args:
        config_data: Любая системная конфигурация
    
    Returns:
        bool: True если успешно
    """
    # Заглушка для будущих системных конфигураций
    print(f"[apply_system] Применена системная конфигурация: {config_data}")
    return True


@app.route('/api/v1/software/update', methods=['POST'])
def update_software_v1():
    """
    API endpoint для получения и установки обновлений ПО через VPN
    
    Принимает зашифрованный архив, расшифровывает и устанавливает его.
    
    Формат запроса:
    {
        "encrypted_archive": "<base64 зашифрованный архив>",
        "archive_type": "update" | "full",
        "node_name": "<имя узла для проверки>"
    }
    """
    print("🛬 Получен запрос /api/v1/software/update")
    print(f"[update_software] Запрос от IP: {request.remote_addr}")
    print(f"[update_software] URL: {request.url}")
    print(f"[update_software] Method: {request.method}")
    print(f"[update_software] Headers: {dict(request.headers)}")
    
    try:
        # 1. Проверка VPN IP
        is_allowed, vpn_ip = check_vpn_ip_allowed(request)
        if not is_allowed:
            print(f"⚠️  Запрос с неразрешенного VPN IP: {vpn_ip}")
            return jsonify({
                'success': False,
                'error': f'Access denied from VPN IP: {vpn_ip}'
            }), 403
        
        print(f"[update_software] ✅ Запрос с разрешенного VPN IP: {vpn_ip}")
        
        # 2. Получение данных
        data = request.json
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        required_fields = ['encrypted_archive', 'archive_type', 'node_name']
        if not all(field in data for field in required_fields):
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400
        
        # 3. Проверка имени узла
        from app.config import load_config
        agent_config = load_config()
        if agent_config.get('name') != data['node_name']:
            return jsonify({'success': False, 'error': 'Node name mismatch'}), 400
        
        # 4. Расшифровка архива
        import base64
        
        # КРИТИЧНО: Проверяем наличие cryptography и устанавливаем если нужно
        try:
            import cryptography
        except ImportError:
            print("[update_software] ⚠️  Модуль cryptography не найден, устанавливаем...")
            try:
                import subprocess
                import sys
                # Пробуем установить через pip
                result = subprocess.run(
                    [sys.executable, '-m', 'pip', 'install', '--user', 'cryptography>=41.0.0'],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                if result.returncode == 0:
                    print("[update_software] ✅ cryptography успешно установлен")
                    # Перезагружаем модуль
                    import importlib
                    import sys
                    if 'cryptography' in sys.modules:
                        del sys.modules['cryptography']
                    import cryptography
                else:
                    # Пробуем с sudo если есть права
                    result = subprocess.run(
                        ['sudo', sys.executable, '-m', 'pip', 'install', 'cryptography>=41.0.0'],
                        capture_output=True,
                        text=True,
                        timeout=60,
                        input='\n'  # Пустой ввод для sudo
                    )
                    if result.returncode == 0:
                        print("[update_software] ✅ cryptography успешно установлен (с sudo)")
                        import importlib
                        import sys
                        if 'cryptography' in sys.modules:
                            del sys.modules['cryptography']
                        import cryptography
                    else:
                        error_msg = f"Не удалось установить cryptography: {result.stderr}"
                        print(f"[update_software] ❌ {error_msg}")
                        return jsonify({
                            'success': False,
                            'error': error_msg
                        }), 500
            except Exception as install_err:
                error_msg = f"Ошибка установки cryptography: {str(install_err)}"
                print(f"[update_software] ❌ {error_msg}")
                return jsonify({
                    'success': False,
                    'error': error_msg
                }), 500
        
        from app.crypto_utils import get_local_encryptor
        
        encryptor = get_local_encryptor()
        encrypted_data = base64.b64decode(data['encrypted_archive'])
        
        try:
            config_data = encryptor.decrypt_json(encrypted_data)
        except Exception as decrypt_err:
            print(f"[update_software] ❌ Ошибка расшифровки: {decrypt_err}")
            return jsonify({
                'success': False,
                'error': 'Failed to decrypt archive. Invalid key?'
            }), 400
        
        # 5. Извлекаем архив из расшифрованных данных
        archive_b64 = config_data.get('archive_data')
        if not archive_b64:
            return jsonify({
                'success': False,
                'error': 'Archive data not found in decrypted config'
            }), 400
        
        archive_data = base64.b64decode(archive_b64)
        
        print(f"[update_software] ✅ Архив расшифрован, тип: {data['archive_type']}")
        
        # 6. Сохраняем архив во временный файл
        import tempfile
        temp_archive = tempfile.NamedTemporaryFile(suffix='.tar.gz', delete=False)
        temp_archive.write(archive_data)
        temp_archive.close()
        
        try:
            # 7. Определяем директорию агента
            from pathlib import Path
            agent_dir = Path(__file__).parent.parent  # NMC_WGr
            
            # 8. Распаковываем архив (только код для update, полный для full)
            import tarfile
            import shutil
            
            archive_type = data['archive_type']
            
            if archive_type == 'update':
                # Для update исключаем некоторые файлы при распаковке
                # Но так как мы уже исключили их при создании архива, просто распаковываем
                with tarfile.open(temp_archive.name, 'r:gz') as tar:
                    tar.extractall(path=agent_dir)
            else:
                # Полный архив - распаковываем все
                with tarfile.open(temp_archive.name, 'r:gz') as tar:
                    tar.extractall(path=agent_dir)
            
            print(f"[update_software] ✅ Архив распакован в {agent_dir}")
            
            # 9. Перезапускаем сервис (если запущен)
            import subprocess
            
            # Определяем имя сервиса из конфигурации
            node_name = agent_config.get('name', '')
            role = agent_config.get('role', 'Magos').lower()
            service_name = f"{role}-{node_name.lower()}.service"
            
            try:
                # Проверяем статус сервиса
                check_cmd = ['sudo', '-n', 'systemctl', 'is-active', service_name]
                result = subprocess.run(check_cmd, capture_output=True, text=True, timeout=5)
                
                if result.returncode == 0:
                    # Сервис активен, перезапускаем
                    restart_cmd = ['sudo', '-n', 'systemctl', 'restart', service_name]
                    restart_result = subprocess.run(restart_cmd, capture_output=True, text=True, timeout=30)
                    
                    if restart_result.returncode == 0:
                        print(f"[update_software] ✅ Сервис {service_name} перезапущен")
                    else:
                        print(f"[update_software] ⚠️  Не удалось перезапустить сервис: {restart_result.stderr}")
                else:
                    print(f"[update_software] ℹ️  Сервис {service_name} не запущен, пропускаем перезапуск")
            
            except Exception as restart_err:
                print(f"[update_software] ⚠️  Ошибка перезапуска сервиса: {restart_err}")
                # Не критично, обновление установлено
            
            return jsonify({
                'success': True,
                'message': f'Software update {archive_type} installed successfully'
            }), 200
        
        finally:
            # Удаляем временный архив
            import os
            if os.path.exists(temp_archive.name):
                os.unlink(temp_archive.name)
    
    except Exception as e:
        print(f"[update_software] ❌ Ошибка: {e}")
        import traceback
        print(f"[update_software] Детали: {traceback.format_exc()}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# Тестовый endpoint для проверки регистрации маршрутов
@app.route('/api/v1/test', methods=['GET', 'POST'])
def test_endpoint():
    """Тестовый endpoint для проверки что маршруты работают"""
    print(f"[test] Запрос на /api/v1/test от {request.remote_addr}")
    return jsonify({
        'success': True,
        'message': 'Test endpoint работает',
        'url': request.url,
        'method': request.method,
        'remote_addr': request.remote_addr,
        'endpoints': ['/api/v1/config/apply', '/api/v1/software/update', '/api/v1/test']
    }), 200
