import requests
import socket
import threading
import time
import subprocess
import re
import json
from app.mtls_client import get_mtls_session_from_config
from app.config import load_config

def get_interfaces_with_ips():
    """
    Получает список интерфейсов с их IP адресами локально
    
    Returns:
        list: [{'name': 'eth0', 'ip': '192.168.1.10'}, ...]
    """
    interfaces = []
    try:
        result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True, timeout=5)
        
        current_iface = None
        for line in result.stdout.split('\n'):
            # Находим интерфейс: "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>"
            if_match = re.match(r'\d+: (\w+):', line)
            if if_match:
                current_iface = if_match.group(1)
            
            # Находим IP адрес: "    inet 192.168.1.10/24"
            ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', line)
            if ip_match and current_iface and current_iface != 'lo':
                ip = ip_match.group(1)
                interfaces.append({'name': current_iface, 'ip': ip})
        
        # Добавляем WireGuard интерфейс если есть
        from app.config import load_config
        agent_config = load_config()
        # КРИТИЧНО: bootstrap_config использует 'node_name', а не 'name'
        node_name = agent_config.get('name') or agent_config.get('node_name')
        if node_name:
            # Получаем IP из ip_pool
            ip_pool = agent_config.get('ip_pool', '')
            if ip_pool:
                vpn_ip = ip_pool.split('/')[0]
                # Добавляем VPN интерфейс первым
                if not any(i['name'] == node_name for i in interfaces):
                    interfaces.insert(0, {'name': node_name, 'ip': vpn_ip})
        
        return interfaces
    except Exception as e:
        print(f"[heartbeat] Ошибка получения интерфейсов: {e}")
        return []

def check_wireguard_status(node_name):
    """
    Проверяет статус WireGuard интерфейса
    
    Returns:
        bool: True если интерфейс активен, False если нет
    """
    try:
        result = subprocess.run(
            ['sudo', '-n', 'wg', 'show', node_name],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.returncode == 0
    except Exception as e:
        print(f"[heartbeat] Ошибка проверки WireGuard статуса: {e}")
        return False

def send_heartbeat(config):
    import sys
    # КРИТИЧНО: Используем sys.stderr для вывода в systemd журнал
    def log(msg):
        print(msg, file=sys.stderr, flush=True)
    
    # КРИТИЧНО: Проверяем наличие server_url
    server_url = config.get('server_url')
    if not server_url:
        log(f"[heartbeat] ❌ server_url не найден в конфигурации. Доступные ключи: {list(config.keys())}")
        return False
    
    url = server_url.rstrip('/') + '/api/magos/heartbeat'
    log(f"[heartbeat] 🔄 Отправка heartbeat на {url}")

    # Получаем интерфейсы с IP адресами
    interfaces = get_interfaces_with_ips()
    
    # КРИТИЧНО: bootstrap_config использует 'node_name', а не 'name'
    node_name = config.get('name') or config.get('node_name', '')
    if not node_name:
        log(f"[heartbeat] ❌ node_name не найден в конфигурации. Доступные ключи: {list(config.keys())}")
        return False
    
    wireguard_enabled = check_wireguard_status(node_name) if node_name else False

    data = {
        'public_key': config.get('public_key', ''),
        'name': node_name,  # Используем node_name из конфигурации
        'local_ip': get_local_ip(),
        'status': 'active',
        'clients': [],  # позже заполним, пока пусть будет пусто
        'interfaces': interfaces,  # Список интерфейсов с IP адресами
        'wireguard_enabled': wireguard_enabled  # Статус WireGuard интерфейса
    }
    
    log(f"[heartbeat] 📤 Данные: name={node_name}, local_ip={data.get('local_ip')}, wireguard_enabled={wireguard_enabled}")

    headers = {
        'Authorization': f"Bearer {config.get('api_token', '')}"
    }

    # Используем mTLS сессию, если доступна
    mtls_enabled = config.get('mtls_enabled', False)
    mtls_cert_file = config.get('mtls_cert_file', '')
    mtls_key_file = config.get('mtls_key_file', '')
    
    log(f"[heartbeat] 🔍 Проверка mTLS: enabled={mtls_enabled}, cert={mtls_cert_file}, key={mtls_key_file}")
    
    if mtls_enabled and mtls_cert_file and mtls_key_file:
        mtls_session = get_mtls_session_from_config(config)
        if mtls_session:
            try:
                log(f"[heartbeat] 🔐 Попытка отправки через mTLS...")
                response = mtls_session.post(url, json=data, headers=headers, timeout=10)
                response.raise_for_status()
                log(f"[heartbeat] ✅ Успешно отправлен через mTLS: {response.status_code}")
                log(f"[heartbeat] 📥 Ответ сервера: {response.text[:200]}")
                return True
            except requests.exceptions.Timeout as e:
                log(f"[heartbeat] ⏱️  Таймаут mTLS запроса: {e}")
            except requests.exceptions.ConnectionError as e:
                log(f"[heartbeat] 🔌 Ошибка подключения mTLS: {e}")
            except requests.exceptions.HTTPError as e:
                log(f"[heartbeat] ❌ HTTP ошибка mTLS: {e} - {response.status_code if 'response' in locals() else 'N/A'}")
                if 'response' in locals():
                    log(f"[heartbeat] 📥 Тело ответа mTLS: {response.text[:500]}")
            except Exception as e:
                log(f"[heartbeat] ⚠️  Ошибка mTLS запроса, пробуем без mTLS: {type(e).__name__}: {e}")
                import traceback
                log(f"[heartbeat] 📋 Traceback mTLS: {traceback.format_exc()}")
        else:
            log(f"[heartbeat] ⚠️  mTLS включен, но сессия не создана. Проверьте наличие сертификатов.")
    else:
        log(f"[heartbeat] ℹ️  mTLS не включен или сертификаты не указаны в конфигурации")
    
    # Fallback: обычный HTTP запрос (если mTLS не настроен или не работает)
    try:
        log(f"[heartbeat] 🌐 Попытка отправки без mTLS (verify=False)...")
        response = requests.post(url, json=data, headers=headers, timeout=10, verify=False)
        response.raise_for_status()
        log(f"[heartbeat] ✅ Успешно отправлен (без mTLS): {response.status_code}")
        log(f"[heartbeat] 📥 Ответ сервера: {response.text[:200]}")
        return True
    except requests.exceptions.Timeout as e:
        log(f"[heartbeat] ❌ Таймаут запроса: {e}")
        return False
    except requests.exceptions.ConnectionError as e:
        log(f"[heartbeat] ❌ Ошибка подключения: {e}")
        return False
    except requests.exceptions.HTTPError as e:
        log(f"[heartbeat] ❌ HTTP ошибка: {e} - {response.status_code if 'response' in locals() else 'N/A'}")
        if 'response' in locals():
            log(f"[heartbeat] 📥 Тело ответа: {response.text[:500]}")
        return False
    except Exception as e:
        log(f"[heartbeat] ❌ Ошибка отправки heartbeat: {type(e).__name__}: {e}")
        import traceback
        log(f"[heartbeat] 📋 Traceback: {traceback.format_exc()}")
        return False


def send_traffic_logs(config):
    """
    Собирает и отправляет логи трафика на Omnissiah
    """
    try:
        from app.traffic_collector import collect_traffic_logs
        
        # Собираем логи
        logs = collect_traffic_logs()
        
        if not logs:
            return True  # Нет логов - это нормально
        
        # Отправляем на сервер
        url = config['server_url'].rstrip('/') + '/api/report_traffic'
        
        data = {
            'node_name': config.get('name', ''),
            'logs': logs
        }
        
        headers = {
            'Authorization': f"Bearer {config.get('api_token', '')}"
        }
        
        # Используем mTLS сессию, если доступна
        mtls_session = get_mtls_session_from_config(config)
        if mtls_session:
            try:
                response = mtls_session.post(url, json=data, headers=headers, timeout=10)
                response.raise_for_status()
                print(f"[traffic] ✅ Отправлено {len(logs)} записей трафика через mTLS")
                return True
            except Exception as e:
                print(f"[traffic] ⚠️  Ошибка mTLS отправки трафика, пробуем без mTLS: {e}")
        
        # Fallback: обычный HTTP запрос
        try:
            response = requests.post(url, json=data, headers=headers, timeout=10, verify=False)
            response.raise_for_status()
            print(f"[traffic] ✅ Отправлено {len(logs)} записей трафика (без mTLS)")
            return True
        except Exception as e:
            print(f"[traffic] ❌ Ошибка отправки логов трафика: {e}")
            return False
    
    except ImportError as e:
        print(f"[traffic] ⚠️  Модуль traffic_collector не найден: {e}")
        return False
    except Exception as e:
        print(f"[traffic] ❌ Ошибка сбора/отправки логов трафика: {e}")
        return False

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def heartbeat_loop():
    """Основной цикл отправки heartbeat"""
    traffic_log_counter = 0  # Счетчик для отправки трафика каждые 5 минут
    key_registration_attempts = 0  # Счетчик попыток регистрации ключей
    
    while True:
        try:
            config = load_config()
            
            # В ZTN архитектуре: проверяем и регистрируем ключи если нужно
            # Пробуем регистрировать ключи первые 10 циклов (5 минут) или пока не зарегистрированы
            if key_registration_attempts < 10:
                from app.key_registration import check_and_register_keys
                if check_and_register_keys():
                    key_registration_attempts = 999  # Помечаем как успешно зарегистрировано
                else:
                    key_registration_attempts += 1
            
            send_heartbeat(config)
            
            # Отправляем логи трафика каждые 5 минут (10 циклов по 30 секунд)
            traffic_log_counter += 1
            if traffic_log_counter >= 10:
                send_traffic_logs(config)
                traffic_log_counter = 0
            
        except Exception as e:
            print(f"[heartbeat] Ошибка в цикле heartbeat: {e}")
        
        # Отправляем heartbeat каждые 30 секунд
        time.sleep(30)

def start_heartbeat_loop():
    """Запускает фоновый поток для отправки heartbeat"""
    heartbeat_thread = threading.Thread(target=heartbeat_loop, daemon=True)
    heartbeat_thread.start()
    print("[heartbeat] ✅ Цикл heartbeat запущен (интервал 30 секунд)")
