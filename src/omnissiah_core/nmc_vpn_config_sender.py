"""
Модуль для отправки конфигураций на удаленные узлы через VPN
Заменяет SSH для передачи конфигураций
"""
import requests
import base64
import json
import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Добавляем путь к корню проекта для импорта
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

logger = logging.getLogger(__name__)


def check_vpn_connectivity(vpn_ip: str, timeout: int = 5) -> Tuple[bool, Optional[str]]:
    """
    Проверяет доступность VPN IP адреса через ping
    
    Args:
        vpn_ip: VPN IP адрес для проверки
        timeout: Timeout для ping (секунды)
    
    Returns:
        tuple: (is_reachable: bool, error_message: str | None)
    """
    import subprocess
    
    try:
        # Используем ping для проверки доступности
        result = subprocess.run(
            ['ping', '-c', '1', '-W', str(timeout), vpn_ip],
            capture_output=True,
            text=True,
            timeout=timeout + 2
        )
        
        if result.returncode == 0:
            return True, None
        else:
            return False, f"VPN IP {vpn_ip} недоступен (ping failed)"
    
    except subprocess.TimeoutExpired:
        return False, f"Timeout при проверке VPN IP {vpn_ip}"
    except FileNotFoundError:
        # ping не найден, пробуем другой способ
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            # Используем порт 5001 по умолчанию (для проверки connectivity)
            agent_port = 5001
            result = sock.connect_ex((vpn_ip, agent_port))
            sock.close()
            
            if result == 0:
                return True, None
            else:
                return False, f"Не удалось подключиться к VPN IP {vpn_ip}:{agent_port}"
        except Exception as e:
            return False, f"Ошибка проверки VPN connectivity: {str(e)}"
    except Exception as e:
        return False, f"Ошибка проверки VPN connectivity: {str(e)}"


def send_config_via_vpn(node, config_type: str, config_data: dict, app=None, 
                        check_connectivity: bool = True) -> Tuple[bool, Optional[str]]:
    """
    Отправляет конфигурацию на узел через VPN канал с шифрованием
    
    Args:
        node: Объект General (узел Magos/Cognitor)
        config_type: Тип конфигурации ("iptables", "routes", "system")
        config_data: Словарь с данными конфигурации
        app: Flask приложение (для доступа к crypto_utils)
        check_connectivity: Проверять ли доступность VPN перед отправкой (по умолчанию True)
    
    Returns:
        tuple: (success: bool, error_message: str | None)
    """
    try:
        # Импортируем модуль шифрования
        from omnissiah_utils.nmc_crypto_utils import encrypt_config_for_node
        
        # 1. Проверяем что узел активен и имеет VPN IP
        if not node.ip_pool:
            return False, "Узел не имеет VPN IP адреса"
        
        vpn_ip = node.ip_pool.split('/')[0]
        if not vpn_ip:
            return False, "Не удалось определить VPN IP узла"
        
        # 2. Проверяем что WireGuard интерфейс активен (для локального узла)
        if node.role == 'Omnissiah':
            # Для Omnissiah применяем локально
            return apply_config_locally(config_type, config_data)
        
        # 3. КРИТИЧНО: Проверяем доступность VPN перед отправкой
        if check_connectivity:
            is_reachable, error_msg = check_vpn_connectivity(vpn_ip, timeout=5)
            if not is_reachable:
                logger.warning(f"VPN недоступен для узла {node.name} ({vpn_ip}): {error_msg}")
                return False, f"VPN туннель не работает: {error_msg}. Проверьте что WireGuard активен на обоих узлах."
        
        # 4. Шифруем конфигурацию
        try:
            encrypted_data = encrypt_config_for_node(config_data, node, app)
            encrypted_b64 = base64.b64encode(encrypted_data).decode('utf-8')
        except Exception as e:
            logger.error(f"Ошибка шифрования конфигурации для узла {node.name}: {e}")
            return False, f"Ошибка шифрования: {str(e)}"
        
        # 4. Формируем URL на VPN IP узла
        # Порт агента можно указать в узле, по умолчанию 5001
        vpn_port = getattr(node, 'agent_port', None) or 5001
        vpn_url = f"http://{vpn_ip}:{vpn_port}/api/v1/config/apply"
        
        # 5. Формируем payload
        payload = {
            "config_type": config_type,
            "encrypted_config": encrypted_b64,
            "node_name": node.name
        }
        
        # 6. Отправляем запрос через VPN
        try:
            response = requests.post(
                vpn_url,
                json=payload,
                timeout=30,
                verify=False  # VPN канал уже зашифрован WireGuard
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    logger.info(f"Конфигурация {config_type} успешно отправлена на {node.name} ({vpn_ip})")
                    return True, None
                else:
                    error_msg = result.get('error', 'Unknown error')
                    # Если ошибка связана с отсутствием cryptography, пытаемся установить автоматически
                    if 'No module named \'cryptography\'' in error_msg or ('cryptography' in error_msg.lower() and 'module' in error_msg.lower()):
                        logger.warning(f"Обнаружено отсутствие cryptography на {node.name}, пытаемся установить...")
                        try:
                            # Пробуем вызвать endpoint для установки зависимостей
                            install_url = f"http://{vpn_ip}:{vpn_port}/api/v1/install_dependencies"
                            install_response = requests.post(
                                install_url,
                                timeout=120,
                                verify=False
                            )
                            if install_response.status_code == 200:
                                install_result = install_response.json()
                                if install_result.get('success'):
                                    logger.info(f"cryptography успешно установлен на {node.name}, повторяем отправку конфигурации...")
                                    # Повторяем отправку конфигурации
                                    retry_response = requests.post(
                                        vpn_url,
                                        json=payload,
                                        timeout=30,
                                        verify=False
                                    )
                                    if retry_response.status_code == 200:
                                        retry_result = retry_response.json()
                                        if retry_result.get('success'):
                                            logger.info(f"Конфигурация {config_type} успешно отправлена на {node.name} после установки cryptography")
                                            return True, None
                        except Exception as install_err:
                            logger.warning(f"Не удалось автоматически установить cryptography: {install_err}")
                        
                        error_msg = f"Модуль cryptography не установлен на узле {node.name}. " \
                                   f"Попытка автоматической установки не удалась. " \
                                   f"Необходимо установить вручную: pip3 install --user cryptography>=41.0.0 " \
                                   f"или переразвернуть агент через SSH."
                    logger.error(f"Ошибка применения конфигурации на {node.name}: {error_msg}")
                    return False, error_msg
            else:
                error_msg = f"HTTP {response.status_code}: {response.text}"
                # Проверяем текст ответа на наличие ошибки cryptography
                if 'No module named \'cryptography\'' in error_msg or 'cryptography' in error_msg.lower():
                    error_msg = f"HTTP {response.status_code}: Модуль cryptography не установлен на узле {node.name}. " \
                               f"Необходимо установить: pip3 install --user cryptography>=41.0.0 " \
                               f"или переразвернуть агент через SSH."
                logger.error(f"Ошибка отправки конфигурации на {node.name}: {error_msg}")
                return False, error_msg
        
        except requests.exceptions.Timeout:
            error_msg = f"Timeout при отправке на {node.name}"
            logger.error(error_msg)
            return False, error_msg
        except requests.exceptions.ConnectionError as e:
            error_msg = f"Не удалось подключиться к {node.name} ({vpn_ip}): {str(e)}"
            logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Неожиданная ошибка при отправке на {node.name}: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    except Exception as e:
        logger.error(f"Ошибка в send_config_via_vpn для узла {node.name}: {e}", exc_info=True)
        return False, str(e)


def apply_config_locally(config_type: str, config_data: dict) -> Tuple[bool, Optional[str]]:
    """
    Применяет конфигурацию локально на Omnissiah
    
    Args:
        config_type: Тип конфигурации
        config_data: Данные конфигурации
    
    Returns:
        tuple: (success: bool, error_message: str | None)
    """
    import subprocess
    
    try:
        if config_type == 'iptables':
            action = config_data.get('action', 'add')
            rules = config_data.get('rules', [])
            
            for rule_parts in rules:
                if action == 'add':
                    cmd = ['sudo', '-n', 'iptables'] + rule_parts
                elif action == 'remove':
                    delete_parts = ['-D'] + rule_parts[1:] if rule_parts[0] == '-A' else ['-D'] + rule_parts
                    cmd = ['sudo', '-n', 'iptables'] + delete_parts
                else:
                    continue
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
                if result.returncode != 0:
                    logger.warning(f"Ошибка применения iptables правила: {result.stderr}")
        
        elif config_type == 'routes':
            action = config_data.get('action', 'add')
            routes = config_data.get('routes', [])
            
            for route in routes:
                network = route.get('network')
                gateway = route.get('gateway')
                interface = route.get('interface', 'n1')
                
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
                    if 'File exists' not in result.stderr and 'No such process' not in result.stderr:
                        logger.warning(f"Ошибка применения маршрута: {result.stderr}")
        
        return True, None
    
    except Exception as e:
        logger.error(f"Ошибка применения локальной конфигурации: {e}", exc_info=True)
        return False, str(e)


def send_iptables_rules_via_vpn(node, rules: List[List[str]], action: str = 'add', app=None,
                                check_connectivity: bool = True) -> Tuple[bool, Optional[str]]:
    """
    Отправляет iptables правила на узел через VPN
    
    Args:
        node: Объект узла
        rules: Список правил iptables (каждый элемент - список частей команды)
        action: "add" или "remove"
        app: Flask приложение
        check_connectivity: Проверять ли доступность VPN перед отправкой
    
    Returns:
        tuple: (success: bool, error_message: str | None)
    """
    config_data = {
        "action": action,
        "rules": rules
    }
    return send_config_via_vpn(node, "iptables", config_data, app, check_connectivity=check_connectivity)


def send_routes_via_vpn(node, routes: List[Dict], action: str = 'add', app=None,
                       check_connectivity: bool = True) -> Tuple[bool, Optional[str]]:
    """
    Отправляет маршруты на узел через VPN
    
    Args:
        node: Объект узла
        routes: Список маршрутов [{"network": "...", "gateway": "...", "interface": "..."}]
        action: "add" или "remove"
        app: Flask приложение
        check_connectivity: Проверять ли доступность VPN перед отправкой
    
    Returns:
        tuple: (success: bool, error_message: str | None)
    """
    config_data = {
        "action": action,
        "routes": routes
    }
    return send_config_via_vpn(node, "routes", config_data, app, check_connectivity=check_connectivity)

