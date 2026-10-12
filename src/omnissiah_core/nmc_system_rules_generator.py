"""
Генератор системных правил iptables для узлов
"""
from datetime import datetime
from ipaddress import ip_network
import json
import subprocess
import re


def create_system_rules_for_omnissiah(node, admin_ip, mtls_port=5001):
    """
    Создает системные правила для Omnissiah
    
    Правила (в порядке приоритета):
    1. Разрешить loopback и ESTABLISHED соединения (extra_commands)
    2. Разрешить весь трафик с/на IP администратора (INPUT и OUTPUT) - применяется ко ВСЕМ интерфейсам
    3. Разрешить mTLS для всех (INPUT)
    4. Разрешить VPN - разрешить подключение на порт VPN (UDP INPUT)
    5. Разрешить DNS - входящие и исходящие DNS запросы (UDP/TCP порт 53)
    6. Разрешить ICMP (ping) - входящие и исходящие запросы
    7. Разрешить веб-портал (Flask приложение TCP 33787)
    8. Разрешить HTTP/HTTPS для Nginx (TCP 80,443)
    9. Разрешить весь исходящий трафик с Omnissiah на любые узлы (extra_commands, применяется ДО политики DROP)
    10. Запретить весь входящий и исходящий трафик (политика по умолчанию через iptables -P INPUT/OUTPUT DROP)
    
    ВАЖНО: Правила администратора используют destination_network='0.0.0.0/0' для INPUT 
    и source_network='0.0.0.0/0' для OUTPUT, что обеспечивает доступ ко ВСЕМ интерфейсам узла,
    а не только к VPN интерфейсу.
    
    Returns:
        list: Список словарей с данными для создания AccessPolicyRule
        dict: Словарь с дополнительными командами (политики по умолчанию, loopback и т.д.)
    """
    rules = []
    extra_commands = []  # Дополнительные команды для применения отдельно
    
    # Правило 0: Разрешить loopback (добавляется как extra_commands, не как AccessPolicyRule)
    extra_commands.append({
        'chain': 'INPUT',
        'cmd': ['-A', 'INPUT', '-i', 'lo', '-j', 'ACCEPT'],
        'description': 'Разрешить loopback (системное)'
    })
    
    extra_commands.append({
        'chain': 'OUTPUT',
        'cmd': ['-A', 'OUTPUT', '-o', 'lo', '-j', 'ACCEPT'],
        'description': 'Разрешить loopback OUTPUT (системное)'
    })
    
    # Правило 0b: Разрешить установленные соединения
    extra_commands.append({
        'chain': 'INPUT',
        'cmd': ['-A', 'INPUT', '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'],
        'description': 'Разрешить установленные соединения (системное)'
    })
    
    extra_commands.append({
        'chain': 'OUTPUT',
        'cmd': ['-A', 'OUTPUT', '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'],
        'description': 'Разрешить установленные соединения OUTPUT (системное)'
    })
    
    # Правило 0c: Разрешить localhost (127.0.0.1) - критично для веб-портала
    extra_commands.append({
        'chain': 'INPUT',
        'cmd': ['-A', 'INPUT', '-s', '127.0.0.1', '-d', '127.0.0.1', '-j', 'ACCEPT'],
        'description': 'Разрешить localhost (127.0.0.1) INPUT (системное)'
    })
    
    extra_commands.append({
        'chain': 'OUTPUT',
        'cmd': ['-A', 'OUTPUT', '-s', '127.0.0.1', '-d', '127.0.0.1', '-j', 'ACCEPT'],
        'description': 'Разрешить localhost (127.0.0.1) OUTPUT (системное)'
    })
    
    # Правило 1: Разрешить весь трафик с/на IP администратора
    # ВАЖНО: Используем destination_type='network' с '0.0.0.0/0' для доступа ко ВСЕМ интерфейсам
    if admin_ip:
        admin_network = admin_ip if '/' in admin_ip else f"{admin_ip}/32"
        
        # Входящий трафик с администратора на ЛЮБОЙ интерфейс узла
        # Используем destination_network='0.0.0.0/0' чтобы правило применялось ко всем интерфейсам
        rules.append({
            'source_type': 'network',
            'source_network': admin_network,
            'destination_type': 'network',  # Используем network вместо node для доступа ко всем интерфейсам
            'destination_network': '0.0.0.0/0',  # Применяется ко всем интерфейсам и адресам узла
            'protocol': 'any',
            'ports': '',
            'service': 'ALL',
            'description': f'Разрешить весь трафик с узла администратора ({admin_ip}) на все интерфейсы',
            'is_system_rule': True,
            'status': 'applied',
            'direction': 'INPUT'  # Указываем направление для правильной генерации команд
        })
        
        # Исходящий трафик с узла на администратора
        # Используем source_network='0.0.0.0/0' для всех интерфейсов узла
        rules.append({
            'source_type': 'network',
            'source_network': '0.0.0.0/0',  # Применяется ко всем интерфейсам узла
            'destination_type': 'network',
            'destination_network': admin_network,
            'protocol': 'any',
            'ports': '',
            'service': 'ALL',
            'description': f'Разрешить весь трафик с любого интерфейса на узел администратора ({admin_ip})',
            'is_system_rule': True,
            'status': 'applied',
            'direction': 'OUTPUT'  # Указываем направление
        })
    
    # Правило 2: Запретить весь трафик (не создаем как AccessPolicyRule, это политика по умолчанию)
    # Это применяется через iptables -P INPUT DROP / OUTPUT DROP
    
    # Правило 3: Разрешить mTLS для всех (входящий)
    rules.append({
        'source_type': 'network',
        'source_network': '0.0.0.0/0',
        'destination_type': 'node',
        'destination_id': node.id,
        'protocol': 'tcp',
        'ports': str(mtls_port),
        'service': 'mTLS',
        'description': 'Разрешить mTLS для всех (системное правило)',
        'is_system_rule': True,
        'status': 'applied',
        'direction': 'INPUT'
    })
    
    # Правило 4: Разрешить VPN (UDP входящий на порт WireGuard)
    vpn_port = node.listen_port if node.listen_port else 51820
    rules.append({
        'source_type': 'network',
        'source_network': '0.0.0.0/0',
        'destination_type': 'node',
        'destination_id': node.id,
        'protocol': 'udp',
        'ports': str(vpn_port),
        'service': 'WireGuard VPN',
        'description': f'Разрешить VPN подключения на порт {vpn_port} (системное правило)',
        'is_system_rule': True,
        'status': 'applied',
        'direction': 'INPUT'
    })
    
    # Правило 5: Разрешить DNS (UDP порт 53) - входящий и исходящий
    # Входящий DNS (запросы к DNS серверу на этом узле)
    rules.append({
        'source_type': 'network',
        'source_network': '0.0.0.0/0',
        'destination_type': 'node',
        'destination_id': node.id,
        'protocol': 'udp',
        'ports': '53',
        'service': 'DNS',
        'description': 'Разрешить входящие DNS запросы (UDP 53) (системное правило)',
        'is_system_rule': True,
        'status': 'applied',
        'direction': 'INPUT'
    })
    
    # Исходящий DNS (запросы с этого узла к DNS серверам)
    rules.append({
        'source_type': 'network',
        'source_network': '0.0.0.0/0',  # С любого интерфейса узла
        'destination_type': 'network',
        'destination_network': '0.0.0.0/0',  # На любой DNS сервер
        'protocol': 'udp',
        'ports': '53',
        'service': 'DNS',
        'description': 'Разрешить исходящие DNS запросы (UDP 53) (системное правило)',
        'is_system_rule': True,
        'status': 'applied',
        'direction': 'OUTPUT'
    })
    
    # Также разрешаем TCP DNS (для больших ответов или зонных трансферов)
    rules.append({
        'source_type': 'network',
        'source_network': '0.0.0.0/0',
        'destination_type': 'node',
        'destination_id': node.id,
        'protocol': 'tcp',
        'ports': '53',
        'service': 'DNS',
        'description': 'Разрешить входящие DNS запросы (TCP 53) (системное правило)',
        'is_system_rule': True,
        'status': 'applied',
        'direction': 'INPUT'
    })
    
    rules.append({
        'source_type': 'network',
        'source_network': '0.0.0.0/0',
        'destination_type': 'network',
        'destination_network': '0.0.0.0/0',
        'protocol': 'tcp',
        'ports': '53',
        'service': 'DNS',
        'description': 'Разрешить исходящие DNS запросы (TCP 53) (системное правило)',
        'is_system_rule': True,
        'status': 'applied',
        'direction': 'OUTPUT'
    })
    
    # Правило 6: Разрешить ICMP (ping) - входящий и исходящий
    # Входящий ping (echo-request)
    rules.append({
        'source_type': 'network',
        'source_network': '0.0.0.0/0',
        'destination_type': 'node',
        'destination_id': node.id,
        'protocol': 'icmp',
        'ports': '',
        'service': 'ICMP',
        'description': 'Разрешить входящие ping запросы (ICMP) (системное правило)',
        'is_system_rule': True,
        'status': 'applied',
        'direction': 'INPUT'
    })
    
    # Исходящий ping (echo-request и echo-reply)
    rules.append({
        'source_type': 'network',
        'source_network': '0.0.0.0/0',
        'destination_type': 'network',
        'destination_network': '0.0.0.0/0',
        'protocol': 'icmp',
        'ports': '',
        'service': 'ICMP',
        'description': 'Разрешить исходящие ping запросы и ответы (ICMP) (системное правило)',
        'is_system_rule': True,
        'status': 'applied',
        'direction': 'OUTPUT'
    })
    
    # Правило 7: Разрешить веб-портал (Flask приложение на порту 33787)
    rules.append({
        'source_type': 'network',
        'source_network': '0.0.0.0/0',
        'destination_type': 'node',
        'destination_id': node.id,
        'protocol': 'tcp',
        'ports': '33787',
        'service': 'Web Portal',
        'description': 'Разрешить доступ к веб-порталу (TCP 33787) (системное правило)',
        'is_system_rule': True,
        'status': 'applied',
        'direction': 'INPUT'
    })
    
    # Правило 8: Разрешить HTTP/HTTPS для Nginx (порты 80 и 443)
    rules.append({
        'source_type': 'network',
        'source_network': '0.0.0.0/0',
        'destination_type': 'node',
        'destination_id': node.id,
        'protocol': 'tcp',
        'ports': '80,443',
        'service': 'HTTP/HTTPS',
        'description': 'Разрешить HTTP/HTTPS для Nginx (TCP 80,443) (системное правило)',
        'is_system_rule': True,
        'status': 'applied',
        'direction': 'INPUT'
    })
    
    # Правило 9: Разрешить исходящий трафик с Omnissiah на любые узлы
    # Добавляем как правило в БД для отображения в интерфейсе
    rules.append({
        'source_type': 'node',
        'source_id': node.id,
        'destination_type': 'network',
        'destination_network': '0.0.0.0/0',  # На любые узлы
        'protocol': 'any',
        'ports': '',
        'service': 'ALL',
        'description': 'Разрешить исходящий трафик с Omnissiah на любые узлы (системное правило)',
        'is_system_rule': True,
        'status': 'applied',
        'direction': 'OUTPUT'
    })
    
    # Правило 9b: Разрешить весь исходящий трафик (добавляем как extra_commands ПЕРЕД политикой DROP)
    # ВАЖНО: Это применяется ПОСЛЕ всех специфичных правил, но ДО политики DROP
    # Это позволяет Omnissiah инициировать соединения с любыми узлами (SSH, HTTP, и т.д.)
    # Применяется в самом конце, перед политикой DROP
    extra_commands.append({
        'chain': 'OUTPUT',
        'cmd': ['-A', 'OUTPUT', '-j', 'ACCEPT'],
        'description': 'Разрешить весь исходящий трафик с Omnissiah (системное правило, перед DROP)'
    })
    
    # Правило 2: Запретить весь трафик (политика по умолчанию)
    # Это применяется через iptables -P INPUT DROP / OUTPUT DROP (не создается как AccessPolicyRule)
    extra_commands.append({
        'chain': 'POLICY',
        'cmd': ['-P', 'INPUT', 'DROP'],
        'description': 'Политика по умолчанию: запретить входящий трафик (системное)'
    })
    extra_commands.append({
        'chain': 'POLICY',
        'cmd': ['-P', 'OUTPUT', 'DROP'],
        'description': 'Политика по умолчанию: запретить исходящий трафик (системное)'
    })
    
    return rules, extra_commands


def create_system_rules_for_magos(node, omnissiah, mtls_port=5001, admin_ip=None):
    """
    Создает системные правила для Magos
    
    Правила:
    1. Разрешить mTLS только с Omnissiah и родительским узлом
    2. SSH разрешен с Omnissiah и администратора (INPUT и OUTPUT)
    3. Разрешить исходящий трафик с Magos на любые узлы
    4. Запретить весь трафик (политика по умолчанию)
    
    Args:
        node: Узел Magos
        omnissiah: Узел Omnissiah
        mtls_port: Порт mTLS
        admin_ip: IP адрес администратора (опционально)
    
    Returns:
        list: Список словарей с данными для создания AccessPolicyRule
    """
    rules = []
    extra_commands = []
    
    # Разрешить loopback и ESTABLISHED
    extra_commands.append({
        'chain': 'INPUT',
        'cmd': ['-A', 'INPUT', '-i', 'lo', '-j', 'ACCEPT'],
        'description': 'Разрешить loopback (системное)'
    })
    extra_commands.append({
        'chain': 'OUTPUT',
        'cmd': ['-A', 'OUTPUT', '-o', 'lo', '-j', 'ACCEPT'],
        'description': 'Разрешить loopback OUTPUT (системное)'
    })
    extra_commands.append({
        'chain': 'INPUT',
        'cmd': ['-A', 'INPUT', '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'],
        'description': 'Разрешить установленные соединения (системное)'
    })
    extra_commands.append({
        'chain': 'OUTPUT',
        'cmd': ['-A', 'OUTPUT', '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'],
        'description': 'Разрешить установленные соединения OUTPUT (системное)'
    })
    
    # Определяем родительский узел
    parent = node.parent if node.parent_id else None
    
    # КРИТИЧНО: Для системных правил (SSH, mTLS) используем РЕАЛЬНЫЕ IP адреса (endpoint),
    # а не VPN IP, так как эти правила должны работать даже когда VPN не включен
    
    # Правило 1: Разрешить mTLS только с Omnissiah - используем реальный IP
    if omnissiah and omnissiah.endpoint:
        # Извлекаем IP из endpoint (формат: IP:PORT или просто IP)
        omnissiah_real_ip = omnissiah.endpoint.split(':')[0] if ':' in omnissiah.endpoint else omnissiah.endpoint
        
        # Входящий mTLS с Omnissiah (реальный IP)
        extra_commands.append({
            'chain': 'INPUT',
            'cmd': ['-A', 'INPUT', '-s', omnissiah_real_ip, '-p', 'tcp', '--dport', str(mtls_port), '-j', 'ACCEPT'],
            'description': f'Разрешить входящий mTLS с Omnissiah ({omnissiah_real_ip}) (системное правило)'
        })
    
    # Правило 1b: Разрешить mTLS только с родительским узлом (если есть и это не Omnissiah)
    if parent and parent.id != omnissiah.id and parent.endpoint:
        # Извлекаем IP из endpoint родительского узла
        parent_real_ip = parent.endpoint.split(':')[0] if ':' in parent.endpoint else parent.endpoint
        
        # Входящий mTLS с родительского узла (реальный IP)
        extra_commands.append({
            'chain': 'INPUT',
            'cmd': ['-A', 'INPUT', '-s', parent_real_ip, '-p', 'tcp', '--dport', str(mtls_port), '-j', 'ACCEPT'],
            'description': f'Разрешить входящий mTLS с родительского узла {parent.name} ({parent_real_ip}) (системное правило)'
        })
    
    # Правило 2: SSH разрешен с Omnissiah (INPUT и OUTPUT) - используем реальный IP
    if omnissiah and omnissiah.endpoint:
        # Извлекаем IP из endpoint
        omnissiah_real_ip = omnissiah.endpoint.split(':')[0] if ':' in omnissiah.endpoint else omnissiah.endpoint
        
        # Входящий SSH с Omnissiah (реальный IP)
        extra_commands.append({
            'chain': 'INPUT',
            'cmd': ['-A', 'INPUT', '-s', omnissiah_real_ip, '-p', 'tcp', '--dport', '22', '-j', 'ACCEPT'],
            'description': f'Разрешить входящий SSH с Omnissiah ({omnissiah_real_ip}) (системное правило)'
        })
        
        # Исходящий SSH на Omnissiah (реальный IP)
        extra_commands.append({
            'chain': 'OUTPUT',
            'cmd': ['-A', 'OUTPUT', '-d', omnissiah_real_ip, '-p', 'tcp', '--dport', '22', '-j', 'ACCEPT'],
            'description': f'Разрешить исходящий SSH на Omnissiah ({omnissiah_real_ip}) (системное правило)'
        })
    
    # Правило 2b: SSH разрешен с администратора (INPUT и OUTPUT) - используем реальный IP
    if admin_ip:
        # Входящий SSH с администратора (реальный IP)
        extra_commands.append({
            'chain': 'INPUT',
            'cmd': ['-A', 'INPUT', '-s', admin_ip, '-p', 'tcp', '--dport', '22', '-j', 'ACCEPT'],
            'description': f'Разрешить входящий SSH с администратора ({admin_ip}) (системное правило)'
        })
        
        # Исходящий SSH на администратора (реальный IP)
        extra_commands.append({
            'chain': 'OUTPUT',
            'cmd': ['-A', 'OUTPUT', '-d', admin_ip, '-p', 'tcp', '--dport', '22', '-j', 'ACCEPT'],
            'description': f'Разрешить исходящий SSH на администратора ({admin_ip}) (системное правило)'
        })
    
    # Правило 3: Разрешить ICMP (ping) - входящий и исходящий
    # Входящий ping
    extra_commands.append({
        'chain': 'INPUT',
        'cmd': ['-A', 'INPUT', '-p', 'icmp', '-j', 'ACCEPT'],
        'description': 'Разрешить входящий ICMP (ping) (системное правило)'
    })
    # Исходящий ping
    extra_commands.append({
        'chain': 'OUTPUT',
        'cmd': ['-A', 'OUTPUT', '-p', 'icmp', '-j', 'ACCEPT'],
        'description': 'Разрешить исходящий ICMP (ping) (системное правило)'
    })
    
    # Правило 4: Разрешить heartbeat (HTTPS) на Omnissiah - используем реальный IP (endpoint)
    if omnissiah and omnissiah.endpoint:
        # Извлекаем IP из endpoint (формат: IP:PORT или просто IP)
        omnissiah_real_ip = omnissiah.endpoint.split(':')[0] if ':' in omnissiah.endpoint else omnissiah.endpoint
        
        # Входящий HTTPS с Omnissiah (для ответов на heartbeat)
        extra_commands.append({
            'chain': 'INPUT',
            'cmd': ['-A', 'INPUT', '-s', omnissiah_real_ip, '-p', 'tcp', '--sport', '443', '-j', 'ACCEPT'],
            'description': f'Разрешить входящий HTTPS (ответы на heartbeat) с Omnissiah ({omnissiah_real_ip}) (системное правило)'
        })
        
        # Исходящий HTTPS на Omnissiah (для отправки heartbeat)
        extra_commands.append({
            'chain': 'OUTPUT',
            'cmd': ['-A', 'OUTPUT', '-d', omnissiah_real_ip, '-p', 'tcp', '--dport', '443', '-j', 'ACCEPT'],
            'description': f'Разрешить исходящий HTTPS (heartbeat) на Omnissiah ({omnissiah_real_ip}) (системное правило)'
        })
        
        # Также разрешаем HTTP на случай если используется HTTP вместо HTTPS
        extra_commands.append({
            'chain': 'OUTPUT',
            'cmd': ['-A', 'OUTPUT', '-d', omnissiah_real_ip, '-p', 'tcp', '--dport', '80', '-j', 'ACCEPT'],
            'description': f'Разрешить исходящий HTTP на Omnissiah ({omnissiah_real_ip}) (системное правило)'
        })
    
    # Правило 5: Разрешить исходящий трафик с Magos на любые узлы
    rules.append({
        'source_type': 'node',
        'source_id': node.id,
        'destination_type': 'network',
        'destination_network': '0.0.0.0/0',  # На любые узлы
        'protocol': 'any',
        'ports': '',
        'service': 'ALL',
        'description': 'Разрешить исходящий трафик с Magos на любые узлы (системное правило)',
        'is_system_rule': True,
        'status': 'applied',
        'direction': 'OUTPUT'
    })
    
    # Правило 6: Разрешить весь исходящий трафик (добавляем как extra_commands ПЕРЕД политикой DROP)
    extra_commands.append({
        'chain': 'OUTPUT',
        'cmd': ['-A', 'OUTPUT', '-j', 'ACCEPT'],
        'description': 'Разрешить весь исходящий трафик с Magos (системное правило, перед DROP)'
    })
    
    # Политика по умолчанию
    extra_commands.append({
        'chain': 'POLICY',
        'cmd': ['-P', 'INPUT', 'DROP'],
        'description': 'Политика по умолчанию: запретить входящий трафик (системное)'
    })
    extra_commands.append({
        'chain': 'POLICY',
        'cmd': ['-P', 'OUTPUT', 'DROP'],
        'description': 'Политика по умолчанию: запретить исходящий трафик (системное)'
    })
    
    return rules, extra_commands


def create_system_rules_for_cognitor(node, omnissiah, parent, mtls_port=5001, admin_ip=None):
    """
    Создает системные правила для Cognitor
    
    Правила:
    1. Разрешить mTLS только с Omnissiah и родительским узлом (Magos)
    2. SSH разрешен с Omnissiah и администратора (INPUT и OUTPUT)
    3. Разрешить исходящий трафик с Cognitor на любые узлы
    4. Запретить весь трафик (политика по умолчанию)
    
    Args:
        node: Узел Cognitor
        omnissiah: Узел Omnissiah
        parent: Родительский узел (Magos)
        mtls_port: Порт mTLS
        admin_ip: IP адрес администратора (опционально)
    
    Returns:
        list: Список словарей с данными для создания AccessPolicyRule
        dict: Словарь с дополнительными командами
    """
    rules = []
    extra_commands = []
    
    # Разрешить loopback и ESTABLISHED
    extra_commands.append({
        'chain': 'INPUT',
        'cmd': ['-A', 'INPUT', '-i', 'lo', '-j', 'ACCEPT'],
        'description': 'Разрешить loopback (системное)'
    })
    extra_commands.append({
        'chain': 'OUTPUT',
        'cmd': ['-A', 'OUTPUT', '-o', 'lo', '-j', 'ACCEPT'],
        'description': 'Разрешить loopback OUTPUT (системное)'
    })
    extra_commands.append({
        'chain': 'INPUT',
        'cmd': ['-A', 'INPUT', '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'],
        'description': 'Разрешить установленные соединения (системное)'
    })
    extra_commands.append({
        'chain': 'OUTPUT',
        'cmd': ['-A', 'OUTPUT', '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'],
        'description': 'Разрешить установленные соединения OUTPUT (системное)'
    })
    
    # КРИТИЧНО: Для системных правил (SSH, mTLS) используем РЕАЛЬНЫЕ IP адреса (endpoint),
    # а не VPN IP, так как эти правила должны работать даже когда VPN не включен
    
    # Правило 1: Разрешить mTLS только с Omnissiah - используем реальный IP
    if omnissiah and omnissiah.endpoint:
        # Извлекаем IP из endpoint
        omnissiah_real_ip = omnissiah.endpoint.split(':')[0] if ':' in omnissiah.endpoint else omnissiah.endpoint
        
        # Входящий mTLS с Omnissiah (реальный IP)
        extra_commands.append({
            'chain': 'INPUT',
            'cmd': ['-A', 'INPUT', '-s', omnissiah_real_ip, '-p', 'tcp', '--dport', str(mtls_port), '-j', 'ACCEPT'],
            'description': f'Разрешить входящий mTLS с Omnissiah ({omnissiah_real_ip}) (системное правило)'
        })
    
    # Правило 1b: Разрешить mTLS только с родительским узлом (Magos) - используем реальный IP
    if parent and parent.endpoint:
        # Извлекаем IP из endpoint родительского узла
        parent_real_ip = parent.endpoint.split(':')[0] if ':' in parent.endpoint else parent.endpoint
        
        # Входящий mTLS с родительского узла (реальный IP)
        extra_commands.append({
            'chain': 'INPUT',
            'cmd': ['-A', 'INPUT', '-s', parent_real_ip, '-p', 'tcp', '--dport', str(mtls_port), '-j', 'ACCEPT'],
            'description': f'Разрешить входящий mTLS с родительского узла {parent.name} ({parent_real_ip}) (системное правило)'
        })
    
    # Правило 2: SSH разрешен с Omnissiah (INPUT и OUTPUT) - используем реальный IP
    if omnissiah and omnissiah.endpoint:
        # Извлекаем IP из endpoint
        omnissiah_real_ip = omnissiah.endpoint.split(':')[0] if ':' in omnissiah.endpoint else omnissiah.endpoint
        
        # Входящий SSH с Omnissiah (реальный IP)
        extra_commands.append({
            'chain': 'INPUT',
            'cmd': ['-A', 'INPUT', '-s', omnissiah_real_ip, '-p', 'tcp', '--dport', '22', '-j', 'ACCEPT'],
            'description': f'Разрешить входящий SSH с Omnissiah ({omnissiah_real_ip}) (системное правило)'
        })
        
        # Исходящий SSH на Omnissiah (реальный IP)
        extra_commands.append({
            'chain': 'OUTPUT',
            'cmd': ['-A', 'OUTPUT', '-d', omnissiah_real_ip, '-p', 'tcp', '--dport', '22', '-j', 'ACCEPT'],
            'description': f'Разрешить исходящий SSH на Omnissiah ({omnissiah_real_ip}) (системное правило)'
        })
    
    # Правило 2b: SSH разрешен с администратора (INPUT и OUTPUT) - используем реальный IP
    if admin_ip:
        # Входящий SSH с администратора (реальный IP)
        extra_commands.append({
            'chain': 'INPUT',
            'cmd': ['-A', 'INPUT', '-s', admin_ip, '-p', 'tcp', '--dport', '22', '-j', 'ACCEPT'],
            'description': f'Разрешить входящий SSH с администратора ({admin_ip}) (системное правило)'
        })
        
        # Исходящий SSH на администратора (реальный IP)
        extra_commands.append({
            'chain': 'OUTPUT',
            'cmd': ['-A', 'OUTPUT', '-d', admin_ip, '-p', 'tcp', '--dport', '22', '-j', 'ACCEPT'],
            'description': f'Разрешить исходящий SSH на администратора ({admin_ip}) (системное правило)'
        })
    
    # Правило 3: Разрешить ICMP (ping) - входящий и исходящий
    # Входящий ping
    extra_commands.append({
        'chain': 'INPUT',
        'cmd': ['-A', 'INPUT', '-p', 'icmp', '-j', 'ACCEPT'],
        'description': 'Разрешить входящий ICMP (ping) (системное правило)'
    })
    # Исходящий ping
    extra_commands.append({
        'chain': 'OUTPUT',
        'cmd': ['-A', 'OUTPUT', '-p', 'icmp', '-j', 'ACCEPT'],
        'description': 'Разрешить исходящий ICMP (ping) (системное правило)'
    })
    
    # Правило 4: Разрешить heartbeat (HTTPS) на Omnissiah - используем реальный IP
    if omnissiah and omnissiah.endpoint:
        # Извлекаем IP из endpoint
        omnissiah_real_ip = omnissiah.endpoint.split(':')[0] if ':' in omnissiah.endpoint else omnissiah.endpoint
        
        # Входящий HTTPS с Omnissiah (для ответов на heartbeat)
        extra_commands.append({
            'chain': 'INPUT',
            'cmd': ['-A', 'INPUT', '-s', omnissiah_real_ip, '-p', 'tcp', '--sport', '443', '-j', 'ACCEPT'],
            'description': f'Разрешить входящий HTTPS (ответы на heartbeat) с Omnissiah ({omnissiah_real_ip}) (системное правило)'
        })
        
        # Исходящий HTTPS на Omnissiah (для отправки heartbeat)
        extra_commands.append({
            'chain': 'OUTPUT',
            'cmd': ['-A', 'OUTPUT', '-d', omnissiah_real_ip, '-p', 'tcp', '--dport', '443', '-j', 'ACCEPT'],
            'description': f'Разрешить исходящий HTTPS (heartbeat) на Omnissiah ({omnissiah_real_ip}) (системное правило)'
        })
        
        # Также разрешаем HTTP на случай если используется HTTP вместо HTTPS
        extra_commands.append({
            'chain': 'OUTPUT',
            'cmd': ['-A', 'OUTPUT', '-d', omnissiah_real_ip, '-p', 'tcp', '--dport', '80', '-j', 'ACCEPT'],
            'description': f'Разрешить исходящий HTTP на Omnissiah ({omnissiah_real_ip}) (системное правило)'
        })
    
    # Правило 5: Разрешить исходящий трафик с Cognitor на любые узлы
    rules.append({
        'source_type': 'node',
        'source_id': node.id,
        'destination_type': 'network',
        'destination_network': '0.0.0.0/0',  # На любые узлы
        'protocol': 'any',
        'ports': '',
        'service': 'ALL',
        'description': 'Разрешить исходящий трафик с Cognitor на любые узлы (системное правило)',
        'is_system_rule': True,
        'status': 'applied',
        'direction': 'OUTPUT'
    })
    
    # Правило 6: Разрешить весь исходящий трафик (добавляем как extra_commands ПЕРЕД политикой DROP)
    extra_commands.append({
        'chain': 'OUTPUT',
        'cmd': ['-A', 'OUTPUT', '-j', 'ACCEPT'],
        'description': 'Разрешить весь исходящий трафик с Cognitor (системное правило, перед DROP)'
    })
    
    # Политика по умолчанию
    extra_commands.append({
        'chain': 'POLICY',
        'cmd': ['-P', 'INPUT', 'DROP'],
        'description': 'Политика по умолчанию: запретить входящий трафик (системное)'
    })
    extra_commands.append({
        'chain': 'POLICY',
        'cmd': ['-P', 'OUTPUT', 'DROP'],
        'description': 'Политика по умолчанию: запретить исходящий трафик (системное)'
    })
    
    return rules, extra_commands


def create_default_protected_objects(node, admin_ip=None):
    """
    Создает защищенные объекты по умолчанию для узла
    
    По умолчанию добавляются:
    - 0.0.0.0/0 (вся сеть)
    - IP адрес узла администратора (если указан)
    - Адреса интерфейсов всех узлов (для Omnissiah добавляются адреса всех узлов)
    
    Returns:
        list: Список словарей с данными для создания ProtectedObject
    """
    objects = []
    
    # 1. Вся сеть 0.0.0.0/0
    objects.append({
        'network': '0.0.0.0/0',
        'node_id': node.id,
        'interface': 'any',
        'description': 'Вся сеть (по умолчанию)',
        'is_active': True
    })
    
    # 2. IP адрес узла администратора
    if admin_ip:
        # Добавляем /32 если нет маски
        admin_network = admin_ip if '/' in admin_ip else f"{admin_ip}/32"
        objects.append({
            'network': admin_network,
            'node_id': node.id,
            'interface': 'any',
            'description': 'Узел администратора (по умолчанию)',
            'is_active': True
        })
    
    # 3. Адреса интерфейсов узла
    # Для Omnissiah получаем локально, для других узлов из heartbeat_interfaces
    if node.role == 'Omnissiah':
        # Используем импорт внутри функции чтобы избежать circular import
        try:
            from flask import current_app
            
            # Безопасное получение интерфейсов через subprocess напрямую, без обращения к SQLAlchemy объекту
            # Это избегает проблем с контекстом SQLAlchemy
            try:
                # Получаем список интерфейсов через ip addr show
                result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True, timeout=5)
                
                current_iface = None
                for line in result.stdout.split('\n'):
                    # Находим интерфейс
                    if_match = re.match(r'\d+: (\w+):', line)
                    if if_match:
                        current_iface = if_match.group(1)
                    
                    # Находим IP адрес
                    ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+/\d+)', line)
                    if ip_match and current_iface and current_iface != 'lo':
                        ip_with_mask = ip_match.group(1)
                        ip = ip_with_mask.split('/')[0]
                        if ip and ip != '0.0.0.0':
                            # Добавляем /32 если нет маски в оригинале
                            if '/' not in ip_with_mask:
                                ip_network = f"{ip}/32"
                            else:
                                ip_network = ip_with_mask
                            objects.append({
                                'network': ip_network,
                                'node_id': node.id,
                                'interface': current_iface,
                                'description': f'IP интерфейса {current_iface} Omnissiah (по умолчанию)',
                                'is_active': True
                            })
                
                # Также добавляем WireGuard интерфейс если есть
                try:
                    node_dict = node.__dict__
                    node_dict_clean = {k: v for k, v in node_dict.items() if not k.startswith('_sa_')}
                    node_name = str(node_dict_clean.get('name')) if node_dict_clean.get('name') else None
                    node_ip_pool = str(node_dict_clean.get('ip_pool')) if node_dict_clean.get('ip_pool') else None
                    
                    if node_name and node_ip_pool:
                        # Получаем IP из ip_pool
                        vpn_ip = node_ip_pool.split('/')[0]
                        if vpn_ip:
                            vpn_network = node_ip_pool if '/' in node_ip_pool else f"{vpn_ip}/32"
                            # Проверяем, нет ли уже такого IP
                            if not any(obj.get('network') == vpn_network for obj in objects):
                                objects.append({
                                    'network': vpn_network,
                                    'node_id': node.id,
                                    'interface': node_name,
                                    'description': f'IP интерфейса WireGuard {node_name} Omnissiah (по умолчанию)',
                                    'is_active': True
                                })
                except Exception:
                    pass  # Игнорируем ошибки получения VPN интерфейса
                
                # Адреса интерфейсов всех узлов (Magos, Cognitor)
                # НЕ используем SQLAlchemy здесь, чтобы избежать проблем с контекстом
                # Вместо этого извлекаем данные напрямую из базы через sqlite3
                # Это безопасно и не требует Flask app context
                try:
                    import sqlite3
                    import os
                    from pathlib import Path
                    
                    # Определяем путь к базе данных
                    # SQLAlchemy использует sqlite:///vpngate.db (относительный путь)
                    # Пытаемся найти базу относительно текущего файла
                    current_dir = Path(__file__).parent.parent
                    db_path = current_dir / 'vpngate.db'
                    
                    # Если не найдена, пробуем database/retra.db
                    if not os.path.exists(db_path):
                        db_path = current_dir / 'database' / 'retra.db'
                    
                    # Если и там нет, пробуем vpngate.db в корне проекта
                    if not os.path.exists(db_path):
                        db_path = current_dir / 'vpngate.db'
                    
                    if os.path.exists(db_path):
                        conn = sqlite3.connect(str(db_path))
                        cursor = conn.cursor()
                        try:
                            # Получаем узлы Magos и Cognitor напрямую из базы
                            cursor.execute("""
                                SELECT id, name, heartbeat_interfaces 
                                FROM general 
                                WHERE role IN ('Magos', 'Cognitor')
                            """)
                            
                            for row in cursor.fetchall():
                                node_id_db, node_name_db, heartbeat_interfaces_str = row
                                if heartbeat_interfaces_str:
                                    try:
                                        interfaces = json.loads(heartbeat_interfaces_str)
                                        for iface in interfaces:
                                            if 'name' in iface and 'ip' in iface:
                                                ip = iface['ip'].split('/')[0]
                                                if ip and ip != '0.0.0.0' and not ip.startswith('172.18.16.'):
                                                    if '/' not in iface['ip']:
                                                        ip = f"{ip}/32"
                                                    else:
                                                        ip = iface['ip']
                                                    objects.append({
                                                        'network': ip,
                                                        'node_id': node.id,
                                                        'interface': 'any',
                                                        'description': f'IP интерфейса {iface["name"]} узла {node_name_db or "unknown"} (по умолчанию)',
                                                        'is_active': True
                                                    })
                                    except Exception as e:
                                        print(f"Ошибка парсинга heartbeat_interfaces для {node_name_db}: {e}")
                        finally:
                            conn.close()
                except Exception as e:
                    print(f"Ошибка получения других узлов: {e}")
                    
            except Exception as e:
                print(f"Ошибка получения интерфейсов через subprocess: {e}")
        except Exception as e:
            print(f"Ошибка получения интерфейсов для Omnissiah: {e}")
    else:
        # Для Magos/Cognitor используем heartbeat_interfaces
        # Безопасное извлечение через __dict__
        try:
            node_dict = node.__dict__
            node_dict_clean = {k: v for k, v in node_dict.items() if not k.startswith('_sa_')}
            heartbeat_interfaces_str = str(node_dict_clean.get('heartbeat_interfaces')) if node_dict_clean.get('heartbeat_interfaces') else None
            
            if heartbeat_interfaces_str:
                try:
                    interfaces = json.loads(heartbeat_interfaces_str)
                    for iface in interfaces:
                        if 'name' in iface and 'ip' in iface:
                            ip = iface['ip'].split('/')[0]  # Убираем маску для добавления /32
                            if ip and ip != '0.0.0.0':
                                # Добавляем /32 если нет маски
                                if '/' not in iface['ip']:
                                    ip = f"{ip}/32"
                                else:
                                    ip = iface['ip']
                                objects.append({
                                    'network': ip,
                                    'node_id': node.id,
                                    'interface': iface['name'],
                                    'description': f'IP интерфейса {iface["name"]} (по умолчанию)',
                                    'is_active': True
                                })
                except Exception as e:
                    print(f"Ошибка парсинга heartbeat_interfaces: {e}")
            else:
                # Нет heartbeat_interfaces - пропускаем
                pass
        except Exception as e:
            print(f"Ошибка получения heartbeat_interfaces для узла: {e}")
    
    return objects

