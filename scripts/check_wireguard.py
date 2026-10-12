#!/usr/bin/env python3
"""
Скрипт для проверки и диагностики WireGuard конфигурации
Проверяет:
- Корректность конфигурации WireGuard
- Соответствие реальных IP и VPN IP
- Доступность пиров
- Маршрутизацию трафика
"""

import sys
import subprocess
import json
from pathlib import Path

# Добавляем корень проекта в путь
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from ipaddress import IPv4Address, ip_network
from src.app import app, db, General
from flask import Flask

def check_wireguard_interface(interface_name):
    """Проверяет статус WireGuard интерфейса"""
    print(f"\n{'='*60}")
    print(f"Проверка интерфейса: {interface_name}")
    print(f"{'='*60}")
    
    # Проверяем что интерфейс существует
    try:
        result = subprocess.run(
            ["sudo", "wg", "show", interface_name],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode != 0:
            print(f"❌ Интерфейс {interface_name} не найден или не активен")
            print(f"Ошибка: {result.stderr}")
            return False
        
        print(f"✅ Интерфейс {interface_name} активен")
        print(f"\nИнформация о интерфейсе:")
        print(result.stdout)
        return True
    except Exception as e:
        print(f"❌ Ошибка при проверке интерфейса: {e}")
        return False


def check_wireguard_config_file(interface_name):
    """Проверяет конфигурационный файл WireGuard"""
    config_path = Path(f"/etc/wireguard/{interface_name}.conf")
    
    print(f"\n{'='*60}")
    print(f"Проверка конфигурационного файла: {config_path}")
    print(f"{'='*60}")
    
    if not config_path.exists():
        print(f"❌ Конфигурационный файл не найден: {config_path}")
        return False
    
    print(f"✅ Конфигурационный файл существует")
    
    # Читаем конфигурацию
    try:
        with open(config_path, 'r') as f:
            config_content = f.read()
        
        print(f"\nСодержимое конфигурации:")
        print("-" * 60)
        print(config_content)
        print("-" * 60)
        
        # Проверяем наличие проблем
        issues = []
        
        # Проверка AllowedIPs = 0.0.0.0/0
        if "AllowedIPs = 0.0.0.0/0" in config_content:
            issues.append("⚠️  Найдено AllowedIPs = 0.0.0.0/0 - это может маршрутизировать весь трафик через VPN")
        
        # Проверка endpoint
        lines = config_content.split('\n')
        for i, line in enumerate(lines):
            if line.strip().startswith('Endpoint ='):
                endpoint = line.split('=')[1].strip()
                # Проверяем что endpoint не является VPN IP (10.x.x.x или 172.18.x.x)
                if endpoint.startswith('10.') or endpoint.startswith('172.18.'):
                    issues.append(f"⚠️  Endpoint может быть VPN IP: {endpoint} (строка {i+1})")
        
        if issues:
            print(f"\n⚠️  Обнаружены потенциальные проблемы:")
            for issue in issues:
                print(f"  {issue}")
        else:
            print(f"\n✅ Потенциальных проблем не обнаружено")
        
        return True
    except Exception as e:
        print(f"❌ Ошибка при чтении конфигурации: {e}")
        return False


def check_node_configuration(node):
    """Проверяет конфигурацию узла"""
    print(f"\n{'='*60}")
    print(f"Проверка узла: {node.name} (role: {node.role})")
    print(f"{'='*60}")
    
    issues = []
    
    # Проверка VPN IP
    if node.ip_pool:
        vpn_ip = node.ip_pool.split('/')[0]
        print(f"VPN IP: {vpn_ip}/{node.ip_pool.split('/')[1] if '/' in node.ip_pool else '32'}")
        
        # Проверка endpoint
        if node.endpoint:
            endpoint_ip = node.endpoint.split(':')[0] if ':' in node.endpoint else node.endpoint
            print(f"Endpoint из БД: {node.endpoint}")
            
            # Проверяем что endpoint не является VPN IP
            try:
                vpn_network = ip_network(node.ip_pool, strict=False)
                ip_addr = IPv4Address(endpoint_ip)
                if ip_addr in vpn_network:
                    issues.append(f"❌ Endpoint ({endpoint_ip}) является VPN IP! Должен быть реальный внешний IP")
                else:
                    print(f"✅ Endpoint ({endpoint_ip}) не является VPN IP")
            except (ValueError, AttributeError) as e:
                issues.append(f"⚠️  Ошибка проверки endpoint: {e}")
        else:
            print(f"⚠️  Endpoint не указан в БД")
        
        # Проверка heartbeat_ip
        if node.heartbeat_ip:
            print(f"Heartbeat IP: {node.heartbeat_ip}")
            
            # Проверяем что heartbeat_ip не является VPN IP
            try:
                vpn_network = ip_network(node.ip_pool, strict=False)
                ip_addr = IPv4Address(node.heartbeat_ip)
                if ip_addr in vpn_network:
                    issues.append(f"⚠️  Heartbeat IP ({node.heartbeat_ip}) является VPN IP")
                else:
                    print(f"✅ Heartbeat IP ({node.heartbeat_ip}) не является VPN IP")
            except (ValueError, AttributeError):
                pass
        
        # Проверка heartbeat_interfaces
        if node.heartbeat_interfaces:
            try:
                interfaces = json.loads(node.heartbeat_interfaces)
                print(f"\nИнтерфейсы из heartbeat:")
                real_ips = []
                vpn_ips = []
                
                vpn_network = ip_network(node.ip_pool, strict=False)
                
                for iface in interfaces:
                    if 'ip' in iface:
                        ip = iface['ip'].split('/')[0]
                        try:
                            ip_addr = IPv4Address(ip)
                            if ip_addr in vpn_network:
                                vpn_ips.append(ip)
                            else:
                                real_ips.append(ip)
                        except ValueError:
                            pass
                
                if real_ips:
                    print(f"  ✅ Реальные IP: {', '.join(real_ips)}")
                if vpn_ips:
                    print(f"  ⚠️  VPN IP: {', '.join(vpn_ips)}")
                
                if not real_ips:
                    issues.append(f"❌ Не найдено реальных внешних IP в heartbeat_interfaces")
            except Exception as e:
                issues.append(f"⚠️  Ошибка парсинга heartbeat_interfaces: {e}")
    
    # Проверка публичного ключа
    if not node.public_key:
        issues.append(f"❌ Публичный ключ не указан")
    else:
        print(f"✅ Публичный ключ: {node.public_key[:16]}...")
    
    # Вывод результатов
    if issues:
        print(f"\n⚠️  Обнаружены проблемы:")
        for issue in issues:
            print(f"  {issue}")
        return False
    else:
        print(f"\n✅ Проблем не обнаружено")
        return True


def check_peer_connectivity(interface_name, peer_ip):
    """Проверяет связность с пиром"""
    print(f"\n{'='*60}")
    print(f"Проверка связности с пиром: {peer_ip}")
    print(f"{'='*60}")
    
    # Проверяем последнее handshake
    try:
        result = subprocess.run(
            ["sudo", "wg", "show", interface_name, "dump"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if peer_ip in line:
                    parts = line.split('\t')
                    if len(parts) >= 6:
                        latest_handshake = parts[5]
                        if latest_handshake == '0':
                            print(f"⚠️  Handshake не произошел (peer не подключен)")
                            return False
                        else:
                            print(f"✅ Последний handshake: {latest_handshake} секунд назад")
                            return True
    except Exception as e:
        print(f"❌ Ошибка при проверке handshake: {e}")
        return False
    
    print(f"⚠️  Peer {peer_ip} не найден в конфигурации")
    return False


def ping_test(ip):
    """Тестирует ping до IP адреса"""
    print(f"\n{'='*60}")
    print(f"Тест ping до: {ip}")
    print(f"{'='*60}")
    
    try:
        result = subprocess.run(
            ["ping", "-c", "3", "-W", "2", ip],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            print(f"✅ Ping успешен")
            print(result.stdout)
            return True
        else:
            print(f"❌ Ping не удался")
            print(result.stderr)
            return False
    except Exception as e:
        print(f"❌ Ошибка при выполнении ping: {e}")
        return False


def main():
    """Основная функция"""
    print("=" * 60)
    print("WireGuard Configuration Diagnostic Tool")
    print("=" * 60)
    
    with app.app_context():
        # Получаем все узлы
        nodes = General.query.all()
        
        print(f"\nНайдено узлов: {len(nodes)}")
        
        # Проверяем каждый узел
        for node in nodes:
            if node.role == 'Omnissiah':
                # Проверяем интерфейс Omnissiah
                check_wireguard_interface(node.name)
                check_wireguard_config_file(node.name)
            
            # Проверяем конфигурацию узла
            check_node_configuration(node)
            
            # Если это Magos, проверяем связность
            if node.role == 'Magos':
                omnissiah = General.query.filter_by(role='Omnissiah').first()
                if omnissiah:
                    vpn_ip = node.ip_pool.split('/')[0] if node.ip_pool else None
                    if vpn_ip:
                        print(f"\n{'='*60}")
                        print(f"Тестирование связи Magos ({node.name}) с Omnissiah")
                        print(f"{'='*60}")
                        
                        # Проверяем ping до VPN IP Omnissiah
                        omnissiah_vpn_ip = omnissiah.ip_pool.split('/')[0] if omnissiah.ip_pool else None
                        if omnissiah_vpn_ip:
                            ping_test(omnissiah_vpn_ip)
                        
                        # Проверяем ping до VPN IP Magos с Omnissiah
                        ping_test(vpn_ip)
        
        print(f"\n{'='*60}")
        print("Диагностика завершена")
        print(f"{'='*60}")


if __name__ == '__main__':
    main()

