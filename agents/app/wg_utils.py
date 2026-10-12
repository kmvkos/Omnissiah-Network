"""
Утилиты для работы с WireGuard в Magos агенте
"""
import subprocess
import os
from pathlib import Path


def add_peer_to_wireguard(interface_name, public_key, allowed_ips, preshared_key=None, 
                         keepalive=25, config_path=None):
    """
    Добавляет пира в WireGuard интерфейс
    
    Args:
        interface_name: имя интерфейса WireGuard (например, "wg0")
        public_key: публичный ключ пира
        allowed_ips: разрешенные IP адреса (например, "10.0.0.2/32")
        preshared_key: опциональный preshared key
        keepalive: интервал keepalive в секундах
        config_path: путь к конфигурационному файлу (опционально)
    """
    try:
        # Проверяем, существует ли интерфейс
        result = subprocess.run(
            ['sudo', '-n', 'wg', 'show', interface_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5
        )
        
        if result.returncode != 0:
            print(f"⚠️  Интерфейс {interface_name} не найден или не активен")
            return False
        
        # Собираем команду для добавления пира
        cmd = ['sudo', '-n', 'wg', 'set', interface_name, 'peer', public_key]
        cmd.extend(['allowed-ips', allowed_ips])
        
        if keepalive:
            cmd.extend(['persistent-keepalive', str(keepalive)])
        
        # Если есть preshared key, передаем через stdin
        if preshared_key:
            result = subprocess.run(
                cmd + ['preshared-key', '/dev/stdin'],
                input=preshared_key.encode(),
                check=True,
                timeout=10
            )
        else:
            result = subprocess.run(cmd, check=True, timeout=10)
        
        print(f"✅ Пир {public_key[:8]}... добавлен в {interface_name}")
        
        # Если указан путь к конфигурационному файлу, сохраняем изменения
        if config_path and os.path.exists(config_path):
            try:
                subprocess.run(['sudo', '-n', 'wg-quick', 'save', interface_name], 
                             check=True, timeout=5)
                print(f"✅ Конфигурация сохранена")
            except subprocess.CalledProcessError as e:
                print(f"⚠️  Не удалось сохранить конфигурацию: {e}")
        
        return True
        
    except subprocess.TimeoutExpired:
        print(f"❌ Таймаут при добавлении пира в WireGuard")
        return False
    except subprocess.CalledProcessError as e:
        print(f"❌ Ошибка добавления пира в WireGuard: {e}")
        return False
    except Exception as e:
        print(f"❌ Неожиданная ошибка: {e}")
        return False


def remove_peer_from_wireguard(interface_name, public_key):
    """
    Удаляет пира из WireGuard интерфейса
    
    Args:
        interface_name: имя интерфейса WireGuard
        public_key: публичный ключ пира для удаления
    """
    try:
        result = subprocess.run(
            ['sudo', '-n', 'wg', 'set', interface_name, 'peer', public_key, 'remove'],
            check=True,
            timeout=10
        )
        print(f"✅ Пир {public_key[:8]}... удален из {interface_name}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Ошибка удаления пира: {e}")
        return False
    except Exception as e:
        print(f"❌ Неожиданная ошибка: {e}")
        return False


def get_wireguard_status(interface_name):
    """
    Получает статус интерфейса WireGuard
    
    Args:
        interface_name: имя интерфейса
        
    Returns:
        dict с информацией о статусе или None при ошибке
    """
    try:
        result = subprocess.run(
            ['sudo', '-n', 'wg', 'show', interface_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5
        )
        
        if result.returncode != 0:
            return None
        
        # Парсим вывод wg show
        status = {
            'interface': interface_name,
            'peers': []
        }
        
        current_peer = None
        for line in result.stdout.split('\n'):
            line = line.strip()
            if line.startswith('peer:'):
                if current_peer:
                    status['peers'].append(current_peer)
                current_peer = {'public_key': line.split(':')[1].strip()}
            elif line.startswith('allowed ips:'):
                if current_peer:
                    current_peer['allowed_ips'] = line.split(':')[1].strip()
            elif line.startswith('latest handshake:'):
                if current_peer:
                    current_peer['latest_handshake'] = line.split(':', 1)[1].strip()
            elif line.startswith('transfer:'):
                if current_peer:
                    current_peer['transfer'] = line.split(':', 1)[1].strip()
        
        if current_peer:
            status['peers'].append(current_peer)
        
        return status
        
    except Exception as e:
        print(f"❌ Ошибка получения статуса WireGuard: {e}")
        return None
