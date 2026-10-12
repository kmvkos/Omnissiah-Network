"""
Утилиты для работы с WireGuard конфигурационными файлами и операциями
"""
import re
import os
import subprocess
import requests
from pathlib import Path
from typing import Tuple, Optional


def comment_peer_in_config(interface_name: str, peer_public_key: str, config_path: Optional[str] = None) -> Tuple[bool, str]:
    """
    Комментирует peer в WireGuard конфигурационном файле
    
    Args:
        interface_name: Имя интерфейса WireGuard (например, 'n1')
        peer_public_key: Публичный ключ peer для комментирования
        config_path: Путь к конфигурационному файлу (если None, используется /etc/wireguard/{interface_name}.conf)
    
    Returns:
        Tuple[bool, str]: (успех, сообщение)
    """
    try:
        if config_path is None:
            config_path = f"/etc/wireguard/{interface_name}.conf"
        
        if not os.path.exists(config_path):
            return False, f"Конфигурационный файл {config_path} не найден"
        
        # Читаем конфигурационный файл
        with open(config_path, 'r') as f:
            lines = f.readlines()
        
        # Находим секцию [Peer] для указанного публичного ключа
        in_target_peer = False
        peer_start_idx = -1
        modified = False
        
        i = 0
        while i < len(lines):
            stripped = lines[i].strip()
            
            # Начало новой секции [Peer]
            if stripped == '[Peer]' or stripped == '#[Peer]':
                # Если мы уже были в целевой секции, она закончилась
                if in_target_peer:
                    break
                in_target_peer = False
                peer_start_idx = i
                i += 1
                continue
            
            # Проверяем PublicKey в текущей секции (может быть закомментирован)
            if peer_start_idx >= 0:
                match = re.search(r'^#?PublicKey\s*=\s*(.+)', stripped)
                if match:
                    key = match.group(1).strip()
                    if key == peer_public_key:
                        # Нашли нужную секцию!
                        in_target_peer = True
                        # Комментируем [Peer] если не закомментирован
                        if not lines[peer_start_idx].strip().startswith('#'):
                            # Сохраняем отступ
                            original_line = lines[peer_start_idx]
                            indent = len(original_line) - len(original_line.lstrip())
                            lines[peer_start_idx] = ' ' * indent + '#' + original_line.lstrip()
                            modified = True
                        i += 1
                        continue
            
            # Если мы в целевой секции, комментируем все строки до следующей секции
            if in_target_peer:
                if stripped.startswith('[') and not stripped.startswith('#['):
                    # Конец секции (новая незакомментированная секция)
                    break
                # Комментируем строку если она еще не закомментирована и не пустая
                if not stripped.startswith('#') and stripped:
                    # Сохраняем отступ
                    original_line = lines[i]
                    indent = len(original_line) - len(original_line.lstrip())
                    lines[i] = ' ' * indent + '#' + original_line.lstrip()
                    modified = True
            
            i += 1
        
        if not modified:
            # Секция уже закомментирована или не найдена
            return False, "Peer не найден или уже закомментирован"
        
        # Записываем обратно
        with open(config_path, 'w') as f:
            f.writelines(lines)
        
        return True, f"Peer закомментирован в {config_path}"
    
    except Exception as e:
        return False, f"Ошибка комментирования peer: {str(e)}"


def uncomment_peer_in_config(interface_name: str, peer_public_key: str, config_path: Optional[str] = None) -> Tuple[bool, str]:
    """
    Раскомментирует peer в WireGuard конфигурационном файле
    
    Args:
        interface_name: Имя интерфейса WireGuard (например, 'n1')
        peer_public_key: Публичный ключ peer для раскомментирования
        config_path: Путь к конфигурационному файлу (если None, используется /etc/wireguard/{interface_name}.conf)
    
    Returns:
        Tuple[bool, str]: (успех, сообщение)
    """
    try:
        if config_path is None:
            config_path = f"/etc/wireguard/{interface_name}.conf"
        
        if not os.path.exists(config_path):
            return False, f"Конфигурационный файл {config_path} не найден"
        
        # Читаем конфигурационный файл
        with open(config_path, 'r') as f:
            lines = f.readlines()
        
        # Находим закомментированную секцию [Peer] для указанного публичного ключа
        in_target_peer = False
        peer_start_idx = -1
        modified = False
        
        for i, line in enumerate(lines):
            stripped = line.strip()
            
            # Начало новой секции [Peer] (может быть закомментирован)
            if stripped == '[Peer]' or stripped == '#[Peer]':
                # Если мы уже были в целевой секции, она закончилась
                if in_target_peer:
                    break
                in_target_peer = False
                peer_start_idx = i
                continue
            
            # Проверяем PublicKey в текущей секции (может быть закомментирован)
            if peer_start_idx >= 0:
                # Ищем PublicKey даже если он закомментирован
                match = re.search(r'^#?PublicKey\s*=\s*(.+)', stripped)
                if match:
                    key = match.group(1).strip()
                    if key == peer_public_key:
                        # Нашли нужную секцию!
                        in_target_peer = True
                        peer_start_idx = i - 1  # Начало секции [Peer]
                        # Раскомментируем [Peer] если закомментирован
                        if lines[peer_start_idx].strip().startswith('#'):
                            lines[peer_start_idx] = lines[peer_start_idx].lstrip('#')
                            modified = True
                        continue
            
            # Если мы в целевой секции, раскомментируем все закомментированные строки
            if in_target_peer:
                if stripped.startswith('[') and not stripped.startswith('#['):
                    # Конец секции (новая незакомментированная секция)
                    break
                # Раскомментируем строку если она закомментирована
                if stripped.startswith('#') and not stripped.startswith('#['):
                    # Убираем # в начале строки
                    lines[i] = line.lstrip('#')
                    # Восстанавливаем оригинальный отступ
                    original_indent = len(line) - len(line.lstrip())
                    comment_indent = len(line) - len(line.lstrip('#'))
                    if comment_indent < original_indent:
                        lines[i] = ' ' * (original_indent - comment_indent) + lines[i].lstrip()
                    modified = True
        
        if not modified:
            # Секция уже раскомментирована или не найдена
            return False, "Peer не найден или уже раскомментирован"
        
        # Записываем обратно
        with open(config_path, 'w') as f:
            f.writelines(lines)
        
        return True, f"Peer раскомментирован в {config_path}"
    
    except Exception as e:
        return False, f"Ошибка раскомментирования peer: {str(e)}"


def is_peer_commented(interface_name: str, peer_public_key: str, config_path: Optional[str] = None) -> Tuple[Optional[bool], str]:
    """
    Проверяет, закомментирован ли peer в конфигурационном файле
    
    Args:
        interface_name: Имя интерфейса WireGuard
        peer_public_key: Публичный ключ peer
        config_path: Путь к конфигурационному файлу
    
    Returns:
        Tuple[Optional[bool], str]: (None если не найден, True если закомментирован, False если активен, сообщение)
    """
    try:
        if config_path is None:
            config_path = f"/etc/wireguard/{interface_name}.conf"
        
        if not os.path.exists(config_path):
            return None, f"Конфигурационный файл {config_path} не найден"
        
        with open(config_path, 'r') as f:
            lines = f.readlines()
        
        in_target_peer = False
        peer_start_idx = -1
        
        for i, line in enumerate(lines):
            stripped = line.strip()
            
            if stripped == '[Peer]' or stripped == '#[Peer]':
                if in_target_peer:
                    # Конец секции
                    break
                in_target_peer = False
                peer_start_idx = i
                # Проверяем, закомментирован ли [Peer]
                if stripped == '#[Peer]':
                    in_target_peer = True
                continue
            
            if peer_start_idx >= 0:
                match = re.search(r'^#?PublicKey\s*=\s*(.+)', stripped)
                if match:
                    key = match.group(1).strip()
                    if key == peer_public_key:
                        # Проверяем, закомментирован ли [Peer] или PublicKey
                        if lines[peer_start_idx].strip().startswith('#'):
                            return True, "Peer закомментирован"
                        if stripped.startswith('#'):
                            return True, "Peer закомментирован"
                        return False, "Peer активен"
        
        return None, "Peer не найден в конфигурации"
    
    except Exception as e:
        return None, f"Ошибка проверки: {str(e)}"


def validate_interface_name(interface: str) -> bool:
    """
    Валидация имени интерфейса для предотвращения инъекций в subprocess
    
    Args:
        interface: Имя интерфейса для проверки
    
    Returns:
        bool: True если имя валидно, False иначе
    """
    if not interface:
        return False
    # Разрешаем буквы, цифры, дефисы, подчеркивания и точки (для доменных имен типа omnissiah.pro)
    return bool(re.match(r'^[a-zA-Z0-9_.-]+$', interface))


def get_wg_interfaces():
    """
    Возвращает список интерфейсов WireGuard
    
    Returns:
        list: Список имен интерфейсов WireGuard
    """
    try:
        result = subprocess.run(
            ["sudo", "/usr/bin/wg", "show", "interfaces"],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip().split()
    except subprocess.CalledProcessError:
        # Логирование будет выполнено в вызывающем коде
        return []


def generate_wg_keys():
    """
    Генерирует пару ключей WireGuard (приватный и публичный)
    
    Returns:
        Tuple[str, str]: (приватный_ключ, публичный_ключ)
    
    Raises:
        RuntimeError: Если не удалось сгенерировать ключи
    """
    try:
        private_key = subprocess.check_output(
            ["sudo", "-n", "/usr/bin/wg", "genkey"],
            text=True
        ).strip()
        public_key = subprocess.check_output(
            ["sudo", "-n", "/usr/bin/wg", "pubkey"],
            input=private_key,
            text=True
        ).strip()
        return private_key, public_key
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Ошибка генерации ключей: {e.stderr}")


def get_external_ip(logger=None):
    """
    Получает внешний IP адрес сервера
    
    Args:
        logger: Опциональный logger для логирования ошибок
    
    Returns:
        str: Внешний IP адрес или "ВАШ_ВНЕШНИЙ_IP" в случае ошибки
    """
    try:
        return requests.get("https://api.ipify.org", timeout=5).text.strip()
    except (requests.RequestException, requests.Timeout, requests.ConnectionError, ValueError) as e:
        if logger:
            logger.warning(f"Не удалось получить внешний IP: {e}")
        return "ВАШ_ВНЕШНИЙ_IP"


def ping_ip(ip: str) -> bool:
    """
    Проверяет, отвечает ли IP на ping
    
    Args:
        ip: IP адрес для проверки
    
    Returns:
        bool: True если IP отвечает, False иначе
    """
    try:
        subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return True
    except subprocess.CalledProcessError:
        return False

