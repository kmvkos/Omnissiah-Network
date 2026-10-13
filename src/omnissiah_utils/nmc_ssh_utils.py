"""
Утилиты для SSH подключений с поддержкой ключей
Используется только для критических операций (включение/выключение VPN)
"""
import paramiko
import os
import socket
import logging
from pathlib import Path
from typing import Optional, Tuple

# Инициализация logger для этого модуля
logger = logging.getLogger(__name__)


def connect_ssh_with_key_or_password(
    hostname: str,
    username: str,
    password: Optional[str] = None,
    key_file: Optional[str] = None,
    key_data: Optional[str] = None,
    timeout: int = 30
) -> Tuple[Optional[paramiko.SSHClient], Optional[str]]:
    """
    Подключается к SSH используя ключ или пароль
    
    Приоритет:
    1. key_file (путь к файлу ключа)
    2. key_data (содержимое ключа как строка)
    3. password (пароль)
    
    Args:
        hostname: IP адрес или hostname
        username: Имя пользователя
        password: Пароль (если нет ключа)
        key_file: Путь к файлу приватного ключа
        key_data: Содержимое приватного ключа (строка)
        timeout: Timeout подключения
    
    Returns:
        tuple: (ssh_client, error_message)
    """
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    # Параметры для ускорения подключения и избежания таймаутов
    connect_kwargs = {
        'timeout': timeout,
        'look_for_keys': False,      # Не ищем ключи автоматически (экономит время)
        'allow_agent': False,       # Не используем SSH агент
        'banner_timeout': 15,       # Timeout для баннера SSH (увеличено)
        'auth_timeout': timeout - 5  # Timeout для аутентификации (чуть меньше основного)
    }
    
    try:
        # Пробуем подключиться по ключу
        if key_file and os.path.exists(key_file):
            try:
                key = paramiko.RSAKey.from_private_key_file(key_file)
                ssh.connect(hostname, username=username, pkey=key, **connect_kwargs)
                return ssh, None
            except Exception as e:
                # Пробуем ED25519 ключ
                try:
                    key = paramiko.ed25519key.Ed25519Key.from_private_key_file(key_file)
                    ssh.connect(hostname, username=username, pkey=key, **connect_kwargs)
                    return ssh, None
                except (paramiko.AuthenticationException, paramiko.SSHException, OSError, ValueError) as e:
                    # Игнорируем ошибки аутентификации по ED25519 ключу
                    logger.debug(f"Не удалось подключиться по ED25519 ключу: {e}")
                    pass
                # Если не получилось, пробуем пароль
        
        if key_data:
            try:
                from io import StringIO
                key_file_obj = StringIO(key_data)
                key = paramiko.RSAKey.from_private_key_file(key_file_obj)
                ssh.connect(hostname, username=username, pkey=key, **connect_kwargs)
                return ssh, None
            except Exception as e:
                # Пробуем ED25519
                try:
                    from io import StringIO
                    key_file_obj = StringIO(key_data)
                    key = paramiko.ed25519key.Ed25519Key.from_private_key_file(key_file_obj)
                    ssh.connect(hostname, username=username, pkey=key, **connect_kwargs)
                    return ssh, None
                except (paramiko.AuthenticationException, paramiko.SSHException, OSError, ValueError) as e:
                    # Игнорируем ошибки аутентификации по ED25519 ключу
                    logger.debug(f"Не удалось подключиться по ED25519 ключу: {e}")
                    pass
        
        # Используем пароль если нет ключа
        if password:
            try:
                ssh.connect(hostname, username=username, password=password, **connect_kwargs)
                return ssh, None
            except socket.timeout:
                return None, "Таймаут подключения. Проверьте доступность узла и сетевые настройки."
            except Exception as e:
                raise  # Пробрасываем исключение дальше для обработки
        
        return None, "Не указан ни ключ, ни пароль для SSH подключения"
    
    except paramiko.AuthenticationException:
        return None, "SSH аутентификация не удалась. Проверьте логин и пароль."
    except paramiko.SSHException as e:
        return None, f"SSH ошибка: {str(e)}"
    except socket.timeout:
        return None, "Таймаут подключения. Узел недоступен или не отвечает."
    except socket.error as e:
        return None, f"Ошибка сетевого подключения: {str(e)}"
    except Exception as e:
        error_msg = str(e)
        # Избегаем дублирования сообщения об ошибке
        if 'timed out' in error_msg.lower():
            return None, "Таймаут подключения"
        return None, f"Ошибка SSH подключения: {error_msg}"


def get_default_ssh_key_path(node_name: Optional[str] = None) -> Optional[str]:
    """
    Получает путь к SSH ключу по умолчанию для узла
    
    Ищет ключ в стандартных местах:
    - ~/.ssh/nmcwg_{node_name}_id_rsa
    - ~/.ssh/nmcwg_id_rsa
    - ~/.ssh/id_rsa
    
    Args:
        node_name: Имя узла (опционально)
    
    Returns:
        Путь к ключу или None
    """
    home = Path.home()
    ssh_dir = home / '.ssh'
    
    # Пробуем узкоспецифичный ключ
    if node_name:
        key_paths = [
            ssh_dir / f'nmcwg_{node_name}_id_rsa',
            ssh_dir / f'nmcwg_{node_name}_id_ed25519',
        ]
        for key_path in key_paths:
            if key_path.exists():
                return str(key_path)
    
    # Пробуем общий ключ NMC
    key_paths = [
        ssh_dir / 'nmcwg_id_rsa',
        ssh_dir / 'nmcwg_id_ed25519',
        ssh_dir / 'id_rsa',
        ssh_dir / 'id_ed25519',
    ]
    
    for key_path in key_paths:
        if key_path.exists():
            return str(key_path)
    
    return None

