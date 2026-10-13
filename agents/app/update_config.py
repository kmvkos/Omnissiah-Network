"""
Модуль для обновления WireGuard конфигурации на Magos агенте
"""
import os
import base64
import subprocess
import configparser
from pathlib import Path
from cryptography.fernet import Fernet
from app.config import load_config
from app.wg_utils import add_peer_to_wireguard, remove_peer_from_wireguard, get_wireguard_status


def get_decryption_cipher():
    """
    Получает cipher suite для расшифровки конфигурации
    
    Returns:
        Fernet cipher или None если ключ недоступен
    """
    try:
        # Пытаемся получить WG_MASTER_KEY из переменных окружения
        master_key = os.environ.get('WG_MASTER_KEY')
        if not master_key:
            # Пытаемся загрузить из bootstrap_config.json
            config = load_config()
            master_key = config.get('master_key')
        
        if not master_key:
            return None
        
        return Fernet(master_key.encode())
    except Exception as e:
        print(f"[update_config] Ошибка инициализации cipher: {e}")
        return None


def decrypt_config(encrypted_b64):
    """
    Расшифровывает WireGuard конфигурацию
    
    Args:
        encrypted_b64: Base64-кодированная зашифрованная конфигурация
    
    Returns:
        str: Расшифрованная конфигурация или None при ошибке
    """
    try:
        cipher = get_decryption_cipher()
        if not cipher:
            return None
        
        encrypted_data = base64.b64decode(encrypted_b64)
        decrypted = cipher.decrypt(encrypted_data)
        return decrypted.decode('utf-8')
    except Exception as e:
        print(f"[update_config] Ошибка расшифровки: {e}")
        return None


def apply_wg_config(config_content, interface_name="wg0", config_file_path=None):
    """
    Применяет новую WireGuard конфигурацию
    
    Стратегия: обновляем конфигурацию через wg set команды вместо перезапуска интерфейса
    Это минимизирует разрыв соединения
    
    Args:
        config_content: Содержимое WireGuard конфигурации (строка)
        interface_name: Имя интерфейса WireGuard
        config_file_path: Путь к конфигурационному файлу (опционально)
    
    Returns:
        bool: True если успешно, False при ошибке
    """
    try:
        # Парсим конфигурацию как INI файл
        config_parser = configparser.ConfigParser(allow_no_value=True)
        # ConfigParser требует секции, а WireGuard конфигурация может иметь несколько [Peer]
        # Разбиваем на секции вручную
        lines = config_content.strip().split('\n')
        current_section = None
        parsed_content = {}
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            if line.startswith('[') and line.endswith(']'):
                current_section = line[1:-1]
                if current_section not in parsed_content:
                    parsed_content[current_section] = {}
            elif current_section:
                if '=' in line:
                    key, value = line.split('=', 1)
                    parsed_content[current_section][key.strip()] = value.strip()
                else:
                    # Некоторые поля без значения
                    parsed_content[current_section][line] = None
        
        # Определяем путь к конфигурационному файлу
        if not config_file_path:
            # Стандартные пути для WireGuard
            standard_paths = [
                f"/etc/wireguard/{interface_name}.conf",
                Path(__file__).parent.parent / "setup" / f"{interface_name}.conf"
            ]
            for path in standard_paths:
                if Path(path).exists():
                    config_file_path = path
                    break
        
        if not config_file_path:
            # Создаем стандартный путь
            config_file_path = Path(__file__).parent.parent / "setup" / f"{interface_name}.conf"
            config_file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Получаем текущие peers (чтобы удалить старые)
        result = subprocess.run(
            ['sudo', '-n', 'wg', 'show', interface_name, 'dump'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10
        )
        
        old_peers = set()
        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                parts = line.split('\t')
                if len(parts) >= 1:
                    old_peers.add(parts[0])  # Первый столбец - публичный ключ
        
        # Обрабатываем [Interface] секцию (пока не обновляем, только логируем)
        if 'Interface' in parsed_content:
            interface = parsed_content['Interface']
            print(f"[update_config] Интерфейс: {interface_name}")
        
        # Обрабатываем [Peer] секции
        new_peers = set()
        peer_count = 0
        for section_name in parsed_content:
            if section_name == 'Interface':
                continue
            
            # Это секция [Peer] (может быть несколько с одинаковым именем)
            peer = parsed_content[section_name]
            public_key = peer.get('PublicKey', '').strip()
            if not public_key:
                continue
            
            new_peers.add(public_key)
            peer_count += 1
            
            # Формируем команду wg set
            cmd = ['sudo', '-n', 'wg', 'set', interface_name, 'peer', public_key]
            
            allowed_ips = peer.get('AllowedIPs', '').strip()
            if allowed_ips:
                cmd.extend(['allowed-ips', allowed_ips])
            
            keepalive = peer.get('PersistentKeepalive', '').strip()
            if keepalive:
                cmd.extend(['persistent-keepalive', keepalive])
            
            endpoint = peer.get('Endpoint', '').strip()
            if endpoint:
                cmd.extend(['endpoint', endpoint])
            
            preshared_key = peer.get('PresharedKey', '').strip()
            try:
                if preshared_key:
                    # Передаем через stdin
                    result = subprocess.run(
                        cmd + ['preshared-key', '/dev/stdin'],
                        input=preshared_key.encode(),
                        check=True,
                        timeout=10,
                        stderr=subprocess.PIPE,
                        stdout=subprocess.PIPE
                    )
                else:
                    result = subprocess.run(cmd, check=True, timeout=10,
                                          stderr=subprocess.PIPE, stdout=subprocess.PIPE)
                
                print(f"[update_config] ✅ Peer {public_key[:8]}... добавлен/обновлен")
            except subprocess.CalledProcessError as e:
                print(f"[update_config] ⚠️  Ошибка добавления peer {public_key[:8]}...: {e.stderr.decode() if e.stderr else str(e)}")
                # Продолжаем обработку остальных peers
        
        # Удаляем старые peers, которых нет в новой конфигурации
        peers_to_remove = old_peers - new_peers
        for peer_key in peers_to_remove:
            try:
                subprocess.run(
                    ['sudo', '-n', 'wg', 'set', interface_name, 'peer', peer_key, 'remove'],
                    check=True,
                    timeout=10,
                    stderr=subprocess.PIPE,
                    stdout=subprocess.PIPE
                )
                print(f"[update_config] ✅ Старый peer {peer_key[:8]}... удален")
            except Exception as e:
                print(f"[update_config] ⚠️  Не удалось удалить peer {peer_key[:8]}...: {e}")
        
        # Сохраняем обновленную конфигурацию в файл
        temp_config = config_file_path.with_suffix('.conf.tmp')
        with open(temp_config, 'w') as f:
            f.write(config_content)
        
        # Проверяем синтаксис
        result = subprocess.run(
            ['sudo', '-n', 'wg-quick', 'strip', str(temp_config)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10
        )
        
        if result.returncode != 0:
            print(f"[update_config] ⚠️  Предупреждение валидации: {result.stderr.decode()}")
        
        # Сохраняем конфигурацию
        subprocess.run(['sudo', '-n', 'cp', str(temp_config), str(config_file_path)], check=True)
        subprocess.run(['sudo', '-n', 'chmod', '600', str(config_file_path)], check=True)
        temp_config.unlink()
        
        # Сохраняем текущее состояние через wg-quick save (если доступно)
        try:
            subprocess.run(['sudo', '-n', 'wg-quick', 'save', interface_name], 
                          stderr=subprocess.DEVNULL, timeout=5)
        except:
            pass  # Не критично
        
        print(f"[update_config] ✅ Конфигурация успешно применена (hot-reload, {peer_count} peers)")
        return True
        
    except Exception as e:
        print(f"[update_config] Ошибка применения конфигурации: {e}")
        import traceback
        print(f"[update_config] Детали: {traceback.format_exc()}")
        return False
