"""
Модуль для генерации конфигурации WireGuard на агенте
В ZTN архитектуре агент сам генерирует конфигурацию для подключения к Omnissiah
"""
import os
import sys
from pathlib import Path
from app.config import load_config


def generate_wg_config_for_agent():
    """
    Генерирует базовую конфигурацию WireGuard для агента
    Конфигурация позволяет подключиться только к Omnissiah, не блокируя другой трафик
    
    Returns:
        str: Содержимое конфигурации WireGuard или None при ошибке
    """
    try:
        config = load_config()
        config_path = Path(__file__).parent.parent / "setup" / "bootstrap_config.json"
        
        # Получаем необходимые данные из конфигурации
        node_name = config.get('name') or config.get('node_name', '')
        if not node_name:
            print(f"[wg_config_generator] ❌ node_name не найден в конфигурации", file=sys.stderr, flush=True)
            return None
        
        # Получаем приватный ключ (должен быть уже сгенерирован)
        private_key = config.get('private_key')
        if not private_key or not private_key.strip():
            print(f"[wg_config_generator] ❌ private_key не найден в конфигурации", file=sys.stderr, flush=True)
            return None
        
        # Получаем VPN IP из ip_pool
        ip_pool = config.get('ip_pool', '')
        if not ip_pool:
            print(f"[wg_config_generator] ❌ ip_pool не найден в конфигурации", file=sys.stderr, flush=True)
            return None
        
        # Убеждаемся, что ip_pool в правильном формате
        if '/' not in ip_pool:
            ip_pool = f"{ip_pool}/32"
        
        # Получаем информацию об Omnissiah
        omnissiah_public_key = config.get('omnissiah_public_key')
        omnissiah_endpoint = config.get('omnissiah_endpoint')
        omnissiah_listen_port = config.get('omnissiah_listen_port')
        omnissiah_ip_pool = config.get('omnissiah_ip_pool', '')
        
        if not omnissiah_public_key:
            print(f"[wg_config_generator] ⚠️ omnissiah_public_key не найден в конфигурации, конфигурация будет без peer", file=sys.stderr, flush=True)
        
        # Получаем DNS и MTU из конфигурации
        dns = config.get('dns', '1.1.1.1')
        mtu = config.get('mtu', 1420)
        listen_port = config.get('listen_port')
        
        # Генерируем конфигурацию WireGuard
        config_content = f"""[Interface]
PrivateKey = {private_key.strip()}
Address = {ip_pool}
DNS = {dns}
MTU = {mtu}
"""
        
        # Добавляем ListenPort для Magos
        if listen_port:
            config_content += f"ListenPort = {listen_port}\n"
        
        # Добавляем peer для Omnissiah
        if omnissiah_public_key:
            # Определяем AllowedIPs - только VPN сеть Omnissiah, не весь трафик
            # Это позволяет не блокировать другой трафик
            if omnissiah_ip_pool:
                # Используем VPN сеть Omnissiah (например, 11.11.11.0/24)
                # Но для подключения нужен только VPN IP Omnissiah, не вся сеть
                # Извлекаем первый IP из сети Omnissiah
                omnissiah_network_base = omnissiah_ip_pool.split('/')[0]
                # Используем только VPN IP Omnissiah, не всю сеть
                omnissiah_network = f"{omnissiah_network_base}/32"
            else:
                # Fallback: используем только VPN IP Omnissiah
                if omnissiah_endpoint:
                    # Пробуем извлечь IP из endpoint
                    endpoint_ip = omnissiah_endpoint.split(':')[0] if ':' in omnissiah_endpoint else omnissiah_endpoint
                    omnissiah_network = f"{endpoint_ip}/32"
                else:
                    # Используем только VPN IP из ip_pool (первый IP в сети)
                    # Это не идеально, но лучше чем 0.0.0.0/0
                    ip_base = ip_pool.split('/')[0]
                    ip_parts = ip_base.split('.')
                    if len(ip_parts) == 4:
                        # Используем первый IP в сети (например, если наш IP 10.11.11.81, то Omnissiah может быть 10.11.11.1)
                        network_base = '.'.join(ip_parts[:3]) + '.1/32'
                        omnissiah_network = network_base
                    else:
                        omnissiah_network = f"{ip_base}/32"
            
            config_content += f"""
[Peer]
PublicKey = {omnissiah_public_key.strip()}
AllowedIPs = {omnissiah_network}
PersistentKeepalive = 25
"""
            
            # Добавляем Endpoint если есть
            if omnissiah_endpoint and omnissiah_listen_port:
                endpoint_ip = omnissiah_endpoint.split(':')[0] if ':' in omnissiah_endpoint else omnissiah_endpoint
                config_content += f"Endpoint = {endpoint_ip}:{omnissiah_listen_port}\n"
            elif omnissiah_endpoint:
                endpoint_ip = omnissiah_endpoint.split(':')[0] if ':' in omnissiah_endpoint else omnissiah_endpoint
                config_content += f"Endpoint = {endpoint_ip}\n"
            
            # Добавляем PresharedKey если есть
            preshared_key = config.get('preshared_key')
            if preshared_key:
                config_content += f"PresharedKey = {preshared_key}\n"
        
        print(f"[wg_config_generator] ✅ Конфигурация WireGuard сгенерирована для {node_name}", file=sys.stderr, flush=True)
        return config_content
        
    except Exception as e:
        print(f"[wg_config_generator] ❌ Ошибка генерации конфигурации WireGuard: {e}", file=sys.stderr, flush=True)
        import traceback
        print(f"[wg_config_generator] Traceback: {traceback.format_exc()}", file=sys.stderr, flush=True)
        return None


def save_wg_config(config_content, node_name=None):
    """
    Сохраняет конфигурацию WireGuard в файл
    
    Args:
        config_content: Содержимое конфигурации
        node_name: Имя узла (опционально, будет взято из конфигурации)
    
    Returns:
        str: Путь к сохраненному файлу или None при ошибке
    """
    try:
        if not config_content:
            print(f"[wg_config_generator] ❌ Пустая конфигурация, не сохраняем", file=sys.stderr, flush=True)
            return None
        
        config = load_config()
        if not node_name:
            node_name = config.get('name') or config.get('node_name', 'wg0')
        
        # Определяем путь к конфигурации
        setup_dir = Path(__file__).parent.parent / "setup"
        setup_dir.mkdir(parents=True, exist_ok=True)
        
        config_file = setup_dir / f"{node_name}.conf"
        
        # Сохраняем конфигурацию
        with open(config_file, 'w') as f:
            f.write(config_content)
        
        # Устанавливаем права доступа (600 - только владелец может читать/писать)
        os.chmod(config_file, 0o600)
        
        print(f"[wg_config_generator] ✅ Конфигурация WireGuard сохранена: {config_file}", file=sys.stderr, flush=True)
        return str(config_file)
        
    except Exception as e:
        print(f"[wg_config_generator] ❌ Ошибка сохранения конфигурации WireGuard: {e}", file=sys.stderr, flush=True)
        import traceback
        print(f"[wg_config_generator] Traceback: {traceback.format_exc()}", file=sys.stderr, flush=True)
        return None


def generate_and_save_wg_config():
    """
    Генерирует и сохраняет конфигурацию WireGuard для агента
    
    Returns:
        str: Путь к сохраненному файлу или None при ошибке
    """
    config_content = generate_wg_config_for_agent()
    if config_content:
        return save_wg_config(config_content)
    return None

