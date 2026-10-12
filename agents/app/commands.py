import requests
import subprocess
from app.mtls_client import get_mtls_session_from_config

def fetch_and_execute_commands(config):
    url = config['server_url'].rstrip('/') + '/api/magos/commands'
    headers = {
        'Authorization': f"Bearer {config.get('api_token', '')}"
    }

    try:
        # Используем mTLS сессию, если доступна
        mtls_session = get_mtls_session_from_config(config)
        if mtls_session:
            try:
                response = mtls_session.get(url, headers=headers, timeout=5)
                response.raise_for_status()
                commands = response.json().get('commands', [])
                for cmd in commands:
                    execute_command(cmd)
                print(f"[commands] Команды получены через mTLS")
                return
            except Exception as e:
                print(f"[commands] Ошибка mTLS запроса, пробуем без mTLS: {e}")
        
        # Fallback: обычный HTTP запрос
        response = requests.get(url, headers=headers, timeout=5, verify=False)
        response.raise_for_status()
        commands = response.json().get('commands', [])
        for cmd in commands:
            execute_command(cmd)
        print(f"[commands] Команды получены (без mTLS)")
    except Exception as e:
        print(f"[commands] Ошибка получения/выполнения команд: {e}")

def execute_command(cmd):
    cmd_type = cmd.get('type')

    if cmd_type == 'restart':
        print("[command] Перезапуск системы...")
        subprocess.call(["sudo", "reboot"])
    elif cmd_type == 'set_ip':
        new_ip = cmd.get('value')
        if new_ip:
            subprocess.call(["sudo", "ip", "addr", "add", new_ip, "dev", "eth0"])
            print(f"[command] IP изменен на {new_ip}")
    elif cmd_type == 'firewall_on':
        subprocess.call(["sudo", "ufw", "enable"])
        print("[command] Фаервол включен")
    elif cmd_type == 'firewall_off':
        subprocess.call(["sudo", "ufw", "disable"])
        print("[command] Фаервол выключен")
    elif cmd_type == 'upgrade':
        subprocess.call(["sudo", "apt", "update"])
        subprocess.call(["sudo", "apt", "upgrade", "-y"])
        print("[command] Обновление завершено")
    else:
        print(f"[command] Неизвестная команда: {cmd_type}")