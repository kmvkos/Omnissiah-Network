# -*- coding: utf-8 -*-
"""
Утилиты для автоматической настройки межсетевого экрана
"""

import subprocess
import ipaddress
from typing import Optional, Tuple


def setup_magos_firewall(omnissiah_ip: str, ssh_client=None, sudo_password: Optional[str] = None, admin_ip: Optional[str] = None) -> Tuple[bool, str]:
    """
    Настройка межсетевого экрана на Magos узле
    
    КРИТИЧНО: Использует РЕАЛЬНЫЕ IP адреса (не VPN), так как развертывание идет по реальному IP
    
    Правила:
    - Разрешить SSH с Omnissiah (реальный IP) и администратора (реальный IP)
    - Разрешить mTLS (порт 5001) с Omnissiah (реальный IP)
    - Разрешить ICMP (ping)
    - Разрешить весь исходящий трафик (OUTPUT ACCEPT)
    - Политика INPUT DROP (но OUTPUT остается ACCEPT)
    
    Args:
        omnissiah_ip: РЕАЛЬНЫЙ IP адрес главного узла Omnissiah (из endpoint, не VPN!)
        ssh_client: Объект SSH клиента (paramiko.SSHClient), если None - настраивается локально
        sudo_password: Пароль для sudo команд на удаленном узле
        admin_ip: РЕАЛЬНЫЙ IP адрес администратора (опционально)
        
    Returns:
        Tuple[bool, str]: (успех, сообщение)
    """
    try:
        # Определяем порты
        mtls_port = 5001  # Порт mTLS агента
        ssh_port = 22
        
        # КРИТИЧНО: Порядок применения правил очень важен!
        # 1. Сначала устанавливаем политики ACCEPT (чтобы не разорвать SSH)
        # 2. Очищаем существующие правила
        # 3. Добавляем все правила
        # 4. Устанавливаем политику INPUT DROP (но OUTPUT остается ACCEPT!)
        
        commands = [
            # ШАГ 1: Устанавливаем политики ACCEPT ПЕРЕД очисткой
            # Это критично - чтобы SSH соединение не разорвалось
            "iptables -P INPUT ACCEPT",
            "iptables -P OUTPUT ACCEPT",
            "iptables -P FORWARD ACCEPT",
            
            # ШАГ 2: Очищаем существующие правила (теперь безопасно, так как политики ACCEPT)
            "iptables -F",
            "iptables -X",
            "iptables -t nat -F",
            "iptables -t nat -X",
            
            # ШАГ 3: Добавляем все правила
            
            # Базовые правила: loopback
            "iptables -A INPUT -i lo -j ACCEPT",
            "iptables -A OUTPUT -o lo -j ACCEPT",
            
            # Разрешить установленные соединения (критично для работы SSH!)
            "iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT",
            "iptables -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT",
            
            # SSH правила с РЕАЛЬНЫМИ IP адресами
            
            # SSH разрешен с Omnissiah (реальный IP)
            f"iptables -A INPUT -p tcp --dport {ssh_port} -s {omnissiah_ip} -j ACCEPT",
            f"iptables -A OUTPUT -p tcp --dport {ssh_port} -d {omnissiah_ip} -j ACCEPT",
            
            # SSH разрешен с администратора (реальный IP, если указан)
        ]
        
        # Добавляем правила для администратора если указан
        if admin_ip:
            commands.extend([
                f"iptables -A INPUT -p tcp --dport {ssh_port} -s {admin_ip} -j ACCEPT",
                f"iptables -A OUTPUT -p tcp --dport {ssh_port} -d {admin_ip} -j ACCEPT",
            ])
        
        # Продолжаем добавлять правила
        commands.extend([
            # ICMP (ping) разрешен
            "iptables -A INPUT -p icmp -j ACCEPT",
            "iptables -A OUTPUT -p icmp -j ACCEPT",
            
            # mTLS разрешен с Omnissiah (реальный IP)
            f"iptables -A INPUT -p tcp --dport {mtls_port} -s {omnissiah_ip} -j ACCEPT",
            
            # VPN (WireGuard) разрешен с Omnissiah (реальный IP)
            f"iptables -A INPUT -p udp --dport 51820 -s {omnissiah_ip} -j ACCEPT",
            
            # КРИТИЧНО: Разрешить весь исходящий трафик (ПЕРЕД политикой DROP!)
            "iptables -A OUTPUT -j ACCEPT",
            
            # ШАГ 4: Устанавливаем политику INPUT DROP (но OUTPUT остается ACCEPT!)
            "iptables -P INPUT DROP",
            # OUTPUT НЕ устанавливаем в DROP - остается ACCEPT!
        ])
        
        if ssh_client:
            # Выполняем команды через SSH
            for cmd in commands:
                try:
                    if sudo_password:
                        # Используем безопасный способ передачи пароля
                        import shlex
                        escaped_password = shlex.quote(sudo_password)
                        # Команда должна быть без sudo в начале, так как мы добавляем sudo -S
                        cmd_without_sudo = cmd.replace('sudo ', '') if cmd.startswith('sudo ') else cmd
                        escaped_cmd = shlex.quote(cmd_without_sudo)
                        full_cmd = f"echo {escaped_password} | sudo -S {escaped_cmd}"
                    else:
                        full_cmd = f"sudo -n {cmd}"
                    
                    stdin, stdout, stderr = ssh_client.exec_command(full_cmd, timeout=10)
                    # КРИТИЧНО: Читаем вывод СРАЗУ, иначе команда может не выполниться
                    stdout_output = stdout.read().decode()
                    stderr_output = stderr.read().decode()
                    # Получаем статус ПОСЛЕ чтения вывода
                    exit_status = stdout.channel.recv_exit_status()
                    
                    if exit_status != 0:
                        # Игнорируем ошибки для команд сохранения
                        if "save" in cmd.lower() or "which" in cmd.lower():
                            continue
                        error_msg = f"Ошибка выполнения команды: {cmd}\n"
                        if stderr_output:
                            error_msg += f"stderr: {stderr_output}\n"
                        if stdout_output:
                            error_msg += f"stdout: {stdout_output}"
                        return False, error_msg
                except Exception as cmd_error:
                    # Игнорируем ошибки для команд сохранения
                    if "save" in cmd.lower() or "which" in cmd.lower():
                        continue
                    return False, f"Ошибка выполнения команды {cmd}: {str(cmd_error)}"
        else:
            # Выполняем локально
            for cmd in commands:
                try:
                    result = subprocess.run(
                        ['sudo', '-n'] + cmd.split(),
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    if result.returncode != 0:
                        # Игнорируем ошибки сохранения, если утилиты нет
                        if "save" in cmd.lower() or "which" in cmd.lower():
                            continue
                        return False, f"Ошибка выполнения команды: {cmd}\n{result.stderr}"
                except Exception as cmd_error:
                    # Игнорируем ошибки для команд сохранения
                    if "save" in cmd.lower() or "which" in cmd.lower():
                        continue
                    return False, f"Ошибка выполнения команды {cmd}: {str(cmd_error)}"
        
        return True, "Межсетевой экран настроен успешно"
        
    except Exception as e:
        return False, f"Ошибка настройки межсетевого экрана: {str(e)}"


def check_network_accessible_via_interface(network: str, interface: str, 
                                         ssh_client=None, sudo_password: Optional[str] = None) -> Tuple[bool, str]:
    """
    Проверяет, доступна ли сеть через указанный интерфейс
    
    Args:
        network: IP или подсеть (например, 192.168.200.1/24)
        interface: Имя интерфейса (например, eth0)
        ssh_client: SSH клиент для удаленной проверки, если None - локально
        sudo_password: Пароль для sudo на удаленном узле
        
    Returns:
        Tuple[bool, str]: (доступна, сообщение)
    """
    try:
        # Парсим сеть
        try:
            net = ipaddress.ip_network(network, strict=False)
        except ValueError:
            return False, f"Неверный формат сети: {network}"
        
        # Команда для получения IP адресов интерфейса
        if ssh_client:
            cmd = f"ip addr show {interface} | grep 'inet ' | awk '{{print $2}}'"
            if sudo_password:
                full_cmd = f"echo '{sudo_password}' | sudo -S {cmd}"
            else:
                full_cmd = f"sudo {cmd}"
            
            stdin, stdout, stderr = ssh_client.exec_command(full_cmd, timeout=5)
            output = stdout.read().decode().strip()
            stderr_output = stderr.read().decode()
            exit_status = stdout.channel.recv_exit_status()
            
            if exit_status != 0:
                return False, f"Интерфейс {interface} не найден или недоступен"
            
            interface_ips = output.split('\n') if output else []
        else:
            # Локальная проверка
            result = subprocess.run(
                ['ip', 'addr', 'show', interface],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode != 0:
                return False, f"Интерфейс {interface} не найден или недоступен"
            
            # Парсим вывод ip addr show
            import re
            interface_ips = re.findall(r'inet (\S+)', result.stdout)
        
        # Проверяем, есть ли IP адреса интерфейса в указанной сети
        for ip_str in interface_ips:
            try:
                # Убираем маску если есть (например, 192.168.1.1/24 -> 192.168.1.1)
                ip_addr = ipaddress.ip_address(ip_str.split('/')[0])
                if ip_addr in net:
                    return True, f"Сеть доступна через интерфейс {interface} (IP: {ip_str})"
            except ValueError:
                continue
        
        return False, f"Интерфейс {interface} не имеет IP адресов в сети {network}"
        
    except Exception as e:
        return False, f"Ошибка проверки доступности сети: {str(e)}"

