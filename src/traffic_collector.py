"""
Модуль для сбора данных трафика через iptables LOG
"""
import subprocess
import re
import json
from datetime import datetime, timezone
from typing import List, Dict, Optional
import logging

logger = logging.getLogger(__name__)


def parse_iptables_log_line(line: str) -> Optional[Dict]:
    """
    Парсит строку лога iptables в формате:
    IN=eth0 OUT= MAC=... SRC=10.0.0.1 DST=10.0.0.2 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=0 DF PROTO=TCP SPT=12345 DPT=80 WINDOW=65535 RES=0x00 SYN URGP=0
    
    Returns:
        dict: Парсированные данные трафика или None
    """
    if not line or 'IN=' not in line:
        return None
    
    try:
        # Извлекаем основные поля
        in_match = re.search(r'IN=(\S+)', line)
        out_match = re.search(r'OUT=(\S+)', line)
        src_match = re.search(r'SRC=(\S+)', line)
        dst_match = re.search(r'DST=(\S+)', line)
        proto_match = re.search(r'PROTO=(\S+)', line)
        spt_match = re.search(r'SPT=(\d+)', line)
        dpt_match = re.search(r'DPT=(\d+)', line)
        len_match = re.search(r'LEN=(\d+)', line)
        
        # Определяем направление
        direction = 'in' if in_match else 'out'
        interface = in_match.group(1) if in_match else (out_match.group(1) if out_match else None)
        
        # Определяем действие (по умолчанию ACCEPT, так как это LOG)
        action = 'ACCEPT'
        
        # Определяем состояние соединения (если есть)
        state_match = re.search(r'STATE=(\S+)', line)
        connection_state = state_match.group(1) if state_match else None
        
        # Определяем размер пакета
        packet_len = int(len_match.group(1)) if len_match else 0
        
        return {
            'source_ip': src_match.group(1) if src_match else None,
            'destination_ip': dst_match.group(1) if dst_match else None,
            'source_port': int(spt_match.group(1)) if spt_match else None,
            'destination_port': int(dpt_match.group(1)) if dpt_match else None,
            'protocol': proto_match.group(1).upper() if proto_match else None,
            'action': action,
            'bytes_sent': packet_len if direction == 'out' else 0,
            'bytes_received': packet_len if direction == 'in' else 0,
            'packets_sent': 1 if direction == 'out' else 0,
            'packets_received': 1 if direction == 'in' else 0,
            'interface': interface,
            'direction': direction,
            'connection_state': connection_state,
            'timestamp': datetime.now(timezone.utc)
        }
    except Exception as e:
        logger.warning(f"Ошибка парсинга строки лога: {e}")
        return None


def read_iptables_logs(log_file: str = '/var/log/kern.log') -> List[Dict]:
    """
    Читает логи iptables из системного лога
    
    Args:
        log_file: Путь к файлу лога
        
    Returns:
        list: Список записей трафика
    """
    logs = []
    
    try:
        # Читаем последние строки из лога (можно оптимизировать через tail -f)
        result = subprocess.run(
            ['sudo', '-n', 'tail', '-n', '1000', log_file],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode != 0:
            logger.warning(f"Не удалось прочитать лог: {result.stderr}")
            return logs
        
        # Фильтруем только строки с iptables LOG
        for line in result.stdout.splitlines():
            if 'iptables' in line.lower() or 'IN=' in line:
                parsed = parse_iptables_log_line(line)
                if parsed:
                    logs.append(parsed)
        
        return logs
    
    except Exception as e:
        logger.error(f"Ошибка чтения логов iptables: {e}")
        return logs


def setup_iptables_logging():
    """
    Настраивает iptables для логирования трафика
    Добавляет правила LOG в начало цепочек INPUT и OUTPUT
    """
    try:
        # Проверяем, есть ли уже правила LOG
        result = subprocess.run(
            ['sudo', '-n', 'iptables', '-L', 'INPUT', '-n', '--line-numbers'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if 'LOG' in result.stdout:
            logger.debug("Правила LOG уже установлены")
            return True
        
        # Добавляем правила LOG в начало цепочек
        # Логируем только если нет правил LOG
        log_rules = [
            ['iptables', '-I', 'INPUT', '1', '-j', 'LOG', '--log-prefix', 'IPTABLES-IN: ', '--log-level', '4'],
            ['iptables', '-I', 'OUTPUT', '1', '-j', 'LOG', '--log-prefix', 'IPTABLES-OUT: ', '--log-level', '4'],
            ['iptables', '-I', 'FORWARD', '1', '-j', 'LOG', '--log-prefix', 'IPTABLES-FWD: ', '--log-level', '4']
        ]
        
        for rule in log_rules:
            result = subprocess.run(
                ['sudo', '-n'] + rule,
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode != 0:
                logger.warning(f"Не удалось добавить правило LOG: {result.stderr}")
        
        logger.info("Правила LOG для iptables установлены")
        return True
    
    except Exception as e:
        logger.error(f"Ошибка настройки логирования iptables: {e}")
        return False


def collect_traffic_logs() -> List[Dict]:
    """
    Основная функция сбора логов трафика
    
    Returns:
        list: Список записей трафика
    """
    # Убеждаемся что логирование настроено
    setup_iptables_logging()
    
    # Читаем логи
    logs = read_iptables_logs()
    
    return logs






