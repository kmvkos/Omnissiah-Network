"""
Утилиты для работы с subprocess
"""
import subprocess
import logging
from typing import Optional, List, Dict, Any
from src.exceptions import NetworkError, SecurityError

logger = logging.getLogger(__name__)


def run_command(
    cmd: List[str],
    check: bool = False,
    timeout: int = 30,
    input_data: Optional[bytes] = None,
    capture_output: bool = True,
    sudo: bool = True
) -> subprocess.CompletedProcess:
    """
    Безопасное выполнение команды через subprocess
    
    Args:
        cmd: Команда для выполнения
        check: Вызывать исключение при ненулевом коде возврата
        timeout: Таймаут выполнения
        input_data: Данные для stdin
        capture_output: Захватывать вывод
        sudo: Использовать sudo
        
    Returns:
        CompletedProcess с результатами
        
    Raises:
        NetworkError: При ошибке выполнения команды
        SecurityError: При проблемах безопасности
    """
    if sudo and cmd[0] != 'sudo':
        cmd = ['sudo', '-n'] + cmd
    
    try:
        result = subprocess.run(
            cmd,
            check=check,
            timeout=timeout,
            input=input_data,
            capture_output=capture_output,
            text=True
        )
        
        if check and result.returncode != 0:
            error_msg = result.stderr if result.stderr else "Unknown error"
            logger.error(f"Command failed: {' '.join(cmd)} - {error_msg}")
            raise NetworkError(
                f"Команда завершилась с ошибкой: {error_msg}",
                details=f"Command: {' '.join(cmd)}, Return code: {result.returncode}"
            )
        
        return result
        
    except subprocess.TimeoutExpired as e:
        logger.error(f"Command timeout: {' '.join(cmd)}")
        raise NetworkError(
            f"Команда превысила время ожидания ({timeout}s)",
            details=f"Command: {' '.join(cmd)}"
        )
    except FileNotFoundError as e:
        logger.error(f"Command not found: {' '.join(cmd)}")
        raise SecurityError(
            f"Команда не найдена: {cmd[0]}",
            details=str(e)
        )
    except PermissionError as e:
        logger.error(f"Permission denied: {' '.join(cmd)}")
        raise SecurityError(
            "Недостаточно прав для выполнения команды",
            details=str(e)
        )
    except Exception as e:
        logger.error(f"Unexpected error executing command: {' '.join(cmd)} - {str(e)}")
        raise NetworkError(
            f"Ошибка выполнения команды: {str(e)}",
            details=f"Command: {' '.join(cmd)}"
        )


def check_command_exists(cmd: str) -> bool:
    """
    Проверяет существование команды в системе
    
    Args:
        cmd: Имя команды
        
    Returns:
        True если команда существует
    """
    try:
        result = run_command(['which', cmd], sudo=False, check=False)
        return result.returncode == 0
    except Exception:
        return False


def get_wg_status(interface: str) -> Dict[str, Any]:
    """
    Получает статус WireGuard интерфейса
    
    Args:
        interface: Имя интерфейса
        
    Returns:
        Словарь со статусом
        
    Raises:
        WireGuardError: При ошибке получения статуса
    """
    from src.exceptions import WireGuardError
    
    try:
        result = run_command(['wg', 'show', interface], check=False, timeout=5)
        
        return {
            'active': result.returncode == 0,
            'output': result.stdout if result.returncode == 0 else None,
            'error': result.stderr if result.returncode != 0 else None
        }
    except NetworkError as e:
        raise WireGuardError(f"Ошибка получения статуса WireGuard: {e.message}", e.details)

