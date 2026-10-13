"""
Тесты для утилит subprocess
"""
import pytest
from unittest.mock import patch, MagicMock
from nmc_utils.subprocess_utils import run_command, check_command_exists, get_wg_status
from nmc_core.nmc_exceptions import NetworkError, SecurityError, WireGuardError


def test_run_command_success():
    """Тест успешного выполнения команды"""
    with patch('subprocess.run') as mock_run:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "success"
        mock_result.stderr = ""
        mock_run.return_value = mock_result
        
        result = run_command(['echo', 'test'], sudo=False)
        assert result.returncode == 0


def test_run_command_with_sudo():
    """Тест выполнения команды с sudo"""
    with patch('subprocess.run') as mock_run:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "success"
        mock_result.stderr = ""
        mock_run.return_value = mock_result
        
        result = run_command(['ls'], sudo=True)
        # Проверяем что sudo добавлен
        assert 'sudo' in str(mock_run.call_args[0][0])


def test_run_command_timeout():
    """Тест таймаута команды"""
    with patch('subprocess.run') as mock_run:
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(['test'], 5)
        
        with pytest.raises(NetworkError) as exc_info:
            run_command(['sleep', '10'], timeout=5)
        assert "превысила время ожидания" in str(exc_info.value.message)


def test_run_command_file_not_found():
    """Тест ошибки 'команда не найдена'"""
    with patch('subprocess.run') as mock_run:
        mock_run.side_effect = FileNotFoundError("Command not found")
        
        with pytest.raises(SecurityError) as exc_info:
            run_command(['nonexistent_command'])
        assert "не найдена" in str(exc_info.value.message)


def test_check_command_exists():
    """Тест проверки существования команды"""
    with patch('src.utils.subprocess_utils.run_command') as mock_run:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_run.return_value = mock_result
        
        assert check_command_exists('ls') is True


def test_get_wg_status():
    """Тест получения статуса WireGuard"""
    with patch('src.utils.subprocess_utils.run_command') as mock_run:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "interface: wg0"
        mock_result.stderr = ""
        mock_run.return_value = mock_result
        
        status = get_wg_status('wg0')
        assert status['active'] is True
        assert status['output'] == "interface: wg0"

