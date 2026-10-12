"""
Кастомные исключения для приложения
"""
from typing import Optional


class NMCError(Exception):
    """Базовое исключение для приложения"""
    def __init__(self, message: str, details: Optional[str] = None):
        self.message = message
        self.details = details
        super().__init__(self.message)


class VPNError(NMCError):
    """Ошибка работы с VPN"""
    pass


class WireGuardError(VPNError):
    """Ошибка работы с WireGuard"""
    pass


class DatabaseError(NMCError):
    """Ошибка работы с БД"""
    pass


class ConfigurationError(NMCError):
    """Ошибка конфигурации"""
    pass


class NetworkError(NMCError):
    """Ошибка работы с сетью"""
    pass


class ValidationError(NMCError):
    """Ошибка валидации данных"""
    pass


class SecurityError(NMCError):
    """Ошибка безопасности"""
    pass


class SSHError(NMCError):
    """Ошибка SSH соединения"""
    pass


class IPTablesError(NMCError):
    """Ошибка работы с iptables"""
    pass

