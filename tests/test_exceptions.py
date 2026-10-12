"""
Тесты для кастомных исключений
"""
import pytest
from omnissiah_core.nmc_exceptions import (
    NMCError, VPNError, WireGuardError, DatabaseError,
    ConfigurationError, NetworkError, ValidationError,
    SecurityError, SSHError, IPTablesError
)


def test_nmc_error():
    """Тест базового исключения"""
    error = NMCError("Test message", "Test details")
    assert str(error) == "Test message"
    assert error.message == "Test message"
    assert error.details == "Test details"


def test_vpn_error():
    """Тест VPN исключения"""
    error = VPNError("VPN error")
    assert isinstance(error, NMCError)
    assert str(error) == "VPN error"


def test_wireguard_error():
    """Тест WireGuard исключения"""
    error = WireGuardError("WG error")
    assert isinstance(error, VPNError)
    assert isinstance(error, NMCError)


def test_database_error():
    """Тест Database исключения"""
    error = DatabaseError("DB error")
    assert isinstance(error, NMCError)


def test_network_error():
    """Тест Network исключения"""
    error = NetworkError("Network error")
    assert isinstance(error, NMCError)

