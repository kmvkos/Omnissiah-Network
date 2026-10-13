"""
NMC Models - Модели базы данных
"""
from flask_sqlalchemy import SQLAlchemy

# Инициализация SQLAlchemy (будет создана в app.py)
db = SQLAlchemy()

# Импорты моделей (циклический импорт разрешится через lazy import)
from .models import (
    BaseUser, General, NodeConnection, ProtectedObject,
    AccessPolicyRule, FirewallRule, PolicyGroup, TrafficLog,
    BaseConfigModel, BaseInfoModel, validate_network_field
)

__all__ = [
    'db',
    'BaseUser', 'General', 'NodeConnection', 'ProtectedObject',
    'AccessPolicyRule', 'FirewallRule', 'PolicyGroup', 'TrafficLog',
    'BaseConfigModel', 'BaseInfoModel', 'validate_network_field'
]

