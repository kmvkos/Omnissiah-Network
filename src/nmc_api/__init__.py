"""
NMC API - API endpoints для Flask приложения
"""
from flask import Blueprint

# Импортируем все Blueprints
from .nodes import nodes_bp
from .heartbeat import heartbeat_bp
from .peers import peers_bp
from .traffic import traffic_bp
from .cognitors import cognitors_bp
from .protected_objects import protected_objects_bp
from .access_policies import access_policies_bp
from .legacy_policy_bridge import legacy_policy_bridge_bp
from .policy_apply import policy_apply_bp
from .cross_routes import cross_route_bp

# Список всех Blueprints для регистрации
api_blueprints = [
    nodes_bp,
    heartbeat_bp,
    peers_bp,
    traffic_bp,
    cognitors_bp,
    protected_objects_bp,
    access_policies_bp,
    legacy_policy_bridge_bp,
    policy_apply_bp,
    cross_route_bp
]

__all__ = [
    'nodes_bp',
    'heartbeat_bp',
    'peers_bp',
    'traffic_bp',
    'cognitors_bp',
    'protected_objects_bp',
    'access_policies_bp',
    'legacy_policy_bridge_bp',
    'policy_apply_bp',
    'cross_route_bp',
    'api_blueprints'
]
