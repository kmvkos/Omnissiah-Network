"""
Модели базы данных для NMC_WG
"""
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from sqlalchemy.orm import validates
from ipaddress import IPv4Address, IPv4Network
from wtforms.validators import ValidationError
from typing import List, Dict, Tuple

# db будет импортирован из __init__.py
from . import db


class FirewallRule(db.Model):
    """Модель правил firewall"""
    __tablename__ = 'firewall_rules'
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(10), nullable=False, default='deny')
    direction = db.Column(db.String(10), nullable=False, default='in')
    interface = db.Column(db.String(50), nullable=False, default='any')
    source = db.Column(db.String(50), nullable=False, default='any')
    destination = db.Column(db.String(50), nullable=False, default='any')
    port = db.Column(db.String(20), nullable=True, default='')
    protocol = db.Column(db.String(10), nullable=False, default='any')
    comment = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)

    @validates('interface')
    def validate_interface(self, key, value):
        """Валидация интерфейса"""
        if value.lower() == 'any' or value == 'lo':
            return value
        
        # Получаем системные интерфейсы
        valid_interfaces = []
        try:
            import subprocess
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if ':' in line and not line.startswith(' '):
                        ifname = line.split(':')[1].strip().split('@')[0]
                        if ifname:
                            valid_interfaces.append(ifname)
        except Exception:
            pass
        
        # Добавляем интерфейсы WireGuard из БД
        try:
            from .models import General
            nodes = General.query.all()
            for node in nodes:
                if node.name:
                    valid_interfaces.append(node.name)
        except Exception:
            pass
        
        # Добавляем активные WireGuard интерфейсы
        try:
            import subprocess
            result = subprocess.run(['wg', 'show', 'interfaces'], capture_output=True, text=True)
            if result.returncode == 0:
                for ifname in result.stdout.strip().split('\n'):
                    if ifname:
                        valid_interfaces.append(ifname)
        except Exception:
            pass
        
        if value not in valid_interfaces:
            raise ValueError(f"Недопустимый интерфейс: {value}")
        return value

    @validates('protocol')
    def validate_protocol(self, key, protocol):
        """Валидация протокола"""
        valid_protocols = ['tcp', 'udp', 'icmp', 'any']
        if protocol.lower() not in valid_protocols:
            raise ValueError(f"Недопустимый протокол: {protocol}")
        return protocol.lower()

    @validates('port')
    def validate_port(self, key, port):
        """Валидация порта"""
        if not port or port == '':
            return port
        # Разрешаем диапазоны, множественные порты и пустую строку
        if '-' in port:
            start, end = port.split('-')
            try:
                if not (1 <= int(start) <= 65535 and 1 <= int(end) <= 65535):
                    raise ValueError("Порты должны быть в диапазоне 1-65535")
            except ValueError:
                raise ValueError("Некорректный формат диапазона портов")
        elif ',' in port:
            for p in port.split(','):
                try:
                    if not (1 <= int(p.strip()) <= 65535):
                        raise ValueError("Порты должны быть в диапазоне 1-65535")
                except ValueError:
                    raise ValueError(f"Некорректный формат порта: {p}")
        else:
            try:
                if not (1 <= int(port) <= 65535):
                    raise ValueError("Порт должен быть в диапазоне 1-65535")
            except ValueError:
                raise ValueError("Некорректный формат порта")
        return port

    def __repr__(self):
        return f"<FirewallRule {self.action} {self.direction} {self.protocol}:{self.port}>"


class BaseUser(db.Model, UserMixin):
    """Модель пользователя"""
    __tablename__ = 'base_users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    role = db.Column(db.String(20), default='user')


# Функция валидации для сетевых полей (используется в General)
from functools import wraps
from wtforms.validators import ValidationError as WTFormsValidationError


def validate_network_field(field_name):
    """Декоратор для валидации сетевых полей модели General."""
    def decorator(func):
        @wraps(func)
        def wrapper(self, key, value):
            # Общие проверки для ip_pool
            if field_name == 'ip_pool':
                try:
                    network = IPv4Network(value, strict=False)
                    if network.version != 4:
                        raise WTFormsValidationError("Поддерживаются только IPv4 сети.")
                    node_role = getattr(self, 'role', None)
                    min_prefix = 16
                    if node_role == 'Omnissiah':
                        max_prefix = 29
                    else:
                        max_prefix = 32
                    
                    if network.prefixlen < min_prefix or network.prefixlen > max_prefix:
                        if node_role == 'Omnissiah':
                            raise WTFormsValidationError("Маска сети должна быть между /16 и /29.")
                        else:
                            raise WTFormsValidationError("Маска сети должна быть между /16 и /32.")
                except ValueError as e:
                    raise WTFormsValidationError(f"Неверный формат IP-пула: {str(e)}")

            # Общие проверки для endpoint
            elif field_name == 'endpoint':
                if value is None or (isinstance(value, str) and value.strip() == ''):
                    return func(self, key, value)
                try:
                    ip = IPv4Address(value)
                    if ip.version != 4:
                        raise WTFormsValidationError("Поддерживаются только IPv4 адреса.")
                except ValueError:
                    raise WTFormsValidationError("Неверный формат Endpoint. Ожидается IPv4 адрес.")

            elif field_name == 'listen_port':
                try:
                    port = int(value)
                    if not (1024 <= port <= 65535):
                        raise WTFormsValidationError("Порт должен быть в диапазоне 1024–65535.")
                except ValueError:
                    raise WTFormsValidationError("Порт должен быть целым числом.")

            elif field_name == 'role':
                valid_roles = ['Omnissiah', 'Magos', 'Cognitor']
                if value not in valid_roles:
                    raise WTFormsValidationError(f"Недопустимая роль. Допустимые значения: {', '.join(valid_roles)}")

            return func(self, key, value)
        return wrapper
    return decorator


class General(db.Model):
    """Модель узла сети (Omnissiah, Magos, Cognitor)"""
    __tablename__ = 'general'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    ip_pool = db.Column(db.String(50), nullable=False)
    listen_port = db.Column(db.Integer, nullable=False)
    private_key = db.Column(db.String(256), nullable=False)
    public_key = db.Column(db.String(256), nullable=False)
    dns = db.Column(db.String(50), default='1.1.1.1')
    mtu = db.Column(db.Integer, default=1420)
    post_up = db.Column(db.String(500))
    post_down = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='stopped')
    endpoint = db.Column(db.String(100))
    communication = db.Column(db.String(500))
    role = db.Column(db.String(20), default='Omnissiah')
    preshared_key = db.Column(db.String(256))
    parent_id = db.Column(db.Integer, db.ForeignKey('general.id'))
    children = db.relationship(
        'General',
        foreign_keys=[parent_id],
        backref=db.backref('parent', remote_side=[id]),
        lazy='dynamic'
    )
    last_handshake = db.Column(db.DateTime)
    total_receive = db.Column(db.BigInteger, default=0)
    total_sent = db.Column(db.BigInteger, default=0)
    last_heartbeat = db.Column(db.DateTime, nullable=True)
    heartbeat_ip = db.Column(db.String(50))
    heartbeat_interfaces = db.Column(db.Text)
    wireguard_enabled = db.Column(db.Boolean, default=False)
    sent_to_magos = db.Column(db.Integer, default=0)
    ack_from_magos = db.Column(db.Integer, default=0)
    nginx_enabled = db.Column(db.Boolean, default=False)
    nginx_domain = db.Column(db.String(255))
    nginx_cert_type = db.Column(db.String(50), default='self-signed')
    nginx_cert_path = db.Column(db.String(500))
    nginx_key_path = db.Column(db.String(500))
    nginx_https_port = db.Column(db.Integer, default=443)
    nginx_redirect_http = db.Column(db.Boolean, default=True)
    mtls_enabled = db.Column(db.Boolean, default=False)
    mtls_ca_cert_path = db.Column(db.String(500))
    mtls_ca_key_path = db.Column(db.String(500))
    mtls_server_cert_path = db.Column(db.String(500))
    mtls_server_key_path = db.Column(db.String(500))
    admin_ip = db.Column(db.String(50))
    allow_cognitor_to_cognitor = db.Column(db.Boolean, default=False)
    ssh_ip = db.Column(db.String(50))
    ssh_user = db.Column(db.String(100))
    ssh_password = db.Column(db.Text)
    ssh_key_path = db.Column(db.String(500))

    @property
    def all_children(self):
        children = []
        for child in self.children:
            children.append(child)
            children.extend(child.all_children)
        return children

    @validates('parent_id')
    def validate_parent_id(self, key, parent_id):
        if parent_id:
            node = db.session.get(General, parent_id)
            if not node:
                raise ValueError("Central node not found")
            if node.role == 'Cognitor':
                raise ValueError("Client node cannot be a central node")
            if self.role == 'Omnissiah' and parent_id:
                raise ValueError("Main server cannot have a central node")
        return parent_id

    def __repr__(self):
        return f"<General {self.name} ({self.role})>"

    def get_available_for_connections(self):
        """Return nodes available for additional connections"""
        query = General.query.filter(
            (General.role.in_(['Omnissiah', 'Magos'])) &
            (General.id != self.id)
        )

        connected_ids = set()
        for conn in self.connections_as_node1 + self.connections_as_node2:
            connected_ids.add(conn.node2_id if conn.node1_id == self.id else conn.node1_id)

        if self.parent_id:
            connected_ids.add(self.parent_id)
        if self.role == 'Omnissiah':
            connected_ids.update([c.id for c in self.children])

        if connected_ids:
            query = query.filter(~General.id.in_(connected_ids))

        return query.all()

    @property
    def connections_as_node1(self):
        return NodeConnection.query.filter_by(node1_id=self.id).all()

    @property
    def connections_as_node2(self):
        return NodeConnection.query.filter_by(node2_id=self.id).all()

    def get_connected_nodes(self):
        """Get all directly connected nodes (excluding hierarchy)"""
        nodes = []
        for conn in self.connections_as_node1:
            nodes.append(conn.node2)
        for conn in self.connections_as_node2:
            nodes.append(conn.node1)
        return list(set(nodes))

    @validates('ip_pool')
    @validate_network_field('ip_pool')
    def validate_ip_pool(self, key, value):
        if not value:
            return value
        try:
            # Нормализуем IP-адрес сети (исправляем host bits)
            # Например: 11.11.11.1/24 -> 11.11.11.0/24
            network = IPv4Network(value, strict=False)
            normalized_value = f"{network.network_address}/{network.prefixlen}"
            
            if self.role == 'Omnissiah' and network.num_addresses < 50:
                raise WTFormsValidationError("Главный сервер требует пул минимум на 50 адресов")
            
            return normalized_value
        except ValueError as e:
            raise WTFormsValidationError(f"Некорректный формат IP-пула: {str(e)}")

    @validates('endpoint')
    @validate_network_field('endpoint')
    def validate_endpoint(self, key, value):
        if value is None or (isinstance(value, str) and value.strip() == ''):
            return value
        return value

    @validates('role')
    @validate_network_field('role')
    def validate_role(self, key, value):
        """Валидация роли с проверкой на Omnissiah"""
        valid_roles = ['Omnissiah', 'Magos', 'Cognitor']
        if value not in valid_roles:
            raise WTFormsValidationError(f"Invalid role. Must be one of: {', '.join(valid_roles)}")
        if value == 'Omnissiah' and self.parent_id:
            raise WTFormsValidationError("Главный сервер не может иметь родительский узел")
        return value


class NodeConnection(db.Model):
    """Модель связей между узлами"""
    __tablename__ = 'node_connections'
    id = db.Column(db.Integer, primary_key=True)
    node1_id = db.Column(db.Integer, db.ForeignKey('general.id'), nullable=False)
    node2_id = db.Column(db.Integer, db.ForeignKey('general.id'), nullable=False)
    description = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    node1 = db.relationship('General', foreign_keys=[node1_id])
    node2 = db.relationship('General', foreign_keys=[node2_id])

    __table_args__ = (
        db.UniqueConstraint('node1_id', 'node2_id', name='_node_connection_uc'),
    )

    def __repr__(self):
        return f"<Connection {self.node1.name} ↔ {self.node2.name}>"


class ProtectedObject(db.Model):
    """Защищенные объекты (сети/IP за узлами)"""
    __tablename__ = 'protected_objects'
    id = db.Column(db.Integer, primary_key=True)
    network = db.Column(db.String(50), nullable=False)
    node_id = db.Column(db.Integer, db.ForeignKey('general.id'), nullable=False)
    interface = db.Column(db.String(50), nullable=True)
    description = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('base_users.id'))
    is_active = db.Column(db.Boolean, default=True)
    warning_shown = db.Column(db.Boolean, default=False)
    
    node = db.relationship('General', foreign_keys=[node_id])
    creator = db.relationship('BaseUser', foreign_keys=[created_by])

    def __repr__(self):
        interface_str = f"/{self.interface}" if self.interface else ""
        return f"<ProtectedObject {self.network} @ {self.node.name if self.node else 'unknown'}{interface_str}>"


class AccessPolicyRule(db.Model):
    """Правила политики доступа"""
    __tablename__ = 'access_policy_rules'
    id = db.Column(db.Integer, primary_key=True)
    
    source_type = db.Column(db.String(20), nullable=False)
    source_id = db.Column(db.Integer, nullable=True)
    source_network = db.Column(db.String(50), nullable=True)
    
    destination_type = db.Column(db.String(20), nullable=False)
    destination_id = db.Column(db.Integer, nullable=True)
    destination_network = db.Column(db.String(50), nullable=True)
    
    protocol = db.Column(db.String(20), default='tcp')
    ports = db.Column(db.String(200))
    service = db.Column(db.String(50))
    direction = db.Column(db.String(20), default='FORWARD')
    action = db.Column(db.String(20), default='ACCEPT')
    
    status = db.Column(db.String(20), default='pending')
    applied_at = db.Column(db.DateTime, nullable=True)
    applied_by = db.Column(db.Integer, db.ForeignKey('base_users.id'), nullable=True)
    
    applied_on_nodes = db.Column(db.Text)
    configuration_snapshot = db.Column(db.Text)
    
    description = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('base_users.id'))
    is_system_rule = db.Column(db.Boolean, default=False)
    priority = db.Column(db.Integer, default=100)
    group_id = db.Column(db.Integer, db.ForeignKey('policy_groups.id'), nullable=True)
    
    creator = db.relationship('BaseUser', foreign_keys=[created_by])
    applier = db.relationship('BaseUser', foreign_keys=[applied_by])
    
    def __repr__(self):
        src = self.get_source_display()
        dst = self.get_destination_display()
        return f"<AccessPolicyRule {src} -> {dst} ({self.protocol}:{self.ports})>"
    
    def get_source_display(self):
        """Возвращает читаемое представление источника"""
        if self.source_type == 'protected_object':
            obj = db.session.get(ProtectedObject, self.source_id) if self.source_id else None
            return obj.network if obj else f"ProtectedObject#{self.source_id}"
        elif self.source_type == 'node':
            node = db.session.get(General, self.source_id) if self.source_id else None
            return f"{node.role}:{node.name}" if node else f"Node#{self.source_id}"
        else:
            return self.source_network or "Unknown"
    
    def get_destination_display(self):
        """Возвращает читаемое представление назначения"""
        if self.destination_type == 'protected_object':
            obj = db.session.get(ProtectedObject, self.destination_id) if self.destination_id else None
            return obj.network if obj else f"ProtectedObject#{self.destination_id}"
        elif self.destination_type == 'node':
            node = db.session.get(General, self.destination_id) if self.destination_id else None
            return f"{node.role}:{node.name}" if node else f"Node#{self.destination_id}"
        else:
            return self.destination_network or "Unknown"


class PolicyGroup(db.Model):
    """Группа правил политики безопасности"""
    __tablename__ = 'policy_groups'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.String(500))
    is_active = db.Column(db.Boolean, default=True)
    priority = db.Column(db.Integer, default=100)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('base_users.id'), nullable=True)
    
    creator = db.relationship('BaseUser', foreign_keys=[created_by])
    rules = db.relationship('AccessPolicyRule', backref='group', lazy='dynamic')
    
    def __repr__(self):
        return f"<PolicyGroup {self.name} ({self.rules.count()} правил)>"


class TrafficLog(db.Model):
    """Модель для хранения журнала трафика"""
    __tablename__ = 'traffic_logs'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    node_id = db.Column(db.Integer, db.ForeignKey('general.id'), nullable=False, index=True)
    source_ip = db.Column(db.String(50), index=True)
    destination_ip = db.Column(db.String(50), index=True)
    source_port = db.Column(db.Integer)
    destination_port = db.Column(db.Integer)
    protocol = db.Column(db.String(10))
    action = db.Column(db.String(20))
    bytes_sent = db.Column(db.BigInteger, default=0)
    bytes_received = db.Column(db.BigInteger, default=0)
    packets_sent = db.Column(db.Integer, default=0)
    packets_received = db.Column(db.Integer, default=0)
    interface = db.Column(db.String(50))
    direction = db.Column(db.String(10))
    connection_state = db.Column(db.String(20))
    
    node = db.relationship('General', backref='traffic_logs', lazy='joined')
    
    def __repr__(self):
        return f"<TrafficLog {self.source_ip}:{self.source_port} -> {self.destination_ip}:{self.destination_port} ({self.protocol})>"


class BaseConfigModel(db.Model):
    """Базовая модель конфигураций (абстрактная)"""
    __abstract__ = True
    id = db.Column(db.Integer, primary_key=True)
    base_user_id = db.Column(db.Integer, db.ForeignKey('base_users.id'), nullable=False)
    user_email = db.Column(db.String(120))
    old_endpoint = db.Column(db.String(100))
    real_endpoint = db.Column(db.String(100))
    allowed_ip = db.Column(db.String(15))
    public_key = db.Column(db.String(256))
    private_key = db.Column(db.String(256))
    api_peer_id = db.Column(db.String(50))
    dns = db.Column(db.String(50))
    endpoint_allowed_ip = db.Column(db.String(100))
    latest_handshake = db.Column(db.DateTime)
    server_conf = db.Column(db.Text)
    total_receive = db.Column(db.BigInteger)
    total_sent = db.Column(db.BigInteger)
    total_data = db.Column(db.BigInteger)
    status = db.Column(db.String(20), default='pending')
    cumu_receive = db.Column(db.BigInteger)
    cumu_sent = db.Column(db.BigInteger)
    cumu_data = db.Column(db.BigInteger)


class BaseInfoModel(db.Model):
    """Базовая модель информации (абстрактная)"""
    __abstract__ = True
    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(50))
    connected_peers = db.Column(db.Integer)
    receive = db.Column(db.Float)
    sent = db.Column(db.Float)
    total = db.Column(db.Float)
    listen_port = db.Column(db.String(10))
    name = db.Column(db.String(50))
    post_down = db.Column(db.String(500))
    post_up = db.Column(db.String(500))
    pre_down = db.Column(db.String(500))
    pre_up = db.Column(db.String(500))
    public_key = db.Column(db.String(256))
    save_config = db.Column(db.Boolean)
    status = db.Column(db.Boolean)
    mtu = db.Column(db.Integer)
    persistent_keepalive = db.Column(db.Integer)
    preshared_key = db.Column(db.String(256))

