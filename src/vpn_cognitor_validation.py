"""Validation-only Cognitor draft admission. NEVER changes VPN/routes/firewall.

A client generates its private WireGuard key on its own device. Controller
stores only the public key. Legacy /add_peer route is intentionally bypassed.
"""
import base64
import binascii
from ipaddress import IPv4Address, ip_interface, ip_network
import re

NAME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]{0,49}$")


class CognitorValidationError(ValueError):
    pass


def normalized_key(value):
    if not isinstance(value, str) or len(value) != 44:
        raise CognitorValidationError("Публичный ключ WireGuard должен быть длиной 44 символа")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise CognitorValidationError("Неверный публичный ключ WireGuard") from exc
    if len(decoded) != 32 or base64.b64encode(decoded).decode() != value:
        raise CognitorValidationError("Неверный публичный ключ WireGuard")
    return value


def validate_draft(*, name, address, public_key, parent,
                   pool, occupied_ips=(), occupied_names=(), occupied_keys=()):
    """Return canonical public-only fields. Parent is a Magos-like object.

    pool: Omnissiah's assigned IPv4 address pool (not a transport endpoint).
    occupied_* must include ALL existing node identities plus staged clients.
    Final database uniqueness constraints must independently enforce races.
    """
    name = name.strip() if isinstance(name, str) else ""
    if not NAME_PATTERN.fullmatch(name):
        raise CognitorValidationError("Имя: латинские буквы, цифры, _ и -, до 50 символов; начало — буква")
    if name.lower() in {str(item).lower() for item in occupied_names}:
        raise CognitorValidationError("Имя клиента уже занято")
    if getattr(parent, "role", None) != "Magos":
        raise CognitorValidationError("Родительским узлом Cognitor может быть только Magos")
    key = normalized_key(public_key.strip() if isinstance(public_key, str) else public_key)
    if key in set(occupied_keys):
        raise CognitorValidationError("Публичный ключ уже зарегистрирован")
    try:
        value = ip_interface(address)
        allowed_pool = ip_network(pool, strict=False)
    except (ValueError, TypeError) as exc:
        raise CognitorValidationError("Неверный VPN-адрес или пул") from exc
    if value.version != 4 or value.network.prefixlen != 32:
        raise CognitorValidationError("Адрес Cognitor должен быть IPv4 с маской /32")
    ip = IPv4Address(value.ip)
    if allowed_pool.version != 4 or ip not in allowed_pool:
        raise CognitorValidationError("Адрес Cognitor находится вне VPN-пула")
    if ip == allowed_pool.network_address or (
            allowed_pool.prefixlen < 31 and ip == allowed_pool.broadcast_address):
        raise CognitorValidationError("Адрес сети или broadcast нельзя назначить клиенту")
    if str(ip) in {str(entry).split("/")[0] for entry in occupied_ips}:
        raise CognitorValidationError("VPN-адрес уже используется")
    return {"name": name, "address": str(ip) + "/32",
            "public_key": key, "parent_id": parent.id, "status": "draft"}
