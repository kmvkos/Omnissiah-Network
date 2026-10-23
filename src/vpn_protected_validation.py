"""Strict, pure admission checks for proposed protected resources.

Inventory registration NEVER creates routes, WireGuard AllowedIPs or ACL rules.
"""
from ipaddress import ip_address, ip_network
import re


class ProtectedResourceError(ValueError):
    pass


def validate_protected_object(*, name, network, description, parent,
                              registered_networks, vpn_pool, management_ips):
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,49}", name):
        raise ProtectedResourceError("Имя: латиница, цифры, _ или -, до 50 символов")
    if parent is None or getattr(parent, "role", None) != "Magos":
        raise ProtectedResourceError("Выберите зарегистрированный Magos")
    if not isinstance(description, str) or len(description.strip()) > 255:
        raise ProtectedResourceError("Описание не должно превышать 255 символов")
    if not isinstance(network, str):
        raise ProtectedResourceError("Неверная подсеть")
    try:
        target = ip_network(network.strip(), strict=True)
    except ValueError as exc:
        raise ProtectedResourceError("Укажите IPv4 CIDR с адресом сети (например, 172.16.40.0/24)") from exc
    if (target.version != 4 or target.prefixlen == 0
            or target.is_multicast or target.is_loopback or target.is_link_local
            or target.is_reserved or target.network_address.is_unspecified
            or target.broadcast_address.is_multicast):
        raise ProtectedResourceError("Системные, общие и служебные сети запрещены")
    try:
        pool = ip_network(vpn_pool, strict=False)
    except (ValueError, TypeError) as exc:
        raise ProtectedResourceError("Не определён корректный VPN-пул Omnissiah") from exc
    if pool.version != 4 or target.overlaps(pool):
        raise ProtectedResourceError("Защищаемая сеть пересекается с VPN-пулом")
    for old in registered_networks:
        try:
            existing = ip_network(old, strict=True)
        except (TypeError, ValueError) as exc:
            raise ProtectedResourceError("Реестр защищаемых объектов требует проверки") from exc
        if target.overlaps(existing):
            raise ProtectedResourceError("Сеть пересекается с уже зарегистрированным объектом")
    for raw in management_ips:
        if not raw:
            continue
        try:
            address = ip_address(raw)
        except ValueError as exc:
            raise ProtectedResourceError("Невозможно проверить управляющий адрес узла") from exc
        if address.version == 4 and address in target:
            raise ProtectedResourceError("Объект включает управляющий IP узла")
    return {
        "name": name,
        "network": str(target),
        "description": description.strip(),
        "parent_magos_id": parent.id,
    }
