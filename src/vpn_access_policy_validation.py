"""Pure validation and explanatory read-only preview of VPN policy intentions.

The preview NEVER means a Magos has installed a rule or that traffic is blocked.
"""
import re
from ipaddress import ip_interface, ip_network


class AccessPolicyError(ValueError):
    pass


def validate_policy(*, name, source, target, protocol, port, decision, existing_rules):
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,49}", name):
        raise AccessPolicyError("Имя правила: латиница, цифры, _ или -, максимум 50 символов")
    if source is None or getattr(source, "status", None) != "applied":
        raise AccessPolicyError("Выберите Cognitor, применённый на Magos")
    if target is None or getattr(target, "status", None) != "inventory_only":
        raise AccessPolicyError("Выберите зарегистрированный защищаемый объект")
    if type(getattr(source, "id", None)) is not int or type(getattr(target, "id", None)) is not int:
        raise AccessPolicyError("Некорректные идентификаторы объектов")
    try:
        source_ip = ip_interface(source.vpn_address)
        destination = ip_network(target.network, strict=True)
    except (ValueError, TypeError, AttributeError) as exc:
        raise AccessPolicyError("Недопустимые адреса клиента или защищаемого объекта") from exc
    if (source_ip.version != 4 or source_ip.network.prefixlen != 32
            or destination.version != 4 or destination.prefixlen == 0
            or source_ip.ip in destination):
        raise AccessPolicyError("Некорректное соответствие Cognitor и защищаемого объекта")
    if (type(getattr(source, "parent_magos_id", None)) is not int
            or type(getattr(target, "parent_magos_id", None)) is not int):
        raise AccessPolicyError("Не указан Magos, владеющий ресурсом")
    if protocol not in ("tcp", "udp", "icmp"):
        raise AccessPolicyError("Разрешены только TCP, UDP или ICMP")
    if decision not in ("allow", "deny"):
        raise AccessPolicyError("Решение должно быть allow или deny")
    if not isinstance(port, str):
        raise AccessPolicyError("Некорректный порт")
    port = port.strip()
    if protocol == "icmp":
        if port:
            raise AccessPolicyError("Для ICMP порт не указывается")
        destination_port = 0
    else:
        if not re.fullmatch(r"[0-9]{1,5}", port) or not 1 <= int(port) <= 65535:
            raise AccessPolicyError("Для TCP/UDP укажите порт от 1 до 65535")
        destination_port = int(port)
    for item in existing_rules:
        try:
            key = (item.source_cognitor_id, item.target_object_id,
                   item.protocol, item.destination_port)
        except AttributeError as exc:
            raise AccessPolicyError("Не удалось проверить существующие политики") from exc
        if key == (source.id, target.id, protocol, destination_port):
            raise AccessPolicyError(
                "Такое правило уже существует (включая конфликт allow/deny)")
    return {
        "name": name,
        "source_cognitor_id": source.id,
        "target_object_id": target.id,
        "protocol": protocol,
        "destination_port": destination_port,
        "decision": decision,
    }


def preview_policy(rule):
    """Explain the desired flow and missing prerequisites; NEVER authorize Apply."""
    if getattr(rule, "status", None) != "draft":
        raise AccessPolicyError("Неизвестное состояние правила")
    source = getattr(rule, "source_cognitor", None)
    target = getattr(rule, "target_object", None)
    if source is None or target is None:
        raise AccessPolicyError("Источник или ресурс правила удалён")
    fields = validate_policy(
        name=rule.name, source=source, target=target,
        protocol=rule.protocol,
        port="" if rule.protocol == "icmp" else str(rule.destination_port),
        decision=rule.decision, existing_rules=(),
    )
    if fields["destination_port"] != rule.destination_port:
        raise AccessPolicyError("Некорректный порт в сохранённом правиле")
    return {
        "source": source.name,
        "source_address": source.vpn_address,
        "source_magos_id": source.parent_magos_id,
        "destination": target.name,
        "destination_network": target.network,
        "destination_magos_id": target.parent_magos_id,
        "protocol": rule.protocol.upper(),
        "port": None if rule.protocol == "icmp" else rule.destination_port,
        "decision": rule.decision,
        "cross_magos": source.parent_magos_id != target.parent_magos_id,
        "result": "inventory_only",
        "routing_verified": False,
        "firewall_installed": False,
        "traffic_filtered": False,
        "apply_available": False,
        "writes_performed": False,
    }
