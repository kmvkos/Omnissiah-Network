#!/usr/bin/env python3
"""Create only a root-owned WireGuard client config; NEVER start/modify network.

Usage on the Cognitor Debian VM:
 sudo python3 cognitor_debian_setup.py \
   --private-key /home/fabricator/wireguard-client/cognitor.key \
   --address 10.77.0.5/32 --parent-ip 10.77.0.4/32 \
   --parent-public-key <Magos-public-key> \
   --endpoint 192.168.32.172:51820
"""
import argparse
import base64
import binascii
import ipaddress
import os
from pathlib import Path
import re
import stat

WG_FILE = Path("/etc/wireguard/wg0.conf")


def key(value):
    if not isinstance(value, str) or len(value) != 44:
        raise ValueError("Неверный ключ WireGuard")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("Некорректная Base64-строка ключа") from exc
    if len(raw) != 32 or base64.b64encode(raw).decode() != value:
        raise ValueError("Некорректный ключ WireGuard")
    return value


def config(*, secret, address, parent_ip, parent_public_key, endpoint):
    secret = key(secret.strip())
    parent_public_key = key(parent_public_key.strip())
    try:
        local = ipaddress.ip_interface(address)
        remote = ipaddress.ip_interface(parent_ip)
        host, raw_port = endpoint.rsplit(":", 1)
        endpoint_ip = ipaddress.IPv4Address(host)
        port = int(raw_port)
    except (ValueError, TypeError) as exc:
        raise ValueError("Неверный IP или endpoint") from exc
    if (local.version != 4 or remote.version != 4
            or local.network.prefixlen != 32 or remote.network.prefixlen != 32
            or local.ip == remote.ip or local.ip.is_unspecified
            or remote.ip.is_unspecified or local.ip.is_multicast
            or remote.ip.is_multicast or remote.ip.is_loopback
            or endpoint_ip.is_unspecified or endpoint_ip.is_multicast
            or not 1 <= port <= 65535):
        raise ValueError("Только безопасные IPv4 /32 и UDP endpoint")
    if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+:\d+", endpoint):
        raise ValueError("Endpoint должен быть IPv4:UDP_PORT")
    # Only the Magos VPN /32 is routed via the client tunnel. No default
    # route or LAN access is authorized by this first-stage configuration.
    return ("# Omnissiah Cognitor client - private key stays on this VM\n"
            "[Interface]\nPrivateKey = " + secret + "\n"
            "Address = " + str(local) + "\n\n"
            "[Peer]\nPublicKey = " + parent_public_key + "\n"
            "Endpoint = " + endpoint + "\n"
            "AllowedIPs = " + str(remote) + "\n"
            "PersistentKeepalive = 25\n")


def write_config(secret_path, output, *, address, parent_ip, parent_public_key, endpoint):
    # Do not accept symlinks or world-readable private keys.
    source = Path(secret_path)
    if source.is_symlink() or not source.is_file():
        raise ValueError("Нет защищённого файла приватного ключа")
    mode = source.stat().st_mode
    if not stat.S_ISREG(mode) or mode & 0o077:
        raise ValueError("Приватный ключ должен иметь права 0600")
    payload = config(secret=source.read_text(), address=address, parent_ip=parent_ip,
                     parent_public_key=parent_public_key, endpoint=endpoint)
    target = Path(output)
    if target.name != "wg0.conf" or target.parent.is_symlink():
        raise ValueError("Разрешена только конфигурация wg0.conf")
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if target.is_symlink():
        raise ValueError("Символическая ссылка недопустима")
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w") as out:
            out.write(payload)
            out.flush()
            os.fsync(out.fileno())
    except Exception:
        target.unlink(missing_ok=True)
        raise
    return str(target)


def main():
    parser = argparse.ArgumentParser(description="Cognitor: создать wg0.conf без запуска VPN")
    parser.add_argument("--private-key", required=True)
    parser.add_argument("--address", required=True)
    parser.add_argument("--parent-ip", required=True)
    parser.add_argument("--parent-public-key", required=True)
    parser.add_argument("--endpoint", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Требуется root (sudo)")
    try:
        write_config(args.private_key, WG_FILE,
                     address=args.address, parent_ip=args.parent_ip,
                     parent_public_key=args.parent_public_key, endpoint=args.endpoint)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print("Создан /etc/wireguard/wg0.conf (0600). VPN ещё не запущен.")


if __name__ == "__main__":
    main()
