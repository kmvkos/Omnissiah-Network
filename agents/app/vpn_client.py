"""Unix-socket bridge to the root-owned VPN helper (no shell and no sudo)."""
import json
import os
import socket

SOCKET = "/run/omnissiah-vpn/control.sock"
MAX_BYTES = 65536


def request_helper(action, *, plan=None, node_name=None):
    if action not in ("identity", "status", "prepare", "start", "apply"):
        raise ValueError("Unsupported VPN action")
    message = {"action": action}
    if node_name is not None:
        message["node_name"] = node_name
    if plan is not None:
        message["plan"] = plan
    payload = json.dumps(message, separators=(",", ":")).encode()
    if len(payload) > MAX_BYTES:
        raise ValueError("VPN plan too large")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(20)
        connection.connect(SOCKET)
        connection.sendall(payload + b"\n")
        data = bytearray()
        while not data.endswith(b"\n"):
            chunk = connection.recv(8192)
            if not chunk:
                raise RuntimeError("VPN helper closed without a result")
            data.extend(chunk)
            if len(data) > MAX_BYTES:
                raise RuntimeError("VPN helper response too large")
    result = json.loads(data)
    if not result.get("ok"):
        raise RuntimeError(result.get("error", "VPN helper error"))
    return result["result"]
