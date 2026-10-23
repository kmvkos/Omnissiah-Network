"""Root-owned local RPC with peer credential checking and strict helper verbs.

Service-account-only Unix socket. No arbitrary commands, file paths or shell.
"""
import json
import os
from pathlib import Path
import pwd
import socket
import struct
import subprocess
import tempfile

SOCKET = "/run/omnissiah-vpn/control.sock"
STATE = Path("/var/lib/omnissiah-network/vpn")
HELPER = "/usr/local/libexec/omnissiah-vpn-helper"
LIMIT = 65536


def process(message):
    if not isinstance(message, dict):
        raise ValueError("Expected JSON object")
    verb = message.get("action")
    if verb not in ("identity", "status", "prepare", "start", "apply", "route-preview", "route-transaction", "transaction-status", "cognitor-preview", "cognitor-add", "policy-preview", "policy-apply"):
        raise ValueError("Unknown operation")
    if set(message) - {"action", "node_name", "plan", "operation_id"}:
        raise ValueError("Unknown fields")
    node_name = message.get("node_name")
    if not isinstance(node_name, str) or not node_name or len(node_name) > 50 or any(
        c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
        for c in node_name
    ):
        raise ValueError("Invalid node name")
    expected = os.environ.get("OMNISSIAH_NODE_NAME")
    if not expected or node_name != expected:
        raise ValueError("Node mismatch")
    plan = message.get("plan")
    if verb in ("prepare", "apply", "route-preview", "route-transaction", "cognitor-preview", "cognitor-add", "policy-preview", "policy-apply"):
        if not isinstance(plan, dict):
            raise ValueError("Plan required")
    elif plan is not None:
        raise ValueError("Unexpected plan")
    operation_id = message.get("operation_id")
    if verb in ("route-transaction", "cognitor-add", "policy-apply"):
        from vpn_operation_fence import OperationRejected, validate_operation_id
        try:
            validate_operation_id(operation_id)
        except OperationRejected as exc:
            raise ValueError("Invalid operation UUIDv4") from exc
    elif operation_id is not None:
        raise ValueError("Unexpected operation ID")
    if verb in ("policy-preview", "policy-apply"):
        from vpn_acl_policy import LinuxACL
        if set(plan) not in ({"node_name", "address", "clients"},
                             {"node_name", "address", "clients", "expected_revision"}):
            raise ValueError("Unexpected ACL plan fields")
        raw = {key: value for key, value in plan.items() if key != "expected_revision"}
        protected = os.environ.get("OMNISSIAH_PROTECTED_MANAGEMENT_IPV4", "").split(",")
        service = LinuxACL(node_name=node_name, protected_ips=protected)
        if verb == "policy-preview":
            if "expected_revision" in plan:
                raise ValueError("Unexpected ACL preview revision")
            return service.preview(raw)
        if "expected_revision" not in plan:
            raise ValueError("ACL apply needs preview revision")
        return service.apply(raw, revision=plan["expected_revision"],
                             operation_id=operation_id)
    command = ["/usr/bin/python3", HELPER, verb, "--node-name", node_name]
    if operation_id is not None:
        command += ["--operation-id", operation_id]
    staged = None
    try:
        if plan is not None:
            STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(mode="w", dir=STATE, prefix="rpc-", suffix=".json", delete=False) as tmp:
                staged = Path(tmp.name)
                os.fchmod(tmp.fileno(), 0o600)
                json.dump(plan, tmp)
            command += ["--plan", str(staged)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=50)
        if result.returncode:
            # Keep stderr in the local journal; never pass it to HTTP clients.
            import logging
            logging.getLogger("omnissiah.vpn.rpc").error(
                "VPN helper %s exited %s: %s", verb,
                result.returncode, (result.stderr or "").strip()[:1000])
            raise ValueError("VPN helper rejected request; see local journal")
        return json.loads(result.stdout)
    finally:
        if staged is not None:
            staged.unlink(missing_ok=True)


def serve():
    if os.geteuid() != 0:
        raise RuntimeError("The VPN RPC service must run as root")
    service_uid = pwd.getpwnam("omnissiah").pw_uid
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    # Socket is created by the systemd socket unit and is already bound.
    if os.environ.get("LISTEN_FDS") == "1" and os.environ.get("LISTEN_PID") == str(os.getpid()):
        sock.close()
        sock = socket.fromfd(3, socket.AF_UNIX, socket.SOCK_STREAM)
    else:
        raise RuntimeError("Expected an activated systemd socket")
    while True:
        connection, _ = sock.accept()
        with connection:
            try:
                pid, uid, gid = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                if uid != service_uid:
                    raise PermissionError("Unauthorized local peer")
                connection.settimeout(10)
                data = bytearray()
                while not data.endswith(b"\n"):
                    block = connection.recv(4096)
                    if not block:
                        raise ValueError("Incomplete request")
                    data.extend(block)
                    if len(data) > LIMIT:
                        raise ValueError("Request too long")
                output = {"ok": True, "result": process(json.loads(data))}
            except Exception as exc:
                output = {"ok": False, "error": str(exc) if isinstance(exc, ValueError) else "Request rejected"}
            connection.sendall(json.dumps(output).encode() + b"\n")


if __name__ == "__main__":
    serve()
