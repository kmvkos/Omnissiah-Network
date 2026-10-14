"""Restricted, root-owned WireGuard lifecycle helper.

No SSH/shell commands accepted from HTTP. The privileged helper consumes a
root-owned staged JSON plan, checks identity and syntax, and only manipulates
a fixed interface (wg0). It is intentionally NOT installed as sudoers yet.
"""
import argparse
import base64
import binascii
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

STATE = Path("/var/lib/omnissiah-network/vpn")
WG_DIR = Path("/etc/wireguard")
IFACE = "wg0"


class HelperError(Exception):
    pass


def run(argv, *, input=None):
    result = subprocess.run(argv, input=input, text=True, capture_output=True,
                            timeout=20)
    if result.returncode:
        raise HelperError("%s failed: %s" % (argv[0], result.stderr.strip()))
    return result.stdout


def validate_plan(data, expected_name):
    if not isinstance(data, dict) or set(data) != {"node_name", "address", "listen_port", "peers"}:
        raise HelperError("Unexpected plan schema")
    if data["node_name"] != expected_name:
        raise HelperError("Plan belongs to another node")
    if not isinstance(data["listen_port"], int) or not 1 <= data["listen_port"] <= 65535:
        raise HelperError("Invalid listen port")
    try:
        addr = ipaddress.ip_interface(data["address"])
    except (TypeError, ValueError) as exc:
        raise HelperError("Invalid interface address") from exc
    if addr.version != 4 or addr.network.prefixlen != 32 or addr.ip.is_unspecified or addr.ip.is_multicast:
        raise HelperError("Only explicit IPv4 /32 addresses are supported")
    seen_keys, seen_ips = set(), set()
    peers = data["peers"]
    if not isinstance(peers, list) or len(peers) > 128:
        raise HelperError("Invalid peer count")
    for peer in peers:
        if not isinstance(peer, dict) or set(peer) != {"public_key", "endpoint", "allowed_ips", "keepalive"}:
            raise HelperError("Unexpected peer schema")
        try:
            pub = base64.b64decode(peer["public_key"], validate=True)
        except (binascii.Error, ValueError, TypeError) as exc:
            raise HelperError("Invalid public key") from exc
        if len(pub) != 32 or peer["public_key"] in seen_keys:
            raise HelperError("Duplicate or invalid public key")
        seen_keys.add(peer["public_key"])
        endpoint = peer["endpoint"]
        if not isinstance(endpoint, str) or endpoint.count(":") != 1:
            raise HelperError("Invalid endpoint")
        host, port = endpoint.split(":")
        try:
            ip = ipaddress.IPv4Address(host)
            port_num = int(port)
        except ValueError as exc:
            raise HelperError("Invalid endpoint address") from exc
        if ip.is_unspecified or ip.is_multicast or not 1 <= port_num <= 65535:
            raise HelperError("Invalid endpoint")
        if not isinstance(peer["keepalive"], int) or not 0 <= peer["keepalive"] <= 65535:
            raise HelperError("Invalid keepalive")
        ips = peer["allowed_ips"]
        if not isinstance(ips, list) or len(ips) != 1:
            raise HelperError("Only one explicit host route per peer")
        try:
            network = ipaddress.ip_network(ips[0], strict=True)
        except (TypeError, ValueError) as exc:
            raise HelperError("Invalid AllowedIPs") from exc
        if network.version != 4 or network.prefixlen != 32 or network.network_address == addr.ip or network in seen_ips:
            raise HelperError("Broad, self or duplicate AllowedIPs")
        seen_ips.add(network)
    return data


def ensure_keys(state):
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    secret, public = state / "private.key", state / "public.key"
    if secret.exists() != public.exists():
        raise HelperError("Incomplete key pair; manual recovery required")
    if not secret.exists():
        value = run(["wg", "genkey"]).strip()
        key = run(["wg", "pubkey"], input=value + "\n").strip()
        fd = os.open(secret, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(value + "\n")
        fd = os.open(public, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        with os.fdopen(fd, "w") as f:
            f.write(key + "\n")
    else:
        derived = run(["wg", "pubkey"], input=secret.read_text()).strip()
        if derived != public.read_text().strip():
            raise HelperError("Stored WireGuard key pair does not match")
    return public.read_text().strip()


def render(data, private_key):
    lines = ["# Managed by Omnissiah VPN v2", "[Interface]", "PrivateKey = " + private_key,
             "Address = " + data["address"], "ListenPort = " + str(data["listen_port"])]
    for p in data["peers"]:
        lines.extend(["", "[Peer]", "PublicKey = " + p["public_key"],
                      "AllowedIPs = " + p["allowed_ips"][0],
                      "Endpoint = " + p["endpoint"],
                      "PersistentKeepalive = " + str(p["keepalive"])])
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["identity", "validate", "prepare", "start", "apply", "status"])
    parser.add_argument("--node-name", required=True)
    parser.add_argument("--plan", type=Path)
    args = parser.parse_args()
    if not args.node_name or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in args.node_name):
        parser.error("Invalid node name")
    if os.geteuid() != 0:
        parser.error("Must run as root")
    if args.command == "identity":
        print(json.dumps({"public_key": ensure_keys(STATE)}))
        return
    if args.command == "status":
        exists = subprocess.run(["ip", "link", "show", "dev", IFACE], capture_output=True).returncode == 0
        handshakes = {}
        if exists:
            output = run(["wg", "show", IFACE, "latest-handshakes"])
            for line in output.splitlines():
                fields = line.split()
                if len(fields) == 2:
                    try:
                        handshakes[fields[0]] = int(fields[1])
                    except ValueError:
                        pass
        print(json.dumps({"interface": IFACE, "active": exists, "handshakes": handshakes}))
        return
    if args.command == "start":
        config_file = WG_DIR / "wg0.conf"
        if not config_file.is_file() or config_file.is_symlink() or not config_file.read_text().startswith("# Managed by Omnissiah VPN v2\\n"):
            raise HelperError("No prepared configuration")
        if subprocess.run(["wg", "show", IFACE], capture_output=True).returncode == 0:
            print(json.dumps({"active": True, "changed": False}))
            return
        try:
            run(["wg-quick", "up", IFACE])
        except HelperError:
            # wg-quick tries its own rollback; do not change the management route.
            raise
        # Persist only after explicit, successful start.
        try:
            run(["systemctl", "enable", "wg-quick@wg0.service"])
        except HelperError:
            run(["wg-quick", "down", IFACE])
            raise
        print(json.dumps({"active": True, "changed": True, "boot_enabled": True}))
        return
    if not args.plan:
        parser.error("--plan required")
    # Only root-owned regular staged files in the state directory.
    candidate = args.plan
    if candidate.parent != STATE or candidate.is_symlink():
        raise HelperError("Plan path must be a direct child of root state directory")
    st = candidate.stat()
    if not candidate.is_file() or st.st_uid != 0 or st.st_mode & 0o077:
        raise HelperError("Plan must be a root-owned 0600 file")
    data = validate_plan(json.loads(candidate.read_text()), args.node_name)
    if args.command == "validate":
        print(json.dumps({"valid": True, "peers": len(data["peers"])}))
        return
    secret = STATE / "private.key"
    if not secret.is_file() or secret.is_symlink():
        raise HelperError("Identity must be initialized before apply")
    stored_config = WG_DIR / "wg0.conf"
    if stored_config.exists():
        if stored_config.is_symlink() or not stored_config.is_file() or not stored_config.read_text().startswith("# Managed by Omnissiah VPN v2\\n"):
            raise HelperError("Refusing to overwrite a configuration not owned by VPN v2")
    active = subprocess.run(["wg", "show", IFACE], capture_output=True).returncode == 0
    if args.command == "apply":
        # wg syncconf updates peers but does NOT manage Linux routes.
        # Refuse an active topology change until route reconciliation exists.
        def peer_routes(text):
            return sorted(
                value.split("=", 1)[1].strip()
                for value in text.splitlines()
                if value.strip().startswith("AllowedIPs =")
            )
        current_routes = peer_routes(stored_config.read_text()) if stored_config.exists() else []
        desired_routes = sorted(
            route for peer in data["peers"] for route in peer["allowed_ips"]
        )
        if current_routes != desired_routes:
            raise HelperError("Live route-set changes are not supported; use a controlled maintenance procedure")
    if args.command == "apply" and not active:
        raise HelperError("Interface is not active; refusing implicit activation")
    if args.command == "prepare" and active:
        raise HelperError("Cannot prepare while interface is active; use apply")
    ensure_keys(STATE)  # Verify the persisted private/public pair before use.
    content = render(data, secret.read_text().strip())
    with tempfile.NamedTemporaryFile(mode="w", dir=WG_DIR, prefix="wg-", suffix=".conf", delete=False) as file:
        file.write(content)
        tmp = Path(file.name)
    try:
        tmp.chmod(0o600)
        # wg-quick strip removes Address/other wg-quick-only settings.
        stripped = run(["wg-quick", "strip", str(tmp)])
        if args.command == "apply":
            previous = run(["wg", "showconf", IFACE])
            try:
                run(["wg", "syncconf", IFACE, "/dev/stdin"], input=stripped)
                tmp.replace(WG_DIR / "wg0.conf")
            except Exception:
                # Reconcile kernel peers back to the last observed configuration.
                run(["wg", "syncconf", IFACE, "/dev/stdin"], input=previous)
                raise
        else:
            tmp.replace(WG_DIR / "wg0.conf")
    finally:
        tmp.unlink(missing_ok=True)
    print(json.dumps({"action": args.command, "changed": True, "peers": len(data["peers"])}))


if __name__ == "__main__":
    try:
        main()
    except (HelperError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print("VPN helper error: " + str(exc), file=sys.stderr)
        sys.exit(1)
