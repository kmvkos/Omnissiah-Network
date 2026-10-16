#!/usr/bin/env python3
"""Read-only VPN reboot acceptance probe for a disposable Linux Magos VM.

Never calls wg-quick up/down, ip route add/del, systemctl start/stop or any
other mutator. Never prints or persists private keys or raw public peer keys.
A human must reboot or power off the disposable VM outside this program.

Usage:
  python3 scripts/vpn_vm_reboot_probe.py baseline --controller-ip 192.0.2.1 --out /tmp/vpn-before.json
  python3 scripts/vpn_vm_reboot_probe.py verify --controller-ip 192.0.2.1 --baseline /tmp/vpn-before.json --wait 90
"""
import argparse
import hashlib
from ipaddress import IPv4Address, ip_network
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time


class ProbeError(RuntimeError):
    pass


CONFIG_PATH = Path("/etc/wireguard/wg0.conf")


def _run(argv, *, runner=subprocess.run, allowed_codes=(0,)):
    result = runner(argv, capture_output=True, text=True, check=False, timeout=10)
    if result.returncode not in allowed_codes:
        raise ProbeError("observation_failed:" + argv[0])
    return result.stdout.strip()


def _fingerprint(public_key):
    # Raw peer keys are never printed or saved. A stable digest allows
    # comparison across reboot without disclosing the actual key.
    return hashlib.sha256(public_key.encode("ascii")).hexdigest()


def _peer_inventory(runner):
    peer_lines = _run(["wg", "show", "wg0", "peers"], runner=runner).splitlines()
    ids = set()
    for key in peer_lines:
        value = key.strip()
        if not re.fullmatch(r"[A-Za-z0-9+/]{43}=", value):
            raise ProbeError("invalid_peer_identity")
        digest = _fingerprint(value)
        if digest in ids:
            raise ProbeError("duplicate_peer_identity")
        ids.add(digest)
    if not ids:
        raise ProbeError("no_wireguard_peers")
    handshakes = {}
    for line in _run(["wg", "show", "wg0", "latest-handshakes"], runner=runner).splitlines():
        fields = line.split()
        if len(fields) != 2:
            raise ProbeError("malformed_handshake")
        try:
            stamp = int(fields[1])
        except ValueError as exc:
            raise ProbeError("malformed_handshake") from exc
        digest = _fingerprint(fields[0])
        if digest in handshakes:
            raise ProbeError("duplicate_handshake")
        handshakes[digest] = stamp
    if ids != set(handshakes):
        raise ProbeError("incomplete_handshake_observation")
    ips = {}
    for line in _run(["wg", "show", "wg0", "allowed-ips"], runner=runner).splitlines():
        fields = line.split()
        if len(fields) != 2:
            raise ProbeError("malformed_allowed_ips")
        digest = _fingerprint(fields[0])
        if digest in ips:
            raise ProbeError("duplicate_allowed_ips")
        networks = []
        for entry in fields[1].split(","):
            try:
                network = ip_network(entry.strip(), strict=True)
            except ValueError as exc:
                raise ProbeError("invalid_allowed_ips") from exc
            if network.version != 4 or network.prefixlen != 32:
                raise ProbeError("unexpected_peer_route")
            networks.append(str(network))
        if len(networks) != 1:
            raise ProbeError("expected_one_host_route_per_peer")
        ips[digest] = networks[0]
    if ids != set(ips) or len(set(ips.values())) != len(ips):
        raise ProbeError("inconsistent_allowed_ips")
    return sorted(ids), ips, handshakes


def _persisted_peer_inventory(config_path):
    """Inspect the managed on-disk config without displaying PrivateKey values.

    Inactive one-shot systemd state is safe for the *baseline* only if the
    on-disk configuration has the same peer identities and host routes as
    the currently running kernel. After reboot, systemd must be active.
    """
    path = Path(config_path)
    if path.is_symlink() or not path.is_file():
        raise ProbeError("missing_or_unsafe_persisted_config")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ProbeError("unsafe_persisted_config_permissions")
    try:
        lines = path.read_text().splitlines()
    except (UnicodeError, OSError) as exc:
        raise ProbeError("persisted_config_unreadable") from exc
    if not lines or lines[0] != "# Managed by Omnissiah VPN v2":
        raise ProbeError("unmanaged_persisted_config")
    section = None
    has_interface = False
    peers = {}
    current = None

    def complete_peer():
        if current is None:
            return
        key = current.get("PublicKey")
        cidr = current.get("AllowedIPs")
        if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9+/]{43}=", key):
            raise ProbeError("invalid_persisted_peer")
        try:
            network = ip_network(cidr, strict=True)
        except (ValueError, TypeError) as exc:
            raise ProbeError("invalid_persisted_peer_route") from exc
        if network.version != 4 or network.prefixlen != 32:
            raise ProbeError("unexpected_persisted_peer_route")
        digest = _fingerprint(key)
        if digest in peers:
            raise ProbeError("duplicate_persisted_peer")
        peers[digest] = str(network)

    for raw in lines[1:]:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            complete_peer()
            current = None
            section = line
            if section == "[Interface]":
                has_interface = True
            elif section == "[Peer]":
                if not has_interface:
                    raise ProbeError("invalid_persisted_config_structure")
                current = {}
            else:
                raise ProbeError("unsupported_persisted_config_section")
            continue
        if "=" not in line or section is None:
            raise ProbeError("invalid_persisted_config_structure")
        k, v = (part.strip() for part in line.split("=", 1))
        if section == "[Peer]" and k in ("PublicKey", "AllowedIPs"):
            if k in current:
                raise ProbeError("duplicate_persisted_peer_field")
            current[k] = v
    complete_peer()
    if not has_interface or not peers:
        raise ProbeError("persisted_config_incomplete")
    return peers


def snapshot(controller_ip, *, runner=subprocess.run, now=None,
             require_active=False, config_path=None):
    try:
        address = str(IPv4Address(controller_ip))
    except ValueError as exc:
        raise ProbeError("invalid_controller_ip") from exc
    if address == "0.0.0.0":
        raise ProbeError("invalid_controller_ip")
    ids, allowed, handshakes = _peer_inventory(runner)
    persisted = _persisted_peer_inventory(CONFIG_PATH if config_path is None else config_path)
    if persisted != allowed:
        raise ProbeError("persisted_peers_differ_from_kernel")
    try:
        main_routes = json.loads(_run(
            ["ip", "-j", "-4", "route", "show", "table", "main"], runner=runner))
        path = json.loads(_run(
            ["ip", "-j", "-4", "route", "get", address], runner=runner))
    except ValueError as exc:
        raise ProbeError("invalid_route_json") from exc
    if (not isinstance(main_routes, list) or not all(isinstance(x, dict) for x in main_routes)
            or not isinstance(path, list) or len(path) != 1 or not isinstance(path[0], dict)):
        raise ProbeError("incomplete_route_observation")
    management = path[0]
    if not management.get("dev") or management["dev"] == "wg0":
        raise ProbeError("unsafe_management_route")
    targets = set(allowed.values())
    actual = []
    for route in main_routes:
        if route.get("dev") != "wg0":
            continue
        dst = route.get("dst")
        if not isinstance(dst, str):
            raise ProbeError("unknown_wg0_route")
        try:
            net = ip_network(dst, strict=False)
        except ValueError as exc:
            raise ProbeError("unknown_wg0_route") from exc
        actual.append(str(net))
        if str(net) not in targets or route.get("gateway") or route.get("metric") not in (None, 0):
            raise ProbeError("unexpected_wg0_route")
    if len(actual) != len(targets) or set(actual) != targets:
        raise ProbeError("missing_or_duplicate_wg0_route")
    enabled = _run(["systemctl", "is-enabled", "wg-quick@wg0.service"], runner=runner)
    # is-active returns status 3 for inactive oneshot services even when a
    # manually started wg0 is healthy. Never reject baseline just for that.
    service = _run(["systemctl", "is-active", "wg-quick@wg0.service"],
                   runner=runner, allowed_codes=(0, 3))
    if enabled != "enabled":
        raise ProbeError("wg_quick_not_enabled")
    if service not in ("active", "inactive"):
        raise ProbeError("wg_quick_unhealthy_service")
    if require_active and service != "active":
        raise ProbeError("wg_quick_not_active_after_reboot")
    now = time.time() if now is None else now
    max_age = 180
    fresh = all(ts > 0 and 0 <= now - ts <= max_age for ts in handshakes.values())
    return {
        "schema_version": 1,
        "peer_fingerprints": ids,
        "peer_allowed_ips": {key: allowed[key] for key in ids},
        "wg0_routes": sorted(actual),
        "management": {k: management.get(k) for k in
                       ("dev", "gateway", "prefsrc", "src", "table")},
        "boot_enabled": True,
        "boot_active": service == "active",
        "handshakes_fresh": fresh,
    }


def verify(before, after):
    if not isinstance(before, dict) or before.get("schema_version") != 1:
        raise ProbeError("invalid_baseline")
    fields = ("peer_fingerprints", "peer_allowed_ips", "wg0_routes",
              "management", "boot_enabled")
    problems = [key for key in fields if before.get(key) != after.get(key)]
    # Unlike the baseline, the systemd service MUST be active after reboot.
    # Comparing the preboot state would report false drift when the node was
    # originally started via wg-quick up and systemctl enable.
    if after.get("boot_active") is not True:
        problems.append("wg_quick_not_active_after_reboot")
    if not before.get("handshakes_fresh"):
        problems.append("baseline_handshakes")
    if not after.get("handshakes_fresh"):
        problems.append("handshakes_fresh")
    return problems


def load_baseline(path):
    file = Path(path)
    if file.is_symlink() or not file.is_file():
        raise ProbeError("unsafe_baseline")
    info = file.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ProbeError("unsafe_baseline_permissions")
    try:
        data = json.loads(file.read_text())
    except (ValueError, OSError) as exc:
        raise ProbeError("unreadable_baseline") from exc
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ProbeError("invalid_baseline")
    return data


def write_baseline(path, value):
    file = Path(path)
    parent = file.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ProbeError("unsafe_baseline_directory")
    if file.is_symlink() or (file.exists() and not file.is_file()):
        raise ProbeError("unsafe_baseline_destination")
    temp = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", dir=parent, prefix=".vpn-reboot-", delete=False
        ) as stream:
            temp = Path(stream.name)
            os.fchmod(stream.fileno(), 0o600)
            json.dump(value, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, file)
        temp = None
        handle = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(handle)
        finally:
            os.close(handle)
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only WireGuard reboot acceptance")
    parser.add_argument("action", choices=("baseline", "verify"))
    parser.add_argument("--controller-ip", required=True)
    parser.add_argument("--out")
    parser.add_argument("--baseline")
    parser.add_argument("--wait", type=int, default=0)
    args = parser.parse_args(argv)
    if not (0 <= args.wait <= 300):
        parser.error("--wait must be 0..300 seconds")
    if args.action == "baseline" and (not args.out or args.baseline):
        parser.error("baseline requires --out only")
    if args.action == "verify" and (not args.baseline or args.out):
        parser.error("verify requires --baseline only")
    try:
        if args.action == "baseline":
            observed = snapshot(args.controller_ip)
            if not observed["handshakes_fresh"]:
                raise ProbeError("baseline_handshakes_not_fresh")
            write_baseline(args.out, observed)
            print(json.dumps({"result": "baseline_saved", "peers": len(observed["peer_fingerprints"])}))
            return 0
        before = load_baseline(args.baseline)
        deadline = time.monotonic() + args.wait
        while True:
            try:
                current = snapshot(args.controller_ip, require_active=True)
                failures = verify(before, current)
            except ProbeError as exc:
                failures = [str(exc)]
            if not failures or time.monotonic() >= deadline:
                break
            time.sleep(min(5, max(0, deadline - time.monotonic())))
        print(json.dumps({"result": "pass" if not failures else "fail",
                          "problems": failures, "writes_performed": False}))
        return 0 if not failures else 2
    except ProbeError as exc:
        print(json.dumps({"result": "fail", "problems": [str(exc)],
                          "writes_performed": False}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
