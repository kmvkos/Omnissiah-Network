"""Narrow, fail-closed recovery of interrupted add-only VPN transactions.

NOT an agent action, API endpoint or enabled boot job. Requires a durable v1
journal with a public desired-peer descriptor written before the first kernel
mutation. Only additions of new peer keys and /32 host routes are recoverable.

This intentionally refuses replacement/removal of existing peers, subnet routes,
foreign changes and old journals that lack the descriptor.
"""
import base64
import binascii
import fcntl
from ipaddress import IPv4Address, ip_network
import json
import os
from pathlib import Path

from vpn_prepared_recovery import PreparedRecoveryBlocked, _load_backup, _secure_regular
from vpn_route_executor_sim import _durable_write, _load_journal
from vpn_route_journal import prepare_transaction, snapshot_digest
from vpn_route_tx import normalize_route, reject_protected_host_routes


class AddOnlyRecoveryBlocked(PreparedRecoveryBlocked):
    pass


def _identity(peer, *, desired=False):
    if not isinstance(peer, dict):
        raise AddOnlyRecoveryBlocked("Invalid peer observation")
    if desired and set(peer) != {"public_key", "endpoint", "allowed_ips", "keepalive"}:
        raise AddOnlyRecoveryBlocked("Invalid recovery descriptor")
    key = peer.get("public_key")
    try:
        if not isinstance(key, str) or len(base64.b64decode(key, validate=True)) != 32:
            raise ValueError("Invalid key")
    except (binascii.Error, ValueError) as exc:
        raise AddOnlyRecoveryBlocked("Invalid public peer identity") from exc
    endpoint = peer.get("endpoint")
    try:
        host, port = endpoint.rsplit(":", 1)
        address = IPv4Address(host)
        if address.is_unspecified or address.is_multicast:
            raise ValueError("Invalid endpoint address")
        if not (1 <= int(port) <= 65535):
            raise ValueError("Invalid endpoint port")
    except (AttributeError, TypeError, ValueError) as exc:
        raise AddOnlyRecoveryBlocked("Invalid peer endpoint") from exc
    ips = peer.get("allowed_ips")
    if not isinstance(ips, list) or len(ips) != 1:
        raise AddOnlyRecoveryBlocked("Invalid peer AllowedIPs")
    try:
        dst = ip_network(ips[0], strict=True)
        if dst.version != 4 or dst.prefixlen != 32 or dst.network_address.is_multicast or dst.network_address.is_unspecified:
            raise ValueError("Invalid destination")
    except (TypeError, ValueError) as exc:
        raise AddOnlyRecoveryBlocked("Invalid peer host route") from exc
    keepalive = peer.get("keepalive")
    if type(keepalive) is not int or not 0 <= keepalive <= 65535:
        raise AddOnlyRecoveryBlocked("Invalid keepalive")
    return (key, str(endpoint), str(dst), keepalive)


def _peers_by_key(peers, *, desired=False):
    if not isinstance(peers, list) or len(peers) > 128:
        raise AddOnlyRecoveryBlocked("Invalid peer set")
    result = {}
    destinations = set()
    for peer in peers:
        ident = _identity(peer, desired=desired)
        if ident[0] in result or ident[2] in destinations:
            raise AddOnlyRecoveryBlocked("Duplicate peer or destination")
        result[ident[0]] = ident
        destinations.add(ident[2])
    return result


def _unmanaged_routes(routes, add_destinations):
    """Return stable snapshot of every route not explicitly owned by this add."""
    # The general /32 planner ignores the default route; recovery must not.
    # Even unrelated default-route drift is a reason to refuse automation.
    unowned = []
    for raw in routes:
        row = normalize_route(raw)
        if row is None:
            unowned.append({"kernel_default": raw})
        elif row["dst"] not in add_destinations:
            unowned.append(row)
    return sorted(json.dumps(row, sort_keys=True) for row in unowned)


def _validate_new_routes(routes, add_destinations):
    seen = set()
    for row in routes:
        route = normalize_route(row)
        if route is None or route["dst"] not in add_destinations:
            continue
        if route["dst"] in seen:
            raise AddOnlyRecoveryBlocked("Ambiguous duplicate added route")
        seen.add(route["dst"])
        if (route["dev"] != "wg0" or route["gateway"]
                or route["metric"] not in (None, 0)
                or route["table"] not in ("main", 254)
                or route["type"] != "unicast"):
            raise AddOnlyRecoveryBlocked("Foreign route at added destination")
        if route["protocol"] not in (None, "boot") or route["scope"] not in (None, "link"):
            raise AddOnlyRecoveryBlocked("Unexpected route ownership")


def _protect_paths(backend, addresses):
    rows = {}
    for host in addresses:
        raw = backend._command(["ip", "-j", "-4", "route", "get", host])
        try:
            parsed = json.loads(raw)
        except (ValueError, TypeError) as exc:
            raise AddOnlyRecoveryBlocked("Protected routing is not observable") from exc
        if not isinstance(parsed, list) or len(parsed) != 1 or not isinstance(parsed[0], dict):
            raise AddOnlyRecoveryBlocked("Protected route observation incomplete")
        route = parsed[0]
        if not route.get("dev") or route["dev"] == "wg0":
            raise AddOnlyRecoveryBlocked("Protected route traverses WireGuard")
        rows[host] = {key: route.get(key) for key in ("dev", "gateway", "prefsrc", "src", "table")}
    return rows


def _interface_section(conf):
    if not isinstance(conf, str) or not conf.startswith("[Interface]\n"):
        raise AddOnlyRecoveryBlocked("Invalid kernel WireGuard configuration")
    return conf.split("\n[Peer]", 1)[0]


def reconcile_add_only(folder, backend, management_addresses):
    """Restore original mesh after an interrupted *add-only* route-stage change.

    The concrete backend must be explicitly mutation enabled and rooted.
    This is a local root-only recovery helper, not a remotely callable action.
    An incomplete rollback can be retried only if it still matches a proven
    subset of the original add-only operation.
    """
    folder = Path(folder)
    if getattr(backend, "_state", None) != folder:
        raise AddOnlyRecoveryBlocked("Backend state directory does not match journal")
    if folder.is_symlink() or not folder.is_dir():
        raise AddOnlyRecoveryBlocked("Unsafe recovery directory")
    info = folder.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise AddOnlyRecoveryBlocked("Unsafe recovery directory permissions")
    _secure_regular(folder / "mesh-transaction.lock")
    fd = os.open(folder / "mesh-transaction.lock", os.O_RDWR | os.O_NOFOLLOW)
    with os.fdopen(fd, "r+") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise AddOnlyRecoveryBlocked("Transaction still in progress") from exc
        _secure_regular(folder / "mesh-transaction.json")
        record = _load_journal(folder / "mesh-transaction.json")
        if not isinstance(record, dict) or record.get("schema_version") != 1:
            raise AddOnlyRecoveryBlocked("Invalid journal")
        if record.get("state") in ("committed", "rolled_back"):
            return {"state": record["state"], "changed": False}
        is_new = record.get("state") == "applying" and record.get("phase") == "route"
        is_resume = (record.get("state") == "rolling_back"
                     and record.get("phase") == "add_only_recovery")
        if not (is_new or is_resume):
            raise AddOnlyRecoveryBlocked("Transaction phase is not recoverable")
        digest = record.get("snapshot_sha256")
        if not isinstance(digest, str) or len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise AddOnlyRecoveryBlocked("Invalid journal generation")
        old = _load_backup(folder, digest)
        recovery = record.get("recovery")
        if not isinstance(recovery, dict) or set(recovery) != {"desired_peers"}:
            raise AddOnlyRecoveryBlocked("No authenticated recovery descriptor")
        desired = recovery["desired_peers"]
        before = _peers_by_key(old["peers"])
        after = _peers_by_key(desired, desired=True)
        if not before or not set(before) < set(after):
            raise AddOnlyRecoveryBlocked("Only peer additions are recoverable")
        if any(after[k] != before[k] for k in before):
            raise AddOnlyRecoveryBlocked("Existing peer modification is not recoverable")
        transaction = prepare_transaction(desired, old["peers"], old["routes"])
        if transaction["snapshot_sha256"] != digest or transaction["delta"]["remove"]:
            raise AddOnlyRecoveryBlocked("Untrusted route recovery delta")
        added = set(transaction["delta"]["add"])
        expected_new = {after[k][2] for k in (after.keys() - before.keys())}
        if not added or added != expected_new or len(added) > 8:
            raise AddOnlyRecoveryBlocked("Unsupported recovery route set")
        if type(record.get("route_ops")) is not int or record["route_ops"] > len(added) or record["route_ops"] < 0:
            raise AddOnlyRecoveryBlocked("Invalid route operation count")
        steps = transaction["steps"]
        if is_new:
            pending = record.get("pending_route")
            if pending is not None and pending != (steps[record["route_ops"]] if record["route_ops"] < len(steps) else None):
                raise AddOnlyRecoveryBlocked("Unexpected pending route")
        if not management_addresses:
            raise AddOnlyRecoveryBlocked("No trusted management addresses")
        reject_protected_host_routes(desired, old["peers"], management_addresses)
        protected = sorted(set(management_addresses) |
                           {ident[1].rsplit(":", 1)[0] for ident in after.values()})
        # Mutation opt-in is independently checked by the privileged backend.
        backend._require_enabled()
        peers, routes = backend.snapshot()
        running = _peers_by_key(peers)
        if is_new and running != after:
            raise AddOnlyRecoveryBlocked("Kernel peer state differs from completed syncconf")
        if is_resume and (not set(before) <= set(running) or not set(running) <= set(after)
                          or any(running[k] != before[k] for k in before)
                          or any(running[k] != after[k] for k in set(running) - set(before))):
            raise AddOnlyRecoveryBlocked("Foreign peer state during rollback")
        if _unmanaged_routes(routes, added) != _unmanaged_routes(old["routes"], added):
            raise AddOnlyRecoveryBlocked("Unrelated kernel route changed")
        _validate_new_routes(routes, added)
        original_file = old["config"].encode()
        if backend._config_bytes() != original_file:
            raise AddOnlyRecoveryBlocked("Persisted configuration is not original")
        current_conf = backend._command(["wg", "showconf", "wg0"])
        if _interface_section(current_conf) != _interface_section(old["wg_conf"]):
            raise AddOnlyRecoveryBlocked("WireGuard interface identity changed")
        before_paths = _protect_paths(backend, protected)
        # Every dynamic field and every route is verified before the first write.
        if is_new:
            record.update(state="rolling_back", phase="add_only_recovery")
            record.pop("pending_route", None)
            _durable_write(folder, "mesh-transaction.json", record)

        # Removal-only operations. An absent added route/peer is a valid
        # intermediate rollback state; an unowned route is never overwritten.
        for dst in sorted(added):
            current_peers, current_routes = backend.snapshot()
            _validate_new_routes(current_routes, added)
            if (_unmanaged_routes(current_routes, added)
                    != _unmanaged_routes(old["routes"], added)
                    or _protect_paths(backend, protected) != before_paths):
                raise AddOnlyRecoveryBlocked("Foreign route changed during rollback")
            observed = _peers_by_key(current_peers)
            if (not set(before) <= set(observed) or not set(observed) <= set(after)
                    or any(observed[k] != before[k] for k in before)
                    or any(observed[k] != after[k] for k in set(observed) - set(before))):
                raise AddOnlyRecoveryBlocked("Foreign peer changed during rollback")
            if any(normalize_route(route) is not None
                   and normalize_route(route)["dst"] == dst for route in current_routes):
                backend._command(["ip", "-4", "route", "delete", dst, "dev", "wg0", "table", "main"])
        for key in sorted(set(after) - set(before)):
            current_peers, current_routes = backend.snapshot()
            if (_unmanaged_routes(current_routes, added)
                    != _unmanaged_routes(old["routes"], added)
                    or _protect_paths(backend, protected) != before_paths):
                raise AddOnlyRecoveryBlocked("Foreign route changed during rollback")
            observed = _peers_by_key(current_peers)
            if (not set(before) <= set(observed) or not set(observed) <= set(after)
                    or any(observed[k] != before[k] for k in before)
                    or any(observed[k] != after[k] for k in set(observed) - set(before))):
                raise AddOnlyRecoveryBlocked("Foreign peer changed during rollback")
            if key in observed:
                backend._command(["wg", "set", "wg0", "peer", key, "remove"])

        peers_final, routes_final = backend.snapshot()
        if (_peers_by_key(peers_final) != before
                or snapshot_digest(peers_final, routes_final) != digest
                or backend._config_bytes() != original_file
                or _interface_section(backend._command(["wg", "showconf", "wg0"])) != _interface_section(old["wg_conf"])
                or _protect_paths(backend, protected) != before_paths):
            raise AddOnlyRecoveryBlocked("Rollback verification failed; manual review required")
        record.update(state="rolled_back", phase="done")
        _durable_write(folder, "mesh-transaction.json", record)
        if record.get("operation_id") is not None:
            from vpn_operation_fence import finish
            finish(folder, record["operation_id"], "rolled_back")
        return {"state": "rolled_back", "changed": True}
