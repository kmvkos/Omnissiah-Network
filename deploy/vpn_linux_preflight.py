"""Read-only Linux/WireGuard preflight for a future privileged transaction runner.

No route or WireGuard writes, no imports in the live RPC/helper path.
Only fixed argv operations are permitted. Operations are validated against
an independently captured kernel snapshot, never against user-provided routes.
"""
import json
import subprocess

from vpn_reconcile import parse_wg_dump
from vpn_route_journal import prepare_transaction, assert_snapshot_unchanged
from vpn_route_tx import RouteConflict


class KernelObservationError(RuntimeError):
    pass


class LinuxReadOnlyPreflight:
    """Observe Linux main-table routes and wg0 peers, without any mutation."""

    def __init__(self, runner=subprocess.run):
        self._runner = runner

    def _read(self, argv):
        result = self._runner(argv, capture_output=True, text=True, timeout=10, check=False)
        if result.returncode:
            raise KernelObservationError("Kernel observation failed: " + argv[0])
        return result.stdout

    def snapshot(self):
        # Fail closed if WG is absent. Never interpret absence as empty peers.
        wg = self._read(["wg", "show", "wg0", "dump"])
        peers = parse_wg_dump(wg)
        try:
            routes = json.loads(self._read(["ip", "-j", "-4", "route", "show", "table", "main"]))
        except (ValueError, TypeError) as exc:
            raise KernelObservationError("Invalid kernel IPv4 route JSON") from exc
        if not isinstance(routes, list) or not all(isinstance(route, dict) for route in routes):
            raise KernelObservationError("Incomplete kernel main-table route snapshot")
        return peers, routes

    def plan(self, desired_peers):
        actual_peers, routes = self.snapshot()
        return prepare_transaction(desired_peers, actual_peers, routes)

    def recheck(self, transaction):
        peers, routes = self.snapshot()
        return assert_snapshot_unchanged(transaction, peers, routes)


def _strict_route_operation(step):
    """Validate a preview step and produce an inert argv specification."""
    from ipaddress import ip_network
    if not isinstance(step, dict) or set(step) != {"op", "dst", "dev"}:
        raise RouteConflict("Invalid route operation")
    if step["op"] not in ("add", "delete") or step["dev"] != "wg0":
        raise RouteConflict("Unsupported route operation")
    try:
        net = ip_network(step["dst"], strict=True)
    except (TypeError, ValueError) as exc:
        raise RouteConflict("Malformed route destination") from exc
    if net.version != 4 or net.prefixlen != 32 or net.network_address.is_multicast or net.network_address.is_unspecified or net.network_address.is_loopback:
        raise RouteConflict("Only unicast IPv4 /32 destinations are permitted")
    return ["ip", "-4", "route", step["op"], str(net), "dev", "wg0", "table", "main"]


def preview_route_commands(transaction):
    """Return a non-executable list of strictly validated command arguments."""
    if not isinstance(transaction, dict) or transaction.get("executable") is not False:
        raise RouteConflict("Only non-executable transaction plans supported")
    if transaction.get("iface") != "wg0" or transaction.get("schema_version") != 1:
        raise RouteConflict("Unsupported transaction plan")
    steps = transaction.get("steps")
    rollback = transaction.get("rollback")
    if not isinstance(steps, list) or not isinstance(rollback, list):
        raise RouteConflict("Invalid transaction operations")
    # Validate every step before accessing its fields, including forged plans.
    result = [_strict_route_operation(step) for step in steps]
    [_strict_route_operation(step) for step in rollback]
    inverse = {"add": "delete", "delete": "add"}
    if rollback != [
        {"op": inverse[step["op"]], "dst": step["dst"], "dev": step["dev"]}
        for step in reversed(steps)
    ]:
        raise RouteConflict("Non-reversible transaction rejected")
    return {"commands": result, "writes_performed": False, "executable": False}
