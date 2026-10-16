#!/usr/bin/python3
"""Root-only conservative VPN recovery entrypoint for a future boot service.

This entrypoint is NOT part of the agent HTTP API and cannot be invoked
through VPN RPC. It does not mutate any network interface or Linux route.
The systemd service is installed disabled until supervised lab validation.
"""
import json
import os
from pathlib import Path
import stat
import sys

from vpn_linux_preflight import LinuxReadOnlyPreflight
from vpn_prepared_recovery import PreparedRecoveryBlocked, reconcile_prepared
from vpn_route_executor_sim import _load_journal


STATE = Path("/var/lib/omnissiah-network/vpn")
CONFIG = Path("/etc/wireguard/wg0.conf")
MANAGED = b"# Managed by Omnissiah VPN v2\n"


class ReadOnlyBackend:
    def snapshot(self):
        return LinuxReadOnlyPreflight().snapshot()

    def _config_bytes(self):
        if CONFIG.is_symlink() or not CONFIG.is_file():
            raise PreparedRecoveryBlocked("No managed WireGuard config")
        info = CONFIG.stat()
        if info.st_uid != os.geteuid() or info.st_mode & 0o077 or not stat.S_ISREG(info.st_mode):
            raise PreparedRecoveryBlocked("Unsafe WireGuard config")
        data = CONFIG.read_bytes()
        if not data.startswith(MANAGED):
            raise PreparedRecoveryBlocked("Foreign WireGuard config")
        return data


def run():
    if os.geteuid() != 0:
        raise PreparedRecoveryBlocked("Root-only recovery")
    # Do not create a state folder, backup or lock file just to inspect it.
    if not STATE.exists() or STATE.is_symlink():
        return {"state": "not_initialized", "changed": False}
    journal = _load_journal(STATE / "mesh-transaction.json")
    if journal is None:
        return {"state": "idle", "changed": False}
    if not isinstance(journal, dict):
        raise PreparedRecoveryBlocked("Invalid journal")
    if journal.get("state") in ("committed", "rolled_back"):
        return {"state": journal["state"], "changed": False}
    if journal.get("state") != "prepared":
        raise PreparedRecoveryBlocked("Interrupted transaction needs operator review")
    # The recovery routine takes the same flock as the writer and revalidates
    # everything, preventing any race between this observation and completion.
    return reconcile_prepared(STATE, ReadOnlyBackend())


if __name__ == "__main__":
    try:
        print(json.dumps(run(), sort_keys=True))
    except (PreparedRecoveryBlocked, OSError, ValueError) as exc:
        # Never include backend exception payloads: they might contain
        # configuration lines or command output with secret key material.
        print(json.dumps({"state": "recovery_required",
                          "changed": False, "reason": "prepared_recovery_refused"}))
        sys.exit(1)
