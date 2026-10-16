"""Conservative recovery for the pre-mutation journal window.

A 'prepared' record is written only after its backup is durable and before
any kernel, route or config write. If the original state is still present, it
may be marked rolled_back without mutating WireGuard or Linux routes.

For 'applying', 'rolling_back' and 'recovery_required', no automatic repair is
attempted: reconstructing safe writes needs more information and fault tests.
No HTTP request is permitted to invoke this module.
"""
import fcntl
import json
import os
from pathlib import Path
import stat

from vpn_route_executor_sim import TransactionBlocked, _durable_write, _load_journal
from vpn_route_journal import snapshot_digest


class PreparedRecoveryBlocked(TransactionBlocked):
    pass


def _secure_regular(path):
    if path.is_symlink() or not path.is_file():
        raise PreparedRecoveryBlocked("Unsafe transaction file")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise PreparedRecoveryBlocked("Unsafe transaction file permissions")


def _load_backup(folder, snapshot_hash):
    from vpn_linux_backend import _digest
    path = folder / "mesh-backup.json"
    _secure_regular(path)
    try:
        record = json.loads(path.read_text())
        data = record["data"]
        if not isinstance(data, dict) or record["sha256"] != _digest(data):
            raise ValueError("Digest mismatch")
        if data.get("snapshot_sha256") != snapshot_hash:
            raise ValueError("Wrong backup generation")
        if not isinstance(data.get("config"), str) or not isinstance(data.get("wg_conf"), str):
            raise ValueError("Incomplete backup")
        if not isinstance(data.get("peers"), list) or not isinstance(data.get("routes"), list):
            raise ValueError("Incomplete snapshot")
        if snapshot_digest(data["peers"], data["routes"]) != snapshot_hash:
            raise ValueError("Forged snapshot")
    except (OSError, KeyError, TypeError, ValueError) as exc:
        raise PreparedRecoveryBlocked("Invalid transaction backup") from exc
    return data


def reconcile_prepared(folder, backend):
    """Mark a verified untouched 'prepared' transaction rolled_back.

    The caller supplies a read-only backend with snapshot() and _config_bytes().
    This never restores configurations, invokes wg/ip writes, deletes a backup,
    or begins another transaction. All other incomplete states stay blocked.
    """
    folder = Path(folder)
    if folder.is_symlink() or not folder.is_dir():
        raise PreparedRecoveryBlocked("Unsafe recovery directory")
    d = folder.stat()
    if d.st_uid != os.geteuid() or d.st_mode & 0o077:
        raise PreparedRecoveryBlocked("Unsafe recovery directory permissions")

    lockfile = folder / "mesh-transaction.lock"
    _secure_regular(lockfile)
    # Do not use O_CREAT and never wait behind an active writer.
    fd = os.open(lockfile, os.O_RDWR | os.O_NOFOLLOW)
    with os.fdopen(fd, "r+") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise PreparedRecoveryBlocked("Transaction still in progress") from exc

        journal = folder / "mesh-transaction.json"
        _secure_regular(journal)
        record = _load_journal(journal)
        if not isinstance(record, dict) or record.get("schema_version") != 1:
            raise PreparedRecoveryBlocked("Invalid transaction journal")
        if record.get("state") in ("committed", "rolled_back"):
            return {"state": record["state"], "changed": False}
        if record.get("state") != "prepared" or record.get("phase") != "none":
            raise PreparedRecoveryBlocked("Recovery requires operator review")

        snapshot_hash = record.get("snapshot_sha256")
        if (not isinstance(snapshot_hash, str) or len(snapshot_hash) != 64
                or any(ch not in "0123456789abcdef" for ch in snapshot_hash)
                or type(record.get("route_ops")) is not int
                or record["route_ops"] != 0
                or "pending_route" in record):
            raise PreparedRecoveryBlocked("Invalid prepared transaction")
        saved = _load_backup(folder, snapshot_hash)
        try:
            actual_peers, actual_routes = backend.snapshot()
            actual_config = backend._config_bytes()
            if (snapshot_digest(actual_peers, actual_routes) != snapshot_hash
                    or actual_config != saved["config"].encode()):
                raise PreparedRecoveryBlocked("Original state changed; operator review required")
        except (OSError, ValueError, TypeError) as exc:
            raise PreparedRecoveryBlocked("Cannot verify original state") from exc

        completed = dict(record, state="rolled_back", phase="done")
        completed.pop("pending_route", None)
        _durable_write(folder, "mesh-transaction.json", completed)
        if record.get("operation_id") is not None:
            # Only close a UUID after original state verification and the
            # terminal journal fsync. Failure leaves the UUID reserved.
            from vpn_operation_fence import finish
            finish(folder, record["operation_id"], "rolled_back")
        return {"state": "rolled_back", "changed": True}
