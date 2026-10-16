"""Read-only, fail-closed inspection of the root-owned VPN transaction journal.

No recovery or mutation is performed by this module. It deliberately exposes
only a small allowlist of status fields: never return saved WireGuard configs,
private keys, peer public keys, backup contents, or route snapshots to HTTP.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat

TERMINAL = frozenset(("committed", "rolled_back"))
ACTIVE = frozenset(("prepared", "applying", "rolling_back", "recovery_required"))
VALID_PHASES = frozenset(("none", "wg_sync", "route", "verify", "persist_config",
                          "restore", "manual", "done"))


def _bad(reason):
    return {"state": "recovery_required", "phase": "unknown",
            "route_ops": 0, "needs_attention": True,
            "backup_verified": False, "reason": reason}


def _valid_file(path):
    if path.is_symlink() or not path.is_file():
        return False
    info = path.stat()
    return (stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
            and info.st_mode & 0o077 == 0)


def inspect_transaction(directory):
    """Observe an idle, completed or interrupted operation without changing state.

    The shared, nonblocking file lock prevents a read from racing an active
    route transaction. If a writer owns the lock, report in_progress without
    inspecting possibly transient files.
    """
    folder = Path(directory)
    if not folder.exists():
        return {"state": "not_initialized", "phase": "none", "route_ops": 0,
                "needs_attention": False, "backup_verified": False, "reason": None}
    if folder.is_symlink() or not folder.is_dir():
        return _bad("unsafe_state_directory")
    info = folder.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        return _bad("unsafe_state_directory")
    lock_path = folder / "mesh-transaction.lock"
    journal = folder / "mesh-transaction.json"
    if journal.is_symlink():
        return _bad("unsafe_journal")
    if lock_path.is_symlink():
        return _bad("unsafe_lock_file")
    if not lock_path.exists():
        if journal.exists():
            return _bad("missing_lock_file")
        # A backup can be durable before the first journal write. Never
        # misreport this crash window as a clean idle state.
        backup = folder / "mesh-backup.json"
        if backup.exists() or backup.is_symlink():
            return _bad("orphan_backup")
        return {"state": "idle", "phase": "none", "route_ops": 0,
                "needs_attention": False, "backup_verified": False, "reason": None}
    try:
        fd = os.open(lock_path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "r") as lock:
            meta = os.fstat(lock.fileno())
            if not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.geteuid() or meta.st_mode & 0o077:
                return _bad("unsafe_lock_file")
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError:
                return {"state": "in_progress", "phase": "unknown", "route_ops": 0,
                        "needs_attention": False, "backup_verified": False,
                        "reason": "transaction_lock_held"}
            return _inspect_locked(folder)
    except OSError:
        return _bad("journal_unavailable")


def _inspect_locked(folder):
    journal = folder / "mesh-transaction.json"
    if not journal.exists() and not journal.is_symlink():
        backup = folder / "mesh-backup.json"
        if backup.exists() or backup.is_symlink():
            return _bad("orphan_backup")
        return {"state": "idle", "phase": "none", "route_ops": 0,
                "needs_attention": False, "backup_verified": False, "reason": None}
    if not _valid_file(journal):
        return _bad("unsafe_journal")
    try:
        record = json.loads(journal.read_text())
    except (OSError, ValueError):
        return _bad("invalid_journal")
    if not isinstance(record, dict) or record.get("schema_version") != 1:
        return _bad("invalid_journal")
    state, phase, count = record.get("state"), record.get("phase"), record.get("route_ops")
    if state not in TERMINAL | ACTIVE or phase not in VALID_PHASES or type(count) is not int or count < 0:
        return _bad("invalid_journal")
    snapshot_hash = record.get("snapshot_sha256")
    if not isinstance(snapshot_hash, str) or len(snapshot_hash) != 64 or any(
        letter not in "0123456789abcdef" for letter in snapshot_hash
    ):
        return _bad("invalid_journal")
    backup = folder / "mesh-backup.json"
    verified = False
    if backup.exists() or backup.is_symlink():
        if not _valid_file(backup):
            return _bad("unsafe_backup")
        try:
            packed = json.loads(backup.read_text())
            data = packed["data"]
            digest = hashlib.sha256(json.dumps(data, sort_keys=True,
                separators=(",", ":")).encode()).hexdigest()
            verified = packed["sha256"] == digest and data["snapshot_sha256"] == snapshot_hash
        except (OSError, ValueError, TypeError, KeyError):
            return _bad("invalid_backup")
        if not verified:
            return _bad("invalid_backup")
    if state in ACTIVE and not verified:
        return _bad("missing_backup")
    return {"state": state, "phase": phase, "route_ops": count,
            "needs_attention": state in ACTIVE, "backup_verified": verified,
            "reason": "unresolved_transaction" if state in ACTIVE else None}
