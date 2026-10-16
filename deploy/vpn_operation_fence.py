"""Durable at-most-once admission ledger for privileged VPN route transactions.

The coordinator must hold mesh-transaction.lock exclusively before invoking
these helpers. They make no network calls. This ledger is an additional
fail-closed fence, NOT distributed exactly-once execution or automatic recovery.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import uuid

from vpn_route_executor_sim import _durable_write, TransactionBlocked

LEDGER = "mesh-operation-ledger.json"
MAX_OPERATIONS = 4096


class OperationRejected(TransactionBlocked):
    pass


def validate_operation_id(value):
    if not isinstance(value, str) or len(value) != 36:
        raise OperationRejected("A canonical operation UUIDv4 is required")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise OperationRejected("Invalid operation UUID") from exc
    if parsed.version != 4 or str(parsed) != value:
        raise OperationRejected("Operation ID must be canonical UUIDv4")
    return value


def revision(plan, desired):
    data = json.dumps({"plan": plan, "desired": desired},
                      sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(data.encode()).hexdigest()


def _load(directory):
    path = Path(directory) / LEDGER
    if not path.exists() and not path.is_symlink():
        return {"version": 1, "operations": {}}
    if path.is_symlink() or not path.is_file():
        raise OperationRejected("Unsafe operation ledger")
    info = path.stat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o077):
        raise OperationRejected("Operation ledger must be owner-only")
    try:
        obj = json.loads(path.read_text())
    except (ValueError, OSError) as exc:
        raise OperationRejected("Unreadable operation ledger") from exc
    if (not isinstance(obj, dict) or set(obj) != {"version", "operations"}
            or obj["version"] != 1 or not isinstance(obj["operations"], dict)
            or len(obj["operations"]) > MAX_OPERATIONS):
        raise OperationRejected("Invalid operation ledger")
    for op_id, record in obj["operations"].items():
        validate_operation_id(op_id)
        if (not isinstance(record, dict) or set(record) != {"revision", "state"}
                or not isinstance(record["revision"], str)
                or len(record["revision"]) != 64
                or any(c not in "0123456789abcdef" for c in record["revision"])
                or record["state"] not in ("reserved", "committed", "rolled_back")):
            raise OperationRejected("Corrupt operation record")
    return obj


def reserve(directory, operation_id, plan, desired):
    """Under coordinator exclusive lock: permanently block duplicate IDs.

    Also block *different* IDs while any earlier attempt is unaccounted for.
    The caller may move into backup / network writes only after fsync succeeds.
    """
    op_id = validate_operation_id(operation_id)
    folder = Path(directory)
    if folder.is_symlink() or not folder.is_dir():
        raise OperationRejected("Unsafe transaction state directory")
    info = folder.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise OperationRejected("Unsafe transaction state permissions")
    ledger = _load(folder)
    existing = ledger["operations"]
    if op_id in existing:
        raise OperationRejected("Operation ID already used; inspect journal, do not retry Apply")
    if any(item["state"] == "reserved" for item in existing.values()):
        raise OperationRejected("Earlier transaction outcome unknown; operator review required")
    if len(existing) >= MAX_OPERATIONS:
        raise OperationRejected("Operation ledger at capacity; operator maintenance required")
    previous = dict(existing)
    previous[op_id] = {"revision": revision(plan, desired), "state": "reserved"}
    _durable_write(folder, LEDGER, {"version": 1, "operations": previous})
    return op_id


def finish(directory, operation_id, outcome):
    """Mark a known terminal result only AFTER durable transaction journal."""
    op_id = validate_operation_id(operation_id)
    if outcome not in ("committed", "rolled_back"):
        raise OperationRejected("Invalid terminal state")
    folder = Path(directory)
    ledger = _load(folder)
    entry = ledger["operations"].get(op_id)
    if entry is None or entry["state"] != "reserved":
        raise OperationRejected("Missing/finished operation reservation")
    ledger["operations"][op_id]["state"] = outcome
    _durable_write(folder, LEDGER, ledger)


def status(directory, operation_id):
    """Sanitized, read-only status. No routes, keys or write effects."""
    op_id = validate_operation_id(operation_id)
    entry = _load(directory)["operations"].get(op_id)
    if entry is None:
        return {"state": "unknown", "writes_performed": False}
    return {"state": entry["state"], "writes_performed": False}
