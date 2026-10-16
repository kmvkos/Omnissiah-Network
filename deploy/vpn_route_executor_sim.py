"""Offline-only, durable route transaction simulator.

The executor is deliberately not imported by a privileged helper or HTTP endpoint.
It models route operations on an injected backend, journals every transition before
and after mutations, and fails closed after interruptions. WireGuard sync and
production recovery are NOT implemented; this is not safe for live traffic.
"""
import fcntl
import json
import os
from pathlib import Path
import tempfile

from vpn_route_journal import assert_snapshot_unchanged
from vpn_route_tx import RouteConflict


class TransactionBlocked(RuntimeError):
    """The operator must inspect and explicitly recover the journal."""


def _durable_write(directory, name, record):
    """Replace the journal atomically and fsync both contents and directory."""
    directory = Path(directory)
    payload = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
    temp_name = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", dir=directory, prefix=".journal-", delete=False
        ) as stream:
            temp_name = stream.name
            os.chmod(temp_name, 0o600)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, directory / name)
        temp_name = None
        dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        if temp_name is not None:
            os.unlink(temp_name)


def _load_journal(path):
    if path.is_symlink():
        raise TransactionBlocked("Symlink journal refused")
    if not path.exists():
        return None
    if not path.is_file():
        raise TransactionBlocked("Invalid journal")
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise TransactionBlocked("Unparseable journal; manual recovery required") from exc


def run_simulated(transaction, backend, directory):
    """Run prepared route steps against a test backend, not against Linux.

    backend must provide snapshot() -> (peers, main_routes), apply(step),
    and verify(transaction). Never invoke with a real-network adapter.

    A pending transaction is left in the journal across crashes. Even if
    a simulated rollback succeeds, only an explicit later transaction may
    proceed after the journal shows a fully verified state.
    """
    directory = Path(directory)
    if not directory.is_dir() or directory.is_symlink():
        raise TransactionBlocked("Journal directory must already exist")
    lock_path = directory / "lock"
    if lock_path.is_symlink():
        raise TransactionBlocked("Symlink lock refused")
    with open(lock_path, "a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        path = directory / "route-journal.json"
        previous = _load_journal(path)
        if previous and previous.get("state") not in ("committed", "rolled_back"):
            raise TransactionBlocked("Unresolved transaction journal; manual recovery required")
        if transaction.get("executable") is not False or transaction.get("writes_performed") is not False:
            raise TransactionBlocked("Only non-executable preview plans may be simulated")
        steps = transaction.get("steps")
        rollback = transaction.get("rollback")
        if not isinstance(steps, list) or not isinstance(rollback, list):
            raise TransactionBlocked("Invalid transaction structure")
        inverse = {"add": "delete", "delete": "add"}
        if rollback != [
            {"op": inverse[step["op"]], "dst": step["dst"], "dev": step["dev"]}
            for step in reversed(steps)
        ]:
            raise TransactionBlocked("Non-reversible transaction rejected")
        if any(
            not isinstance(step, dict)
            or set(step) != {"op", "dst", "dev"}
            or step["op"] not in inverse
            or step["dev"] != "wg0"
            for step in steps
        ):
            raise TransactionBlocked("Unexpected route operation")
        before_peers, before_routes = backend.snapshot()
        assert_snapshot_unchanged(transaction, before_peers, before_routes)
        record = {"version": 1, "state": "prepared", "transaction": transaction,
                  "applied": 0, "pending": None}
        _durable_write(directory, path.name, record)
        completed = []
        try:
            for step in steps:
                # Write-ahead record before touching external state.
                record.update(state="applying", pending=step)
                _durable_write(directory, path.name, record)
                backend.apply(step)
                completed.append(step)
                record.update(applied=len(completed), pending=None)
                _durable_write(directory, path.name, record)
            backend.verify(transaction)
            record["state"] = "committed"
            _durable_write(directory, path.name, record)
            return record
        except Exception:
            record["state"] = "rolling_back"
            _durable_write(directory, path.name, record)
            try:
                # Include the pending operation: a failed call may have mutated
                # the kernel before raising. Recovery verification is mandatory.
                may_have_run = list(completed)
                pending = record.get("pending")
                if pending is not None:
                    may_have_run.append(pending)
                for step in reversed(may_have_run):
                    inverse_step = {"op": inverse[step["op"]], "dst": step["dst"], "dev": step["dev"]}
                    record["rollback_pending"] = inverse_step
                    _durable_write(directory, path.name, record)
                    backend.revert(inverse_step)
                    record["rollback_pending"] = None
                    _durable_write(directory, path.name, record)
                now_peers, now_routes = backend.snapshot()
                assert_snapshot_unchanged(transaction, now_peers, now_routes)
            except Exception as rollback_exc:
                record["state"] = "recovery_required"
                _durable_write(directory, path.name, record)
                raise TransactionBlocked("Rollback verification failed; manual recovery required") from rollback_exc
            record.update(state="rolled_back", pending=None)
            _durable_write(directory, path.name, record)
            raise
