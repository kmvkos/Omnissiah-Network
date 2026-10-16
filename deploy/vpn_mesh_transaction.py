"""Fail-closed, offline WireGuard + route + configuration transaction coordinator.

This module is NOT wired into the daemon or privileged helper. It accepts only an
injected test backend and never invokes kernel/file commands itself. A production
backend needs atomic, root-owned backups and crash recovery before activation.
"""
import fcntl
import json
from pathlib import Path

from vpn_route_journal import assert_snapshot_unchanged, prepare_transaction
from vpn_route_executor_sim import _durable_write, _load_journal, TransactionBlocked


class MeshTransactionBlocked(TransactionBlocked):
    pass


def _journal(folder, record):
    _durable_write(folder, "mesh-transaction.json", record)


def _check_plan(plan):
    if not isinstance(plan, dict) or plan.get("schema_version") != 1:
        raise MeshTransactionBlocked("Invalid transaction plan")
    if plan.get("iface") != "wg0" or plan.get("executable") is not False:
        raise MeshTransactionBlocked("Only inert wg0 previews are supported")
    if plan.get("writes_performed") is not False:
        raise MeshTransactionBlocked("Mutated preview refused")
    steps, inverse_steps = plan.get("steps"), plan.get("rollback")
    if not isinstance(steps, list) or not isinstance(inverse_steps, list):
        raise MeshTransactionBlocked("Missing route delta or inverse")
    invert = {"add": "delete", "delete": "add"}
    if any(not isinstance(s, dict) or set(s) != {"op", "dst", "dev"}
           or s["op"] not in invert or s["dev"] != "wg0" for s in steps):
        raise MeshTransactionBlocked("Invalid route step")
    if inverse_steps != [{"op": invert[s["op"]], "dst": s["dst"], "dev": "wg0"}
                         for s in reversed(steps)]:
        raise MeshTransactionBlocked("Inconsistent rollback plan")


def run_offline_mesh_transaction(plan, desired, backend, journal_directory):
    """Orchestrate a fault-injectable offline transaction.

    Backend contract: snapshot()->(wg_peers, routes), stage_backup(),
    sync_wireguard(desired), route_step(step), verify(desired, plan),
    persist_config(desired), restore_wireguard(), restore_routes(),
    restore_config(), verify_restored(). Backups are wholly backend-owned.

    Crash recovery is intentionally NOT automated. Any nonterminal journal
    blocks further operations until an operator reviews kernel+disk state.
    """
    directory = Path(journal_directory)
    if directory.is_symlink() or not directory.is_dir():
        raise MeshTransactionBlocked("Journal directory must preexist")
    _check_plan(plan)
    lockfile = directory / "mesh-transaction.lock"
    if lockfile.is_symlink():
        raise MeshTransactionBlocked("Symlink lock refused")
    with lockfile.open("a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        old = _load_journal(directory / "mesh-transaction.json")
        if old is not None and old.get("state") not in ("committed", "rolled_back"):
            raise MeshTransactionBlocked("Unresolved mesh transaction; manual recovery required")
        peers, routes = backend.snapshot()
        assert_snapshot_unchanged(plan, peers, routes)
        # Reject forged step sets even if the previous-state digest matches.
        canonical = prepare_transaction(desired, peers, routes)
        if canonical != plan:
            raise MeshTransactionBlocked("Preview does not match desired state")
        # Backups MUST exist before journal enters 'prepared'. A real backend
        # must durably persist original wg/file/route state; never journal keys.
        backend.stage_backup()
        rec = {"schema_version": 1, "state": "prepared", "phase": "none",
               "snapshot_sha256": plan["snapshot_sha256"], "route_ops": 0}
        _journal(directory, rec)
        try:
            rec.update(state="applying", phase="wg_sync")
            _journal(directory, rec)
            backend.sync_wireguard(desired)
            for step in plan["steps"]:
                rec.update(phase="route", pending_route=step)
                _journal(directory, rec)
                backend.route_step(step)
                rec["route_ops"] += 1
                rec.pop("pending_route", None)
                _journal(directory, rec)
            rec["phase"] = "verify"
            _journal(directory, rec)
            backend.verify(desired, plan)
            rec["phase"] = "persist_config"
            _journal(directory, rec)
            backend.persist_config(desired)
            rec.update(state="committed", phase="done")
            _journal(directory, rec)
            return {"state": "committed", "route_ops": rec["route_ops"]}
        except Exception as original:
            rec.update(state="rolling_back", phase="restore")
            _journal(directory, rec)
            try:
                # Backups are authoritative. Do NOT blindly invert individual
                # steps: a route call may mutate then raise.
                backend.restore_wireguard()
                backend.restore_routes()
                backend.restore_config()
                backend.verify_restored()
            except Exception as recovery_error:
                rec.update(state="recovery_required", phase="manual")
                _journal(directory, rec)
                raise MeshTransactionBlocked("Automatic rollback failed; manual recovery required") from recovery_error
            rec.update(state="rolled_back", phase="done")
            _journal(directory, rec)
            raise original
