"""Regression tests for the agent's managed-mode legacy API guard.

Extract the real before_request handler without importing the legacy agent,
whose module performs application/bootstrap work at import time.
"""
import ast
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]


def _guard(config, path):
    source = (ROOT / "agents/app/agent.py").read_text()
    tree = ast.parse(source)
    paths = next(
        node.value for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "_LEGACY_WRITE_PATHS"
                for target in node.targets)
    )
    fn = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
              and node.name == "require_controller_identity")
    fn.decorator_list = []
    namespace = {
        "frozenset": frozenset,
        "load_config": lambda: config,
        "request": SimpleNamespace(path=path),
        "jsonify": lambda **data: data,
    }
    module = ast.Module(body=[
        ast.Assign(targets=[ast.Name(id="_LEGACY_WRITE_PATHS", ctx=ast.Store())],
                   value=paths),
        fn,
    ], type_ignores=[])
    exec(compile(ast.fix_missing_locations(module), str(ROOT / "agents/app/agent.py"), "exec"), namespace)
    return namespace["require_controller_identity"]()


def test_managed_mtls_blocks_all_legacy_mutators():
    paths = (
        "/api/v1/install_dependencies", "/api/traffic_log/clear",
        "/api/add_peer", "/api/magos/update_config", "/api/update_config",
        "/api/v1/config/apply", "/api/v1/software/update",
    )
    for path in paths:
        payload, status = _guard({"mtls_required": True}, path)
        assert status == 403, path
        assert payload["error"] == "Legacy mutation API disabled in managed mode"


def test_legacy_mutators_are_not_blocked_by_new_guard_in_unmanaged_mode():
    assert _guard({"mtls_required": False}, "/api/v1/config/apply") is None


def test_managed_health_is_unaffected():
    assert _guard({"mtls_required": True}, "/health") is None
