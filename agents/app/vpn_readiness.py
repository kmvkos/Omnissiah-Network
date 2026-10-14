"""Read-only WireGuard readiness checks for authenticated management calls.

No root privileges, network mutations, or private-key disclosure.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess


def get_readiness(config):
    expected = config.get("name") or config.get("node_name")
    errors = []
    if not expected:
        errors.append("missing_node_identity")
    state = Path(os.environ.get("OMNISSIAH_VPN_STATE_DIR",
                                "/var/lib/omnissiah-network/vpn"))
    # The privileged state is normally 0700 root; no key material is read.
    iface = "wg0"
    try:
        present = subprocess.run(
            ["ip", "-j", "-d", "link", "show", "dev", iface],
            capture_output=True, text=True, timeout=2, check=False)
        active = present.returncode == 0 and any(
            link.get("linkinfo", {}).get("info_kind") == "wireguard" and
            "UP" in link.get("flags", [])
            for link in json.loads(present.stdout or "[]"))
    except (OSError, ValueError, subprocess.TimeoutExpired):
        active = False
        errors.append("interface_probe_failed")
    if not shutil.which("wg") or not shutil.which("wg-quick"):
        errors.append("wireguard_tools_missing")
    return {
        "node_name": expected,
        "interface": iface,
        "vpn_enabled": active,
        "management_mode": "isolated" if config.get("mtls_required") else "legacy",
        "manage_wireguard": bool(config.get("manage_wireguard", False)),
        "helper_installed": Path("/usr/local/libexec/omnissiah-vpn-helper").is_file(),
        "key_present": None,  # Only root helper can report identity state.
        "desired_state": "unconfigured",
        "errors": errors,
    }
