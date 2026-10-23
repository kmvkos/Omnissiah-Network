"""Update installation-owned settings while preserving agent-owned VPN state."""
import argparse
import json
from pathlib import Path
from pki import write_if_changed

MANAGED = {'name', 'role', 'management_ip', 'controller_name', 'server_url',
           'mtls_enabled', 'mtls_required', 'mtls_cert_file', 'mtls_key_file', 'mtls_ca_cert_file',
           'vpn_route_transactions_enabled', 'vpn_policy_apply_enabled', 'vpn_cross_route_mutations_enabled'}


def configure(path, desired):
    path = Path(path)
    existing = json.loads(path.read_text()) if path.exists() else {}
    if existing.get('name', desired['name']) != desired['name']:
        raise ValueError('Node identity change requires explicit migration')
    for key, value in desired.items():
        if key in MANAGED or key not in existing:
            existing[key] = value
    return write_if_changed(path, (json.dumps(existing, indent=2, sort_keys=True) + '\n').encode())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--desired', type=Path, required=True)
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps({'changed': configure(args.config, json.loads(args.desired.read_text()))}))
