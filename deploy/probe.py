"""Deployment smoke checks with mandatory TLS validation."""
import argparse
import json
import os
import sys
from pathlib import Path
import requests


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    heartbeat = sub.add_parser('heartbeat'); heartbeat.add_argument('--config', type=Path, required=True)
    agent = sub.add_parser('agent'); agent.add_argument('--url', required=True)
    agent.add_argument('--pki', type=Path, required=True)
    args = parser.parse_args()
    if args.operation == 'heartbeat':
        # Exercise the actual agent implementation. A verification heartbeat must
        # never replace runtime VPN state with installation-time false values.
        os.environ['OMNISSIAH_AGENT_CONFIG'] = str(args.config.resolve())
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'agents'))
        from app.heartbeat import send_heartbeat
        config = json.loads(args.config.read_text())
        if not send_heartbeat(config):
            raise RuntimeError('Authenticated agent heartbeat failed')
        print(json.dumps({'status': 'ok', 'operation': 'heartbeat'}))
        return
    else:
        session = requests.Session()
        session.trust_env = False
        session.cert = (str(args.pki / 'identity.crt'), str(args.pki / 'identity.key'))
        session.verify = str(args.pki / 'ca.crt')
        with session:
            response = session.get(args.url, timeout=10)
    response.raise_for_status()
    print(json.dumps({'status': response.status_code, 'response': response.json()}))


if __name__ == '__main__':
    main()
