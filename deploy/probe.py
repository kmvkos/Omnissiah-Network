"""Deployment smoke checks with mandatory TLS validation."""
import argparse
import json
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
        config = json.loads(args.config.read_text())
        response = requests.post(config['server_url'] + '/api/magos/heartbeat',
            cert=(config['mtls_cert_file'], config['mtls_key_file']),
            verify=config['mtls_ca_cert_file'], timeout=10,
            json={'name': config['name'], 'local_ip': config['management_ip'],
                  'wireguard_enabled': False, 'interfaces': []})
    else:
        response = requests.get(args.url,
            cert=(str(args.pki / 'identity.crt'), str(args.pki / 'identity.key')),
            verify=str(args.pki / 'ca.crt'), timeout=10)
    response.raise_for_status()
    print(json.dumps({'status': response.status_code, 'response': response.json()}))


if __name__ == '__main__':
    main()
