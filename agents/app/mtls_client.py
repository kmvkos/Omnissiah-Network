"""Mutual TLS with certificate-chain and server-hostname verification."""
from pathlib import Path
import requests


def create_mtls_session(cert_file, key_file, ca_cert_file=None):
    for value in (cert_file, key_file, ca_cert_file):
        if value and not Path(value).is_file():
            raise FileNotFoundError(value)
    session = requests.Session()
    # Inventory-managed LAN connections must not inherit proxy/CA environment overrides.
    session.trust_env = False
    session.cert = (cert_file, key_file)
    session.verify = ca_cert_file or True
    return session


def get_mtls_session_from_config(config):
    base = Path(__file__).resolve().parent.parent
    paths = []
    for field in ('mtls_cert_file', 'mtls_key_file', 'mtls_ca_cert_file'):
        value = config.get(field)
        paths.append(str((base / value).resolve()) if value else None)
    if not paths[0] or not paths[1]:
        return None
    if config.get('mtls_required') and not paths[2]:
        return None
    try:
        return create_mtls_session(*paths)
    except (OSError, ValueError) as error:
        print(f'[mTLS] Cannot load identity: {error}')
        return None
