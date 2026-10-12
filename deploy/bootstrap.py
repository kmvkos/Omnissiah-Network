"""Idempotent local enrollment invoked by Ansible on Omnissiah, without SSH passwords."""
import argparse
import json
import os
from pathlib import Path
import secrets
import sys

from cryptography.fernet import Fernet
from dotenv import dotenv_values, load_dotenv
from werkzeug.security import generate_password_hash

from pki import write_if_changed


from validate_manifest import validate_manifest


def ensure_environment(project, state):
    path = project / '.env'
    previous = dict(dotenv_values(path)) if path.exists() else {}
    values = dict(previous)
    values.setdefault('WG_MASTER_KEY', Fernet.generate_key().decode())
    values.setdefault('SECRET_KEY', secrets.token_hex(32))
    values.update(OMNISSIAH_DATABASE_URI=f'sqlite:///{state / "data" / "vpngate.db"}',
                  OMNISSIAH_REQUIRE_MTLS='true', DEBUG='false')
    if not values.get('WG_MASTER_KEY') or not values.get('SECRET_KEY'):
        raise ValueError('Existing environment contains empty secrets; explicit repair required')
    Fernet(values['WG_MASTER_KEY'].encode())
    changed = write_if_changed(path, ''.join(
        f'{key}={json.dumps(value)}\n' for key, value in sorted(values.items())).encode(), 0o640)
    load_dotenv(path, override=True)
    return changed


def enroll(project, state, manifest):
    validate_manifest(manifest)
    state.mkdir(parents=True, exist_ok=True)
    (state / 'data').mkdir(exist_ok=True)
    changed = ensure_environment(project, state)
    sys.path.insert(0, str(project / 'src'))
    from app import app, create_dynamic_models, dynamic_info_models, dynamic_user_models, configurations
    from nmc_models import db, General, BaseUser
    with app.app_context():
        db.create_all()
        username = manifest.get('admin_username', 'admin')
        admin = BaseUser.query.filter_by(email=username).first()
        if admin is None:
            if BaseUser.query.count():
                raise ValueError('Existing database has other users; refusing to create a second initial administrator')
            password = os.getenv('OMNISSIAH_INITIAL_ADMIN_PASSWORD') or secrets.token_urlsafe(24)
            if len(password) < 12:
                raise ValueError('Initial administrator password must contain at least 12 characters')
            db.session.add(BaseUser(email=username, password_hash=generate_password_hash(password), role='admin'))
            write_if_changed(state / 'admin-password', (password + '\n').encode())
            changed = True
        ordered = sorted(manifest['nodes'], key=lambda n: n['role'] != 'Omnissiah')
        controller = None
        for entry in ordered:
            node = General.query.filter_by(name=entry['name']).first()
            if node is None:
                node = General(name=entry['name'], role=entry['role'], ip_pool=entry['vpn_address'],
                               listen_port=51820, private_key='', public_key='',
                               endpoint=entry['management_ip'], status='stopped')
                db.session.add(node)
                db.session.flush()
                if controller and entry['role'] == 'Magos':
                    node.parent_id = controller.id
                changed = True
            elif node.role != entry['role']:
                raise ValueError(f'Role change for {node.name} requires explicit migration')
            if entry['role'] == 'Omnissiah':
                controller = node
            # Preserve application-owned VPN keys, addresses, connections and policies.
            pki = str(state / 'pki') if entry['role'] == 'Omnissiah' else entry['pki_directory']
            fields = dict(ssh_ip=entry['management_ip'], nginx_enabled=True,
                nginx_domain=entry['management_ip'], nginx_https_port=manifest['https_port'],
                nginx_cert_path=f'{pki}/identity.crt', nginx_key_path=f'{pki}/identity.key',
                mtls_enabled=True, mtls_ca_cert_path=f'{pki}/ca.crt',
                mtls_server_cert_path=f'{pki}/identity.crt', mtls_server_key_path=f'{pki}/identity.key')
            for key, value in fields.items():
                if getattr(node, key) != value:
                    setattr(node, key, value)
                    changed = True
        db.session.commit()
        # Legacy views expect dynamic per-interface tables even before a tunnel exists.
        for node in General.query.all():
            user_model, info_model = create_dynamic_models(node.name)
            dynamic_user_models[node.name], dynamic_info_models[node.name] = user_model, info_model
            if node.name not in configurations:
                configurations.append(node.name)
        db.create_all()
    return changed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', type=Path, required=True)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    args = parser.parse_args()
    changed = enroll(args.project.resolve(), args.state.resolve(), json.loads(args.manifest.read_text()))
    print(json.dumps({'changed': changed}))


if __name__ == '__main__':
    main()
