import importlib.util
import json
import os
from pathlib import Path
import shutil
import sqlite3
import ssl
import subprocess
import sys
import threading
import types
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import quote

import pytest
import requests
from flask import Flask
from jinja2 import Environment, FileSystemLoader

from pki import ensure_ca, ensure_csr, sign_csr
from bootstrap_agent import configure
from deployment_auth import proxy_identity

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def identity_tree(tmp_path):
    ca = tmp_path / 'ca'
    ensure_ca(ca)
    for name in ('omni01', 'magos01', 'magos02'):
        ensure_csr(tmp_path / name, name, '127.0.0.1')
        sign_csr(ca, tmp_path / name / 'identity.csr', tmp_path / name / 'identity.crt')
    return tmp_path


def test_pki_preserves_keys_and_certificates(identity_tree):
    before = {str(p): p.read_bytes() for p in identity_tree.rglob('*') if p.is_file()}
    assert ensure_ca(identity_tree / 'ca') is False
    for name in ('omni01', 'magos01', 'magos02'):
        assert ensure_csr(identity_tree / name, name, '127.0.0.1') is False
        assert sign_csr(identity_tree / 'ca', identity_tree / name / 'identity.csr',
                        identity_tree / name / 'identity.crt') is False
    assert before == {str(p): p.read_bytes() for p in identity_tree.rglob('*') if p.is_file()}
    assert (identity_tree / 'ca' / 'ca.key').stat().st_mode & 0o777 == 0o600


def test_pki_refuses_to_replace_incomplete_ca(identity_tree):
    key = (identity_tree / 'ca' / 'ca.key').read_bytes()
    (identity_tree / 'ca' / 'ca.crt').unlink()
    with pytest.raises(ValueError, match='Incomplete CA'):
        ensure_ca(identity_tree / 'ca')
    assert (identity_tree / 'ca' / 'ca.key').read_bytes() == key


def test_changed_address_renews_certificate_without_rekeying(identity_tree):
    directory = identity_tree / 'magos01'
    private_key = (directory / 'identity.key').read_bytes()
    certificate = (directory / 'identity.crt').read_bytes()
    assert ensure_csr(directory, 'magos01', '192.168.50.11') is True
    assert sign_csr(identity_tree / 'ca', directory / 'identity.csr', directory / 'identity.crt') is True
    assert (directory / 'identity.key').read_bytes() == private_key
    assert (directory / 'identity.crt').read_bytes() != certificate


def test_agent_bootstrap_preserves_runtime_state(tmp_path):
    path = tmp_path / 'bootstrap.json'
    desired = dict(name='magos01', management_ip='192.168.50.11',
                   server_url='https://192.168.50.10:8443', manage_wireguard=False, ip_pool='10.77.0.2/32')
    assert configure(path, desired)
    config = json.loads(path.read_text())
    config.update(manage_wireguard=True, private_key='local-key', ip_pool='10.88.0.2/32')
    path.write_text(json.dumps(config))
    configure(path, dict(desired, management_ip='192.168.50.21'))
    actual = json.loads(path.read_text())
    assert actual['manage_wireguard'] is True
    assert actual['private_key'] == 'local-key'
    assert actual['ip_pool'] == '10.88.0.2/32'
    assert actual['management_ip'] == '192.168.50.21'
    assert configure(path, dict(desired, management_ip='192.168.50.21')) is False


def test_proxy_identity_requires_loopback_and_verified_header(identity_tree):
    app = Flask(__name__)
    headers = {'X-SSL-Client-Verify': 'SUCCESS', 'X-SSL-Client-Cert': quote(
        (identity_tree / 'magos01' / 'identity.crt').read_text(), safe='')}
    with app.test_request_context(headers=headers, environ_base={'REMOTE_ADDR': '127.0.0.1'}):
        assert proxy_identity() == 'magos01'
    with app.test_request_context(headers=headers, environ_base={'REMOTE_ADDR': '192.168.50.11'}):
        assert proxy_identity() is None
    with app.test_request_context(headers={'X-SSL-Client-Cert': headers['X-SSL-Client-Cert']},
                                  environ_base={'REMOTE_ADDR': '127.0.0.1'}):
        assert proxy_identity() is None


def load_agent_module(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'agents/app' / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_real_mtls_chain_and_hostname_validation(identity_tree):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200); self.end_headers(); self.wfile.write(b'ok')
        def log_message(self, *args):
            pass
    server = HTTPServer(('127.0.0.1', 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    directory = identity_tree / 'omni01'
    context.load_cert_chain(directory / 'identity.crt', directory / 'identity.key')
    context.load_verify_locations(identity_tree / 'ca' / 'ca.crt')
    context.verify_mode = ssl.CERT_REQUIRED
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    module = load_agent_module('agent_mtls_test', 'mtls_client.py')
    magos = identity_tree / 'magos01'
    session = module.create_mtls_session(str(magos / 'identity.crt'), str(magos / 'identity.key'),
                                         str(identity_tree / 'ca' / 'ca.crt'))
    try:
        assert session.get(f'https://127.0.0.1:{server.server_port}', timeout=3).status_code == 200
        with pytest.raises(requests.exceptions.SSLError):
            session.get(f'https://localhost:{server.server_port}', timeout=3)
        with pytest.raises(requests.exceptions.SSLError):
            requests.get(f'https://127.0.0.1:{server.server_port}',
                         verify=str(identity_tree / 'ca' / 'ca.crt'), timeout=3)
        ensure_ca(identity_tree / 'other-ca')
        session.verify = str(identity_tree / 'other-ca' / 'ca.crt')
        # Use a new Session to avoid reusing an already-authenticated connection.
        wrong = module.create_mtls_session(str(magos / 'identity.crt'), str(magos / 'identity.key'), session.verify)
        with pytest.raises(requests.exceptions.SSLError):
            wrong.get(f'https://127.0.0.1:{server.server_port}', timeout=3)
        wrong.close()
    finally:
        session.close(); server.shutdown(); server.server_close(); thread.join(timeout=3)


def test_required_mtls_never_falls_back_to_plain_request(monkeypatch):
    config = dict(name='magos01', server_url='https://192.168.50.10:8443',
                  management_ip='192.168.50.11', manage_wireguard=False,
                  mtls_enabled=True, mtls_required=True, mtls_cert_file='missing', mtls_key_file='missing')
    config_module = types.ModuleType('app.config'); config_module.load_config = lambda: config
    tls_module = types.ModuleType('app.mtls_client'); tls_module.get_mtls_session_from_config = lambda _: None
    monkeypatch.setitem(sys.modules, 'app.config', config_module)
    monkeypatch.setitem(sys.modules, 'app.mtls_client', tls_module)
    module = load_agent_module('heartbeat_test', 'heartbeat.py')
    monkeypatch.setattr(module, 'get_interfaces_with_ips', lambda: [])
    def forbidden(*args, **kwargs):
        raise AssertionError('TLS failure must not cause an unauthenticated retry')
    monkeypatch.setattr(module.requests, 'post', forbidden)
    assert module.send_heartbeat(config) is False
    class BrokenSession:
        def post(self, *args, **kwargs):
            raise requests.exceptions.SSLError('wrong CA')
    monkeypatch.setattr(module, 'get_mtls_session_from_config', lambda _: BrokenSession())
    assert module.send_heartbeat(config) is False


@pytest.fixture
def enrolled_project(tmp_path):
    project = tmp_path / 'project'; project.mkdir()
    for name in ('src', 'templates', 'deploy'):
        shutil.copytree(ROOT / name, project / name, ignore=shutil.ignore_patterns('__pycache__'))
    shutil.copy(ROOT / 'mtls_utils.py', project)
    state = tmp_path / 'state'
    manifest = dict(https_port=8443, admin_username='admin', nodes=[
        dict(name='omni01', role='Omnissiah', management_ip='192.168.50.10', vpn_address='10.77.0.1/24', pki_directory=str(state / 'pki')),
        dict(name='magos01', role='Magos', management_ip='192.168.50.11', vpn_address='10.77.0.2/32', pki_directory=str(state / 'pki')),
        dict(name='magos02', role='Magos', management_ip='192.168.50.12', vpn_address='10.77.0.3/32', pki_directory=str(state / 'pki'))])
    path = tmp_path / 'manifest.json'; path.write_text(json.dumps(manifest))
    command = [sys.executable, str(project / 'deploy/bootstrap.py'), '--project', str(project), '--state', str(state), '--manifest', str(path)]
    def enroll():
        result = subprocess.run(command, cwd=project, capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout.splitlines()[-1])
    assert enroll()['changed'] is True
    return project, state, path, enroll


def test_enrollment_repeat_preserves_secrets_password_and_vpn_state(enrolled_project):
    project, state, _, enroll = enrolled_project
    environment = (project / '.env').read_bytes()
    password = (state / 'admin-password').read_bytes()
    connection = sqlite3.connect(state / 'data' / 'vpngate.db')
    connection.execute("UPDATE general SET private_key='saved-encrypted-key', ip_pool='10.88.0.2/32' WHERE name='magos01'")
    connection.commit()
    assert enroll()['changed'] is False
    assert (project / '.env').read_bytes() == environment
    assert (state / 'admin-password').read_bytes() == password
    assert connection.execute('SELECT COUNT(*) FROM general').fetchone()[0] == 3
    assert connection.execute("SELECT private_key,ip_pool FROM general WHERE name='magos01'").fetchone() == ('saved-encrypted-key', '10.88.0.2/32')
    assert connection.execute('SELECT COUNT(*) FROM base_users').fetchone()[0] == 1
    connection.close()


def test_controller_login_dashboard_and_node_bound_heartbeat(enrolled_project, identity_tree):
    project, state, _, _ = enrolled_project
    script = '''
import os,json
from pathlib import Path
from urllib.parse import quote
from dotenv import load_dotenv
load_dotenv('.env',override=True)
from wsgi import app
from nmc_models import General
client=app.test_client()
assert client.get('/health').status_code==200
assert client.get('/login').status_code==200
assert client.get('/api/nodes').status_code==401
assert client.post('/api/magos/heartbeat',json={'name':'magos01'}).status_code==401
headers={'X-SSL-Client-Verify':'SUCCESS','X-SSL-Client-Cert':quote(Path(os.environ['TEST_CERT']).read_text(),safe='')}
assert client.post('/api/magos/heartbeat',json={'name':'magos02'},headers=headers).status_code==403
assert client.post('/api/magos/heartbeat',json={'name':'magos01','local_ip':'192.168.50.11','wireguard_enabled':False},headers=headers).status_code==200
with app.app_context():
    assert General.query.filter_by(name='magos01').first().last_heartbeat is not None
password=Path(os.environ['TEST_STATE']+'/admin-password').read_text().strip()
response=client.post('/login',data={'username':'admin','password':password},follow_redirects=True)
assert response.status_code==200, response.data[:200]
assert b'magos01' in response.data
assert client.get('/api/nodes').status_code==200
print('controller checks passed')
'''
    result = subprocess.run([sys.executable, '-c', script], cwd=project, capture_output=True, text=True,
        env=dict(os.environ, PYTHONPATH=str(project / 'src'), TEST_CERT=str(identity_tree / 'magos01' / 'identity.crt'),
                 TEST_STATE=str(state)), timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr


def test_nginx_and_manifest_templates_use_separate_management_addresses():
    environment = Environment(loader=FileSystemLoader(ROOT / 'ansible/roles/controller/templates'))
    environment.filters['to_json'] = json.dumps
    values = dict(groups={'omnissiah':['omni01'],'magos':['magos01']},
        hostvars={'omni01':dict(ansible_host='192.168.50.10',omnissiah_vpn_address='10.77.0.1/24'),
                  'magos01':dict(ansible_host='192.168.50.11',omnissiah_vpn_address='10.77.0.2/32')},
        omnissiah_https_port=8443, omnissiah_admin_username='admin', omnissiah_state_dir='/var/lib/omnissiah-network')
    manifest = json.loads(environment.get_template('manifest.json.j2').render(**values))
    assert manifest['nodes'][1]['pki_directory']=='/var/lib/omnissiah-network/pki'
    assert manifest['nodes'][1]['management_ip']!='10.77.0.2'
    environment.loader = FileSystemLoader(ROOT / 'ansible/roles/services/templates')
    values.update(inventory_hostname='magos01',ansible_host='192.168.50.11')
    proxy = environment.get_template('nginx.conf.j2').render(**values)
    assert 'ssl_verify_client on;' in proxy
    assert 'proxy_pass http://127.0.0.1:5001;' in proxy
    assert 'proxy_set_header X-SSL-Client-Verify $ssl_client_verify;' in proxy
