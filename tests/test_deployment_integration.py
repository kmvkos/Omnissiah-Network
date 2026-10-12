"""Real nginx/Gunicorn management-path test, without privileged network changes."""
import json
import os
import pwd
import grp
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import sys
import time

from jinja2 import Environment, FileSystemLoader
import pytest
import requests

from pki import ensure_ca, ensure_csr, sign_csr

ROOT = Path(__file__).resolve().parents[1]
NGINX = os.getenv('OMNISSIAH_TEST_NGINX') or shutil.which('nginx')


def unused_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


@pytest.mark.skipif(not NGINX, reason='nginx is required for the real proxy smoke test')
def test_nginx_gunicorn_and_agent_heartbeat(tmp_path):
    project = tmp_path / 'project'; project.mkdir()
    for name in ('src', 'templates', 'deploy', 'agents'):
        shutil.copytree(ROOT / name, project / name, ignore=shutil.ignore_patterns('__pycache__', 'database'))
    shutil.copy(ROOT / 'mtls_utils.py', project)
    state = tmp_path / 'controller'
    agent_state = tmp_path / 'agent'
    ca = state / 'pki' / 'ca'; ensure_ca(ca)
    for name, directory, address in [('omni01',state,'127.0.0.1'),('magos01',agent_state,'127.0.0.2')]:
        ensure_csr(directory / 'pki', name, address)
        sign_csr(ca, directory / 'pki' / 'identity.csr', directory / 'pki' / 'identity.crt')
        shutil.copy(ca / 'ca.crt', directory / 'pki' / 'ca.crt')
    https_port, controller_port, agent_port = unused_port(), unused_port(), unused_port()
    manifest = dict(https_port=https_port, admin_username='admin', nodes=[
        dict(name='omni01',role='Omnissiah',management_ip='127.0.0.1',vpn_address='10.77.0.1/24',pki_directory=str(state / 'pki')),
        dict(name='magos01',role='Magos',management_ip='127.0.0.2',vpn_address='10.77.0.2/32',pki_directory=str(agent_state / 'pki'))])
    manifest_path = tmp_path / 'manifest.json'; manifest_path.write_text(json.dumps(manifest))
    result = subprocess.run([sys.executable,str(project / 'deploy/bootstrap.py'),'--project',str(project),
        '--state',str(state),'--manifest',str(manifest_path)],capture_output=True,text=True,timeout=30)
    assert result.returncode == 0, result.stderr
    agent_config = dict(name='magos01',role='Magos',management_ip='127.0.0.2',
        controller_name='omni01',server_url=f'https://127.0.0.1:{https_port}',manage_wireguard=False,
        mtls_enabled=True,mtls_required=True,mtls_cert_file=str(agent_state / 'pki' / 'identity.crt'),
        mtls_key_file=str(agent_state / 'pki' / 'identity.key'),mtls_ca_cert_file=str(ca / 'ca.crt'))
    config_path = agent_state / 'bootstrap_config.json'; config_path.write_text(json.dumps(agent_config))
    template = Environment(loader=FileSystemLoader(ROOT / 'ansible/roles/services/templates')).get_template('nginx.conf.j2')
    groups = {'omnissiah':['omni01'],'magos':['magos01']}
    controller_proxy = template.render(inventory_hostname='omni01',groups=groups,ansible_host='127.0.0.1',
        omnissiah_state_dir=str(state),omnissiah_https_port=https_port).replace('127.0.0.1:33787',f'127.0.0.1:{controller_port}')
    agent_proxy = template.render(inventory_hostname='magos01',groups=groups,ansible_host='127.0.0.2',
        omnissiah_state_dir=str(agent_state),omnissiah_https_port=https_port).replace('127.0.0.1:5001',f'127.0.0.1:{agent_port}')
    nginx_config = tmp_path / 'nginx.conf'
    nginx_config.write_text(f'user {pwd.getpwuid(os.getuid()).pw_name} {grp.getgrgid(os.getgid()).gr_name};\n'
        f'pid {tmp_path}/nginx.pid;\nerror_log {tmp_path}/nginx-error.log;\n'
        f'events {{ worker_connections 64; }}\nhttp {{ access_log {tmp_path}/nginx-access.log;\n'
        + ''.join(f'{kind}_temp_path {tmp_path}/{kind};\n' for kind in ('client_body','proxy','fastcgi','uwsgi','scgi'))
        + controller_proxy + agent_proxy + '\n}\n')
    syntax = subprocess.run([NGINX,'-t','-p',str(tmp_path),'-c',str(nginx_config)],capture_output=True,text=True)
    assert syntax.returncode == 0, syntax.stderr
    children = []
    logs = []
    session = requests.Session(); session.trust_env=False; session.verify=str(ca / 'ca.crt')
    try:
        for name, module, port, working_directory, extra in [
            ('controller','wsgi:app',controller_port,project,
             dict(PYTHONPATH=str(project / 'src'))),
            ('agent','app.agent:app',agent_port,project / 'agents',
             dict(PYTHONPATH=f'{project}/agents:{project}/src',
                  OMNISSIAH_AGENT_CONFIG=str(config_path),OMNISSIAH_AGENT_STATE_DIR=str(agent_state / 'database'),
                  OMNISSIAH_AGENT_BACKGROUND='true'))]:
            output = (tmp_path / f'{name}.log').open('w'); logs.append(output)
            children.append(subprocess.Popen([sys.executable,'-m','gunicorn','--workers','1','--threads','4',
                '--bind',f'127.0.0.1:{port}',module],cwd=working_directory,env=dict(os.environ,**extra),
                stdout=output,stderr=subprocess.STDOUT))
        output = (tmp_path / 'nginx.log').open('w'); logs.append(output)
        children.append(subprocess.Popen([NGINX,'-p',str(tmp_path),'-c',str(nginx_config),
            '-g','daemon off; master_process off;'],stdout=output,stderr=subprocess.STDOUT))
        base = f'https://127.0.0.1:{https_port}'
        deadline = time.monotonic()+15
        while True:
            try:
                if session.get(base+'/health',timeout=1).status_code == 200:
                    break
            except requests.RequestException:
                pass
            if time.monotonic()>deadline:
                pytest.fail('Services failed to start: '+''.join(p.read_text() for p in tmp_path.glob('*.log')))
            time.sleep(0.1)
        # nginx must strip a caller's spoofed verification headers.
        forged = {'X-SSL-Client-Verify':'SUCCESS','X-SSL-Client-Cert':(agent_state / 'pki' / 'identity.crt').read_text().replace('\n','%0A')}
        assert session.post(base+'/api/magos/heartbeat',json={'name':'magos01'},headers=forged).status_code == 401
        session.cert=(str(agent_state / 'pki' / 'identity.crt'),str(agent_state / 'pki' / 'identity.key'))
        assert session.post(base+'/api/magos/heartbeat',json={'name':'omni01'}).status_code == 403
        assert session.post(base+'/api/magos/heartbeat',json={'name':'magos01','local_ip':'127.0.0.2'}).status_code == 200
        connection=sqlite3.connect(state / 'data' / 'vpngate.db')
        assert connection.execute("SELECT last_heartbeat FROM general WHERE name='magos01'").fetchone()[0]
        connection.close()
        controller_client=requests.Session(); controller_client.trust_env=False
        controller_client.verify=str(ca / 'ca.crt')
        controller_client.cert=(str(state / 'pki' / 'identity.crt'),str(state / 'pki' / 'identity.key'))
        assert controller_client.get(f'https://127.0.0.2:{https_port}/health',timeout=3).json()['status']=='alive'
        controller_client.close()
        # Exercise the actual agent heartbeat implementation through nginx.
        probe = '''import sys,json;from app.heartbeat import send_heartbeat;from app.config import load_config;sys.exit(0 if send_heartbeat(load_config()) else 1)'''
        result=subprocess.run([sys.executable,'-c',probe],cwd=project / 'agents',capture_output=True,text=True,
            env=dict(os.environ,PYTHONPATH=f'{project}/agents:{project}/src',OMNISSIAH_AGENT_CONFIG=str(config_path)),timeout=15)
        assert result.returncode==0,result.stdout+result.stderr
        password=(state / 'admin-password').read_text().strip()
        assert session.post(base+'/login',data={'username':'admin','password':password},timeout=3).status_code==200
    finally:
        session.close()
        for child in reversed(children):
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill(); child.wait(timeout=3)
        for output in logs:
            output.close()
