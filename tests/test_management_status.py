from datetime import datetime, timedelta, timezone
import json
from types import SimpleNamespace

from flask import Flask
import pytest

from management_status import controller_status, describe, nginx_mtls_configured, peer_status


def node(**values):
    return SimpleNamespace(name='omni01', mtls_enabled=True, nginx_enabled=True,
        mtls_ca_cert_path=None, nginx_cert_path=None, last_heartbeat=None,
        last_handshake=None, wireguard_enabled=False, **values)


def test_stale_or_future_heartbeat_does_not_claim_online(monkeypatch):
    monkeypatch.setenv('OMNISSIAH_REQUIRE_MTLS', 'true')
    for age in (-20, 100):
        peer = node()
        peer.last_heartbeat = datetime.now(timezone.utc) - timedelta(seconds=age)
        peer.wireguard_enabled = True
        peer.last_handshake = datetime.now(timezone.utc)
        assert not any(peer_status(peer).values())


def test_authenticated_agent_can_be_online_without_vpn(monkeypatch):
    monkeypatch.setenv('OMNISSIAH_REQUIRE_MTLS', 'true')
    peer = node()
    peer.last_heartbeat = datetime.now(timezone.utc).replace(tzinfo=None)
    observed = peer_status(peer)
    assert observed['service_active'] and observed['mtls_enabled']
    assert not observed['vpn_enabled'] and not observed['vpn_connected']
    monkeypatch.setenv('OMNISSIAH_REQUIRE_MTLS', 'false')
    assert not peer_status(peer)['mtls_enabled']


@pytest.mark.parametrize('verify,expected', [('optional', True), ('on', True), ('off', False)])
def test_managed_nginx_does_not_require_legacy_location(tmp_path, monkeypatch, verify, expected):
    monkeypatch.setenv('OMNISSIAH_REQUIRE_MTLS', 'true')
    ca, cert = tmp_path / 'ca.crt', tmp_path / 'identity.crt'
    ca.write_text('public-ca'); cert.write_text('public-leaf')
    path = tmp_path / 'nginx.conf'
    path.write_text(f'''ssl_client_certificate {ca};
        ssl_verify_client {verify};
        location / {{ proxy_pass http://127.0.0.1:33787;
            proxy_set_header X-SSL-Client-Verify $ssl_client_verify;
            proxy_set_header X-SSL-Client-Cert $ssl_client_escaped_cert; }}''')
    monkeypatch.setenv('OMNISSIAH_NGINX_CONFIG', str(path))
    controller = node()
    controller.mtls_ca_cert_path, controller.nginx_cert_path = str(ca), str(cert)
    assert nginx_mtls_configured(controller) == expected


def test_configured_mtls_needs_proxy_or_authenticated_heartbeat(monkeypatch):
    monkeypatch.setattr('management_status.nginx_mtls_configured', lambda _: True)
    monkeypatch.setattr('management_status.subprocess.run', lambda *a, **k: SimpleNamespace(
        returncode=0, stdout=json.dumps([dict(flags=['UP'], linkinfo=dict(info_kind='ether'))])))
    app = Flask(__name__)
    with app.test_request_context('/', headers={'X-Forwarded-Proto': 'https'},
                                  environ_base={'REMOTE_ADDR': '192.168.50.30'}):
        observed = controller_status(node(), [])
        assert observed['service_active'] and not observed['mtls_enabled']
        assert not observed['vpn_enabled']
    with app.test_request_context('/', headers={'X-Forwarded-Proto': 'https'},
                                  environ_base={'REMOTE_ADDR': '127.0.0.1'}):
        observed = controller_status(node(), [])
        assert observed['mtls_enabled'] and not observed['mtls_connected']
        assert describe(observed)['status_text'] == 'mTLS активен; VPN не активен'
