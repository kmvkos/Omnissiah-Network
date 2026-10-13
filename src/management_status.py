"""Independent observations of management traffic and VPN state; no root commands."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess

from flask import has_request_context, request


def recent(value, seconds):
    if value is None:
        return False
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return 0 <= (datetime.now(timezone.utc) - value).total_seconds() < seconds


def peer_status(node):
    heartbeat = recent(node.last_heartbeat, 90)
    return dict(service_active=heartbeat,
                mtls_enabled=bool(node.mtls_enabled and heartbeat and
                    os.getenv('OMNISSIAH_REQUIRE_MTLS', 'false').lower() == 'true'),
                vpn_enabled=bool(node.wireguard_enabled and heartbeat),
                vpn_connected=bool(node.wireguard_enabled and heartbeat and recent(node.last_handshake, 180)))


def nginx_mtls_configured(node):
    if not node.mtls_enabled or not node.nginx_enabled:
        return False
    try:
        if not all(Path(p).is_file() for p in (node.mtls_ca_cert_path, node.nginx_cert_path)):
            return False
        config = Path(os.getenv('OMNISSIAH_NGINX_CONFIG', '/etc/nginx/sites-available/omnissiah-network')).read_text()
        config = re.sub(r'#[^\n]*', '', config)
        # The managed proxy forwards verified identity; Flask enforces CN binding.
        # A dedicated legacy /api/magos/ location is not required.
        return all(re.search(pattern, config) for pattern in (
            r'ssl_client_certificate\s+' + re.escape(node.mtls_ca_cert_path) + r'\s*;',
            r'ssl_verify_client\s+(?:optional|on)\s*;',
            r'proxy_set_header\s+X-SSL-Client-Verify\s+\$ssl_client_verify\s*;',
            r'proxy_set_header\s+X-SSL-Client-Cert\s+\$ssl_client_escaped_cert\s*;',
            r'proxy_pass\s+http://127\.0\.0\.1:',
        )) and os.getenv('OMNISSIAH_REQUIRE_MTLS', 'false').lower() == 'true'
    except (OSError, TypeError):
        return False


def controller_status(node, peers):
    vpn_enabled = False
    try:
        result = subprocess.run(['ip', '-details', '-json', 'link', 'show', 'dev', node.name],
                                capture_output=True, text=True, timeout=2)
        if result.returncode == 0:
            links = json.loads(result.stdout)
            vpn_enabled = any(link.get('linkinfo', {}).get('info_kind') == 'wireguard'
                              and 'UP' in link.get('flags', []) for link in links)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass
    # This page is served by the controller application itself. Proxy observation
    # is separate from the installation configuration and authenticated heartbeats.
    proxy_active = bool(has_request_context() and request.remote_addr in ('127.0.0.1', '::1')
                        and request.headers.get('X-Forwarded-Proto') == 'https')
    configured = nginx_mtls_configured(node)
    connected = configured and any(peer_status(peer)['mtls_enabled'] for peer in peers)
    return dict(vpn_enabled=vpn_enabled,
                vpn_connected=vpn_enabled and any(recent(peer.last_handshake, 180) for peer in peers),
                service_active=True, mtls_enabled=configured and (proxy_active or connected),
                mtls_connected=connected)


def describe(status):
    if status['mtls_enabled']:
        text = 'mTLS активен; VPN активен' if status['vpn_enabled'] else 'mTLS активен; VPN не активен'
        color = 'success' if status['vpn_enabled'] else 'info'
    else:
        text = 'mTLS не подтверждён; VPN активен' if status['vpn_enabled'] else 'mTLS не подтверждён; VPN не активен'
        color = 'warning' if status['service_active'] else 'danger'
    return dict(status, status_text=text, status_color=color)
