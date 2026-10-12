"""Validate inventory-derived enrollment data using only Python's standard library."""
import ipaddress
import json
from pathlib import Path
import re
import sys


def validate_manifest(manifest):
    nodes = manifest['nodes']
    if sum(node['role'] == 'Omnissiah' for node in nodes) != 1:
        raise ValueError('Exactly one Omnissiah is required')
    names, addresses, vpn_addresses = set(), set(), set()
    reserved = {'general', 'base_users', 'firewall_rules', 'node_connections',
                'protected_objects', 'access_policy_rules', 'policy_groups', 'traffic_logs'}
    for node in nodes:
        name = node['name']
        if (not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,14}', name)
                or name.casefold() in names or name.casefold() in reserved):
            raise ValueError('Node names must be unique non-reserved interface names (1-15 characters)')
        names.add(name.casefold())
        address = ipaddress.IPv4Address(node['management_ip'])
        if address in addresses or address.is_unspecified or address.is_multicast:
            raise ValueError('Management addresses must be unique unicast IPv4 addresses')
        addresses.add(address)
        vpn = ipaddress.IPv4Interface(node['vpn_address'])
        if vpn.ip in vpn_addresses or not 16 <= vpn.network.prefixlen <= 32:
            raise ValueError('Invalid or duplicate VPN address')
        if vpn.network.prefixlen < 31 and vpn.ip in (vpn.network.network_address, vpn.network.broadcast_address):
            raise ValueError('VPN address cannot be a network or broadcast address')
        vpn_addresses.add(vpn.ip)
        if node['role'] not in ('Omnissiah', 'Magos'):
            raise ValueError('Only Omnissiah and Magos are supported by initial deployment')
        if node['role'] == 'Omnissiah' and vpn.network.prefixlen > 29:
            raise ValueError('Omnissiah requires an address with prefix /16 to /29')
    if not 1024 <= int(manifest['https_port']) <= 65535:
        raise ValueError('Invalid HTTPS port')
    controller_network = ipaddress.IPv4Interface(next(
        node['vpn_address'] for node in nodes if node['role'] == 'Omnissiah')).network
    for node in nodes:
        if ipaddress.IPv4Interface(node['vpn_address']).ip not in controller_network:
            raise ValueError('Initial VPN addresses must belong to the controller pool')
        if ipaddress.IPv4Address(node['management_ip']) in controller_network:
            raise ValueError('Management addresses must be outside the reserved VPN pool')


if __name__ == '__main__':
    validate_manifest(json.loads(Path(sys.argv[1]).read_text()))
    print('Inventory parameters validated')
