"""Interactive inventory preparation on control; never collects passwords."""
import argparse
import ipaddress
import json
from pathlib import Path
import re


def create_inventory(addresses, username):
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]*', username):
        raise ValueError('Invalid SSH username')
    addresses = [str(ipaddress.IPv4Address(value)) for value in addresses]
    if len(set(addresses)) != 3:
        raise ValueError('The three nodes require different addresses')
    return {'all': {'vars': {'ansible_user': username}, 'children': {
        'omnissiah': {'hosts': {'omni01': {'ansible_host': addresses[0], 'omnissiah_vpn_address': '10.77.0.1/24'}}},
        'magos': {'hosts': {
            'magos01': {'ansible_host': addresses[1], 'omnissiah_vpn_address': '10.77.0.2/32'},
            'magos02': {'ansible_host': addresses[2], 'omnissiah_vpn_address': '10.77.0.3/32'}}}}}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', type=Path, required=True)
    args = parser.parse_args()
    if args.inventory.exists():
        print(f'Используется существующий inventory: {args.inventory}')
        return
    addresses = []
    for name in ('omni01', 'magos01', 'magos02'):
        while True:
            value = input(f'IPv4-адрес {name}: ').strip()
            try:
                value = str(ipaddress.IPv4Address(value))
                if value in addresses:
                    raise ValueError('Адрес уже используется')
                addresses.append(value)
                break
            except ValueError:
                print('Введите корректный уникальный IPv4-адрес.')
    while True:
        username = input('SSH-пользователь на узлах [admin]: ').strip() or 'admin'
        try:
            inventory = create_inventory(addresses, username)
            break
        except ValueError:
            print('Проверьте имя SSH-пользователя.')
    # JSON is valid YAML and avoids needing PyYAML before Ansible is installed.
    args.inventory.write_text(json.dumps(inventory, indent=2) + '\n')
    args.inventory.chmod(0o600)
    print(f'Inventory сохранён: {args.inventory}')


if __name__ == '__main__':
    main()
