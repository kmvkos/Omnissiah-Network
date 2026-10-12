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
    if not 2 <= len(addresses) <= 254:
        raise ValueError('Use one controller and 1–253 Magos for the default /24 pool')
    if len(set(addresses)) != len(addresses):
        raise ValueError('All nodes require different addresses')
    return {'all': {'vars': {'ansible_user': username}, 'children': {
        'omnissiah': {'hosts': {'omni01': {'ansible_host': addresses[0], 'omnissiah_vpn_address': '10.77.0.1/24'}}},
        'magos': {'hosts': {
            f'magos{index:02d}': {'ansible_host': address,
                                 'omnissiah_vpn_address': f'10.77.0.{index + 1}/32'}
            for index, address in enumerate(addresses[1:], start=1)}}}}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', type=Path, required=True)
    args = parser.parse_args()
    if args.inventory.exists():
        print(f'Используется существующий inventory: {args.inventory}')
        return
    while True:
        try:
            count = int(input('Количество узлов Magos [2]: ').strip() or '2')
            if not 1 <= count <= 253:
                raise ValueError
            break
        except ValueError:
            print('Введите число от 1 до 253 (начальный VPN-пул 10.77.0.0/24).')
    addresses = []
    for name in ['omni01'] + [f'magos{index:02d}' for index in range(1, count + 1)]:
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
