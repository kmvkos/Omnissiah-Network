#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
if [[ ! -f inventory.yml ]]; then
    echo 'Создайте inventory.yml из inventory.example.yml и укажите адреса ваших ВМ.' >&2
    exit 1
fi
exec ansible-playbook -i inventory.yml site.yml "$@"
