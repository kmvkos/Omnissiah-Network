# Соглашения об именовании NMC_WG

## Общие принципы

1. **snake_case** для файлов, функций, переменных
2. **PascalCase** для классов
3. **UPPER_CASE** для констант
4. **Префиксы** для группировки связанных модулей

## Роли узлов в системе

- **Omnissiah** (NMC_WG) - главный узел управления
- **Magos** (NMC_WGr) - ретранслятор/промежуточный узел
- **Cognitor** (NMC_WGc) - клиентский узел

## Структура именования

### Файлы и модули

**Префикс `nmc_` для всех модулей проекта (не `nmc_wg_`)**

```
nmc_<module>_<purpose>.py
```

Примеры:
- `nmc_vpn_config.py` - конфигурация VPN
- `nmc_node_manager.py` - управление узлами
- `nmc_policy_engine.py` - политики безопасности
- `nmc_wireguard_utils.py` - утилиты WireGuard

### Папки

```
nmc_<category>/
```

Примеры:
- `nmc_core/` - основная логика (Omnissiah)
- `nmc_services/` - сервисы
- `nmc_models/` - модели БД
- `nmc_api/` - API endpoints
- `nmc_utils/` - утилиты

### Переменные для ролей

```python
# Узлы
omnissiah_node = ...  # NMC_WG - главный узел
magos_node = ...      # NMC_WGr - ретранслятор
cognitor_node = ...   # NMC_WGc - клиент

# Конфигурации
wireguard_config = ...
vpn_config = ...

# Сервисы
node_service = ...
vpn_service = ...
```

## Текущая структура (исправлена)

### Файлы в src/

| Файл | Назначение | Роль |
|------|-----------|------|
| `nmc_vpn_config_sender.py` | Отправка конфигураций | Omnissiah → Magos/Cognitor |
| `nmc_vpn_software_update.py` | Обновление ПО | Omnissiah → Magos/Cognitor |
| `nmc_crypto_utils.py` | Криптография | Все узлы |
| `nmc_wireguard_config_utils.py` | Утилиты WG | Все узлы |
| `nmc_ssh_utils.py` | SSH утилиты | Omnissiah → Magos/Cognitor |
| `nmc_firewall_utils.py` | Firewall утилиты | Все узлы |
| `nmc_system_rules_generator.py` | Генерация правил | Omnissiah |

### Папки

| Папка | Назначение | Содержимое |
|-------|-----------|------------|
| `nmc_core/` | Основная логика Omnissiah | VPN, исключения, системные правила |
| `nmc_utils/` | Утилиты для всех узлов | Криптография, SSH, firewall, WG |
| `nmc_models/` | Модели БД | Все модели |
| `nmc_api/` | API endpoints | REST API |
| `nmc_services/` | Бизнес-логика | Сервисы |

### Импорты

```python
# Правильный стиль
from nmc_core.nmc_vpn_config_sender import send_config_via_vpn
from nmc_utils.error_handler import handle_errors
from nmc_models.models import General, BaseUser
```

## Примечания

- **NMC_WG** = название проекта, не используется в префиксах файлов
- **nmc_** = префикс для всех модулей проекта
- Роли узлов (Omnissiah/Magos/Cognitor) указываются в коде, не в именах файлов
- Имена файлов отражают функциональность, а не роль узла
