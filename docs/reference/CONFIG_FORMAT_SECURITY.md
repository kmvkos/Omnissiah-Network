# Формат конфигурации и безопасность

## 📦 Формат конфигурации

### Структура передачи:

```
1. Исходные данные (dict):
   {
       "action": "add",
       "rules": [
           ["-A", "FORWARD", "-s", "192.168.1.0/24", ...]
       ]
   }

2. JSON сериализация:
   '{"action":"add","rules":[...]}'  (строка UTF-8)

3. Шифрование Fernet:
   <зашифрованные bytes>

4. Base64 кодирование:
   'gAAAAABh...'  (base64 строка)

5. HTTP JSON payload:
   {
       "config_type": "iptables",
       "encrypted_config": "gAAAAABh...",
       "node_name": "magos1"
   }

6. Передача через VPN туннель (WireGuard)
```

### Формат данных:

**iptables конфигурация:**
```json
{
    "action": "add" | "remove",
    "rules": [
        ["-A", "FORWARD", "-s", "192.168.1.0/24", "-d", "10.0.0.0/24", "-p", "tcp", "--dport", "80", "-j", "ACCEPT"]
    ]
}
```

**routes конфигурация:**
```json
{
    "action": "add" | "remove",
    "routes": [
        {
            "network": "192.168.100.0/24",
            "gateway": "172.18.16.1",
            "interface": "wg0"
        }
    ]
}
```

**software update:**
```json
{
    "archive_type": "update" | "full",
    "archive_data": "<base64 зашифрованного tar.gz архива>"
}
```

## 🔐 Механизм шифрования

### На Omnissiah (отправка):

1. Получаем preshared_key узла из БД
2. Генерируем Fernet ключ через PBKDF2:
   ```
   password = preshared_key.encode('utf-8')
   salt = 'nmc-salt-v1-2025'  # Фиксированная соль
   iterations = 100000
   key = PBKDF2(password, salt, iterations) → Fernet key
   ```
3. Шифруем JSON через Fernet
4. Кодируем в base64

### На Magos/Cognitor (получение):

1. Загружаем preshared_key из локальной конфигурации (`bootstrap_config.json`)
2. Генерируем тот же Fernet ключ (те же параметры PBKDF2)
3. Декодируем base64
4. Расшифровываем через Fernet
5. Парсим JSON

### ⚠️ КРИТИЧНО: Preshared key должен быть одинаковым!

**Проблема**: Если preshared_key на Omnissiah (БД) не совпадает с preshared_key на Magos (локальный конфиг) - расшифровка не сработает!

**Решение**: 
- Использовать один и тот же preshared_key из WireGuard конфигурации
- Или использовать public_key как fallback (менее безопасно)

## 🔐 Принцип расшифровки на Magos/Cognitor

### На Magos/Cognitor агенте:

1. **Получение preshared_key**:
   ```python
   from app.config import load_config
   config = load_config()
   preshared_key = config.get('preshared_key')  # Из bootstrap_config.json
   ```

2. **Генерация Fernet ключа** (идентично Omnissiah):
   ```python
   password = preshared_key.encode('utf-8')
   salt = b'nmc-salt-v1-2025'  # ТА ЖЕ соль
   iterations = 100000  # ТО ЖЕ количество итераций
   key = PBKDF2(password, salt, iterations) → Fernet key
   ```

3. **Расшифровка**:
   ```python
   encrypted_data = base64.b64decode(encrypted_config)
   config_data = encryptor.decrypt_json(encrypted_data)
   ```

### ⚠️ КРИТИЧНО: Preshared key должен совпадать!

**Источники ключа:**
- **Omnissiah**: Из БД (`node.preshared_key`)
- **Magos/Cognitor**: Из `bootstrap_config.json` (`preshared_key`)

**Проблема**: Если ключи не совпадают → расшифровка не сработает → ошибка "Failed to decrypt configuration. Invalid key?"

**Решение**: 
- Использовать один и тот же preshared_key из WireGuard конфигурации
- Fallback на public_key если preshared_key нет (менее безопасно)

## 🚨 Проблемы безопасности (исправлены)

### 1. ✅ Добавлена проверка VPN connectivity

**Решение**: Функция `check_vpn_connectivity()` проверяет доступность VPN IP перед отправкой:

```python
# Проверка ping перед отправкой
is_reachable, error_msg = check_vpn_connectivity(vpn_ip, timeout=5)
if not is_reachable:
    return False, "VPN туннель не работает. Проверьте что WireGuard активен."
```

**Методы проверки**:
1. `ping -c 1` (если доступен)
2. `socket.connect_ex()` на порт 5001 (fallback)

**Результат**: Если VPN недоступен, отправка не происходит, возвращается ошибка.

### 2. ⚠️ Fallback механизм

**Текущее поведение**: 
- Если VPN недоступен → ошибка с предложением включить VPN
- Для обновлений ПО дополнительно проверяется активность VPN через heartbeat/handshake

**Предложение**: В будущем можно добавить опцию принудительной отправки через SSH (с предупреждением о безопасности).

### 3. ⚠️ Проверка совпадения ключей

**Проблема**: Нет автоматической проверки что ключи совпадают.

**Текущее решение**: 
- Используем preshared_key из WireGuard конфигурации (должен быть одинаковым)
- Fallback на public_key если preshared_key нет

**Рекомендация**: 
- При создании узла сохранять preshared_key в bootstrap_config.json
- При heartbeat или при первом подключении валидировать что ключи совпадают

## 📊 Схема передачи конфигурации

```
Omnissiah                          Magos/Cognitor
─────────────────────────────────────────────────────
1. Получает preshared_key         1. Загружает preshared_key
   из БД                              из bootstrap_config.json

2. PBKDF2(password, salt, 100000)  2. PBKDF2(password, salt, 100000)
   → Fernet key                      → Fernet key
   (ТОТ ЖЕ процесс!)                 (ТОТ ЖЕ процесс!)

3. config_data (dict) → JSON      3. JSON → config_data (dict)
4. JSON → bytes (UTF-8)           4. bytes → JSON (UTF-8)
5. Fernet.encrypt(bytes)          5. Fernet.decrypt(bytes)
6. Base64.encode()                6. Base64.decode()

7. HTTP POST через VPN             7. Принимает через VPN
   (WireGuard шифрование)            (WireGuard расшифровка)

8. Проверка VPN IP                8. Проверка VPN IP источника
9. Проверка node_name              9. Проверка node_name

10. Расшифровка и применение       10. Применение конфигурации
```

