# Подготовка Linux-стенда

Это инструкция подготовки к проверке прототипа. Полный запуск и VPN-трафик
после импорта ещё не подтверждены. Используйте отдельные ВМ со снимками состояния.

## Omnissiah

Для Debian установите системные инструменты:

```bash
sudo apt-get update
sudo apt-get install python3 python3-venv python3-pip wireguard-tools iptables sudo openssh-client nginx lsof
```

Из корня репозитория создайте окружение:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
# Используется существующими функциями SSH-развёртывания:
python -m pip install paramiko
cp .env.example .env
chmod 600 .env
```

Получите новые значения ключей и внесите их в `.env`:

```bash
python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
python -c 'import secrets; print(secrets.token_hex(32))'
```

Первая команда даёт `WG_MASTER_KEY`, вторая — `SECRET_KEY`.
`SUDO_PASSWORD` требуется существующим скриптом запуска. Некоторые операции
используют `sudo -n` и требуют отдельной настройки sudoers. Пароль в `.env`
сам по себе эти права не предоставляет.

Сначала просмотрите `start.sh` и функции настройки системы в `src/app.py`.
Запуск из активированного окружения:

```bash
bash start.sh
```

Скрипт может остановить процесс, уже занимающий порт 33787, и восстанавливать
WireGuard. На этапе восстановления проекта такое поведение нужно исправить.
После успешного запуска веб-интерфейс будет доступен на `http://<IP-ВМ>:33787`.
Для новой БД код создаёт учётную запись `Adeptus` / `Mechanicus`.

`install.sh` и `omnissiah_setup.sh` сохранены из архива, но их автоматическое
применение ещё не проверено. `install.sh` использует установку пакетов `pip --user`,
поэтому для первого стенда зависимости выше устанавливаются в venv вручную.

## Magos

Подготовьте две Linux-ВМ с WireGuard, SSH-доступом и проверенными правами
на сетевые операции. Основной путь в текущем проекте — развёртывание агента
из веб-интерфейса Omnissiah. Сервер формирует bootstrap, конфигурацию WireGuard,
сертификаты и unit systemd для выбранного узла.

`agents/run.py` ожидает локальный `agents/setup/bootstrap_config.json` и
конфигурацию WireGuard в `agents/setup/`. Они намеренно отсутствуют в Git:
их содержимое зависит от узла и включает секреты. Запуск агента из одного
только клона без подготовки этих файлов не является готовым сценарием.

Отдельный пустой `agents/setup/installer.sh` из архива исключён.
Полноценный универсальный установщик агента ещё требуется подготовить.

## Проверки исходников

Без запуска сетевых операций:

```bash
python -m compileall -q src agents tests scripts mtls_utils.py
python -m pip install -r tests/requirements.txt
PYTHONPATH=src python -m pytest tests -q
```

Исходные тесты пока используют несуществующие пакеты `nmc_core` и `nmc_utils`.
До обновления импортов ожидается ошибка сбора тестов; это не проверка VPN.

## Сборка переносимого архива

```bash
bash build.sh
```

В архив попадает состояние текущего коммита Git. Незакоммиченные изменения,
локальная БД, `.env`, сертификаты и прочие неотслеживаемые файлы не включаются.
На целевой ВМ архив распаковывается в каталог `omnissiah-network/`, затем
окружение и настройки подготавливаются заново по этой инструкции.
