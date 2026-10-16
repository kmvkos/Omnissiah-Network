import os
import secrets
import subprocess
import traceback
import requests
import atexit
import qrcode
import re
import tempfile
import pwd  # Импорт модуля для работы с пользовательской информацией
import grp
import textwrap
import json
import zipfile
import base64
from io import BytesIO
from datetime import datetime, timedelta, timezone
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash, current_app, abort, \
    jsonify
from flask.views import MethodView
from typing import List, Dict, Tuple
from wtforms import BooleanField, SelectMultipleField
from functools import wraps
from contextlib import contextmanager
from sqlalchemy import create_engine, select, event
from sqlalchemy.orm import validates
from ipaddress import ip_network, IPv4Address, IPv4Network
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet, InvalidToken
import sys
# Добавляем корень проекта в путь для импорта mtls_utils
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))
from mtls_utils import generate_ca_certificate, generate_server_certificate, generate_client_certificate
try:
    from omnissiah_utils.nmc_firewall_utils import setup_magos_firewall, check_network_accessible_via_interface
except ImportError:
    # Fallback для случая когда модуль еще не создан
    def setup_magos_firewall(*args, **kwargs):
        return False, "Firewall utils not available"
    def check_network_accessible_via_interface(*args, **kwargs):
        return False, "Firewall utils not available"
# Импортируем API утилиты
from omnissiah_utils.nmc_api_utils import get_api_url, get_next_available_ip, get_next_available_ip_list
from apscheduler.schedulers.background import BackgroundScheduler
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from sqlalchemy.exc import IntegrityError, OperationalError
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, \
    login_required  # не используется в версии с API
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, SelectField, SubmitField
from wtforms.validators import DataRequired, NumberRange, ValidationError, Regexp, Optional

# Импорт моделей из nmc_models
from nmc_models import (
    db, BaseUser, General, NodeConnection, ProtectedObject,
    AccessPolicyRule, FirewallRule, PolicyGroup, TrafficLog,
    BaseConfigModel, BaseInfoModel, validate_network_field
)

# Импорт API Blueprints
from nmc_api import api_blueprints

engine = create_engine("sqlite:///vpngate.db", future=True)

# Загрузка переменных окружения
env_path = Path(__file__).resolve().parent.parent / '.env'
load_dotenv(dotenv_path=env_path)

# Инициализация Flask приложения
app = Flask(__name__, template_folder='../templates')
app.secret_key = os.getenv('SECRET_KEY') or secrets.token_hex(32)
app.config['DEBUG'] = os.getenv('DEBUG', 'False').lower() == 'true'

scheduler = BackgroundScheduler(daemon=True)


# validate_interface_name теперь импортируется из omnissiah_utils.nmc_wireguard_config_utils
from omnissiah_utils.nmc_wireguard_config_utils import (
    validate_interface_name, get_wg_interfaces, generate_wg_keys, 
    get_external_ip, ping_ip
)


def update_omnissiah_traffic():
    """
    Обновляет статистику трафика для Omnissiah узла.
    Использует SELECT FOR UPDATE для предотвращения race conditions.
    """
    with app.app_context():
        try:
            # Используем SELECT FOR UPDATE для блокировки строки и предотвращения race conditions
            # with_for_update() - это метод запроса, не требует отдельного импорта
            omnissiah_node = db.session.query(General).filter_by(role='Omnissiah').with_for_update(nowait=True).first()
            
            if not omnissiah_node:
                return

            interface = omnissiah_node.name
            if not validate_interface_name(interface):
                app.logger.warning(f"Invalid or None interface name: {interface}, skipping traffic update")
                return
            
            try:
                result = subprocess.run(["sudo", "-n", "wg", "show", interface, "transfer"],
                                        capture_output=True, text=True, check=False, timeout=5)
                
                if result.returncode != 0:
                    # Интерфейс может не существовать или быть остановлен
                    app.logger.debug(f"Интерфейс {interface} не доступен или не имеет peer'ов: {result.stderr}")
                    return
                
                output = result.stdout.strip()
                total_rx, total_tx = 0, 0

                for line in output.splitlines():
                    if line:
                        parts = line.strip().split()
                        if len(parts) >= 3:
                            try:
                                rx, tx = int(parts[1]), int(parts[2])
                                total_rx += rx
                                total_tx += tx
                            except (ValueError, IndexError) as parse_error:
                                app.logger.warning(f"Ошибка парсинга трафика для {interface}: {parse_error}")
                                continue

                # wg show transfer возвращает накопительные значения, поэтому используем их напрямую
                # Обновляем только если значения изменились (для избежания лишних коммитов)
                if omnissiah_node.total_receive != total_rx or omnissiah_node.total_sent != total_tx:
                    omnissiah_node.total_receive = total_rx
                    omnissiah_node.total_sent = total_tx
                    db.session.commit()
                    app.logger.debug(f"[Traffic] Updated: RX={total_rx}, TX={total_tx}")

            except subprocess.TimeoutExpired:
                app.logger.warning(f"Таймаут при получении статистики трафика для {interface}")
            except subprocess.SubprocessError as e:
                app.logger.error(f"Ошибка subprocess при получении статистики трафика: {e}")
            except ValueError as e:
                app.logger.error(f"Ошибка обработки данных трафика: {e}")
            except OperationalError as e:
                # Ошибка блокировки БД (другой процесс уже заблокировал строку)
                app.logger.debug(f"Узел заблокирован другим процессом, пропускаем обновление: {e}")
            except Exception as e:
                app.logger.error(f"Ошибка при получении трафика: {e}", exc_info=True)
                db.session.rollback()
        except Exception as e:
            app.logger.error(f"Критическая ошибка в update_omnissiah_traffic: {e}", exc_info=True)
            try:
                db.session.rollback()
            except Exception:
                pass

# Функция для сбора и сохранения журнала трафика на Omnissiah
def collect_and_save_traffic_logs():
    """Собирает логи трафика и сохраняет в базу данных"""
    with app.app_context():
        try:
            omnissiah_node = General.query.filter_by(role='Omnissiah').first()
            if not omnissiah_node:
                return
            
            # Импортируем модуль сбора трафика
            try:
                from traffic_collector import collect_traffic_logs
                logs = collect_traffic_logs()
            except ImportError:
                try:
                    # Пробуем альтернативный путь
                    import sys
                    import os
                    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
                    from traffic_collector import collect_traffic_logs
                    logs = collect_traffic_logs()
                except ImportError:
                    # Если модуль не найден, используем простой сбор через iptables
                    app.logger.warning("Модуль traffic_collector не найден, сбор трафика отключен")
                    logs = []
            
            # Сохраняем логи в базу данных
            saved_count = 0
            for log_data in logs:
                try:
                    traffic_log = TrafficLog(
                        timestamp=log_data.get('timestamp', datetime.now(timezone.utc)),
                        node_id=omnissiah_node.id,
                        source_ip=log_data.get('source_ip'),
                        destination_ip=log_data.get('destination_ip'),
                        source_port=log_data.get('source_port'),
                        destination_port=log_data.get('destination_port'),
                        protocol=log_data.get('protocol'),
                        action=log_data.get('action'),
                        bytes_sent=log_data.get('bytes_sent', 0),
                        bytes_received=log_data.get('bytes_received', 0),
                        packets_sent=log_data.get('packets_sent', 0),
                        packets_received=log_data.get('packets_received', 0),
                        interface=log_data.get('interface'),
                        direction=log_data.get('direction'),
                        connection_state=log_data.get('connection_state')
                    )
                    db.session.add(traffic_log)
                    saved_count += 1
                except (IntegrityError, ValueError, TypeError) as e:
                    app.logger.warning(f"Ошибка сохранения записи трафика: {e}")
                    continue
            
            if saved_count > 0:
                db.session.commit()
                app.logger.debug(f"[TrafficLog] Сохранено {saved_count} записей трафика")
        
        except (AttributeError, RuntimeError, IntegrityError) as e:
            app.logger.error(f"Ошибка сбора логов трафика: {e}", exc_info=True)

# Планировщик будет запущен после инициализации БД в if __name__ == '__main__'
# Это предотвращает попытки работы с неинициализированной БД


@contextmanager
def db_transaction():
    """
    Контекстный менеджер для атомарных транзакций БД.
    Автоматически делает commit при успехе и rollback при ошибке.
    
    Использование:
        with db_transaction():
            node = General(...)
            db.session.add(node)
            # Все операции атомарны
    """
    try:
        yield db.session
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Ошибка в транзакции БД, выполнен rollback: {e}", exc_info=True)
        raise


def validate_network_field(field_name):
    """Декоратор для валидации сетевых полей модели General."""

    def decorator(func):
        @wraps(func)
        def wrapper(self, key, value):
            # Общие проверки для ip_pool
            if field_name == 'ip_pool':
                try:
                    network = ip_network(value, strict=False)
                    if network.version != 4:
                        raise ValidationError("Поддерживаются только IPv4 сети.")
                    # Для Omnissiah требуем /16 - /29, для других узлов разрешаем /32 (одиночный IP)
                    # Проверяем роль объекта (self в контексте валидатора - это модель General)
                    # При создании объекта роль может быть еще не установлена, поэтому разрешаем /32 по умолчанию
                    node_role = getattr(self, 'role', None)
                    min_prefix = 16
                    # Если роль не установлена или это не Omnissiah, разрешаем /32
                    # Если роль Omnissiah, то максимум /29
                    if node_role == 'Omnissiah':
                        max_prefix = 29
                    else:
                        max_prefix = 32  # Разрешаем /32 для Magos, Cognitor и при создании
                    
                    if network.prefixlen < min_prefix or network.prefixlen > max_prefix:
                        if node_role == 'Omnissiah':
                            raise ValidationError("Маска сети должна быть между /16 и /29.")
                        else:
                            raise ValidationError("Маска сети должна быть между /16 и /32.")
                except ValueError as e:
                    raise ValidationError(f"Неверный формат IP-пула: {str(e)}")

            # Общие проверки для endpoint
            elif field_name == 'endpoint':
                # Пропускаем валидацию если значение None или пустая строка
                if value is None or (isinstance(value, str) and value.strip() == ''):
                    return func(self, key, value)
                try:
                    ip = IPv4Address(value)
                    if ip.version != 4:
                        raise ValidationError("Поддерживаются только IPv4 адреса.")
                except ValueError:
                    raise ValidationError("Неверный формат Endpoint. Ожидается IPv4 адрес.")

            elif field_name == 'listen_port':
                try:
                    port = int(value)
                    if not (1024 <= port <= 65535):
                        raise ValidationError("Порт должен быть в диапазоне 1024–65535.")
                except ValueError:
                    raise ValidationError("Порт должен быть целым числом.")

            # Общие проверки для role
            elif field_name == 'role':
                valid_roles = ['Omnissiah', 'Magos', 'Cognitor']
                if value not in valid_roles:
                    raise ValidationError(f"Недопустимая роль. Допустимые значения: {', '.join(valid_roles)}")

            return func(self, key, value)

        return wrapper

    return decorator



STATUS_CHOICES = {
    'active': '🟢 Подключен',
    'inactive': '🔴 Неактивен',
    'stopped': '⏸ Остановлен',
    'pending': '🟡 Ожидание'
}

# Конфигурация приложения
app.config.update(
    SQLALCHEMY_DATABASE_URI=os.getenv('OMNISSIAH_DATABASE_URI', 'sqlite:///vpngate.db'),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    WG_CONFIG_PATH='/etc/wireguard/',
    WG_DEFAULT_DNS='1.1.1.1',
    WG_DEFAULT_ALLOWED_IPS='0.0.0.0/0',
    WG_IP_POOL='10.0.0.0/24',
    # SECRET_KEY теперь берется из переменной окружения или генерируется при запуске
)

# Глобальные переменные
configurations = []  # Список доступных конфигураций
dynamic_user_models = {}
dynamic_info_models = {}

# Инициализация базы данных (db уже импортирован из nmc_models)
db.init_app(app)

# Регистрация API Blueprints
for blueprint in api_blueprints:
    app.register_blueprint(blueprint)

# The Ansible deployment uses a loopback backend behind a TLS reverse proxy.
from deployment_auth import install_management_auth
install_management_auth(app)



def init_system():
    """Создание системного пользователя и настройка прав"""
    if not manage_sudo_permissions('wg'):
        raise RuntimeError("Не удалось настроить sudo права для WireGuard")
    try:
        wg_dir = app.config['WG_CONFIG_PATH']
        current_user = os.getenv('SUDO_USER') or os.getenv('USER')
        current_group = grp.getgrgid(os.getgid()).gr_name

        subprocess.run(["sudo", "-n", "mkdir", "-p", wg_dir], check=True)
        subprocess.run(["sudo", "-n", "chown", f"{current_user}:{current_group}", wg_dir], check=True)
        subprocess.run(["sudo", "-n", "chmod", "770", wg_dir], check=True)

        if not manage_sudo_permissions('wg'):
            raise RuntimeError("Не удалось настроить sudo права для WireGuard")

        app.logger.info("Системные настройки успешно применены")
        return True

    except subprocess.CalledProcessError as e:
        error_msg = f"""
            Ошибка инициализации!
            Команда: {' '.join(e.cmd)}
            Код ошибки: {e.returncode}
            Сообщение: {e.stderr.decode() if e.stderr else 'Нет дополнительной информации'}
            """
        app.logger.error(error_msg)
        return False
    except (OSError, PermissionError, FileNotFoundError) as e:
        current_app.logger.error(f"Системная ошибка при инициализации: {str(e)}")
        return False
    except (RuntimeError, ValueError, AttributeError) as e:
        current_app.logger.error(f"Ошибка инициализации: {str(e)}", exc_info=True)
        return False



def get_system_interfaces(node=None, include_down=True):
    """
    Возвращает список интерфейсов:
    {'name': ..., 'ip': ..., 'display': ..., 'is_wireguard': ...}
    Только для главного узла (Omnissiah), исключая lo, docker, any и интерфейсы без IP.

    Аргументы:
        node: General-объект узла. Работает только если node.role == 'Omnissiah'.
        include_down: bool — включать ли выключенные интерфейсы (по умолчанию True).
    """
    interfaces = []

    try:
        if node and node.role != 'Omnissiah':
            return []

        # Получаем список WG-интерфейсов
        try:
            wg_result = subprocess.run(
                ["wg", "show", "interfaces"],
                capture_output=True,
                text=True,
                check=True
            )
            wg_interfaces = set(wg_result.stdout.strip().split())
        except subprocess.CalledProcessError:
            wg_interfaces = set()

        # Команда получения интерфейсов
        ip_link_command = ["ip", "-o", "link", "show"]
        if not include_down:
            ip_link_command.append("up")  # фильтрация по "включённым" интерфейсам

        # Список всех интерфейсов
        link_result = subprocess.run(
            ip_link_command,
            capture_output=True,
            text=True,
            check=True
        )
        interface_lines = link_result.stdout.splitlines()

        for line in interface_lines:
            iface = line.split(': ')[1].split('@')[0]

            # Исключаем lo, docker, any
            if iface.startswith('lo') or iface.startswith('docker') or iface == 'any':
                continue

            # Получаем IPv4 адреса
            ip_result = subprocess.run(
                ["ip", "-4", "-o", "addr", "show", "dev", iface],
                capture_output=True,
                text=True,
                check=False
            )

            ips = []
            if ip_result.returncode == 0:
                for ip_line in ip_result.stdout.splitlines():
                    parts = ip_line.strip().split()
                    if len(parts) >= 4:
                        ip = parts[3].split('/')[0]
                        ips.append(ip)

            if not ips:
                continue  # исключаем интерфейсы без IP

            interfaces.append({
                'name': iface,
                'ip': ','.join(ips),
                'display': f"{iface} - {', '.join(ips)}",
                'is_wireguard': iface in wg_interfaces
            })

    except subprocess.CalledProcessError as e:
        current_app.logger.error(f"Ошибка получения интерфейсов: {e.stderr}")
    except (OSError, subprocess.SubprocessError, FileNotFoundError) as e:
        current_app.logger.error(f"Системная ошибка при получении интерфейсов: {str(e)}")
    except (ValueError, AttributeError) as e:
        current_app.logger.error(f"Ошибка обработки данных интерфейсов: {str(e)}", exc_info=True)

    return interfaces



class NodeService:
    @staticmethod
    def get_available_ips(node):
        try:
            if not node or not node.ip_pool:
                return []
            network = ip_network(node.ip_pool, strict=False)
            used_ips = {peer.ip_pool.split('/')[0] for peer in node.children if peer and peer.ip_pool}
            return [f"{host}/{network.prefixlen}"
                    for host in network.hosts()
                    if str(host) not in used_ips]
        except ValueError as e:
            current_app.logger.error(f"IP calculation error: {str(e)}")
            return []

def get_sudo_status():
    """Проверяем, есть ли у пользователя права sudo без пароля"""
    try:
        result = subprocess.run(
            ['sudo', '-n', 'true'],
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            timeout=5
        )
        return result.returncode == 0
    except subprocess.TimeoutError:
        return False


def manage_sudo_permissions(mode: str = 'wg') -> bool:
    """
    Универсальная функция для настройки sudo прав
    :param mode: Режим настройки ('wg' - для WireGuard, 'fw' - для фаервола, 'all' - полный доступ)
    :return: True если настройка успешна, False в случае ошибки
    """
    current_user = os.getenv('SUDO_USER') or os.getenv('USER')
    sudoers_dir = '/etc/sudoers.d'
    tmp_path = None

    try:
        # Определяем команды для разных режимов
        commands = {
            'wg': [
                '/usr/sbin/iptables',
                '/usr/sbin/iptables-save',
                '/usr/sbin/iptables-restore',
                '/usr/bin/wg*',
                '/usr/bin/wg-quick*'
            ],
            'fw': [
                '/usr/sbin/iptables',
                '/usr/sbin/iptables-save',
                '/usr/sbin/iptables-restore'
            ],
            'nginx': [
                '/usr/sbin/nginx',
                '/bin/systemctl',
                '/bin/cp',
                '/bin/rm',
                '/bin/ln',
                '/bin/mkdir',
                '/bin/chmod',
                '/bin/chown',
                '/usr/bin/certbot'
            ],
            'all': [
                '/usr/sbin/iptables*',
                '/usr/bin/wg*',
                '/usr/sbin/nginx',
                '/bin/systemctl reload nginx',
                '/bin/systemctl restart nginx',
                '/bin/cp',
                '/bin/rm',
                '/bin/ln',
                '/bin/mkdir',
                '/bin/chmod',
                '/bin/chown'
            ]
        }.get(mode, [])

        valid_modes = ['wg', 'fw', 'nginx', 'all']
        if mode not in valid_modes:
            raise ValueError(f"Invalid mode: {mode}. Valid modes: {', '.join(valid_modes)}")

        filename = f"nmc-wg-{mode}"
        dest_path = os.path.join(sudoers_dir, filename)
        
        # Удаляем старый файл, если существует
        if os.path.exists(dest_path):
            try:
                subprocess.run(['sudo', 'rm', dest_path], check=True, stderr=subprocess.DEVNULL)
                app.logger.info(f"Удален старый файл sudoers: {dest_path}")
            except subprocess.CalledProcessError:
                pass  # Игнорируем ошибки удаления

        # Формируем содержимое файла с уникальным именем псевдонима
        alias_name = f"NMC_{mode.upper()}_CMDS"
        sudo_content = f"""# Правила для NMC WireGuard Manager (режим: {mode})
# Создано автоматически при запуске приложения
Cmnd_Alias {alias_name} = {', '.join(commands)}
{current_user} ALL=(root) NOPASSWD: {alias_name}
"""

        # Создаем временный файл
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
            tmp.write(sudo_content.strip())
            tmp_path = tmp.name

        # Копируем с использованием sudo
        subprocess.run(['sudo', 'cp', tmp_path, dest_path], check=True)
        subprocess.run(['sudo', 'chmod', '0440', dest_path], check=True)
        subprocess.run(['sudo', 'chown', 'root:root', dest_path], check=True)

        # Проверка синтаксиса
        check_result = subprocess.run(
            ['sudo', 'visudo', '-c', '-f', dest_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        if check_result.returncode != 0:
            app.logger.error(f"Ошибка проверки синтаксиса: {check_result.stderr}")
            return False

        return True

    except subprocess.CalledProcessError as e:
        app.logger.error(f"Ошибка выполнения команды: {e.stderr.decode()}")
        return False
    except (OSError, PermissionError, FileNotFoundError) as e:
        app.logger.error(f"Системная ошибка: {str(e)}")
        return False
    except (ValueError, AttributeError, RuntimeError) as e:
        app.logger.error(f"Ошибка обработки данных: {str(e)}", exc_info=True)
        return False
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except (OSError, PermissionError) as e:
                app.logger.error(f"Ошибка удаления временного файла: {str(e)}")




# Все модели теперь импортируются из nmc_models

class ConfigForm(FlaskForm):
    name = StringField('Имя интерфейса', validators=[DataRequired()])
    ip_pool = StringField('IP-пул', validators=[DataRequired()])
    port = IntegerField('Порт', validators=[DataRequired(), NumberRange(min=1024, max=65535)])


# Все модели теперь импортируются из nmc_models

def calculate_ip_ranges(ip_pool: str, node: General) -> Dict:
    """Упрощенный расчет диапазонов IP с использованием возможностей ipaddress"""
    network = IPv4Network(ip_pool, strict=False)
    used_ips = set()

    # Проверяем входные данные
    if not ip_pool:
        return []

    # Собираем все используемые IP
    server_ip = IPv4Address(ip_pool.split('/')[0])
    used_ips.add(server_ip)

    for peer in node.all_children:
        if not peer or not peer.ip_pool:
            continue
        peer_ip = IPv4Address(peer.ip_pool.split('/')[0])
        used_ips.add(peer_ip)

    # Сортируем и преобразуем в числовой формат
    sorted_used = sorted([ip_int for ip in used_ips if (ip_int := int(ip))])
    all_ips = [int(ip) for ip in network.hosts()]

    # Функция для группировки последовательных IP
    def group_ips(ips: List[int]) -> List[Tuple[str, str]]:
        if not ips:
            return []
        ranges = []
        start = current = ips[0]
        for ip in ips[1:]:
            if ip == current + 1:
                current = ip
            else:
                ranges.append((start, current))
                start = current = ip
        ranges.append((start, current))
        return [(str(IPv4Address(s)), str(IPv4Address(e))) for s, e in ranges]

    used_ranges = group_ips(sorted_used)
    free_ips = sorted(set(all_ips) - set(sorted_used))
    free_ranges = group_ips(free_ips)

    return {
        'server_ip': str(server_ip),  # IP адрес сервера из ip_pool
        'used_ranges': [{'start': s, 'end': e} for s, e in used_ranges],
        'free_ranges': [{'start': s, 'end': e} for s, e in free_ranges],
        'total_ips': len(all_ips),
        'used_ips': len(sorted_used),
        'free_ips': len(free_ips)
    }

@app.template_filter('ip_to_int')
def ip_to_int_filter(ip_str: str) -> int:
    return int(IPv4Address(ip_str))

# Все модели теперь импортируются из nmc_models

class ServerConfigForm(FlaskForm):
    name = StringField('Имя конфигурации', validators=[DataRequired()])
    ip_pool = StringField('IP-пул', validators=[DataRequired()])  # Это поле обязательно!
    port = IntegerField('Порт', validators=[DataRequired(), NumberRange(min=1, max=65535)])
    dns = StringField('DNS-серверы', validators=[DataRequired()])
    mtu = IntegerField('MTU', validators=[DataRequired(), NumberRange(min=576, max=1500)])
    endpoint = StringField('Endpoint', validators=[DataRequired()])
    use_preshared_key = BooleanField('Использовать общий ключ')

    def validate_ip_pool(self, field):
        try:
            ip_str, prefix = field.data.split('/')
            ip = IPv4Address(ip_str)
            network = ip_network(f"{ip}/{prefix}", strict=False)
            if int(prefix) < 16 or int(prefix) > 29:
                raise ValidationError("Маска должна быть между /16 и /29")
        except ValueError:
            raise ValidationError("Некорректный формат IP-пула (пример: 10.0.0.1/24)")

def validate_network(value, field_type):
    try:
        if field_type == 'ip_pool':
            network = ip_network(value, strict=False)
            if network.prefixlen < 16 or network.prefixlen > 29:
                raise ValueError("Mask must be between /16 and /29")
        elif field_type == 'endpoint':
            if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}$', value):
                raise ValueError("Invalid endpoint format")
        return True
    except ValueError as e:
        raise ValidationError(str(e))

class BaseNetworkForm(FlaskForm):
    def validate_network(self, field):
        return validate_network(field.data, self.field_type)

class SetupWizardForm(FlaskForm):
    name = StringField('Имя сервера', validators=[DataRequired()])
    configure_wireguard = BooleanField('Настроить WireGuard', default=False)
    ip_pool = SelectField('IP-пул', validators=[Optional()], choices=[])  # Выпадающий список с доступными IP
    port = IntegerField('Порт', validators=[
        Optional(),
        NumberRange(min=1024, max=65535)
    ])
    dns = StringField('DNS сервер', default='1.1.1.1')
    mtu = IntegerField('MTU', default=1420)
    endpoint = StringField('Endpoint сервера', validators=[Optional()])
    role = SelectField('Роль сервера', choices=[
        ('Omnissiah', 'Omnissiah (Главный сервер)'),
        ('Magos', 'Magos (Ретранслятор)'),
        ('Cognitor', 'Cognitor (Клиент)')
    ])
    parent_id = SelectField('Родительский узел', coerce=int, validators=[Optional()], choices=[])
    communication = StringField('Связи (необязательно)')
    use_preshared_key = BooleanField('Использовать общий ключ', default=True)
    deploy_via_ssh = BooleanField('Отправить ПО и конфигурацию по SSH', default=False)
    
    # Поля для настройки nginx
    configure_nginx = BooleanField('Настроить nginx', default=False)
    nginx_domain = StringField('Домен для nginx', validators=[Optional()])
    nginx_cert_type = SelectField('Тип сертификата', choices=[
        ('self-signed', 'Self-signed (для внутренней сети)'),
        ('letsencrypt', 'Let\'s Encrypt (для публичного домена)')
    ], default='self-signed')
    nginx_email = StringField('Email для Let\'s Encrypt', validators=[Optional()])
    nginx_https_port = IntegerField('HTTPS порт', default=443, validators=[Optional(), NumberRange(min=1, max=65535)])
    nginx_redirect_http = BooleanField('Перенаправлять HTTP на HTTPS', default=True)
    admin_ip = StringField('IP адрес узла администратора', validators=[Optional()], 
                          description='IP адрес с которого разрешен весь трафик (только для Omnissiah)')

    additional_connections = SelectMultipleField(
        'Дополнительные связи (необязательно)',
        coerce=int,
        choices=[],
        render_kw={'data-live-search': 'true'}
    )

    def validate_ip_pool(self, field):
        # Валидация только если поле заполнено
        if not field.data:
            return
        try:
            ip_str, prefix = field.data.split('/')
            ip = IPv4Address(ip_str)
            network = ip_network(f"{ip}/{prefix}", strict=False)
            if int(prefix) < 16 or int(prefix) > 29:
                raise ValidationError("Маска должна быть между /16 и /29")
        except ValueError:
            raise ValidationError("Некорректный формат IP-пула")
    
    def validate(self, extra_validators=None):
        """Дополнительная валидация: если configure_wireguard=True, то параметры обязательны"""
        if not super().validate():
            return False
        
        # Для главного сервера проверяем флаг configure_wireguard
        if hasattr(self, 'role') and self.role.data == 'Omnissiah':
            if self.configure_wireguard.data:
                if not self.ip_pool.data:
                    self.ip_pool.errors.append('IP-пул обязателен при настройке WireGuard')
                    return False
                if not self.port.data:
                    self.port.errors.append('Порт обязателен при настройке WireGuard')
                    return False
                if not self.endpoint.data:
                    self.endpoint.errors.append('Endpoint обязателен при настройке WireGuard')
                    return False
            
            # Валидация для nginx
            if self.configure_nginx.data:
                if not self.nginx_domain.data:
                    self.nginx_domain.errors.append('Домен обязателен при настройке nginx')
                    return False
                if self.nginx_cert_type.data == 'letsencrypt' and not self.nginx_email.data:
                    self.nginx_email.errors.append('Email обязателен для Let\'s Encrypt')
                    return False
        # Для Magos и Cognitor параметры обязательны всегда
        elif hasattr(self, 'role') and self.role.data in ['Magos', 'Cognitor']:
            if not self.ip_pool.data:
                self.ip_pool.errors.append('IP-пул обязателен')
                return False
            if not self.endpoint.data:
                self.endpoint.errors.append('Endpoint обязателен')
                return False
        
        return True

    def __init__(self,  *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Заполняем choices для интерфейса
        if hasattr(self, 'obj') and self.obj:
            if self.obj.role in ['Omnissiah', 'Magos']:
                available_nodes = self.obj.get_available_for_connections()
                self.additional_connections.choices = [
                    (n.id, f"{n.name} ({n.role})") for n in available_nodes
                ]


# Декоратор для проверки прав администратора. Не для API
def exempt_from_csrf(f):
    """Декоратор для отключения CSRF проверки для API endpoints"""
    f.exempt_from_csrf = True
    return f


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:  # Если не авторизован → на логин
            return redirect(url_for('login'))
        if current_user.role != 'admin':      # Если не админ → 403 Forbidden
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


def require_omnissiah(f):
    """Декоратор для проверки наличия главной конфигурации (Omnissiah)"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Проверяем наличие главной конфигурации
        omnissiah = General.query.filter_by(role='Omnissiah').first()
        if not omnissiah:
            flash('Сначала необходимо создать главную конфигурацию', 'warning')
            return redirect(url_for('setup_wizard'))
        return f(*args, **kwargs)
    return decorated_function


# Все модели теперь импортируются из nmc_models

class AddPeerForm(FlaskForm):
    name = StringField('Имя объекта', validators=[
        DataRequired(),
        Regexp(r'^[a-zA-Z0-9_-]+$', message='Только буквы, цифры, дефисы и подчёркивания')
    ])
    role = SelectField('Роль', choices=[
        ('Magos', 'Magos (Ретранслятор)'),
        ('Cognitor', 'Cognitor (Клиент)')
    ], validators=[DataRequired()])
    ip_pool = StringField('IP-адрес', validators=[
        DataRequired(),
        Regexp(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$', message='Формат: XXX.XXX.XXX.XXX/XX')
    ])
    endpoint = StringField('Endpoint (для Magos)')
    parent_id = SelectField('Центральный узел (для Cognitor)', coerce=int)

    def validate_ip_address(self, field):
        try:
            ip_str, prefix = field.data.split('/')
            ip = IPv4Address(ip_str)
            network = ip_network(field.data, strict=False)

            # Основные проверки
            if network.prefixlen < 16 or network.prefixlen > 29:
                raise ValidationError("Маска должна быть между /16 и /29")

            if General.query.filter(General.ip_pool.startswith(f"{ip_str}/")).first():
                raise ValidationError("Этот IP уже используется в системе")

            if ping_ip(ip_str):
                raise ValidationError("Этот IP уже кем-то используется в сети")

            # Проверка принадлежности к сети родительского узла
            if self.role.data == 'Cognitor' and self.parent_id.data:
                parent_node = General.query.get(self.parent_id.data)
                if not parent_node:
                    raise ValidationError("Центральный узел не найден")

                parent_network = ip_network(parent_node.ip_pool, strict=False)
                if ip not in parent_network:
                    raise ValidationError(
                        f"IP должен быть в сети центрального узла ({parent_node.ip_pool})"
                    )

            elif self.role.data == 'Magos':
                omnissiah_server = General.query.filter_by(role='Omnissiah').first()
                if omnissiah_server:
                    main_network = ip_network(omnissiah_server.ip_pool, strict=False)
                    if ip not in main_network:
                        raise ValidationError(
                            "IP Magos должен быть в сети главного сервера"
                        )

        except ValueError:
            raise ValidationError("Некорректный формат IP-адреса")

    def validate(self, extra_validators=None):
        if not super().validate():
            return False

        if self.role.data == 'Cognitor' and not self.parent_id.data:
            self.parent_id.errors.append('Для клиента должен быть выбран центральный узел')
            return False

        return True

    def validate_ip_address(self, field):
        try:
            # Проверяем валидность IP
            ip = IPv4Address(field.data.split('/')[0])
            network = ip_network(field.data, strict=False)

            # Проверяем, что IP не занят
            if General.query.filter(General.ip_pool.like(f"%{ip}%")).first():
                raise ValidationError("Этот IP-адрес уже используется")

            # Проверяем, что IP входит в сеть главного сервера
            omnissiah_config = General.query.filter_by(role='Omnissiah').first()
            if omnissiah_config:
                main_network = ip_network(omnissiah_config.ip_pool, strict=False)
                if ip not in main_network:
                    raise ValidationError("IP должен быть в сети главного сервера")

        except ValueError:
            raise ValidationError("Некорректный формат IP-адреса")


@app.route('/api/magi_status')
def api_magi_status():
    now = datetime.now(timezone.utc)
    results = []

    magi = General.query.filter_by(role='Magos').all()

    if os.getenv('OMNISSIAH_REQUIRE_MTLS', 'false').lower() == 'true':
        from management_status import peer_status
        return jsonify([dict(id=node.id, name=node.name, ip=node.ip_pool,
            vpn_status='online' if peer_status(node)['vpn_connected'] else 'offline',
            service_status='online' if peer_status(node)['service_active'] else 'offline') for node in magi])

    try:
        wg_output = subprocess.run(["wg", "show", "all", "dump"],
                                   capture_output=True, text=True, check=True)
        wg_lines = wg_output.stdout.strip().splitlines()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        wg_lines = []
        app.logger.debug(f"Не удалось выполнить wg dump: {e}")

    for magos in magi:
        if not magos or not magos.ip_pool:
            continue
        latest_handshake = 0
        magos_ip = magos.ip_pool.split("/")[0]

        for line in wg_lines:
            parts = line.strip().split()
            if len(parts) >= 6:
                allowed_ips = parts[4].split(",")
                allowed_ips = [ip.strip().split("/")[0] for ip in allowed_ips]
                if magos_ip in allowed_ips:
                    try:
                        latest_handshake = int(parts[5])
                    except ValueError:
                        latest_handshake = 0
                    break

        # 🔁 VPN статус
        vpn_alive = (int(now.timestamp()) - latest_handshake) < 180
        vpn_status = "online" if vpn_alive else "offline"

        # 💓 Сервис статус (по last_heartbeat)
        if magos.last_heartbeat:
            magos_last_hb = magos.last_heartbeat
            if magos_last_hb.tzinfo is None:
                magos_last_hb = magos_last_hb.replace(tzinfo=timezone.utc)
            hb_alive = (now - magos_last_hb) < timedelta(seconds=90)
        else:
            hb_alive = False
        service_status = "online" if hb_alive else "offline"

        # 💾 Сохраняем в БД (обновляем последнее рукопожатие и статус сервиса)
        magos.last_handshake = datetime.fromtimestamp(latest_handshake, tz=timezone.utc) if latest_handshake else None
        magos.status = service_status

        results.append({
            "id": magos.id,
            "name": magos.name,
            "ip": magos.ip_pool,
            "vpn_status": vpn_status,
            "service_status": service_status
        })

    db.session.commit()
    for magos in magi:
        if magos.status == "online":
            # Используем SELECT FOR UPDATE для предотвращения race conditions
            # with_for_update() - это метод запроса, не требует отдельного импорта
            try:
                cognitors = db.session.query(General).filter_by(
                    parent_id=magos.id, 
                    role='Cognitor'
                ).with_for_update(nowait=True).all()
            except OperationalError:
                # Если другой процесс уже заблокировал строки, пропускаем этот Magos
                app.logger.debug(f"Узлы для {magos.name} заблокированы другим процессом, пропускаем")
                continue
            
            for cognitor in cognitors:
                # --- ДОБАВЛЕНИЕ ---
                # Используем атомарную проверку и обновление через refresh для актуального состояния
                db.session.refresh(cognitor)
                if cognitor.sent_to_magos == 0 and cognitor.ack_from_magos == 0:
                    try:
                        magos_url = get_api_url(magos, endpoint="/api/add_peer", default_port=5001)

                        payload = {
                            "name": cognitor.name,
                            "ip_pool": cognitor.ip_pool,
                            "public_key": cognitor.public_key,
                            "preshared_key": cognitor.preshared_key,
                            "parent_public_key": magos.public_key,
                            "dns": cognitor.dns,
                            "mtu": cognitor.mtu
                        }

                        # Для self-signed сертификатов отключаем проверку SSL
                        verify_ssl = magos.nginx_cert_type != 'self-signed' if magos.nginx_enabled else True
                        response = requests.post(magos_url, json=payload, timeout=10, verify=verify_ssl)

                        if response.status_code == 200:
                            resp_json = response.json()
                            if resp_json.get("status") == "ok":
                                # Обновляем статус атомарно в транзакции
                                cognitor.sent_to_magos = 1   # статус "отправлен"
                                cognitor.ack_from_magos = 1  # статус "подтвержден"
                                db.session.commit()
                                app.logger.info(f"✅ {cognitor.name} отправлен и подтверждён от {magos.name}")
                            else:
                                app.logger.warning(f"⚠️ Отправлен, но не подтверждён от {magos.name}")
                                cognitor.sent_to_magos = 1   # попытка отправки была
                                cognitor.ack_from_magos = 0  # ack не получен
                                db.session.commit()
                        else:
                            app.logger.warning(f"⚠️ HTTP {response.status_code} при отправке {cognitor.name} → {magos.name}")
                    except (requests.RequestException, requests.Timeout, requests.ConnectionError) as e:
                        app.logger.error(f"❌ Ошибка сетевого запроса при отправке клиента {cognitor.name} → {magos.name}: {str(e)}")
                        db.session.rollback()
                    except (ValueError, KeyError, AttributeError) as e:
                        app.logger.error(f"❌ Ошибка данных при отправке клиента {cognitor.name} → {magos.name}: {str(e)}")
                        db.session.rollback()
                    except (RuntimeError, TypeError) as e:
                        app.logger.error(f"❌ Ошибка обработки при отправке клиента {cognitor.name} → {magos.name}: {str(e)}", exc_info=True)
                        db.session.rollback()
                # --- УДАЛЕНИЕ ---
                elif cognitor.sent_to_magos == 2 and cognitor.ack_from_magos != 2:
                    try:
                        magos_url = get_api_url(magos, endpoint="/api/remove_peer", default_port=5001)

                        payload = {
                            "cognitor_name": cognitor.name
                        }

                        # Для self-signed сертификатов отключаем проверку SSL
                        verify_ssl = magos.nginx_cert_type != 'self-signed' if magos.nginx_enabled else True
                        response = requests.post(magos_url, json=payload, timeout=10, verify=verify_ssl)

                        if response.status_code == 200:
                            app.logger.info(f"🗑 Запрос на удаление {cognitor.name} отправлен на {magos.name}")
                        else:
                            app.logger.warning(f"⚠️ Ошибка при удалении: {response.text}")
                    except (requests.RequestException, requests.Timeout, requests.ConnectionError) as e:
                        app.logger.error(f"❌ Ошибка сетевого запроса при удалении {cognitor.name} → {magos.name}: {str(e)}")
                    except (RuntimeError, TypeError, AttributeError) as e:
                        app.logger.error(f"❌ Ошибка обработки при удалении {cognitor.name} → {magos.name}: {str(e)}", exc_info=True)
                # --- Всё остальное (уже отправлено, подтверждено, либо ждем ack на удаление) ---
                else:
                    continue

    return jsonify(results)

# Endpoints /api/ack_peer и /api/ack_remove_peer теперь в nmc_api/peers.py


@app.before_request
def check_wg_configs():
    """Проверка валидности конфигов WireGuard перед запросами"""
    if request.path.startswith('/node/'):
        try:
            for filename in os.listdir(app.config['WG_CONFIG_PATH']):
                if filename.endswith('.conf'):
                    config_path = os.path.join(app.config['WG_CONFIG_PATH'], filename)
                    # Используем showconf вместо checkconf
                    result = subprocess.run(
                        ['sudo', '-n', '/usr/bin/wg', 'showconf', filename.replace('.conf', '')],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    if result.returncode != 0:
                        current_app.logger.error(f"Invalid WireGuard config {filename}: {result.stderr}")
        except (OSError, subprocess.SubprocessError, FileNotFoundError) as e:
            current_app.logger.error(f"Ошибка проверки конфигурации WireGuard: {str(e)}")
        except (ValueError, AttributeError) as e:
            current_app.logger.error(f"Ошибка обработки данных конфигурации: {str(e)}", exc_info=True)


def setup_wireguard_permissions():
    """Настраивает права для работы с WireGuard"""
    try:
        wg_dir = '/etc/wireguard'
        current_user = os.getenv('SUDO_USER') or os.getenv('USER')

        # Создаем директорию, если не существует
        if not os.path.exists(wg_dir):
            subprocess.run(['sudo', '-n', 'mkdir', '-p', wg_dir], check=True)

        # Устанавливаем владельца и права
        subprocess.run(['sudo', '-n', 'chown', f'{current_user}:{current_user}', wg_dir], check=True)
        subprocess.run(['sudo', '-n', 'chmod', '700', wg_dir], check=True)

        return True
    except subprocess.CalledProcessError as e:
        app.logger.error(f"Ошибка настройки прав: {e.stderr}")
        return False

# Замените проверку наличия WireGuard на:
def check_wg_installation():
    try:
        subprocess.run(
            ["sudo", "/usr/bin/wg", "--version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def check_wg_permissions():
    """Проверяет возможность записи конфигов WireGuard"""
    try:
        test_file = '/etc/wireguard/.test_permissions'
        subprocess.run(['sudo', 'touch', test_file], check=True)
        subprocess.run(['sudo', 'rm', test_file], check=True)
        return True
    except subprocess.CalledProcessError:
        return False


def update_wg_config_file(config):
    """Безопасное обновление конфигурации WireGuard"""
    config_path = Path('/etc/wireguard') / f"{config.name}.conf"
    current_user = os.getenv('SUDO_USER') or os.getenv('USER')
    current_group = grp.getgrgid(os.getgid()).gr_name

    try:  # Было ttry, исправлено на try
        # Проверяем наличие обязательных полей
        if not config or not config.ip_pool:
            app.logger.error(f"Отсутствует ip_pool для конфигурации {config.name if config else 'Unknown'}")
            return False
        
        # Формируем содержимое конфига
        server_ip = config.ip_pool.split('/')[0]
        network = ip_network(config.ip_pool, strict=False)

        # Получаем расшифрованный private_key
        decrypted_private_key = get_decrypted_private_key(config)
        if not decrypted_private_key:
            app.logger.error(f"Не удалось получить private_key для {config.name}")
            return False

        config_content = f"""[Interface]
PrivateKey = {decrypted_private_key}
Address = {server_ip}/{network.prefixlen}
ListenPort = {config.listen_port}"""

        if config.mtu:
            config_content += f"\nMTU = {config.mtu}"

        # Создаем временный файл
        with tempfile.NamedTemporaryFile('w', delete=False) as tmp:
            tmp.write(config_content)
            tmp_path = tmp.name

        # Копируем с использованием sudo
        subprocess.run(['sudo', '-n', 'cp', tmp_path, str(config_path)], check=True)
        subprocess.run(['sudo', '-n', 'chown', f'{current_user}:{current_group}', str(config_path)], check=True)
        subprocess.run(['sudo', '-n', 'chmod', '600', str(config_path)], check=True)

        return True

    except (OSError, PermissionError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        app.logger.critical(f"Критическая ошибка обновления конфигурации WireGuard: {str(e)}", exc_info=True)
        return False
    finally:
        if 'tmp_path' in locals() and os.path.exists(tmp_path):
            os.unlink(tmp_path)


# функция новой версии. не для API
def parse_wg_output(output):
    """Парсит вывод команды wg show в структурированный словарь"""
    result = {
        'interface': {},
        'peers': []
    }
    current_peer = None

    for line in output.split('\n'):
        line = line.strip()
        if not line:
            continue

        if line.startswith('interface:'):
            result['interface']['name'] = line.split(': ')[1]
        elif line.startswith('public key:'):
            if current_peer is None:
                result['interface']['public_key'] = line.split(': ')[1]
            else:
                current_peer['public_key'] = line.split(': ')[1]
        elif line.startswith('peer:'):
            if current_peer is not None:
                result['peers'].append(current_peer)
            current_peer = {'public_key': line.split(': ')[1]}
        elif current_peer is not None and ': ' in line:
            key, value = line.split(': ', 1)
            current_peer[key] = value
        elif ': ' in line:
            key, value = line.split(': ', 1)
            result['interface'][key] = value

    if current_peer is not None:
        result['peers'].append(current_peer)

    return result


def update_server_status():
    with app.app_context():
        interfaces = get_wg_interfaces()
        global configurations

        for interface in interfaces:
            # Валидация имени интерфейса для безопасности
            if not validate_interface_name(interface):
                app.logger.warning(f"Skipping invalid interface name: {interface}")
                continue
            try:
                output = subprocess.check_output(
                    ["sudo", "/usr/bin/wg", "show", interface],
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=5
                )

                # Создаем модели при необходимости
                if interface not in dynamic_user_models:
                    user_model, info_model = create_dynamic_models(interface)
                    dynamic_user_models[interface] = user_model
                    dynamic_info_models[interface] = info_model

                config = parse_wg_output(output)
                InfoModel = dynamic_info_models[interface]

                # Обновляем статистику
                info = InfoModel.query.first() or InfoModel()
                total_receive = 0
                total_sent = 0

                for peer in config['peers']:
                    received = int(peer.get('transfer received', '0').split()[0])
                    sent = int(peer.get('transfer sent', '0').split()[0])
                    total_receive += received
                    total_sent += sent

                info.receive = total_receive
                info.sent = total_sent
                info.total = total_receive + total_sent
                db.session.add(info)

            except subprocess.CalledProcessError as e:
                app.logger.error(f"Ошибка интерфейса {interface}: {e.output}")
                continue

        db.session.commit()


# проверку прав доступа
def check_config_permissions(config_path):
    """Проверка прав доступа к конфигурационному файлу"""
    try:
        current_user = pwd.getpwuid(os.getuid()).pw_name
        stat = os.stat(config_path)
        if stat.st_uid != os.getuid():
            subprocess.run(
                ["sudo", "-n", "chown", f"{current_user}:", str(config_path)],
                check=True
            )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as e:
        app.logger.error(f"Permission check failed: {str(e)}")

# Исправлено создание моделей
def create_dynamic_models(config_name):
    """Создает динамические модели для конфигурации"""
    user_model = type(
        f'{config_name}Config',
        (BaseConfigModel,),
        {
            '__tablename__': config_name,
            '__table_args__': {'extend_existing': True},
            'id': db.Column(db.Integer, primary_key=True),
            'base_user_id': db.Column(db.Integer, db.ForeignKey('base_users.id')),
            'allowed_ip': db.Column(db.String(15)),
            'public_key': db.Column(db.String(256)),
            'private_key': db.Column(db.String(256)),
            'api_peer_id': db.Column(db.String(50)),
            'latest_handshake': db.Column(db.DateTime),
            'server_conf': db.Column(db.Text),
            'dns': db.Column(db.String(50)),
            'endpoint_allowed_ip': db.Column(db.String(100)),
            'total_receive': db.Column(db.BigInteger),
            'total_sent': db.Column(db.BigInteger),
            'total_data': db.Column(db.BigInteger),
            'status': db.Column(db.String(20), default='pending'),
            'cumu_receive': db.Column(db.BigInteger),
            'cumu_sent': db.Column(db.BigInteger),
            'cumu_data': db.Column(db.BigInteger),
            'old_endpoint': db.Column(db.String(100)),
            'real_endpoint': db.Column(db.String(100))
        }
    )
    info_model = type(
        f'{config_name}Info',
        (BaseInfoModel,),
        {
            '__tablename__': f'{config_name}_info',
            'id': db.Column(db.Integer, primary_key=True),
            'address': db.Column(db.String(50)),
            'connected_peers': db.Column(db.Integer),
            'receive': db.Column(db.Float),
            'sent': db.Column(db.Float),
            'total': db.Column(db.Float),
            'listen_port': db.Column(db.String(10)),
            'name': db.Column(db.String(50)),
            'post_down': db.Column(db.String(500)),
            'post_up': db.Column(db.String(500)),
            'pre_down': db.Column(db.String(500)),
            'pre_up': db.Column(db.String(500)),
            'public_key': db.Column(db.String(256)),
            'save_config': db.Column(db.Boolean),
            'status': db.Column(db.Boolean),
            'mtu': db.Column(db.Integer),
            'persistent_keepalive': db.Column(db.Integer),
            'preshared_key': db.Column(db.String(256))
        }
    )
    return user_model, info_model


def init_db():
    """Инициализация БД с локальными интерфейсами"""
    global configurations
    with app.app_context():
        # Создаем все таблицы (включая BaseUser)
        db.create_all()
        # Получаем инспектор для проверки существования таблиц
        inspector = db.inspect(db.engine)

        interfaces = get_wg_interfaces()

        # Создаем администратора если нет пользователей
        if BaseUser.query.count() == 0:
            admin = BaseUser(
                email='Adeptus',
                password_hash=generate_password_hash('Mechanicus'),
                role='admin'
            )
            db.session.add(admin)
            db.session.commit()
            app.logger.info("Создан администратор по умолчанию: Adeptus / Mechanicus")

        # Создаем модели для существующих интерфейсов
        for interface in interfaces:
            if interface not in dynamic_user_models:
                user_model, info_model = create_dynamic_models(interface)
                dynamic_user_models[interface] = user_model
                dynamic_info_models[interface] = info_model
                configurations.append(interface)

        # Заполняем информацию о серверах
        for interface in interfaces:
            if interface in dynamic_info_models:  # Проверяем, что модель создана
                info_model = dynamic_info_models[interface]
                # Создаем таблицу, если ее нет
                if not inspector.has_table(info_model.__tablename__):
                    info_model.__table__.create(db.engine)

                # Получаем или создаем запись для интерфейса
                server_info = info_model.query.first()
                if not server_info:
                    server_info = info_model()
                    db.session.add(server_info)

                # Валидация имени интерфейса для безопасности
                if not validate_interface_name(interface):
                    app.logger.warning(f"Skipping invalid interface name in init_db: {interface}")
                    continue
                
                try:
                    output = subprocess.check_output(["sudo", "-n", "wg", "show", interface],
                                                     text=True)
                    config = parse_wg_output(output)

                    server_info.name = interface
                    server_info.listen_port = config['interface'].get('listening port', '')
                    server_info.public_key = config['interface'].get('public key', '')
                    server_info.status = True

                    db.session.add(server_info)

                except subprocess.CalledProcessError as e:
                    app.logger.error(f"Ошибка получения информации о интерфейсе {interface}: {str(e)}")
                    continue

        # Проверка изменений
        try:
            db.session.commit()
        except (IntegrityError, OperationalError) as e:
            db.session.rollback()
            app.logger.error(f"Ошибка при коммите БД: {str(e)}")
            raise


# Шифрование (ленивая инициализация)
_cipher_suite = None

def get_cipher_suite():
    """Получить cipher_suite с ленивой инициализацией"""
    global _cipher_suite
    if _cipher_suite is None:
        # КРИТИЧНО: Загружаем ключ из переменной окружения
        # load_dotenv() уже вызван в начале файла, но может быть нужно перезагрузить
        master_key = os.environ.get('WG_MASTER_KEY')
        
        # Если ключ не найден в переменных окружения, пробуем загрузить из .env напрямую
        if not master_key:
            try:
                env_path = Path(__file__).parent.parent / '.env'
                if env_path.exists():
                    with open(env_path, 'r') as f:
                        for line in f:
                            if line.strip().startswith('WG_MASTER_KEY='):
                                # Извлекаем значение после знака =
                                master_key = line.split('=', 1)[1].strip()
                                # Убираем кавычки если есть
                                master_key = master_key.strip('"').strip("'")
                                break
            except Exception as e:
                app.logger.debug(f"Не удалось загрузить WG_MASTER_KEY из .env: {e}")
        
        # Если ключ не задан, генерируем новый
        if not master_key:
            app.logger.warning("WG_MASTER_KEY не найден в переменных окружения, генерируем новый ключ...")
            master_key = Fernet.generate_key().decode('utf-8')
            # Сохраняем в переменную окружения для текущей сессии
            os.environ['WG_MASTER_KEY'] = master_key
            # Пытаемся сохранить в .env файл
            try:
                env_path = Path(__file__).parent.parent / '.env'
                if env_path.exists():
                    # Читаем существующий .env
                    with open(env_path, 'r') as f:
                        env_content = f.read()
                    
                    # Проверяем, есть ли уже WG_MASTER_KEY
                    if 'WG_MASTER_KEY' not in env_content:
                        # Добавляем ключ в конец файла
                        with open(env_path, 'a') as f:
                            f.write(f"\n# Автоматически сгенерированный ключ шифрования\n")
                            f.write(f"WG_MASTER_KEY={master_key}\n")
                        app.logger.info(f"WG_MASTER_KEY сохранен в {env_path}")
                else:
                    # Создаем новый .env файл
                    with open(env_path, 'w') as f:
                        f.write(f"# Автоматически сгенерированный ключ шифрования\n")
                        f.write(f"WG_MASTER_KEY={master_key}\n")
                    app.logger.info(f"Создан новый .env файл с WG_MASTER_KEY: {env_path}")
            except Exception as e:
                app.logger.warning(f"Не удалось сохранить WG_MASTER_KEY в .env файл: {e}")
                app.logger.warning(f"ВНИМАНИЕ: Используйте этот ключ в .env файле: WG_MASTER_KEY={master_key}")
        
        # Проверяем формат ключа
        try:
            # Пытаемся декодировать ключ из base64
            # КРИТИЧНО: Убираем все лишние символы - пробелы, переносы строк, кавычки
            master_key_clean = master_key.strip().replace('\n', '').replace('\r', '').strip('"').strip("'").strip()
            
            # Проверяем что ключ не пустой
            if not master_key_clean:
                raise ValueError("Ключ пустой после очистки")
            
            app.logger.debug(f"Очищенный ключ (первые 20 символов): {master_key_clean[:20]}...")
            
            # Пытаемся декодировать
            try:
                decoded_key = base64.urlsafe_b64decode(master_key_clean.encode('utf-8'))
            except Exception as decode_err:
                # Если не удалось декодировать, пробуем добавить padding если нужно
                # base64 требует padding (знак =) для правильной длины
                # Длина base64 строки должна быть кратна 4
                padding_needed = (4 - (len(master_key_clean) % 4)) % 4
                if padding_needed > 0:
                    master_key_clean += '=' * padding_needed
                    app.logger.debug(f"Добавлен padding: {padding_needed} символов")
                    decoded_key = base64.urlsafe_b64decode(master_key_clean.encode('utf-8'))
                else:
                    raise decode_err
            
            if len(decoded_key) != 32:
                raise ValueError(f"Ключ должен быть длиной 32 байта, получено {len(decoded_key)} байт")
            
            # Если декодирование успешно, используем очищенный ключ
            master_key = master_key_clean
            app.logger.info(f"✅ WG_MASTER_KEY успешно валидирован (длина декодированного: {len(decoded_key)} байт)")
        except (ValueError, TypeError, Exception) as e:
            # Обрабатываем ошибки декодирования base64 (включая Incorrect padding)
            # base64.urlsafe_b64decode может выбросить ValueError или binascii.Error
            # но binascii.Error является подклассом ValueError в Python
            # Если ключ не в правильном формате (Incorrect padding, неправильная длина и т.д.), генерируем новый
            app.logger.error(f"WG_MASTER_KEY имеет неправильный формат: {e}")
            app.logger.warning("Генерируем новый ключ...")
            master_key = Fernet.generate_key().decode('utf-8')
            os.environ['WG_MASTER_KEY'] = master_key
            # Пытаемся обновить .env файл
            try:
                env_path = Path(__file__).parent.parent / '.env'
                if env_path.exists():
                    # Читаем и обновляем .env
                    with open(env_path, 'r') as f:
                        lines = f.readlines()
                    
                    # Заменяем или добавляем WG_MASTER_KEY
                    updated = False
                    with open(env_path, 'w') as f:
                        for line in lines:
                            if line.startswith('WG_MASTER_KEY='):
                                f.write(f"WG_MASTER_KEY={master_key}\n")
                                updated = True
                            else:
                                f.write(line)
                        if not updated:
                            f.write(f"\n# Автоматически сгенерированный ключ шифрования\n")
                            f.write(f"WG_MASTER_KEY={master_key}\n")
                    app.logger.info(f"WG_MASTER_KEY обновлен в {env_path}")
            except Exception as update_error:
                app.logger.warning(f"Не удалось обновить .env файл: {update_error}")
                app.logger.warning(f"ВНИМАНИЕ: Используйте этот ключ в .env файле: WG_MASTER_KEY={master_key}")
        
        try:
            _cipher_suite = Fernet(master_key.encode('utf-8'))
            app.logger.info("Cipher suite успешно инициализирован")
        except (ValueError, Exception) as e:
            raise RuntimeError(f"Ошибка инициализации шифрования: {str(e)}. Убедитесь, что WG_MASTER_KEY является валидным Fernet ключом (32 байта в base64).")
    
    return _cipher_suite


def get_decrypted_private_key(node):
    """
    Получить расшифрованный private_key узла
    
    Поддерживает обратную совместимость: если ключ не зашифрован, возвращает как есть.
    
    Args:
        node: Объект General (узел)
    
    Returns:
        str: Расшифрованный private_key или None
    """
    if not node or not node.private_key:
        return None
    
    try:
        # Пытаемся расшифровать (если зашифрован)
        cipher = get_cipher_suite()
        decrypted = cipher.decrypt(node.private_key.encode('utf-8')).decode('utf-8')
        return decrypted
    except (ValueError, AttributeError, RuntimeError) as e:
        # Если не удалось расшифровать, возможно ключ не зашифрован (старая запись)
        # Или ключ зашифрован другим мастер-ключом
        app.logger.debug(f"Не удалось расшифровать private_key для {node.name}: {e}. Предполагаем, что ключ не зашифрован.")
        # Возвращаем как есть
        return node.private_key
    except Exception as e:
        # Обрабатываем InvalidToken и другие исключения от cryptography
        from cryptography.fernet import InvalidToken
        if isinstance(e, InvalidToken):
            # Ключ не зашифрован или зашифрован другим ключом
            app.logger.debug(f"InvalidToken при расшифровке private_key для {node.name}. Предполагаем, что ключ не зашифрован.")
            return node.private_key
        else:
            # Другая ошибка - логируем и возвращаем как есть
            app.logger.warning(f"Неожиданная ошибка при расшифровке private_key для {node.name}: {e}. Возвращаем ключ как есть.")
            return node.private_key


def ensure_omnissiah_private_key_encrypted():
    """
    Гарантирует, что private_key у Omnissiah зашифрован Fernet.
    Если ключ еще в открытом виде (старые записи), он шифруется на месте.
    """
    with app.app_context():
        try:
            omnissiah = General.query.filter_by(role='Omnissiah').first()
            if not omnissiah or not omnissiah.private_key:
                return
            
            cipher = get_cipher_suite()
            
            # Если ключ уже зашифрован корректно, decrypt не выбросит InvalidToken
            try:
                cipher.decrypt(omnissiah.private_key.encode('utf-8'))
                return  # уже зашифрован
            except InvalidToken:
                # Ключ в открытом виде — продолжаем
                pass
            except Exception as decrypt_error:
                app.logger.warning(f"Не удалось проверить шифрование private_key Omnissiah: {decrypt_error}")
                return
            
            encrypted_key = cipher.encrypt(omnissiah.private_key.encode('utf-8')).decode('utf-8')
            with db_transaction():
                omnissiah.private_key = encrypted_key
            app.logger.info("Private key Omnissiah зашифрован (обновлена старая запись)")
        except Exception as e:
            app.logger.error(f"Ошибка при шифровании private_key Omnissiah: {e}", exc_info=True)

# Константы
KEEPALIVE = 21
MTU = 1420
INACTIVITY_DAYS = 30

# Планировщик задач

def shutdown_scheduler():
    """Безопасное завершение планировщика"""
    try:
        if scheduler.running:
            scheduler.shutdown()
    except Exception as e:
        # Игнорируем ошибки при shutdown, так как это atexit callback
        pass

atexit.register(shutdown_scheduler)


# Функции get_external_ip, ping_ip, generate_wg_keys теперь импортируются из omnissiah_utils.nmc_wireguard_config_utils


def generate_self_signed_cert(domain, cert_dir=None):
    """Генерирует self-signed SSL сертификат для домена"""
    try:
        # Используем директорию в домашней папке пользователя или в директории приложения
        if cert_dir is None:
            app_dir = Path(__file__).parent.parent
            cert_dir = app_dir / "ssl_certs"
        else:
            cert_dir = Path(cert_dir)
        
        # Создаем директорию для сертификатов (без sudo, в доступной директории)
        cert_dir.mkdir(parents=True, exist_ok=True)
        
        cert_path = cert_dir / f"{domain}.crt"
        key_path = cert_dir / f"{domain}.key"
        
        # Генерируем сертификат (openssl не требует sudo, если файлы создаются в доступной директории)
        subprocess.run([
            "openssl", "req", "-x509", "-nodes", "-days", "365",
            "-newkey", "rsa:2048",
            "-keyout", str(key_path),
            "-out", str(cert_path),
            "-subj", f"/CN={domain}/O=Omnissiah Network/C=RU"
        ], check=True)
        
        # Устанавливаем правильные права доступа
        key_path.chmod(0o600)
        cert_path.chmod(0o644)
        
        return str(cert_path), str(key_path)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Ошибка генерации сертификата: {e.stderr}")
    except (OSError, FileNotFoundError, ValueError) as e:
        raise RuntimeError(f"Ошибка генерации сертификата: {str(e)}")


def setup_letsencrypt_cert(domain, email):
    """Устанавливает Let's Encrypt сертификат через certbot"""
    try:
        # Проверяем наличие certbot
        subprocess.run(["which", "certbot"], check=True, stdout=subprocess.DEVNULL)
        
        # Получаем сертификат (используем sudo -n для безпарольного выполнения)
        subprocess.run([
            "sudo", "-n", "certbot", "certonly", "--standalone",
            "--email", email,
            "--agree-tos", "--no-eff-email",
            "-d", domain,
            "--non-interactive"
        ], check=True)
        
        cert_path = f"/etc/letsencrypt/live/{domain}/fullchain.pem"
        key_path = f"/etc/letsencrypt/live/{domain}/privkey.pem"
        
        return cert_path, key_path
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Ошибка получения Let's Encrypt сертификата: {e.stderr}")
    except FileNotFoundError:
        raise RuntimeError("certbot не установлен. Установите: apt-get install certbot")


def generate_nginx_config(domain, flask_port, https_port=443, cert_path=None, key_path=None, 
                         redirect_http=True, service_name="omnissiah-network", 
                         mtls_ca_cert_path=None, mtls_enabled=False):
    """
    Генерирует конфигурацию nginx для Flask приложения с HTTPS и опциональным mTLS
    mtls_enabled: включить ли mutual TLS (проверку клиентских сертификатов)
    mtls_ca_cert_path: путь к CA сертификату для проверки клиентских сертификатов
    """
    
    http_block = ""
    if redirect_http:
        http_block = f"""server {{
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name {domain} _;
    return 301 https://$server_name$request_uri;
}}
"""
    
    ssl_block = ""
    if cert_path and key_path:
        ssl_block = f"""
    ssl_certificate {cert_path};
    ssl_certificate_key {key_path};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;"""
        
        # Настройка mTLS только для CA (без обязательной проверки на уровне server)
        # Это позволяет использовать mTLS только для конкретных location блоков
        if mtls_enabled and mtls_ca_cert_path:
            ssl_block += f"""
    ssl_client_certificate {mtls_ca_cert_path};
    ssl_verify_client optional;
    ssl_verify_depth 2;"""
    
    # Формируем location для API с обязательным mTLS (если включен)
    # Примечание: ssl_verify_client нельзя использовать в location,
    # поэтому используем optional на уровне server и проверяем $ssl_client_verify
    mtls_location_block = ""
    if mtls_enabled and mtls_ca_cert_path:
        mtls_location_block = f"""
    # API endpoints с обязательным mTLS
    # ssl_verify_client установлен в optional на уровне server,
    # здесь проверяем что клиентский сертификат был предоставлен и валиден
    location /api/magos/ {{
        proxy_pass http://127.0.0.1:{flask_port};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-SSL-Client-Cert $ssl_client_cert;
        proxy_set_header X-SSL-Client-Verify $ssl_client_verify;
        
        # Проверяем наличие и валидность клиентского сертификата
        # $ssl_client_verify может быть: SUCCESS, FAILED, NONE
        if ($ssl_client_verify != "SUCCESS") {{
            return 403 "Client certificate required";
        }}
    }}
"""
    
    config = f"""{http_block}server {{
    listen {https_port} ssl http2 default_server;
    listen [::]:{https_port} ssl http2 default_server;
    server_name {domain} _;
{ssl_block}
    
    # Логи
    access_log /var/log/nginx/{service_name}_access.log;
    error_log /var/log/nginx/{service_name}_error.log;
    
    # Специальный location для setup_wizard и SSH API с увеличенными таймаутами
    # Эти маршруты могут занимать много времени из-за генерации ключей и сертификатов
    location ~ ^/(setup_wizard|api/ssh/) {{
        proxy_pass http://127.0.0.1:{flask_port};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $server_name;
        proxy_connect_timeout 300s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
        proxy_buffering off;
    }}
    
    # API для обновления конфигурации (от Omnissiah к Magos)
    # НЕ требует mTLS, так как Omnissiah не имеет клиентского сертификата для Magos
    # Вместо этого конфигурация шифруется через WG_MASTER_KEY
    # Должен быть ПЕРЕД location /api/magos/ чтобы не попасть под mTLS проверку
    location /api/magos/update_config {{
        proxy_pass http://127.0.0.1:{flask_port};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 120s;
        proxy_send_timeout 120s;
        proxy_read_timeout 120s;
        # Не требуем mTLS для этого endpoint - конфигурация защищена шифрованием
    }}
    
    # API endpoints с обязательным mTLS (должен быть ПЕРЕД location /)
    # Это позволяет mTLS работать только для /api/magos/, а не для всего сайта
{mtls_location_block}
    # Проксирование на Flask (веб-интерфейс с TLS, но БЕЗ mTLS)
    # TLS серверный сертификат используется для шифрования HTTPS
    # Клиентский сертификат НЕ требуется для веб-интерфейса
    location / {{
        proxy_pass http://127.0.0.1:{flask_port};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $server_name;
        
        # Таймауты
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }}
    # Увеличиваем размер загружаемых файлов
    client_max_body_size 10M;
}}
"""
    return config


# Функции get_api_url, get_next_available_ip, get_next_available_ip_list 
# теперь импортируются из omnissiah_utils.nmc_api_utils


# Вместо вызовов "wg" используйте полные пути:
WG_BIN = "/usr/bin/wg"
WG_QUICK_BIN = "/usr/bin/wg-quick"

# get_wg_interfaces теперь импортируется из omnissiah_utils.nmc_wireguard_config_utils


def is_ip_available(ip_address):
    try:
        ip = IPv4Address(ip_address.split('/')[0])
        network = ip_network(ip_address, strict=False)

        # Проверяем по базе данных
        existing = General.query.filter(
            General.ip_pool.startswith(str(ip))
        ).first()

        # Проверяем ping
        return not existing and not ping_ip(str(ip))
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError, ValueError) as e:
        app.logger.debug(f"Ошибка проверки доступности IP {ip}: {e}")
        return False

# доп. маршруты
@app.template_filter('format_datetime')
def format_datetime_filter(value, format='%d.%m.%Y %H:%M:%S'):
    """Форматирует datetime в строку."""
    if not value:
        return 'N/A'
    try:
        return value.strftime(format)
    except AttributeError:
        return 'Некорректная дата'

@app.context_processor
def inject_functions():
    """Добавляет функции и переменные в контекст всех шаблонов"""
    omnissiah_server = None
    try:
        omnissiah_server = General.query.filter_by(role='Omnissiah').first()
    except (AttributeError, RuntimeError) as e:
        app.logger.debug(f"Ошибка получения Omnissiah сервера: {e}")
        pass
    
    return dict(
        get_external_ip=get_external_ip,
        General=General,
        omnissiah_server=omnissiah_server,
        STATUS_CHOICES=STATUS_CHOICES
    )


@app.template_filter('bytes_to_mb')
def bytes_to_mb_filter(bytes_value):
    """Конвертирует байты в мегабайты (с округлением до 2 знаков)."""
    try:
        return round(float(bytes_value) / 1024 / 1024, 2)
    except (TypeError, ValueError):
        return 0.0


@app.template_filter('from_json')
def from_json_filter(value):
    """Парсит JSON строку в Python объект."""
    import json
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return []
    return value if value is not None else []


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500


# Мастер развёртывания WARP
@app.route('/network_deployment_wizard', methods=['GET', 'POST'])
@app.route('/network_deployment_wizard/<int:step>', methods=['GET', 'POST'])
@login_required
@admin_required
@require_omnissiah
def network_deployment_wizard(step=1):
    """
    Мастер развёртывания ZTN сети
    
    Этап 1: Указание узлов (IP, роль, SSH данные)
    Этап 2: Настройка прямых связей для mesh VPN сети
    
    Omnissiah знает о всех узлах и управляет их конфигурациями.
    Все узлы подключаются к Omnissiah, mesh сеть строится автоматически.
    """
    step = request.args.get('step', step, type=int)
    
    # Получаем все узлы из Flask session
    from flask import session as flask_session
    nodes = flask_session.get('deployment_nodes', [])
    
    # Проверяем, есть ли активное развертывание
    deployment_active = flask_session.get('deployment_active', False)
    if deployment_active and step == 1 and request.method == 'GET':
        # Если есть активное развертывание, перенаправляем на страницу прогресса
        flash('Развертывание уже выполняется. Переход на страницу прогресса...', 'info')
        return redirect(url_for('network_deployment_wizard_finalize'))
    
    if step == 1:
        # Этап 1: Указание узлов
        if request.method == 'POST':
            # Проверяем удаление узла
            remove_node_id = request.form.get('remove_node')
            if remove_node_id:
                remove_node_id = int(remove_node_id)
                nodes = [n for n in nodes if n['id'] != remove_node_id]
                flask_session['deployment_nodes'] = nodes
                flash('Узел удален', 'success')
                return redirect(url_for('network_deployment_wizard', step=1))
            
            # Проверяем использование единых аутентификационных данных
            use_unified_auth = request.form.get('use_unified_auth') == 'on'
            
            # Если единые данные и есть уже добавленные узлы, берем данные из первого узла
            if use_unified_auth and nodes:
                first_node = nodes[0]
                ssh_user = first_node.get('ssh_user', request.form.get('ssh_user', '').strip())
                ssh_password = first_node.get('ssh_password', request.form.get('ssh_password', '').strip())
                ssh_key_path = first_node.get('ssh_key_path', request.form.get('ssh_key_path', '').strip())
            else:
                ssh_user = request.form.get('ssh_user', '').strip()
                ssh_password = request.form.get('ssh_password', '').strip()
                ssh_key_path = request.form.get('ssh_key_path', '').strip()
            
            # Добавляем новый узел
            node_data = {
                'name': request.form.get('name', '').strip(),
                'ip': request.form.get('ip', '').strip(),
                'role': request.form.get('role', '').strip(),
                'ssh_user': ssh_user,
                'ssh_password': ssh_password,
                'ssh_key_path': ssh_key_path,
                'id': max([n['id'] for n in nodes], default=0) + 1  # Временный ID
            }
            
            # Валидация
            if not node_data['name']:
                flash('Необходимо указать имя узла', 'error')
            elif not node_data['ip'] or not node_data['role']:
                flash('Необходимо указать IP адрес и роль', 'error')
            elif node_data['role'] not in ['Magos', 'Cognitor']:
                flash('Неверная роль. Должна быть: Magos или Cognitor. Omnissiah уже существует на этом сервере.', 'error')
            elif not node_data['ssh_user']:
                flash('Необходимо указать пользователя SSH', 'error')
            elif not node_data['ssh_password'] and not node_data['ssh_key_path']:
                flash('Необходимо указать пароль SSH или путь к ключу', 'error')
            else:
                # Проверяем уникальность имени
                if any(n.get('name') == node_data['name'] for n in nodes):
                    flash(f'Узел с именем "{node_data["name"]}" уже добавлен', 'error')
                else:
                    nodes.append(node_data)
                    flask_session['deployment_nodes'] = nodes
                    # Сохраняем флаг единых данных
                    flask_session['use_unified_auth'] = use_unified_auth
                    flash(f'Узел {node_data["name"]} ({node_data["ip"]}, {node_data["role"]}) добавлен', 'success')
            
            return redirect(url_for('network_deployment_wizard', step=1))
        
        use_unified_auth = flask_session.get('use_unified_auth', False)
        
        return render_template('network_deployment_wizard.html', 
                             step=1, 
                             nodes=nodes,
                             use_unified_auth=use_unified_auth,
                             total_steps=2)
    
    elif step == 2:
        # Этап 2: Настройка прямых связей для mesh VPN сети
        if not nodes:
            flash('Сначала добавьте узлы на этапе 1', 'warning')
            return redirect(url_for('network_deployment_wizard', step=1))
        
        if request.method == 'POST':
            # Получаем Omnissiah из БД
            omnissiah = General.query.filter_by(role='Omnissiah').first()
            
            if not omnissiah:
                flash('Ошибка: Omnissiah не найден в системе. Убедитесь, что главный узел настроен.', 'error')
                return redirect(url_for('network_deployment_wizard', step=2))
            
            # Получаем выбранные прямые связи для mesh сети
            direct_connections = []
            
            for node in nodes:
                connected_ids = request.form.getlist(f'connections_{node["id"]}')
                for connected_id in connected_ids:
                    if connected_id and connected_id != 'none':
                        # Все узлы автоматически подключаются к Omnissiah (не нужно выбирать)
                        if connected_id == 'omnissiah':
                            # Связь с Omnissiah будет обработана при создании узлов автоматически
                            pass
                        else:
                            # Прямая связь с другим узлом из списка (для mesh)
                            try:
                                other_node_id = int(connected_id)
                                # Создаем пару (меньший ID, больший ID) для избежания дубликатов
                                pair = tuple(sorted([node['id'], other_node_id]))
                                if pair not in direct_connections:
                                    direct_connections.append(pair)
                            except ValueError:
                                pass
            
            flask_session['direct_connections'] = direct_connections
            
            # Сохраняем данные и переходим к финализации
            return redirect(url_for('network_deployment_wizard_finalize'))
        
        direct_connections = flask_session.get('direct_connections', [])
        
        # Получаем Omnissiah из БД для отображения
        omnissiah = General.query.filter_by(role='Omnissiah').first()
        
        return render_template('network_deployment_wizard.html',
                             step=2,
                             nodes=nodes,
                             direct_connections=direct_connections,
                             omnissiah=omnissiah,
                             total_steps=2)
    
    return redirect(url_for('network_deployment_wizard', step=1))


def rollback_deployment_nodes(nodes_to_rollback, nodes_data):
    """
    Откатывает развертывание для списка узлов
    
    Args:
        nodes_to_rollback: Список узлов General для отката
        nodes_data: Список словарей с исходными данными узлов из сессии (для SSH параметров)
    
    Returns:
        tuple: (success: bool, errors: list, log: list)
    """
    from omnissiah_utils.nmc_ssh_utils import connect_ssh_with_key_or_password
    # Импортируем subprocess в начале функции для использования в обработчиках исключений
    import subprocess
    errors = []
    log = []
    
    for node in nodes_to_rollback:
        try:
            # Получаем SSH параметры из исходных данных
            # Сопоставляем по IP или имени узла
            node_data = None
            for nd in nodes_data:
                if (nd.get('ip') == node.ssh_ip or 
                    nd.get('ip') == node.endpoint or
                    (nd.get('name') and nd.get('name') == node.name)):
                    node_data = nd
                    break
            
            if not node_data:
                # Если не найдено по IP, берем из самого узла
                node_data = {
                    'ip': node.ssh_ip or node.endpoint,
                    'ssh_user': node.ssh_user,
                    'ssh_password': node.ssh_password,
                    'ssh_key_path': node.ssh_key_path
                }
                log.append(f"⚠️  {node.name}: используем данные из узла для отката")
            
            ssh_ip = node.ssh_ip or node_data.get('ip')
            ssh_user = node.ssh_user or node_data.get('ssh_user', 'root')
            ssh_password = node_data.get('ssh_password')
            ssh_key_path = node_data.get('ssh_key_path')
            
            # Подключаемся по SSH
            ssh_client = None
            if ssh_ip and (ssh_password or ssh_key_path):
                ssh_client, error = connect_ssh_with_key_or_password(
                    hostname=ssh_ip,
                    username=ssh_user,
                    password=ssh_password,
                    key_file=ssh_key_path,
                    timeout=60
                )
                
                if not ssh_client:
                    errors.append(f"{node.name}: не удалось подключиться по SSH: {error}")
                    log.append(f"⚠️  {node.name}: SSH подключение не удалось, пропускаем удаление ПО")
                else:
                    log.append(f"✅ {node.name}: SSH подключение установлено")
            
            # Откат: удаление ПО и сервисов
            if ssh_client:
                try:
                    wg_interface = node.name
                    
                    # Останавливаем и удаляем сервисы
                    possible_service_names = [
                        f"{node.role.lower()}-{node.name.lower()}",
                        f"nmc-agent-{node.name.lower()}",
                        f"nmc-{node.name.lower()}",
                        "nmc-agent",
                        f"nmcwg-agent-{node.name.lower()}",
                        "nmcwg-agent"
                    ]
                    
                    for svc_name in possible_service_names:
                        try:
                            # Останавливаем сервис
                            stop_cmd = f"sudo -n systemctl stop {svc_name} 2>/dev/null || true"
                            ssh_client.exec_command(stop_cmd, timeout=10)
                            
                            # Отключаем автозапуск
                            disable_cmd = f"sudo -n systemctl disable {svc_name} 2>/dev/null || true"
                            ssh_client.exec_command(disable_cmd, timeout=10)
                            
                            # Удаляем файл сервиса
                            service_file = f"/etc/systemd/system/{svc_name}.service"
                            rm_service_cmd = f"sudo -n rm -f {service_file} 2>/dev/null || true"
                            ssh_client.exec_command(rm_service_cmd, timeout=10)
                            
                            log.append(f"✅ {node.name}: сервис {svc_name} удален")
                        except (OSError, subprocess.SubprocessError, Exception) as e:
                            app.logger.debug(f"Ошибка удаления сервиса {svc_name} на {node.name}: {e}")
                            pass
                    
                    # Перезагружаем systemd
                    ssh_client.exec_command("sudo -n systemctl daemon-reload 2>/dev/null || true", timeout=10)
                    
                    # Удаляем директории с ПО
                    possible_paths = [
                        f"/opt/nmcwg-{node.name.lower()}",
                        "/opt/nmcwg",
                        f"/opt/agents",
                        f"/home/{ssh_user}/agents",
                        f"/opt/nmc-agent-{node.name.lower()}",
                        "/opt/nmc-agent"
                    ]
                    
                    for app_path in possible_paths:
                        try:
                            rm_cmd = f"sudo -n rm -rf {app_path} 2>/dev/null || true"
                            ssh_client.exec_command(rm_cmd, timeout=30)
                            log.append(f"✅ {node.name}: директория {app_path} удалена")
                        except (OSError, subprocess.SubprocessError, Exception) as e:
                            app.logger.debug(f"Ошибка удаления директории {app_path} на {node.name}: {e}")
                            pass
                    
                    # Отключаем VPN и удаляем конфигурацию
                    wg_down_cmd = f"sudo -n wg-quick down {wg_interface} 2>/dev/null || true"
                    ssh_client.exec_command(wg_down_cmd, timeout=10)
                    
                    possible_conf_paths = [
                        f"/etc/wireguard/{wg_interface}.conf",
                        f"/home/{ssh_user}/agents/setup/{wg_interface}.conf",
                        f"/opt/agents/setup/{wg_interface}.conf"
                    ]
                    
                    for conf_path in possible_conf_paths:
                        try:
                            rm_config_cmd = f"sudo -n rm -f {conf_path} 2>/dev/null || true"
                            ssh_client.exec_command(rm_config_cmd, timeout=10)
                        except (OSError, subprocess.SubprocessError, Exception) as e:
                            app.logger.debug(f"Ошибка удаления конфигурации {conf_path}: {e}")
                            pass
                    
                    log.append(f"✅ {node.name}: VPN конфигурация удалена")
                    
                    # Удаляем mTLS сертификаты (если были)
                    if node.mtls_enabled:
                        try:
                            mtls_certs_paths = [
                                f"/opt/agents/mtls_certs",
                                f"/home/{ssh_user}/agents/mtls_certs",
                                f"/opt/nmcwg-{node.name.lower()}/mtls_certs"
                            ]
                            
                            for mtls_path in mtls_certs_paths:
                                rm_mtls_cmd = f"sudo -n rm -rf {mtls_path} 2>/dev/null || true"
                                ssh_client.exec_command(rm_mtls_cmd, timeout=10)
                            
                            log.append(f"✅ {node.name}: mTLS сертификаты удалены")
                        except (OSError, subprocess.SubprocessError, AttributeError) as e:
                            errors.append(f"{node.name}: ошибка удаления mTLS сертификатов: {str(e)}")
                    
                    # Удаляем iptables правила (если были настроены)
                    try:
                        # Очищаем все правила, связанные с этим узлом
                        # Используем комментарии для идентификации правил
                        cleanup_cmd = f"sudo -n iptables-save | grep -i '{node.name}' | grep -o '^-A [^ ]*' | sort -u | while read rule; do sudo -n iptables -D ${{rule#-A }} 2>/dev/null || true; done 2>/dev/null || true"
                        ssh_client.exec_command(cleanup_cmd, timeout=30)
                        log.append(f"✅ {node.name}: iptables правила удалены")
                    except (OSError, subprocess.SubprocessError, AttributeError) as e:
                        errors.append(f"{node.name}: ошибка удаления iptables правил: {str(e)}")
                    
                    ssh_client.close()
                    
                except (OSError, subprocess.SubprocessError, AttributeError, RuntimeError) as e:
                    errors.append(f"{node.name}: ошибка при откате на удаленном узле: {str(e)}")
                    if ssh_client:
                        try:
                            ssh_client.close()
                        except (OSError, AttributeError):
                            pass
            
            # Удаляем узел из WireGuard конфигурации Omnissiah
            try:
                omnissiah = General.query.filter_by(role='Omnissiah').first()
                if omnissiah and node.public_key:
                    try:
                        subprocess.run([
                            "sudo", "-n", "wg", "set", omnissiah.name,
                            "peer", node.public_key, "remove"
                        ], check=False, timeout=10, capture_output=True)
                        
                        subprocess.run([
                            "sudo", "-n", "wg-quick", "save", omnissiah.name
                        ], check=False, timeout=10, capture_output=True)
                        
                        log.append(f"✅ {node.name}: удален из конфигурации Omnissiah")
                    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as e:
                        app.logger.debug(f"Ошибка сохранения конфигурации WireGuard для {node.name}: {e}")
                        pass
            except Exception as e:
                errors.append(f"{node.name}: ошибка удаления из WireGuard: {str(e)}")
            
            # Удаляем связи NodeConnection
            try:
                NodeConnection.query.filter(
                    (NodeConnection.node1_id == node.id) | (NodeConnection.node2_id == node.id)
                ).delete()
                
                # Удаляем дочерние узлы
                General.query.filter_by(parent_id=node.id).update({'parent_id': None})
                
                # Удаляем узел из БД
                db.session.delete(node)
                log.append(f"✅ {node.name}: удален из БД")
            except Exception as e:
                errors.append(f"{node.name}: ошибка удаления из БД: {str(e)}")
                
        except Exception as e:
            errors.append(f"{node.name}: критическая ошибка при откате: {str(e)}")
            app.logger.error(f"Ошибка отката для {node.name}: {str(e)}")
            import traceback
            app.logger.error(traceback.format_exc())
    
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        errors.append(f"Ошибка коммита БД при откате: {str(e)}")
    
    return len(errors) == 0, errors, log


@app.route('/network_deployment_wizard/finalize', methods=['GET', 'POST'])
@login_required
@admin_required
def network_deployment_wizard_finalize():
    """
    Финальный этап: создание и развертывание всех узлов с защитой отката
    
    Если на каком-то узле не удалось развернуть ПО, настроить mTLS, настроить iptables,
    включить VPN, то на остальных узлах из списка установки все удаляется и отключается.
    """
    from flask import session as flask_session
    from omnissiah_utils.nmc_ssh_utils import connect_ssh_with_key_or_password
    from omnissiah_core.nmc_vpn_software_update import send_software_update_via_vpn
    
    nodes = flask_session.get('deployment_nodes', [])
    direct_connections = flask_session.get('direct_connections', [])
    
    if not nodes:
        flash('Нет узлов для создания. Начните с этапа 1.', 'error')
        return redirect(url_for('network_deployment_wizard', step=1))
    
    # Если это GET запрос, показываем страницу с прогресс-баром
    if request.method == 'GET':
        deployment_active = flask_session.get('deployment_active', False)
        return render_template('deployment_progress.html', 
                             nodes_count=len(nodes),
                             nodes=[{'name': n.get('name', n.get('ip', 'Unknown')), 'role': n.get('role', 'Unknown')} for n in nodes],
                             deployment_active=deployment_active)
    
    # POST запрос - запускаем развертывание через SSE
    # Проверяем, не запущено ли уже развертывание
    deployment_active = flask_session.get('deployment_active', False)
    if deployment_active:
        flash('Развертывание уже выполняется. Дождитесь завершения или остановите текущее развертывание.', 'warning')
        return redirect(url_for('network_deployment_wizard_finalize'))
    
    # Перенаправляем на страницу прогресса, которая подключится к SSE эндпоинту
    flask_session['deployment_started'] = True
    app.logger.info(f"📋 POST запрос на finalize: nodes={len(nodes)}, перенаправляем на страницу прогресса")
    # Редирект на ту же страницу (GET), которая покажет прогресс и подключится к SSE
    return redirect(url_for('network_deployment_wizard_finalize'))


# Основные Маршруты
@app.route('/')
def index():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))

    # Проверяем наличие главной конфигурации
    if not General.query.first():
        return redirect(url_for('setup_wizard'))

    return redirect(url_for('dashboard'))

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(BaseUser, int(user_id))


@app.route('/get_available_ips')
@login_required
def get_available_ips():
    omnissiah_config = General.query.filter_by(role='Omnissiah').first()
    if not omnissiah_config:
        return jsonify({'ips': []})

    try:
        network = ip_network(omnissiah_config.ip_pool, strict=False)
        used_ips = [ip.split('/')[0] for ip in
                    [p.ip_pool for p in General.query.filter(General.ip_pool.isnot(None)).all()]]

        available_ips = []
        for host in network.hosts():
            host_ip = str(host)
            if host_ip not in used_ips and (omnissiah_config.ip_pool and host_ip != omnissiah_config.ip_pool.split('/')[0]):
                available_ips.append(f"{host_ip}/{network.prefixlen}")

        return jsonify({'ips': available_ips[:50]})  # Ограничиваем вывод 50 адресами

    except (ValueError, AttributeError, TypeError) as e:
        app.logger.error(f"Ошибка парсинга IP адресов: {str(e)}")
        return jsonify({'ips': []})
    except (ValueError, AttributeError, RuntimeError) as e:
        app.logger.error(f"Ошибка получения IP: {str(e)}", exc_info=True)
        return jsonify({'ips': []})


@app.route('/add_peer', methods=['GET', 'POST'])
@login_required
@admin_required
@require_omnissiah
def add_peer():
    omnissiah_config = General.query.filter_by(role='Omnissiah').first()

    form = AddPeerForm()
    form.parent_id.choices = [(c.id, f"{c.name} ({c.role})")
                                 for c in General.query.filter(General.role.in_(['Omnissiah', 'Magos'])).all()]

    # Получаем список доступных IP
    if not omnissiah_config or not omnissiah_config.ip_pool:
        flash("Главный сервер не настроен или отсутствует IP-пул", "danger")
        return redirect(url_for('dashboard'))
    
    network = ip_network(omnissiah_config.ip_pool, strict=False)
    used_ips = [peer.ip_pool.split('/')[0] for peer in omnissiah_config.children if peer and peer.ip_pool] + [network.network_address]
    available_ips = [f"{host}/{network.prefixlen}"
                    for host in network.hosts()
                    if str(host) not in used_ips]

    if form.validate_on_submit():
        try:
            # Проверяем корректность IP-адреса
            network = ip_network(form.ip_pool.data, strict=False)
            if network.prefixlen < 24:
                flash('Маска сети должна быть /24 или больше', 'danger')
                return redirect(url_for('add_peer'))

            if not is_ip_available(form.ip_pool.data.split('/')[0]):
                flash('Выбранный IP-адрес уже занят', 'danger')
                return redirect(url_for('add_peer'))

            # Генерация ключей
            private_key, public_key = generate_wg_keys()
            preshared_key = subprocess.check_output(["wg", "genpsk"]).strip()

            # Определяем родительский узел
            parent_node = omnissiah_config if form.role.data == 'Magos' else db.session.get(General, form.parent_id.data)

            new_peer = General(
                name=form.name.data,
                ip_pool=form.ip_pool.data,
                listen_port=parent_node.listen_port,
                private_key=private_key,
                public_key=public_key,
                dns=parent_node.dns,
                mtu=parent_node.mtu,
                endpoint=form.endpoint.data if form.role.data == 'Magos' else parent_node.endpoint,
                role=form.role.data,
                preshared_key=preshared_key.decode(),
                parent_id=omnissiah_config.id if form.role.data == 'Magos' else form.parent_id.data,
                #central_node=omnissiah_config.id if form.role.data == 'Magos' else form.central_node.data,
                status='stopped'
            )

            # Для Magos добавляем в конфиг главного сервера
            new_peer_id = None

            if form.role.data == 'Magos':
                result = subprocess.run(
                    [
                        "sudo", "-n", "wg", "set", omnissiah_config.name,
                        "peer", public_key,
                        "allowed-ips", f"{form.ip_pool.data.split('/')[0]}/32",
                        "preshared-key", "/dev/stdin"
                    ],
                    input=preshared_key,
                    stderr=subprocess.PIPE
                )

                if result.returncode != 0:
                    error = result.stderr.decode() if result.stderr else "Неизвестная ошибка"
                    raise subprocess.CalledProcessError(result.returncode, result.args, error)

                subprocess.run(["sudo", "-n", "wg-quick", "save", omnissiah_config.name], check=True)

            with db_transaction():
                db.session.add(new_peer)
                db.session.flush()
                new_peer_id = new_peer.id

            if new_peer.role == 'Cognitor':
                parent_node = db.session.get(General, new_peer.parent_id)
                if parent_node and parent_node.role == 'Magos':
                    try:
                        if not new_peer.sent_to_magos:
                            magos_url = get_api_url(parent_node, endpoint="/api/add_peer", default_port=5001)

                            payload = {
                                "name": new_peer.name,
                                "ip_pool": new_peer.ip_pool,
                                "public_key": new_peer.public_key,
                                "preshared_key": new_peer.preshared_key,
                                "parent_public_key": parent_node.public_key,
                                "dns": new_peer.dns,
                                "mtu": new_peer.mtu
                            }

                            # Для self-signed сертификатов отключаем проверку SSL
                            verify_ssl = parent_node.nginx_cert_type != 'self-signed' if parent_node.nginx_enabled else True
                            response = requests.post(magos_url, json=payload, timeout=10, verify=verify_ssl)

                            if response.status_code == 200:
                                resp_json = response.json()
                                if resp_json.get("status") == "ok":
                                    with db_transaction():
                                        persisted_peer = db.session.get(General, new_peer_id)
                                        if persisted_peer:
                                            persisted_peer.sent_to_magos = True
                                            persisted_peer.ack_from_magos = True
                                    app.logger.info(f"✅ Cognitor {new_peer.name} отправлен и подтверждён от {parent_node.name}")
                                else:
                                    app.logger.warning(f"⚠️ Cognitor отправлен, но не подтверждён: {response.text}")
                                    with db_transaction():
                                        persisted_peer = db.session.get(General, new_peer_id)
                                        if persisted_peer:
                                            persisted_peer.sent_to_magos = True
                                            persisted_peer.ack_from_magos = False
                            else:
                                app.logger.warning(f"⚠️ Ошибка при отправке Cognitor: {response.text}")

                    except Exception as e:
                        app.logger.error(f"❌ Исключение при отправке Cognitor: {str(e)}", exc_info=True)

            flash(f'{"Cognitor" if form.role.data == "Cognitor" else "Magos" if form.role.data == "Magos" else "Omnissiah"} {form.name.data} успешно добавлен!', 'success')
            omnissiah_config = General.query.filter_by(role='Omnissiah').first()
            if omnissiah_config:
                return redirect(url_for('dashboard'))
            else:
                return redirect(url_for('dashboard'))

        except subprocess.CalledProcessError as e:
            db.session.rollback()
            error = e.stderr.decode() if hasattr(e.stderr, 'decode') else str(e)
            flash(f'Ошибка WireGuard: {error}', 'danger')

        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка: {str(e)}', 'danger')

    return render_template('add_peer.html',
                           form=form,
                           omnissiah_config=omnissiah_config,
                           available_ips=available_ips[:50])


# Endpoint /api/nodes теперь в nmc_api/nodes.py
# Для обратной совместимости оставляем старый endpoint, но он теперь использует Blueprint
@app.route('/api/nodes')
@login_required
def get_available_nodes():
    """Старый endpoint для обратной совместимости - использует Blueprint"""
    nodes = General.query.filter(General.role.in_(['Omnissiah', 'Magos'])).all()
    return jsonify([{
        'id': node.id,
        'name': node.name,
        'role': node.role,
        'endpoint': node.endpoint,
        'ip_pool': node.ip_pool
    } for node in nodes])

@app.route('/get_node_info/<int:node_id>')
@login_required
def get_node_info(node_id):
    node = General.query.get_or_404(node_id)
    return jsonify({
        'endpoint': node.endpoint,
        'listen_port': node.listen_port,
        'heartbeat_ip': node.heartbeat_ip
    })

def restore_wg_config_from_db(node):
    """
    Восстанавливает полную конфигурацию WireGuard из БД для узла
    Включает всех активных пиров (Magos для Omnissiah, Cognitors для Magos)
    
    Args:
        node: Узел General для которого восстанавливается конфигурация
    
    Returns:
        str: Полное содержимое WireGuard конфигурации или None при ошибке
    """
    try:
        # Проверяем наличие обязательных полей
        if not node or not node.ip_pool:
            app.logger.warning(f"Отсутствует ip_pool для узла {node.name if node else 'Unknown'}, пропускаем")
            return None
        
        # Базовые параметры интерфейса
        server_ip = node.ip_pool.split('/')[0]
        network = ip_network(node.ip_pool, strict=False)
        
        # Получаем расшифрованный private_key
        decrypted_private_key = get_decrypted_private_key(node)
        if not decrypted_private_key:
            app.logger.warning(f"Не удалось получить private_key для {node.name}, пропускаем")
            return None
        
        # КРИТИЧНО: Формируем конфигурацию в правильном порядке
        # Address ДОЛЖЕН быть после PrivateKey и перед ListenPort/MTU
        # КРИТИЧНО: В Address должен быть КОНКРЕТНЫЙ IP адрес, а не адрес сети!
        # Если ip_pool это адрес сети (например, 11.11.11.0/24), берем первый хост
        network_address = str(network.network_address)
        ip_pool_base = node.ip_pool.split('/')[0]
        
        if ip_pool_base == network_address:
            # Это адрес сети, берем первый хост
            if network.num_addresses > 2:
                first_host = list(network.hosts())[0]
                address_ip = str(first_host)
            else:
                address_ip = str(network.network_address + 1)
        else:
            # Это уже конкретный IP адрес
            address_ip = ip_pool_base
        
        config_content = f"""[Interface]
PrivateKey = {decrypted_private_key}
Address = {address_ip}/{network.prefixlen}"""
        
        # Добавляем ListenPort и MTU после Address
        if node.listen_port:
            config_content += f"\nListenPort = {node.listen_port}"
        
        if node.mtu:
            config_content += f"\nMTU = {node.mtu}"
        
        # Добавляем пустую строку перед [Peer] секциями
        config_content += "\n"
        
        # Для Omnissiah добавляем всех активных Magos как пиров
        if node.role == 'Omnissiah':
            magos_nodes = General.query.filter(
                General.role == 'Magos',
                General.status.in_(['active', 'online'])
            ).all()
            
            app.logger.info(f"🔍 Восстановление конфигурации для {node.name}: найдено {len(magos_nodes)} активных Magos узлов")
            
            for magos in magos_nodes:
                # Проверяем что public_key не пустой (может быть пустая строка "")
                if not magos or not magos.public_key or not magos.public_key.strip() or not magos.ip_pool:
                    app.logger.warning(f"⚠️ Пропускаем Magos {magos.name if magos else 'Unknown'}: public_key={bool(magos.public_key if magos else None)}, ip_pool={bool(magos.ip_pool if magos else None)}")
                    continue
                
                # КРИТИЧНО: На сервере (Omnissiah) НЕ должно быть endpoint для пиров!
                # Endpoint указывается только в конфигурации клиента (Magos), который подключается к серверу
                # Сервер пассивно слушает, клиенты инициируют подключение
                
                magos_ip = magos.ip_pool.split('/')[0]
                
                # Формируем allowed-ips (VPN IP + защищенные подсети)
                allowed_ips_list = [f"{magos_ip}/32"]
                
                # Добавляем защищенные подсети для этого Magos
                protected_objects = ProtectedObject.query.filter_by(
                    node_id=magos.id,
                    is_active=True
                ).all()
                
                for protected_obj in protected_objects:
                    try:
                        protected_net = ip_network(protected_obj.network, strict=False)
                        vpn_net = ip_network(magos.ip_pool, strict=False)
                        if not (protected_net == vpn_net or protected_net.subnet_of(vpn_net) or vpn_net.subnet_of(protected_net)):
                            allowed_ips_list.append(protected_obj.network)
                    except (ValueError, AttributeError) as e:
                        # Игнорируем ошибки парсинга сетей
                        app.logger.debug(f"Ошибка обработки защищенной подсети {protected_obj.network}: {e}")
                        pass
                
                allowed_ips_str = ",".join(allowed_ips_list)
                
                config_content += f"\n\n[Peer]"
                config_content += f"\nPublicKey = {magos.public_key}"
                config_content += f"\nAllowedIPs = {allowed_ips_str}"
                # КРИТИЧНО: На сервере (Omnissiah) НЕ должно быть endpoint для пиров!
                # Endpoint указывается только в конфигурации клиента (Magos), который подключается к серверу
                # Сервер пассивно слушает, клиенты инициируют подключение
                config_content += f"\nPersistentKeepalive = 25"
                
                app.logger.info(f"✅ Добавлен peer для {node.name} -> {magos.name}: AllowedIPs={allowed_ips_str} (без endpoint, т.к. Omnissiah - сервер)")
                
                if magos.preshared_key:
                    config_content += f"\nPresharedKey = {magos.preshared_key}"
        
        # Для Magos добавляем дочерние Cognitors
        elif node.role == 'Magos':
            cognitors = General.query.filter_by(parent_id=node.id).all()
            for cognitor in cognitors:
                if not cognitor or not cognitor.public_key or not cognitor.ip_pool:
                    continue
                
                cognitor_ip = cognitor.ip_pool.split('/')[0] + '/32'
                config_content += f"\n\n[Peer]"
                config_content += f"\nPublicKey = {cognitor.public_key}"
                config_content += f"\nAllowedIPs = {cognitor_ip}"
                config_content += f"\nPersistentKeepalive = 25"
                
                if cognitor.preshared_key:
                    config_content += f"\nPresharedKey = {cognitor.preshared_key}"
        
        return config_content
    
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError, AttributeError) as e:
        app.logger.error(f"Ошибка восстановления конфигурации WireGuard для {node.name}: {str(e)}")
        import traceback
        app.logger.error(traceback.format_exc())
        return None


def get_real_external_ip(node):
    """
    Определяет реальный внешний IP адрес узла, исключая VPN IP.
    
    Args:
        node: Узел General
    
    Returns:
        str: Реальный внешний IP или None
    """
    # Сначала проверяем endpoint из БД (если он указан, он должен быть реальным IP)
    if node.endpoint:
        endpoint_ip = node.endpoint.split(':')[0] if ':' in node.endpoint else node.endpoint
        # Проверяем что это не VPN IP
        if node.ip_pool:
            try:
                vpn_network = ip_network(node.ip_pool, strict=False)
                ip_addr = IPv4Address(endpoint_ip)
                if ip_addr not in vpn_network:
                    app.logger.debug(f"Найден внешний IP для {node.name} из endpoint: {endpoint_ip} (не VPN IP)")
                    return endpoint_ip
                else:
                    app.logger.warning(f"endpoint для {node.name} является VPN IP: {endpoint_ip}, пропускаем")
            except (ValueError, AttributeError) as e:
                app.logger.debug(f"Ошибка проверки endpoint для {node.name}: {e}")
                pass
        else:
            # Если нет ip_pool, используем endpoint как есть
            app.logger.debug(f"Используем endpoint как внешний IP для {node.name}: {endpoint_ip} (нет ip_pool)")
            return endpoint_ip
    
    # КРИТИЧНО: Используем ssh_ip если он есть (это реальный IP для подключения)
    if hasattr(node, 'ssh_ip') and node.ssh_ip:
        ssh_ip = node.ssh_ip.split(':')[0] if ':' in node.ssh_ip else node.ssh_ip
        # Проверяем что это не VPN IP
        if node.ip_pool:
            try:
                vpn_network = ip_network(node.ip_pool, strict=False)
                ip_addr = IPv4Address(ssh_ip)
                if ip_addr not in vpn_network:
                    app.logger.info(f"Найден внешний IP для {node.name} из ssh_ip: {ssh_ip}")
                    return ssh_ip
            except (ValueError, AttributeError):
                pass
        else:
            # Если нет ip_pool, используем ssh_ip как есть
            app.logger.info(f"Используем ssh_ip как внешний IP для {node.name}: {ssh_ip}")
            return ssh_ip
    
    # Пытаемся найти внешний IP из heartbeat_interfaces
    if node.heartbeat_interfaces:
        try:
            interfaces = json.loads(node.heartbeat_interfaces)
            for iface in interfaces:
                if 'ip' in iface:
                    ip = iface['ip'].split('/')[0]
                    # Проверяем что это не VPN IP
                    if node.ip_pool:
                        try:
                            vpn_network = ip_network(node.ip_pool, strict=False)
                            ip_addr = IPv4Address(ip)
                            if ip_addr not in vpn_network:
                                app.logger.info(f"Найден внешний IP для {node.name} из heartbeat_interfaces: {ip}")
                                return ip
                        except (ValueError, AttributeError):
                            pass
        except Exception as e:
            app.logger.warning(f"Ошибка парсинга heartbeat_interfaces для {node.name}: {e}")
    
    # Используем heartbeat_ip как fallback (но проверяем что это не VPN IP)
    if node.heartbeat_ip:
        if node.ip_pool:
            try:
                vpn_network = ip_network(node.ip_pool, strict=False)
                ip_addr = IPv4Address(node.heartbeat_ip)
                if ip_addr not in vpn_network:
                    app.logger.warning(f"Используем heartbeat_ip как внешний IP для {node.name}: {node.heartbeat_ip}")
                    return node.heartbeat_ip
                else:
                    app.logger.warning(f"heartbeat_ip для {node.name} является VPN IP: {node.heartbeat_ip}, пропускаем")
            except (ValueError, AttributeError):
                pass
    
    return None


def generate_wg_config_with_connections(node, include_additional_peers=True):
    """
    Генерирует полную WireGuard конфигурацию для узла, включая прямые связи
    
    Args:
        node: Узел General для которого генерируется конфигурация
        include_additional_peers: Включать ли дополнительные peers из NodeConnection
    
    Returns:
        str: Содержимое WireGuard конфигурации
    """
    # Определяем родителя
    if node.role == 'Cognitor':
        parent = node.parent
    elif node.role == 'Magos':
        parent = General.query.filter_by(role='Omnissiah').first()
    else:  # Omnissiah
        parent = None
    
    # Получаем расшифрованный private_key
    decrypted_private_key = get_decrypted_private_key(node)
    if not decrypted_private_key:
        app.logger.warning(f"Не удалось получить private_key для {node.name}")
        return None
    
    # Начало конфигурации
    # КРИТИЧНО: В Address должен быть КОНКРЕТНЫЙ IP адрес, а не весь пул!
    # Для Omnissiah и Magos ip_pool может быть целой подсетью (например, 11.11.11.0/24)
    # В этом случае нужно использовать конкретный IP адрес из этой подсети
    if '/' in node.ip_pool:
        try:
            network = ip_network(node.ip_pool, strict=False)
            # Проверяем, является ли ip_pool целой подсетью (адрес сети)
            network_address = str(network.network_address)
            ip_pool_base = node.ip_pool.split('/')[0]
            
            # Если ip_pool это адрес сети (например, 11.11.11.0/24), берем первый хост
            if ip_pool_base == network_address:
                # Это подсеть, берем первый хост
                if network.num_addresses > 2:
                    # Берем первый хост из сети
                    first_host = list(network.hosts())[0]
                    ip_pool_formatted = f"{first_host}/{network.prefixlen}"
                else:
                    # Слишком маленькая сеть, используем адрес сети + 1
                    ip_pool_formatted = f"{network.network_address + 1}/{network.prefixlen}"
            else:
                # Это уже конкретный IP адрес, используем как есть
                ip_pool_formatted = node.ip_pool
        except Exception as e:
            app.logger.warning(f"Ошибка обработки ip_pool для {node.name} ({node.role}): {e}, используем как есть")
            ip_pool_formatted = node.ip_pool
    else:
        # Если нет префикса, добавляем /32
        ip_pool_formatted = f"{node.ip_pool}/32"
    
    config_content = f"""[Interface]
PrivateKey = {decrypted_private_key}
Address = {ip_pool_formatted}
"""
    
    if parent:
        config_content += f"DNS = {parent.dns}\n"
        config_content += f"MTU = {parent.mtu}\n"
    
    # Добавляем ListenPort для Magos и Omnissiah
    if node.role in ['Magos', 'Omnissiah'] and node.listen_port:
        config_content += f"ListenPort = {node.listen_port}\n"
    
    # Добавляем peer к родителю (Omnissiah для Magos, Magos для Cognitor)
    if parent:
        # КРИТИЧНО: Для Magos endpoint должен быть внешним IP Omnissiah, а не VPN IP
        endpoint = get_real_external_ip(parent)
        
        listen_port = parent.listen_port if parent.listen_port else None
        
        # КРИТИЧНО: Для Magos AllowedIPs должен быть 0.0.0.0/0
        # Это означает что весь трафик будет маршрутизироваться через VPN к Omnissiah
        # Для Cognitor AllowedIPs должен быть VPN IP родителя (Magos)
        if node.role == 'Magos':
            allowed_ips = "0.0.0.0/0"
        else:
            # Для Cognitor используем VPN IP родителя
            allowed_ips = parent.ip_pool.split('/')[0] + '/32'
        
        config_content += f"""
[Peer]
PublicKey = {parent.public_key}
AllowedIPs = {allowed_ips}"""
        
        if endpoint and listen_port:
            # Убираем порт из endpoint если он там есть (добавим правильный)
            endpoint_ip = endpoint.split(':')[0] if ':' in endpoint else endpoint
            config_content += f"\nEndpoint = {endpoint_ip}:{listen_port}"
            app.logger.info(f"Настроен peer для {node.name} -> {parent.name}: endpoint={endpoint_ip}:{listen_port}, AllowedIPs={allowed_ips}")
        elif endpoint:
            # Если нет listen_port, но есть endpoint, используем endpoint как есть
            config_content += f"\nEndpoint = {endpoint}"
            app.logger.warning(f"Настроен peer для {node.name} -> {parent.name} без порта: endpoint={endpoint}, AllowedIPs={allowed_ips}")
        else:
            app.logger.warning(f"Не удалось определить endpoint для {parent.name}, peer будет без endpoint")
        
        config_content += "\nPersistentKeepalive = 25"
        
        if parent.preshared_key:
            config_content += f"\nPresharedKey = {parent.preshared_key}"
    
    # Добавляем дочерние узлы (для Magos - Cognitor'ы, для Omnissiah - Magos и прямые Cognitor'ы)
    if node.role == 'Magos':
        cognitors = General.query.filter_by(parent_id=node.id).all()
        for cognitor in cognitors:
            if not cognitor or not cognitor.public_key or not cognitor.ip_pool:
                continue
            
            allowed_ip = cognitor.ip_pool.split('/')[0] + '/32'
            config_content += f"""
            
[Peer]
PublicKey = {cognitor.public_key}
AllowedIPs = {allowed_ip}
PersistentKeepalive = 25"""
            if cognitor.preshared_key:
                config_content += f"\nPresharedKey = {cognitor.preshared_key}"
    
    elif node.role == 'Omnissiah':
        # Добавляем Magos
        magi = General.query.filter_by(role='Magos').all()
        for magos in magi:
            # Проверяем что public_key не пустой (может быть пустая строка "")
            if not magos.public_key or not magos.public_key.strip() or not magos.ip_pool:
                continue
            
            allowed_ip = magos.ip_pool.split('/')[0] + '/32'
            # КРИТИЧНО: Endpoint должен быть реальным внешним IP Magos, а не VPN IP
            endpoint = get_real_external_ip(magos)
            listen_port = magos.listen_port if magos.listen_port else None
            
            config_content += f"""
            
[Peer]
PublicKey = {magos.public_key}
AllowedIPs = {allowed_ip}"""
            
            if endpoint and listen_port:
                endpoint_ip = endpoint.split(':')[0] if ':' in endpoint else endpoint
                config_content += f"\nEndpoint = {endpoint_ip}:{listen_port}"
                app.logger.info(f"Настроен peer для {node.name} -> {magos.name}: endpoint={endpoint_ip}:{listen_port}, AllowedIPs={allowed_ip}")
            elif endpoint:
                config_content += f"\nEndpoint = {endpoint}"
                app.logger.warning(f"Настроен peer для {node.name} -> {magos.name} без порта: endpoint={endpoint}, AllowedIPs={allowed_ip}")
            else:
                app.logger.warning(f"Не удалось определить endpoint для {magos.name}, peer будет без endpoint")
            
            config_content += "\nPersistentKeepalive = 25"
            
            if magos.preshared_key:
                config_content += f"\nPresharedKey = {magos.preshared_key}"
        
        # Добавляем прямые Cognitor'ы (без родителя Magos)
        direct_cognitors = General.query.filter(
            General.role == 'Cognitor',
            General.parent_id == node.id
        ).all()
        for cognitor in direct_cognitors:
            if not cognitor.public_key or not cognitor.ip_pool:
                continue
            
            allowed_ip = cognitor.ip_pool.split('/')[0] + '/32'
            config_content += f"""
            
[Peer]
PublicKey = {cognitor.public_key}
AllowedIPs = {allowed_ip}
PersistentKeepalive = 25"""
            if cognitor.preshared_key:
                config_content += f"\nPresharedKey = {cognitor.preshared_key}"
    
    # Добавляем прямые связи (NodeConnection) если включено
    if include_additional_peers:
        connected_nodes = node.get_connected_nodes()
        for connected_node in connected_nodes:
            # Проверяем, может ли узел взаимодействовать напрямую
            can_direct, reason = can_nodes_communicate_directly(node, connected_node)
            
            if can_direct and 'прямая связь' in reason.lower():
                # Пропускаем если это уже родитель или дочерний узел
                if parent and connected_node.id == parent.id:
                    continue
                if node.role == 'Magos' and connected_node.role == 'Cognitor' and connected_node.parent_id == node.id:
                    continue
                if node.role == 'Omnissiah' and connected_node.role in ['Magos', 'Cognitor']:
                    # Проверяем, не является ли это дочерним узлом
                    if connected_node.parent_id == node.id:
                        continue
                
                if not connected_node.public_key or not connected_node.ip_pool:
                    continue
                
                allowed_ip = connected_node.ip_pool.split('/')[0] + '/32'
                # КРИТИЧНО: Endpoint должен быть реальным внешним IP, а не VPN IP
                endpoint = get_real_external_ip(connected_node)
                listen_port = connected_node.listen_port if connected_node.listen_port and connected_node.role in ['Magos', 'Omnissiah'] else None
                
                config_content += f"""
                
[Peer]
PublicKey = {connected_node.public_key}
AllowedIPs = {allowed_ip}"""
                
                if endpoint and listen_port:
                    endpoint_ip = endpoint.split(':')[0] if ':' in endpoint else endpoint
                    config_content += f"\nEndpoint = {endpoint_ip}:{listen_port}"
                    app.logger.info(f"Настроен peer для {node.name} -> {connected_node.name}: endpoint={endpoint_ip}:{listen_port}, AllowedIPs={allowed_ip}")
                elif endpoint:
                    config_content += f"\nEndpoint = {endpoint}"
                    app.logger.warning(f"Настроен peer для {node.name} -> {connected_node.name} без порта: endpoint={endpoint}, AllowedIPs={allowed_ip}")
                
                config_content += "\nPersistentKeepalive = 25"
                
                if connected_node.preshared_key:
                    config_content += f"\nPresharedKey = {connected_node.preshared_key}"
    
    return config_content


def encrypt_wg_config(config_content):
    """
    Шифрует WireGuard конфигурацию для безопасной передачи
    
    Args:
        config_content: Содержимое конфигурации (строка)
    
    Returns:
        bytes: Зашифрованные данные
    """
    cipher = get_cipher_suite()
    encrypted = cipher.encrypt(config_content.encode('utf-8'))
    return encrypted

def _vpn_v2_send(node, action, plan=None):
    """Use Omnissiah's node certificate and CA for managed mTLS."""
    from urllib.parse import urlsplit
    controller = General.query.filter_by(role='Omnissiah').first()
    if not controller or not node or node.role != "Magos":
        raise ValueError("Magos and controller are required")
    import ipaddress
    host = str(ipaddress.IPv4Address(node.endpoint))
    # Management nginx port is configured identically on controller and agents.
    port = int(controller.nginx_https_port)
    cert = "/var/lib/omnissiah-network/pki/identity.crt"
    key = "/var/lib/omnissiah-network/pki/identity.key"
    ca = "/var/lib/omnissiah-network/pki/ca.crt"
    if not all(Path(p).is_file() for p in (cert, key, ca)):
        raise ValueError("Omnissiah management identity not installed")
    payload = {"action": action}
    if plan is not None:
        payload["plan"] = plan
    response = requests.post(
        f"https://{host}:{port}/api/v2/vpn/control",
        cert=(cert, key), verify=ca, json=payload, timeout=65)
    response.raise_for_status()
    reply = response.json()
    if not reply.get("success"):
        raise ValueError("Magos reported a failed operation")
    return reply["result"]


@app.route('/api/v2/vpn/mesh/operation', methods=['POST'])
@login_required
@admin_required
@require_omnissiah
def vpn_mesh_operation():
    """Explicit VPN operation. Never triggered from 'save connections'."""
    from vpn_topology import project_magos_mesh
    from vpn_plan import VPNPlanError
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or set(body) != {"node_id", "action"}:
        return jsonify(error="Expected node_id and action"), 400
    action = body["action"]
    if action not in ("identity", "status", "prepare", "start", "apply", "route-transaction"):
        return jsonify(error="Unsupported operation"), 400
    if type(body["node_id"]) is not int:
        return jsonify(error="Invalid node ID"), 400
    node = db.session.get(General, body["node_id"])
    if not node or node.role != "Magos":
        return jsonify(error="Magos not found"), 404
    if action in ("start", "apply", "route-transaction") and request.headers.get("X-VPN-Explicit-Apply") != "ENABLE_TEST_MESH":
        return jsonify(error="Explicit lab activation acknowledgement required"), 409
    try:
        plan = None
        if action in ("prepare", "apply", "route-transaction"):
            projected = project_magos_mesh(General.query.filter_by(role="Magos").all(),
                                            NodeConnection.query.all())
            selected = next(p for p in projected if p["node_id"] == node.id)
            # Agent expects the exact strict schema, excluding UI-only peer names.
            plan = {"node_name": selected["node_name"], "address": selected["address"],
                    "listen_port": selected["listen_port"],
                    "peers": [{k: peer[k] for k in ("public_key", "endpoint", "allowed_ips", "keepalive")}
                              for peer in selected["peers"]]}
            if not plan["peers"]:
                return jsonify(error="No explicit Magos links configured"), 409
        if action == "apply":
            # Recheck eligibility immediately before the privileged write.
            from vpn_change_preview import preview as preview_change
            from vpn_reconcile import compare
            observed_before = _vpn_v2_send(node, "status")
            decision = preview_change(plan["peers"], observed_before.get("peers"),
                                      active=observed_before.get("active") is True)
            if decision["decision"] != "eligible":
                return jsonify(error="Apply refused by live preflight", preflight=decision), 409
        if action == "route-transaction":
            # Explicitly disabled until lab rollout and crash-recovery review.
            if not app.config.get("VPN_ROUTE_TRANSACTIONS_ENABLED", False):
                return jsonify(error="Route transactions not enabled on controller"), 403
        result = _vpn_v2_send(node, action, plan)
        if action == "apply":
            from vpn_reconcile import compare
            observed_after = _vpn_v2_send(node, "status")
            verification = compare(plan["peers"], observed_after.get("peers"))
            if verification["state"] != "in_sync":
                app.logger.error("VPN apply verification mismatch for %s", node.name)
                return jsonify(error="Apply returned but postflight is not in sync; manual investigation required",
                               verification=verification["state"]), 502
        if action == "identity":
            new_key = result.get("public_key")
            if not isinstance(new_key, str):
                raise ValueError("Invalid Magos public identity")
            import base64, binascii
            try:
                if len(base64.b64decode(new_key, validate=True)) != 32:
                    raise ValueError("Invalid public key length")
            except (binascii.Error, ValueError) as exc:
                raise ValueError("Invalid public key") from exc
            if node.public_key and node.public_key != new_key:
                return jsonify(error="Key differs from registered identity; explicit rotation required"), 409
            node.public_key = new_key
            db.session.commit()
        return jsonify(success=True, action=action, node=node.name, result=result), 200
    except (ValueError, VPNPlanError, StopIteration) as exc:
        db.session.rollback()
        return jsonify(error=str(exc)), 409
    except (requests.RequestException, OSError, KeyError) as exc:
        db.session.rollback()
        app.logger.error("VPN v2 %s failed for %s: %s", action, node.name, exc)
        return jsonify(error="VPN control call failed; check service and TLS logs"), 502


@app.route('/api/v2/vpn/mesh/change-preview', methods=['GET'])
@login_required
@admin_required
@require_omnissiah
def vpn_mesh_change_preview():
    """Dry run only. No key disclosure, persistence or WireGuard writes."""
    from vpn_topology import project_magos_mesh
    from vpn_plan import VPNPlanError
    from vpn_change_preview import preview
    nodes = General.query.filter_by(role='Magos').all()
    by_id = {node.id: node for node in nodes}
    try:
        plans = project_magos_mesh(nodes, NodeConnection.query.all())
    except VPNPlanError as exc:
        return jsonify(error=str(exc)), 409
    results = []
    for plan in plans:
        try:
            observation = _vpn_v2_send(by_id[plan["node_id"]], "status")
            result = preview(plan["peers"], observation.get("peers"),
                             active=observation.get("active") is True)
            if result.get("reason") == "route_change_requires_transaction":
                # A separate root-owned dry run checks the actual kernel
                # routing table; no route changes are authorized here.
                strict_plan = {
                    "node_name": plan["node_name"],
                    "address": plan["address"],
                    "listen_port": plan["listen_port"],
                    "peers": [
                        {key: peer[key] for key in
                         ("public_key", "endpoint", "allowed_ips", "keepalive")}
                        for peer in plan["peers"]
                    ],
                }
                try:
                    routes = _vpn_v2_send(by_id[plan["node_id"]], "route-preview", strict_plan)
                    result["route_delta"] = routes.get("route_delta", {})
                    result["reason"] = "route_changes_validated_but_not_applied"
                except (ValueError, requests.RequestException, OSError, RuntimeError) as exc:
                    app.logger.warning("VPN route preflight rejected %s: %s",
                                       plan["node_name"], exc)
                    result["reason"] = "route_preflight_rejected"
        except (ValueError, requests.RequestException, OSError, KeyError, RuntimeError) as exc:
            app.logger.warning("VPN dry-run observation failed for %s: %s",
                               plan["node_name"], exc)
            result = {"decision": "blocked", "reason": "management_query_failed",
                      "add": 0, "remove": 0, "update": 0}
        results.append({"node_id": plan["node_id"],
                        "node_name": plan["node_name"], **result})
    # This endpoint is NOT a commit authorization. It returns no sensitive keys.
    return jsonify(results=results, writes_performed=False)


@app.route('/api/v2/vpn/mesh/reconcile', methods=['GET'])
@login_required
@admin_required
@require_omnissiah
def reconcile_vpn_mesh():
    """Observe each Magos directly over mTLS; no mutating operations."""
    from vpn_topology import project_magos_mesh
    from vpn_plan import VPNPlanError
    from vpn_reconcile import compare
    nodes = General.query.filter_by(role='Magos').all()
    by_id = {n.id: n for n in nodes}
    try:
        plans = project_magos_mesh(nodes, NodeConnection.query.all())
    except VPNPlanError as exc:
        return jsonify(error=str(exc), ready=False), 409

    def poll(plan):
        node = by_id[plan["node_id"]]
        try:
            result = _vpn_v2_send(node, "status")
            return plan["node_id"], result, None
        except (ValueError, requests.RequestException, OSError, KeyError, RuntimeError) as exc:
            app.logger.warning("VPN status poll failed for %s: %s", node.name, exc)
            return plan["node_id"], None, "management_query_failed"

    # _vpn_v2_send reads the controller SQLAlchemy model: perform calls inside
    # the request application context, not in contextless worker threads.
    observed = {node_id: (status, error)
                for node_id, status, error in map(poll, plans)}
    records = []
    for plan in plans:
        state, error = observed[plan["node_id"]]
        expected = plan["peers"]
        if error:
            diff = {"state": "unknown", "reason": error}
        elif not state.get("active"):
            diff = {"state": "drift", "reason": "interface_inactive"}
        else:
            diff = compare(expected, state.get("peers"))
        # Intentionally avoid copying keys to the summary response.
        records.append({
            "node_id": plan["node_id"], "node_name": plan["node_name"],
            "desired_peers": len(expected),
            "observed_peers": len(state["peers"]) if state and state.get("peers") is not None else None,
            "interface_active": bool(state.get("active")) if state else None,
            "state": diff["state"],
            "reason": diff.get("reason"),
            "missing_peers": len(diff.get("missing_peer_keys", [])),
            "unexpected_peers": len(diff.get("unexpected_peer_keys", [])),
            "different_peers": len(diff.get("different_peers", [])),
        })
    return jsonify(results=records, applied=False, queried_at=datetime.now(timezone.utc).isoformat())


@app.route('/api/v2/vpn/mesh/preview', methods=['GET'])
@login_required
@admin_required
@require_omnissiah
def preview_vpn_mesh():
    """Read-only, authenticated plan; does not activate any VPN interface."""
    from vpn_topology import project_magos_mesh
    from vpn_plan import VPNPlanError
    magos_nodes = General.query.filter_by(role='Magos').all()
    edges = NodeConnection.query.all()
    try:
        plans = project_magos_mesh(magos_nodes, edges)
    except VPNPlanError as exc:
        return jsonify({'ready': False, 'error': str(exc)}), 409
    return jsonify({'ready': True, 'plans': plans, 'applied': False}), 200


@app.route('/vpn/overview')
@login_required
@require_omnissiah
def vpn_overview():
    """Dashboard for observed Magos VPN and explicitly desired topology."""
    from management_status import peer_status
    magi = General.query.filter_by(role='Magos').order_by(General.name).all()
    by_id = {n.id: n for n in magi}
    observations = [dict(node=n, status=peer_status(n)) for n in magi]
    links = []
    for edge in NodeConnection.query.all():
        left, right = by_id.get(edge.node1_id), by_id.get(edge.node2_id)
        if left is not None and right is not None:
            links.append(dict(left=left.name, right=right.name))
    return render_template('vpn_overview.html', nodes=observations, links=links)


@app.route('/manage_connections/<int:node_id>', methods=['GET', 'POST'])
@login_required
@admin_required
@require_omnissiah
def manage_connections(node_id):
    """Save explicit desired Magos mesh edges; never apply VPN implicitly."""
    node = db.session.get(General, node_id)
    if not node or node.role != 'Magos':
        abort(404)
    available_nodes = General.query.filter(
        General.role == "Magos", General.id != node_id).order_by(General.name).all()
    connected_ids = {
        conn.node2_id if conn.node1_id == node.id else conn.node1_id
        for conn in node.connections_as_node1 + node.connections_as_node2
    }
    if request.method == 'POST':
        from vpn_topology import project_magos_mesh
        from vpn_plan import VPNPlanError
        selected = request.form.getlist('connections')
        try:
            selected_ids = {int(n) for n in selected}
        except ValueError:
            abort(400)
        valid_ids = {n.id for n in available_nodes}
        if not selected_ids.issubset(valid_ids):
            abort(400)
        desired_ids = {(min(node.id, peer_id), max(node.id, peer_id)) for peer_id in selected_ids}
        connections = NodeConnection.query.all()
        untouched = [c for c in connections if node.id not in (c.node1_id, c.node2_id)]
        proposed = untouched + [
            NodeConnection(node1_id=a, node2_id=b) for a, b in desired_ids]
        try:
            # Validate address/route topology before changing the database.
            # Missing peer keys are allowed while staging the topology:
            # those are acquired through explicit v2 identity operations.
            from types import SimpleNamespace
            nodes = General.query.filter_by(role="Magos").all()
            projected_nodes = [SimpleNamespace(
                id=n.id, name=n.name, role=n.role, ip_pool=n.ip_pool,
                endpoint=n.endpoint, listen_port=n.listen_port,
                public_key=n.public_key or ('A' * 43 + '=')
            ) for n in nodes]
            project_magos_mesh(projected_nodes, proposed)
            NodeConnection.query.filter(
                (NodeConnection.node1_id == node_id) |
                (NodeConnection.node2_id == node_id)
            ).delete(synchronize_session=False)
            for a, b in desired_ids:
                db.session.add(NodeConnection(node1_id=a, node2_id=b,
                                             description=f"Magos {a} ↔ Magos {b}"))
            db.session.commit()
            flash('Связи сохранены как желаемая топология. VPN НЕ применён.', 'success')
        except (VPNPlanError, ValueError) as exc:
            db.session.rollback()
            flash(f'Ошибка проверки топологии: {exc}', 'danger')
        except Exception:
            db.session.rollback()
            app.logger.exception('Failed to save Magos desired mesh')
            flash('Не удалось сохранить связи', 'danger')
        return redirect(url_for('manage_connections', node_id=node.id))
    return render_template('manage_connections.html', node=node,
                           available_nodes=available_nodes, connected_ids=connected_ids)


@app.route('/api/available_ips', methods=['GET'])
@login_required
def api_available_ips():
    """API endpoint для получения доступных IP адресов для родительского узла"""
    try:
        parent_id = request.args.get('parent_id')
        if not parent_id:
            return jsonify({'success': False, 'error': 'Missing parent_id'}), 400
        
        parent = db.session.get(General, int(parent_id))
        if not parent or not parent.ip_pool:
            return jsonify({'success': False, 'error': 'Invalid parent or no IP pool'}), 400
        
        available_ips = get_next_available_ip_list(parent, limit=50)
        return jsonify({'success': True, 'ips': available_ips}), 200
    except (ValueError, AttributeError, RuntimeError) as e:
        app.logger.error(f"Ошибка получения доступных IP: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/setup_wizard', methods=['GET', 'POST'])
@login_required
@admin_required
def setup_wizard():
    # Импорты для динамического создания полей формы
    from wtforms import StringField
    from wtforms.validators import DataRequired
    
    omnissiah_config = General.query.filter_by(role='Omnissiah').first()
    has_omnissiah_config = omnissiah_config is not None

    form = SetupWizardForm()

    if has_omnissiah_config:
        form.role.choices = [
            ('Magos', 'Magos (Ретранслятор)'),
            ('Cognitor', 'Cognitor (Клиент)')
        ]
        # Фильтруем только Omnissiah и Magos как возможных родителей
        form.parent_id.choices = [(c.id, c.name) for c in General.query.filter(General.role.in_(['Omnissiah', 'Magos'])).all()]
        
        # Заполняем доступные IP для выбора (берем Omnissiah по умолчанию)
        if omnissiah_config and omnissiah_config.ip_pool:
            available_ips = get_next_available_ip_list(omnissiah_config, limit=50)
            if available_ips:
                form.ip_pool.choices = [(ip, ip) for ip in available_ips]
                # Автоматически выбираем первый доступный IP
                form.ip_pool.data = available_ips[0]
            else:
                # Если нет доступных IP, все равно показываем поле (пустой список)
                form.ip_pool.choices = []
                form.ip_pool.data = None
        else:
            # Если нет Omnissiah или пула, очищаем choices
            form.ip_pool.choices = []
            form.ip_pool.data = None
        
        # Автоматически заполняем endpoint для Magos (из Omnissiah)
        if form.role.data == 'Magos' and omnissiah_config and omnissiah_config.endpoint:
            form.endpoint.data = omnissiah_config.endpoint
    else:
        form.role.choices = [('Omnissiah', 'Omnissiah (Главный сервер)')]
        form.parent_id.choices = []  # Для главного сервера parent_id не нужен
        
        # Для главной конфигурации (Omnissiah) ip_pool должно быть текстовым полем, а не SelectField
        # Правильный способ - создать экземпляр через правильный механизм WTForms
        # Импорты уже сделаны в начале функции
        
        # Создаем новый экземпляр StringField и привязываем к форме
        new_ip_pool = StringField('IP-пул', validators=[DataRequired()]).bind(form, 'ip_pool')
        
        # ВАЖНО: Вызываем process ДО замены поля в форме для правильной инициализации
        # Всегда вызываем process для правильной инициализации поля
        if request.method == 'POST':
            new_ip_pool.process(request.form, data=None)
        else:
            # Для GET запросов тоже нужно вызвать process для инициализации атрибута data
            new_ip_pool.process(None, data=None)
        
        # Убеждаемся что поле полностью инициализировано перед заменой
        if not hasattr(new_ip_pool, 'data'):
            new_ip_pool.process(None, data=None)
        
        # Заменяем поле в форме только после полной инициализации
        form._fields['ip_pool'] = new_ip_pool
        form.ip_pool = new_ip_pool
        
        # После замены поля вызываем process() на форме для правильной инициализации всех полей
        # Это особенно важно для GET запросов
        if request.method == 'GET':
            form.process(formdata=None)

    if form.validate_on_submit():
        try:
            # Для Magos автоматически выбираем главный сервер
            if form.role.data == 'Magos' and not form.parent_id.data:
                form.parent_id.data = omnissiah_config.id

            # Генерация ключей только если настроен WireGuard
            private_key = None
            public_key = None
            preshared_key = None
            
            # Для главного сервера проверяем, настроен ли WireGuard
            configure_wg = form.configure_wireguard.data if form.role.data == 'Omnissiah' else True
            
            # Проверяем что ip_pool указан для Magos/Cognitor
            if form.role.data in ['Magos', 'Cognitor'] and not form.ip_pool.data:
                db.session.rollback()
                error_msg = "Необходимо выбрать IP-пул из доступных"
                if form.deploy_via_ssh.data:
                    return jsonify({'success': False, 'error': error_msg}), 400
                flash(error_msg, "danger")
                return render_template('setup_wizard.html',
                                     form=form,
                                     has_omnissiah_config=has_omnissiah_config,
                                     omnissiah_config=omnissiah_config)
            
            if configure_wg:
                private_key, public_key = generate_wg_keys()
                preshared_key = subprocess.check_output(["sudo", "-n", "wg", "genpsk"],
                                                        text=True).strip() if form.use_preshared_key.data else None

                # Для главного сервера создаем конфигурационный файл
                if form.role.data == 'Omnissiah' and form.ip_pool.data:
                    server_ip = form.ip_pool.data.split('/')[0]
                    ip_prefix = form.ip_pool.data.split('/')[1] if '/' in form.ip_pool.data else '24'
                    config_content = f"""[Interface]
PrivateKey = {private_key}
Address = {server_ip}/{ip_prefix}
ListenPort = {form.port.data}
MTU = {form.mtu.data}"""

                    config_path = Path(app.config['WG_CONFIG_PATH']) / f"{form.name.data}.conf"
                    
                    # Сохраняем во временный файл, затем копируем через sudo
                    app_dir = Path(__file__).parent.parent
                    temp_config_path = app_dir / "tmp" / f"{form.name.data}.conf"
                    temp_config_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(temp_config_path, 'w') as f:
                        f.write(config_content)
                    
                    # Копируем в системную директорию через sudo
                    subprocess.run([
                        "sudo", "-n", "cp", str(temp_config_path), str(config_path)
                    ], check=True)
                    subprocess.run([
                        "sudo", "-n", "chmod", "600", str(config_path)
                    ], check=True)
                    
                    # Удаляем временный файл
                    temp_config_path.unlink()

            # Проверяем, не существует ли уже узел с таким именем
            existing_node = General.query.filter_by(name=form.name.data).first()
            if existing_node:
                db.session.rollback()
                flash(f"Ошибка: узел с именем '{form.name.data}' уже существует!", "danger")
                return render_template('setup_wizard.html',
                                     form=form,
                                     has_omnissiah_config=has_omnissiah_config,
                                     omnissiah_config=omnissiah_config)
            
            # Сначала определяем endpoint (чтобы избежать проблем с валидацией)
            endpoint_value = None
            if has_omnissiah_config and form.role.data in ['Magos', 'Cognitor']:
                # Для Magos и Cognitor endpoint устанавливается автоматически или из формы
                if form.endpoint.data and form.endpoint.data.strip():
                    endpoint_value = form.endpoint.data.strip()
                else:
                    # Автоматически определяем endpoint
                    if form.role.data == 'Cognitor':
                        # Определим parent_id заранее
                        parent_id_for_endpoint = form.parent_id.data if form.parent_id.data else (omnissiah_config.id if form.role.data == 'Magos' else None)
                        if parent_id_for_endpoint:
                            parent_node = db.session.get(General, parent_id_for_endpoint)
                            if parent_node:
                                # Приоритет: heartbeat_ip -> endpoint родителя -> endpoint Omnissiah
                                if parent_node.heartbeat_ip:
                                    endpoint_value = parent_node.heartbeat_ip
                                elif parent_node.endpoint:
                                    endpoint_value = parent_node.endpoint
                                elif omnissiah_config and omnissiah_config.endpoint:
                                    endpoint_value = omnissiah_config.endpoint
                    elif form.role.data == 'Magos':
                        # Magos всегда подключается к Omnissiah, используем его endpoint
                        if omnissiah_config and omnissiah_config.endpoint:
                            endpoint_value = omnissiah_config.endpoint
            elif form.role.data == 'Omnissiah' and configure_wg:
                # Для Omnissiah endpoint устанавливается из формы (если указан)
                if form.endpoint.data and form.endpoint.data.strip():
                    endpoint_value = form.endpoint.data.strip()
            
            # Создаем запись в базе
            # Для Magos/Cognitor ip_pool обязателен если WireGuard настроен
            ip_pool_value = None
            if configure_wg:
                if form.role.data == 'Omnissiah':
                    ip_pool_value = form.ip_pool.data if form.ip_pool.data else None
                else:
                    # Для Magos/Cognitor ip_pool обязателен
                    ip_pool_value = form.ip_pool.data if form.ip_pool.data else None
                    if not ip_pool_value:
                        db.session.rollback()
                        error_msg = "Необходимо выбрать IP-пул"
                        if form.deploy_via_ssh.data:
                            return jsonify({'success': False, 'error': error_msg}), 400
                        flash(error_msg, "danger")
                        return render_template('setup_wizard.html',
                                             form=form,
                                             has_omnissiah_config=has_omnissiah_config,
                                             omnissiah_config=omnissiah_config)
            
            # Шифруем private_key перед сохранением в БД (для всех узлов)
            encrypted_private_key = None
            if private_key:
                try:
                    cipher = get_cipher_suite()
                    encrypted_private_key = cipher.encrypt(private_key.encode('utf-8')).decode('utf-8')
                except (RuntimeError, ValueError, AttributeError) as e:
                    app.logger.error(f"Ошибка шифрования private_key: {str(e)}")
                    db.session.rollback()
                    flash(f"Ошибка шифрования ключа: {str(e)}", "danger")
                    return render_template('setup_wizard.html',
                                         form=form,
                                         has_omnissiah_config=has_omnissiah_config,
                                         omnissiah_config=omnissiah_config)
            
            new_config = General(
                name=form.name.data,
                ip_pool=ip_pool_value,
                listen_port=form.port.data if (form.role.data == 'Omnissiah' and configure_wg) else (omnissiah_config.listen_port if has_omnissiah_config else None),
                private_key=encrypted_private_key if encrypted_private_key else private_key,
                public_key=public_key,
                dns=form.dns.data if (form.role.data == 'Omnissiah' and configure_wg) else (omnissiah_config.dns if has_omnissiah_config else None),
                mtu=form.mtu.data if (form.role.data == 'Omnissiah' and configure_wg) else (omnissiah_config.mtu if has_omnissiah_config else None),
                endpoint=endpoint_value,  # Устанавливаем endpoint сразу, избегая валидации None
                role=form.role.data,
                preshared_key=preshared_key,
                #central_node=form.central_node.data if has_omnissiah_config else None,
                status='stopped',
                admin_ip=form.admin_ip.data.strip() if (form.role.data == 'Omnissiah' and form.admin_ip.data) else None
            )

            # Устанавливаем parent_id для Magos и Cognitor
            if has_omnissiah_config and form.role.data in ['Magos', 'Cognitor']:
                if form.role.data == 'Magos' and not form.parent_id.data:
                    new_config.parent_id = omnissiah_config.id
                elif form.parent_id.data:
                    new_config.parent_id = form.parent_id.data
                # endpoint уже установлен выше

            # Настройка mTLS для главного сервера (ДО настройки nginx, чтобы сертификаты были готовы)
            if form.role.data == 'Omnissiah':
                try:
                    app_dir = Path(__file__).parent.parent
                    mtls_dir = app_dir / "mtls_certs"
                    mtls_dir.mkdir(parents=True, exist_ok=True)
                    
                    # Генерируем CA сертификат и ключ
                    ca_cert_path, ca_key_path = generate_ca_certificate(str(mtls_dir / "ca"))
                    
                    # Генерируем серверный сертификат
                    server_ip = form.ip_pool.data.split('/')[0] if (form.ip_pool.data and configure_wg) else None
                    server_cert_path, server_key_path = generate_server_certificate(
                        ca_cert_path, ca_key_path, form.name.data, str(mtls_dir / "server"), server_ip
                    )
                    
                    # Сохраняем пути в БД (пока не коммитим)
                    new_config.mtls_enabled = True
                    new_config.mtls_ca_cert_path = ca_cert_path
                    new_config.mtls_ca_key_path = ca_key_path
                    new_config.mtls_server_cert_path = server_cert_path
                    new_config.mtls_server_key_path = server_key_path
                    
                    app.logger.info(f"mTLS сертификаты сгенерированы для {form.name.data}")
                    flash("mTLS сертификаты успешно созданы", "success")
                except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, RuntimeError, ValueError) as e:
                    app.logger.error(f"Ошибка настройки mTLS: {str(e)}")
                    import traceback
                    app.logger.error(traceback.format_exc())
                    flash(f"Предупреждение: mTLS настроен не полностью: {str(e)}", "warning")
                    # Не блокируем создание сервера, если mTLS не настроился
            
            # Генерация клиентского сертификата для Magos (если главный сервер поддерживает mTLS)
            if form.role.data == 'Magos' and has_omnissiah_config and omnissiah_config.mtls_enabled:
                try:
                    if omnissiah_config.mtls_ca_cert_path and omnissiah_config.mtls_ca_key_path:
                        app_dir = Path(__file__).parent.parent
                        mtls_dir = app_dir / "mtls_certs" / "clients"
                        mtls_dir.mkdir(parents=True, exist_ok=True)
                        
                        # Генерируем клиентский сертификат для Magos
                        client_cert_path, client_key_path = generate_client_certificate(
                            omnissiah_config.mtls_ca_cert_path,
                            omnissiah_config.mtls_ca_key_path,
                            form.name.data,
                            str(mtls_dir)
                        )
                        
                        # Сохраняем пути к сертификатам в БД Magos
                        # Примечание: пути будут сохранены как дополнительные поля или через другой механизм
                        # Пока сохраняем в отдельной таблице или в JSON поле
                        app.logger.info(f"mTLS клиентский сертификат сгенерирован для {form.name.data}")
                        
                        # Сохраняем информацию о сертификатах в конфигурацию Magos
                        # Это будет использоваться для обновления bootstrap_config.json агента
                        new_config.mtls_enabled = True
                        new_config.mtls_ca_cert_path = omnissiah_config.mtls_ca_cert_path  # CA для проверки сервера
                        new_config.mtls_server_cert_path = client_cert_path  # Переиспользуем поле для хранения клиентского сертификата
                        new_config.mtls_server_key_path = client_key_path  # Переиспользуем поле для хранения клиентского ключа
                        
                        flash(f"mTLS клиентский сертификат создан для {form.name.data}", "success")
                except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, RuntimeError, ValueError) as e:
                    app.logger.error(f"Ошибка генерации клиентского mTLS сертификата для Magos: {str(e)}")
                    import traceback
                    app.logger.error(traceback.format_exc())
                    flash(f"Предупреждение: клиентский mTLS сертификат не создан: {str(e)}", "warning")

            # Настройка nginx для главного сервера
            if form.role.data == 'Omnissiah' and form.configure_nginx.data:
                cert_path = None
                key_path = None
                
                try:
                    # Проверяем и настраиваем sudo права для nginx (если нужно)
                    if not get_sudo_status():
                        manage_sudo_permissions('nginx')
                    
                    if form.nginx_cert_type.data == 'self-signed':
                        cert_path, key_path = generate_self_signed_cert(form.nginx_domain.data)
                    elif form.nginx_cert_type.data == 'letsencrypt':
                        cert_path, key_path = setup_letsencrypt_cert(form.nginx_domain.data, form.nginx_email.data)
                    
                    # Сохраняем настройки nginx в БД
                    new_config.nginx_enabled = True
                    new_config.nginx_domain = form.nginx_domain.data
                    new_config.nginx_cert_type = form.nginx_cert_type.data
                    new_config.nginx_cert_path = cert_path
                    new_config.nginx_key_path = key_path
                    new_config.nginx_https_port = form.nginx_https_port.data
                    new_config.nginx_redirect_http = form.nginx_redirect_http.data
                    
                    # Копируем сертификаты в системную директорию через sudo (если нужно)
                    # Но для self-signed оставляем в проекте и указываем полный путь
                    system_cert_dir = "/etc/nginx/ssl"
                    if form.nginx_cert_type.data == 'self-signed':
                        # Для self-signed копируем в системную директорию через sudo
                        subprocess.run(["sudo", "-n", "mkdir", "-p", system_cert_dir], check=False)
                        cert_name = Path(cert_path).name
                        key_name = Path(key_path).name
                        system_cert_path = f"{system_cert_dir}/{cert_name}"
                        system_key_path = f"{system_cert_dir}/{key_name}"
                        
                        # Копируем через sudo
                        subprocess.run(["sudo", "-n", "cp", cert_path, system_cert_path], check=True)
                        subprocess.run(["sudo", "-n", "cp", key_path, system_key_path], check=True)
                        subprocess.run(["sudo", "-n", "chmod", "644", system_cert_path], check=True)
                        subprocess.run(["sudo", "-n", "chmod", "600", system_key_path], check=True)
                        
                        # Используем системные пути в nginx конфигурации
                        cert_path = system_cert_path
                        key_path = system_key_path
                    
                    # Генерируем конфигурацию nginx
                    flask_port = int(os.getenv('SERVICE_PORT', '33787'))
                    
                    # Получаем настройки mTLS (если уже созданы)
                    mtls_ca_cert = new_config.mtls_ca_cert_path if (new_config.mtls_enabled and new_config.mtls_ca_cert_path) else None
                    mtls_enabled_flag = new_config.mtls_enabled if new_config.mtls_enabled else False
                    
                    nginx_config = generate_nginx_config(
                        domain=form.nginx_domain.data,
                        flask_port=flask_port,
                        https_port=form.nginx_https_port.data,
                        cert_path=cert_path,
                        key_path=key_path,
                        redirect_http=form.nginx_redirect_http.data,
                        service_name="omnissiah-network",
                        mtls_ca_cert_path=mtls_ca_cert,
                        mtls_enabled=mtls_enabled_flag
                    )
                    
                    # Сохраняем конфигурацию nginx (используем sudo только для системных директорий)
                    nginx_config_path = Path("/etc/nginx/sites-available/omnissiah-network")
                    
                    # Сначала сохраняем во временный файл
                    app_dir = Path(__file__).parent.parent
                    temp_config_path = app_dir / "tmp" / "omnissiah-network.conf"
                    temp_config_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(temp_config_path, 'w') as f:
                        f.write(nginx_config)
                    
                    # Копируем в системную директорию через sudo
                    subprocess.run([
                        "sudo", "-n", "cp", str(temp_config_path), str(nginx_config_path)
                    ], check=True)
                    
                    # Создаем символическую ссылку через sudo
                    nginx_enabled_path = Path("/etc/nginx/sites-enabled/omnissiah-network")
                    if nginx_enabled_path.exists():
                        subprocess.run([
                            "sudo", "-n", "rm", str(nginx_enabled_path)
                        ], check=True)
                    subprocess.run([
                        "sudo", "-n", "ln", "-s", str(nginx_config_path), str(nginx_enabled_path)
                    ], check=True)
                    
                    # Удаляем временный файл
                    temp_config_path.unlink()
                    
                    # Проверяем конфигурацию nginx и перезагружаем
                    # Сначала проверяем конфигурацию с выводом ошибок для диагностики
                    nginx_test = subprocess.run(["sudo", "-n", "nginx", "-t"], 
                                               capture_output=True, 
                                               text=True,
                                               check=False)
                    if nginx_test.returncode != 0:
                        error_msg = f"Ошибка конфигурации nginx: {nginx_test.stderr}"
                        app.logger.error(error_msg)
                        # Не перезагружаем nginx если конфигурация невалидна
                        flash(f"Предупреждение: nginx настроен не полностью. Конфигурация невалидна: {nginx_test.stderr[:200]}", "warning")
                    else:
                        # Конфигурация валидна, проверяем статус nginx перед перезагрузкой
                        nginx_status = subprocess.run(['systemctl', 'is-active', 'nginx'], 
                                                      capture_output=True, timeout=5, check=False)
                        if nginx_status.returncode == 0:
                            # Nginx активен, пробуем перезагрузить
                            reload_result = subprocess.run(["sudo", "-n", "systemctl", "reload", "nginx"], 
                                                           capture_output=True,
                                                           text=True,
                                                           check=False)
                            if reload_result.returncode != 0:
                                error_msg = f"Ошибка перезагрузки nginx: {reload_result.stderr}"
                                app.logger.error(error_msg)
                                # Пробуем restart если reload не удался
                                restart_result = subprocess.run(["sudo", "-n", "systemctl", "restart", "nginx"], 
                                                               capture_output=True,
                                                               text=True,
                                                               check=False)
                                if restart_result.returncode != 0:
                                    error_msg = f"Ошибка перезапуска nginx: {restart_result.stderr}"
                                    app.logger.error(error_msg)
                                    flash(f"Предупреждение: nginx настроен не полностью. Не удалось перезагрузить: {restart_result.stderr[:200]}", "warning")
                                else:
                                    app.logger.info("Nginx успешно перезапущен (restart)")
                            else:
                                app.logger.info("Nginx успешно перезагружен (reload)")
                        else:
                            # Nginx не активен, пробуем запустить
                            start_result = subprocess.run(["sudo", "-n", "systemctl", "start", "nginx"], 
                                                          capture_output=True,
                                                          text=True,
                                                          check=False)
                            if start_result.returncode == 0:
                                app.logger.info("Nginx успешно запущен")
                            else:
                                error_msg = f"Ошибка запуска nginx: {start_result.stderr}"
                                app.logger.error(error_msg)
                                flash(f"Предупреждение: nginx настроен, но не удалось запустить: {start_result.stderr[:200]}", "warning")
                    
                except Exception as e:
                    error_msg = f"Ошибка настройки nginx: {str(e)}"
                    app.logger.error(error_msg, exc_info=True)
                    flash(f"Предупреждение: nginx настроен не полностью: {str(e)}", "warning")

            deploy_via_ssh_value = form.deploy_via_ssh.data if hasattr(form.deploy_via_ssh, 'data') else None
            deploy_via_ssh_form = request.form.get('deploy_via_ssh')
            is_deploy_ssh = (
                deploy_via_ssh_value == True or 
                deploy_via_ssh_form in ['y', 'true', 'on', '1', True] or
                str(deploy_via_ssh_value).lower() == 'true'
            )
            
            if form.role.data in ['Magos', 'Cognitor'] and is_deploy_ssh:
                with db_transaction():
                    db.session.add(new_config)
                    db.session.flush()
                    response_data = {
                        'success': True,
                        'node_id': new_config.id,
                        'message': f"Узел {form.name.data} успешно создан"
                    }
                    app.logger.info(f"Returning JSON response for SSH deploy: {json.dumps(response_data)}")
                    response = jsonify(response_data)
                    response.headers['Content-Type'] = 'application/json; charset=utf-8'
                    return response
            
            with db_transaction():
                db.session.add(new_config)
                db.session.flush()  # Получаем ID узла
            
            # Создаем системные правила и защищенные объекты
            try:
                from omnissiah_core.nmc_system_rules_generator import (
                    create_system_rules_for_omnissiah,
                    create_system_rules_for_magos,
                    create_system_rules_for_cognitor,
                    create_default_protected_objects
                )
                
                # Создаем защищенные объекты по умолчанию
                protected_objects_data = create_default_protected_objects(
                    new_config,
                    admin_ip=new_config.admin_ip if new_config.role == 'Omnissiah' else None
                )
                
                for obj_data in protected_objects_data:
                    # Проверяем, нет ли уже такого объекта
                    existing = ProtectedObject.query.filter_by(
                        network=obj_data['network'],
                        node_id=obj_data['node_id'],
                        is_active=True
                    ).first()
                    if not existing:
                        protected_obj = ProtectedObject(**obj_data, created_by=current_user.id if current_user.is_authenticated else None)
                        db.session.add(protected_obj)
                
                # Создаем системные правила в зависимости от роли
                system_rules_data = []
                extra_commands_data = []
                if new_config.role == 'Omnissiah':
                    system_rules_data, extra_commands_data = create_system_rules_for_omnissiah(
                        new_config,
                        admin_ip=new_config.admin_ip,
                        mtls_port=5001
                    )
                elif new_config.role == 'Magos':
                    omnissiah = General.query.filter_by(role='Omnissiah').first()
                    # Получаем admin_ip из Omnissiah для правил SSH
                    admin_ip = omnissiah.admin_ip if omnissiah else None
                    system_rules_data, extra_commands_data = create_system_rules_for_magos(
                        new_config,
                        omnissiah=omnissiah,
                        mtls_port=5001,
                        admin_ip=admin_ip
                    )
                elif new_config.role == 'Cognitor':
                    omnissiah = General.query.filter_by(role='Omnissiah').first()
                    parent = new_config.parent if new_config.parent_id else None
                    # Получаем admin_ip из Omnissiah для правил SSH
                    admin_ip = omnissiah.admin_ip if omnissiah else None
                    system_rules_data, extra_commands_data = create_system_rules_for_cognitor(
                        new_config,
                        omnissiah=omnissiah,
                        parent=parent,
                        mtls_port=5001,
                        admin_ip=admin_ip
                    )
                
                # Применяем базовые команды (loopback, ESTABLISHED, localhost) ДО применения политики DROP
                # ВАЖНО: Порядок критичен - сначала разрешающие правила, потом политика DROP
                # Только для Omnissiah локально
                if new_config.role == 'Omnissiah' and extra_commands_data:
                    # Разделяем команды на базовые (INPUT, не POLICY, не OUTPUT), OUTPUT и политики
                    basic_commands = [cmd for cmd in extra_commands_data 
                                     if cmd['chain'] not in ['POLICY', 'OUTPUT']]
                    output_commands = [cmd for cmd in extra_commands_data if cmd['chain'] == 'OUTPUT']
                    policy_commands = [cmd for cmd in extra_commands_data if cmd['chain'] == 'POLICY']
                    
                    # Сначала применяем базовые правила (loopback, ESTABLISHED, localhost)
                    for extra_cmd in basic_commands:
                        try:
                            cmd_list = extra_cmd['cmd']
                            subprocess.run(['sudo', '-n', 'iptables'] + cmd_list, check=True, timeout=5)
                            app.logger.info(f"Применена системная команда: {extra_cmd['description']}")
                        except Exception as e:
                            app.logger.warning(f"Ошибка применения системной команды {extra_cmd['description']}: {e}")
                    
                    # КРИТИЧНО: Добавляем SSH правила для VPN интерфейсов (если VPN активен)
                    # Это нужно чтобы SSH работал и когда VPN включен
                    try:
                        wg_result = subprocess.run(['sudo', '-n', 'wg', 'show', 'interfaces'], 
                                                  capture_output=True, text=True, timeout=2)
                        if wg_result.returncode == 0:
                            wg_interfaces = wg_result.stdout.strip().split()
                            for wg_iface in wg_interfaces:
                                if wg_iface:
                                    # Разрешаем SSH через VPN интерфейс
                                    subprocess.run(['sudo', '-n', 'iptables', '-A', 'INPUT', 
                                                   '-i', wg_iface, '-p', 'tcp', '--dport', '22', '-j', 'ACCEPT'], 
                                                  check=False, timeout=5)
                                    subprocess.run(['sudo', '-n', 'iptables', '-A', 'OUTPUT', 
                                                   '-o', wg_iface, '-p', 'tcp', '--sport', '22', '-j', 'ACCEPT'], 
                                                  check=False, timeout=5)
                                    # Разрешаем весь трафик через VPN интерфейс (для администратора и других служб)
                                    subprocess.run(['sudo', '-n', 'iptables', '-A', 'INPUT', 
                                                   '-i', wg_iface, '-j', 'ACCEPT'], 
                                                  check=False, timeout=5)
                                    subprocess.run(['sudo', '-n', 'iptables', '-A', 'OUTPUT', 
                                                   '-o', wg_iface, '-j', 'ACCEPT'], 
                                                  check=False, timeout=5)
                                    app.logger.info(f"Добавлены правила SSH для VPN интерфейса {wg_iface}")
                    except Exception:
                        pass  # Если VPN не активен или не удалось получить список интерфейсов
                    
                    # Также добавляем общее правило SSH на всех интерфейсах (без указания IP)
                    # Это гарантирует что SSH работает независимо от того, откуда идет трафик
                    try:
                        subprocess.run(['sudo', '-n', 'iptables', '-A', 'INPUT', 
                                       '-p', 'tcp', '--dport', '22', '-j', 'ACCEPT'], 
                                      check=False, timeout=5)
                        subprocess.run(['sudo', '-n', 'iptables', '-A', 'OUTPUT', 
                                       '-p', 'tcp', '--sport', '22', '-j', 'ACCEPT'], 
                                      check=False, timeout=5)
                        app.logger.info("Добавлено общее правило SSH на всех интерфейсах")
                    except Exception as e:
                        app.logger.warning(f"Не удалось добавить общее правило SSH: {e}")
                
                # Создаем правила в БД
                for rule_data in system_rules_data:
                    # Извлекаем direction перед созданием правила (если есть)
                    direction = rule_data.pop('direction', None)
                    rule = AccessPolicyRule(**rule_data, created_by=current_user.id if current_user.is_authenticated else None)
                    if direction:
                        rule.direction = direction
                    db.session.add(rule)
                    db.session.flush()  # Flush чтобы получить ID правила
                    
                    # Автоматически применяем системные правила (пока только для Omnissiah локально)
                    # Для Magos/Cognitor правила будут применены при первом подключении или через VPN
                    if rule_data.get('status') == 'applied':
                        if new_config.role == 'Omnissiah':
                            try:
                                app.logger.info(f"Применение системного правила для Omnissiah: {rule.description}")
                                # Используем локальные функции вместо импорта
                                iptables_cmds = generate_iptables_commands_for_rule(rule)
                                app.logger.info(f"Сгенерировано команд iptables: {len(iptables_cmds)}")
                                
                                if not iptables_cmds:
                                    app.logger.warning(f"Не удалось сгенерировать команды iptables для правила {rule.id}")
                                    continue
                                
                                # subprocess уже импортирован глобально в начале файла
                                for cmd_list in iptables_cmds:
                                    try:
                                        if isinstance(cmd_list, list):
                                            # Формируем полную команду iptables
                                            full_cmd = ['iptables'] + cmd_list
                                            app.logger.debug(f"Выполнение команды: {' '.join(['sudo', '-n'] + full_cmd)}")
                                            result = subprocess.run(['sudo', '-n'] + full_cmd, check=True, timeout=5, capture_output=True, text=True)
                                            app.logger.info(f"Команда iptables выполнена успешно: {' '.join(full_cmd)}")
                                        else:
                                            # Если это строка
                                            full_cmd = ['iptables'] + cmd_list.split()
                                            app.logger.debug(f"Выполнение команды (строка): {' '.join(['sudo', '-n'] + full_cmd)}")
                                            result = subprocess.run(['sudo', '-n'] + full_cmd, check=True, timeout=5, capture_output=True, text=True)
                                            app.logger.info(f"Команда iptables выполнена успешно (строка): {' '.join(full_cmd)}")
                                    except subprocess.CalledProcessError as e:
                                        app.logger.error(f"Ошибка применения команды iptables {cmd_list}: {e.stderr}")
                                    except Exception as e:
                                        app.logger.error(f"Ошибка применения системного правила: {e}")
                                
                                rule.applied_at = datetime.now(timezone.utc)
                                rule.applied_by = current_user.id if current_user.is_authenticated else None
                                rule.applied_on_nodes = json.dumps([new_config.id])
                                app.logger.info(f"Системное правило {rule.id} успешно применено для Omnissiah")
                            except Exception as e:
                                app.logger.error(f"Не удалось применить системное правило автоматически: {e}")
                                import traceback
                                app.logger.error(traceback.format_exc())
                
                # Коммитим все правила
                db.session.commit()
                
                # Применяем OUTPUT правила (разрешить весь исходящий трафик) ПОСЛЕ правил из БД, но ДО политики DROP
                # Это критично - правило OUTPUT ACCEPT должно быть перед политикой DROP
                if new_config.role == 'Omnissiah' and extra_commands_data:
                    output_commands = [cmd for cmd in extra_commands_data if cmd['chain'] == 'OUTPUT']
                    for extra_cmd in output_commands:
                        try:
                            cmd_list = extra_cmd['cmd']
                            subprocess.run(['sudo', '-n', 'iptables'] + cmd_list, check=True, timeout=5)
                            app.logger.info(f"Применено OUTPUT правило: {extra_cmd['description']}")
                        except Exception as e:
                            app.logger.warning(f"Ошибка применения OUTPUT правила {extra_cmd['description']}: {e}")
                
                # Только ПОСЛЕ применения всех разрешающих правил применяем политику DROP
                # Это критично - иначе портал будет заблокирован
                if new_config.role == 'Omnissiah' and extra_commands_data:
                    policy_commands = [cmd for cmd in extra_commands_data if cmd['chain'] == 'POLICY']
                    for extra_cmd in policy_commands:
                        try:
                            cmd_list = extra_cmd['cmd']
                            subprocess.run(['sudo', '-n', 'iptables'] + cmd_list, check=True, timeout=5)
                            app.logger.info(f"Применена политика по умолчанию: {extra_cmd['description']}")
                        except Exception as e:
                            app.logger.warning(f"Ошибка применения политики {extra_cmd['description']}: {e}")
                
                app.logger.info(f"Созданы системные правила и защищенные объекты для {new_config.name}")
            except Exception as e:
                app.logger.error(f"Ошибка создания системных правил: {str(e)}")
                import traceback
                app.logger.error(traceback.format_exc())
                # Не блокируем создание узла, если правила не создались
                db.session.commit()  # Коммитим хотя бы то, что создалось

            # Для пиров добавляем их в главную конфигурацию только если WireGuard настроен у обоих
            if has_omnissiah_config and configure_wg and form.ip_pool.data:
                # Проверяем, что у главного сервера тоже настроен WireGuard
                if omnissiah_config.private_key and omnissiah_config.public_key:
                    # Для peer используем /32 вместо полного пула
                    peer_ip = form.ip_pool.data.split('/')[0] + '/32'
                    subprocess.run([
                        "sudo", "-n", "wg", "set", omnissiah_config.name,
                        "peer", public_key,
                        "allowed-ips", peer_ip,
                        "preshared-key", "/dev/stdin"
                    ], input=preshared_key.encode() if preshared_key else None, check=True)

                    subprocess.run(["sudo", "-n", "wg-quick", "save", omnissiah_config.name], check=True)
            
            if False:  # Этот блок больше не используется для deploy_via_ssh
                # Убеждаемся что возвращаем JSON с правильными заголовками
                # json уже импортирован в начале файла, используем глобальный импорт
                response_data = {
                    'success': True,
                    'node_id': new_config.id,
                    'message': f"Узел {form.name.data} успешно создан"
                }
                app.logger.info(f"Returning JSON response for SSH deploy: {json.dumps(response_data)}")
                response = jsonify(response_data)
                response.headers['Content-Type'] = 'application/json; charset=utf-8'
                return response
            
            flash(f"{'Объект' if has_omnissiah_config else 'Сервер'} успешно создан!", "success")
            omnissiah_config = General.query.filter_by(role='Omnissiah').first()
            if omnissiah_config:
                # КРИТИЧНО: Если nginx включен и настроен домен, перенаправляем на HTTPS
                if omnissiah_config.nginx_enabled and omnissiah_config.nginx_domain:
                    # Формируем HTTPS URL
                    https_url = f"https://{omnissiah_config.nginx_domain}"
                    if omnissiah_config.nginx_https_port and omnissiah_config.nginx_https_port != 443:
                        https_url += f":{omnissiah_config.nginx_https_port}"
                    return redirect(https_url)
                else:
                    return redirect(url_for('dashboard'))
            else:
                return redirect(url_for('dashboard'))

        except subprocess.CalledProcessError as e:
            db.session.rollback()
            error_msg = f"Ошибка команды: {e.stderr.decode() if e.stderr else str(e)}"
            app.logger.error(f"setup_wizard subprocess error: {error_msg}")
            # Проверяем deploy_via_ssh из request.form напрямую
            deploy_via_ssh = request.form.get('deploy_via_ssh') == 'y' or request.form.get('deploy_via_ssh') == 'true'
            role_from_form = request.form.get('role', '')
            if role_from_form in ['Magos', 'Cognitor'] and deploy_via_ssh:
                return jsonify({'success': False, 'error': error_msg}), 500
            flash(error_msg, "danger")
        except Exception as e:
            db.session.rollback()
            error_msg = f"Ошибка: {str(e)}"
            app.logger.error(f"setup_wizard error: {error_msg}")
            import traceback
            app.logger.error(traceback.format_exc())
            # Проверяем deploy_via_ssh из request.form напрямую (на случай ошибки валидации)
            deploy_via_ssh = request.form.get('deploy_via_ssh') == 'y' or request.form.get('deploy_via_ssh') == 'true'
            role_from_form = request.form.get('role', '')
            if request.method == 'POST' and role_from_form in ['Magos', 'Cognitor'] and deploy_via_ssh:
                return jsonify({'success': False, 'error': error_msg}), 500
            flash(error_msg, "danger")

    # Если форма не прошла валидацию, но deploy_via_ssh включен, возвращаем JSON с ошибками
    if request.method == 'POST' and form.errors:
        deploy_via_ssh = request.form.get('deploy_via_ssh') == 'y' or request.form.get('deploy_via_ssh') == 'true'
        role_from_form = request.form.get('role', '')
        if role_from_form in ['Magos', 'Cognitor'] and deploy_via_ssh:
            errors = {}
            for field, error_list in form.errors.items():
                errors[field] = error_list[0] if error_list else 'Ошибка валидации'
            response = jsonify({'success': False, 'error': 'Ошибки валидации формы', 'errors': errors})
            response.headers['Content-Type'] = 'application/json'
            return response, 400
    
    # Проверяем, не требуется ли JSON ответ для AJAX запросов с deploy_via_ssh
    if request.method == 'POST':
        deploy_via_ssh = request.form.get('deploy_via_ssh') == 'y' or request.form.get('deploy_via_ssh') == 'true'
        role_from_form = request.form.get('role', '')
        # Если это AJAX запрос (проверяем по заголовку X-Requested-With или Accept)
        is_ajax = (request.headers.get('X-Requested-With') == 'XMLHttpRequest' or 
                   'application/json' in request.headers.get('Accept', ''))
        if role_from_form in ['Magos', 'Cognitor'] and deploy_via_ssh and is_ajax:
            # Если форма не прошла валидацию и это AJAX, возвращаем JSON
            if form.errors:
                errors = {}
                for field, error_list in form.errors.items():
                    errors[field] = error_list[0] if error_list else 'Ошибка валидации'
                response = jsonify({'success': False, 'error': 'Ошибки валидации формы', 'errors': errors})
                response.headers['Content-Type'] = 'application/json'
                return response, 400
    
    return render_template('setup_wizard.html',
                           form=form,
                           has_omnissiah_config=has_omnissiah_config,
                           omnissiah_config=omnissiah_config)

#ROUTE UFW

@app.route('/dashboard')
@login_required
@require_omnissiah
def dashboard():
    omnissiah_server = General.query.filter_by(role='Omnissiah').first()
    magi = General.query.filter_by(role='Magos').all()
    cognitors = General.query.filter_by(role='Cognitor').all()

    all_nodes = [omnissiah_server] + magi + cognitors if omnissiah_server else magi + cognitors
    # Dashboard counts reflect observed management reachability, not
    # the legacy VPN activation flag on the control-plane server.
    from management_status import recent
    active_nodes = (1 if omnissiah_server else 0) + sum(
        1 for node in magi if recent(node.last_heartbeat, 90))
    inactive_nodes = len(all_nodes) - active_nodes

    connections = NodeConnection.query.all()

    ip_stats = {}
    if omnissiah_server:
        ip_stats = calculate_ip_ranges(omnissiah_server.ip_pool, omnissiah_server)

    # VPN exists only on Magos: use the last authenticated observed heartbeat,
    # never try to inspect the controller's local wg interface.
    from management_status import peer_status
    for magos in magi:
        observed = peer_status(magos)
        magos.vpn_status = 'online' if observed['vpn_connected'] else (
            'active' if observed['vpn_enabled'] else 'offline')
        magos.service_status = 'online' if observed['service_active'] else 'offline'
        magos.mtls_status = 'online' if observed['mtls_enabled'] else 'offline'

    magos_by_id = {n.id: n for n in magi}
    vpn_links = [
        dict(left=magos_by_id[c.node1_id].name, right=magos_by_id[c.node2_id].name)
        for c in connections
        if c.node1_id in magos_by_id and c.node2_id in magos_by_id
    ]
    return render_template('dashboard.html',
                           omnissiah_server=omnissiah_server,
                           magi=magi,
                           cognitors=cognitors,
                           connections=connections,
                           vpn_links=vpn_links,
                           ip_stats=ip_stats,
                           STATUS_CHOICES=STATUS_CHOICES,
                           active_nodes=active_nodes,
                           inactive_nodes=inactive_nodes,
                           current_node=omnissiah_server)


# Удалена функция apply_iptables_rules




def get_interfaces_with_ips(node_or_data, ssh_client=None, sudo_password=None):
    """
    Получает список интерфейсов с их IP адресами для узла
    
    Аргументы:
        node_or_data: объект General SQLAlchemy ИЛИ словарь с данными узла:
            {'name': str, 'role': str, 'ip_pool': str, 'heartbeat_ip': str, 'heartbeat_interfaces': str}
        ssh_client: объект SSH клиента (опционально)
        sudo_password: пароль для sudo (опционально)
    
    Returns:
        list: [{'name': 'eth0', 'ip': '192.168.1.10'}, ...]
    """
    interfaces = []
    
    # Импортируем has_app_context один раз
    try:
        from flask import has_app_context
    except ImportError:
        has_app_context = None
    
    # Вспомогательная функция для безопасного логирования
    def safe_log(level, message):
        try:
            if has_app_context and has_app_context():
                getattr(current_app.logger, level)(message)
        except Exception:
            pass  # Если логирование не работает, просто игнорируем
    
    # Извлекаем данные узла: поддерживаем как объект SQLAlchemy, так и словарь
    node_name = None
    node_role = None
    node_ip_pool = None
    node_heartbeat_ip = None
    node_heartbeat_interfaces = None
    
    if node_or_data is None:
        return interfaces
    
    # Проверяем, что передано: объект или словарь
    if isinstance(node_or_data, dict):
        # Передан словарь с данными - используем напрямую
        node_name = node_or_data.get('name')
        node_role = node_or_data.get('role')
        node_ip_pool = node_or_data.get('ip_pool')
        node_heartbeat_ip = node_or_data.get('heartbeat_ip')
        node_heartbeat_interfaces = node_or_data.get('heartbeat_interfaces')
        # Преобразуем в строки для безопасности
        if node_name is not None:
            node_name = str(node_name)
        if node_role is not None:
            node_role = str(node_role)
        if node_ip_pool is not None:
            node_ip_pool = str(node_ip_pool)
        if node_heartbeat_ip is not None:
            node_heartbeat_ip = str(node_heartbeat_ip)
        if node_heartbeat_interfaces is not None:
            node_heartbeat_interfaces = str(node_heartbeat_interfaces)
    else:
        # Передан объект SQLAlchemy - извлекаем данные безопасно через __dict__
        try:
            node = node_or_data
            node_dict = node.__dict__
            # Фильтруем только служебные поля SQLAlchemy (_sa_instance_state)
            node_dict_clean = {k: v for k, v in node_dict.items() 
                              if not k.startswith('_sa_')}
            node_name = node_dict_clean.get('name')
            node_role = node_dict_clean.get('role')
            node_ip_pool = node_dict_clean.get('ip_pool')
            node_heartbeat_ip = node_dict_clean.get('heartbeat_ip')
            node_heartbeat_interfaces = node_dict_clean.get('heartbeat_interfaces')
            # Преобразуем в примитивные типы для безопасности
            if node_name is not None:
                node_name = str(node_name)
            if node_role is not None:
                node_role = str(node_role)
            if node_ip_pool is not None:
                node_ip_pool = str(node_ip_pool)
            if node_heartbeat_ip is not None:
                node_heartbeat_ip = str(node_heartbeat_ip)
            if node_heartbeat_interfaces is not None:
                node_heartbeat_interfaces = str(node_heartbeat_interfaces)
        except Exception as e:
            safe_log('error', f"Ошибка извлечения данных из объекта узла: {e}")
            return interfaces
    
    # Если нет роли - значит данные не извлечены
    if not node_role:
        safe_log('error', f"Не удалось получить данные узла")
        return interfaces
    
    try:
        if node_role == 'Omnissiah':
            # Для Omnissiah получаем интерфейсы локально
            result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True, timeout=5)
            import re
            
            # Парсим вывод ip addr show
            current_iface = None
            for line in result.stdout.split('\n'):
                # Находим интерфейс: "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>"
                if_match = re.match(r'\d+: (\w+):', line)
                if if_match:
                    current_iface = if_match.group(1)
                
                # Находим IP адрес: "    inet 192.168.1.10/24"
                ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', line)
                if ip_match and current_iface and current_iface != 'lo':
                    ip = ip_match.group(1)
                    interfaces.append({'name': current_iface, 'ip': ip})
            
            # Добавляем WireGuard интерфейс если он есть
            if node_name:
                try:
                    wg_result = subprocess.run(['sudo', '-n', 'wg', 'show', node_name], 
                                             capture_output=True, text=True, timeout=2)
                    if wg_result.returncode == 0:
                        # Получаем IP из конфигурации WireGuard
                        # Ищем Address в конфигурационном файле
                        wg_conf_path = Path(f"/etc/wireguard/{node_name}.conf")
                        if wg_conf_path.exists():
                            with open(wg_conf_path, 'r') as f:
                                content = f.read()
                                addr_match = re.search(r'Address\s*=\s*(\d+\.\d+\.\d+\.\d+)', content)
                                if addr_match:
                                    wg_ip = addr_match.group(1).split('/')[0]
                                    interfaces.insert(0, {'name': node_name, 'ip': wg_ip})
                        else:
                            # Используем IP из ip_pool
                            vpn_ip = node_ip_pool.split('/')[0] if node_ip_pool else None
                            if vpn_ip:
                                interfaces.insert(0, {'name': node_name, 'ip': vpn_ip})
                except Exception as e:
                    safe_log('debug', f"Не удалось получить IP для WireGuard интерфейса {node_name}: {e}")
        
        else:
            # Для Magos получаем интерфейсы из heartbeat (приоритет)
            # Если есть сохраненные интерфейсы из heartbeat, используем их
            if node_heartbeat_interfaces:
                try:
                    interfaces = json.loads(node_heartbeat_interfaces)
                    # Убеждаемся что это список словарей
                    if isinstance(interfaces, list) and len(interfaces) > 0:
                        # Интерфейсы уже в правильном формате из heartbeat
                        pass
                    else:
                        interfaces = []
                except Exception as e:
                    safe_log('warning', f"Ошибка парсинга heartbeat_interfaces для {node_name}: {e}")
                    interfaces = []
            
            # Если интерфейсы из heartbeat не получены, пробуем через SSH
            if not interfaces and ssh_client:
                # Получаем через SSH
                cmd = "ip addr show | grep -E '^[0-9]+:|inet '"
                if sudo_password:
                    full_cmd = f"echo '{sudo_password}' | sudo -S {cmd}"
                else:
                    full_cmd = f"sudo -n {cmd}"
                
                stdin, stdout, stderr = ssh_client.exec_command(full_cmd, timeout=5)
                output = stdout.read().decode()
                
                import re
                current_iface = None
                for line in output.split('\n'):
                    if_match = re.match(r'\d+: (\w+):', line)
                    if if_match:
                        current_iface = if_match.group(1)
                    
                    ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match and current_iface and current_iface != 'lo':
                        ip = ip_match.group(1)
                        interfaces.append({'name': current_iface, 'ip': ip})
                
                # Добавляем WireGuard интерфейс (VPN)
                if node_name:
                    vpn_ip = node_ip_pool.split('/')[0] if node_ip_pool else None
                    if vpn_ip:
                        interfaces.insert(0, {'name': node_name, 'ip': vpn_ip})
            
            # Если интерфейсы все еще не получены, используем минимальный набор
            if not interfaces:
                # VPN интерфейс из данных узла
                if node_name:
                    vpn_ip = node_ip_pool.split('/')[0] if node_ip_pool else None
                    if vpn_ip:
                        interfaces.append({'name': node_name, 'ip': vpn_ip})
                
                # Интерфейс из heartbeat_ip если есть
                if node_heartbeat_ip:
                    # Используем heartbeat_ip как основной интерфейс (обычно это eth0 или ens33)
                    # Не добавляем если уже есть VPN интерфейс с таким же IP
                    if not any(i['ip'] == node_heartbeat_ip for i in interfaces):
                        # Пытаемся определить имя интерфейса, используем стандартные
                        for iface_name in ['ens33', 'eth0', 'eth1']:
                            if not any(i['name'] == iface_name for i in interfaces):
                                interfaces.append({'name': iface_name, 'ip': node_heartbeat_ip})
                                break
    
    except Exception as e:
        # Безопасное получение имени узла для логирования
        try:
            node_id_str = str(getattr(node, 'id', 'unknown'))
        except Exception:
            node_id_str = 'unknown'
        try:
            node_name_str = str(node_name) if node_name else 'неизвестного узла'
        except Exception:
            node_name_str = f'узла (id: {node_id_str})'
        
        safe_log('error', f"Ошибка получения интерфейсов для {node_name_str}: {e}")
        # Возвращаем хотя бы VPN интерфейс, если данные доступны
        try:
            if node_name and node_ip_pool:
                vpn_ip = str(node_ip_pool).split('/')[0] if '/' in str(node_ip_pool) else str(node_ip_pool)
                node_name_safe = str(node_name)
                if vpn_ip and node_name_safe:
                    interfaces.append({'name': node_name_safe, 'ip': vpn_ip})
        except Exception:
            pass  # Если даже это не работает, просто возвращаем пустой список
    
    return interfaces


@app.route('/protected_objects')
@login_required
@admin_required
@require_omnissiah
def protected_objects():
    """
    Страница управления защищенными объектами
    
    Функционал:
    - Добавляя адрес/подсеть и указывая узел и интерфейс, мы указываем,
      что этот адрес/подсеть находится за этим узлом и интерфейсом.
    - В будущем будут политики безопасности для управления доступом.
    """
    objects = ProtectedObject.query.filter_by(is_active=True).order_by(ProtectedObject.created_at.desc()).all()
    
    # Получаем все узлы Omnissiah и Magos для выбора
    nodes = General.query.filter(General.role.in_(['Omnissiah', 'Magos'])).all()
    
    # Получаем список интерфейсов с IP адресами для каждого узла
    nodes_with_interfaces = []
    for node in nodes:
        # Извлекаем данные узла через __dict__ для безопасности (без обращения к SQLAlchemy)
        try:
            node_dict = node.__dict__
            node_dict_clean = {k: v for k, v in node_dict.items() if not k.startswith('_sa_')}
            node_data = {
                'name': str(node_dict_clean.get('name')) if node_dict_clean.get('name') else None,
                'role': str(node_dict_clean.get('role')) if node_dict_clean.get('role') else None,
                'ip_pool': str(node_dict_clean.get('ip_pool')) if node_dict_clean.get('ip_pool') else None,
                'heartbeat_ip': str(node_dict_clean.get('heartbeat_ip')) if node_dict_clean.get('heartbeat_ip') else None,
                'heartbeat_interfaces': str(node_dict_clean.get('heartbeat_interfaces')) if node_dict_clean.get('heartbeat_interfaces') else None
            }
        except Exception:
            # Fallback - если __dict__ не работает, пытаемся через атрибуты
            try:
                node_data = {
                    'name': str(node.name) if node.name else None,
                    'role': str(node.role) if node.role else None,
                    'ip_pool': str(node.ip_pool) if node.ip_pool else None,
                    'heartbeat_ip': str(node.heartbeat_ip) if node.heartbeat_ip else None,
                    'heartbeat_interfaces': str(node.heartbeat_interfaces) if node.heartbeat_interfaces else None
                }
            except Exception:
                node_data = {'name': None, 'role': None, 'ip_pool': None, 'heartbeat_ip': None, 'heartbeat_interfaces': None}
        
        # Получаем интерфейсы с IP адресами, передавая словарь вместо объекта
        interfaces = get_interfaces_with_ips(node_data)
        
        nodes_with_interfaces.append({
            'node': node,
            'interfaces': interfaces
        })
    
    return render_template('protected_objects.html',
                         objects=objects,
                         nodes_with_interfaces=nodes_with_interfaces)


@app.route('/access_policy')
@app.route('/access_policy/node/<int:node_id>')
@login_required
@admin_required
@require_omnissiah
def access_policy(node_id=None):
    """
    Страница управления политикой доступа
    
    Позволяет создавать правила доступа между объектами (защищенные объекты, узлы, сети):
    - Источник доступа (ProtectedObject, узел, или сеть)
    - Назначение доступа (ProtectedObject, узел, или сеть)
    - Параметры доступа (протокол, порты, сервис)
    - Применение правил на узлы сети
    
    Если указан node_id, показывает только политики для этого узла.
    Иначе показывает все политики, сгруппированные по узлам.
    
    Параметры сортировки:
    - sort_by: поле для сортировки (id, node_id, node_name, protocol, status, created_at, priority)
    - order: направление сортировки (asc, desc)
    """
    # Параметры сортировки
    sort_by = request.args.get('sort_by', 'priority')
    order = request.args.get('order', 'asc')
    
    # Получаем все узлы для группировки
    all_nodes = General.query.filter(General.role.in_(['Omnissiah', 'Magos', 'Cognitor'])).all()
    
    # Если указан конкретный узел, показываем только его политики
    if node_id:
        node = db.session.get(General, node_id)
        if not node:
            flash('Узел не найден', 'error')
            return redirect(url_for('access_policy'))
        
        # Получаем правила, связанные с этим узлом
        rules = get_rules_for_node(node)
        
        # Применяем сортировку к правилам узла
        if sort_by == 'id':
            rules = sorted(rules, key=lambda r: r.id, reverse=(order == 'desc'))
        elif sort_by == 'protocol':
            rules = sorted(rules, key=lambda r: r.protocol or '', reverse=(order == 'desc'))
        elif sort_by == 'status':
            rules = sorted(rules, key=lambda r: r.status or '', reverse=(order == 'desc'))
        elif sort_by == 'created_at':
            rules = sorted(rules, key=lambda r: r.created_at or datetime.min, reverse=(order == 'desc'))
        elif sort_by == 'priority':
            rules = sorted(rules, key=lambda r: (r.priority if hasattr(r, 'priority') and r.priority is not None else 100), reverse=(order == 'desc'))
        elif sort_by == 'node_name':
            # Для одного узла сортировка по имени не имеет смысла, но оставляем для совместимости
            pass
        elif sort_by == 'source':
            rules = sorted(rules, key=lambda r: r.get_source_display() if hasattr(r, 'get_source_display') else '', reverse=(order == 'desc'))
        elif sort_by == 'destination':
            rules = sorted(rules, key=lambda r: r.get_destination_display() if hasattr(r, 'get_destination_display') else '', reverse=(order == 'desc'))
        elif sort_by == 'ports':
            def get_ports_key(r):
                if r.service:
                    return r.service
                elif r.ports:
                    return r.ports
                return ''
            rules = sorted(rules, key=get_ports_key, reverse=(order == 'desc'))
        
        # Группируем правила по узлам для отображения
        if node.role == 'Magos':
            # Для Magos группируем по самому Magos и его Cognitor-ам
            rules_by_node = {node.name: []}
            cognitors = General.query.filter_by(parent_id=node.id, role='Cognitor').all()
            for cognitor in cognitors:
                rules_by_node[cognitor.name] = []
            
            # Распределяем правила по узлам
            for rule in rules:
                related_node = get_related_node_for_rule(rule)
                if related_node:
                    if related_node.id == node.id:
                        rules_by_node[node.name].append(rule)
                    elif related_node.parent_id == node.id and related_node.role == 'Cognitor':
                        rules_by_node[related_node.name].append(rule)
                else:
                    # Если не удалось определить узел, добавляем к основному узлу
                    rules_by_node[node.name].append(rule)
        else:
            # Для Cognitor или Omnissiah просто группируем по текущему узлу
            rules_by_node = {node.name: rules}
        
        current_node = node
        # Создаем словарь узлов по ID для быстрого доступа в шаблоне
        nodes_dict = {node.id: node for node in all_nodes}
    else:
        # Получаем все правила
        try:
            query = AccessPolicyRule.query
            # Применяем сортировку
            if sort_by == 'id':
                query = query.order_by(AccessPolicyRule.id.desc() if order == 'desc' else AccessPolicyRule.id.asc())
            elif sort_by == 'protocol':
                query = query.order_by(AccessPolicyRule.protocol.desc() if order == 'desc' else AccessPolicyRule.protocol.asc())
            elif sort_by == 'status':
                query = query.order_by(AccessPolicyRule.status.desc() if order == 'desc' else AccessPolicyRule.status.asc())
            elif sort_by == 'created_at':
                query = query.order_by(AccessPolicyRule.created_at.desc() if order == 'desc' else AccessPolicyRule.created_at.asc())
            elif sort_by == 'priority':
                query = query.order_by(AccessPolicyRule.priority.desc() if order == 'desc' else AccessPolicyRule.priority.asc())
            elif sort_by == 'ports':
                # Сначала сортируем по service, затем по ports
                # Для SQLite используем более простую сортировку
                if order == 'desc':
                    query = query.order_by(
                        db.func.coalesce(AccessPolicyRule.service, '').desc(),
                        db.func.coalesce(AccessPolicyRule.ports, '').desc()
                    )
                else:
                    query = query.order_by(
                        db.func.coalesce(AccessPolicyRule.service, '').asc(),
                        db.func.coalesce(AccessPolicyRule.ports, '').asc()
                    )
            else:
                # По умолчанию сортируем по priority, затем по created_at
                query = query.order_by(AccessPolicyRule.priority.asc(), AccessPolicyRule.created_at.desc())
            
            all_rules = query.all()
        except Exception as e:
            # Если колонка priority не существует, сортируем только по created_at
            app.logger.warning(f"Ошибка сортировки, используем сортировку по created_at: {e}")
            all_rules = AccessPolicyRule.query.order_by(AccessPolicyRule.created_at.desc()).all()
        
        # Если сортировка по полям, требующим вычислений, сортируем в Python
        if sort_by in ['node_id', 'node_name', 'source', 'destination']:
            def get_sort_key(rule):
                if sort_by == 'node_id':
                    node = get_related_node_for_rule(rule)
                    return node.id if node else 0
                elif sort_by == 'node_name':
                    node = get_related_node_for_rule(rule)
                    return node.name if node else ''
                elif sort_by == 'source':
                    return rule.get_source_display() if hasattr(rule, 'get_source_display') else ''
                elif sort_by == 'destination':
                    return rule.get_destination_display() if hasattr(rule, 'get_destination_display') else ''
                return ''
            
            all_rules = sorted(all_rules, key=get_sort_key, reverse=(order == 'desc'))
        
        rules = all_rules  # Передаем все правила для отображения в таблице
        rules_by_node = group_rules_by_node(all_rules, all_nodes)
        current_node = None
    
    # Получаем защищенные объекты для выбора
    protected_objects = ProtectedObject.query.filter_by(is_active=True).all()
    
    # Получаем узлы для выбора
    nodes = General.query.filter(General.role.in_(['Omnissiah', 'Magos', 'Cognitor'])).all()
    
    # Создаем словарь узлов по ID для быстрого доступа в шаблоне
    nodes_dict = {node.id: node for node in all_nodes}
    
    # Подготавливаем данные для выбора источника и назначения
    source_options = []
    destination_options = []
    
    # Добавляем защищенные объекты
    for obj in protected_objects:
        display_name = f"{obj.network} @ {obj.node.role}:{obj.node.name}"
        source_options.append({
            'type': 'protected_object',
            'id': obj.id,
            'display': display_name,
            'network': obj.network
        })
        destination_options.append({
            'type': 'protected_object',
            'id': obj.id,
            'display': display_name,
            'network': obj.network
        })
    
    # Добавляем узлы
    for node in nodes:
        display_name = f"{node.role}: {node.name}"
        source_options.append({
            'type': 'node',
            'id': node.id,
            'display': display_name,
            'network': node.ip_pool.split('/')[0] if node.ip_pool else None
        })
        destination_options.append({
            'type': 'node',
            'id': node.id,
            'display': display_name,
            'network': node.ip_pool.split('/')[0] if node.ip_pool else None
        })
    
    # Предустановленные сервисы
    services = [
        {'name': 'SSH', 'protocol': 'tcp', 'ports': '22'},
        {'name': 'HTTP', 'protocol': 'tcp', 'ports': '80'},
        {'name': 'HTTPS', 'protocol': 'tcp', 'ports': '443'},
        {'name': 'RDP', 'protocol': 'tcp', 'ports': '3389'},
        {'name': 'VNC', 'protocol': 'tcp', 'ports': '5900'},
        {'name': 'Ping', 'protocol': 'icmp', 'ports': None},
    ]
    
    return render_template('access_policy.html',
                         rules=rules,  # Передаем правила для отображения в таблице
                         rules_by_node=rules_by_node,
                         all_nodes=all_nodes,
                         nodes_dict=nodes_dict,  # Словарь узлов по ID
                         current_node=current_node,
                         protected_objects=protected_objects,  # Для определения узлов через защищенные объекты
                         source_options=source_options,
                         destination_options=destination_options,
                         services=services,
                         sort_by=sort_by,
                         sort_order=order)


@app.route('/access_policy/view/<int:rule_id>')
@login_required
@admin_required
def view_access_policy_config(rule_id):
    """
    Страница просмотра полной конфигурации правила
    """
    try:
        rule = db.session.get(AccessPolicyRule, rule_id)
        if not rule:
            flash('Правило не найдено', 'error')
            return redirect(url_for('access_policy'))
        
        # Парсим сохраненную конфигурацию
        config_data = None
        if rule.configuration_snapshot:
            try:
                config_data = json.loads(rule.configuration_snapshot)
            except Exception as e:
                app.logger.warning(f"Ошибка парсинга configuration_snapshot: {e}")
        
        # Если конфигурация не сохранена, генерируем для просмотра
        if not config_data:
            try:
                nodes_to_apply = determine_nodes_for_rule(rule)
                iptables_rules = generate_iptables_commands_for_rule(rule)
                routes = generate_routes_for_rule(rule)
                
                config_data = {
                    'iptables_rules': iptables_rules or [],
                    'routes': routes or [],
                    'target_nodes': [{'id': n.id, 'name': n.name, 'role': n.role} for n in nodes_to_apply] if nodes_to_apply else [],
                    'preview_only': True  # Помечаем что это только предпросмотр
                }
            except Exception as e:
                app.logger.error(f"Ошибка генерации конфигурации для правила {rule_id}: {e}", exc_info=True)
                # Для системных правил возвращаем пустую конфигурацию вместо ошибки
                config_data = {
                    'iptables_rules': [],
                    'routes': [],
                    'target_nodes': [],
                    'preview_only': True,
                    'error': f'Не удалось сгенерировать конфигурацию: {str(e)}'
                }
        
        return render_template('access_policy_view.html', rule=rule, config_data=config_data)
    except Exception as e:
        app.logger.error(f"Ошибка при просмотре правила {rule_id}: {e}", exc_info=True)
        flash(f'Ошибка при загрузке правила: {str(e)}', 'error')
        return redirect(url_for('access_policy'))


@app.route('/api/toggle_vpn/<int:node_id>', methods=['POST'])
@login_required
@admin_required
def api_toggle_vpn(node_id):
    """
    Включение/выключение VPN для узла (локально для Omnissiah)
    """
    try:
        node = db.session.get(General, node_id)
        if not node:
            return jsonify({'success': False, 'error': 'Узел не найден'}), 404
        
        # Для Omnissiah включаем/выключаем локально
        if node.role == 'Omnissiah':
            interface_name = node.name
            if not interface_name:
                return jsonify({'success': False, 'error': 'Имя интерфейса не задано'}), 400
            
            if node.status == 'stopped' or node.status == 'inactive':
                # Включаем VPN
                try:
                    result = subprocess.run(
                        ['sudo', '-n', 'wg-quick', 'up', interface_name],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    
                    # КРИТИЧНО: Разрешаем FORWARD трафик через WireGuard интерфейс на Omnissiah
                    try:
                        # Разрешаем FORWARD трафик через VPN интерфейс
                        subprocess.run(['sudo', '-n', 'iptables', '-A', 'FORWARD', '-i', interface_name, '-j', 'ACCEPT'], 
                                     check=False, timeout=5)
                        subprocess.run(['sudo', '-n', 'iptables', '-A', 'FORWARD', '-o', interface_name, '-j', 'ACCEPT'], 
                                     check=False, timeout=5)
                        app.logger.info(f"✅ Разрешен FORWARD трафик через VPN интерфейс {interface_name} на Omnissiah")
                    except Exception as e:
                        app.logger.warning(f"⚠️ Ошибка добавления правил FORWARD для {interface_name}: {e}")
                    
                    if result.returncode == 0:
                        # КРИТИЧНО: Синхронизируем пиры после включения VPN
                        try:
                            sync_wireguard_peers(node)
                            app.logger.info(f"✅ Пиры WireGuard синхронизированы для {interface_name}")
                        except Exception as e:
                            app.logger.warning(f"⚠️ Ошибка синхронизации пиров для {interface_name}: {e}")
                        
                        # КРИТИЧНО: Переприменяем системные правила iptables после включения VPN
                        # Это необходимо чтобы сохранить mTLS доступ от узлов
                        # wg-quick up может изменить iptables правила через PostUp скрипты
                        try:
                            from omnissiah_core.nmc_system_rules_generator import create_system_rules_for_omnissiah
                            
                            # Получаем admin_ip из узла
                            admin_ip = node.admin_ip if node.admin_ip else None
                            
                            # Генерируем системные правила
                            system_rules_data, extra_commands_data = create_system_rules_for_omnissiah(
                                node,
                                admin_ip=admin_ip,
                                mtls_port=5001
                            )
                            
                            # Применяем базовые команды (loopback, ESTABLISHED, localhost)
                            if extra_commands_data:
                                basic_commands = [cmd for cmd in extra_commands_data 
                                                 if cmd['chain'] not in ['POLICY', 'OUTPUT']]
                                output_commands = [cmd for cmd in extra_commands_data if cmd['chain'] == 'OUTPUT']
                                
                                # Применяем базовые правила
                                for extra_cmd in basic_commands:
                                    try:
                                        cmd_list = extra_cmd['cmd']
                                        # Проверяем что правило еще не существует перед добавлением
                                        check_cmd = ['sudo', '-n', 'iptables', '-C'] + cmd_list[1:]  # Заменяем -A на -C для проверки
                                        check_result = subprocess.run(check_cmd, capture_output=True, timeout=5)
                                        if check_result.returncode != 0:
                                            # Правило не существует, добавляем
                                            subprocess.run(['sudo', '-n', 'iptables'] + cmd_list, check=False, timeout=5)
                                            app.logger.debug(f"Применена системная команда: {extra_cmd['description']}")
                                    except Exception as cmd_err:
                                        app.logger.debug(f"Ошибка применения команды {extra_cmd['description']}: {cmd_err}")
                                
                                # Применяем OUTPUT правила
                                for extra_cmd in output_commands:
                                    try:
                                        cmd_list = extra_cmd['cmd']
                                        check_cmd = ['sudo', '-n', 'iptables', '-C'] + cmd_list[1:]
                                        check_result = subprocess.run(check_cmd, capture_output=True, timeout=5)
                                        if check_result.returncode != 0:
                                            subprocess.run(['sudo', '-n', 'iptables'] + cmd_list, check=False, timeout=5)
                                            app.logger.debug(f"Применена OUTPUT команда: {extra_cmd['description']}")
                                    except Exception as cmd_err:
                                        app.logger.debug(f"Ошибка применения OUTPUT команды: {cmd_err}")
                            
                            # Применяем системные правила доступа (mTLS, VPN, DNS и т.д.)
                            # Используем существующие правила из БД вместо создания новых
                            existing_system_rules = AccessPolicyRule.query.filter_by(
                                destination_id=node.id,
                                is_system_rule=True,
                                status='applied'
                            ).all()
                            
                            for rule in existing_system_rules:
                                try:
                                    iptables_cmds = generate_iptables_commands_for_rule(rule)
                                    
                                    if iptables_cmds:
                                        for cmd_list in iptables_cmds:
                                            if isinstance(cmd_list, list):
                                                # Проверяем существование правила
                                                try:
                                                    check_cmd = ['sudo', '-n', 'iptables', '-C'] + cmd_list[1:]
                                                    check_result = subprocess.run(check_cmd, capture_output=True, timeout=5)
                                                    if check_result.returncode != 0:
                                                        # Правило не существует, добавляем
                                                        subprocess.run(['sudo', '-n', 'iptables'] + cmd_list, check=False, timeout=5)
                                                        app.logger.debug(f"Применено системное правило: {rule.description}")
                                                except Exception as rule_err:
                                                    app.logger.debug(f"Ошибка применения системного правила: {rule_err}")
                                except Exception as rule_err:
                                    app.logger.debug(f"Ошибка обработки системного правила: {rule_err}")
                            
                            app.logger.info(f"✅ Системные правила iptables переприменены для {interface_name} (mTLS сохранен)")
                        except Exception as rules_err:
                            app.logger.warning(f"⚠️ Ошибка переприменения системных правил для {interface_name}: {rules_err}")
                            import traceback
                            app.logger.debug(traceback.format_exc())
                        
                        node.status = 'active'
                        db.session.commit()
                        return jsonify({
                            'success': True,
                            'message': 'VPN включен',
                            'new_status': 'active'
                        }), 200
                    else:
                        return jsonify({
                            'success': False,
                            'error': f'Ошибка включения VPN: {result.stderr}'
                        }), 500
                except Exception as e:
                    return jsonify({
                        'success': False,
                        'error': f'Ошибка включения VPN: {str(e)}'
                    }), 500
            else:
                # Выключаем VPN
                try:
                    result = subprocess.run(
                        ['sudo', '-n', 'wg-quick', 'down', interface_name],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    node.status = 'stopped'
                    node.last_handshake = None
                    db.session.commit()
                    return jsonify({
                        'success': True,
                        'message': 'VPN выключен',
                        'new_status': 'stopped'
                    }), 200
                except Exception as e:
                    return jsonify({
                        'success': False,
                        'error': f'Ошибка выключения VPN: {str(e)}'
                    }), 500
        else:
            return jsonify({
                'success': False,
                'error': 'Эта функция доступна только для Omnissiah'
            }), 400
            
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Ошибка переключения VPN: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/main_node')
@app.route('/main_node/<int:node_id>')
@login_required
@admin_required
@require_omnissiah
def main_node(node_id=None):
    """
    Страница просмотра главного узла (Omnissiah)
    Показывает информацию об узле и подключенных узлах
    """
    if node_id:
        node = db.session.get(General, node_id)
        if not node:
            flash('Узел не найден', 'error')
            return redirect(url_for('dashboard'))
    else:
        # По умолчанию показываем Omnissiah
        node = General.query.filter_by(role='Omnissiah').first()
        if not node:
            flash('Главный узел не найден. Сначала создайте конфигурацию.', 'danger')
            return redirect(url_for('setup_wizard'))
    
    # Получаем дочерние узлы (Magos и Cognitor)
    if node.role == 'Omnissiah':
        peers = General.query.filter(
            General.role.in_(['Cognitor', 'Magos'])
        ).all()
    else:
        peers = General.query.filter_by(parent_id=node.id, role='Cognitor').all()
    
    # Обогащаем peers данными для отображения
    for peer in peers:
        if peer.parent_id:
            peer.parent_id_obj = db.session.get(General, peer.parent_id)
        else:
            peer.parent_id_obj = None
        
        # Добавляем VPN IP
        peer.vpn_ip = peer.ip_pool.split('/')[0] if peer.ip_pool else None
        
        # Добавляем heartbeat IP адреса
        peer.heartbeat_ips_display = []
        if peer.heartbeat_interfaces:
            try:
                interfaces = json.loads(peer.heartbeat_interfaces)
                for iface in interfaces:
                    if 'name' in iface and 'ip' in iface:
                        ip_addr = iface['ip'].split('/')[0]
                        peer.heartbeat_ips_display.append({
                            'interface': iface['name'],
                            'ip': ip_addr
                        })
            except Exception as e:
                app.logger.warning(f"Ошибка парсинга heartbeat_interfaces для {peer.name}: {e}")
        
        # Основной heartbeat IP
        if peer.heartbeat_ips_display:
            peer.heartbeat_ip_display = peer.heartbeat_ips_display[0]['ip'] if peer.heartbeat_ips_display else None
        else:
            peer.heartbeat_ip_display = peer.heartbeat_ip if peer.heartbeat_ip else None
        
        from management_status import peer_status
        observed = peer_status(peer)
        peer.vpn_status_display = ('online' if observed['vpn_connected'] else
                                   'active' if observed['vpn_enabled'] else 'offline')
        peer.mtls_status_display = 'online' if observed['mtls_enabled'] else 'offline'
        peer.management_status_display = 'online' if observed['service_active'] else 'offline'

    # Получаем интерфейсы для текущего узла
    interfaces = None
    if node.role == 'Omnissiah':
        interfaces = get_system_interfaces(node, include_down=True)
    elif node.role in ['Magos', 'Cognitor']:
        try:
            node_dict = node.__dict__
            node_dict_clean = {k: v for k, v in node_dict.items() if not k.startswith('_sa_')}
            node_data = {
                'name': str(node_dict_clean.get('name')) if node_dict_clean.get('name') else None,
                'role': str(node_dict_clean.get('role')) if node_dict_clean.get('role') else None,
                'ip_pool': str(node_dict_clean.get('ip_pool')) if node_dict_clean.get('ip_pool') else None,
                'heartbeat_ip': str(node_dict_clean.get('heartbeat_ip')) if node_dict_clean.get('heartbeat_ip') else None,
                'heartbeat_interfaces': str(node_dict_clean.get('heartbeat_interfaces')) if node_dict_clean.get('heartbeat_interfaces') else None
            }
        except Exception:
            try:
                node_data = {
                    'name': str(node.name) if node.name else None,
                    'role': str(node.role) if node.role else None,
                    'ip_pool': str(node.ip_pool) if node.ip_pool else None,
                    'heartbeat_ip': str(node.heartbeat_ip) if node.heartbeat_ip else None,
                    'heartbeat_interfaces': str(node.heartbeat_interfaces) if node.heartbeat_interfaces else None
                }
            except Exception:
                node_data = {'name': None, 'role': None, 'ip_pool': None, 'heartbeat_ip': None, 'heartbeat_interfaces': None}
        
        interfaces_raw = get_interfaces_with_ips(node_data)
        interfaces = []
        for iface in interfaces_raw:
            interfaces.append({
                'name': iface.get('name', ''),
                'ip': iface.get('ip', '')
            })
    
    # Management heartbeat, application health and VPN are independent.
    from management_status import describe, peer_status
    security_status = (get_node_security_status(node) if node.role == 'Omnissiah'
                       else describe(peer_status(node)))

    return render_template('main_node.html',
                           node=node,
                           peers=peers,
                           STATUS_CHOICES=STATUS_CHOICES,
                           get_system_interfaces=get_system_interfaces,
                           interfaces=interfaces,
                           security_status=security_status)


@app.route('/manage_node/<int:node_id>')
@login_required
@admin_required
def manage_node(node_id):
    """
    Универсальная страница управления узлом (Omnissiah, Magos, Cognitor)
    """
    node = db.session.get(General, node_id)
    if not node:
        flash('Узел не найден', 'error')
        return redirect(url_for('dashboard'))
    
    # Для Omnissiah перенаправляем на main_node
    if node.role == 'Omnissiah':
        return redirect(url_for('main_node', node_id=node_id))
    
    # Получаем информацию о родителе
    parent = None
    if node.parent_id:
        parent = db.session.get(General, node.parent_id)
    
    # Получаем Omnissiah для получения admin_ip
    omnissiah = General.query.filter_by(role='Omnissiah').first()
    
    # Получаем подключенные узлы (для Magos - Cognitor'ы, которые являются его детьми)
    peers = []
    if node.role == 'Magos':
        peers = General.query.filter_by(parent_id=node.id, role='Cognitor').all()
    
    # Обогащаем peers данными для отображения (аналогично main_node)
    for peer in peers:
        if peer.parent_id:
            peer.parent_id_obj = db.session.get(General, peer.parent_id)
        else:
            peer.parent_id_obj = None
        
        # Добавляем VPN IP
        peer.vpn_ip = peer.ip_pool.split('/')[0] if peer.ip_pool else None
        
        # Добавляем heartbeat IP адреса
        peer.heartbeat_ips_display = []
        if peer.heartbeat_interfaces:
            try:
                interfaces = json.loads(peer.heartbeat_interfaces)
                for iface in interfaces:
                    if 'name' in iface and 'ip' in iface:
                        ip_addr = iface['ip'].split('/')[0]
                        peer.heartbeat_ips_display.append({
                            'interface': iface['name'],
                            'ip': ip_addr
                        })
            except Exception as e:
                app.logger.warning(f"Ошибка парсинга heartbeat_interfaces для {peer.name}: {e}")
        
        # Основной heartbeat IP
        if peer.heartbeat_ips_display:
            peer.heartbeat_ip_display = peer.heartbeat_ips_display[0]['ip'] if peer.heartbeat_ips_display else None
        else:
            peer.heartbeat_ip_display = peer.heartbeat_ip if peer.heartbeat_ip else None
        
        from management_status import peer_status
        observed = peer_status(peer)
        peer.vpn_status_display = ('online' if observed['vpn_connected'] else
                                   'active' if observed['vpn_enabled'] else 'offline')
        peer.mtls_status_display = 'online' if observed['mtls_enabled'] else 'offline'
        peer.management_status_display = 'online' if observed['service_active'] else 'offline'

    from management_status import peer_status
    observed_vpn = peer_status(node)
    return render_template('manage_node.html',
                           observed_vpn=observed_vpn,
                           node=node,
                           parent=parent,
                           omnissiah=omnissiah,
                           peers=peers,
                           STATUS_CHOICES=STATUS_CHOICES)


@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')

    if not check_password_hash(current_user.password_hash, current_password):
        flash('Неверный текущий пароль', 'danger')
        return redirect(url_for('profile'))

    current_user.password_hash = generate_password_hash(new_password)
    db.session.commit()
    flash('Пароль успешно изменен', 'success')
    return redirect(url_for('profile'))


@app.route('/api/toggle_peer_tunnel/<int:peer_id>', methods=['POST'])
@login_required
@admin_required
def api_toggle_peer_tunnel(peer_id):
    """
    Переключает туннель peer: комментирует или раскомментирует peer в WireGuard конфиге на Omnissiah
    """
    try:
        peer = db.session.get(General, peer_id)
        if not peer:
            return jsonify({'success': False, 'error': 'Peer не найден'}), 404
        
        # Только для клиентов Omnissiah
        omnissiah = General.query.filter_by(role='Omnissiah').first()
        if not omnissiah:
            return jsonify({'success': False, 'error': 'Omnissiah не найден'}), 404
        
        if not peer.public_key:
            return jsonify({'success': False, 'error': 'У peer нет публичного ключа'}), 400
        
        # Импортируем утилиту для работы с конфигом
        from omnissiah_utils.nmc_wireguard_config_utils import comment_peer_in_config, uncomment_peer_in_config, is_peer_commented
        
        interface_name = omnissiah.name
        config_path = f"/etc/wireguard/{interface_name}.conf"
        
        # Проверяем текущее состояние peer
        is_commented, msg = is_peer_commented(interface_name, peer.public_key, config_path)
        
        if is_commented is None:
            return jsonify({'success': False, 'error': f'Peer не найден в конфигурации: {msg}'}), 404
        
        # Переключаем состояние
        if is_commented:
            # Раскомментируем
            success, message = uncomment_peer_in_config(interface_name, peer.public_key, config_path)
            if success:
                # Перезагружаем WireGuard интерфейс для применения изменений
                try:
                    subprocess.run(['sudo', '-n', 'wg-quick', 'down', interface_name], 
                                 capture_output=True, timeout=5)
                    subprocess.run(['sudo', '-n', 'wg-quick', 'up', interface_name], 
                                 capture_output=True, timeout=5)
                    sync_wireguard_peers(omnissiah)
                except Exception as e:
                    app.logger.warning(f"Ошибка перезагрузки WireGuard после раскомментирования: {str(e)}")
                return jsonify({
                    'success': True,
                    'message': 'Туннель включен',
                    'tunnel_enabled': True
                }), 200
            else:
                return jsonify({'success': False, 'error': message}), 500
        else:
            # Комментируем
            success, message = comment_peer_in_config(interface_name, peer.public_key, config_path)
            if success:
                # Перезагружаем WireGuard интерфейс для применения изменений
                try:
                    subprocess.run(['sudo', '-n', 'wg-quick', 'down', interface_name], 
                                 capture_output=True, timeout=5)
                    subprocess.run(['sudo', '-n', 'wg-quick', 'up', interface_name], 
                                 capture_output=True, timeout=5)
                except Exception as e:
                    app.logger.warning(f"Ошибка перезагрузки WireGuard после комментирования: {str(e)}")
                return jsonify({
                    'success': True,
                    'message': 'Туннель отключен',
                    'tunnel_enabled': False
                }), 200
            else:
                return jsonify({'success': False, 'error': message}), 500
    
    except Exception as e:
        app.logger.error(f"Ошибка переключения туннеля peer {peer_id}: {str(e)}")
        import traceback
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/delete_peer/<int:peer_id>', methods=['POST'])
@login_required
@admin_required
def delete_peer(peer_id):
    peer = General.query.get_or_404(peer_id)

    # Получаем родительский объект (Magos или Omnissiah)
    parent = General.query.get(peer.parent_id) if peer.parent_id else None

    # Если это Cognitor, у которого родитель — Magos
    if peer.role == 'Cognitor' and parent and parent.role == 'Magos':
        peer.sent_to_magos = 2  # Статус "ожидание удаления"
        db.session.commit()

        # Формируем endpoint Magos (только если указан)
        magos_endpoint = parent.endpoint or ""
        magos_ip = magos_endpoint.split(':')[0] if ':' in magos_endpoint else magos_endpoint
        magos_port = magos_endpoint.split(':')[1] if ':' in magos_endpoint else "5001"
        if magos_ip:
            magos_node = db.session.get(General, peer.parent_id)
            if magos_node:
                magos_url = get_api_url(magos_node, endpoint="/api/remove_peer", default_port=5001)
                verify_ssl = magos_node.nginx_cert_type != 'self-signed' if magos_node.nginx_enabled else True
            else:
                # Fallback если узел не найден
                magos_url = f"http://{magos_ip}:{magos_port}/api/remove_peer"
                verify_ssl = True
            try:
                resp = requests.post(
                    magos_url,
                    json={"cognitor_name": peer.name, "child_name": peer.name},  # Поддержка старого формата
                    timeout=10,
                    verify=verify_ssl
                )
                if resp.status_code == 200:
                    flash('Команда на удаление отправлена на Magos. После подтверждения запись удалится автоматически.', 'info')
                else:
                    flash(f'Ошибка отправки команды на удаление: {resp.text}', 'danger')
            except Exception as e:
                flash(f'Ошибка отправки команды на удаление: {str(e)}', 'danger')
        else:
            flash('Endpoint у Magos не задан — команда на удаление не отправлена.', 'danger')

        # Не удаляем Cognitor из базы! Ждём ack от Magos
        return redirect(url_for('dashboard'))

    # Все остальные случаи — удаляем сразу
    db.session.delete(peer)
    db.session.commit()
    flash('Клиент удалён.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/download_config/<int:node_id>')
@login_required
@admin_required
def download_config(node_id):
    node = db.session.get(General, node_id)
    if not node:
        abort(404)

    # Разрешаем скачивание для Cognitor и Magos (исправлено условие)
    if node.role not in ['Cognitor', 'Magos']:
        abort(400, "Скачивание конфигурации доступно только для Cognitor и Magos")

    # Для Cognitor используем непосредственного родителя
    if node.role == 'Cognitor':
        parent = node.parent
        if not parent:
            abort(400, "Для Cognitor не указан родительский узел")
    # Для Magos используем главный сервер
    else:
        parent = General.query.filter_by(role='Omnissiah').first()
        if not parent:
            abort(400, "Главный сервер не найден")

    # Проверяем наличие обязательных полей
    if not node or not node.ip_pool:
        abort(400, "Узел не найден или отсутствует ip_pool")
    
    # Получаем расшифрованный private_key
    decrypted_private_key = get_decrypted_private_key(node)
    if not decrypted_private_key:
        abort(500, "Не удалось получить private_key для узла")

    # Формируем конфигурацию ТОЛЬКО для текущего узла
    config_content = f"""[Interface]
    PrivateKey = {decrypted_private_key}
    Address = {node.ip_pool}
    DNS = {parent.dns if parent and parent.dns else '1.1.1.1'}
    MTU = {parent.mtu if parent and parent.mtu else 1420}
    """

    # Добавляем ListenPort, если это Magos
    if node.role == 'Magos':
        config_content += f"ListenPort = {node.listen_port}\n"

    # Добавляем peer к родителю (Omnissiah)
    config_content += f"""
    
[Peer]
PublicKey = {parent.public_key}
AllowedIPs = 0.0.0.0/0
Endpoint = {parent.endpoint}:{parent.listen_port}
PersistentKeepalive = 25"""
    if node.preshared_key:
        config_content += f"\nPresharedKey = {node.preshared_key}"

    # 🔥 Добавляем [Peer] блоки для дочерних Cognitor, если этот узел — Magos
    if node.role == 'Magos':
        cognitors = General.query.filter_by(parent_id=node.id).all()
        for cognitor in cognitors:
            allowed_ip = cognitor.ip_pool.split('/')[0] + '/32'
            config_content += f"""
            
[Peer]
PublicKey = {cognitor.public_key}
AllowedIPs = {allowed_ip}
PersistentKeepalive = 25"""
            if cognitor.preshared_key:
                config_content += f"\nPresharedKey = {cognitor.preshared_key}"

    return send_file(
        BytesIO(config_content.encode()),
        as_attachment=True,
        download_name=f"{node.name}.conf"
    )

@app.route('/download_installer/<int:node_id>')
@login_required
@admin_required
def download_installer(node_id):
    node = db.session.get(General, node_id)
    if not node:
        abort(404)

    if node.role not in ['Cognitor', 'Magos']:
        abort(400, "Доступно только для Cognitor и Magos")

    # 🧠 Определяем родителя
    if node.role == 'Cognitor':
        parent = node.parent
    else:  # Magos
        parent = General.query.filter_by(role='Omnissiah').first()

    if not parent:
        abort(400, "Главный узел не найден")

    # Получаем расшифрованный private_key
    decrypted_private_key = get_decrypted_private_key(node)
    if not decrypted_private_key:
        abort(500, "Не удалось получить private_key для узла")

    # 🔐 Генерация .conf
    config_content = f"""[Interface]
PrivateKey = {decrypted_private_key}
Address = {node.ip_pool}
DNS = {parent.dns}
MTU = {parent.mtu}
"""

    # Добавляем ListenPort, если это Magos
    if node.role == 'Magos':
        config_content += f"ListenPort = {node.listen_port}\n"

    # Добавляем peer к родителю (Omnissiah)
    config_content += f"""
    
[Peer]
PublicKey = {parent.public_key}
AllowedIPs = 0.0.0.0/0
Endpoint = {parent.endpoint}:{parent.listen_port}
PersistentKeepalive = 25"""
    if node.preshared_key:
        config_content += f"\nPresharedKey = {node.preshared_key}"

    # 🔥 Добавляем [Peer] блоки для дочерних Cognitor, если этот узел — Magos
    if node.role == 'Magos':
        cognitors = General.query.filter_by(parent_id=node.id).all()
        for cognitor in cognitors:
            allowed_ip = cognitor.ip_pool.split('/')[0] + '/32'
            config_content += f"""
            
[Peer]
PublicKey = {cognitor.public_key}
AllowedIPs = {allowed_ip}
PersistentKeepalive = 25"""
            if cognitor.preshared_key:
                config_content += f"\nPresharedKey = {cognitor.preshared_key}"

    # Определяем URL главного сервера для агента
    # ВАЖНО: Для агентов используем IP адрес вместо домена (use_ip=True)
    # чтобы избежать проблем с DNS резолвингом на удаленных узлах
    omnissiah_server = General.query.filter_by(role='Omnissiah').first()
    if omnissiah_server:
        server_url = get_api_url(omnissiah_server, endpoint="", default_port=33787, use_ip=True)
    else:
        server_url = "http://127.0.0.1:33787"
    
    bootstrap_config = {
        "name": node.name,
        "server_url": server_url,
        "ip_pool": node.ip_pool,
        "listen_port": node.listen_port,
        "dns": node.dns,
        "mtu": node.mtu,
        "public_key": node.public_key,
        "private_key": node.private_key,
        "endpoint": node.endpoint,
        "preshared_key": node.preshared_key,
        "role": node.role,
        "parent_id": node.parent_id,
        "api_token": "",  # Пока не используется, можно добавить позже
        "mtls_cert_file": "",
        "mtls_key_file": "",
        "mtls_ca_cert_file": "",
        "master_key": os.environ.get('WG_MASTER_KEY', '')  # Для расшифровки конфигураций от Omnissiah
    }
    
    # Если у Magos есть mTLS сертификаты, добавляем их пути и включаем в архив
    if node.role == 'Magos' and node.mtls_enabled and node.mtls_server_cert_path and node.mtls_server_key_path:
        # Пути относительно директории установки агента
        bootstrap_config["mtls_cert_file"] = f"mtls/{Path(node.mtls_server_cert_path).name}"
        bootstrap_config["mtls_key_file"] = f"mtls/{Path(node.mtls_server_key_path).name}"
        
        # Если есть CA сертификат для проверки сервера
        if node.mtls_ca_cert_path:
            bootstrap_config["mtls_ca_cert_file"] = f"mtls/{Path(node.mtls_ca_cert_path).name}"
    
    # 📦 Упаковываем ZIP
    memory_file = BytesIO()
    with zipfile.ZipFile(memory_file, 'w') as zf:
        zf.writestr(f"{node.name}.conf", config_content)
        zf.writestr("bootstrap_config.json", json.dumps(bootstrap_config, indent=2))
        
        # Добавляем mTLS сертификаты, если они есть
        if node.role == 'Magos' and node.mtls_enabled:
            if node.mtls_server_cert_path and Path(node.mtls_server_cert_path).exists():
                zf.write(node.mtls_server_cert_path, f"mtls/{Path(node.mtls_server_cert_path).name}")
            if node.mtls_server_key_path and Path(node.mtls_server_key_path).exists():
                zf.write(node.mtls_server_key_path, f"mtls/{Path(node.mtls_server_key_path).name}")
            # Добавляем CA сертификат для проверки сервера
            if node.mtls_ca_cert_path and Path(node.mtls_ca_cert_path).exists():
                zf.write(node.mtls_ca_cert_path, f"mtls/{Path(node.mtls_ca_cert_path).name}")

    memory_file.seek(0)

    return send_file(
        memory_file,
        download_name=f"{node.name}_installer.zip",
        as_attachment=True
    )

def check_wg_interface(interface):
    """Безопасная проверка интерфейса WG"""
    try:
        # Быстрая проверка через ip link (меньше ошибок, чем wg show)
        result = subprocess.run(
            ['ip', 'link', 'show', 'dev', interface],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=2
        )
        return result.returncode == 0
    except Exception as e:
        current_app.logger.debug(f"Ошибка проверки интерфейса {interface}: {str(e)}")
        return False


def get_node_security_status(node):
    from management_status import controller_status, describe
    peers = General.query.filter_by(role='Magos').all()
    return describe(controller_status(node, peers))


def sync_wireguard_peers(omnissiah_config):
    """
    Синхронизирует пиры WireGuard на Omnissiah с данными из БД
    Добавляет всех активных Magos узлов как peers
    
    ВАЖНО: endpoint для peer на Omnissiah должен быть IP:PORT Magos (откуда он подключается)
    Но Magos подключается к Omnissiah, поэтому на стороне Magos endpoint = Omnissiah IP:PORT
    """
    import sys  # КРИТИЧНО: Импортируем sys в начале функции для использования в print()
    
    if not omnissiah_config or omnissiah_config.role != 'Omnissiah':
        return False
    
    try:
        interface_name = omnissiah_config.name
        # Ищем все активные Magos узлы (status может быть 'active' или 'online')
        magos_nodes = General.query.filter(
            General.role == 'Magos',
            General.status.in_(['active', 'online'])
        ).all()
        
        # Получаем текущие пиры из WireGuard
        current_peers = set()
        try:
            result = subprocess.run(
                ["sudo", "-n", "wg", "show", interface_name],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                # Парсим вывод wg show для получения публичных ключей пиров
                for line in result.stdout.split('\n'):
                    if line.strip().startswith('peer: '):
                        peer_key = line.strip().replace('peer: ', '').strip()
                        if peer_key:
                            current_peers.add(peer_key)
        except Exception as e:
            app.logger.debug(f"Ошибка получения текущих пиров: {str(e)}")
            pass
        
        # Добавляем недостающие пиры
        app.logger.info(f"🔍 Найдено {len(magos_nodes)} активных Magos узлов для синхронизации")
        print(f"🔍 Найдено {len(magos_nodes)} активных Magos узлов для синхронизации", file=sys.stderr, flush=True)
        
        for magos in magos_nodes:
            app.logger.info(f"🔍 Обрабатываем Magos {magos.name}: public_key={magos.public_key[:20] if magos.public_key else 'None'}...")
            print(f"🔍 Обрабатываем Magos {magos.name}", file=sys.stderr, flush=True)
            
            if not magos.public_key:
                app.logger.warning(f"⚠️ У Magos {magos.name} нет public_key, пропускаем")
                print(f"⚠️ У Magos {magos.name} нет public_key, пропускаем", file=sys.stderr, flush=True)
                continue
            
            # Проверяем наличие endpoint или heartbeat_ip
            if not magos.endpoint and not magos.heartbeat_ip:
                app.logger.warning(f"⚠️ У Magos {magos.name} нет endpoint и heartbeat_ip, пропускаем")
                print(f"⚠️ У Magos {magos.name} нет endpoint и heartbeat_ip, пропускаем", file=sys.stderr, flush=True)
                continue
            
            # Проверяем, есть ли уже этот peer
            # Если пир существует, мы все равно обновим его allowed-ips,
            # чтобы включить новые защищенные подсети
            peer_exists = magos.public_key in current_peers
            
            # Добавляем peer для Magos
            magos_ip = magos.ip_pool.split('/')[0] if magos.ip_pool else None
            if not magos_ip:
                continue
            
            # КРИТИЧНО: На сервере (Omnissiah) НЕ должно быть endpoint для пиров!
            # Endpoint указывается только в конфигурации клиента (Magos), который подключается к серверу
            # Сервер пассивно слушает, клиенты инициируют подключение
            # Поэтому мы НЕ добавляем endpoint для пиров на Omnissiah
            
            # Формируем список allowed-ips: VPN IP + все защищенные подсети для этого Magos
            allowed_ips_list = [f"{magos_ip}/32"]
            
            # Добавляем защищенные подсети для этого Magos узла
            protected_objects = ProtectedObject.query.filter_by(
                node_id=magos.id,
                is_active=True
            ).all()
            
            for protected_obj in protected_objects:
                # Проверяем, что подсеть не перекрывается с VPN IP
                try:
                    protected_net = ip_network(protected_obj.network, strict=False)
                    vpn_net = ip_network(magos.ip_pool, strict=False)
                    # Добавляем подсеть, если она не совпадает с VPN сетью
                    if not (protected_net == vpn_net or protected_net.subnet_of(vpn_net) or vpn_net.subnet_of(protected_net)):
                        allowed_ips_list.append(protected_obj.network)
                        app.logger.debug(f"Добавляем защищенную подсеть {protected_obj.network} для {magos.name}")
                except Exception as e:
                    app.logger.warning(f"Ошибка обработки защищенной подсети {protected_obj.network}: {str(e)}")
            
            # Объединяем allowed-ips в одну строку через запятую
            allowed_ips_str = ",".join(allowed_ips_list)
            
            # КРИТИЧНО: На сервере (Omnissiah) НЕ должно быть endpoint для пиров!
            # Endpoint указывается только в конфигурации клиента (Magos), который подключается к серверу
            # Сервер пассивно слушает, клиенты инициируют подключение
            
            # КРИТИЧНО: Логируем информацию о peer перед добавлением
            app.logger.info(f"🔵 Добавляем peer для {magos.name}:")
            app.logger.info(f"  - PublicKey: {magos.public_key[:16]}...")
            app.logger.info(f"  - AllowedIPs: {allowed_ips_str}")
            app.logger.info(f"  - VPN IP: {magos_ip}")
            app.logger.info(f"  - БЕЗ endpoint (Omnissiah - сервер, Magos подключается к нему)")
            print(f"🔵 Добавляем peer для {magos.name}:", file=sys.stderr, flush=True)
            print(f"  - PublicKey: {magos.public_key[:16]}...", file=sys.stderr, flush=True)
            print(f"  - AllowedIPs: {allowed_ips_str}", file=sys.stderr, flush=True)
            print(f"  - БЕЗ endpoint (Omnissiah - сервер)", file=sys.stderr, flush=True)
            
            # Команда для добавления или обновления пира (wg set обновляет если пир существует)
            # КРИТИЧНО: НЕ добавляем endpoint для пиров на сервере!
            cmd = [
                "sudo", "-n", "wg", "set", interface_name,
                "peer", magos.public_key,
                "allowed-ips", allowed_ips_str,
                "persistent-keepalive", "25"
            ]
            
            # Добавляем preshared-key через временный файл
            if magos.preshared_key:
                tmp_key_path = None
                try:
                    with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp_key:
                        tmp_key.write(magos.preshared_key)
                        tmp_key_path = tmp_key.name
                    
                    cmd.extend(["preshared-key", tmp_key_path])
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    if result.returncode != 0:
                        app.logger.warning(f"Не удалось добавить peer {magos.name}: {result.stderr}")
                        continue
                except Exception as e:
                    app.logger.error(f"Ошибка добавления peer {magos.name}: {str(e)}")
                    continue
                finally:
                    if tmp_key_path and os.path.exists(tmp_key_path):
                        try:
                            os.unlink(tmp_key_path)
                        except Exception:
                            pass
            else:
                try:
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    if result.returncode != 0:
                        app.logger.warning(f"Не удалось добавить peer {magos.name}: {result.stderr}")
                        continue
                except Exception as e:
                    app.logger.error(f"Ошибка добавления peer {magos.name}: {str(e)}")
                    continue
            
            app.logger.info(f"✅ Peer {magos.name} добавлен в WireGuard через wg set")
            print(f"✅ Peer {magos.name} добавлен в WireGuard через wg set", file=sys.stderr, flush=True)
        
        # КРИТИЧНО: Сохраняем конфигурацию в файл после добавления всех пиров
        # Это необходимо чтобы конфигурация сохранилась после перезапуска
        # ВАЖНО: Используем restore_wg_config_from_db для полного восстановления из БД
        # Это гарантирует что Address и все пиры будут в файле
        try:
            restored_config = restore_wg_config_from_db(omnissiah_config)
            if restored_config:
                config_path = f"/etc/wireguard/{interface_name}.conf"
                temp_config_path = None
                
                try:
                    temp_config = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf')
                    temp_config.write(restored_config)
                    temp_config.close()
                    temp_config_path = temp_config.name
                    
                    subprocess.run(['sudo', '-n', 'cp', temp_config_path, config_path], 
                                 check=True, timeout=10)
                    subprocess.run(['sudo', '-n', 'chmod', '600', config_path], 
                                 check=True, timeout=5)
                    
                    # Проверяем что конфигурация действительно содержит пиры
                    # КРИТИЧНО: Используем sudo для чтения файла, так как он принадлежит root
                    try:
                        result = subprocess.run(
                            ['sudo', '-n', 'cat', config_path],
                            capture_output=True,
                            text=True,
                            timeout=5
                        )
                        if result.returncode == 0:
                            config_content = result.stdout
                            peer_count = config_content.count('[Peer]')
                            app.logger.info(f"✅ Конфигурация {interface_name} сохранена с {peer_count} peer(ов)")
                            print(f"✅ Конфигурация {interface_name} сохранена с {peer_count} peer(ов)", file=sys.stderr, flush=True)
                        else:
                            app.logger.warning(f"Не удалось прочитать конфигурацию: {result.stderr}")
                            print(f"⚠️ Не удалось прочитать конфигурацию: {result.stderr}", file=sys.stderr, flush=True)
                    except Exception as read_err:
                        app.logger.warning(f"Ошибка чтения конфигурации: {read_err}")
                        print(f"⚠️ Ошибка чтения конфигурации: {read_err}", file=sys.stderr, flush=True)
                except Exception as restore_err:
                    app.logger.warning(f"Не удалось восстановить конфигурацию: {str(restore_err)}")
                    # Fallback: используем wg-quick save
                    save_result = subprocess.run(
                        ["sudo", "-n", "wg-quick", "save", interface_name],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    if save_result.returncode == 0:
                        app.logger.info(f"Конфигурация WireGuard сохранена через wg-quick save для {interface_name}")
                    else:
                        app.logger.warning(f"Не удалось сохранить конфигурацию WireGuard: {save_result.stderr}")
                finally:
                    if temp_config_path and os.path.exists(temp_config_path):
                        try:
                            os.unlink(temp_config_path)
                        except Exception:
                            pass
            else:
                app.logger.warning(f"Не удалось восстановить конфигурацию из БД для {interface_name}")
                # Fallback: используем wg-quick save
                save_result = subprocess.run(
                    ["sudo", "-n", "wg-quick", "save", interface_name],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if save_result.returncode == 0:
                    app.logger.info(f"Конфигурация WireGuard сохранена через wg-quick save для {interface_name}")
                else:
                    app.logger.warning(f"Не удалось сохранить конфигурацию WireGuard: {save_result.stderr}")
        except Exception as save_err:
            app.logger.error(f"Ошибка сохранения конфигурации WireGuard: {str(save_err)}", exc_info=True)
        
        return True
    except Exception as e:
        app.logger.error(f"Ошибка синхронизации пиров WireGuard: {str(e)}")
        import traceback
        app.logger.error(traceback.format_exc())
        return False


@app.route('/toggle_config/<config_name>', methods=['POST'])
@login_required
@admin_required
def toggle_config(config_name):
    config = General.query.filter_by(name=config_name).first_or_404()

    if config.role == 'Cognitor':
        return jsonify({'success': False, 'error': "Нельзя управлять клиентами напрямую"}), 400

    config_path = f"/etc/wireguard/{config.name}.conf"
    if not os.path.exists(config_path):
        return jsonify({
            'success': False,
            'message': f"Файл конфигурации {config_path} не существует."
        }), 500

    try:
        # Проверяем реальное состояние интерфейса WireGuard
        interface_check = subprocess.run(
            ["sudo", "-n", "wg", "show", config_name],
            capture_output=True,
            text=True,
            timeout=2
        )
        is_interface_up = interface_check.returncode == 0
        app.logger.info(f"toggle_config для {config_name}: статус в БД={config.status}, интерфейс активен={is_interface_up}")
        
        if config.status == 'stopped':
            # Пытаемся включить VPN
            if is_interface_up:
                # Интерфейс уже активен, просто обновляем статус в БД
                app.logger.info(f"Интерфейс {config_name} уже активен, обновляем статус в БД")
                config.status = 'active'
            else:
                # КРИТИЧНО: Восстанавливаем конфигурацию из БД перед запуском
                # Это гарантирует что Address будет в файле
                app.logger.info(f"Восстанавливаем конфигурацию WireGuard из БД для {config_name}...")
                try:
                    restored_config = restore_wg_config_from_db(config)
                    if restored_config:
                        temp_config = None
                        temp_config_path = None
                        
                        try:
                            temp_config = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf')
                            temp_config.write(restored_config)
                            temp_config.close()
                            temp_config_path = temp_config.name
                            
                            subprocess.run(['sudo', '-n', 'cp', temp_config_path, config_path], 
                                         check=True, timeout=10)
                            subprocess.run(['sudo', '-n', 'chmod', '600', config_path], 
                                         check=True, timeout=5)
                            app.logger.info(f"Конфигурация восстановлена из БД для {config_name} (включая Address)")
                        except Exception as restore_err:
                            app.logger.warning(f"Не удалось восстановить конфигурацию: {str(restore_err)}")
                        finally:
                            if temp_config_path and os.path.exists(temp_config_path):
                                try:
                                    os.unlink(temp_config_path)
                                except Exception:
                                    pass
                except Exception as restore_err:
                    app.logger.warning(f"Ошибка восстановления конфигурации: {str(restore_err)}")
                
                app.logger.info(f"Включаем VPN {config_name} через wg-quick up")
                result = subprocess.run(
                    ["sudo", "-n", "/usr/bin/wg-quick", "up", config_name],
                    check=True,
                    stderr=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    text=True
                )
                app.logger.info(f"wg-quick up для {config_name} выполнен успешно: {result.stdout[:100]}")
                config.status = 'active'
            
            # Если это Omnissiah, синхронизируем пиры из БД (всегда, даже если интерфейс уже был активен)
            if config.role == 'Omnissiah':
                app.logger.info(f"Синхронизируем пиры WireGuard для {config_name}")
                try:
                    sync_result = sync_wireguard_peers(config)
                    if sync_result:
                        app.logger.info(f"Пиры успешно синхронизированы для {config_name}")
                    else:
                        app.logger.warning(f"Не удалось синхронизировать пиры для {config_name}, но VPN включен")
                except Exception as sync_error:
                    # Ошибка синхронизации пиров не должна блокировать включение VPN
                    app.logger.error(f"Ошибка синхронизации пиров для {config_name}: {str(sync_error)}")
        else:
            # Пытаемся выключить VPN
            if not is_interface_up:
                # Интерфейс уже выключен, просто обновляем статус в БД
                app.logger.info(f"Интерфейс {config_name} уже выключен, обновляем статус в БД")
                config.status = 'stopped'
                config.last_handshake = None
            else:
                result = subprocess.run(
                    ["sudo", "-n", "/usr/bin/wg-quick", "down", config_name],
                    check=True,
                    stderr=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    text=True
                )
                config.status = 'stopped'
                # Очищаем last_handshake при выключении VPN
                config.last_handshake = None

        db.session.commit()
        return jsonify({
            'success': True,
            'new_status': config.status,
            'message': f"Конфигурация {config_name} успешно {'включена' if config.status == 'active' else 'выключена'}"
        })

    except subprocess.CalledProcessError as e:
        db.session.rollback()
        # При text=True stderr уже строка, не нужно decode
        error_output = e.stderr.strip() if e.stderr else str(e)
        app.logger.error(f"Ошибка выполнения команды wg-quick для {config_name}: {error_output}")
        return jsonify({
            'success': False,
            'message': f"Ошибка команды: {error_output}"
        }), 500

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Ошибка toggle_config для {config_name}: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'message': f"Ошибка: {str(e)}"
        }), 500

# Endpoints /api/heartbeat и /api/magos/heartbeat теперь в nmc_api/heartbeat.py


@app.route('/api/config_update_feedback', methods=['POST'])
def api_config_update_feedback():
    """
    Endpoint для получения фидбэка от Magos агентов после обновления конфигурации
    
    Позволяет отслеживать статус применения обновленных WireGuard конфигураций
    """
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    node_name = data.get('node_name')
    status = data.get('status')
    timestamp = data.get('timestamp')
    
    if not node_name:
        return jsonify({'error': 'Missing node_name'}), 400
    
    node = General.query.filter_by(name=node_name).first()
    if not node:
        return jsonify({'error': 'Node not found'}), 404
    
    app.logger.info(f"✅ Фидбэк от {node_name}: {status} (timestamp: {timestamp})")
    
    # Можно сохранить статус обновления в БД или просто логировать
    # Например, добавить поле config_update_status в модель General в будущем
    
    return jsonify({'success': True, 'message': 'Feedback received'}), 200


@app.route('/traffic_log')
@app.route('/traffic_log/node/<int:node_id>')
@login_required
@admin_required
@require_omnissiah
def traffic_log(node_id=None):
    """
    Страница просмотра журнала трафика
    
    Параметры фильтрации:
    - node_id: фильтр по узлу
    - start_date: начальная дата (YYYY-MM-DD)
    - end_date: конечная дата (YYYY-MM-DD)
    - source_ip: фильтр по IP источника
    - destination_ip: фильтр по IP назначения
    - source_port: фильтр по порту источника
    - destination_port: фильтр по порту назначения
    - protocol: фильтр по протоколу (TCP, UDP, ICMP)
    - action: фильтр по действию (ACCEPT, DROP, REJECT)
    - direction: фильтр по направлению (in - входящий, out - исходящий)
    - sort_by: поле для сортировки
    - order: направление сортировки (asc, desc)
    - page: номер страницы для пагинации
    """
    # Получаем параметры фильтрации
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    source_ip = request.args.get('source_ip', '').strip()
    destination_ip = request.args.get('destination_ip', '').strip()
    source_port = request.args.get('source_port', '').strip()
    destination_port = request.args.get('destination_port', '').strip()
    protocol = request.args.get('protocol', '').strip()
    action = request.args.get('action', '').strip()
    direction = request.args.get('direction', '').strip()
    sort_by = request.args.get('sort_by', 'timestamp')
    order = request.args.get('order', 'desc')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    
    # Базовый запрос
    query = TrafficLog.query
    
    # Фильтр по узлу
    if node_id:
        node = db.session.get(General, node_id)
        if not node:
            flash('Узел не найден', 'error')
            return redirect(url_for('traffic_log'))
        query = query.filter(TrafficLog.node_id == node_id)
    
    # Фильтры по дате
    if start_date:
        try:
            start_dt = datetime.strptime(start_date, '%Y-%m-%d')
            query = query.filter(TrafficLog.timestamp >= start_dt)
        except ValueError:
            flash('Неверный формат начальной даты', 'warning')
    
    if end_date:
        try:
            end_dt = datetime.strptime(end_date, '%Y-%m-%d')
            # Добавляем 23:59:59 к конечной дате
            end_dt = end_dt.replace(hour=23, minute=59, second=59)
            query = query.filter(TrafficLog.timestamp <= end_dt)
        except ValueError:
            flash('Неверный формат конечной даты', 'warning')
    
    # Фильтры по IP
    if source_ip:
        query = query.filter(TrafficLog.source_ip.like(f'%{source_ip}%'))
    if destination_ip:
        query = query.filter(TrafficLog.destination_ip.like(f'%{destination_ip}%'))
    
    # Фильтры по портам
    if source_port:
        try:
            source_port_int = int(source_port)
            query = query.filter(TrafficLog.source_port == source_port_int)
        except ValueError:
            # Если не число, игнорируем фильтр
            pass
    if destination_port:
        try:
            destination_port_int = int(destination_port)
            query = query.filter(TrafficLog.destination_port == destination_port_int)
        except ValueError:
            # Если не число, игнорируем фильтр
            pass
    
    # Фильтры по протоколу, действию и направлению
    if protocol:
        query = query.filter(TrafficLog.protocol == protocol.upper())
    if action:
        query = query.filter(TrafficLog.action == action.upper())
    if direction:
        # direction может быть 'in' (входящий) или 'out' (исходящий)
        query = query.filter(TrafficLog.direction == direction.lower())
    
    # Сортировка
    if sort_by == 'timestamp':
        query = query.order_by(TrafficLog.timestamp.desc() if order == 'desc' else TrafficLog.timestamp.asc())
    elif sort_by == 'node_name':
        query = query.join(General).order_by(
            General.name.desc() if order == 'desc' else General.name.asc()
        )
    elif sort_by == 'source_ip':
        query = query.order_by(TrafficLog.source_ip.desc() if order == 'desc' else TrafficLog.source_ip.asc())
    elif sort_by == 'destination_ip':
        query = query.order_by(TrafficLog.destination_ip.desc() if order == 'desc' else TrafficLog.destination_ip.asc())
    elif sort_by == 'protocol':
        query = query.order_by(TrafficLog.protocol.desc() if order == 'desc' else TrafficLog.protocol.asc())
    elif sort_by == 'action':
        query = query.order_by(TrafficLog.action.desc() if order == 'desc' else TrafficLog.action.asc())
    elif sort_by == 'bytes_sent':
        query = query.order_by(TrafficLog.bytes_sent.desc() if order == 'desc' else TrafficLog.bytes_sent.asc())
    elif sort_by == 'bytes_received':
        query = query.order_by(TrafficLog.bytes_received.desc() if order == 'desc' else TrafficLog.bytes_received.asc())
    else:
        query = query.order_by(TrafficLog.timestamp.desc())
    
    # Пагинация
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    logs = pagination.items
    
    # Получаем все узлы для фильтра
    all_nodes = General.query.filter(General.role.in_(['Omnissiah', 'Magos', 'Cognitor'])).all()
    nodes_dict = {node.id: node for node in all_nodes}
    
    # Статистика
    total_logs = query.count()
    
    # Проверяем запрос на выгрузку
    export_format = request.args.get('format')
    if export_format and request.args.get('export'):
        # Выгружаем данные в указанном формате
        all_logs = query.limit(10000).all()  # Ограничиваем для больших объемов
        
        if export_format == 'csv':
            import csv
            from io import StringIO
            
            output = StringIO()
            writer = csv.writer(output)
            
            # Заголовки
            writer.writerow([
                'Время', 'Узел', 'Источник IP', 'Источник порт', 'Назначение IP', 'Назначение порт',
                'Протокол', 'Действие', 'Байт отправлено', 'Байт получено', 'Пакетов отправлено',
                'Пакетов получено', 'Интерфейс', 'Направление', 'Состояние соединения'
            ])
            
            # Данные
            for log in all_logs:
                writer.writerow([
                    log.timestamp.strftime('%Y-%m-%d %H:%M:%S') if log.timestamp else '',
                    log.node.name if log.node else '',
                    log.source_ip or '',
                    log.source_port or '',
                    log.destination_ip or '',
                    log.destination_port or '',
                    log.protocol or '',
                    log.action or '',
                    log.bytes_sent or 0,
                    log.bytes_received or 0,
                    log.packets_sent or 0,
                    log.packets_received or 0,
                    log.interface or '',
                    log.direction or '',
                    log.connection_state or ''
                ])
            
            output.seek(0)
            filename = f'traffic_log_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            return send_file(
                BytesIO(output.getvalue().encode('utf-8-sig')),  # BOM для Excel
                mimetype='text/csv',
                as_attachment=True,
                download_name=filename
            )
            
        elif export_format == 'json':
            logs_data = []
            for log in all_logs:
                logs_data.append({
                    'timestamp': log.timestamp.isoformat() if log.timestamp else None,
                    'node_name': log.node.name if log.node else None,
                    'source_ip': log.source_ip,
                    'source_port': log.source_port,
                    'destination_ip': log.destination_ip,
                    'destination_port': log.destination_port,
                    'protocol': log.protocol,
                    'action': log.action,
                    'bytes_sent': log.bytes_sent,
                    'bytes_received': log.bytes_received,
                    'packets_sent': log.packets_sent,
                    'packets_received': log.packets_received,
                    'interface': log.interface,
                    'direction': log.direction,
                    'connection_state': log.connection_state
                })
            
            filename = f'traffic_log_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
            return send_file(
                BytesIO(json.dumps(logs_data, indent=2, ensure_ascii=False).encode('utf-8')),
                mimetype='application/json',
                as_attachment=True,
                download_name=filename
            )
    
    return render_template('traffic_log.html',
                         logs=logs,
                         pagination=pagination,
                         nodes_dict=nodes_dict,
                         all_nodes=all_nodes,
                         current_node_id=node_id,
                         start_date=start_date,
                         end_date=end_date,
                         source_ip=source_ip,
                         destination_ip=destination_ip,
                         source_port=source_port,
                         destination_port=destination_port,
                         protocol=protocol,
                         action=action,
                         direction=direction,
                         sort_by=sort_by,
                         order=order,
                         total_logs=total_logs)


# Endpoint /api/traffic_log/clear теперь в nmc_api/traffic.py
# @app.route('/api/traffic_log/clear', methods=['POST'])
# @login_required
# @admin_required
def api_clear_traffic_log():
    """
    API endpoint для очистки журнала трафика
    
    Параметры:
    - node_id: ID узла (опционально, если не указан - очищает все узлы)
    """
    try:
        node_id = request.args.get('node_id', type=int)
        
        if node_id:
            node = db.session.get(General, node_id)
            if not node:
                return jsonify({'success': False, 'error': 'Node not found'}), 404
            
            # Очищаем логи для конкретного узла
            deleted_count = TrafficLog.query.filter_by(node_id=node_id).delete()
            db.session.commit()
            
            # Также отправляем команду на удаленный узел для очистки локального журнала
            if node.role in ['Magos', 'Cognitor']:
                try:
                    # get_api_url определена в этом же файле (строка 1881)
                    node_url = get_api_url(node, endpoint="/api/traffic_log/clear", default_port=5001)
                    verify_ssl = node.nginx_cert_type != 'self-signed' if node.nginx_enabled else True
                    
                    response = requests.post(
                        node_url,
                        json={'clear_local': True},
                        timeout=10,
                        verify=verify_ssl
                    )
                    if response.status_code == 200:
                        app.logger.info(f"✅ Команда очистки журнала отправлена на {node.name}")
                except Exception as e:
                    app.logger.warning(f"Не удалось отправить команду очистки на {node.name}: {e}")
            
            return jsonify({
                'success': True,
                'message': f'Cleared {deleted_count} logs for node {node.name}',
                'deleted_count': deleted_count
            }), 200
        else:
            # Очищаем все логи
            deleted_count = TrafficLog.query.delete()
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': f'Cleared {deleted_count} logs from all nodes',
                'deleted_count': deleted_count
            }), 200
            
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Ошибка очистки журнала трафика: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


# Endpoint /api/report_traffic теперь в nmc_api/traffic.py
# @app.route('/api/report_traffic', methods=['POST'])
def api_report_traffic():
    """
    API endpoint для приема данных трафика от удаленных узлов (Magos, Cognitor)
    
    Формат данных:
    {
        "node_name": "magos1",
        "logs": [
            {
                "timestamp": "2024-01-01T12:00:00Z",
                "source_ip": "10.0.0.1",
                "destination_ip": "10.0.0.2",
                "source_port": 12345,
                "destination_port": 80,
                "protocol": "TCP",
                "action": "ACCEPT",
                "bytes_sent": 1024,
                "bytes_received": 2048,
                "packets_sent": 10,
                "packets_received": 15,
                "interface": "wg0",
                "direction": "out",
                "connection_state": "ESTABLISHED"
            },
            ...
        ]
    }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        node_name = data.get('node_name')
        if not node_name:
            return jsonify({'error': 'Missing node_name'}), 400
        
        node = General.query.filter_by(name=node_name).first()
        if not node:
            return jsonify({'error': 'Node not found'}), 404
        
        logs = data.get('logs', [])
        if not isinstance(logs, list):
            return jsonify({'error': 'logs must be a list'}), 400
        
        # Сохраняем логи в базу данных
        saved_count = 0
        for log_data in logs:
            try:
                # Парсим timestamp если он строка
                timestamp_str = log_data.get('timestamp')
                if isinstance(timestamp_str, str):
                    try:
                        timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    except ValueError:
                        timestamp = datetime.now(timezone.utc)
                elif isinstance(timestamp_str, datetime):
                    timestamp = timestamp_str
                else:
                    timestamp = datetime.now(timezone.utc)
                
                traffic_log = TrafficLog(
                    timestamp=timestamp,
                    node_id=node.id,
                    source_ip=log_data.get('source_ip'),
                    destination_ip=log_data.get('destination_ip'),
                    source_port=log_data.get('source_port'),
                    destination_port=log_data.get('destination_port'),
                    protocol=log_data.get('protocol'),
                    action=log_data.get('action'),
                    bytes_sent=log_data.get('bytes_sent', 0),
                    bytes_received=log_data.get('bytes_received', 0),
                    packets_sent=log_data.get('packets_sent', 0),
                    packets_received=log_data.get('packets_received', 0),
                    interface=log_data.get('interface'),
                    direction=log_data.get('direction'),
                    connection_state=log_data.get('connection_state')
                )
                db.session.add(traffic_log)
                saved_count += 1
            except Exception as e:
                app.logger.warning(f"Ошибка сохранения записи трафика: {e}")
                continue
        
        db.session.commit()
        app.logger.info(f"✅ Принято {saved_count} записей трафика от {node_name}")
        
        return jsonify({
            'success': True,
            'message': f'Saved {saved_count} traffic logs',
            'saved_count': saved_count
        }), 200
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Ошибка обработки отчета трафика: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/ssh/connect', methods=['POST'])
@login_required
@admin_required
def api_ssh_connect():
    """
    Проверка SSH подключения к удаленному узлу
    """
    try:
        data = request.get_json()
        node_id = data.get('node_id')
        ip = data.get('ip')
        user = data.get('user')
        password = data.get('password')
        
        if not all([node_id, ip, user, password]):
            return jsonify({'success': False, 'error': 'Missing required parameters'}), 400
        
        # Проверяем что узел существует и это Magos или Cognitor
        node = db.session.get(General, node_id)
        if not node or node.role not in ['Magos', 'Cognitor']:
            return jsonify({'success': False, 'error': 'Invalid node. SSH deployment only for Magos and Cognitor'}), 400
        
        # Пробуем подключиться по SSH
        try:
            import paramiko
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=user, password=password, timeout=10)
            ssh.close()
            return jsonify({'success': True, 'message': 'Connection successful'}), 200
        except ImportError:
            return jsonify({'success': False, 'error': 'paramiko library not installed. Run: pip3 install paramiko'}), 500
        except Exception as e:
            return jsonify({'success': False, 'error': f'SSH connection failed: {str(e)}'}), 500
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/ssh/deploy', methods=['POST'])
@login_required
@admin_required
def api_ssh_deploy():
    """
    Передача файлов Magos агента на удаленный узел через SSH
    Возвращает Server-Sent Events (SSE) поток для прогресс-бара
    """
    try:
        data = request.get_json()
        node_id = data.get('node_id')
        ip = data.get('ip')
        user = data.get('user')
        password = data.get('password')
        
        if not all([node_id, ip, user, password]):
            return jsonify({'success': False, 'error': 'Missing required parameters'}), 400
        
        # Проверяем что узел существует и это Magos или Cognitor
        node = db.session.get(General, node_id)
        if not node or node.role not in ['Magos', 'Cognitor']:
            return jsonify({'success': False, 'error': 'Invalid node. SSH deployment only for Magos and Cognitor'}), 400
        
        try:
            import paramiko
        except ImportError:
            return jsonify({'success': False, 'error': 'paramiko library not installed'}), 500
        
        # Получаем реальный IP администратора ПЕРЕД генератором
        # Это IP откуда идет запрос к API
        admin_real_ip_from_request = None
        try:
            # Получаем реальный IP из заголовков (если есть прокси) или напрямую
            admin_real_ip_from_request = request.headers.get('X-Real-IP') or \
                                       request.headers.get('X-Forwarded-For', '').split(',')[0].strip() or \
                                       request.remote_addr
            # Убираем порт если есть
            if admin_real_ip_from_request and ':' in admin_real_ip_from_request:
                admin_real_ip_from_request = admin_real_ip_from_request.split(':')[0]
        except (AttributeError, TypeError) as e:
            # Игнорируем ошибки обработки IP адреса
            app.logger.debug(f"Ошибка обработки admin_real_ip_from_request: {e}")
            pass
        
        # Также пробуем получить из данных запроса
        if not admin_real_ip_from_request:
            admin_real_ip_from_request = data.get('admin_ip')
        
        app.logger.info(f"SSH deploy для узла {node_id}: admin_real_ip={admin_real_ip_from_request}, ssh_ip={ip}")
        
        # Функция для отправки прогресса через SSE
        # КРИТИЧНО: Весь генератор должен работать внутри app_context
        def generate():
            # Устанавливаем контекст приложения для работы с БД и Flask компонентами
            with app.app_context():
                # Перезагружаем узел из БД внутри контекста
                node = db.session.get(General, node_id)
                if not node or node.role not in ['Magos', 'Cognitor']:
                    yield f"data: {json.dumps({'error': 'Invalid node. SSH deployment only for Magos and Cognitor'})}\n\n"
                    return
                
                try:
                    # Подключение
                    yield f"data: {json.dumps({'progress': 5, 'status': 'Подключение к узлу...'})}\n\n"
                    
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(ip, username=user, password=password, timeout=30)
                    sftp = ssh.open_sftp()
                    
                    try:
                        # Создаем временный архив с файлами агента
                        yield f"data: {json.dumps({'progress': 10, 'status': 'Подготовка файлов...'})}\n\n"
                        
                        import tarfile
                        import tempfile
                        import shutil
                        
                        # Определяем путь к директории agents
                        # __file__ может быть /home/nmc-admin/NMC_WG/src/app.py
                        current_file = Path(__file__).resolve()
                        
                        # Определяем корень проекта (NMC_WG)
                        if 'src' in current_file.parts:
                            # Находим индекс 'src' и берем родительскую директорию
                            src_index = current_file.parts.index('src')
                            app_dir = Path(*current_file.parts[:src_index])
                        else:
                            # Если файл уже в корне, используем текущую директорию
                            app_dir = current_file.parent
                        
                        agent_source_dir = app_dir / "agents"
                        
                        if not agent_source_dir.exists():
                            # Пробуем альтернативные пути
                            alternative_paths = [
                                Path("/home/nmc-admin/NMC_WG/agents"),
                                Path("/opt/nmcwg/agents"),
                                Path.cwd() / "agents"
                            ]
                            
                            found = False
                            for alt_path in alternative_paths:
                                if alt_path.exists():
                                    agent_source_dir = alt_path
                                    found = True
                                    break
                            
                            if not found:
                                error_msg = f"Директория agents не найдена. Проверялись пути: {agent_source_dir}, {', '.join(str(p) for p in alternative_paths)}"
                                app.logger.error(error_msg)
                                yield f"data: {json.dumps({'progress': 0, 'status': f'Ошибка: {error_msg}'})}\n\n"
                                return
                        
                        # Создаем временный архив
                        temp_archive = tempfile.NamedTemporaryFile(suffix='.tar.gz', delete=False)
                        temp_archive.close()
                        
                        # Создаем service файл заранее для включения в архив
                        role_label = 'Magos' if node.role == 'Magos' else 'Cognitor'
                        service_name = f"{node.role.lower()}-{node.name.lower()}.service"
                        remote_agent_dir = f"/home/{user}/agents"
                        service_content = f"""[Unit]
Description={role_label} Agent for {node.name}
After=network.target

[Service]
Type=simple
User={user}
Group={user}
WorkingDirectory={remote_agent_dir}
ExecStart=/usr/bin/env python3 {remote_agent_dir}/run.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
Environment="PYTHONUNBUFFERED=1"
Environment="HOME=/home/{user}"
Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="PWD={remote_agent_dir}"

[Install]
WantedBy=multi-user.target
"""
                        
                        # Создаем временный service файл для добавления в архив
                        temp_service = tempfile.NamedTemporaryFile(mode='w', suffix='.service', delete=False)
                        temp_service.write(service_content)
                        temp_service.close()
                        service_path = Path(temp_service.name)
                        
                        with tarfile.open(temp_archive.name, 'w:gz') as tar:
                            # Добавляем все файлы из agents (кроме некоторых)
                            exclude_patterns = ['__pycache__', '.git', 'database', 'instance']
                            for root, dirs, files in os.walk(agent_source_dir):
                                # Фильтруем директории
                                dirs[:] = [d for d in dirs if not any(pattern in d for pattern in exclude_patterns)]
                                
                                for file in files:
                                    if not any(file.endswith(ext) for ext in ['.pyc', '.pyo']):
                                        file_path = Path(root) / file
                                        arc_name = file_path.relative_to(agent_source_dir)
                                        tar.add(file_path, arcname=str(arc_name))
                            
                            # Создаем setup директорию в архиве и добавляем service файл
                            setup_in_archive = f"setup/{service_name}"
                            tar.add(service_path, arcname=setup_in_archive)
                        
                        # Удаляем временный service файл
                        os.unlink(temp_service.name)
                        
                        yield f"data: {json.dumps({'progress': 30, 'status': 'Архив создан, отправка...'})}\n\n"
                        
                        # Отправляем архив на удаленный узел
                        remote_agent_dir = f"/home/{user}/agents"
                        remote_archive_path = f"{remote_agent_dir}.tar.gz"
                        
                        # Создаем директорию если не существует через sftp (синхронно)
                        try:
                            sftp.stat(remote_agent_dir)
                        except IOError:
                            # Директория не существует, создаем ее рекурсивно
                            parts = remote_agent_dir.split('/')
                            current_path = ''
                            for part in parts[1:]:  # Пропускаем первый пустой элемент
                                current_path += '/' + part
                                try:
                                    sftp.stat(current_path)
                                except IOError:
                                    sftp.mkdir(current_path)
                        
                        # Копируем архив
                        sftp.put(temp_archive.name, remote_archive_path)
                        yield f"data: {json.dumps({'progress': 50, 'status': 'Архив отправлен, распаковка...'})}\n\n"
                        
                        # Распаковываем архив в правильную директорию
                        # Архив содержит файлы без префикса agents/, поэтому нужно распаковать в саму директорию
                        unpack_cmd = f"mkdir -p {remote_agent_dir} && tar -xzf {remote_archive_path} -C {remote_agent_dir} && rm {remote_archive_path}"
                        stdin, stdout, stderr = ssh.exec_command(unpack_cmd, timeout=60)
                        # Ждем завершения распаковки
                        stdout_output = stdout.read().decode().strip()
                        stderr_output = stderr.read().decode().strip()
                        exit_status = stdout.channel.recv_exit_status()
                        
                        if exit_status != 0:
                            error_msg = f"Ошибка распаковки архива:\nКоманда: {unpack_cmd}\n"
                            if stderr_output:
                                error_msg += f"Ошибка: {stderr_output}\n"
                            if stdout_output:
                                error_msg += f"Вывод: {stdout_output}"
                            app.logger.error(error_msg)
                            yield f"data: {json.dumps({'error': error_msg})}\n\n"
                            return
                        
                        # Проверяем что файлы распаковались
                        try:
                            sftp.stat(f"{remote_agent_dir}/run.py")
                            app.logger.info(f"Файл run.py найден после распаковки: {remote_agent_dir}/run.py")
                        except IOError:
                            # Попробуем проверить через SSH команду
                            check_cmd = f"test -f {remote_agent_dir}/run.py && echo 'exists' || echo 'not found'"
                            stdin_check, stdout_check, stderr_check = ssh.exec_command(check_cmd, timeout=5)
                            check_result = stdout_check.read().decode().strip()
                            if 'not found' in check_result:
                                error_msg = f"Ошибка: файлы не распаковались в {remote_agent_dir}"
                                app.logger.error(error_msg)
                                yield f"data: {json.dumps({'error': error_msg})}\n\n"
                                return
                        
                        yield f"data: {json.dumps({'progress': 70, 'status': 'Распаковка завершена, установка зависимостей...'})}\n\n"
                        
                        # Устанавливаем зависимости Python
                        stdin, stdout, stderr = ssh.exec_command(
                            f"cd {remote_agent_dir} && python3 -m pip install --user -r requirements.txt 2>&1 || echo 'pip install completed'",
                            timeout=120
                        )
                        stdout.read()  # Ждем завершения
                        yield f"data: {json.dumps({'progress': 90, 'status': 'Зависимости установлены...'})}\n\n"
                        
                        # Создаем installer для этого узла и копируем конфигурацию
                        # Генерируем bootstrap_config.json и копируем
                        # Это требует app_context, который уже установлен выше
                        installer_data = generate_bootstrap_config(node)
                        
                        # КРИТИЧНО: Создаем setup директорию ПОСЛЕ распаковки архива
                        # Даже если она есть в архиве, мы гарантируем что она существует и доступна для записи
                        setup_dir = f"{remote_agent_dir}/setup"
                        app.logger.info(f"Ensuring setup directory exists: {setup_dir}")
                        
                        # Используем sftp.mkdir для синхронного создания директории
                        try:
                            sftp.stat(setup_dir)
                            app.logger.info(f"Setup directory already exists: {setup_dir}")
                        except IOError:
                            # Директория не существует, создаем ее рекурсивно
                            app.logger.info(f"Creating setup directory: {setup_dir}")
                            parts = setup_dir.split('/')
                            current_path = ''
                            for part in parts[1:]:  # Пропускаем первый пустой элемент
                                current_path += '/' + part
                                try:
                                    sftp.stat(current_path)
                                except IOError:
                                    sftp.mkdir(current_path)
                            
                            # Проверяем что директория создана
                            try:
                                sftp.stat(setup_dir)
                                app.logger.info(f"Setup directory created successfully: {setup_dir}")
                            except IOError:
                                # Пробуем еще раз через SSH команду
                                stdin, stdout, stderr = ssh.exec_command(f"mkdir -p {setup_dir}", timeout=10)
                                stdout.read()
                                stderr.read()
                                
                                # Проверяем еще раз
                                try:
                                    sftp.stat(setup_dir)
                                    app.logger.info(f"Setup directory created via SSH: {setup_dir}")
                                except IOError:
                                    app.logger.error(f"Failed to create setup directory: {setup_dir}")
                                    yield f"data: {json.dumps({'error': f'Не удалось создать директорию {setup_dir}'})}\n\n"
                                    return
                        
                        # Service файл уже в архиве, проверяем что он распаковался
                        service_name = f"{node.role.lower()}-{node.name.lower()}.service"
                        service_remote_path = f"{setup_dir}/{service_name}"
                        try:
                            sftp.stat(service_remote_path)
                            app.logger.info(f"Service file found in setup directory: {service_remote_path}")
                            yield f"data: {json.dumps({'progress': 92, 'status': f'Service файл найден: {service_name}'})}\n\n"
                        except IOError:
                            app.logger.warning(f"Service file not found after unpacking, but continuing: {service_remote_path}")
                            yield f"data: {json.dumps({'progress': 92, 'status': 'Конфигурация копируется...'})}\n\n"
                        
                        # Создаем временный файл с bootstrap_config
                        temp_config = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
                        json.dump(installer_data['bootstrap_config'], temp_config, indent=2)
                        temp_config.close()
                        
                        sftp.put(temp_config.name, f"{setup_dir}/bootstrap_config.json")
                        os.unlink(temp_config.name)
                        
                        # Копируем WireGuard конфигурацию
                        temp_wg_config = tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False)
                        temp_wg_config.write(installer_data['wg_config'])
                        temp_wg_config.close()
                        
                        sftp.put(temp_wg_config.name, f"{setup_dir}/{node.name}.conf")
                        os.unlink(temp_wg_config.name)
                        
                        # Копируем mTLS сертификаты если есть (только для Magos)
                        if node.role == 'Magos' and node.mtls_enabled and node.mtls_server_cert_path:
                            mtls_dir = f"{remote_agent_dir}/mtls"
                            # Используем sftp.mkdir для синхронного создания директории
                            try:
                                sftp.stat(mtls_dir)
                            except IOError:
                                # Директория не существует, создаем ее рекурсивно
                                parts = mtls_dir.split('/')
                                current_path = ''
                                for part in parts[1:]:  # Пропускаем первый пустой элемент
                                    current_path += '/' + part
                                    try:
                                        sftp.stat(current_path)
                                    except IOError:
                                        sftp.mkdir(current_path)
                            
                            if Path(node.mtls_server_cert_path).exists():
                                sftp.put(node.mtls_server_cert_path, f"{mtls_dir}/{Path(node.mtls_server_cert_path).name}")
                            if node.mtls_server_key_path and Path(node.mtls_server_key_path).exists():
                                sftp.put(node.mtls_server_key_path, f"{mtls_dir}/{Path(node.mtls_server_key_path).name}")
                            if node.mtls_ca_cert_path and Path(node.mtls_ca_cert_path).exists():
                                sftp.put(node.mtls_ca_cert_path, f"{mtls_dir}/{Path(node.mtls_ca_cert_path).name}")
                        
                        # КРИТИЧНО: Применяем только БАЗОВЫЕ правила iptables для сохранения SSH соединения
                        # Полные правила безопасности будут применены ПОСЛЕ запуска mTLS и VPN
                        yield f"data: {json.dumps({'progress': 95, 'status': 'Применение базовых правил iptables...'})}\n\n"
                        
                        try:
                            # Получаем реальные IP адреса
                            omnissiah = General.query.filter_by(role='Omnissiah').first()
                            
                            # Реальный IP Omnissiah - из endpoint (например, "10.11.11.65:51820" -> "10.11.11.65")
                            omnissiah_real_ip = None
                            if omnissiah and omnissiah.endpoint:
                                omnissiah_real_ip = omnissiah.endpoint.split(':')[0]
                            
                            # Реальный IP администратора - используем значение полученное ПЕРЕД генератором
                            # ВАЖНО: При SSH развертывании администратор подключается с реального IP, не VPN
                            admin_real_ip = admin_real_ip_from_request
                            
                            if not admin_real_ip:
                                app.logger.warning(f"Не удалось определить реальный IP администратора для {node.name}")
                            
                            if not omnissiah_real_ip:
                                app.logger.error(f"КРИТИЧЕСКАЯ ОШИБКА: Не удалось определить реальный IP Omnissiah для {node.name}!")
                                raise Exception(f"Не удалось определить реальный IP Omnissiah (endpoint не настроен)")
                            
                            app.logger.info(f"Применение базовых правил iptables для {node.name}: omnissiah_real_ip={omnissiah_real_ip}, admin_real_ip={admin_real_ip}")
                            
                            # КРИТИЧНО: Сначала устанавливаем политики ACCEPT для INPUT и OUTPUT
                            # Это гарантирует, что SSH соединение не будет разорвано
                            try:
                                iptables_cmd = 'sudo iptables -P INPUT ACCEPT'
                                stdin_ipt, stdout_ipt, stderr_ipt = ssh.exec_command(iptables_cmd, timeout=10)
                                stdout_output = stdout_ipt.read().decode().strip()
                                stderr_output = stderr_ipt.read().decode().strip()
                                exit_status = stdout_ipt.channel.recv_exit_status()
                                if exit_status != 0:
                                    app.logger.error(f"КРИТИЧЕСКАЯ ОШИБКА: Не удалось установить политику INPUT ACCEPT: {stderr_output}")
                                    raise Exception(f"Не удалось установить политику INPUT ACCEPT: {stderr_output}")
                                else:
                                    app.logger.info("Установлена политика INPUT ACCEPT")
                            except Exception as e:
                                app.logger.error(f"КРИТИЧЕСКАЯ ОШИБКА: Не удалось установить политику INPUT ACCEPT: {e}")
                                raise
                            
                            try:
                                iptables_cmd = 'sudo iptables -P OUTPUT ACCEPT'
                                stdin_ipt, stdout_ipt, stderr_ipt = ssh.exec_command(iptables_cmd, timeout=10)
                                stdout_output = stdout_ipt.read().decode().strip()
                                stderr_output = stderr_ipt.read().decode().strip()
                                exit_status = stdout_ipt.channel.recv_exit_status()
                                if exit_status != 0:
                                    app.logger.error(f"КРИТИЧЕСКАЯ ОШИБКА: Не удалось установить политику OUTPUT ACCEPT: {stderr_output}")
                                    raise Exception(f"Не удалось установить политику OUTPUT ACCEPT: {stderr_output}")
                                else:
                                    app.logger.info("Установлена политика OUTPUT ACCEPT")
                            except Exception as e:
                                app.logger.error(f"КРИТИЧЕСКАЯ ОШИБКА: Не удалось установить политику OUTPUT ACCEPT: {e}")
                                raise
                            
                            # Очищаем существующие правила (безопасно при политике ACCEPT)
                            try:
                                iptables_cmd = 'sudo iptables -F'
                                stdin_ipt, stdout_ipt, stderr_ipt = ssh.exec_command(iptables_cmd, timeout=10)
                                stdout_output = stdout_ipt.read().decode().strip()
                                stderr_output = stderr_ipt.read().decode().strip()
                                exit_status = stdout_ipt.channel.recv_exit_status()
                                if exit_status == 0:
                                    app.logger.info("Очищены существующие правила iptables")
                            except Exception as e:
                                app.logger.warning(f"Не удалось очистить правила (не критично): {e}")
                            
                            # Применяем ТОЛЬКО базовые команды (loopback, ESTABLISHED, SSH)
                            # Эти правила нужны для сохранения SSH соединения
                            basic_rules = [
                                ('INPUT', '-i lo -j ACCEPT', 'Разрешить loopback INPUT'),
                                ('OUTPUT', '-o lo -j ACCEPT', 'Разрешить loopback OUTPUT'),
                                ('INPUT', '-m state --state RELATED,ESTABLISHED -j ACCEPT', 'Разрешить установленные соединения INPUT'),
                                ('OUTPUT', '-m state --state RELATED,ESTABLISHED -j ACCEPT', 'Разрешить установленные соединения OUTPUT'),
                            ]
                            
                            for chain, rule_cmd, desc in basic_rules:
                                try:
                                    iptables_cmd = f'sudo iptables -A {chain} {rule_cmd}'
                                    stdin_ipt, stdout_ipt, stderr_ipt = ssh.exec_command(iptables_cmd, timeout=5)
                                    stdout_output = stdout_ipt.read().decode().strip()
                                    stderr_output = stderr_ipt.read().decode().strip()
                                    exit_status = stdout_ipt.channel.recv_exit_status()
                                    if exit_status != 0:
                                        app.logger.error(f"ОШИБКА применения базовой команды iptables {desc}: {stderr_output}")
                                    else:
                                        app.logger.info(f"Применена базовая команда iptables: {desc}")
                                except Exception as e:
                                    app.logger.error(f"ОШИБКА применения базовой команды iptables {desc}: {e}")
                            
                            # SSH разрешен с Omnissiah и администратора (реальные IP)
                            if omnissiah_real_ip:
                                ssh_rules = [
                                    ('INPUT', f'-s {omnissiah_real_ip} -p tcp --dport 22 -j ACCEPT', f'Разрешить входящий SSH с Omnissiah ({omnissiah_real_ip})'),
                                    ('OUTPUT', f'-d {omnissiah_real_ip} -p tcp --dport 22 -j ACCEPT', f'Разрешить исходящий SSH на Omnissiah ({omnissiah_real_ip})'),
                                ]
                                for chain, rule_cmd, desc in ssh_rules:
                                    try:
                                        iptables_cmd = f'sudo iptables -A {chain} {rule_cmd}'
                                        stdin_ipt, stdout_ipt, stderr_ipt = ssh.exec_command(iptables_cmd, timeout=5)
                                        stdout_output = stdout_ipt.read().decode().strip()
                                        stderr_output = stderr_ipt.read().decode().strip()
                                        exit_status = stdout_ipt.channel.recv_exit_status()
                                        if exit_status != 0:
                                            app.logger.error(f"ОШИБКА применения SSH правила {desc}: {stderr_output}")
                                        else:
                                            app.logger.info(f"Применено SSH правило: {desc}")
                                    except Exception as e:
                                        app.logger.error(f"ОШИБКА применения SSH правила {desc}: {e}")
                            
                            if admin_real_ip:
                                ssh_admin_rules = [
                                    ('INPUT', f'-s {admin_real_ip} -p tcp --dport 22 -j ACCEPT', f'Разрешить входящий SSH с администратора ({admin_real_ip})'),
                                    ('OUTPUT', f'-d {admin_real_ip} -p tcp --dport 22 -j ACCEPT', f'Разрешить исходящий SSH на администратора ({admin_real_ip})'),
                                ]
                                for chain, rule_cmd, desc in ssh_admin_rules:
                                    try:
                                        iptables_cmd = f'sudo iptables -A {chain} {rule_cmd}'
                                        stdin_ipt, stdout_ipt, stderr_ipt = ssh.exec_command(iptables_cmd, timeout=5)
                                        stdout_output = stdout_ipt.read().decode().strip()
                                        stderr_output = stderr_ipt.read().decode().strip()
                                        exit_status = stdout_ipt.channel.recv_exit_status()
                                        if exit_status != 0:
                                            app.logger.error(f"ОШИБКА применения SSH правила администратора {desc}: {stderr_output}")
                                        else:
                                            app.logger.info(f"Применено SSH правило администратора: {desc}")
                                    except Exception as e:
                                        app.logger.error(f"ОШИБКА применения SSH правила администратора {desc}: {e}")
                            
                            # Разрешить весь исходящий трафик (для работы mTLS и VPN)
                            try:
                                iptables_cmd = 'sudo iptables -A OUTPUT -j ACCEPT'
                                stdin_ipt, stdout_ipt, stderr_ipt = ssh.exec_command(iptables_cmd, timeout=5)
                                stdout_output = stdout_ipt.read().decode().strip()
                                stderr_output = stderr_ipt.read().decode().strip()
                                exit_status = stdout_ipt.channel.recv_exit_status()
                                if exit_status != 0:
                                    app.logger.error(f"ОШИБКА применения OUTPUT ACCEPT: {stderr_output}")
                                else:
                                    app.logger.info("Применено OUTPUT ACCEPT")
                            except Exception as e:
                                app.logger.error(f"ОШИБКА применения OUTPUT ACCEPT: {e}")
                            
                            # НЕ применяем политику INPUT DROP на этом этапе!
                            # Она будет применена ПОСЛЕ установки VPN и применения правил из БД
                            
                            app.logger.info(f"Базовые правила iptables применены для {node.name} (SSH сохранен)")
                            yield f"data: {json.dumps({'progress': 96, 'status': 'Базовые правила iptables применены'})}\n\n"
                        except Exception as e:
                            app.logger.error(f"Ошибка применения базовых правил iptables через SSH: {e}")
                            import traceback
                            app.logger.error(traceback.format_exc())
                            yield f"data: {json.dumps({'progress': 96, 'status': f'Предупреждение: ошибка применения базовых правил iptables: {str(e)}'})}\n\n"
                        
                        yield f"data: {json.dumps({'progress': 100, 'status': 'Передача завершена!'})}\n\n"
                        
                        # Удаляем временный архив
                        os.unlink(temp_archive.name)
                        
                        # Отправляем сигнал о завершении
                        yield f"data: {json.dumps({'complete': True, 'message': 'Передача файлов успешно завершена'})}\n\n"
                        
                    finally:
                        sftp.close()
                        ssh.close()
                        
                except Exception as e:
                    import traceback
                    app.logger.error(f"SSH deploy error: {str(e)}\n{traceback.format_exc()}")
                    yield f"data: {json.dumps({'error': f'Ошибка: {str(e)}'})}\n\n"
        
        return app.response_class(
            generate(),
            mimetype='text/event-stream',
            headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}
        )
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/deployment/stream', methods=['GET'])
@login_required
@admin_required
def api_deployment_stream():
    """
    SSE поток для развертывания нескольких узлов с прогресс-баром
    GET запрос для EventSource - запускает развертывание и отправляет прогресс
    """
    import sys
    print(f"🔵 API_DEPLOYMENT_STREAM ВЫЗВАН! (функция запущена)", file=sys.stderr, flush=True)
    
    from flask import session as flask_session
    from omnissiah_utils.nmc_ssh_utils import connect_ssh_with_key_or_password
    
    nodes = flask_session.get('deployment_nodes', [])
    direct_connections = flask_session.get('direct_connections', [])
    
    print(f"🔵 Получены данные из сессии: nodes={len(nodes)}", file=sys.stderr, flush=True)
    app.logger.info(f"📋 api_deployment_stream вызван: nodes={len(nodes)}, session_id={flask_session.get('_id', 'unknown')}")
    
    if not nodes:
        print(f"⚠️ Нет узлов в сессии!", file=sys.stderr, flush=True)
        app.logger.warning("⚠️ Нет узлов для развертывания в сессии")
        def generate_error():
            yield f"data: {json.dumps({'error': 'Нет узлов для развертывания', 'complete': True})}\n\n"
        return app.response_class(
            generate_error(),
            mimetype='text/event-stream',
            headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}
        )
    
    print(f"🔵 Создаем генератор для {len(nodes)} узлов", file=sys.stderr, flush=True)
    
    # КРИТИЧНО: Проверяем, не запущено ли уже развертывание
    # Проверяем несколько условий для надежности
    is_active = flask_session.get('deployment_active', False)
    has_nodes = bool(flask_session.get('deployment_nodes', []))
    deployment_start_time = flask_session.get('deployment_start_time', None)
    
    # КРИТИЧНО: Если флаг активен, но узлов нет - предыдущее развертывание завершилось
    # Также проверяем, не прошло ли слишком много времени с момента старта (таймаут 30 минут)
    if is_active:
        if not has_nodes:
            print(f"🧹 Очищаем флаг deployment_active: узлов нет в сессии", file=sys.stderr, flush=True)
            app.logger.info("🧹 Очищаем флаг deployment_active: узлов нет в сессии, развертывание завершено")
            flask_session.pop('deployment_active', None)
            flask_session.pop('deployment_stop_requested', None)
            flask_session.pop('deployment_nodes', None)
            flask_session.pop('deployment_start_time', None)
            flask_session.modified = True
            flask_session.permanent = True
            is_active = False
        elif deployment_start_time:
            # Проверяем таймаут (30 минут = 1800 секунд)
            import time as time_module
            elapsed_time = time_module.time() - deployment_start_time
            if elapsed_time > 1800:  # 30 минут
                print(f"🧹 Очищаем флаг deployment_active: превышен таймаут ({elapsed_time:.0f} сек)", file=sys.stderr, flush=True)
                app.logger.warning(f"🧹 Очищаем флаг deployment_active: превышен таймаут ({elapsed_time:.0f} сек)")
                flask_session.pop('deployment_active', None)
                flask_session.pop('deployment_stop_requested', None)
                flask_session.pop('deployment_nodes', None)
                flask_session.pop('deployment_start_time', None)
                flask_session.modified = True
                flask_session.permanent = True
                is_active = False
    
    # КРИТИЧНО: Дополнительная проверка - если узлы в сессии не совпадают с текущими
    # это означает что развертывание уже завершилось или началось новое
    if is_active and has_nodes:
        current_nodes_in_session = flask_session.get('deployment_nodes', [])
        current_nodes_names = {n.get('name') or n.get('ip', 'unknown') for n in current_nodes_in_session}
        requested_nodes_names = {n.get('name') or n.get('ip', 'unknown') for n in nodes}
        
        # Если узлы не совпадают - это новый запрос, очищаем старое развертывание
        if current_nodes_names != requested_nodes_names:
            print(f"🧹 Очищаем флаг deployment_active: узлы не совпадают (старые: {current_nodes_names}, новые: {requested_nodes_names})", file=sys.stderr, flush=True)
            app.logger.info(f"🧹 Очищаем старое развертывание: узлы не совпадают")
            flask_session.pop('deployment_active', None)
            flask_session.pop('deployment_stop_requested', None)
            flask_session.pop('deployment_nodes', None)
            flask_session.pop('deployment_start_time', None)
            flask_session.modified = True
            flask_session.permanent = True
            is_active = False
    
    if is_active:
        print(f"⚠️ Развертывание уже активно, пропускаем повторный запуск", file=sys.stderr, flush=True)
        app.logger.warning("⚠️ Попытка запустить развертывание, когда оно уже активно")
        def generate_error():
            yield f"data: {json.dumps({'error': 'Развертывание уже выполняется', 'complete': True, 'success': False, 'active': True})}\n\n"
        return app.response_class(
            generate_error(),
            mimetype='text/event-stream',
            headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}
        )
    
    # Сохраняем флаг активного развертывания в сессии ДО создания генератора
    import time as time_module
    flask_session['deployment_active'] = True
    flask_session['deployment_stop_requested'] = False
    flask_session['deployment_start_time'] = time_module.time()  # КРИТИЧНО: Сохраняем время старта для таймаута
    flask_session.modified = True  # КРИТИЧНО: Помечаем сессию как измененную
    flask_session.permanent = True  # КРИТИЧНО: Делаем сессию постоянной для правильного сохранения
    
    # КРИТИЧНО: Принудительно сохраняем сессию перед началом развертывания
    try:
        from flask import session
        session.modified = True
        session.permanent = True
    except Exception as sess_error:
        print(f"⚠️ Ошибка сохранения сессии: {sess_error}", file=sys.stderr, flush=True)
    
    # КРИТИЧНО: Сохраняем контекст запроса для генератора
    # Это позволит генератору работать с сессией в контексте запроса
    from flask import copy_current_request_context
    
    @copy_current_request_context
    def generate():
        # ВАЖНО: Flask запускает генератор только когда начинает читать ответ
        # Поэтому первое сообщение должно быть отправлено НЕМЕДЛЕННО
        import sys
        import time
        import json as json_module
        from flask import session
        from pathlib import Path  # КРИТИЧНО: Импортируем Path для использования в функции
        
        print(f"🚀🚀🚀 SSE ГЕНЕРАТОР ЗАПУЩЕН! (функция generate() вызвана Flask'ом)", file=sys.stderr, flush=True)
        print(f"🚀 Flask начал читать генератор, это значит соединение установлено!", file=sys.stderr, flush=True)
        
        # Используем контекст приложения для работы с сессией
        with app.app_context():
            try:
                # КРИТИЧНО: Определяем app_dir в начале функции для использования в других местах
                import sys as sys_module
                current_file = Path(__file__).resolve()
                src_index = None
                for i, part in enumerate(current_file.parts):
                    if part == 'src':
                        src_index = i + 1
                        break
                if src_index:
                    app_dir = Path(*current_file.parts[:src_index])
                else:
                    app_dir = Path(__file__).parent.parent
                
                total_nodes = len(nodes)
                print(f"🚀 Начинаем развертывание {total_nodes} узлов", file=sys.stderr, flush=True)
                print(f"📁 app_dir определен: {app_dir}", file=sys.stderr, flush=True)
                
                # НЕМЕДЛЕННО отправляем первое сообщение - это критично для SSE
                heartbeat_data = {'heartbeat': True, 'timestamp': time.time()}
                heartbeat_message = f"data: {json_module.dumps(heartbeat_data)}\n\n"
                print(f"💓 Отправляем heartbeat...", file=sys.stderr, flush=True)
                yield heartbeat_message
                print(f"💓 Heartbeat отправлен (выполнен yield)", file=sys.stderr, flush=True)
                
                # НЕМЕДЛЕННО отправляем второе сообщение с прогрессом
                first_data = {
                    'progress': 1, 
                    'status': f'Начинаем развертывание {total_nodes} узлов...', 
                    'total_nodes': total_nodes
                }
                first_message = f"data: {json_module.dumps(first_data)}\n\n"
                print(f"📤 Отправляем первое сообщение о прогрессе...", file=sys.stderr, flush=True)
                yield first_message
                print(f"✅ Первое сообщение отправлено (выполнен yield)", file=sys.stderr, flush=True)
                
                # Flush для гарантии отправки
                sys.stderr.flush()
                
                try:
                    app.logger.info(f"📦 Получено узлов для развертывания: {total_nodes}")
                except (AttributeError, RuntimeError):
                    pass  # Логирование может не работать
                
                created_nodes = []
                deployed_nodes = []
                
                # Этап 1: Создаем все узлы в БД
                yield f"data: {json.dumps({'progress': 5, 'status': 'Создание узлов в базе данных...', 'stage': 'create_nodes'})}\n\n"
                
                for i, node_data in enumerate(nodes):
                    node_name = node_data.get('name', '').strip()
                    if not node_name:
                        node_name = f"{node_data['role'].lower()}_{node_data['ip'].replace('.', '_')}"
                    
                    yield f"data: {json.dumps({'progress': 5 + (i * 5 / total_nodes), 'status': f'Создание узла {node_name}...', 'current_node': node_name, 'stage': 'create_node'})}\n\n"
                    
                    # В ZTN архитектуре ключи генерируются на конечных устройствах, а не на Omnissiah
                    # Пока создаем узел без ключей, они будут сгенерированы на удаленном узле при развертывании
                    # Устанавливаем пустые строки вместо None, так как БД требует NOT NULL
                    private_key = ""
                    public_key = ""
                    
                    # Проверяем, не существует ли уже узел с таким именем
                    existing_node = General.query.filter_by(name=node_name).first()
                    if existing_node:
                        # Если узел уже существует, используем его
                        print(f"⚠️ Узел {node_name} уже существует, используем существующий", file=sys.stderr, flush=True)
                        new_node = existing_node
                        # Обновляем SSH параметры если они изменились
                        if node_data.get('ip'):
                            new_node.ssh_ip = node_data['ip']
                            new_node.endpoint = node_data.get('ip')
                        if node_data.get('ssh_user'):
                            new_node.ssh_user = node_data['ssh_user']
                        if node_data.get('ssh_password'):
                            new_node.ssh_password = node_data.get('ssh_password')
                        if node_data.get('ssh_key_path'):
                            new_node.ssh_key_path = node_data.get('ssh_key_path')
                        db.session.flush()
                    else:
                        # Создаем новый узел без ключей (будут сгенерированы на удаленном узле)
                        # Используем пустые строки вместо None, так как БД требует NOT NULL
                        
                        # КРИТИЧНО: Получаем VPN IP из пула Omnissiah, а не используем внешний IP
                        # Получаем Omnissiah для доступа к пулу IP адресов
                        omnissiah = General.query.filter_by(role='Omnissiah').first()
                        vpn_ip = None
                        if omnissiah:
                            try:
                                vpn_ip = get_next_available_ip(omnissiah)
                                if not vpn_ip:
                                    # Если не удалось получить IP, используем внешний IP как fallback
                                    print(f"⚠️ Не удалось получить VPN IP из пула Omnissiah для {node_name}, используем внешний IP", file=sys.stderr, flush=True)
                                    vpn_ip = node_data['ip'] + '/32'
                            except Exception as ip_error:
                                print(f"⚠️ Ошибка получения VPN IP: {ip_error}, используем внешний IP", file=sys.stderr, flush=True)
                                vpn_ip = node_data['ip'] + '/32'
                        else:
                            # Если Omnissiah не найден, используем внешний IP
                            print(f"⚠️ Omnissiah не найден, используем внешний IP для {node_name}", file=sys.stderr, flush=True)
                            vpn_ip = node_data['ip'] + '/32'
                        
                        # Убеждаемся, что vpn_ip в правильном формате
                        if '/' not in vpn_ip:
                            vpn_ip = f"{vpn_ip}/32"
                        
                        new_node = General(
                            name=node_name,
                            ip_pool=vpn_ip,  # VPN IP из пула Omnissiah, а не внешний IP
                            listen_port=51820,
                            private_key="",  # Будет сгенерирован на удаленном узле и получен через mTLS
                            public_key="",  # Будет получен через mTLS после генерации на удаленном узле
                            role=node_data['role'],
                            endpoint=node_data.get('ip'),  # Внешний IP для подключения
                            ssh_ip=node_data['ip'],  # Внешний IP для SSH
                            ssh_user=node_data['ssh_user'],
                            ssh_password=node_data.get('ssh_password'),
                            ssh_key_path=node_data.get('ssh_key_path')
                        )
                        
                        db.session.add(new_node)
                        db.session.flush()
                    
                    created_nodes.append(new_node)
                    yield f"data: {json.dumps({'progress': 5 + ((i + 1) * 5 / total_nodes), 'status': f'Узел {node_name} создан', 'current_node': node_name, 'node_status': 'created'})}\n\n"
                
                # Получаем Omnissiah
                omnissiah = General.query.filter_by(role='Omnissiah').first()
                if not omnissiah:
                    yield f"data: {json.dumps({'error': 'Omnissiah не найден в системе', 'complete': True})}\n\n"
                    return
                
                # Создаем маппинг временных ID -> созданные узлы
                temp_id_to_node = {}
                for i, node_data in enumerate(nodes):
                    temp_id = node_data.get('id', i + 1)
                    if i < len(created_nodes):
                        temp_id_to_node[temp_id] = created_nodes[i]
                
                # В ZTN архитектуре все узлы автоматически подключаются к Omnissiah
                # Устанавливаем parent_id для всех узлов на Omnissiah
                yield f"data: {json.dumps({'progress': 10, 'status': 'Настройка связей с Omnissiah...', 'stage': 'setup_omnissiah_connections'})}\n\n"
                
                for node in created_nodes:
                    # Все узлы подключаются к Omnissiah
                    node.parent_id = omnissiah.id
                
                # Создаем прямые связи для mesh сети
                yield f"data: {json.dumps({'progress': 12, 'status': 'Настройка прямых связей...', 'stage': 'setup_connections'})}\n\n"
                
                for node1_temp_id, node2_temp_id in direct_connections:
                    node1 = temp_id_to_node.get(node1_temp_id)
                    node2 = temp_id_to_node.get(node2_temp_id)
                    
                    if node1 and node2:
                        existing = NodeConnection.query.filter(
                            ((NodeConnection.node1_id == node1.id) & (NodeConnection.node2_id == node2.id)) |
                            ((NodeConnection.node1_id == node2.id) & (NodeConnection.node2_id == node1.id))
                        ).first()
                        
                        if not existing:
                            connection = NodeConnection(node1_id=node1.id, node2_id=node2.id)
                            db.session.add(connection)
                
                # Связи по умолчанию: все узлы автоматически подключаются к Omnissiah для mesh сети
                for node in created_nodes:
                    existing_omnissiah = NodeConnection.query.filter(
                        ((NodeConnection.node1_id == node.id) & (NodeConnection.node2_id == omnissiah.id)) |
                        ((NodeConnection.node1_id == omnissiah.id) & (NodeConnection.node2_id == node.id))
                    ).first()
                    
                    if not existing_omnissiah:
                        connection = NodeConnection(node1_id=node.id, node2_id=omnissiah.id)
                        db.session.add(connection)
                
                db.session.commit()
                
                # Этап 2: Развертывание каждого узла
                yield f"data: {json.dumps({'progress': 15, 'status': 'Начинаем развертывание узлов...', 'stage': 'deploy_nodes'})}\n\n"
                
                # Здесь вставляем логику развертывания из network_deployment_wizard_finalize
                # Но с отправкой обновлений прогресса через yield
                # Для краткости, показываю структуру - полная логика будет в следующем коммите
                
                for i, node in enumerate(created_nodes):
                    # КРИТИЧНО: Проверяем, не был ли узел уже развернут (защита от повторного запуска)
                    # Проверяем наличие сервиса на удаленном узле
                    already_deployed = False
                    if node.role in ['Magos', 'Cognitor']:
                        try:
                            # Пробуем подключиться по SSH и проверить наличие сервиса
                            from omnissiah_utils.nmc_ssh_utils import connect_ssh_with_key_or_password
                            test_ssh, _ = connect_ssh_with_key_or_password(
                                hostname=node.ssh_ip,
                                username=node.ssh_user,
                                password=node.ssh_password,
                                key_file=node.ssh_key_path,
                                timeout=10
                            )
                            if test_ssh:
                                role_lower = node.role.lower()
                                service_name = f"{role_lower}-{node.name.lower()}.service"
                                check_service_cmd = f"systemctl is-active {service_name} 2>/dev/null || echo 'inactive'"
                                stdin, stdout, stderr = test_ssh.exec_command(check_service_cmd, timeout=5)
                                exit_status = stdout.channel.recv_exit_status()
                                service_output = stdout.read().decode().strip()
                                test_ssh.close()
                                
                                if exit_status == 0 and service_output == 'active':
                                    print(f"⚠️ Узел {node.name} уже развернут (сервис активен), пропускаем", file=sys.stderr, flush=True)
                                    already_deployed = True
                                    deployed_nodes.append(node)
                                    yield f"data: {json.dumps({'progress': 15 + ((i + 1) * 70 / total_nodes), 'status': f'Узел {node.name} уже развернут, пропускаем', 'current_node': node.name, 'node_status': 'skipped'})}\n\n"
                                    continue
                        except Exception as e:
                            # Если не удалось проверить, продолжаем развертывание
                            print(f"⚠️ Не удалось проверить статус узла {node.name}, продолжаем развертывание: {e}", file=sys.stderr, flush=True)
                    
                    # Проверяем, не запрошена ли остановка развертывания
                    try:
                        stop_requested = session.get('deployment_stop_requested', False)
                    except (KeyError, AttributeError, RuntimeError):
                        stop_requested = False
                    
                    if stop_requested:
                        yield f"data: {json.dumps({'progress': 15 + (i * 70 / total_nodes), 'status': 'Развертывание остановлено пользователем', 'complete': True, 'success': False, 'error': 'Развертывание остановлено пользователем'})}\n\n"
                        try:
                            session['deployment_active'] = False
                            session['deployment_stop_requested'] = False
                            session.modified = True
                            session.permanent = True
                        except (AttributeError, RuntimeError):
                            pass
                        return
                    
                    node_data = nodes[i]
                    node_progress_start = 15 + (i * 70 / total_nodes)
                    node_progress_range = 70 / total_nodes
                    deployment_error = None
                    ssh_client = None
                    
                    try:
                        import sys
                        import time as time_module
                        print(f"🔧 Начинаем развертывание узла {i+1}/{total_nodes}: {node.name}", file=sys.stderr, flush=True)
                        
                        # Импорты для развертывания (используются в разных блоках)
                        from pathlib import Path
                        import tarfile
                        import tempfile
                        import json as json_module
                        import paramiko
                        import os as os_module
                        
                        yield f"data: {json.dumps({'progress': node_progress_start, 'status': f'Развертывание узла {node.name} ({i+1}/{total_nodes})...', 'current_node': node.name, 'node_status': 'deploying'})}\n\n"
                        print(f"📤 Отправлено сообщение о начале развертывания {node.name}", file=sys.stderr, flush=True)
                        
                        # Подключаемся по SSH
                        if node.role != 'Omnissiah':
                            yield f"data: {json.dumps({'progress': node_progress_start + 2, 'status': f'Подключение к {node.name} по SSH...', 'current_node': node.name})}\n\n"
                            print(f"🔌 Подключаемся по SSH к {node.name} ({node.ssh_ip})", file=sys.stderr, flush=True)
                            
                            ssh_client, error = connect_ssh_with_key_or_password(
                                hostname=node.ssh_ip,
                                username=node.ssh_user,
                                password=node.ssh_password,
                                key_file=node.ssh_key_path,
                                timeout=120
                            )
                            
                            if not ssh_client:
                                raise Exception(f"SSH подключение не удалось: {error}")
                            
                            print(f"✅ SSH подключение к {node.name} установлено", file=sys.stderr, flush=True)
                            yield f"data: {json.dumps({'progress': node_progress_start + 5, 'status': f'SSH подключение к {node.name} установлено', 'current_node': node.name})}\n\n"
                        
                        # Развертывание ПО через SSH
                        if node.role in ['Magos', 'Cognitor']:
                            yield f"data: {json.dumps({'progress': node_progress_start + 7, 'status': f'Проверка версий на {node.name}...', 'current_node': node.name})}\n\n"
                            print(f"🔍 Проверяем версии на {node.name}...", file=sys.stderr, flush=True)
                            
                            # КРИТИЧНО: Проверяем версии агента и конфига WireGuard перед развертыванием
                            remote_agent_dir = f"/home/{node.ssh_user}/agents"
                            remote_bootstrap_path = f"{remote_agent_dir}/setup/bootstrap_config.json"
                            # КРИТИЧНО: Для Magos/Cognitor конфигурация должна быть в /home/{user}/agents/setup/
                            remote_wg_config_path = f"{remote_agent_dir}/setup/{node.name}.conf"
                            
                            agent_installed = False
                            agent_version_remote = None
                            wg_config_exists = False
                            wg_config_version_remote = None
                            
                            # Проверяем наличие агента
                            check_agent_cmd = f"test -f {remote_agent_dir}/run.py && echo 'installed' || echo 'not_installed'"
                            stdin, stdout, stderr = ssh_client.exec_command(check_agent_cmd, timeout=5)
                            agent_check_result = stdout.read().decode().strip()
                            agent_installed = (agent_check_result == 'installed')
                            
                            if agent_installed:
                                print(f"✅ Агент установлен на {node.name}", file=sys.stderr, flush=True)
                                
                                # Проверяем версию агента (через bootstrap_config.json или хеш директории)
                                check_bootstrap_cmd = f"test -f {remote_bootstrap_path} && cat {remote_bootstrap_path} || echo 'no_config'"
                                stdin, stdout, stderr = ssh_client.exec_command(check_bootstrap_cmd, timeout=5)
                                bootstrap_content = stdout.read().decode().strip()
                                
                                if bootstrap_content and bootstrap_content != 'no_config':
                                    try:
                                        bootstrap_data = json.loads(bootstrap_content)
                                        agent_version_remote = bootstrap_data.get('agent_version') or bootstrap_data.get('version')
                                        print(f"📋 Версия агента на узле: {agent_version_remote}", file=sys.stderr, flush=True)
                                    except Exception as e:
                                        print(f"⚠️ Не удалось прочитать bootstrap_config.json: {e}", file=sys.stderr, flush=True)
                                
                                # Если версия не найдена в конфиге, вычисляем хеш директории агента
                                if not agent_version_remote:
                                    hash_cmd = f"find {remote_agent_dir} -type f -name '*.py' -exec md5sum {{}} \\; 2>/dev/null | sort | md5sum | cut -d' ' -f1 || echo 'no_hash'"
                                    stdin, stdout, stderr = ssh_client.exec_command(hash_cmd, timeout=10)
                                    agent_version_remote = stdout.read().decode().strip()
                                    if agent_version_remote and agent_version_remote != 'no_hash':
                                        print(f"📋 Хеш агента на узле: {agent_version_remote[:16]}...", file=sys.stderr, flush=True)
                            else:
                                print(f"ℹ️ Агент не установлен на {node.name}", file=sys.stderr, flush=True)
                            
                            # Проверяем наличие конфига WireGuard
                            check_wg_cmd = f"test -f {remote_wg_config_path} && echo 'exists' || echo 'not_exists'"
                            stdin, stdout, stderr = ssh_client.exec_command(check_wg_cmd, timeout=5)
                            wg_check_result = stdout.read().decode().strip()
                            wg_config_exists = (wg_check_result == 'exists')
                            
                            if wg_config_exists:
                                print(f"✅ Конфиг WireGuard найден на {node.name}", file=sys.stderr, flush=True)
                                
                                # Вычисляем хеш конфига для проверки версии
                                hash_wg_cmd = f"md5sum {remote_wg_config_path} 2>/dev/null | cut -d' ' -f1 || echo 'no_hash'"
                                stdin, stdout, stderr = ssh_client.exec_command(hash_wg_cmd, timeout=5)
                                wg_config_version_remote = stdout.read().decode().strip()
                                if wg_config_version_remote and wg_config_version_remote != 'no_hash':
                                    print(f"📋 Хеш конфига WireGuard на узле: {wg_config_version_remote[:16]}...", file=sys.stderr, flush=True)
                            else:
                                print(f"ℹ️ Конфиг WireGuard не найден на {node.name}", file=sys.stderr, flush=True)
                            
                            # Вычисляем текущие версии для сравнения
                            # Версия агента - хеш директории agents
                            # КРИТИЧНО: app_dir должен быть определен в начале функции generate()
                            agent_version_local = None
                            try:
                                import hashlib
                                # Используем app_dir, который определен в начале функции generate()
                                if 'app_dir' not in locals():
                                    # Fallback: определяем app_dir если он не определен
                                    current_file = Path(__file__).resolve()
                                    if 'src' in current_file.parts:
                                        src_index = current_file.parts.index('src')
                                        app_dir = Path(*current_file.parts[:src_index])
                                    else:
                                        app_dir = current_file.parent.parent
                                    print(f"⚠️ app_dir не был определен ранее, используем fallback: {app_dir}", file=sys.stderr, flush=True)
                                
                                agent_source_dir = app_dir / "agents"
                                print(f"🔍 Вычисляем хеш агента из: {agent_source_dir}", file=sys.stderr, flush=True)
                                if agent_source_dir.exists():
                                    # Вычисляем хеш всех Python файлов в директории agents
                                    hash_md5 = hashlib.md5()
                                    py_files = sorted(agent_source_dir.rglob('*.py'))
                                    print(f"📋 Найдено Python файлов: {len(py_files)}", file=sys.stderr, flush=True)
                                    for py_file in py_files:
                                        if '__pycache__' not in str(py_file):
                                            try:
                                                with open(py_file, 'rb') as f:
                                                    hash_md5.update(f.read())
                                            except Exception:
                                                pass
                                    agent_version_local = hash_md5.hexdigest()
                                    print(f"📋 Хеш агента локально: {agent_version_local[:16]}...", file=sys.stderr, flush=True)
                                else:
                                    print(f"⚠️ Директория agents не найдена: {agent_source_dir}", file=sys.stderr, flush=True)
                            except Exception as e:
                                print(f"⚠️ Не удалось вычислить хеш агента: {e}", file=sys.stderr, flush=True)
                                import traceback
                                print(f"📋 Traceback: {traceback.format_exc()}", file=sys.stderr, flush=True)
                            
                            # Версия конфига WireGuard - будет вычислена позже при генерации
                            wg_config_version_local = None
                            
                            # Сравниваем версии
                            version_mismatch = False
                            mismatch_details = []
                            
                            if agent_installed and agent_version_remote and agent_version_local:
                                if agent_version_remote != agent_version_local:
                                    version_mismatch = True
                                    mismatch_details.append(f"Версия агента не совпадает (узел: {agent_version_remote[:16]}..., локально: {agent_version_local[:16]}...)")
                                    print(f"⚠️ {mismatch_details[-1]}", file=sys.stderr, flush=True)
                            
                            if wg_config_exists and wg_config_version_remote:
                                # Версию конфига WireGuard проверим после генерации
                                # Пока просто отмечаем, что конфиг существует
                                pass
                            
                            # Если версии не совпадают, предлагаем удаление и переустановку
                            if version_mismatch:
                                yield f"data: {json.dumps({'progress': node_progress_start + 7.5, 'status': f'Обнаружено несоответствие версий на {node.name}. Удаление старой версии...', 'current_node': node.name, 'warning': 'version_mismatch', 'details': mismatch_details})}\n\n"
                                print(f"⚠️ Обнаружено несоответствие версий на {node.name}. Удаляем старую версию...", file=sys.stderr, flush=True)
                                
                                # Останавливаем и удаляем старый агент
                                try:
                                    # Останавливаем service
                                    stop_service_cmd = f"sudo systemctl stop {node.role.lower()}-{node.name.lower()}.service 2>/dev/null || true"
                                    ssh_client.exec_command(stop_service_cmd, timeout=10)
                                    
                                    # Удаляем service
                                    disable_service_cmd = f"sudo systemctl disable {node.role.lower()}-{node.name.lower()}.service 2>/dev/null || true"
                                    ssh_client.exec_command(disable_service_cmd, timeout=10)
                                    
                                    # Удаляем директорию агента (но сохраняем bootstrap_config.json если есть)
                                    remove_agent_cmd = f"rm -rf {remote_agent_dir}/* {remote_agent_dir}/.* 2>/dev/null || true"
                                    ssh_client.exec_command(remove_agent_cmd, timeout=10)
                                    
                                    print(f"✅ Старая версия агента удалена с {node.name}", file=sys.stderr, flush=True)
                                except Exception as e:
                                    print(f"⚠️ Ошибка при удалении старой версии: {e}, продолжаем...", file=sys.stderr, flush=True)
                            
                            yield f"data: {json.dumps({'progress': node_progress_start + 8, 'status': f'Развертывание ПО на {node.name}...', 'current_node': node.name})}\n\n"
                            print(f"📦 Начинаем развертывание ПО на {node.name}", file=sys.stderr, flush=True)
                            
                            # Полная логика развертывания ПО (адаптирована из network_deployment_wizard_finalize)
                            
                            # КРИТИЧНО: Определяем путь к директории agents
                            # Используем app_dir, который определен в начале функции generate()
                            # Если app_dir не определен, определяем его здесь
                            if 'app_dir' not in locals():
                                current_file = Path(__file__).resolve()
                                if 'src' in current_file.parts:
                                    src_index = current_file.parts.index('src')
                                    app_dir = Path(*current_file.parts[:src_index])
                                else:
                                    app_dir = current_file.parent.parent
                                print(f"⚠️ app_dir не был определен ранее, определяем здесь: {app_dir}", file=sys.stderr, flush=True)
                            
                            agent_source_dir = app_dir / "agents"
                            print(f"🔍 Ищем папку agents. app_dir: {app_dir}, agent_source_dir: {agent_source_dir}", file=sys.stderr, flush=True)
                            
                            if not agent_source_dir.exists():
                                print(f"⚠️ Путь {agent_source_dir} не существует, проверяем альтернативные пути...", file=sys.stderr, flush=True)
                                alternative_paths = [
                                    Path("/home/nmc-admin/NMC_WG/agents"),
                                    Path("/opt/nmcwg/agents"),
                                    Path.cwd() / "agents",
                                    Path("/home/nmc-admin/NMC_WG") / "agents"
                                ]
                                
                                found = False
                                for alt_path in alternative_paths:
                                    print(f"🔍 Проверяем путь: {alt_path} (существует: {alt_path.exists()})", file=sys.stderr, flush=True)
                                    if alt_path.exists():
                                        agent_source_dir = alt_path
                                        found = True
                                        print(f"✅ Найдена папка agents: {agent_source_dir}", file=sys.stderr, flush=True)
                                        break
                                
                                if not found:
                                    error_msg = f"Директория agents не найдена. Проверялись пути: {agent_source_dir}, {', '.join(str(p) for p in alternative_paths)}"
                                    print(f"❌ {error_msg}", file=sys.stderr, flush=True)
                                    raise Exception(error_msg)
                            else:
                                print(f"✅ Папка agents найдена: {agent_source_dir}", file=sys.stderr, flush=True)
                            
                            yield f"data: {json.dumps({'progress': node_progress_start + 10, 'status': f'Подготовка архива для {node.name}...', 'current_node': node.name})}\n\n"
                            print(f"📁 Подготавливаем архив для {node.name}, исходная директория: {agent_source_dir}", file=sys.stderr, flush=True)
                            
                            # Создаем временный архив
                            temp_archive = tempfile.NamedTemporaryFile(suffix='.tar.gz', delete=False)
                            temp_archive.close()
                            
                            # Создаем service файл
                            role_label = 'Magos' if node.role == 'Magos' else 'Cognitor'
                            service_name = f"{node.role.lower()}-{node.name.lower()}.service"
                            remote_agent_dir = f"/home/{node.ssh_user}/agents"
                            
                            # Получаем данные для bootstrap_config
                            omnissiah_node = General.query.filter_by(role='Omnissiah').first()
                            parent_node = node.parent if node.parent_id else omnissiah_node
                            
                            # Генерируем сертификаты mTLS если нужно
                            mtls_cert_file = None
                            mtls_key_file = None
                            mtls_ca_cert_file = None
                            mtls_enabled = False
                            
                            # КРИТИЧНО: Проверяем условия для генерации mTLS сертификатов
                            print(f"🔍 Проверка mTLS для {node.name}:", file=sys.stderr, flush=True)
                            print(f"   - omnissiah_node exists: {omnissiah_node is not None}", file=sys.stderr, flush=True)
                            if omnissiah_node:
                                print(f"   - omnissiah_node.mtls_enabled: {omnissiah_node.mtls_enabled}", file=sys.stderr, flush=True)
                                print(f"   - omnissiah_node.mtls_ca_cert_path: {omnissiah_node.mtls_ca_cert_path}", file=sys.stderr, flush=True)
                                print(f"   - omnissiah_node.mtls_ca_key_path: {omnissiah_node.mtls_ca_key_path}", file=sys.stderr, flush=True)
                            
                            if omnissiah_node and omnissiah_node.mtls_enabled and omnissiah_node.mtls_ca_cert_path and omnissiah_node.mtls_ca_key_path:
                                print(f"🔐 Генерируем mTLS сертификаты для {node.name}...", file=sys.stderr, flush=True)
                                try:
                                    # Проверяем существование CA сертификата и ключа
                                    if not Path(omnissiah_node.mtls_ca_cert_path).exists():
                                        raise FileNotFoundError(f"CA сертификат не найден: {omnissiah_node.mtls_ca_cert_path}")
                                    if not Path(omnissiah_node.mtls_ca_key_path).exists():
                                        raise FileNotFoundError(f"CA ключ не найден: {omnissiah_node.mtls_ca_key_path}")
                                    
                                    # КРИТИЧНО: Создаем директорию для сертификатов в директории приложения
                                    # Используем app_dir, который определен в начале функции generate()
                                    # Если app_dir не определен, используем временную директорию
                                    if 'app_dir' not in locals():
                                        app_dir = Path(__file__).parent.parent
                                    
                                    mtls_dir = app_dir / "mtls_certs" / "clients"
                                    mtls_dir.mkdir(parents=True, exist_ok=True)
                                    print(f"📁 Директория для сертификатов: {mtls_dir}", file=sys.stderr, flush=True)
                                    
                                    # Генерируем клиентские сертификаты для узла
                                    print(f"🔧 Вызываем generate_client_certificate для {node.name}...", file=sys.stderr, flush=True)
                                    client_cert_path, client_key_path = generate_client_certificate(
                                        ca_cert_path=omnissiah_node.mtls_ca_cert_path,
                                        ca_key_path=omnissiah_node.mtls_ca_key_path,
                                        client_name=node.name,
                                        client_dir=str(mtls_dir)
                                    )
                                    
                                    # Проверяем, что файлы созданы
                                    if not Path(client_cert_path).exists():
                                        raise FileNotFoundError(f"Сертификат не создан: {client_cert_path}")
                                    if not Path(client_key_path).exists():
                                        raise FileNotFoundError(f"Ключ не создан: {client_key_path}")
                                    
                                    mtls_cert_file = client_cert_path
                                    mtls_key_file = client_key_path
                                    mtls_ca_cert_file = omnissiah_node.mtls_ca_cert_path
                                    mtls_enabled = True
                                    
                                    print(f"✅ mTLS сертификаты созданы для {node.name}:", file=sys.stderr, flush=True)
                                    print(f"   - cert: {mtls_cert_file} (exists: {Path(mtls_cert_file).exists()})", file=sys.stderr, flush=True)
                                    print(f"   - key: {mtls_key_file} (exists: {Path(mtls_key_file).exists()})", file=sys.stderr, flush=True)
                                    print(f"   - ca: {mtls_ca_cert_file} (exists: {Path(mtls_ca_cert_file).exists()})", file=sys.stderr, flush=True)
                                except Exception as e:
                                    print(f"❌ Ошибка создания mTLS сертификатов: {e}", file=sys.stderr, flush=True)
                                    import traceback
                                    print(f"📋 Traceback: {traceback.format_exc()}", file=sys.stderr, flush=True)
                                    # Продолжаем без mTLS
                                    mtls_enabled = False
                                    mtls_cert_file = None
                                    mtls_key_file = None
                                    mtls_ca_cert_file = None
                            else:
                                print(f"⚠️ mTLS не будет использоваться для {node.name}:", file=sys.stderr, flush=True)
                                if not omnissiah_node:
                                    print(f"   - Omnissiah узел не найден", file=sys.stderr, flush=True)
                                elif not omnissiah_node.mtls_enabled:
                                    print(f"   - mTLS не включен на Omnissiah", file=sys.stderr, flush=True)
                                elif not omnissiah_node.mtls_ca_cert_path:
                                    print(f"   - CA сертификат не указан", file=sys.stderr, flush=True)
                                elif not omnissiah_node.mtls_ca_key_path:
                                    print(f"   - CA ключ не указан", file=sys.stderr, flush=True)
                            
                            # Формируем правильный server_url для агента
                            # КРИТИЧНО: Агент ожидает server_url, а не omnissiah_ip/port отдельно
                            if omnissiah_node:
                                # Определяем правильный порт для Omnissiah
                                # Если nginx включен с HTTPS - используем nginx_https_port
                                # Если nginx включен с HTTP - используем nginx_http_port или 80
                                # Если nginx не включен - используем Flask порт (обычно 33787)
                                if omnissiah_node.nginx_enabled:
                                    if omnissiah_node.nginx_https_port:
                                        # HTTPS через nginx
                                        protocol = "https"
                                        port = omnissiah_node.nginx_https_port
                                    elif omnissiah_node.nginx_http_port:
                                        # HTTP через nginx
                                        protocol = "http"
                                        port = omnissiah_node.nginx_http_port
                                    else:
                                        # nginx включен, но порты не указаны - используем стандартные
                                        protocol = "https" if omnissiah_node.nginx_cert_path else "http"
                                        port = 443 if protocol == "https" else 80
                                else:
                                    # nginx не включен - используем Flask порт напрямую
                                    protocol = "http"
                                    port = 33787  # Стандартный порт Flask для Omnissiah
                                
                                # Определяем IP адрес для подключения
                                if omnissiah_node.endpoint:
                                    host = omnissiah_node.endpoint.split(':')[0]  # IP из endpoint
                                else:
                                    host = omnissiah_node.ip_pool.split("/")[0] if omnissiah_node.ip_pool else "127.0.0.1"
                                
                                # Формируем полный URL
                                if (protocol == "https" and port == 443) or (protocol == "http" and port == 80):
                                    server_url = f"{protocol}://{host}"
                                else:
                                    server_url = f"{protocol}://{host}:{port}"
                            else:
                                server_url = None
                            
                            # Вычисляем версию агента для сохранения в bootstrap_config (если еще не вычислена)
                            if 'agent_version_local' not in locals() or not agent_version_local:
                                try:
                                    import hashlib
                                    agent_source_dir_for_version = app_dir / "agents"
                                    if agent_source_dir_for_version.exists():
                                        hash_md5 = hashlib.md5()
                                        py_files = sorted(agent_source_dir_for_version.rglob('*.py'))
                                        for py_file in py_files:
                                            if '__pycache__' not in str(py_file):
                                                try:
                                                    with open(py_file, 'rb') as f:
                                                        hash_md5.update(f.read())
                                                except Exception:
                                                    pass
                                        agent_version_local = hash_md5.hexdigest()
                                except Exception:
                                    agent_version_local = None
                            
                            # КРИТИЧНО: Создаем bootstrap_config с начальными значениями
                            # Пути к mTLS сертификатам будут обновлены после копирования на удаленный узел
                            
                            # Получаем информацию об Omnissiah для подключения
                            omnissiah_public_key = None
                            omnissiah_endpoint = None
                            omnissiah_listen_port = None
                            omnissiah_ip_pool = None
                            
                            if omnissiah_node:
                                omnissiah_public_key = omnissiah_node.public_key
                                omnissiah_endpoint = omnissiah_node.endpoint or get_real_external_ip(omnissiah_node)
                                omnissiah_listen_port = omnissiah_node.listen_port
                                omnissiah_ip_pool = omnissiah_node.ip_pool
                            
                            bootstrap_config = {
                                'node_name': node.name,
                                'name': node.name,  # КРИТИЧНО: Добавляем 'name' для обратной совместимости с heartbeat
                                'node_role': node.role,
                                'role': node.role,  # КРИТИЧНО: Добавляем 'role' для обратной совместимости
                                'server_url': server_url,  # КРИТИЧНО: Полный URL для агента
                                # Информация об Omnissiah для подключения WireGuard
                                'omnissiah_public_key': omnissiah_public_key,
                                'omnissiah_endpoint': omnissiah_endpoint,
                                'omnissiah_listen_port': omnissiah_listen_port,
                                'omnissiah_ip_pool': omnissiah_ip_pool,
                                'public_key': node.public_key if node.public_key else '',  # КРИТИЧНО: Добавляем public_key для heartbeat
                                'ip_pool': node.ip_pool if node.ip_pool else '',  # КРИТИЧНО: Добавляем ip_pool для heartbeat
                                'api_token': '',  # Для обратной совместимости (не используется в mTLS)
                                'omnissiah_ip': omnissiah_node.endpoint if omnissiah_node else None,  # Для обратной совместимости
                                'omnissiah_port': omnissiah_node.nginx_https_port if omnissiah_node and omnissiah_node.nginx_enabled else (omnissiah_node.listen_port if omnissiah_node else 33787),  # Для обратной совместимости
                                'mtls_enabled': mtls_enabled,
                                'mtls_cert_file': '',  # Будет обновлено после копирования сертификатов
                                'mtls_key_file': '',  # Будет обновлено после копирования сертификатов
                                'mtls_ca_cert_file': '',  # Будет обновлено после копирования сертификатов
                                'agent_version': agent_version_local  # КРИТИЧНО: Сохраняем версию агента для будущих проверок
                            }
                            
                            # КРИТИЧНО: Если mTLS включен, копируем сертификаты на удаленный узел
                            # Это должно быть ДО создания bootstrap_config.json, чтобы пути были правильными
                            print(f"🔍 Проверка перед копированием mTLS для {node.name}:", file=sys.stderr, flush=True)
                            print(f"   - mtls_enabled: {mtls_enabled}", file=sys.stderr, flush=True)
                            print(f"   - mtls_cert_file: {mtls_cert_file}", file=sys.stderr, flush=True)
                            print(f"   - mtls_key_file: {mtls_key_file}", file=sys.stderr, flush=True)
                            
                            if mtls_enabled and mtls_cert_file and mtls_key_file:
                                yield f"data: {json.dumps({'progress': node_progress_start + 14.8, 'status': f'Копирование mTLS сертификатов на {node.name}...', 'current_node': node.name})}\n\n"
                                print(f"🔐 Копируем mTLS сертификаты на {node.name}...", file=sys.stderr, flush=True)
                                
                                remote_mtls_dir = f"{remote_agent_dir}/mtls"
                                mkdir_mtls_cmd = f"mkdir -p {remote_mtls_dir}"
                                stdin, stdout, stderr = ssh_client.exec_command(mkdir_mtls_cmd, timeout=5)
                                exit_status = stdout.channel.recv_exit_status()
                                if exit_status != 0:
                                    error_output = stderr.read().decode()
                                    print(f"⚠️ Ошибка создания директории mtls: {error_output}", file=sys.stderr, flush=True)
                                
                                # Копируем сертификаты через SFTP
                                sftp = ssh_client.open_sftp()
                                try:
                                    # Имена файлов на удаленном узле
                                    remote_cert_filename = f"{node.name}.crt"
                                    remote_key_filename = f"{node.name}.key"
                                    remote_ca_filename = "ca.crt"
                                    
                                    remote_cert_path = f"{remote_mtls_dir}/{remote_cert_filename}"
                                    remote_key_path = f"{remote_mtls_dir}/{remote_key_filename}"
                                    remote_ca_path = f"{remote_mtls_dir}/{remote_ca_filename}"
                                    
                                    print(f"📤 Копируем {mtls_cert_file} -> {remote_cert_path}", file=sys.stderr, flush=True)
                                    sftp.put(mtls_cert_file, remote_cert_path)
                                    
                                    print(f"📤 Копируем {mtls_key_file} -> {remote_key_path}", file=sys.stderr, flush=True)
                                    sftp.put(mtls_key_file, remote_key_path)
                                    
                                    if mtls_ca_cert_file and Path(mtls_ca_cert_file).exists():
                                        print(f"📤 Копируем {mtls_ca_cert_file} -> {remote_ca_path}", file=sys.stderr, flush=True)
                                        sftp.put(mtls_ca_cert_file, remote_ca_path)
                                    else:
                                        print(f"⚠️ CA сертификат не найден: {mtls_ca_cert_file}", file=sys.stderr, flush=True)
                                    
                                    # КРИТИЧНО: Обновляем пути в bootstrap_config - используем ОТНОСИТЕЛЬНЫЕ пути
                                    # Агент ожидает пути относительно директории агента
                                    bootstrap_config['mtls_cert_file'] = f"mtls/{remote_cert_filename}"
                                    bootstrap_config['mtls_key_file'] = f"mtls/{remote_key_filename}"
                                    bootstrap_config['mtls_ca_cert_file'] = f"mtls/{remote_ca_filename}"
                                    
                                    print(f"✅ Пути в bootstrap_config обновлены: cert={bootstrap_config['mtls_cert_file']}, key={bootstrap_config['mtls_key_file']}, ca={bootstrap_config['mtls_ca_cert_file']}", file=sys.stderr, flush=True)
                                    
                                    # Устанавливаем права
                                    chmod_mtls_cmd = f"chmod 600 {remote_key_path} && chmod 644 {remote_cert_path}"
                                    if mtls_ca_cert_file:
                                        chmod_mtls_cmd += f" && chmod 644 {remote_ca_path}"
                                    stdin, stdout, stderr = ssh_client.exec_command(chmod_mtls_cmd, timeout=5)
                                    exit_status = stdout.channel.recv_exit_status()
                                    if exit_status != 0:
                                        error_output = stderr.read().decode()
                                        print(f"⚠️ Ошибка установки прав на сертификаты: {error_output}", file=sys.stderr, flush=True)
                                    else:
                                        print(f"✅ Права на сертификаты установлены", file=sys.stderr, flush=True)
                                    
                                    print(f"✅ mTLS сертификаты скопированы на {node.name}", file=sys.stderr, flush=True)
                                except Exception as e:
                                    print(f"❌ Ошибка копирования mTLS сертификатов: {e}", file=sys.stderr, flush=True)
                                    import traceback
                                    print(f"📋 Traceback: {traceback.format_exc()}", file=sys.stderr, flush=True)
                                    raise
                                finally:
                                    sftp.close()
                            else:
                                # Если mTLS не включен, очищаем пути в bootstrap_config
                                bootstrap_config['mtls_cert_file'] = ""
                                bootstrap_config['mtls_key_file'] = ""
                                bootstrap_config['mtls_ca_cert_file'] = ""
                                print(f"⚠️ mTLS не включен для {node.name}, сертификаты не копируются", file=sys.stderr, flush=True)
                                print(f"   Причина: enabled={mtls_enabled}, cert_file={mtls_cert_file}, key_file={mtls_key_file}", file=sys.stderr, flush=True)
                            
                            service_content = f"""[Unit]
Description={role_label} Agent for {node.name}
After=network.target

[Service]
Type=simple
User={node.ssh_user}
Group={node.ssh_user}
WorkingDirectory={remote_agent_dir}
ExecStart=/usr/bin/env python3 {remote_agent_dir}/run.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""
                            
                            # Создаем временный service файл
                            temp_service = tempfile.NamedTemporaryFile(mode='w', suffix='.service', delete=False)
                            temp_service.write(service_content)
                            temp_service.close()
                            service_path = Path(temp_service.name)
                            
                            yield f"data: {json.dumps({'progress': node_progress_start + 11, 'status': f'Создание архива агента для {node.name}...', 'current_node': node.name})}\n\n"
                            print(f"📦 Начинаем создание архива из {agent_source_dir}", file=sys.stderr, flush=True)
                            
                            # Создаем архив
                            file_count = 0
                            print(f"📦 Открываем tarfile для записи: {temp_archive.name}", file=sys.stderr, flush=True)
                            
                            try:
                                with tarfile.open(temp_archive.name, 'w:gz') as tar:
                                    exclude_patterns = ['__pycache__', '.git', 'database', 'instance', '.venv', '.idea']
                                    print(f"📦 Начинаем обход директории {agent_source_dir}", file=sys.stderr, flush=True)
                                    
                                    for root, dirs, files in os_module.walk(agent_source_dir):
                                        # Фильтруем директории
                                        dirs[:] = [d for d in dirs if not any(pattern in d for pattern in exclude_patterns)]
                                        
                                        for file in files:
                                            if not any(file.endswith(ext) for ext in ['.pyc', '.pyo', '.pyo']):
                                                file_path = Path(root) / file
                                                arc_name = file_path.relative_to(agent_source_dir)
                                                try:
                                                    tar.add(file_path, arcname=str(arc_name))
                                                    file_count += 1
                                                    if file_count <= 5 or file_count % 10 == 0:
                                                        print(f"📦 Добавлен файл {file_count}: {arc_name}", file=sys.stderr, flush=True)
                                                except Exception as e:
                                                    print(f"⚠️ Ошибка при добавлении файла {file_path}: {e}", file=sys.stderr, flush=True)
                                    
                                    # Добавляем service файл
                                    setup_in_archive = f"setup/{service_name}"
                                    print(f"📦 Добавляем service файл: {service_path} -> {setup_in_archive}", file=sys.stderr, flush=True)
                                    tar.add(service_path, arcname=setup_in_archive)
                                    file_count += 1
                                    
                                    print(f"📦 Архив создан, всего файлов: {file_count}", file=sys.stderr, flush=True)
                            except Exception as e:
                                import traceback
                                error_trace = traceback.format_exc()
                                print(f"❌ Ошибка при создании архива: {e}\n{error_trace}", file=sys.stderr, flush=True)
                                raise
                            
                            archive_size = os_module.path.getsize(temp_archive.name)
                            print(f"✅ Архив создан: {file_count} файлов, размер: {archive_size / 1024:.1f} KB", file=sys.stderr, flush=True)
                            yield f"data: {json.dumps({'progress': node_progress_start + 11.5, 'status': f'Архив создан ({file_count} файлов, {archive_size / 1024:.1f} KB), отправка на {node.name}...', 'current_node': node.name})}\n\n"
                            
                            os_module.unlink(temp_service.name)
                            
                            yield f"data: {json.dumps({'progress': node_progress_start + 12, 'status': f'Копирование архива на {node.name} через SFTP...', 'current_node': node.name})}\n\n"
                            print(f"📤 Открываем SFTP соединение для {node.name}...", file=sys.stderr, flush=True)
                            
                            # Отправляем архив через SSH
                            sftp = ssh_client.open_sftp()
                            print(f"✅ SFTP соединение открыто", file=sys.stderr, flush=True)
                            
                            # Создаем директорию на удаленном узле
                            print(f"📁 Проверяем/создаем директорию {remote_agent_dir} на {node.name}...", file=sys.stderr, flush=True)
                            try:
                                sftp.stat(remote_agent_dir)
                                print(f"✅ Директория {remote_agent_dir} уже существует", file=sys.stderr, flush=True)
                            except IOError:
                                print(f"📁 Директория не существует, создаем...", file=sys.stderr, flush=True)
                                parts = remote_agent_dir.split('/')
                                current_path = ''
                                for part in parts[1:]:
                                    current_path += '/' + part
                                    try:
                                        sftp.stat(current_path)
                                    except IOError:
                                        print(f"📁 Создаем директорию {current_path}", file=sys.stderr, flush=True)
                                        mkdir_cmd = f"mkdir -p {current_path}"
                                        stdin, stdout, stderr_cmd = ssh_client.exec_command(mkdir_cmd, timeout=10)
                                        exit_status = stdout.channel.recv_exit_status()
                                        if exit_status != 0:
                                            error_out = stderr_cmd.read().decode()
                                            raise Exception(f"Не удалось создать директорию {current_path}: {error_out}")
                            
                            # Копируем архив
                            remote_archive_path = f"{remote_agent_dir}.tar.gz"
                            archive_size_mb = archive_size / (1024 * 1024)
                            print(f"📋 Копируем архив ({archive_size_mb:.2f} MB): {temp_archive.name} -> {remote_archive_path}", file=sys.stderr, flush=True)
                            
                            try:
                                # Копируем с прогрессом (callback вызывается каждые 64KB по умолчанию)
                                sftp.put(temp_archive.name, remote_archive_path)
                                print(f"✅ Архив успешно скопирован на {node.name}", file=sys.stderr, flush=True)
                            except Exception as e:
                                import traceback
                                print(f"❌ Ошибка при копировании архива: {e}\n{traceback.format_exc()}", file=sys.stderr, flush=True)
                                raise
                            
                            yield f"data: {json.dumps({'progress': node_progress_start + 13, 'status': f'Архив скопирован на {node.name}, распаковка...', 'current_node': node.name})}\n\n"
                            
                            # Распаковываем архив
                            unpack_cmd = f"tar -xzf {remote_archive_path} -C {remote_agent_dir} && rm {remote_archive_path}"
                            stdin, stdout, stderr = ssh_client.exec_command(unpack_cmd, timeout=60)
                            exit_status = stdout.channel.recv_exit_status()
                            
                            if exit_status != 0:
                                error_output = stderr.read().decode()
                                raise Exception(f"Ошибка распаковки архива: {error_output}")
                            
                            print(f"✅ Архив распакован на {node.name}", file=sys.stderr, flush=True)
                            
                            yield f"data: {json.dumps({'progress': node_progress_start + 14, 'status': f'Архив распакован на {node.name}, проверка и установка зависимостей...', 'current_node': node.name})}\n\n"
                            print(f"📦 Проверяем и устанавливаем зависимости на {node.name}...", file=sys.stderr, flush=True)
                            
                            # Проверяем и устанавливаем необходимые системные пакеты
                            required_packages = ['python3', 'python3-pip', 'curl']
                            missing_packages = []
                            
                            # Проверяем какие пакеты установлены
                            for package in required_packages:
                                check_cmd = f"which {package} || command -v {package} || echo 'not found'"
                                stdin, stdout, stderr = ssh_client.exec_command(check_cmd, timeout=5)
                                output = stdout.read().decode().strip()
                                
                                if 'not found' in output or not output:
                                    missing_packages.append(package)
                                    print(f"⚠️ Пакет {package} не найден, будет установлен", file=sys.stderr, flush=True)
                                else:
                                    print(f"✅ Пакет {package} найден", file=sys.stderr, flush=True)
                            
                            # Устанавливаем недостающие пакеты
                            if missing_packages:
                                print(f"📦 Устанавливаем недостающие пакеты: {', '.join(missing_packages)}", file=sys.stderr, flush=True)
                                
                                # Определяем менеджер пакетов
                                detect_pkg_cmd = "which apt-get || which yum || which dnf || echo 'unknown'"
                                stdin, stdout, stderr = ssh_client.exec_command(detect_pkg_cmd, timeout=5)
                                pkg_manager = stdout.read().decode().strip()
                                
                                if 'apt-get' in pkg_manager:
                                    # Ожидаем освобождения блокировки apt
                                    wait_apt_lock_cmd = "timeout 60 bash -c 'while fuser /var/lib/apt/lists/lock /var/lib/dpkg/lock /var/cache/apt/archives/lock >/dev/null 2>&1; do sleep 1; done' && echo 'lock released' || echo 'timeout or no lock'"
                                    stdin, stdout, stderr = ssh_client.exec_command(wait_apt_lock_cmd, timeout=65)
                                    lock_status = stdout.read().decode().strip()
                                    print(f"🔒 Статус блокировки apt: {lock_status}", file=sys.stderr, flush=True)
                                    
                                    install_cmd = f"sudo -n DEBIAN_FRONTEND=noninteractive apt-get update -qq && sudo -n DEBIAN_FRONTEND=noninteractive apt-get install -y -qq {' '.join(missing_packages)} 2>&1"
                                elif 'yum' in pkg_manager:
                                    # Ожидаем освобождения блокировки yum
                                    wait_yum_lock_cmd = "timeout 60 bash -c 'while [ -f /var/run/yum.pid ]; do sleep 1; done' && echo 'lock released' || echo 'timeout or no lock'"
                                    stdin, stdout, stderr = ssh_client.exec_command(wait_yum_lock_cmd, timeout=65)
                                    lock_status = stdout.read().decode().strip()
                                    print(f"🔒 Статус блокировки yum: {lock_status}", file=sys.stderr, flush=True)
                                    
                                    install_cmd = f"sudo -n yum install -y -q {' '.join(missing_packages)} 2>&1"
                                elif 'dnf' in pkg_manager:
                                    # Ожидаем освобождения блокировки dnf
                                    wait_dnf_lock_cmd = "timeout 60 bash -c 'while [ -f /var/run/dnf.pid ]; do sleep 1; done' && echo 'lock released' || echo 'timeout or no lock'"
                                    stdin, stdout, stderr = ssh_client.exec_command(wait_dnf_lock_cmd, timeout=65)
                                    lock_status = stdout.read().decode().strip()
                                    print(f"🔒 Статус блокировки dnf: {lock_status}", file=sys.stderr, flush=True)
                                    
                                    install_cmd = f"sudo -n dnf install -y -q {' '.join(missing_packages)} 2>&1"
                                else:
                                    print(f"⚠️ Неизвестный менеджер пакетов, пропускаем установку", file=sys.stderr, flush=True)
                                    install_cmd = None
                                
                                if install_cmd:
                                    stdin, stdout, stderr = ssh_client.exec_command(install_cmd, timeout=120)
                                    exit_status = stdout.channel.recv_exit_status()
                                    
                                    if exit_status != 0:
                                        error_output = stderr.read().decode()
                                        raise Exception(f"Не удалось установить пакеты {', '.join(missing_packages)}: {error_output}")
                                    
                                    print(f"✅ Системные пакеты установлены", file=sys.stderr, flush=True)
                            
                            # Проверяем и устанавливаем Python зависимости
                            yield f"data: {json.dumps({'progress': node_progress_start + 14.5, 'status': f'Установка Python зависимостей на {node.name}...', 'current_node': node.name})}\n\n"
                            print(f"🐍 Проверяем Python зависимости на {node.name}...", file=sys.stderr, flush=True)
                            
                            requirements_file = f"{remote_agent_dir}/requirements.txt"
                            
                            # Проверяем наличие requirements.txt
                            check_req_cmd = f"test -f {requirements_file} && echo 'exists' || echo 'not found'"
                            stdin, stdout, stderr = ssh_client.exec_command(check_req_cmd, timeout=5)
                            req_exists = stdout.read().decode().strip()
                            
                            if req_exists == 'exists':
                                print(f"📋 Найден requirements.txt, устанавливаем зависимости...", file=sys.stderr, flush=True)
                                
                                # Сначала обновляем pip
                                print(f"🔄 Обновляем pip...", file=sys.stderr, flush=True)
                                upgrade_pip_cmd = f"python3 -m pip install --upgrade pip --user --quiet 2>&1 || python3 -m pip install --upgrade pip --break-system-packages --quiet 2>&1"
                                stdin, stdout, stderr = ssh_client.exec_command(upgrade_pip_cmd, timeout=60)
                                
                                # Пробуем установить с --user (для пользователя)
                                print(f"📦 Устанавливаем зависимости в пользовательскую директорию...", file=sys.stderr, flush=True)
                                install_pip_cmd = f"cd {remote_agent_dir} && python3 -m pip install --user --no-warn-script-location -r requirements.txt 2>&1"
                                stdin, stdout, stderr = ssh_client.exec_command(install_pip_cmd, timeout=300)
                                exit_status_user = stdout.channel.recv_exit_status()
                                output_user = stdout.read().decode()
                                error_user = stderr.read().decode()
                                
                                if exit_status_user != 0:
                                    print(f"⚠️ Установка в --user не удалась, пробуем --break-system-packages...", file=sys.stderr, flush=True)
                                    # Пробуем с --break-system-packages (для новых систем типа Debian 12+)
                                    install_pip_cmd2 = f"cd {remote_agent_dir} && python3 -m pip install --break-system-packages --no-warn-script-location -r requirements.txt 2>&1"
                                    stdin, stdout, stderr = ssh_client.exec_command(install_pip_cmd2, timeout=300)
                                    exit_status_system = stdout.channel.recv_exit_status()
                                    output_system = stdout.read().decode()
                                    error_system = stderr.read().decode()
                                    
                                    if exit_status_system != 0:
                                        print(f"❌ Ошибка установки зависимостей:\n{error_system[:1000]}", file=sys.stderr, flush=True)
                                        raise Exception(f"Не удалось установить Python зависимости. Ошибка: {error_system[:500]}")
                                    else:
                                        print(f"✅ Python зависимости установлены (--break-system-packages)", file=sys.stderr, flush=True)
                                else:
                                    print(f"✅ Python зависимости установлены (--user)", file=sys.stderr, flush=True)
                                
                                # Проверяем что ключевые модули установлены
                                print(f"🔍 Проверяем установку ключевых модулей...", file=sys.stderr, flush=True)
                                # Модули для проверки: имя_пакета -> имя_импорта
                                check_modules = {
                                    'flask': 'flask',
                                    'Flask-SQLAlchemy': 'flask_sqlalchemy',  # Пакет Flask-SQLAlchemy, импорт flask_sqlalchemy
                                    'requests': 'requests',
                                    'cryptography': 'cryptography'
                                }
                                missing_modules = []
                                
                                for package_name, import_name in check_modules.items():
                                    check_module_cmd = f"python3 -c 'import {import_name}' 2>&1 && echo 'ok' || echo 'missing'"
                                    stdin, stdout, stderr = ssh_client.exec_command(check_module_cmd, timeout=10)
                                    result = stdout.read().decode().strip()
                                    error_check = stderr.read().decode().strip()
                                    
                                    if 'ok' in result and 'missing' not in result and 'Error' not in result and 'Traceback' not in result:
                                        print(f"✅ Модуль {package_name} (import {import_name}) установлен", file=sys.stderr, flush=True)
                                    else:
                                        missing_modules.append(package_name)
                                        print(f"❌ Модуль {package_name} (import {import_name}) НЕ установлен. Ошибка: {error_check[:200] if error_check else 'не найден'}", file=sys.stderr, flush=True)
                                
                                if missing_modules:
                                    print(f"⚠️ Не установлены модули: {', '.join(missing_modules)}, пробуем установить отдельно...", file=sys.stderr, flush=True)
                                    # Пробуем установить недостающие модули отдельно
                                    for package_name in missing_modules:
                                        print(f"📦 Устанавливаем {package_name}...", file=sys.stderr, flush=True)
                                        install_module_cmd = f"python3 -m pip install --user --no-warn-script-location {package_name} 2>&1 || python3 -m pip install --break-system-packages --no-warn-script-location {package_name} 2>&1"
                                        stdin, stdout, stderr = ssh_client.exec_command(install_module_cmd, timeout=120)
                                        exit_status = stdout.channel.recv_exit_status()
                                        output = stdout.read().decode()
                                        error_output = stderr.read().decode()
                                        
                                        if exit_status != 0:
                                            print(f"❌ Не удалось установить {package_name}: {error_output[:300]}", file=sys.stderr, flush=True)
                                            raise Exception(f"Критический модуль {package_name} не может быть установлен: {error_output[:300]}")
                                        else:
                                            print(f"✅ Модуль {package_name} установлен отдельно", file=sys.stderr, flush=True)
                                            
                                            # Проверяем еще раз после установки
                                            import_name = check_modules[package_name]
                                            verify_cmd = f"python3 -c 'import {import_name}' 2>&1 && echo 'ok' || echo 'missing'"
                                            stdin, stdout, stderr = ssh_client.exec_command(verify_cmd, timeout=10)
                                            verify_result = stdout.read().decode().strip()
                                            
                                            if 'ok' in verify_result and 'missing' not in verify_result:
                                                print(f"✅ Модуль {package_name} успешно установлен и проверен", file=sys.stderr, flush=True)
                                            else:
                                                print(f"⚠️ Модуль {package_name} установлен, но проверка не прошла", file=sys.stderr, flush=True)
                            else:
                                print(f"⚠️ requirements.txt не найден, устанавливаем минимальные зависимости...", file=sys.stderr, flush=True)
                                # Устанавливаем минимальный набор если requirements.txt нет
                                minimal_packages = ['flask>=2.0.0', 'flask-sqlalchemy>=3.0.0', 'requests>=2.31.0', 'cryptography>=41.0.0']
                                install_minimal_cmd = f"python3 -m pip install --user --no-warn-script-location {' '.join(minimal_packages)} 2>&1 || python3 -m pip install --break-system-packages --no-warn-script-location {' '.join(minimal_packages)} 2>&1"
                                stdin, stdout, stderr = ssh_client.exec_command(install_minimal_cmd, timeout=180)
                                exit_status = stdout.channel.recv_exit_status()
                                
                                if exit_status != 0:
                                    error_output = stderr.read().decode()
                                    raise Exception(f"Не удалось установить минимальные зависимости: {error_output[:500]}")
                                else:
                                    print(f"✅ Минимальные зависимости установлены", file=sys.stderr, flush=True)
                            
                            yield f"data: {json.dumps({'progress': node_progress_start + 14.7, 'status': f'Создание конфигурации на {node.name}...', 'current_node': node.name})}\n\n"
                            
                            # Создаем bootstrap_config.json
                            bootstrap_config_path = f"{remote_agent_dir}/setup/bootstrap_config.json"
                            temp_config = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
                            json_module.dump(bootstrap_config, temp_config, indent=2)
                            temp_config.close()
                            
                            sftp.put(temp_config.name, bootstrap_config_path)
                            os_module.unlink(temp_config.name)
                            
                            yield f"data: {json.dumps({'progress': node_progress_start + 15, 'status': f'Установка прав доступа на {node.name}...', 'current_node': node.name})}\n\n"
                            
                            # Устанавливаем права
                            chmod_cmd = f"chmod -R 755 {remote_agent_dir} && chmod 644 {bootstrap_config_path}"
                            ssh_client.exec_command(chmod_cmd, timeout=10)
                            
                            yield f"data: {json.dumps({'progress': node_progress_start + 16, 'status': f'Установка systemd службы на {node.name}...', 'current_node': node.name})}\n\n"
                            print(f"⚙️ Устанавливаем systemd службу на {node.name}", file=sys.stderr, flush=True)
                            
                            # Устанавливаем systemd service
                            service_file_path = f"/etc/systemd/system/{service_name}"
                            setup_dir = f"{remote_agent_dir}/setup"
                            copy_service_cmd = f"sudo -n cp {setup_dir}/{service_name} {service_file_path} && sudo -n systemctl daemon-reload && sudo -n systemctl enable {service_name}"
                            stdin, stdout, stderr = ssh_client.exec_command(copy_service_cmd, timeout=30)
                            exit_status = stdout.channel.recv_exit_status()
                            
                            if exit_status != 0:
                                error_output = stderr.read().decode()
                                raise Exception(f"Не удалось установить systemd service: {error_output}")
                            
                            print(f"✅ Systemd service установлен для {node.name}", file=sys.stderr, flush=True)
                            
                            yield f"data: {json.dumps({'progress': node_progress_start + 17, 'status': f'Запуск systemd службы на {node.name}...', 'current_node': node.name})}\n\n"
                            print(f"🚀 Запускаем systemd службу {service_name} на {node.name}", file=sys.stderr, flush=True)
                            
                            # Запускаем service с несколькими попытками
                            max_start_attempts = 3
                            service_started = False
                            
                            for attempt in range(1, max_start_attempts + 1):
                                print(f"🔄 Попытка {attempt}/{max_start_attempts} запуска сервиса...", file=sys.stderr, flush=True)
                                
                                start_service_cmd = f"sudo -n systemctl start {service_name}"
                                stdin, stdout, stderr = ssh_client.exec_command(start_service_cmd, timeout=15)
                                exit_status = stdout.channel.recv_exit_status()
                                
                                if exit_status != 0:
                                    error_output = stderr.read().decode()
                                    if attempt < max_start_attempts:
                                        print(f"⚠️ Попытка {attempt} не удалась: {error_output}, пробуем еще раз...", file=sys.stderr, flush=True)
                                        time_module.sleep(2)
                                        continue
                                    else:
                                        raise Exception(f"Не удалось запустить systemd service после {max_start_attempts} попыток: {error_output}")
                                
                                # Ждем немного перед проверкой статуса
                                print(f"⏳ Ждем 3 секунды перед проверкой статуса...", file=sys.stderr, flush=True)
                                time_module.sleep(3)
                                
                                # Проверяем статус несколько раз
                                max_status_checks = 5
                                check_interval = 2  # секунды
                                
                                for check_num in range(1, max_status_checks + 1):
                                    check_service_cmd = f"sudo -n systemctl is-active {service_name}"
                                    stdin, stdout, stderr = ssh_client.exec_command(check_service_cmd, timeout=5)
                                    service_status = stdout.read().decode().strip()
                                    error_status = stderr.read().decode().strip()
                                    
                                    print(f"🔍 Проверка {check_num}/{max_status_checks}: статус = '{service_status}'", file=sys.stderr, flush=True)
                                    
                                    if service_status == 'active':
                                        print(f"✅ Сервис активен!", file=sys.stderr, flush=True)
                                        service_started = True
                                        break
                                    elif service_status in ['activating', 'reloading']:
                                        print(f"⏳ Сервис еще активируется, ждем {check_interval} секунд...", file=sys.stderr, flush=True)
                                        time_module.sleep(check_interval)
                                    elif service_status in ['failed', 'inactive']:
                                        error_msg = f"Сервис в статусе '{service_status}'"
                                        if error_status:
                                            error_msg += f": {error_status}"
                                        
                                        # Пробуем получить детали ошибки
                                        journal_cmd = f"sudo -n journalctl -u {service_name} --no-pager -n 20"
                                        stdin, stdout, stderr = ssh_client.exec_command(journal_cmd, timeout=10)
                                        journal_output = stdout.read().decode()
                                        
                                        if journal_output:
                                            print(f"📋 Логи сервиса:\n{journal_output}", file=sys.stderr, flush=True)
                                        
                                        if attempt < max_start_attempts:
                                            print(f"⚠️ {error_msg}, пробуем перезапуск...", file=sys.stderr, flush=True)
                                            break  # Выходим из цикла проверки статуса, пробуем перезапуск
                                        else:
                                            raise Exception(f"Service не активен после {max_start_attempts} попыток запуска. Статус: {service_status}. Логи: {journal_output[:500]}")
                                    else:
                                        print(f"⚠️ Неизвестный статус: '{service_status}'", file=sys.stderr, flush=True)
                                
                                if service_started:
                                    break
                                
                                # Если не запустился, пробуем еще раз
                                if attempt < max_start_attempts:
                                    print(f"🔄 Сервис не запустился, пробуем перезапуск...", file=sys.stderr, flush=True)
                                    # Пробуем перезапуск
                                    restart_cmd = f"sudo -n systemctl restart {service_name}"
                                    stdin, stdout, stderr = ssh_client.exec_command(restart_cmd, timeout=15)
                                    time_module.sleep(3)
                            
                            if not service_started:
                                # Финальная проверка
                                check_service_cmd = f"sudo -n systemctl is-active {service_name}"
                                stdin, stdout, stderr = ssh_client.exec_command(check_service_cmd, timeout=5)
                                service_status = stdout.read().decode().strip()
                                
                                if service_status != 'active':
                                    # Получаем детальные логи
                                    journal_cmd = f"sudo -n journalctl -u {service_name} --no-pager -n 30"
                                    stdin, stdout, stderr = ssh_client.exec_command(journal_cmd, timeout=10)
                                    journal_output = stdout.read().decode()
                                    
                                    raise Exception(f"Service не активен после всех попыток. Финальный статус: {service_status}. Логи:\n{journal_output[:1000]}")
                            
                            # Финальная проверка - убеждаемся что процесс действительно работает
                            print(f"🔍 Финальная проверка: проверяем что процесс запущен...", file=sys.stderr, flush=True)
                            check_process_cmd = f"ps aux | grep -E '{remote_agent_dir}/run.py' | grep -v grep || echo 'not found'"
                            stdin, stdout, stderr = ssh_client.exec_command(check_process_cmd, timeout=5)
                            process_output = stdout.read().decode().strip()
                            
                            if 'not found' in process_output or not process_output:
                                print(f"⚠️ Процесс не найден в ps, но статус сервиса active. Может быть запускается...", file=sys.stderr, flush=True)
                                time_module.sleep(2)
                                # Проверяем еще раз
                                stdin, stdout, stderr = ssh_client.exec_command(check_process_cmd, timeout=5)
                                process_output = stdout.read().decode().strip()
                                if 'not found' in process_output or not process_output:
                                    print(f"⚠️ Процесс все еще не найден, но продолжаем...", file=sys.stderr, flush=True)
                            else:
                                print(f"✅ Процесс найден: {process_output[:100]}", file=sys.stderr, flush=True)
                            
                            print(f"✅ Systemd служба запущена и активна на {node.name}", file=sys.stderr, flush=True)
                            
                            yield f"data: {json.dumps({'progress': node_progress_start + 17.5, 'status': f'Проверка связи агента с главным сервером на {node.name}...', 'current_node': node.name})}\n\n"
                            print(f"🔍 Проверяем связь агента с главным сервером на {node.name}", file=sys.stderr, flush=True)
                            
                            # Проверка связи с главным сервером (Omnissiah)
                            # Ждем немного, чтобы агент успел запуститься
                            import time as time_module
                            time_module.sleep(3)
                            
                            # Проверяем, что агент может подключиться к Omnissiah
                            # Это можно сделать через проверку процесса или попытку подключения
                            check_connection_cmd = f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 5 http://{omnissiah_node.endpoint if omnissiah_node else 'localhost'}:{omnissiah_node.nginx_https_port if omnissiah_node and omnissiah_node.nginx_enabled else 5001}/api/v1/health || echo '000'"
                            stdin, stdout, stderr = ssh_client.exec_command(check_connection_cmd, timeout=10)
                            http_code = stdout.read().decode().strip()
                            
                            # Пока не строгая проверка - просто логируем
                            if http_code and http_code != '000':
                                print(f"✅ Связь с главным сервером установлена (HTTP {http_code})", file=sys.stderr, flush=True)
                            else:
                                print(f"⚠️ Связь с главным сервером пока не установлена (может быть нормально на раннем этапе)", file=sys.stderr, flush=True)
                            
                            sftp.close()
                            os_module.unlink(temp_archive.name)
                            
                            yield f"data: {json.dumps({'progress': node_progress_start + 18, 'status': f'ПО и служба успешно развернуты на {node.name}. Ожидание генерации ключей агентом...', 'current_node': node.name})}\n\n"
                            print(f"✅ ПО успешно развернуто на {node.name}", file=sys.stderr, flush=True)
                            print(f"⏳ Ожидаем генерацию ключей агентом и регистрацию на Omnissiah...", file=sys.stderr, flush=True)
                            
                            # В ZTN архитектуре ключи генерируются агентом при первом запуске
                            # Агент сам сгенерирует ключи и отправит их на Omnissiah через mTLS
                            # Ждем получения ключей через API endpoint /api/nodes/register_key
                            yield f"data: {json.dumps({'progress': node_progress_start + 19, 'status': f'Ожидание регистрации ключей от агента {node.name}...', 'current_node': node.name})}\n\n"
                            
                            # Ждем получения ключей от агента (максимум 60 секунд)
                            import time as time_module
                            max_wait_time = 60  # секунд
                            wait_interval = 2  # секунд
                            waited_time = 0
                            keys_received = False
                            
                            while waited_time < max_wait_time:
                                # Проверяем, получены ли ключи через API endpoint
                                with app.app_context():
                                    db_node = db.session.get(General, node.id)
                                    if db_node and db_node.public_key:
                                        keys_received = True
                                        print(f"✅ Ключи получены от агента {node.name}", file=sys.stderr, flush=True)
                                        yield f"data: {json.dumps({'progress': node_progress_start + 20, 'status': f'Ключи получены от агента {node.name}', 'current_node': node.name})}\n\n"
                                        break
                                
                                time_module.sleep(wait_interval)
                                waited_time += wait_interval
                                
                                if waited_time % 10 == 0:  # Каждые 10 секунд обновляем статус
                                    yield f"data: {json.dumps({'progress': node_progress_start + 19, 'status': f'Ожидание регистрации ключей от агента {node.name}... ({waited_time}/{max_wait_time} сек)', 'current_node': node.name})}\n\n"
                            
                            if not keys_received:
                                print(f"⚠️ Ключи не получены от агента {node.name} в течение {max_wait_time} секунд", file=sys.stderr, flush=True)
                                print(f"ℹ️ Агент должен сгенерировать ключи при первом запуске и отправить их на Omnissiah", file=sys.stderr, flush=True)
                                yield f"data: {json.dumps({'progress': node_progress_start + 19.5, 'status': f'Ключи еще не получены от агента {node.name}. Агент сгенерирует их при первом запуске.', 'current_node': node.name})}\n\n"
                        
                        # Настройка VPN
                        if node.role != 'Omnissiah':
                            yield f"data: {json.dumps({'progress': node_progress_start + 43, 'status': f'Проверка и установка WireGuard на {node.name}...', 'current_node': node.name})}\n\n"
                            print(f"🔍 Проверяем наличие WireGuard на {node.name}...", file=sys.stderr, flush=True)
                            
                            # Проверяем наличие WireGuard
                            check_wg_cmd = "which wg-quick || command -v wg-quick || which wg || command -v wg || echo 'not found'"
                            stdin, stdout, stderr = ssh_client.exec_command(check_wg_cmd, timeout=5)
                            wg_available = stdout.read().decode().strip()
                            
                            if 'not found' in wg_available or not wg_available:
                                print(f"⚠️ WireGuard не найден, устанавливаем...", file=sys.stderr, flush=True)
                                
                                # Определяем менеджер пакетов
                                detect_pkg_cmd = "which apt-get || which yum || which dnf || echo 'unknown'"
                                stdin, stdout, stderr = ssh_client.exec_command(detect_pkg_cmd, timeout=5)
                                pkg_manager = stdout.read().decode().strip()
                                
                                if 'apt-get' in pkg_manager:
                                    # Ожидаем освобождения блокировки apt
                                    wait_apt_lock_cmd = "timeout 60 bash -c 'while fuser /var/lib/apt/lists/lock /var/lib/dpkg/lock /var/cache/apt/archives/lock >/dev/null 2>&1; do sleep 1; done' && echo 'lock released' || echo 'timeout or no lock'"
                                    stdin, stdout, stderr = ssh_client.exec_command(wait_apt_lock_cmd, timeout=65)
                                    lock_status = stdout.read().decode().strip()
                                    print(f"🔒 Статус блокировки apt: {lock_status}", file=sys.stderr, flush=True)
                                    
                                    # Debian/Ubuntu - устанавливаем wireguard, resolvconf (или openresolv) и iptables
                                    install_wg_cmd = "sudo -n DEBIAN_FRONTEND=noninteractive apt-get update -qq && sudo -n DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireguard wireguard-tools resolvconf iptables 2>&1 || sudo -n DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireguard wireguard-tools openresolv iptables 2>&1"
                                elif 'yum' in pkg_manager:
                                    # Ожидаем освобождения блокировки yum
                                    wait_yum_lock_cmd = "timeout 60 bash -c 'while [ -f /var/run/yum.pid ]; do sleep 1; done' && echo 'lock released' || echo 'timeout or no lock'"
                                    stdin, stdout, stderr = ssh_client.exec_command(wait_yum_lock_cmd, timeout=65)
                                    lock_status = stdout.read().decode().strip()
                                    print(f"🔒 Статус блокировки yum: {lock_status}", file=sys.stderr, flush=True)
                                    
                                    # CentOS/RHEL
                                    install_wg_cmd = "sudo -n yum install -y -q epel-release && sudo -n yum install -y -q wireguard-tools resolvconf iptables 2>&1 || sudo -n yum install -y -q wireguard-tools openresolv iptables 2>&1"
                                elif 'dnf' in pkg_manager:
                                    # Ожидаем освобождения блокировки dnf
                                    wait_dnf_lock_cmd = "timeout 60 bash -c 'while [ -f /var/run/dnf.pid ]; do sleep 1; done' && echo 'lock released' || echo 'timeout or no lock'"
                                    stdin, stdout, stderr = ssh_client.exec_command(wait_dnf_lock_cmd, timeout=65)
                                    lock_status = stdout.read().decode().strip()
                                    print(f"🔒 Статус блокировки dnf: {lock_status}", file=sys.stderr, flush=True)
                                    
                                    # Fedora
                                    install_wg_cmd = "sudo -n dnf install -y -q wireguard-tools resolvconf iptables 2>&1 || sudo -n dnf install -y -q wireguard-tools openresolv iptables 2>&1"
                                else:
                                    raise Exception(f"Неизвестный менеджер пакетов, не могу установить WireGuard. Менеджер: {pkg_manager}")
                                
                                print(f"📦 Устанавливаем WireGuard...", file=sys.stderr, flush=True)
                                stdin, stdout, stderr = ssh_client.exec_command(install_wg_cmd, timeout=180)
                                exit_status = stdout.channel.recv_exit_status()
                                
                                if exit_status != 0:
                                    error_output = stderr.read().decode()
                                    stdout_output = stdout.read().decode()
                                    full_error = f"{error_output}\n{stdout_output}".strip()
                                    raise Exception(f"Не удалось установить WireGuard: {full_error}")
                                
                                print(f"✅ WireGuard установлен", file=sys.stderr, flush=True)
                                
                                # Проверяем еще раз
                                check_wg_again_cmd = "which wg-quick || command -v wg-quick || echo 'still not found'"
                                stdin, stdout, stderr = ssh_client.exec_command(check_wg_again_cmd, timeout=5)
                                wg_check_again = stdout.read().decode().strip()
                                
                                if 'still not found' in wg_check_again:
                                    raise Exception("WireGuard установлен, но wg-quick все еще не найден в PATH")
                                
                                print(f"✅ wg-quick найден: {wg_check_again}", file=sys.stderr, flush=True)
                            else:
                                print(f"✅ WireGuard уже установлен: {wg_available}", file=sys.stderr, flush=True)
                            
                            # В ZTN архитектуре: конфигурация WireGuard генерируется агентом на удаленном узле
                            # Агент сам создаст конфигурацию при первом запуске после генерации ключей
                            # На Omnissiah мы не генерируем конфигурацию для узла - она создается агентом
                            yield f"data: {json.dumps({'progress': node_progress_start + 45, 'status': f'Конфигурация WireGuard будет создана агентом на {node.name} при первом запуске', 'current_node': node.name})}\n\n"
                            print(f"ℹ️ Конфигурация WireGuard будет создана агентом на {node.name} при первом запуске", file=sys.stderr, flush=True)
                            print(f"ℹ️ Агент сгенерирует ключи и создаст конфигурацию автоматически", file=sys.stderr, flush=True)
                            
                            # Пропускаем генерацию конфигурации на Omnissiah - она будет создана агентом
                            wg_config = None
                            
                            # Сохраняем конфигурацию только если она была сгенерирована (в ZTN это не нужно)
                            if wg_config:
                                yield f"data: {json.dumps({'progress': node_progress_start + 47, 'status': f'Отправка конфигурации WireGuard на {node.name}...', 'current_node': node.name})}\n\n"
                                print(f"📤 Отправляем конфигурацию WireGuard на {node.name}", file=sys.stderr, flush=True)
                                
                                # Сохраняем конфигурацию на удаленном узле
                                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf') as tmp:
                                    tmp.write(wg_config)
                                    tmp_path = tmp.name
                                
                                try:
                                    # КРИТИЧНО: Для Magos/Cognitor конфигурация должна быть в /home/{user}/agents/setup/
                                    # а не в /etc/wireguard/
                                    remote_agent_dir = f"/home/{node.ssh_user}/agents"
                                    remote_path = f"{remote_agent_dir}/setup/{node.name}.conf"
                                    
                                    with open(tmp_path, 'r') as f:
                                        config_content = f.read()
                                    
                                    sftp = ssh_client.open_sftp()
                                    
                                    temp_remote_path = f"/tmp/{node.name}_wg_config.conf"
                                    with sftp.file(temp_remote_path, 'w') as remote_file:
                                        remote_file.write(config_content)
                                    
                                    yield f"data: {json.dumps({'progress': node_progress_start + 50, 'status': f'Установка конфигурации WireGuard на {node.name}...', 'current_node': node.name})}\n\n"
                                    
                                    # КРИТИЧНО: Создаем директорию agents/setup вместо /etc/wireguard
                                    mkdir_cmd = f"mkdir -p {remote_agent_dir}/setup 2>&1"
                                    stdin, stdout, stderr = ssh_client.exec_command(mkdir_cmd, timeout=5)
                                    exit_status = stdout.channel.recv_exit_status()
                                    if exit_status != 0:
                                        error_output = stderr.read().decode().strip()
                                        print(f"⚠️ Ошибка создания директории {remote_agent_dir}/setup: {error_output}", file=sys.stderr, flush=True)
                                    else:
                                        print(f"✅ Директория {remote_agent_dir}/setup создана", file=sys.stderr, flush=True)
                                    
                                    # КРИТИЧНО: Перемещаем файл без sudo, так как директория принадлежит пользователю
                                    move_cmd = f"mv {temp_remote_path} {remote_path} 2>&1"
                                    
                                    stdin, stdout, stderr = ssh_client.exec_command(move_cmd, timeout=10)
                                    exit_status = stdout.channel.recv_exit_status()
                                    
                                    if exit_status != 0:
                                        error_output = stderr.read().decode()
                                        stdout_output = stdout.read().decode()
                                        full_error = f"{error_output}\n{stdout_output}".strip()
                                        if not full_error:
                                            full_error = "Неизвестная ошибка при перемещении файла"
                                        raise Exception(f"Не удалось переместить конфигурацию: {full_error}")
                                    
                                    # Устанавливаем права (без sudo, так как файл принадлежит пользователю)
                                    chmod_cmd = f"chmod 600 {remote_path} 2>/dev/null || true"
                                    ssh_client.exec_command(chmod_cmd, timeout=5)
                                    
                                    print(f"✅ Конфигурация WireGuard сохранена в {remote_path}", file=sys.stderr, flush=True)
                                    
                                    sftp.close()
                                    
                                    # VPN включение отключено - только создаем конфигурацию
                                    yield f"data: {json.dumps({'progress': node_progress_start + 55, 'status': f'Конфигурация VPN создана на {node.name} (VPN не включается автоматически)', 'current_node': node.name})}\n\n"
                                    print(f"📝 Конфигурация VPN создана на {node.name} (автоматическое включение VPN отключено)", file=sys.stderr, flush=True)
                                    
                                    # Проверяем что конфигурация существует (без sudo)
                                    check_config_cmd = f"test -f {remote_path} && echo 'exists' || echo 'not found'"
                                    stdin, stdout, stderr = ssh_client.exec_command(check_config_cmd, timeout=5)
                                    config_exists = stdout.read().decode().strip()
                                    
                                    if config_exists != 'exists':
                                        raise Exception(f"Конфигурация WireGuard не найдена по пути {remote_path}")
                                    
                                    print(f"✅ Конфигурация найдена: {remote_path}", file=sys.stderr, flush=True)
                                    
                                    # Определяем полный путь к wg-quick (для будущего использования)
                                    find_wg_quick_cmd = "which wg-quick || command -v wg-quick || echo '/usr/bin/wg-quick'"
                                    stdin, stdout, stderr = ssh_client.exec_command(find_wg_quick_cmd, timeout=5)
                                    wg_quick_path = stdout.read().decode().strip()
                                    
                                    if not wg_quick_path or 'not found' in wg_quick_path:
                                        wg_quick_path = '/usr/bin/wg-quick'  # Fallback
                                    
                                    print(f"🔍 Путь к wg-quick определен: {wg_quick_path} (для будущего использования)", file=sys.stderr, flush=True)
                                    
                                    # Пропускаем включение VPN - конфигурация создана, VPN можно включить вручную
                                    print(f"⏭️ Пропускаем автоматическое включение VPN (отключено пользователем)", file=sys.stderr, flush=True)
                                    yield f"data: {json.dumps({'progress': node_progress_start + 60, 'status': f'Конфигурация VPN создана на {node.name}. VPN можно включить вручную.', 'current_node': node.name})}\n\n"
                                    
                                except Exception as config_error:
                                    print(f"❌ Ошибка сохранения конфигурации WireGuard на {node.name}: {config_error}", file=sys.stderr, flush=True)
                                    raise Exception(f"Не удалось сохранить конфигурацию WireGuard на {node.name}: {str(config_error)}")
                                finally:
                                    # Удаляем временный файл если он был создан
                                    if 'tmp_path' in locals() and os_module.path.exists(tmp_path):
                                        os_module.unlink(tmp_path)
                            else:
                                # В ZTN архитектуре конфигурация создается агентом, не на Omnissiah
                                print(f"ℹ️ Конфигурация WireGuard будет создана агентом на {node.name} при первом запуске", file=sys.stderr, flush=True)
                                yield f"data: {json.dumps({'progress': node_progress_start + 46, 'status': f'Конфигурация WireGuard будет создана агентом на {node.name} при первом запуске', 'current_node': node.name})}\n\n"
                                
                                # Комментируем весь блок включения VPN
                                # Блок включения VPN закомментирован по запросу пользователя
                                """
                                # Определяем полный путь к wg (для проверок)
                                find_wg_cmd = "which wg || command -v wg || echo '/usr/bin/wg'"
                                stdin, stdout, stderr = ssh_client.exec_command(find_wg_cmd, timeout=5)
                                wg_path = stdout.read().decode().strip()
                                
                                if not wg_path or 'not found' in wg_path:
                                    wg_path = '/usr/bin/wg'  # Fallback
                                
                                print(f"🔍 Используем путь к wg: {wg_path}", file=sys.stderr, flush=True)
                                
                                # Проверяем наличие iptables (необходимо для wg-quick)
                                yield f"data: {json.dumps({'progress': node_progress_start + 55, 'status': f'Проверка iptables на {node.name}...', 'current_node': node.name})}\n\n"
                                print(f"🔍 Проверяем наличие iptables на {node.name}...", file=sys.stderr, flush=True)
                                
                                check_iptables_cmd = "which iptables-restore || command -v iptables-restore || which iptables || command -v iptables || echo 'not found'"
                                stdin, stdout, stderr = ssh_client.exec_command(check_iptables_cmd, timeout=5)
                                iptables_available = stdout.read().decode().strip()
                                
                                if 'not found' in iptables_available or (not iptables_available or iptables_available == ''):
                                    print(f"⚠️ iptables не найден, устанавливаем...", file=sys.stderr, flush=True)
                                    
                                    # Определяем менеджер пакетов
                                    detect_pkg_cmd = "which apt-get || which yum || which dnf || echo 'unknown'"
                                    stdin, stdout, stderr = ssh_client.exec_command(detect_pkg_cmd, timeout=5)
                                    pkg_manager = stdout.read().decode().strip()
                                    
                                    if 'apt-get' in pkg_manager:
                                        # Ожидаем освобождения блокировки apt
                                        wait_apt_lock_cmd = "timeout 60 bash -c 'while fuser /var/lib/apt/lists/lock /var/lib/dpkg/lock /var/cache/apt/archives/lock >/dev/null 2>&1; do sleep 1; done' && echo 'lock released' || echo 'timeout or no lock'"
                                        stdin, stdout, stderr = ssh_client.exec_command(wait_apt_lock_cmd, timeout=65)
                                        lock_status = stdout.read().decode().strip()
                                        print(f"🔒 Статус блокировки apt: {lock_status}", file=sys.stderr, flush=True)
                                        
                                        install_iptables_cmd = "sudo -n DEBIAN_FRONTEND=noninteractive apt-get update -qq && sudo -n DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables 2>&1"
                                    elif 'yum' in pkg_manager:
                                        # Ожидаем освобождения блокировки yum
                                        wait_yum_lock_cmd = "timeout 60 bash -c 'while [ -f /var/run/yum.pid ]; do sleep 1; done' && echo 'lock released' || echo 'timeout or no lock'"
                                        stdin, stdout, stderr = ssh_client.exec_command(wait_yum_lock_cmd, timeout=65)
                                        lock_status = stdout.read().decode().strip()
                                        print(f"🔒 Статус блокировки yum: {lock_status}", file=sys.stderr, flush=True)
                                        
                                        install_iptables_cmd = "sudo -n yum install -y -q iptables 2>&1"
                                    elif 'dnf' in pkg_manager:
                                        # Ожидаем освобождения блокировки dnf
                                        wait_dnf_lock_cmd = "timeout 60 bash -c 'while [ -f /var/run/dnf.pid ]; do sleep 1; done' && echo 'lock released' || echo 'timeout or no lock'"
                                        stdin, stdout, stderr = ssh_client.exec_command(wait_dnf_lock_cmd, timeout=65)
                                        lock_status = stdout.read().decode().strip()
                                        print(f"🔒 Статус блокировки dnf: {lock_status}", file=sys.stderr, flush=True)
                                        
                                        install_iptables_cmd = "sudo -n dnf install -y -q iptables 2>&1"
                                    else:
                                        raise Exception(f"Неизвестный менеджер пакетов, не могу установить iptables. Менеджер: {pkg_manager}")
                                    
                                    print(f"📦 Устанавливаем iptables...", file=sys.stderr, flush=True)
                                    stdin, stdout, stderr = ssh_client.exec_command(install_iptables_cmd, timeout=60)
                                    exit_status = stdout.channel.recv_exit_status()
                                    
                                    if exit_status != 0:
                                        error_output = stderr.read().decode()
                                        stdout_output = stdout.read().decode()
                                        full_error = f"{error_output}\n{stdout_output}".strip()
                                        raise Exception(f"Не удалось установить iptables: {full_error}")
                                    
                                    print(f"✅ iptables установлен", file=sys.stderr, flush=True)
                                else:
                                    print(f"✅ iptables уже установлен: {iptables_available}", file=sys.stderr, flush=True)
                                
                                # Включаем VPN
                                print(f"🚀 Выполняем команду: {wg_quick_path} up {node.name}", file=sys.stderr, flush=True)
                                wg_up_cmd = f"sudo -n {wg_quick_path} up {node.name} 2>&1"
                                stdin, stdout, stderr = ssh_client.exec_command(wg_up_cmd, timeout=30)
                                
                                # Читаем вывод
                                stdout_output = stdout.read().decode()
                                stderr_output = stderr.read().decode()
                                exit_status = stdout.channel.recv_exit_status()
                                
                                # Объединяем stdout и stderr для проверки (wg-quick выводит команды в stdout)
                                combined_output = f"{stdout_output}\n{stderr_output}"
                                
                                print(f"📋 Вывод команды wg-quick up:\nstdout: {stdout_output}\nstderr: {stderr_output}", file=sys.stderr, flush=True)
                                
                                # Проверяем, есть ли ошибка с resolvconf или iptables-restore, но интерфейс создан
                                if exit_status != 0:
                                    # Проверяем, создан ли интерфейс несмотря на ошибку
                                    check_interface_cmd = f"sudo -n ip link show {node.name} 2>&1 || echo 'not found'"
                                    stdin, stdout, stderr = ssh_client.exec_command(check_interface_cmd, timeout=5)
                                    interface_status = stdout.read().decode()
                                    
                                    # Проверяем тип ошибки (wg-quick выводит команды и ошибки в stdout)
                                    resolvconf_error = ('resolvconf' in combined_output.lower()) and ('not found' in combined_output.lower() or 'command not found' in combined_output.lower())
                                    iptables_error = ('iptables-restore' in combined_output.lower()) and ('not found' in combined_output.lower() or 'command not found' in combined_output.lower())
                                    
                                    # Если ошибка только из-за resolvconf или iptables-restore, но интерфейс создан - продолжаем
                                    if (resolvconf_error or iptables_error) and 'not found' not in interface_status.lower() and node.name in interface_status:
                                        if resolvconf_error:
                                            print(f"⚠️ Ошибка с resolvconf, но интерфейс {node.name} создан. VPN работает без DNS автонастройки. Продолжаем...", file=sys.stderr, flush=True)
                                        if iptables_error:
                                            print(f"⚠️ Ошибка с iptables-restore, но интерфейс {node.name} создан. Продолжаем...", file=sys.stderr, flush=True)
                                        
                                        # Проверяем что интерфейс действительно активен
                                        check_wg_active_cmd = f"sudo -n {wg_path} show {node.name} 2>&1"
                                        stdin, stdout, stderr = ssh_client.exec_command(check_wg_active_cmd, timeout=5)
                                        wg_check_output = stdout.read().decode()
                                        
                                        if node.name in wg_check_output or 'interface' in wg_check_output.lower() or 'public key' in wg_check_output.lower():
                                            print(f"✅ VPN интерфейс активен несмотря на ошибку", file=sys.stderr, flush=True)
                                            # Продолжаем - VPN работает
                                        else:
                                            # Интерфейс не активен, это реальная ошибка
                                            error_msg = f"Интерфейс создан, но WireGuard не активен. Ошибка: {stderr_output}"
                                            raise Exception(f"Не удалось включить VPN на {node.name}: {error_msg}")
                                        
                                        # Устанавливаем недостающие пакеты для будущего использования (в фоне)
                                        try:
                                            if resolvconf_error:
                                                install_resolvconf_cmd = "sudo -n DEBIAN_FRONTEND=noninteractive apt-get install -y -qq resolvconf 2>&1 || sudo -n DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openresolv 2>&1 || sudo -n yum install -y -q resolvconf 2>&1 || sudo -n yum install -y -q openresolv 2>&1 || sudo -n dnf install -y -q resolvconf 2>&1 || sudo -n dnf install -y -q openresolv 2>&1 || echo 'resolvconf install failed'"
                                                ssh_client.exec_command(install_resolvconf_cmd, timeout=60)
                                            if iptables_error:
                                                install_iptables_cmd = "sudo -n DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables 2>&1 || sudo -n yum install -y -q iptables 2>&1 || sudo -n dnf install -y -q iptables 2>&1 || echo 'iptables install failed'"
                                                ssh_client.exec_command(install_iptables_cmd, timeout=60)
                                        except (OSError, subprocess.SubprocessError, AttributeError):
                                            pass
                                    else:
                                        # Используем combined_output для формирования сообщения об ошибке
                                        error_msg = combined_output.strip() if combined_output.strip() else (stderr_output if stderr_output else stdout_output)
                                        if not error_msg or error_msg.strip() == '':
                                            error_msg = f"Неизвестная ошибка при включении VPN (exit_status={exit_status})"
                                        print(f"❌ Ошибка включения VPN (exit_status={exit_status}): {error_msg}", file=sys.stderr, flush=True)
                                        
                                        # Пробуем получить больше информации
                                        check_wg_error_cmd = f"sudo -n {wg_path} show {node.name} 2>&1 || echo 'interface not found'"
                                        stdin, stdout, stderr = ssh_client.exec_command(check_wg_error_cmd, timeout=5)
                                        wg_status = stdout.read().decode()
                                        print(f"📋 Статус WireGuard после ошибки: {wg_status}", file=sys.stderr, flush=True)
                                        
                                        raise Exception(f"Не удалось включить VPN на {node.name}: {error_msg}")
                                
                                print(f"✅ VPN включен на {node.name}", file=sys.stderr, flush=True)
                                
                                yield f"data: {json.dumps({'progress': node_progress_start + 58, 'status': f'Проверка VPN на {node.name}...', 'current_node': node.name})}\n\n"
                                print(f"🔍 Проверяем VPN на {node.name}", file=sys.stderr, flush=True)
                                
                                # Проверяем, что WireGuard интерфейс активен
                                # Используем уже найденный путь к wg
                                check_wg_cmd = f"sudo -n {wg_path} show {node.name} 2>&1"
                                stdin, stdout, stderr = ssh_client.exec_command(check_wg_cmd, timeout=10)
                                wg_output = stdout.read().decode()
                                wg_error = stderr.read().decode()
                                
                                if 'interface' in wg_output.lower() or node.name in wg_output or 'public key' in wg_output.lower():
                                    print(f"✅ VPN интерфейс активен на {node.name}", file=sys.stderr, flush=True)
                                else:
                                    error_msg = wg_error if wg_error else "Интерфейс не найден"
                                    raise Exception(f"VPN интерфейс не активен: {error_msg}")
                                
                                yield f"data: {json.dumps({'progress': node_progress_start + 60, 'status': f'VPN успешно включен и проверен на {node.name}', 'current_node': node.name})}\n\n"
                                print(f"✅ VPN успешно включен и проверен на {node.name}", file=sys.stderr, flush=True)
                                """
                        
                        # Применение политик безопасности (VPN больше не включается автоматически, но политики применяем)
                        if node.role in ['Magos', 'Cognitor']:
                            yield f"data: {json.dumps({'progress': node_progress_start + 62, 'status': f'Применение политик безопасности на {node.name}...', 'current_node': node.name})}\n\n"
                            print(f"🔒 Применяем политики безопасности на {node.name}", file=sys.stderr, flush=True)
                            
                            # Проверяем наличие iptables
                            check_iptables_cmd = "which iptables || command -v iptables || echo 'not found'"
                            stdin, stdout, stderr = ssh_client.exec_command(check_iptables_cmd, timeout=5)
                            iptables_path = stdout.read().decode().strip()
                            has_iptables = iptables_path and 'not found' not in iptables_path
                            iptables_cmd_prefix = iptables_path if iptables_path and has_iptables else 'iptables'
                            
                            if has_iptables:
                                # Создаем системные правила
                                omnissiah_node = General.query.filter_by(role='Omnissiah').first()
                                parent_node = node.parent if node.parent_id else omnissiah_node
                                
                                if node.role == 'Magos':
                                    from omnissiah_core.nmc_system_rules_generator import create_system_rules_for_magos
                                    admin_ip = omnissiah_node.admin_ip if omnissiah_node else None
                                    system_rules_data, extra_commands_data = create_system_rules_for_magos(
                                        node, omnissiah=omnissiah_node, mtls_port=5001, admin_ip=admin_ip
                                    )
                                elif node.role == 'Cognitor':
                                    from omnissiah_core.nmc_system_rules_generator import create_system_rules_for_cognitor
                                    admin_ip = omnissiah_node.admin_ip if omnissiah_node else None
                                    system_rules_data, extra_commands_data = create_system_rules_for_cognitor(
                                        node, omnissiah=omnissiah_node, parent=parent_node, admin_ip=admin_ip
                                    )
                                else:
                                    system_rules_data, extra_commands_data = [], []
                                
                                # Применяем системные правила
                                sudo_password = node_data.get('ssh_password')
                                for rule_data in system_rules_data:
                                    try:
                                        temp_rule = AccessPolicyRule()
                                        for key, value in rule_data.items():
                                            if hasattr(temp_rule, key):
                                                setattr(temp_rule, key, value)
                                        if 'direction' in rule_data:
                                            temp_rule.direction = rule_data['direction']
                                        
                                        iptables_cmds = generate_iptables_commands_for_rule(temp_rule)
                                        for cmd_list in iptables_cmds:
                                            if isinstance(cmd_list, list):
                                                # КРИТИЧНО: Экранируем комментарий для безопасной передачи через SSH
                                                # Используем shlex.quote для экранирования всего комментария
                                                import shlex
                                                escaped_cmd = []
                                                i = 0
                                                cmd_list_with_prefix = ['sudo', '-n', iptables_cmd_prefix] + cmd_list
                                                while i < len(cmd_list_with_prefix):
                                                    arg = cmd_list_with_prefix[i]
                                                    # Если это --comment, экранируем следующий аргумент (комментарий)
                                                    if arg == '--comment' and i + 1 < len(cmd_list_with_prefix):
                                                        escaped_cmd.append(arg)
                                                        escaped_cmd.append(shlex.quote(cmd_list_with_prefix[i + 1]))
                                                        i += 2
                                                    else:
                                                        escaped_cmd.append(arg)
                                                        i += 1
                                                iptables_cmd = ' '.join(escaped_cmd)
                                                stdin, stdout, stderr = ssh_client.exec_command(iptables_cmd, timeout=10)
                                                exit_status = stdout.channel.recv_exit_status()
                                                if exit_status != 0:
                                                    error_output = stderr.read().decode()
                                                    app.logger.warning(f"Не удалось применить системное правило iptables: {error_output}")
                                    except Exception as e:
                                        app.logger.warning(f"Ошибка применения системного правила: {str(e)}")
                                
                                # КРИТИЧНО: Применяем дополнительные команды в правильном порядке
                                # Сначала все разрешающие правила, потом политики DROP
                                policy_commands = []
                                regular_commands = []
                                
                                for extra_cmd in extra_commands_data:
                                    if extra_cmd.get('chain') == 'POLICY':
                                        policy_commands.append(extra_cmd)
                                    else:
                                        regular_commands.append(extra_cmd)
                                
                                # Сначала применяем все разрешающие правила
                                for extra_cmd in regular_commands:
                                    try:
                                        cmd_list = extra_cmd.get('cmd', [])
                                        if cmd_list:
                                            iptables_cmd = ' '.join(['sudo', '-n', iptables_cmd_prefix] + cmd_list)
                                            stdin, stdout, stderr = ssh_client.exec_command(iptables_cmd, timeout=10)
                                            exit_status = stdout.channel.recv_exit_status()
                                            if exit_status == 0:
                                                app.logger.info(f"Применено системное правило: {extra_cmd.get('description', '')}")
                                            else:
                                                error_output = stderr.read().decode()
                                                app.logger.warning(f"Ошибка применения правила {extra_cmd.get('description', '')}: {error_output}")
                                    except Exception as e:
                                        app.logger.warning(f"Ошибка применения дополнительного правила: {str(e)}")
                                
                                # Затем применяем политики DROP (в самом конце)
                                for policy_cmd in policy_commands:
                                    try:
                                        cmd_list = policy_cmd.get('cmd', [])
                                        if cmd_list:
                                            iptables_cmd = ' '.join(['sudo', '-n', iptables_cmd_prefix] + cmd_list)
                                            stdin, stdout, stderr = ssh_client.exec_command(iptables_cmd, timeout=10)
                                            exit_status = stdout.channel.recv_exit_status()
                                            if exit_status == 0:
                                                app.logger.info(f"Применена политика: {policy_cmd.get('description', '')}")
                                            else:
                                                error_output = stderr.read().decode()
                                                app.logger.warning(f"Ошибка применения политики {policy_cmd.get('description', '')}: {error_output}")
                                    except Exception as e:
                                        app.logger.warning(f"Ошибка применения политики: {str(e)}")
                                
                                # КРИТИЧНО: Разрешаем весь трафик через VPN интерфейс (для доступа с админа и к Omnissiah)
                                try:
                                    # Разрешаем весь INPUT трафик через VPN интерфейс
                                    vpn_accept_input_cmd = f"sudo -n {iptables_cmd_prefix} -A INPUT -i {node.name} -j ACCEPT"
                                    stdin, stdout, stderr = ssh_client.exec_command(vpn_accept_input_cmd, timeout=5)
                                    exit_status = stdout.channel.recv_exit_status()
                                    if exit_status == 0:
                                        print(f"✅ Разрешен INPUT трафик через VPN интерфейс {node.name}", file=sys.stderr, flush=True)
                                    
                                    # Разрешаем весь OUTPUT трафик через VPN интерфейс
                                    vpn_accept_output_cmd = f"sudo -n {iptables_cmd_prefix} -A OUTPUT -o {node.name} -j ACCEPT"
                                    stdin, stdout, stderr = ssh_client.exec_command(vpn_accept_output_cmd, timeout=5)
                                    exit_status = stdout.channel.recv_exit_status()
                                    if exit_status == 0:
                                        print(f"✅ Разрешен OUTPUT трафик через VPN интерфейс {node.name}", file=sys.stderr, flush=True)
                                    
                                    # Разрешаем FORWARD трафик через VPN интерфейс
                                    vpn_accept_forward_cmd = f"sudo -n {iptables_cmd_prefix} -A FORWARD -i {node.name} -j ACCEPT"
                                    stdin, stdout, stderr = ssh_client.exec_command(vpn_accept_forward_cmd, timeout=5)
                                    exit_status = stdout.channel.recv_exit_status()
                                    if exit_status == 0:
                                        print(f"✅ Разрешен FORWARD трафик через VPN интерфейс {node.name}", file=sys.stderr, flush=True)
                                    
                                    vpn_accept_forward_out_cmd = f"sudo -n {iptables_cmd_prefix} -A FORWARD -o {node.name} -j ACCEPT"
                                    stdin, stdout, stderr = ssh_client.exec_command(vpn_accept_forward_out_cmd, timeout=5)
                                    exit_status = stdout.channel.recv_exit_status()
                                    if exit_status == 0:
                                        print(f"✅ Разрешен FORWARD OUTPUT трафик через VPN интерфейс {node.name}", file=sys.stderr, flush=True)
                                    
                                except Exception as e:
                                    print(f"⚠️ Ошибка добавления правил для VPN интерфейса: {e}", file=sys.stderr, flush=True)
                                
                                # Применяем правила доступа
                                access_rules = AccessPolicyRule.query.filter(
                                    ((AccessPolicyRule.source_type == 'node') & (AccessPolicyRule.source_id == node.id)) |
                                    ((AccessPolicyRule.destination_type == 'node') & (AccessPolicyRule.destination_id == node.id))
                                ).filter(AccessPolicyRule.status.in_(['applied', 'pending'])).all()
                                
                                protected_objects = ProtectedObject.query.filter_by(node_id=node.id).all()
                                for po in protected_objects:
                                    po_rules = AccessPolicyRule.query.filter(
                                        ((AccessPolicyRule.source_type == 'protected_object') & (AccessPolicyRule.source_id == po.id)) |
                                        ((AccessPolicyRule.destination_type == 'protected_object') & (AccessPolicyRule.destination_id == po.id))
                                    ).filter(AccessPolicyRule.status.in_(['applied', 'pending'])).all()
                                    access_rules.extend(po_rules)
                                
                                access_rules = list(set(access_rules))
                                applied_rules_count = 0
                                
                                for rule in access_rules:
                                    try:
                                        nodes_to_apply = determine_nodes_for_rule(rule)
                                        if node not in nodes_to_apply:
                                            continue
                                        
                                        iptables_cmds = generate_iptables_commands_for_rule(rule)
                                        if not iptables_cmds:
                                            continue
                                        
                                        if has_iptables:
                                            for cmd_list in iptables_cmds:
                                                if isinstance(cmd_list, list):
                                                    # КРИТИЧНО: Экранируем комментарий для безопасной передачи через SSH
                                                    import shlex
                                                    escaped_cmd = []
                                                    i = 0
                                                    cmd_list_with_prefix = ['sudo', '-n', iptables_cmd_prefix] + cmd_list
                                                    while i < len(cmd_list_with_prefix):
                                                        arg = cmd_list_with_prefix[i]
                                                        # Если это --comment, экранируем следующий аргумент (комментарий)
                                                        if arg == '--comment' and i + 1 < len(cmd_list_with_prefix):
                                                            escaped_cmd.append(arg)
                                                            escaped_cmd.append(shlex.quote(cmd_list_with_prefix[i + 1]))
                                                            i += 2
                                                        else:
                                                            escaped_cmd.append(arg)
                                                            i += 1
                                                    iptables_cmd = ' '.join(escaped_cmd)
                                                    stdin, stdout, stderr = ssh_client.exec_command(iptables_cmd, timeout=10)
                                                    exit_status = stdout.channel.recv_exit_status()
                                                    if exit_status == 0:
                                                        applied_rules_count += 1
                                    except Exception as e:
                                        app.logger.warning(f"Ошибка применения правила доступа {rule.id}: {str(e)}")
                            
                                yield f"data: {json.dumps({'progress': node_progress_start + 65, 'status': f'Политики безопасности применены на {node.name}', 'current_node': node.name})}\n\n"
                                print(f"✅ Политики безопасности применены на {node.name}", file=sys.stderr, flush=True)
                            else:
                                print(f"⚠️ iptables не найден на {node.name}, пропускаем применение политик безопасности", file=sys.stderr, flush=True)
                        
                        # КРИТИЧНО: Определяем и сохраняем реальный внешний IP в endpoint ДО закрытия SSH
                        # Это необходимо для синхронизации пиров на Omnissiah
                        # ВАЖНО: node_data['ip'] - это VPN IP, а не реальный внешний IP для SSH
                        if node.role in ['Magos', 'Cognitor']:
                            # Пытаемся определить реальный внешний IP из SSH подключения
                            real_external_ip = None
                            if ssh_client:
                                try:
                                    # КРИТИЧНО: Получаем IP адрес, к которому мы подключились (это реальный внешний IP Magos)
                                    # getpeername() возвращает адрес удаленного хоста (Magos)
                                    transport = ssh_client.get_transport()
                                    if transport:
                                        sock = transport.sock
                                        if sock:
                                            # getpeername() возвращает (host, port) удаленного хоста
                                            remote_addr = sock.getpeername()
                                            if remote_addr:
                                                real_external_ip = remote_addr[0]
                                                app.logger.info(f"✅ Определен реальный внешний IP из SSH подключения для {node.name}: {real_external_ip}")
                                                print(f"🌐 Определен реальный внешний IP из SSH подключения для {node.name}: {real_external_ip}", file=sys.stderr, flush=True)
                                            else:
                                                app.logger.warning(f"Не удалось получить адрес из getpeername() для {node.name}")
                                                print(f"⚠️ Не удалось получить адрес из getpeername() для {node.name}", file=sys.stderr, flush=True)
                                        else:
                                            app.logger.warning(f"SSH transport.sock не доступен для {node.name}")
                                            print(f"⚠️ SSH transport.sock не доступен для {node.name}", file=sys.stderr, flush=True)
                                    else:
                                        app.logger.warning(f"SSH transport не доступен для {node.name}")
                                        print(f"⚠️ SSH transport не доступен для {node.name}", file=sys.stderr, flush=True)
                                except Exception as ip_err:
                                    app.logger.warning(f"Не удалось определить IP из SSH подключения для {node.name}: {ip_err}")
                                    print(f"⚠️ Не удалось определить IP из SSH подключения для {node.name}: {ip_err}", file=sys.stderr, flush=True)
                            
                            # Если не удалось определить из SSH, проверяем существующие поля
                            if not real_external_ip:
                                # Проверяем ssh_ip - если это не VPN IP, используем его
                                if node.ssh_ip:
                                    try:
                                        if node.ip_pool:
                                            vpn_network = ip_network(node.ip_pool, strict=False)
                                            ssh_ip_addr = IPv4Address(node.ssh_ip.split(':')[0] if ':' in node.ssh_ip else node.ssh_ip)
                                            if ssh_ip_addr not in vpn_network:
                                                real_external_ip = node.ssh_ip.split(':')[0] if ':' in node.ssh_ip else node.ssh_ip
                                    except (ValueError, AttributeError):
                                        pass
                            
                            # Если все еще нет реального IP, используем ssh_ip как есть (может быть это и есть реальный IP)
                            if not real_external_ip and node.ssh_ip:
                                real_external_ip = node.ssh_ip.split(':')[0] if ':' in node.ssh_ip else node.ssh_ip
                                app.logger.warning(f"Используем ssh_ip как реальный IP для {node.name}: {real_external_ip} (не проверено)")
                            
                            # Сохраняем реальный IP в endpoint
                            if real_external_ip:
                                node.endpoint = real_external_ip
                                # Также обновляем ssh_ip если он был VPN IP
                                if node.ssh_ip and node.ip_pool:
                                    try:
                                        vpn_network = ip_network(node.ip_pool, strict=False)
                                        ssh_ip_addr = IPv4Address(node.ssh_ip.split(':')[0] if ':' in node.ssh_ip else node.ssh_ip)
                                        if ssh_ip_addr in vpn_network:
                                            # ssh_ip был VPN IP, обновляем на реальный
                                            node.ssh_ip = real_external_ip
                                            app.logger.info(f"Обновлен ssh_ip с VPN IP на реальный IP для {node.name}: {real_external_ip}")
                                    except (ValueError, AttributeError):
                                        pass
                                
                                app.logger.info(f"✅ Сохраняем реальный внешний IP в endpoint для {node.name}: {real_external_ip}")
                                print(f"💾 Сохраняем реальный внешний IP в endpoint для {node.name}: {real_external_ip}", file=sys.stderr, flush=True)
                            else:
                                app.logger.warning(f"⚠️ Не удалось определить реальный внешний IP для {node.name}")
                                print(f"⚠️ Не удалось определить реальный внешний IP для {node.name}", file=sys.stderr, flush=True)
                            
                            # КРИТИЧНО: Устанавливаем статус 'active' для Magos/Cognitor после успешного развертывания
                            # Это необходимо чтобы sync_wireguard_peers мог найти узел
                            if node.status != 'active':
                                node.status = 'active'
                                app.logger.info(f"Устанавливаем статус 'active' для {node.name}")
                                print(f"✅ Устанавливаем статус 'active' для {node.name}", file=sys.stderr, flush=True)
                            
                            db.session.commit()
                            app.logger.info(f"✅ Данные узла {node.name} сохранены в БД: endpoint={node.endpoint}, status={node.status}")
                            print(f"✅ Данные узла {node.name} сохранены в БД: endpoint={node.endpoint}, status={node.status}", file=sys.stderr, flush=True)
                        
                        # Закрываем SSH ПОСЛЕ определения IP
                        if ssh_client:
                            ssh_client.close()
                        
                        deployed_nodes.append(node)
                        print(f"✅ Узел {node.name} добавлен в deployed_nodes. Всего развернуто: {len(deployed_nodes)}/{total_nodes}", file=sys.stderr, flush=True)
                        yield f"data: {json.dumps({'progress': 15 + ((i + 1) * 70 / total_nodes), 'status': f'Узел {node.name} успешно развернут', 'current_node': node.name, 'node_status': 'success', 'deployed_count': len(deployed_nodes), 'total_count': total_nodes})}\n\n"
                        
                        # КРИТИЧНО: Если развернут Magos, синхронизируем пиры на Omnissiah
                        # ВАЖНО: Это должно быть после установки статуса 'active' и сохранения endpoint
                        if node.role == 'Magos':
                            print(f"🔍 Проверяем необходимость синхронизации пиров для Magos {node.name}...", file=sys.stderr, flush=True)
                            try:
                                omnissiah = General.query.filter_by(role='Omnissiah').first()
                                if omnissiah:
                                    app.logger.info(f"🔄 Синхронизируем пиры на Omnissiah после развертывания {node.name}")
                                    print(f"🔄 Синхронизируем пиры на Omnissiah после развертывания {node.name}", file=sys.stderr, flush=True)
                                    app.logger.info(f"  - Endpoint Magos: {node.endpoint}")
                                    app.logger.info(f"  - SSH IP Magos: {node.ssh_ip}")
                                    app.logger.info(f"  - Статус Magos: {node.status}")
                                    app.logger.info(f"  - Public Key Magos: {node.public_key[:20]}...")
                                    print(f"  📋 Endpoint Magos: {node.endpoint}", file=sys.stderr, flush=True)
                                    print(f"  📋 SSH IP Magos: {node.ssh_ip}", file=sys.stderr, flush=True)
                                    print(f"  📋 Статус Magos: {node.status}", file=sys.stderr, flush=True)
                                    
                                    sync_result = sync_wireguard_peers(omnissiah)
                                    if sync_result:
                                        app.logger.info(f"✅ Пиры успешно синхронизированы на Omnissiah для {node.name}")
                                        print(f"✅ Конфигурация Omnissiah обновлена с peer для {node.name}", file=sys.stderr, flush=True)
                                        
                                        # Проверяем что peer действительно добавлен
                                        try:
                                            result = subprocess.run(
                                                ["sudo", "-n", "wg", "show", omnissiah.name, "dump"],
                                                capture_output=True,
                                                text=True,
                                                timeout=5
                                            )
                                            if result.returncode == 0 and node.public_key in result.stdout:
                                                app.logger.info(f"✅ Peer {node.name} подтвержден в конфигурации Omnissiah")
                                                print(f"✅ Peer {node.name} подтвержден в конфигурации Omnissiah", file=sys.stderr, flush=True)
                                            else:
                                                app.logger.warning(f"⚠️ Peer {node.name} не найден в выводе wg show")
                                                print(f"⚠️ Peer {node.name} не найден в выводе wg show", file=sys.stderr, flush=True)
                                        except Exception as check_err:
                                            app.logger.warning(f"Ошибка проверки peer: {check_err}")
                                            print(f"⚠️ Ошибка проверки peer: {check_err}", file=sys.stderr, flush=True)
                                    else:
                                        app.logger.warning(f"❌ Не удалось синхронизировать пиры на Omnissiah для {node.name}")
                                        print(f"❌ Не удалось синхронизировать пиры на Omnissiah для {node.name}", file=sys.stderr, flush=True)
                                else:
                                    app.logger.warning(f"⚠️ Omnissiah не найден в БД, пропускаем синхронизацию")
                                    print(f"⚠️ Omnissiah не найден в БД, пропускаем синхронизацию", file=sys.stderr, flush=True)
                            except Exception as sync_error:
                                app.logger.error(f"❌ Ошибка синхронизации пиров после развертывания {node.name}: {sync_error}", exc_info=True)
                                print(f"❌ Ошибка синхронизации пиров на Omnissiah: {sync_error}", file=sys.stderr, flush=True)
                                import traceback
                                print(f"Traceback: {traceback.format_exc()}", file=sys.stderr, flush=True)
                        else:
                            print(f"ℹ️ Узел {node.name} не является Magos (role={node.role}), пропускаем синхронизацию", file=sys.stderr, flush=True)
                        
                    except Exception as e:
                        deployment_error = str(e)
                        try:
                            app.logger.error(f"❌ Ошибка развертывания узла {node.name}: {deployment_error}")
                        except (AttributeError, RuntimeError):
                            pass
                        
                        if ssh_client:
                            try:
                                ssh_client.close()
                            except (OSError, AttributeError):
                                pass
                        
                        yield f"data: {json.dumps({'progress': 15 + ((i + 1) * 70 / total_nodes), 'status': f'Ошибка развертывания {node.name}: {deployment_error}', 'current_node': node.name, 'node_status': 'error', 'error': deployment_error})}\n\n"
                        
                        # Откат
                        yield f"data: {json.dumps({'progress': 90, 'status': f'Начинаем откат из-за ошибки на {node.name}...', 'stage': 'rollback'})}\n\n"
                        
                        rollback_nodes = deployed_nodes + [n for n in created_nodes if n not in deployed_nodes]
                        success, errors, log = rollback_deployment_nodes(rollback_nodes, nodes)
                        
                        yield f"data: {json.dumps({'progress': 95, 'status': 'Откат завершен', 'stage': 'rollback_complete', 'errors': errors})}\n\n"
                        
                        # Очищаем сессию
                        try:
                            session.pop('deployment_nodes', None)
                            session.pop('parent_relations', None)
                            session.pop('direct_connections', None)
                            session.pop('deployment_active', None)
                            session.pop('deployment_stop_requested', None)
                            session.modified = True  # КРИТИЧНО: Помечаем сессию как измененную
                            session.permanent = True  # КРИТИЧНО: Делаем сессию постоянной
                            print(f"✅ Очищаем флаги развертывания после ошибки", file=sys.stderr, flush=True)
                        except (AttributeError, RuntimeError, KeyError):
                            pass
                        
                        yield f"data: {json.dumps({'complete': True, 'success': False, 'active': False, 'error': f'Ошибка развертывания узла {node.name}: {deployment_error}', 'errors': errors})}\n\n"
                        
                        # КРИТИЧНО: Добавляем небольшую задержку перед завершением генератора
                        import time
                        time.sleep(0.5)
                        
                        return
                
                # КРИТИЧНО: Проверяем, что все узлы действительно развернуты
                print(f"📊 Итоги развертывания: создано узлов={len(created_nodes)}, развернуто узлов={len(deployed_nodes)}, всего узлов={total_nodes}", file=sys.stderr, flush=True)
                
                # КРИТИЧНО: Проверяем, что цикл развертывания завершился
                if len(deployed_nodes) != total_nodes:
                    print(f"⚠️ ВНИМАНИЕ: Развернуто узлов ({len(deployed_nodes)}) не совпадает с общим количеством ({total_nodes})", file=sys.stderr, flush=True)
                    # Это может быть нормально, если некоторые узлы были пропущены (например, Omnissiah)
                    # Но логируем для диагностики
                
                # КРИТИЧНО: Очищаем сессию ПЕРЕД отправкой финального сообщения
                # чтобы очистка произошла пока еще есть контекст запроса
                # ВАЖНО: Очищаем сессию в контексте app_context, но проверяем request context
                try:
                    from flask import has_request_context
                    # Пытаемся очистить сессию напрямую
                    try:
                        # КРИТИЧНО: Очищаем сессию пока еще есть контекст запроса
                        session.pop('deployment_nodes', None)
                        session.pop('parent_relations', None)
                        session.pop('direct_connections', None)
                        session.pop('deployment_active', None)
                        session.pop('deployment_stop_requested', None)
                        session.pop('deployment_start_time', None)
                        session.modified = True
                        session.permanent = True
                        print(f"✅ Очищены флаги развертывания ПЕРЕД отправкой финального сообщения", file=sys.stderr, flush=True)
                        app.logger.info("✅ Очищены флаги развертывания после успешного завершения")
                    except RuntimeError as ctx_error:
                        if 'outside of request context' in str(ctx_error):
                            print(f"⚠️ Работаем вне контекста запроса при очистке сессии", file=sys.stderr, flush=True)
                            # Отправляем сигнал клиенту для очистки через API
                            yield f"data: {json.dumps({'clear_session': True, 'message': 'Очистите сессию через /api/deployment/status'})}\n\n"
                        else:
                            raise
                    except (AttributeError, KeyError) as sess_error:
                        print(f"⚠️ Ошибка очистки сессии (нормально если сессия уже очищена): {sess_error}", file=sys.stderr, flush=True)
                except Exception as e:
                    print(f"⚠️ Неожиданная ошибка при очистке сессии: {e}", file=sys.stderr, flush=True)
                
                # Все узлы успешно развернуты - отправляем финальное сообщение
                yield f"data: {json.dumps({'progress': 100, 'status': f'Все {total_nodes} узлов успешно развернуты!', 'complete': True, 'success': True, 'active': False, 'deployed_count': len(deployed_nodes), 'total_count': total_nodes})}\n\n"
                print(f"✅ Финальное сообщение отправлено: все узлы развернуты", file=sys.stderr, flush=True)
                
                # КРИТИЧНО: Добавляем небольшую задержку перед завершением генератора
                # чтобы убедиться, что последнее сообщение отправлено и сессия сохранена
                import time
                time.sleep(1.0)  # Увеличена задержка для гарантии сохранения сессии
                
                # КРИТИЧНО: Отправляем финальное подтверждение завершения
                yield f"data: {json.dumps({'complete': True, 'final': True, 'message': 'Генератор завершен'})}\n\n"
                
                print(f"🏁 Генератор развертывания завершен", file=sys.stderr, flush=True)
                
                # КРИТИЧНО: Дополнительная задержка для гарантии отправки всех сообщений
                time.sleep(0.5)
                
            except Exception as e:
                import traceback
                error_trace = traceback.format_exc()
                print(f"❌ Критическая ошибка в deployment stream: {str(e)}\n{error_trace}", file=sys.stderr, flush=True)
                try:
                    app.logger.error(f'Ошибка в deployment stream: {str(e)}\n{error_trace}')
                except (AttributeError, RuntimeError):
                    pass
                
                # КРИТИЧНО: Отправляем сообщение об ошибке
                try:
                    yield f"data: {json.dumps({'error': f'Ошибка: {str(e)}', 'complete': True, 'success': False, 'active': False})}\n\n"
                except Exception as yield_error:
                    print(f"⚠️ Ошибка при отправке сообщения об ошибке: {yield_error}", file=sys.stderr, flush=True)
                
                # КРИТИЧНО: Очищаем сессию при ошибке (делаем это ОДИН раз, но тщательно)
                try:
                    from flask import has_request_context
                    if has_request_context():
                        session.pop('deployment_active', None)
                        session.pop('deployment_stop_requested', None)
                        session.pop('deployment_nodes', None)
                        session.pop('parent_relations', None)
                        session.pop('direct_connections', None)
                        session.pop('deployment_start_time', None)
                        session.modified = True
                        session.permanent = True
                        print(f"✅ Очищены флаги развертывания после критической ошибки", file=sys.stderr, flush=True)
                        app.logger.info("✅ Очищены флаги развертывания после критической ошибки")
                    else:
                        print(f"⚠️ Нет контекста запроса при ошибке, сессия будет очищена через /api/deployment/status", file=sys.stderr, flush=True)
                except RuntimeError as ctx_error:
                    if 'outside of request context' in str(ctx_error):
                        print(f"⚠️ Работаем вне контекста запроса при ошибке, сессия будет очищена автоматически", file=sys.stderr, flush=True)
                    else:
                        print(f"⚠️ Ошибка при очистке сессии: {ctx_error}", file=sys.stderr, flush=True)
                        app.logger.warning(f"⚠️ Ошибка при очистке сессии: {ctx_error}")
                except (AttributeError, KeyError) as cleanup_error:
                    print(f"⚠️ Ошибка при очистке сессии: {cleanup_error}", file=sys.stderr, flush=True)
                    app.logger.warning(f"⚠️ Ошибка при очистке сессии: {cleanup_error}")
                
                # КРИТИЧНО: Добавляем небольшую задержку перед завершением генератора
                import time
                time.sleep(0.5)
    
    print(f"🔵 Создан генератор, возвращаем response_class для {len(nodes)} узлов", file=sys.stderr, flush=True)
    
    response = app.response_class(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive',
            'Content-Type': 'text/event-stream; charset=utf-8'
        }
    )
    
    print(f"🔵 Response создан, возвращаем его", file=sys.stderr, flush=True)
    return response


@app.route('/api/deployment/stop', methods=['POST'])
@login_required
@admin_required
def api_deployment_stop():
    """
    Остановка активного развертывания
    """
    from flask import session as flask_session
    
    try:
        flask_session['deployment_stop_requested'] = True
        app.logger.info("Запрошена остановка развертывания")
        return jsonify({'success': True, 'message': 'Остановка развертывания запрошена'})
    except Exception as e:
        app.logger.error(f"Ошибка при запросе остановки развертывания: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/deployment/status', methods=['GET'])
@login_required
@admin_required
def api_deployment_status():
    """
    Получение статуса активного развертывания
    """
    import sys
    from flask import session as flask_session
    
    # КРИТИЧНО: Проверяем не только флаг, но и наличие узлов в сессии
    # Если узлов нет, но флаг активен - это означает что развертывание завершено
    is_active = flask_session.get('deployment_active', False)
    has_nodes = bool(flask_session.get('deployment_nodes', []))
    deployment_start_time = flask_session.get('deployment_start_time', None)
    
    # КРИТИЧНО: Если флаг активен, но узлов нет - развертывание завершено, очищаем флаг
    # Также проверяем, не прошло ли много времени с момента старта (более 10 минут = завершено)
    if is_active:
        if not has_nodes:
            print(f"🧹 API: Флаг deployment_active=True, но узлов нет - очищаем флаг", file=sys.stderr, flush=True)
            app.logger.info("🧹 API: Очищаем флаг deployment_active: узлов нет в сессии")
            flask_session.pop('deployment_active', None)
            flask_session.pop('deployment_stop_requested', None)
            flask_session.pop('deployment_start_time', None)
            flask_session.pop('parent_relations', None)
            flask_session.pop('direct_connections', None)
            flask_session.modified = True
            flask_session.permanent = True
            is_active = False
            print(f"✅ API: Сессия очищена успешно (нет узлов)", file=sys.stderr, flush=True)
        elif deployment_start_time:
            # Проверяем, не прошло ли слишком много времени (более 10 минут = зависшее развертывание)
            import time as time_module
            elapsed_time = time_module.time() - deployment_start_time
            if elapsed_time > 600:  # 10 минут - если развертывание длится дольше, считаем его зависшим
                print(f"🧹 API: Флаг deployment_active=True, но прошло {elapsed_time:.0f} сек (>10 мин) - очищаем как зависшее", file=sys.stderr, flush=True)
                app.logger.warning(f"🧹 API: Очищаем зависшее развертывание ({elapsed_time:.0f} сек)")
                flask_session.pop('deployment_active', None)
                flask_session.pop('deployment_stop_requested', None)
                flask_session.pop('deployment_nodes', None)
                flask_session.pop('deployment_start_time', None)
                flask_session.pop('parent_relations', None)
                flask_session.pop('direct_connections', None)
                flask_session.modified = True
                flask_session.permanent = True
                is_active = False
                print(f"✅ API: Сессия очищена (зависшее развертывание)", file=sys.stderr, flush=True)
    # Проверяем таймаут (30 минут = 1800 секунд)
    elif is_active and deployment_start_time:
        import time as time_module
        elapsed_time = time_module.time() - deployment_start_time
        if elapsed_time > 1800:  # 30 минут
            print(f"⚠️ Флаг deployment_active=True, но превышен таймаут ({elapsed_time:.0f} сек) - очищаем флаг", file=sys.stderr, flush=True)
            app.logger.warning(f"⚠️ Очищаем флаг deployment_active: превышен таймаут ({elapsed_time:.0f} сек)")
            flask_session.pop('deployment_active', None)
            flask_session.pop('deployment_stop_requested', None)
            flask_session.pop('deployment_nodes', None)
            flask_session.pop('deployment_start_time', None)
            flask_session.modified = True
            flask_session.permanent = True
            is_active = False
    
    stop_requested = flask_session.get('deployment_stop_requested', False)
    
    return jsonify({
        'active': is_active,
        'stop_requested': stop_requested,
        'nodes': flask_session.get('deployment_nodes', []),
        'complete': not is_active  # КРИТИЧНО: Явно указываем что развертывание завершено
    })


@app.route('/api/deployment/clear', methods=['POST'])
@login_required
@admin_required
def api_deployment_clear():
    """
    Принудительная очистка сессии развертывания
    Используется для очистки зависших развертываний
    """
    import sys
    from flask import session as flask_session
    
    try:
        print(f"🧹 API CLEAR: Принудительная очистка сессии развертывания", file=sys.stderr, flush=True)
        flask_session.pop('deployment_active', None)
        flask_session.pop('deployment_stop_requested', None)
        flask_session.pop('deployment_nodes', None)
        flask_session.pop('deployment_start_time', None)
        flask_session.pop('parent_relations', None)
        flask_session.pop('direct_connections', None)
        flask_session.modified = True
        flask_session.permanent = True
        print(f"✅ API CLEAR: Сессия очищена успешно", file=sys.stderr, flush=True)
        app.logger.info("✅ Принудительная очистка сессии развертывания выполнена")
        return jsonify({'success': True, 'message': 'Сессия развертывания очищена'})
    except Exception as e:
        print(f"❌ API CLEAR: Ошибка очистки сессии: {e}", file=sys.stderr, flush=True)
        app.logger.error(f"Ошибка принудительной очистки сессии: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/notifications/status', methods=['GET'])
@login_required
@admin_required
def api_notifications_status():
    """
    Получение статусов для панели уведомлений:
    - Развертывание
    - Применение политик
    - Статусы узлов
    """
    from flask import session as flask_session
    
    result = {
        'deployment': {
            'active': False,
            'nodes': []
        },
        'policies': {
            'pending': 0,
            'applying': 0,
            'failed': 0
        },
        'nodes': {
            'omnissiah': None,
            'others': []
        }
    }
    
    # Статус развертывания
    is_active = flask_session.get('deployment_active', False)
    has_nodes = bool(flask_session.get('deployment_nodes', []))
    
    if is_active and not has_nodes:
        # Развертывание завершено, очищаем флаг
        flask_session.pop('deployment_active', None)
        flask_session.pop('deployment_stop_requested', None)
        flask_session.modified = True
        is_active = False
    
    result['deployment']['active'] = is_active
    result['deployment']['nodes'] = flask_session.get('deployment_nodes', [])
    
    # Статусы политик безопасности
    try:
        from nmc_models import AccessPolicyRule
        pending_rules = AccessPolicyRule.query.filter_by(status='pending').count()
        applied_rules = AccessPolicyRule.query.filter_by(status='applied').count()
        failed_rules = AccessPolicyRule.query.filter_by(status='failed').count()
        
        # Проверяем, есть ли правила в процессе применения (можно добавить поле 'applying' если нужно)
        result['policies']['pending'] = pending_rules
        result['policies']['applying'] = 0  # Пока нет отдельного статуса 'applying'
        result['policies']['failed'] = failed_rules
        result['policies']['total'] = AccessPolicyRule.query.count()
    except Exception as e:
        app.logger.error(f"Ошибка получения статусов политик: {e}")
    
    # Статусы узлов
    try:
        omnissiah = General.query.filter_by(role='Omnissiah').first()
        if omnissiah:
            result['nodes']['omnissiah'] = {
                'id': omnissiah.id,
                'name': omnissiah.name,
                'status': omnissiah.status,
                'role': omnissiah.role
            }
        
        # Остальные узлы (Magos и Cognitor)
        other_nodes = General.query.filter(General.role.in_(['Magos', 'Cognitor'])).all()
        result['nodes']['others'] = [
            {
                'id': node.id,
                'name': node.name,
                'status': node.status,
                'role': node.role
            }
            for node in other_nodes
        ]
        
        # Подсчитываем узлы по статусам
        result['nodes']['stats'] = {
            'active': len([n for n in other_nodes if n.status == 'active']),
            'inactive': len([n for n in other_nodes if n.status == 'inactive']),
            'stopped': len([n for n in other_nodes if n.status == 'stopped']),
            'total': len(other_nodes)
        }
    except Exception as e:
        app.logger.error(f"Ошибка получения статусов узлов: {e}")
    
    return jsonify(result)


def generate_bootstrap_config(node):
    """Генерирует bootstrap_config.json и WG конфигурацию для узла"""
    # Проверяем наличие обязательных полей
    if not node or not node.ip_pool:
        return None
    
    # Определяем родителя: для Cognitor это может быть Magos, для Magos - Omnissiah
    if node.role == 'Cognitor':
        parent = node.parent  # Родитель может быть Magos или Omnissiah
    elif node.role == 'Magos':
        parent = General.query.filter_by(role='Omnissiah').first()
    else:
        parent = None
    
    # Если для Cognitor нет родителя, ищем Omnissiah
    if node.role == 'Cognitor' and not parent:
        parent = General.query.filter_by(role='Omnissiah').first()
    
    # Получаем расшифрованный private_key
    decrypted_private_key = get_decrypted_private_key(node)
    if not decrypted_private_key:
        return None
    
    # Генерируем WireGuard конфигурацию
    wg_config = f"""[Interface]
PrivateKey = {decrypted_private_key}
Address = {node.ip_pool}
DNS = {parent.dns if parent and parent.dns else '1.1.1.1'}
MTU = {parent.mtu if parent and parent.mtu else 1420}
"""
    
    if node.role == 'Magos':
        wg_config += f"ListenPort = {node.listen_port}\n"
    
    if parent:
        wg_config += f"""
[Peer]
PublicKey = {parent.public_key}
AllowedIPs = 0.0.0.0/0
Endpoint = {parent.endpoint}:{parent.listen_port}
PersistentKeepalive = 25"""
        if node.preshared_key:
            wg_config += f"\nPresharedKey = {node.preshared_key}"
    
    # Генерируем bootstrap_config.json
    omnissiah_server = General.query.filter_by(role='Omnissiah').first()
    if omnissiah_server:
        server_url = get_api_url(omnissiah_server, endpoint="", default_port=33787, use_ip=True)
    else:
        server_url = "http://127.0.0.1:33787"
    
    # Получаем информацию об Omnissiah для подключения
    omnissiah_public_key = None
    omnissiah_endpoint = None
    omnissiah_listen_port = None
    omnissiah_ip_pool = None
    
    if omnissiah_server:
        omnissiah_public_key = omnissiah_server.public_key
        omnissiah_endpoint = omnissiah_server.endpoint or get_real_external_ip(omnissiah_server)
        omnissiah_listen_port = omnissiah_server.listen_port
        omnissiah_ip_pool = omnissiah_server.ip_pool
    
    bootstrap_config = {
        "name": node.name,
        "server_url": server_url,
        "ip_pool": node.ip_pool,
        "listen_port": node.listen_port,
        "dns": node.dns if node.dns else (parent.dns if parent else '1.1.1.1'),
        "mtu": node.mtu if node.mtu else (parent.mtu if parent else 1420),
        "public_key": node.public_key,
        "private_key": node.private_key,
        "endpoint": node.endpoint,
        "preshared_key": node.preshared_key,
        "role": node.role,
        "parent_id": node.parent_id,
        "api_token": "",
        "mtls_cert_file": "",
        "mtls_key_file": "",
        "mtls_ca_cert_file": "",
        "master_key": os.environ.get('WG_MASTER_KEY', ''),
        # Информация об Omnissiah для подключения
        "omnissiah_public_key": omnissiah_public_key,
        "omnissiah_endpoint": omnissiah_endpoint,
        "omnissiah_listen_port": omnissiah_listen_port,
        "omnissiah_ip_pool": omnissiah_ip_pool
    }
    
    # Для Magos добавляем mTLS сертификаты (Cognitor не использует mTLS напрямую)
    if node.role == 'Magos' and node.mtls_enabled:
        if node.mtls_server_cert_path:
            bootstrap_config["mtls_cert_file"] = f"mtls/{Path(node.mtls_server_cert_path).name}"
        if node.mtls_server_key_path:
            bootstrap_config["mtls_key_file"] = f"mtls/{Path(node.mtls_server_key_path).name}"
        if node.mtls_ca_cert_path:
            bootstrap_config["mtls_ca_cert_file"] = f"mtls/{Path(node.mtls_ca_cert_path).name}"
    
    return {
        'bootstrap_config': bootstrap_config,
        'wg_config': wg_config
    }


@app.route('/api/ssh/update_software/<int:node_id>', methods=['POST'])
@login_required
@admin_required
def api_ssh_update_software(node_id):
    """
    Обновление ПО на удаленном узле через VPN (заменяет SSH)
    
    Отправляет зашифрованный архив через VPN канал
    """
    try:
        node = db.session.get(General, node_id)
        if not node or node.role not in ['Magos', 'Cognitor']:
            return jsonify({'success': False, 'error': 'Invalid node. Update only for Magos and Cognitor'}), 400
        
        # Проверяем что узел имеет VPN IP и активен
        if not node.ip_pool:
            return jsonify({
                'success': False,
                'error': 'Узел не имеет VPN IP адреса. Обновление возможно только через VPN.'
            }), 400
        
        # Проверяем что VPN активен на узле (для Magos проверяем heartbeat, для Cognitor - handshake)
        can_use_vpn = False
        if node.role == 'Magos':
            # Для Magos проверяем последний heartbeat
            if node.last_heartbeat:
                time_since = (datetime.now(timezone.utc) - 
                             (node.last_heartbeat.replace(tzinfo=timezone.utc) if node.last_heartbeat.tzinfo is None else node.last_heartbeat))
                can_use_vpn = time_since.total_seconds() < 120  # Не более 2 минут назад
        elif node.role == 'Cognitor':
            # Для Cognitor проверяем handshake
            if node.last_handshake:
                time_since = (datetime.now(timezone.utc) - 
                             (node.last_handshake.replace(tzinfo=timezone.utc) if node.last_handshake.tzinfo is None else node.last_handshake))
                can_use_vpn = time_since.total_seconds() < 180  # Не более 3 минут назад
        
        if not can_use_vpn:
            return jsonify({
                'success': False,
                'error': 'VPN не активен на узле. Сначала включите VPN или используйте SSH для первой установки.'
            }), 400
        
        # Используем VPN для отправки обновления
        try:
            from omnissiah_core.nmc_vpn_software_update import send_software_update_via_vpn
            
            success, error_msg = send_software_update_via_vpn(
                node, 
                archive_type='update', 
                app=app,
                check_connectivity=True  # Проверяем VPN перед отправкой
            )
            
            if success:
                return jsonify({
                    'success': True,
                    'message': 'Software updated successfully via VPN'
                }), 200
            else:
                return jsonify({
                    'success': False,
                    'error': error_msg or 'Failed to update software via VPN'
                }), 500
        
        except ImportError as e:
            app.logger.error(f"Failed to import vpn_software_update: {e}")
            return jsonify({
                'success': False,
                'error': 'VPN update module not available'
            }), 500
        except Exception as e:
            app.logger.error(f"VPN update software error: {str(e)}")
            import traceback
            app.logger.error(traceback.format_exc())
            return jsonify({'success': False, 'error': str(e)}), 500
            
    except Exception as e:
        app.logger.error(f"Update software error: {str(e)}")
        import traceback
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/wireguard/sync_peers', methods=['POST'])
@login_required
@admin_required
def api_sync_wireguard_peers():
    """
    Синхронизация пиров WireGuard на Omnissiah с данными из БД
    """
    try:
        omnissiah = General.query.filter_by(role='Omnissiah').first()
        if not omnissiah:
            return jsonify({'success': False, 'error': 'Omnissiah node not found'}), 404
        
        if omnissiah.status != 'active':
            return jsonify({'success': False, 'error': 'Omnissiah VPN is not active. Please enable it first.'}), 400
        
        success = sync_wireguard_peers(omnissiah)
        if success:
            return jsonify({'success': True, 'message': 'WireGuard peers synchronized successfully'}), 200
        else:
            return jsonify({'success': False, 'error': 'Failed to synchronize peers'}), 500
    except Exception as e:
        app.logger.error(f"Sync peers error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/ssh/disable_vpn/<int:node_id>', methods=['POST'])
@login_required
@admin_required
def api_ssh_disable_vpn(node_id):
    """
    Выключение VPN на удаленном узле через SSH
    """
    try:
        data = request.get_json() or {}
        
        # КРИТИЧНО: Логируем полученные данные для диагностики
        app.logger.info(f"api_ssh_disable_vpn вызван для node_id={node_id}, данные: {list(data.keys())}")
        
        # КРИТИЧНО: Поддерживаем оба варианта имен полей для совместимости
        # Используем strip() для удаления пробелов и проверяем на пустую строку
        ip = (data.get('ip') or data.get('ssh_ip') or '').strip() or None
        user = (data.get('user') or data.get('ssh_user') or '').strip() or None
        password = (data.get('password') or data.get('ssh_password') or '').strip() or None
        sudo_password = data.get('sudo_password')
        
        # КРИТИЧНО: Логируем полученные значения (без пароля в логах)
        app.logger.info(f"Получены SSH данные: ip={ip}, user={user}, password={'***' if password else 'None'}, ssh_key_file={data.get('ssh_key_file')}, ssh_key_data={'***' if data.get('ssh_key_data') else 'None'}")
        
        node = db.session.get(General, node_id)
        if not node or node.role not in ['Magos', 'Cognitor']:
            return jsonify({'success': False, 'error': 'Invalid node. VPN disable only for Magos and Cognitor'}), 400
        
        # Если SSH данные не переданы, пытаемся определить из узла
        if not ip:
            # Пробуем получить IP из различных полей узла
            ip = (node.ssh_ip or 
                  (node.endpoint.split(':')[0] if node.endpoint and ':' in node.endpoint else None) or 
                  node.endpoint or 
                  (node.ip_pool.split('/')[0] if node.ip_pool else None) or
                  node.heartbeat_ip)
            if ip:
                ip = str(ip).strip()
            app.logger.info(f"IP определен из узла: {ip}")
        if not user:
            user = (node.ssh_user or 'root').strip()
            app.logger.info(f"User определен из узла: {user}")
        
        # Поддержка SSH ключей
        ssh_key_file = data.get('ssh_key_file')
        ssh_key_data = data.get('ssh_key_data')
        
        # Если не указан пароль и ключ, пробуем найти ключ по умолчанию
        if not password and not ssh_key_file and not ssh_key_data:
            try:
                from omnissiah_utils.nmc_ssh_utils import get_default_ssh_key_path
                ssh_key_file = get_default_ssh_key_path(node.name)
                if ssh_key_file:
                    app.logger.info(f"Найден ключ по умолчанию: {ssh_key_file}")
            except Exception as e:
                app.logger.warning(f"Не удалось найти ключ по умолчанию: {e}")
        
        # КРИТИЧНО: Улучшенная проверка - проверяем на None и пустую строку
        # ip и user должны быть непустыми строками
        # password, ssh_key_file или ssh_key_data должны быть указаны
        ip_valid = ip and isinstance(ip, str) and len(ip.strip()) > 0
        user_valid = user and isinstance(user, str) and len(user.strip()) > 0
        credentials_valid = (password and len(password.strip()) > 0) or (ssh_key_file and len(str(ssh_key_file).strip()) > 0) or (ssh_key_data and len(str(ssh_key_data).strip()) > 0)
        
        app.logger.info(f"Проверка валидности: ip_valid={ip_valid}, user_valid={user_valid}, credentials_valid={credentials_valid}")
        
        if not (ip_valid and user_valid and credentials_valid):
            error_details = []
            if not ip_valid:
                error_details.append(f"IP не указан или пустой (получено: {ip})")
            if not user_valid:
                error_details.append(f"User не указан или пустой (получено: {user})")
            if not credentials_valid:
                error_details.append("Не указан пароль, ssh_key_file или ssh_key_data")
            
            app.logger.error(f"Ошибка валидации SSH данных: {', '.join(error_details)}")
            return jsonify({
                'success': False,
                'error': 'Missing SSH credentials. Please provide IP, user and password or SSH key',
                'details': error_details
            }), 400
        
        try:
            from omnissiah_utils.nmc_ssh_utils import connect_ssh_with_key_or_password
            
            ssh, error_msg = connect_ssh_with_key_or_password(
                hostname=ip,
                username=user,
                password=password,
                key_file=ssh_key_file,
                key_data=ssh_key_data,
                timeout=30
            )
            
            if ssh is None:
                return jsonify({'success': False, 'error': error_msg or 'SSH connection failed'}), 500
            
            try:
                remote_agent_dir = f"/home/{user}/agents"
                conf_path = f"{remote_agent_dir}/setup/{node.name}.conf"
                
                # Команда для выключения WireGuard интерфейса
                if sudo_password:
                    disable_cmd = f"echo '{sudo_password}' | sudo -S wg-quick down {conf_path}"
                else:
                    disable_cmd = f"sudo wg-quick down {conf_path}"
                
                stdin, stdout, stderr = ssh.exec_command(disable_cmd, timeout=30)
                stdout_output = stdout.read().decode().strip()
                stderr_output = stderr.read().decode().strip()
                exit_status = stdout.channel.recv_exit_status()
                
                if exit_status != 0:
                    error_msg = stderr_output if stderr_output else stdout_output
                    # Проверяем если интерфейс уже выключен
                    if 'does not exist' in error_msg.lower() or 'not found' in error_msg.lower():
                        # Обновляем статус в БД
                        node.status = 'stopped'
                        node.last_handshake = None  # Очищаем handshake при выключении
                        db.session.commit()
                        ssh.close()
                        return jsonify({'success': True, 'message': 'VPN already disabled'}), 200
                    
                    ssh.close()
                    return jsonify({'success': False, 'error': f'Failed to disable VPN: {error_msg}'}), 500
                
                # Обновляем статус в БД при успешном выключении
                node.status = 'stopped'
                node.last_handshake = None  # Очищаем handshake при выключении
                db.session.commit()
                
                ssh.close()
                return jsonify({'success': True, 'message': 'VPN disabled successfully'}), 200
                
            except Exception as e:
                ssh.close()
                app.logger.error(f"SSH disable VPN error: {str(e)}")
                import traceback
                app.logger.error(traceback.format_exc())
                return jsonify({'success': False, 'error': str(e)}), 500
                
        except ImportError:
            return jsonify({'success': False, 'error': 'paramiko library not installed'}), 500
        except Exception as e:
            app.logger.error(f"SSH connection error: {str(e)}")
            return jsonify({'success': False, 'error': f'SSH connection failed: {str(e)}'}), 500
            
    except Exception as e:
        app.logger.error(f"Disable VPN error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/ssh/enable_vpn/<int:node_id>', methods=['POST'])
@login_required
@admin_required
def api_ssh_enable_vpn(node_id):
    """
    Включение VPN на удаленном узле через SSH
    """
    try:
        data = request.get_json() or {}
        
        # КРИТИЧНО: Логируем полученные данные для диагностики
        app.logger.info(f"api_ssh_enable_vpn вызван для node_id={node_id}, данные: {list(data.keys())}")
        
        # КРИТИЧНО: Поддерживаем оба варианта имен полей для совместимости
        # Используем strip() для удаления пробелов и проверяем на пустую строку
        ip = (data.get('ip') or data.get('ssh_ip') or '').strip() or None
        user = (data.get('user') or data.get('ssh_user') or '').strip() or None
        password = (data.get('password') or data.get('ssh_password') or '').strip() or None
        sudo_password = data.get('sudo_password')
        
        # КРИТИЧНО: Логируем полученные значения (без пароля в логах)
        app.logger.info(f"Получены SSH данные: ip={ip}, user={user}, password={'***' if password else 'None'}, ssh_key_file={data.get('ssh_key_file')}, ssh_key_data={'***' if data.get('ssh_key_data') else 'None'}")
        
        node = db.session.get(General, node_id)
        if not node or node.role not in ['Magos', 'Cognitor']:
            return jsonify({'success': False, 'error': 'Invalid node. VPN enable only for Magos and Cognitor'}), 400
        
        # Если SSH данные не переданы, пытаемся определить из узла
        if not ip:
            # Пробуем получить IP из различных полей узла
            ip = (node.ssh_ip or 
                  (node.endpoint.split(':')[0] if node.endpoint and ':' in node.endpoint else None) or 
                  node.endpoint or 
                  (node.ip_pool.split('/')[0] if node.ip_pool else None) or
                  node.heartbeat_ip)
            if ip:
                ip = str(ip).strip()
            app.logger.info(f"IP определен из узла: {ip}")
        if not user:
            user = (node.ssh_user or 'root').strip()
            app.logger.info(f"User определен из узла: {user}")
        
        # Поддержка SSH ключей
        ssh_key_file = data.get('ssh_key_file')
        ssh_key_data = data.get('ssh_key_data')
        
        # Если не указан пароль и ключ, пробуем найти ключ по умолчанию
        if not password and not ssh_key_file and not ssh_key_data:
            try:
                from omnissiah_utils.nmc_ssh_utils import get_default_ssh_key_path
                ssh_key_file = get_default_ssh_key_path(node.name)
                if ssh_key_file:
                    app.logger.info(f"Найден ключ по умолчанию: {ssh_key_file}")
            except Exception as e:
                app.logger.warning(f"Не удалось найти ключ по умолчанию: {e}")
        
        # КРИТИЧНО: Улучшенная проверка - проверяем на None и пустую строку
        # ip и user должны быть непустыми строками
        # password, ssh_key_file или ssh_key_data должны быть указаны
        ip_valid = ip and isinstance(ip, str) and len(ip.strip()) > 0
        user_valid = user and isinstance(user, str) and len(user.strip()) > 0
        credentials_valid = (password and len(password.strip()) > 0) or (ssh_key_file and len(str(ssh_key_file).strip()) > 0) or (ssh_key_data and len(str(ssh_key_data).strip()) > 0)
        
        app.logger.info(f"Проверка валидности: ip_valid={ip_valid}, user_valid={user_valid}, credentials_valid={credentials_valid}")
        
        if not (ip_valid and user_valid and credentials_valid):
            error_details = []
            if not ip_valid:
                error_details.append(f"IP не указан или пустой (получено: {ip})")
            if not user_valid:
                error_details.append(f"User не указан или пустой (получено: {user})")
            if not credentials_valid:
                error_details.append("Не указан пароль, ssh_key_file или ssh_key_data")
            
            app.logger.error(f"Ошибка валидации SSH данных: {', '.join(error_details)}")
            return jsonify({
                'success': False,
                'error': 'Missing SSH credentials. Please provide IP, user and password or SSH key',
                'details': error_details
            }), 400
        
        try:
            from omnissiah_utils.nmc_ssh_utils import connect_ssh_with_key_or_password
            
            ssh, error_msg = connect_ssh_with_key_or_password(
                hostname=ip,
                username=user,
                password=password,
                key_file=ssh_key_file,
                key_data=ssh_key_data,
                timeout=30
            )
            
            if ssh is None:
                return jsonify({'success': False, 'error': error_msg or 'SSH connection failed'}), 500
            
            try:
                remote_agent_dir = f"/home/{user}/agents"
                conf_path = f"{remote_agent_dir}/setup/{node.name}.conf"
                
                # КРИТИЧНО: Проверяем существование конфигурационного файла
                check_conf_cmd = f"test -f {conf_path} && echo 'exists' || echo 'not_exists'"
                stdin_check, stdout_check, stderr_check = ssh.exec_command(check_conf_cmd, timeout=5)
                conf_exists = stdout_check.read().decode().strip()
                
                if conf_exists != 'exists':
                    error_msg = f"Конфигурационный файл не найден: {conf_path}"
                    app.logger.error(f"❌ {error_msg}")
                    ssh.close()
                    return jsonify({'success': False, 'error': error_msg}), 500
                
                app.logger.info(f"✅ Конфигурационный файл найден: {conf_path}")
                
                # КРИТИЧНО: wg-quick принимает путь к файлу конфигурации
                # Команда для включения WireGuard интерфейса
                if sudo_password:
                    enable_cmd = f"echo '{sudo_password}' | sudo -S wg-quick up {conf_path}"
                else:
                    enable_cmd = f"sudo wg-quick up {conf_path}"
                
                stdin, stdout, stderr = ssh.exec_command(enable_cmd, timeout=30)
                stdout_output = stdout.read().decode().strip()
                stderr_output = stderr.read().decode().strip()
                exit_status = stdout.channel.recv_exit_status()
                
                if exit_status != 0:
                    error_msg = stderr_output if stderr_output else stdout_output
                    # Проверяем если интерфейс уже существует
                    if 'already exists' in error_msg.lower():
                        # Интерфейс уже существует, пробуем перезапустить
                        if sudo_password:
                            restart_cmd = f"echo '{sudo_password}' | sudo -S wg-quick down {conf_path} && echo '{sudo_password}' | sudo -S wg-quick up {conf_path}"
                        else:
                            restart_cmd = f"sudo wg-quick down {conf_path} && sudo wg-quick up {conf_path}"
                        
                        stdin2, stdout2, stderr2 = ssh.exec_command(restart_cmd, timeout=30)
                        stdout2.read()
                        stderr2.read()
                        exit_status2 = stdout2.channel.recv_exit_status()
                        
                        if exit_status2 == 0:
                            # Обновляем статус в БД при успешном включении
                            node.status = 'active'
                            db.session.commit()
                            
                            # Если VPN включен на Magos, синхронизируем пиры на Omnissiah
                            if node.role == 'Magos':
                                try:
                                    omnissiah = General.query.filter_by(role='Omnissiah').first()
                                    if omnissiah and omnissiah.status == 'active':
                                        app.logger.info(f"Синхронизируем пиры на Omnissiah после включения VPN на {node.name} (restart)")
                                        sync_result = sync_wireguard_peers(omnissiah)
                                        if sync_result:
                                            app.logger.info(f"Пиры успешно синхронизированы на Omnissiah для {node.name}")
                                        else:
                                            app.logger.warning(f"Не удалось синхронизировать пиры на Omnissiah для {node.name}")
                                        
                                        # КРИТИЧНО: Проверяем что peer добавлен на Omnissiah
                                        try:
                                            import subprocess
                                            result = subprocess.run(
                                                ["sudo", "-n", "wg", "show", omnissiah.name, "peers"],
                                                capture_output=True,
                                                text=True,
                                                timeout=5
                                            )
                                            if result.returncode == 0:
                                                peers_output = result.stdout.strip()
                                                if node.public_key in peers_output:
                                                    app.logger.info(f"Peer {node.name} ({node.public_key[:16]}...) найден на Omnissiah")
                                                else:
                                                    app.logger.error(f"Peer {node.name} ({node.public_key[:16]}...) НЕ найден на Omnissiah!")
                                                    app.logger.error(f"Текущие peers: {peers_output}")
                                        except Exception as check_error:
                                            app.logger.warning(f"Ошибка проверки peer на Omnissiah: {str(check_error)}")
                                except Exception as sync_error:
                                    app.logger.error(f"Не удалось синхронизировать пиры после включения VPN на {node.name}: {str(sync_error)}")
                                    import traceback
                                    app.logger.error(traceback.format_exc())
                            
                            ssh.close()
                            return jsonify({'success': True, 'message': 'VPN enabled successfully (interface was restarted)'}), 200
                    
                    ssh.close()
                    return jsonify({'success': False, 'error': f'Failed to enable VPN: {error_msg}'}), 500
                
                # Обновляем статус в БД при успешном включении
                node.status = 'active'
                db.session.commit()
                
                # Если VPN включен на Magos, синхронизируем пиры на Omnissiah
                if node.role == 'Magos':
                    try:
                        omnissiah = General.query.filter_by(role='Omnissiah').first()
                        if omnissiah and omnissiah.status == 'active':
                            app.logger.info(f"Синхронизируем пиры на Omnissiah после включения VPN на {node.name}")
                            sync_result = sync_wireguard_peers(omnissiah)
                            if sync_result:
                                app.logger.info(f"Пиры успешно синхронизированы на Omnissiah для {node.name}")
                            else:
                                app.logger.warning(f"Не удалось синхронизировать пиры на Omnissiah для {node.name}")
                            
                            # КРИТИЧНО: Проверяем что peer добавлен на Omnissiah
                            # Проверяем через wg show
                            try:
                                import subprocess
                                result = subprocess.run(
                                    ["sudo", "-n", "wg", "show", omnissiah.name, "peers"],
                                    capture_output=True,
                                    text=True,
                                    timeout=5
                                )
                                if result.returncode == 0:
                                    peers_output = result.stdout.strip()
                                    if node.public_key in peers_output:
                                        app.logger.info(f"Peer {node.name} ({node.public_key[:16]}...) найден на Omnissiah")
                                    else:
                                        app.logger.error(f"Peer {node.name} ({node.public_key[:16]}...) НЕ найден на Omnissiah!")
                                        app.logger.error(f"Текущие peers: {peers_output}")
                            except Exception as check_error:
                                app.logger.warning(f"Ошибка проверки peer на Omnissiah: {str(check_error)}")
                    except Exception as sync_error:
                        app.logger.error(f"Не удалось синхронизировать пиры после включения VPN на {node.name}: {str(sync_error)}")
                        import traceback
                        app.logger.error(traceback.format_exc())
                
                ssh.close()
                return jsonify({'success': True, 'message': 'VPN enabled successfully'}), 200
                
            except Exception as e:
                ssh.close()
                app.logger.error(f"SSH enable VPN error: {str(e)}")
                import traceback
                app.logger.error(traceback.format_exc())
                return jsonify({'success': False, 'error': str(e)}), 500
                
        except ImportError:
            return jsonify({'success': False, 'error': 'paramiko library not installed'}), 500
        except Exception as e:
            app.logger.error(f"SSH connection error: {str(e)}")
            return jsonify({'success': False, 'error': f'SSH connection failed: {str(e)}'}), 500
            
    except Exception as e:
        app.logger.error(f"Enable VPN error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/delete_node/<int:node_id>', methods=['POST'])
@login_required
@admin_required
def api_delete_node(node_id):
    """
    Расширенное удаление узла Magos/Cognitor через SSH
    
    Операции (в зависимости от опций):
    1. Остановить и удалить сервис systemd
    2. Отключить VPN и удалить конфигурацию WireGuard
    3. Удалить ПО и файлы приложения
    4. Удалить узел из БД
    """
    try:
        node = db.session.get(General, node_id)
        if not node:
            return jsonify({'success': False, 'error': 'Узел не найден'}), 404
        
        # Проверяем что это Magos или Cognitor
        if node.role not in ['Magos', 'Cognitor']:
            return jsonify({'success': False, 'error': 'Эта функция доступна только для Magos и Cognitor узлов'}), 400
        
        # Получаем параметры из запроса
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Не указаны параметры удаления'}), 400
        
        ssh_ip = data.get('ssh_ip')
        ssh_user = data.get('ssh_user', 'root')
        ssh_password = data.get('ssh_password')
        sudo_password = data.get('sudo_password', '')
        delete_vpn_config = data.get('delete_vpn_config', False)
        delete_software = data.get('delete_software', False)
        
        # Валидация SSH параметров только если требуется удаление на удаленном узле
        if delete_vpn_config or delete_software:
            if not ssh_ip or not ssh_password:
                return jsonify({'success': False, 'error': 'Не указаны SSH IP или пароль'}), 400
        
        # Определяем режим удаления
        # Если НЕ выбраны опции удаления на удаленном узле, просто удаляем из БД и WireGuard
        local_deletion_only = not delete_vpn_config and not delete_software
        
        # Подключаемся по SSH только если требуется удаление на удаленном узле
        ssh_client = None
        from omnissiah_utils.nmc_ssh_utils import connect_ssh_with_key_or_password
        
        if not local_deletion_only:
        
            app.logger.info(f"Попытка SSH подключения к {ssh_ip} (пользователь: {ssh_user}) для удаления узла {node.name}")
            
            # Используем достаточно большой timeout для операций удаления
            # Увеличено до 120 секунд для медленных соединений или сложных сетевых конфигураций
            ssh_client, error = connect_ssh_with_key_or_password(
                hostname=ssh_ip,
                username=ssh_user,
                password=ssh_password,
                timeout=120
            )
            
            if not ssh_client:
                # Улучшаем сообщение об ошибке
                error_msg = error if error else 'Неизвестная ошибка SSH подключения'
                app.logger.error(f"SSH подключение к {ssh_ip} не удалось: {error_msg}")
                
                if 'timed out' in error_msg.lower() or 'timeout' in error_msg.lower():
                    return jsonify({
                        'success': False, 
                        'error': f'Таймаут подключения к {ssh_ip}.\n\n'
                                 f'Возможные причины:\n'
                                 f'1. Медленное сетевое соединение\n'
                                 f'2. Firewall блокирует подключение\n'
                                 f'3. SSH сервис не отвечает\n\n'
                                 f'Попробуйте:\n'
                                 f'- Проверить подключение: ssh {ssh_user}@{ssh_ip}\n'
                                 f'- Увеличить timeout в настройках\n'
                                 f'- Проверить правила firewall на узле'
                    }), 500
                return jsonify({'success': False, 'error': f'Ошибка SSH подключения: {error_msg}'}), 500
            
            app.logger.info(f"SSH подключение к {ssh_ip} установлено успешно")
        
        operations_log = []
        errors_log = []
        
        try:
            # Определяем имя интерфейса WireGuard (обычно совпадает с именем узла)
            wg_interface = node.name
            wg_config_path = f"/etc/wireguard/{wg_interface}.conf"
            
            # Операция 1: Остановить и удалить сервис systemd (если выбрано)
            if delete_software:
                # Пробуем разные варианты имен сервисов
                possible_service_names = [
                    f"{node.role.lower()}-{node.name.lower()}",
                    f"nmc-agent-{node.name.lower()}",
                    f"nmc-{node.name.lower()}",
                    "nmc-agent",
                    f"nmcwg-agent-{node.name.lower()}",
                    "nmcwg-agent"
                ]
                
                service_found = False
                for svc_name in possible_service_names:
                    try:
                        # Проверяем существует ли сервис
                        check_cmd = f"systemctl list-unit-files {svc_name}.service 2>/dev/null | grep -q '{svc_name}.service' && echo 'exists' || echo 'not_exists'"
                        stdin, stdout, stderr = ssh_client.exec_command(check_cmd, timeout=5)
                        result = stdout.read().decode().strip()
                        
                        # Также проверяем через статус
                        status_cmd = f"systemctl status {svc_name} >/dev/null 2>&1; echo $?"
                        stdin2, stdout2, stderr2 = ssh_client.exec_command(status_cmd, timeout=5)
                        status_result = stdout2.read().decode().strip()
                        
                        # Если сервис найден
                        if result == 'exists' or status_result != '4':
                            service_name = svc_name
                            service_found = True
                            
                            # Останавливаем сервис
                            stop_cmd = f"systemctl stop {service_name}"
                            if sudo_password:
                                stop_cmd = f"echo '{sudo_password}' | sudo -S {stop_cmd}"
                            else:
                                stop_cmd = f"sudo -n {stop_cmd}"
                            
                            stdin, stdout, stderr = ssh_client.exec_command(stop_cmd, timeout=10)
                            exit_status = stdout.channel.recv_exit_status()
                            if exit_status == 0:
                                operations_log.append(f"✅ Сервис {service_name} остановлен")
                            else:
                                stderr_output = stderr.read().decode()
                                errors_log.append(f"⚠️ Не удалось остановить сервис {service_name}: {stderr_output}")
                            
                            # Отключаем автозапуск
                            disable_cmd = f"systemctl disable {service_name}"
                            if sudo_password:
                                disable_cmd = f"echo '{sudo_password}' | sudo -S {disable_cmd}"
                            else:
                                disable_cmd = f"sudo -n {disable_cmd}"
                            
                            stdin, stdout, stderr = ssh_client.exec_command(disable_cmd, timeout=10)
                            exit_status = stdout.channel.recv_exit_status()
                            if exit_status == 0:
                                operations_log.append(f"✅ Сервис {service_name} отключен от автозапуска")
                            else:
                                stderr_output = stderr.read().decode()
                                errors_log.append(f"⚠️ Не удалось отключить сервис {service_name}: {stderr_output}")
                            
                            # Удаляем файл сервиса
                            service_file = f"/etc/systemd/system/{service_name}.service"
                            remove_service_cmd = f"rm -f {service_file}"
                            if sudo_password:
                                remove_service_cmd = f"echo '{sudo_password}' | sudo -S {remove_service_cmd}"
                            else:
                                remove_service_cmd = f"sudo -n {remove_service_cmd}"
                            
                            stdin, stdout, stderr = ssh_client.exec_command(remove_service_cmd, timeout=10)
                            exit_status = stdout.channel.recv_exit_status()
                            if exit_status == 0:
                                operations_log.append(f"✅ Файл сервиса {service_file} удален")
                            else:
                                stderr_output = stderr.read().decode()
                                errors_log.append(f"⚠️ Не удалось удалить файл сервиса: {stderr_output}")
                            
                            # Перезагружаем systemd
                            reload_cmd = "systemctl daemon-reload"
                            if sudo_password:
                                reload_cmd = f"echo '{sudo_password}' | sudo -S {reload_cmd}"
                            else:
                                reload_cmd = f"sudo -n {reload_cmd}"
                            
                            stdin, stdout, stderr = ssh_client.exec_command(reload_cmd, timeout=10)
                            operations_log.append(f"✅ Systemd перезагружен")
                            break
                    except Exception as e:
                        continue
                
                if not service_found:
                    operations_log.append(f"ℹ️  Сервис не найден (возможно уже удален)")
                
                # Удаляем директории с ПО
                # Ищем возможные пути установки
                possible_paths = [
                    f"/opt/nmcwg-{node.name.lower()}",
                    "/opt/nmcwg",
                    f"/opt/agents",
                    f"/home/{ssh_user}/agents",
                    f"/opt/nmc-agent-{node.name.lower()}",
                    "/opt/nmc-agent"
                ]
                
                for app_path in possible_paths:
                    try:
                        # Проверяем существование директории
                        check_cmd = f"test -d {app_path} && echo 'exists' || echo 'not_exists'"
                        stdin, stdout, stderr = ssh_client.exec_command(check_cmd, timeout=5)
                        result = stdout.read().decode().strip()
                        
                        if result == 'exists':
                            # Удаляем директорию
                            rm_cmd = f"rm -rf {app_path}"
                            if sudo_password:
                                rm_cmd = f"echo '{sudo_password}' | sudo -S {rm_cmd}"
                            else:
                                rm_cmd = f"sudo -n {rm_cmd}"
                            
                            stdin, stdout, stderr = ssh_client.exec_command(rm_cmd, timeout=30)
                            exit_status = stdout.channel.recv_exit_status()
                            if exit_status == 0:
                                operations_log.append(f"✅ Директория {app_path} удалена")
                            else:
                                stderr_output = stderr.read().decode()
                                errors_log.append(f"⚠️ Не удалось удалить {app_path}: {stderr_output}")
                    except Exception as e:
                        continue
            
            # Операция 2: Отключить VPN и удалить конфигурацию (если выбрано)
            if delete_vpn_config:
                try:
                    # Пробуем разные пути к конфигурации
                    possible_conf_paths = [
                        f"/etc/wireguard/{wg_interface}.conf",
                        f"/home/{ssh_user}/agents/setup/{wg_interface}.conf",
                        f"/opt/agents/setup/{wg_interface}.conf"
                    ]
                    
                    for conf_path in possible_conf_paths:
                        # Проверяем существование конфигурационного файла
                        check_cmd = f"test -f {conf_path} && echo 'exists' || echo 'not_exists'"
                        stdin, stdout, stderr = ssh_client.exec_command(check_cmd, timeout=5)
                        result = stdout.read().decode().strip()
                        
                        if result == 'exists':
                            wg_config_path = conf_path
                            break
                    else:
                        wg_config_path = f"/etc/wireguard/{wg_interface}.conf"
                    
                    # Останавливаем WireGuard интерфейс
                    wg_down_cmd = f"wg-quick down {wg_interface}"
                    if sudo_password:
                        wg_down_cmd = f"echo '{sudo_password}' | sudo -S {wg_down_cmd}"
                    else:
                        wg_down_cmd = f"sudo -n {wg_down_cmd}"
                    
                    stdin, stdout, stderr = ssh_client.exec_command(wg_down_cmd, timeout=10)
                    exit_status = stdout.channel.recv_exit_status()
                    if exit_status == 0:
                        operations_log.append(f"✅ WireGuard интерфейс {wg_interface} остановлен")
                    else:
                        stderr_output = stderr.read().decode()
                        operations_log.append(f"ℹ️  Интерфейс уже остановлен или не существует")
                    
                    # Удаляем конфигурационный файл
                    rm_config_cmd = f"rm -f {wg_config_path}"
                    if sudo_password:
                        rm_config_cmd = f"echo '{sudo_password}' | sudo -S {rm_config_cmd}"
                    else:
                        rm_config_cmd = f"sudo -n {rm_config_cmd}"
                    
                    stdin, stdout, stderr = ssh_client.exec_command(rm_config_cmd, timeout=10)
                    exit_status = stdout.channel.recv_exit_status()
                    if exit_status == 0:
                        operations_log.append(f"✅ Конфигурация WireGuard {wg_config_path} удалена")
                    else:
                        stderr_output = stderr.read().decode()
                        errors_log.append(f"⚠️ Не удалось удалить конфигурацию: {stderr_output}")
                
                except Exception as e:
                    errors_log.append(f"⚠️ Ошибка при удалении VPN конфигурации: {str(e)}")
            
            # Закрываем SSH соединение если открыто
            if ssh_client:
                ssh_client.close()
            
            # Операция 3: Удаляем узел из WireGuard конфигурации
            try:
                # Для Magos удаляем peer из конфигурации Omnissiah
                if node.role == 'Magos':
                    omnissiah = General.query.filter_by(role='Omnissiah').first()
                    if omnissiah and node.public_key:
                        try:
                            # Удаляем peer из WireGuard
                            subprocess.run([
                                "sudo", "-n", "wg", "set", omnissiah.name,
                                "peer", node.public_key, "remove"
                            ], check=True, timeout=10, capture_output=True, text=True)
                            
                            # Сохраняем конфигурацию через restore_wg_config_from_db
                            restored_config = restore_wg_config_from_db(omnissiah)
                            if restored_config:
                                config_path = f"/etc/wireguard/{omnissiah.name}.conf"
                                temp_config_path = None
                                try:
                                    import tempfile
                                    temp_config = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf')
                                    temp_config.write(restored_config)
                                    temp_config.close()
                                    temp_config_path = temp_config.name
                                    
                                    subprocess.run(['sudo', '-n', 'cp', temp_config_path, config_path], 
                                                 check=True, timeout=10)
                                    subprocess.run(['sudo', '-n', 'chmod', '600', config_path], 
                                                 check=True, timeout=5)
                                    
                                    operations_log.append(f"✅ Узел {node.name} удален из WireGuard конфигурации Omnissiah")
                                    app.logger.info(f"✅ Peer {node.name} удален из конфигурации Omnissiah")
                                except Exception as restore_err:
                                    errors_log.append(f"⚠️ Не удалось сохранить конфигурацию Omnissiah: {str(restore_err)}")
                                finally:
                                    if temp_config_path and os.path.exists(temp_config_path):
                                        try:
                                            os.unlink(temp_config_path)
                                        except Exception:
                                            pass
                            else:
                                errors_log.append(f"⚠️ Не удалось восстановить конфигурацию Omnissiah")
                        except subprocess.CalledProcessError as e:
                            errors_log.append(f"⚠️ Не удалось удалить peer из WireGuard: {e.stderr if e.stderr else str(e)}")
                        except Exception as e:
                            errors_log.append(f"⚠️ Ошибка при удалении из WireGuard: {str(e)}")
                
                # Для Cognitor удаляем peer из конфигурации родителя (Magos или Omnissiah)
                elif node.role == 'Cognitor' and node.parent_id:
                    parent = db.session.get(General, node.parent_id)
                    if parent and node.public_key:
                        try:
                            # Удаляем peer из конфигурации родителя
                            subprocess.run([
                                "sudo", "-n", "wg", "set", parent.name,
                                "peer", node.public_key, "remove"
                            ], check=True, timeout=10, capture_output=True, text=True)
                            
                            # Сохраняем конфигурацию родителя
                            restored_config = restore_wg_config_from_db(parent)
                            if restored_config:
                                config_path = f"/etc/wireguard/{parent.name}.conf" if parent.role == 'Omnissiah' else f"/home/{parent.ssh_user}/agents/setup/{parent.name}.conf"
                                temp_config_path = None
                                try:
                                    import tempfile
                                    temp_config = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf')
                                    temp_config.write(restored_config)
                                    temp_config.close()
                                    temp_config_path = temp_config.name
                                    
                                    if parent.role == 'Omnissiah':
                                        subprocess.run(['sudo', '-n', 'cp', temp_config_path, config_path], 
                                                     check=True, timeout=10)
                                        subprocess.run(['sudo', '-n', 'chmod', '600', config_path], 
                                                     check=True, timeout=5)
                                    else:
                                        # Для Magos конфигурация сохраняется через SSH (если требуется)
                                        # Пока просто логируем
                                        app.logger.info(f"⚠️ Конфигурация Magos {parent.name} должна быть обновлена вручную")
                                    
                                    operations_log.append(f"✅ Узел {node.name} удален из WireGuard конфигурации {parent.name}")
                                    app.logger.info(f"✅ Peer {node.name} удален из конфигурации {parent.name}")
                                except Exception as restore_err:
                                    errors_log.append(f"⚠️ Не удалось сохранить конфигурацию {parent.name}: {str(restore_err)}")
                                finally:
                                    if temp_config_path and os.path.exists(temp_config_path):
                                        try:
                                            os.unlink(temp_config_path)
                                        except Exception:
                                            pass
                            else:
                                errors_log.append(f"⚠️ Не удалось восстановить конфигурацию {parent.name}")
                        except subprocess.CalledProcessError as e:
                            errors_log.append(f"⚠️ Не удалось удалить peer из WireGuard: {e.stderr if e.stderr else str(e)}")
                        except Exception as e:
                            errors_log.append(f"⚠️ Ошибка при удалении из WireGuard: {str(e)}")
            except Exception as e:
                errors_log.append(f"⚠️ Ошибка при работе с WireGuard: {str(e)}")
                app.logger.error(f"Ошибка удаления peer из WireGuard: {str(e)}", exc_info=True)
            
            # Операция 4: Помечаем правила политики доступа, связанные с удаляемым узлом
            try:
                # Находим все правила, где узел является источником или назначением
                affected_rules = AccessPolicyRule.query.filter(
                    ((AccessPolicyRule.source_type == 'node') & (AccessPolicyRule.source_id == node.id)) |
                    ((AccessPolicyRule.destination_type == 'node') & (AccessPolicyRule.destination_id == node.id))
                ).all()
                
                for rule in affected_rules:
                    # Помечаем правило как недействительное (удаляем из applied_on_nodes)
                    if rule.applied_on_nodes:
                        try:
                            applied_nodes = json.loads(rule.applied_on_nodes)
                            if node.id in applied_nodes:
                                applied_nodes.remove(node.id)
                                rule.applied_on_nodes = json.dumps(applied_nodes) if applied_nodes else None
                        except (json.JSONDecodeError, TypeError):
                            pass
                    
                    # Обновляем статус правила - если не было применено, помечаем как удаленное
                    if rule.status == 'applied':
                        # Проверяем, остались ли другие узлы для применения
                        if rule.source_type == 'node' and rule.source_id == node.id:
                            # Источник удален - правило недействительно
                            rule.status = 'invalid'
                            rule.description = f"{rule.description or ''} [Источник удален: {node.name}]"
                        elif rule.destination_type == 'node' and rule.destination_id == node.id:
                            # Назначение удалено - правило недействительно
                            rule.status = 'invalid'
                            rule.description = f"{rule.description or ''} [Назначение удалено: {node.name}]"
                
                if affected_rules:
                    operations_log.append(f"✅ Помечено правил политики доступа: {len(affected_rules)}")
            except Exception as e:
                errors_log.append(f"⚠️ Ошибка при обновлении правил политики доступа: {str(e)}")
            
            # Операция 5: Удаляем узел из БД
            # Сначала удаляем все связанные защищенные объекты
            ProtectedObject.query.filter_by(node_id=node.id).delete()
            
            # Удаляем связи между узлами (NodeConnection)
            NodeConnection.query.filter(
                (NodeConnection.node1_id == node.id) | (NodeConnection.node2_id == node.id)
            ).delete()
            
            # Удаляем дочерние узлы (если есть)
            children = General.query.filter_by(parent_id=node.id).all()
            for child in children:
                # Также удаляем дочерние узлы из WireGuard
                if child.public_key and omnissiah:
                    try:
                        subprocess.run([
                            "sudo", "-n", "wg", "set", omnissiah.name,
                            "peer", child.public_key, "remove"
                        ], check=True, timeout=10, capture_output=True)
                        operations_log.append(f"✅ Дочерний узел {child.name} удален из WireGuard")
                    except Exception as e:
                        errors_log.append(f"⚠️ Не удалось удалить дочерний узел {child.name} из WireGuard: {str(e)}")
                db.session.delete(child)
            
            # Удаляем сам узел
            node_name = node.name
            db.session.delete(node)
            db.session.commit()
            
            operations_log.append(f"✅ Узел {node_name} удален из базы данных")
            
            # Формируем сообщение
            message = f"Узел {node_name} успешно удален.\n\nВыполненные операции:\n" + "\n".join(operations_log)
            if errors_log:
                message += "\n\nПредупреждения:\n" + "\n".join(errors_log)
            
            return jsonify({
                'success': True,
                'message': message,
                'operations': operations_log,
                'warnings': errors_log
            }), 200
        
        except Exception as ssh_error:
            if ssh_client:
                ssh_client.close()
            return jsonify({
                'success': False,
                'error': f'Ошибка выполнения SSH команд: {str(ssh_error)}'
            }), 500
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Ошибка удаления узла {node_id}: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': f'Ошибка удаления узла: {str(e)}'
        }), 500


@app.route('/api/delete_omnissiah/<int:node_id>', methods=['POST'])
@login_required
@admin_required
def api_delete_omnissiah(node_id):
    """
    Полное удаление главного узла (Omnissiah) со всеми данными
    
    Удаляет:
    1. Все дочерние узлы (Magos, Cognitor) и их данные
    2. Все правила iptables (локально)
    3. WireGuard конфигурацию и интерфейс
    4. mTLS сертификаты
    5. Nginx конфигурацию (если настроена)
    6. Все данные из БД (правила, защищенные объекты, связи)
    7. Сбрасывает политики iptables на ACCEPT
    """
    try:
        node = db.session.get(General, node_id)
        if not node:
            return jsonify({'success': False, 'error': 'Узел не найден'}), 404
        
        # Проверяем что это Omnissiah
        if node.role != 'Omnissiah':
            return jsonify({'success': False, 'error': 'Эта функция доступна только для Omnissiah'}), 400
        
        # Получаем подтверждение из запроса
        data = request.get_json() or {}
        confirm = data.get('confirm', False)
        
        if not confirm:
            return jsonify({'success': False, 'error': 'Требуется подтверждение удаления'}), 400
        
        operations_log = []
        errors_log = []
        
        node_name = node.name
        
        # 1. Удаляем все правила iptables для этого узла
        try:
            # Сначала сбрасываем политики на ACCEPT
            subprocess.run(['sudo', '-n', 'iptables', '-P', 'INPUT', 'ACCEPT'], check=False, timeout=5)
            subprocess.run(['sudo', '-n', 'iptables', '-P', 'OUTPUT', 'ACCEPT'], check=False, timeout=5)
            subprocess.run(['sudo', '-n', 'iptables', '-P', 'FORWARD', 'ACCEPT'], check=False, timeout=5)
            
            # Очищаем все правила из цепочек
            subprocess.run(['sudo', '-n', 'iptables', '-F'], check=False, timeout=5)
            subprocess.run(['sudo', '-n', 'iptables', '-X'], check=False, timeout=5)
            
            operations_log.append("✅ Правила iptables очищены и политики сброшены на ACCEPT")
        except Exception as e:
            errors_log.append(f"⚠️ Ошибка очистки iptables: {str(e)}")
        
        # 2. Останавливаем и удаляем WireGuard интерфейс
        if node_name:
            try:
                wg_interface = node_name
                wg_config_path = Path(f"/etc/wireguard/{wg_interface}.conf")
                
                # Останавливаем интерфейс
                subprocess.run(['sudo', '-n', 'wg-quick', 'down', wg_interface], 
                             check=False, timeout=10, capture_output=True)
                operations_log.append(f"✅ WireGuard интерфейс {wg_interface} остановлен")
                
                # Удаляем конфигурацию
                if wg_config_path.exists():
                    subprocess.run(['sudo', '-n', 'rm', '-f', str(wg_config_path)], 
                                 check=True, timeout=5)
                    operations_log.append(f"✅ Конфигурация WireGuard {wg_config_path} удалена")
            except Exception as e:
                errors_log.append(f"⚠️ Ошибка удаления WireGuard: {str(e)}")
        
        # 3. Удаляем mTLS сертификаты
        try:
            app_dir = Path(__file__).parent.parent
            mtls_dir = app_dir / "mtls_certs"
            
            if mtls_dir.exists():
                # Удаляем все сертификаты
                import shutil
                shutil.rmtree(mtls_dir)
                operations_log.append(f"✅ Директория mTLS сертификатов {mtls_dir} удалена")
            else:
                operations_log.append(f"ℹ️  Директория mTLS сертификатов не найдена")
        except Exception as e:
            errors_log.append(f"⚠️ Ошибка удаления mTLS сертификатов: {str(e)}")
        
        # 4. Удаляем Nginx конфигурацию
        # КРИТИЧНО: Удаляем файлы конфигурации nginx независимо от флага nginx_enabled,
        # так как файлы могут существовать даже если флаг не установлен
        try:
            # КРИТИЧНО: Используем фиксированное имя конфигурации "omnissiah-network",
            # которое используется при создании конфигурации (см. setup_wizard, строка 3570)
            nginx_config_name = "omnissiah-network"
            nginx_conf_path = Path(f"/etc/nginx/sites-available/{nginx_config_name}")
            nginx_conf_enabled = Path(f"/etc/nginx/sites-enabled/{nginx_config_name}")
            
            conf_removed = False
            
            # Удаляем символическую ссылку в sites-enabled
            if nginx_conf_enabled.exists():
                subprocess.run(['sudo', '-n', 'rm', '-f', str(nginx_conf_enabled)], check=False, timeout=5)
                operations_log.append("✅ Nginx конфигурация (enabled) удалена")
                conf_removed = True
            
            # Удаляем файл конфигурации в sites-available
            if nginx_conf_path.exists():
                subprocess.run(['sudo', '-n', 'rm', '-f', str(nginx_conf_path)], check=False, timeout=5)
                operations_log.append("✅ Nginx конфигурация (available) удалена")
                conf_removed = True
            
            # Если файлы конфигурации были удалены, перезагружаем nginx
            if conf_removed:
                # Проверяем, установлен ли nginx
                nginx_check = subprocess.run(['systemctl', 'list-unit-files', 'nginx.service'], 
                                            capture_output=True, timeout=5, check=False)
                nginx_installed = nginx_check.returncode == 0
                
                if not nginx_installed:
                    operations_log.append("ℹ️  Nginx не установлен, конфигурация удалена")
                else:
                    # Проверяем статус nginx перед перезагрузкой
                    nginx_status = subprocess.run(['systemctl', 'is-active', 'nginx'], 
                                                  capture_output=True, timeout=5, check=False)
                    if nginx_status.returncode == 0:
                        # Nginx активен, пробуем проверить конфигурацию перед перезагрузкой
                        nginx_test = subprocess.run(['sudo', '-n', 'nginx', '-t'], 
                                                   stdout=subprocess.DEVNULL,
                                                   stderr=subprocess.DEVNULL,
                                                   timeout=5, 
                                                   check=False)
                        if nginx_test.returncode == 0:
                            # Конфигурация валидна, перезагружаем
                            reload_result = subprocess.run(['sudo', '-n', 'systemctl', 'reload', 'nginx'], 
                                                          capture_output=True, timeout=10, check=False)
                            if reload_result.returncode == 0:
                                operations_log.append("✅ Nginx перезагружен")
                            else:
                                # Если reload не удался, пробуем restart
                                restart_result = subprocess.run(['sudo', '-n', 'systemctl', 'restart', 'nginx'], 
                                                               capture_output=True, timeout=10, check=False)
                                if restart_result.returncode == 0:
                                    operations_log.append("✅ Nginx перезапущен")
                                else:
                                    error_msg = restart_result.stderr.decode() if restart_result.stderr else 'Неизвестная ошибка'
                                    errors_log.append(f"⚠️ Не удалось перезапустить nginx: {error_msg}")
                                    operations_log.append("ℹ️  Конфигурация nginx удалена, но сервис требует ручного перезапуска")
                        else:
                            # Конфигурация невалидна, останавливаем nginx
                            operations_log.append("⚠️ Конфигурация nginx невалидна после удаления, останавливаем сервис")
                            subprocess.run(['sudo', '-n', 'systemctl', 'stop', 'nginx'], 
                                          capture_output=True, timeout=10, check=False)
                            operations_log.append("ℹ️  Nginx остановлен (требуется ручная настройка)")
                    else:
                        operations_log.append("ℹ️  Nginx не активен, конфигурация удалена")
            else:
                operations_log.append("ℹ️  Файлы конфигурации nginx не найдены")
        except Exception as e:
            errors_log.append(f"⚠️ Ошибка удаления Nginx конфигурации: {str(e)}")
            try:
                current_app.logger.warning(f"Ошибка при удалении Nginx конфигурации: {e}", exc_info=True)
            except (AttributeError, RuntimeError) as log_err:
                # Если логирование не работает (например, нет app context), просто игнорируем
                pass
        
        # 5. Удаляем все данные из БД
        
        # 5.1. Собираем список всех узлов для удаления (Omnissiah + все дочерние)
        all_nodes = General.query.all()
        child_nodes = [n for n in all_nodes if n.role != 'Omnissiah']
        nodes_to_delete_ids = [node.id]
        for child_node in child_nodes:
            nodes_to_delete_ids.append(child_node.id)
        
        # 5.2. Удаляем все записи TrafficLog для удаляемых узлов ПЕРЕД удалением узлов
        # КРИТИЧНО: node_id имеет ограничение NOT NULL, поэтому нужно удалить записи, а не обнулять
        # Это должно быть сделано ДО удаления узлов, чтобы избежать ошибки IntegrityError
        try:
            if nodes_to_delete_ids:
                traffic_logs_count = TrafficLog.query.filter(TrafficLog.node_id.in_(nodes_to_delete_ids)).count()
                if traffic_logs_count > 0:
                    TrafficLog.query.filter(TrafficLog.node_id.in_(nodes_to_delete_ids)).delete(synchronize_session=False)
                    db.session.flush()  # Применяем удаление перед продолжением
                    operations_log.append(f"✅ Удалено записей TrafficLog: {traffic_logs_count}")
                else:
                    operations_log.append(f"ℹ️  Записей TrafficLog для удаления не найдено")
        except Exception as e:
            errors_log.append(f"⚠️ Ошибка удаления TrafficLog: {str(e)}")
            app.logger.error(f"Ошибка удаления TrafficLog: {e}", exc_info=True)
            # Не прерываем выполнение, но логируем ошибку
        
        # 5.3. Удаляем все дочерние узлы (Magos, Cognitor)
        for child_node in child_nodes:
            # Удаляем связанные данные для каждого дочернего узла
            ProtectedObject.query.filter_by(node_id=child_node.id).delete()
            AccessPolicyRule.query.filter(
                ((AccessPolicyRule.source_type == 'node') & (AccessPolicyRule.source_id == child_node.id)) |
                ((AccessPolicyRule.destination_type == 'node') & (AccessPolicyRule.destination_id == child_node.id))
            ).delete()
            db.session.delete(child_node)
        
        if child_nodes:
            operations_log.append(f"✅ Удалено дочерних узлов: {len(child_nodes)}")
        
        # 5.4. Удаляем все правила доступа (AccessPolicyRule)
        access_rules_count = AccessPolicyRule.query.count()
        AccessPolicyRule.query.delete()
        operations_log.append(f"✅ Удалено правил доступа: {access_rules_count}")
        
        # 5.5. Удаляем все защищенные объекты (ProtectedObject)
        protected_objects_count = ProtectedObject.query.count()
        ProtectedObject.query.delete()
        operations_log.append(f"✅ Удалено защищенных объектов: {protected_objects_count}")
        
        # 5.6. Удаляем все связи узлов (NodeConnection)
        try:
            node_connections_count = NodeConnection.query.count()
            NodeConnection.query.delete()
            operations_log.append(f"✅ Удалено связей узлов: {node_connections_count}")
        except Exception as e:
            # Если NodeConnection не найден, просто пропускаем (может быть не определен в этой версии)
            app.logger.warning(f"NodeConnection не найден, пропускаем удаление связей: {str(e)}")
        
        # 5.7. FirewallRule удалена (функционал firewall упразднен)
        
        # 5.8. Удаляем сам узел Omnissiah
        db.session.delete(node)
        db.session.commit()
        operations_log.append(f"✅ Узел {node_name} удален из базы данных")
        
        # Формируем сообщение об успешном удалении
        message = f"Главный узел {node_name} успешно удален. Выполненные операции:\n" + "\n".join(operations_log)
        if errors_log:
            message += "\n\nПредупреждения:\n" + "\n".join(errors_log)
        
        app.logger.info(f"Полное удаление Omnissiah {node_name} завершено")
        
        # КРИТИЧНО: После удаления главного узла нужно выйти из сессии и перенаправить на страницу входа
        # Выходим из системы перед возвратом ответа
        from flask_login import logout_user
        logout_user()  # Правильный выход из системы
        
        # Возвращаем JSON с редиректом на страницу входа
        return jsonify({
            'success': True,
            'message': f'Главный узел {node_name} успешно удален. Выполненные операции:\n' + '\n'.join(operations_log),
            'operations': operations_log,
            'warnings': errors_log,
            'redirect': '/login',  # Перенаправляем на страницу входа
            'flash_message': f'Главный узел {node_name} успешно удален. Выполнено операций: {len(operations_log)}'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Ошибка полного удаления Omnissiah {node_id}: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': f'Ошибка удаления: {str(e)}'
        }), 500


@app.route('/api/ssh/start_service', methods=['POST'])
@login_required
@admin_required
def api_ssh_start_service():
    """
    Запуск Magos сервиса на удаленном узле через SSH
    """
    try:
        data = request.get_json()
        node_id = data.get('node_id')
        ip = data.get('ip')
        user = data.get('user')
        password = data.get('password')
        
        if not all([node_id, ip, user, password]):
            return jsonify({'success': False, 'error': 'Missing required parameters'}), 400
        
        node = db.session.get(General, node_id)
        if not node or node.role not in ['Magos', 'Cognitor']:
            return jsonify({'success': False, 'error': 'Invalid node. SSH deployment only for Magos and Cognitor'}), 400
        
        try:
            import paramiko
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=user, password=password, timeout=30)
            
            remote_agent_dir = f"/home/{user}/agents"
            service_name = f"{node.role.lower()}-{node.name.lower()}.service"
            service_file_path = f"{remote_agent_dir}/setup/{service_name}"
            
            # Проверяем что service файл существует в setup директории
            sftp = ssh.open_sftp()
            try:
                sftp.stat(service_file_path)
                # Service файл найден, используем его
            except IOError:
                # Service файл не найден, создаем его на месте
                role_label = 'Magos' if node.role == 'Magos' else 'Cognitor'
                service_content = f"""[Unit]
Description={role_label} Agent for {node.name}
After=network.target

[Service]
Type=simple
User={user}
WorkingDirectory={remote_agent_dir}
ExecStart=/usr/bin/env python3 {remote_agent_dir}/run.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
Environment="PYTHONUNBUFFERED=1"

[Install]
WantedBy=multi-user.target
"""
                temp_service = tempfile.NamedTemporaryFile(mode='w', suffix='.service', delete=False)
                temp_service.write(service_content)
                temp_service.close()
                
                # Создаем setup директорию если нужно
                setup_dir = f"{remote_agent_dir}/setup"
                try:
                    sftp.stat(setup_dir)
                except IOError:
                    parts = setup_dir.split('/')
                    current_path = ''
                    for part in parts[1:]:
                        current_path += '/' + part
                        try:
                            sftp.stat(current_path)
                        except IOError:
                            sftp.mkdir(current_path)
                
                sftp.put(temp_service.name, service_file_path)
                os.unlink(temp_service.name)
            else:
                # Service файл уже существует, всё хорошо
                pass
            
            sftp.close()
            
            # Проверяем нужен ли sudo пароль
            sudo_password = data.get('sudo_password')
            
            # Копируем service файл из setup в systemd и активируем
            # Проверяем наличие requirements.txt и устанавливаем зависимости если нужно
            # КРИТИЧНО: Убеждаемся что cryptography установлен
            try:
                # Сначала проверяем наличие cryptography (не требует sudo)
                check_crypto_cmd = f"python3 -c 'import cryptography' 2>&1"
                stdin_crypto, stdout_crypto, stderr_crypto = ssh.exec_command(check_crypto_cmd, timeout=5)
                exit_status_crypto = stdout_crypto.channel.recv_exit_status()
                crypto_output = stdout_crypto.read().decode().strip()
                crypto_stderr = stderr_crypto.read().decode().strip()
                
                crypto_available = (exit_status_crypto == 0 and crypto_output == '' and 'No module named' not in crypto_stderr)
                
                if not crypto_available:
                    app.logger.info(f"cryptography не найден на {node.name}, устанавливаем...")
                    # Устанавливаем cryptography напрямую (может потребоваться sudo для pip)
                    install_crypto_cmd = f"cd {remote_agent_dir} && python3 -m pip install --user cryptography>=41.0.0 2>&1 || python3 -m pip install cryptography>=41.0.0 2>&1"
                    if sudo_password:
                        install_crypto_cmd = f"echo '{sudo_password}' | sudo -S bash -c '{install_crypto_cmd}'"
                    stdin_install, stdout_install, stderr_install = ssh.exec_command(install_crypto_cmd, timeout=120)
                    output = stdout_install.read().decode()
                    stderr_output = stderr_install.read().decode()
                    exit_status_install = stdout_install.channel.recv_exit_status()
                    
                    if exit_status_install == 0:
                        app.logger.info(f"cryptography успешно установлен для {node.name}")
                    else:
                        app.logger.warning(f"Возможны проблемы с установкой cryptography для {node.name}: {stderr_output[:200]}")
                
                requirements_check = f"test -f {remote_agent_dir}/requirements.txt"
                stdin_req, stdout_req, stderr_req = ssh.exec_command(requirements_check, timeout=5)
                stdout_req.read()
                stderr_req.read()
                exit_status_req = stdout_req.channel.recv_exit_status()
                
                if exit_status_req == 0:
                    # Устанавливаем зависимости
                    install_deps_cmd = f"cd {remote_agent_dir} && python3 -m pip install --user -r requirements.txt 2>&1 || python3 -m pip install -r requirements.txt 2>&1"
                    app.logger.info(f"Установка зависимостей для {node.name}...")
                    stdin_deps, stdout_deps, stderr_deps = ssh.exec_command(install_deps_cmd, timeout=120)
                    deps_output = stdout_deps.read().decode().strip()
                    deps_stderr = stderr_deps.read().decode().strip()
                    exit_status_deps = stdout_deps.channel.recv_exit_status()
                    
                    if exit_status_deps == 0:
                        app.logger.info(f"Зависимости установлены для {node.name}")
                    else:
                        app.logger.warning(f"Возможны проблемы с установкой зависимостей для {node.name}: {deps_stderr}")
            except Exception as deps_error:
                app.logger.warning(f"Не удалось установить зависимости: {deps_error}")
            
            commands = [
                (f"cp {service_file_path} /etc/systemd/system/", "Копирование service файла"),
                (f"systemctl daemon-reload", "Перезагрузка systemd"),
                (f"systemctl enable {service_name}", "Активация автозапуска"),
                (f"systemctl start {service_name}", "Запуск сервиса")
            ]
            
            for cmd, description in commands:
                try:
                    # Если нужен sudo пароль, используем echo с -S флагом
                    if sudo_password:
                        # Экранируем пароль для безопасности в команде
                        import shlex
                        escaped_password = shlex.quote(sudo_password)
                        escaped_cmd = shlex.quote(cmd)
                        full_cmd = f"echo {escaped_password} | sudo -S {escaped_cmd}"
                    else:
                        # Пробуем без пароля сначала
                        full_cmd = f"sudo -n {cmd}"
                    
                    stdin, stdout, stderr = ssh.exec_command(full_cmd, timeout=30)
                    
                    # Ждем завершения команды и читаем вывод СРАЗУ
                    # Это предотвращает закрытие канала
                    stdout_output = stdout.read().decode().strip()
                    stderr_output = stderr.read().decode().strip()
                    
                    # Получаем статус после чтения вывода
                    exit_status = stdout.channel.recv_exit_status()
                    
                    # Проверяем на запрос sudo пароля (только если не передавали пароль)
                    if exit_status != 0 and not sudo_password:
                        error_output = (stdout_output + stderr_output).lower()
                        if 'password' in error_output or '[sudo]' in error_output or 'sudo:' in error_output:
                            # Требуется sudo пароль
                            ssh.close()
                            return jsonify({
                                'success': False, 
                                'error': 'Требуется sudo пароль',
                                'requires_sudo_password': True
                            }), 200
                        
                        error_msg = f'{description} не удалось:\nКоманда: {full_cmd}\n'
                        if stderr_output:
                            error_msg += f'Ошибка: {stderr_output}\n'
                        if stdout_output:
                            error_msg += f'Вывод: {stdout_output}'
                        ssh.close()
                        return jsonify({'success': False, 'error': error_msg}), 500
                    elif exit_status != 0:
                        # Ошибка даже с паролем
                        error_msg = f'{description} не удалось:\nКоманда: {full_cmd}\n'
                        if stderr_output:
                            error_msg += f'Ошибка: {stderr_output}\n'
                        if stdout_output:
                            error_msg += f'Вывод: {stdout_output}'
                        ssh.close()
                        return jsonify({'success': False, 'error': error_msg}), 500
                        
                except Exception as cmd_error:
                    ssh.close()
                    return jsonify({
                        'success': False, 
                        'error': f'Ошибка при выполнении команды "{description}": {str(cmd_error)}\nКоманда: {full_cmd}'
                    }), 500
            
            # Проверяем что файлы агента существуют перед запуском
            # remote_agent_dir уже определен выше (строка 6934)
            try:
                check_files_cmd = f"test -f {remote_agent_dir}/run.py && test -x {remote_agent_dir}/run.py || chmod +x {remote_agent_dir}/run.py"
                if sudo_password:
                    import shlex
                    escaped_password = shlex.quote(sudo_password)
                    full_check_files_cmd = f"echo {escaped_password} | sudo -S {check_files_cmd}"
                else:
                    full_check_files_cmd = f"sudo -n {check_files_cmd}"
                
                stdin_files, stdout_files, stderr_files = ssh.exec_command(full_check_files_cmd, timeout=10)
                stdout_files.read()
                stderr_files.read()
                exit_status_files = stdout_files.channel.recv_exit_status()
                
                if exit_status_files != 0:
                    app.logger.warning(f"Файл run.py не найден или не исполняемый для {service_name}")
            except Exception as file_check_error:
                app.logger.warning(f"Ошибка проверки файлов: {file_check_error}")
            
            # Проверяем что Python3 доступен
            try:
                python_check_cmd = "which python3 || which python"
                stdin_py, stdout_py, stderr_py = ssh.exec_command(python_check_cmd, timeout=5)
                python_path = stdout_py.read().decode().strip()
                stderr_py.read()
                exit_status_py = stdout_py.channel.recv_exit_status()
                
                if exit_status_py != 0 or not python_path:
                    ssh.close()
                    return jsonify({
                        'success': False, 
                        'error': 'Python3 не найден на удаленном узле. Установите Python3.'
                    }), 500
                
                app.logger.info(f"Python найден: {python_path}")
            except Exception as py_check_error:
                app.logger.warning(f"Не удалось проверить Python: {py_check_error}")
            
            # Даем сервису время запуститься перед проверкой
            import time
            time.sleep(5)  # Увеличено с 3 до 5 секунд
            
            # Проверяем статус сервиса после запуска
            try:
                if sudo_password:
                    import shlex
                    escaped_password = shlex.quote(sudo_password)
                    check_cmd = f"echo {escaped_password} | sudo -S systemctl is-active {service_name}"
                else:
                    check_cmd = f"sudo -n systemctl is-active {service_name}"
                stdin, stdout, stderr = ssh.exec_command(check_cmd, timeout=10)
                service_status = stdout.read().decode().strip()
                stderr_output = stderr.read().decode().strip()
                exit_status = stdout.channel.recv_exit_status()
                
                app.logger.info(f"Статус сервиса {service_name}: {service_status} (exit code: {exit_status})")
                
                if exit_status != 0 or service_status != 'active':
                    # Получаем подробные логи для диагностики
                    try:
                        if sudo_password:
                            import shlex
                            escaped_password = shlex.quote(sudo_password)
                            journal_cmd = f"echo {escaped_password} | sudo -S journalctl -u {service_name} -n 50 --no-pager"
                            status_cmd = f"echo {escaped_password} | sudo -S systemctl status {service_name} --no-pager -l"
                        else:
                            journal_cmd = f"sudo -n journalctl -u {service_name} -n 50 --no-pager"
                            status_cmd = f"sudo -n systemctl status {service_name} --no-pager -l"
                        
                        # Получаем логи из journalctl
                        stdin_journal, stdout_journal, stderr_journal = ssh.exec_command(journal_cmd, timeout=10)
                        journal_output = stdout_journal.read().decode().strip()
                        stderr_journal.read()
                        stdout_journal.channel.recv_exit_status()
                        
                        # Получаем статус systemctl
                        stdin2, stdout2, stderr2 = ssh.exec_command(status_cmd, timeout=10)
                        status_output = stdout2.read().decode().strip()
                        stderr2.read()
                        stdout2.channel.recv_exit_status()
                        
                        # Проверяем что файл run.py существует
                        check_run_cmd = f"test -f {remote_agent_dir}/run.py && ls -la {remote_agent_dir}/run.py"
                        stdin_run, stdout_run, stderr_run = ssh.exec_command(check_run_cmd, timeout=5)
                        run_file_info = stdout_run.read().decode().strip()
                        stderr_run.read()
                        stdout_run.channel.recv_exit_status()
                        
                        error_details = f'Сервис не запущен. Статус: {service_status}\n'
                        if stderr_output:
                            error_details += f'Ошибка проверки: {stderr_output}\n'
                        error_details += f'\nДетали статуса:\n{status_output}\n'
                        error_details += f'\nПоследние логи:\n{journal_output}\n'
                        if run_file_info:
                            error_details += f'\nИнформация о run.py:\n{run_file_info}\n'
                        
                        ssh.close()
                        return jsonify({
                            'success': False, 
                            'error': error_details
                        }), 500
                    except Exception as log_error:
                        ssh.close()
                        return jsonify({
                            'success': False, 
                            'error': f'Сервис не запущен. Статус: {service_status}. Не удалось получить логи: {str(log_error)}'
                        }), 500
                
                # Получаем логи сервиса для подтверждения
                try:
                    if sudo_password:
                        import shlex
                        escaped_password = shlex.quote(sudo_password)
                        logs_cmd = f"echo {escaped_password} | sudo -S journalctl -u {service_name} -n 10 --no-pager"
                    else:
                        logs_cmd = f"sudo -n journalctl -u {service_name} -n 10 --no-pager"
                    stdin3, stdout3, stderr3 = ssh.exec_command(logs_cmd, timeout=10)
                    logs_output = stdout3.read().decode().strip()
                    stdout3.channel.recv_exit_status()
                except Exception:
                    logs_output = 'Логи недоступны'
                
            except Exception as status_error:
                ssh.close()
                return jsonify({
                    'success': False, 
                    'error': f'Ошибка проверки статуса сервиса: {str(status_error)}'
                }), 500
            
            # Получаем Omnissiah для использования в дальнейшем
            omnissiah = General.query.filter_by(role='Omnissiah').first()
            
            # ШАГ 1: Проверяем что mTLS сервис установил связь с главным сервером
            import time
            from datetime import datetime, timezone, timedelta
            
            app.logger.info(f"Ожидание установки связи mTLS для {node.name}...")
            mtls_connected = False
            max_wait_time = 60  # Максимальное время ожидания в секундах
            wait_start = time.time()
            
            while time.time() - wait_start < max_wait_time:
                # Обновляем узел из БД
                db.session.refresh(node)
                if node.last_heartbeat:
                    # Проверяем что heartbeat был недавно (в течение последних 2 минут)
                    time_since_heartbeat = datetime.now(timezone.utc) - node.last_heartbeat.replace(tzinfo=timezone.utc) if node.last_heartbeat.tzinfo is None else datetime.now(timezone.utc) - node.last_heartbeat
                    if time_since_heartbeat < timedelta(minutes=2):
                        mtls_connected = True
                        app.logger.info(f"mTLS связь установлена для {node.name} (последний heartbeat: {time_since_heartbeat.total_seconds():.1f} сек назад)")
                        break
                
                time.sleep(2)  # Ждем 2 секунды перед следующей проверкой
            
            if not mtls_connected:
                app.logger.warning(f"mTLS связь не установлена для {node.name} в течение {max_wait_time} секунд")
                # Продолжаем выполнение, но с предупреждением
            
            # ШАГ 2: Настраиваем и запускаем VPN (WireGuard)
            vpn_configured = False
            if node.name and node.ip_pool:
                try:
                    wg_config_path = f"/home/{user}/agents/setup/{node.name}.conf"
                    
                    # Проверяем что конфигурация WireGuard существует
                    check_cmd = f"test -f {wg_config_path}"
                    if sudo_password:
                        import shlex
                        escaped_password = shlex.quote(sudo_password)
                        full_check_cmd = f"echo {escaped_password} | sudo -S {check_cmd}"
                    else:
                        full_check_cmd = f"sudo -n {check_cmd}"
                    
                    stdin_check, stdout_check, stderr_check = ssh.exec_command(full_check_cmd, timeout=5)
                    stdout_check.read()
                    stderr_check.read()
                    exit_status_check = stdout_check.channel.recv_exit_status()
                    
                    if exit_status_check == 0:
                        # Конфигурация существует, запускаем VPN
                        app.logger.info(f"Настройка VPN для {node.name}...")
                        
                        # Копируем конфигурацию в /etc/wireguard/
                        copy_wg_cmd = f"cp {wg_config_path} /etc/wireguard/{node.name}.conf"
                        if sudo_password:
                            import shlex
                            escaped_password = shlex.quote(sudo_password)
                            full_wg_cmd = f"echo {escaped_password} | sudo -S {copy_wg_cmd}"
                        else:
                            full_wg_cmd = f"sudo -n {copy_wg_cmd}"
                        
                        stdin_wg, stdout_wg, stderr_wg = ssh.exec_command(full_wg_cmd, timeout=10)
                        stdout_wg.read()
                        stderr_wg.read()
                        exit_status_wg = stdout_wg.channel.recv_exit_status()
                        
                        if exit_status_wg == 0:
                            # Проверяем, не запущен ли уже интерфейс
                            check_wg_cmd = f"wg show {node.name} 2>&1"
                            stdin_check, stdout_check, stderr_check = ssh.exec_command(check_wg_cmd, timeout=5)
                            wg_check_output = stdout_check.read().decode().strip()
                            stderr_check.read()
                            exit_status_check = stdout_check.channel.recv_exit_status()
                            
                            if exit_status_check == 0:
                                # Интерфейс уже активен
                                app.logger.info(f"WireGuard интерфейс {node.name} уже активен")
                                vpn_configured = True
                            else:
                                # Интерфейс не активен, запускаем VPN
                                wg_up_cmd = f"wg-quick up {node.name}"
                                if sudo_password:
                                    import shlex
                                    escaped_password = shlex.quote(sudo_password)
                                    full_wg_up_cmd = f"echo {escaped_password} | sudo -S {wg_up_cmd}"
                                else:
                                    full_wg_up_cmd = f"sudo -n {wg_up_cmd}"
                                
                                stdin_wg_up, stdout_wg_up, stderr_wg_up = ssh.exec_command(full_wg_up_cmd, timeout=15)
                                stdout_wg_up_output = stdout_wg_up.read().decode().strip()
                                stderr_wg_up_output = stderr_wg_up.read().decode().strip()
                                exit_status_wg_up = stdout_wg_up.channel.recv_exit_status()
                                
                                if exit_status_wg_up == 0:
                                    vpn_configured = True
                                    app.logger.info(f"VPN успешно настроен и запущен для {node.name}")
                                    time.sleep(2)  # Даем VPN время установиться
                                else:
                                    # Проверяем, может интерфейс уже был запущен (ошибка "already exists")
                                    if 'already exists' in stderr_wg_up_output.lower():
                                        app.logger.info(f"WireGuard интерфейс {node.name} уже существует и активен")
                                        vpn_configured = True
                                    else:
                                        app.logger.warning(f"Не удалось запустить VPN для {node.name}: {stderr_wg_up_output}")
                                        # Пробуем проверить статус еще раз
                                        check_wg_retry = ssh.exec_command(f"wg show {node.name} 2>&1", timeout=5)
                                        check_output_retry = check_wg_retry[1].read().decode().strip()
                                        check_wg_retry[2].read()
                                        check_exit_retry = check_wg_retry[1].channel.recv_exit_status()
                                        if check_exit_retry == 0:
                                            app.logger.info(f"WireGuard интерфейс {node.name} все же активен после попытки запуска")
                                            vpn_configured = True
                        else:
                            app.logger.warning(f"Не удалось скопировать конфигурацию VPN для {node.name}")
                    else:
                        app.logger.warning(f"Конфигурация VPN не найдена для {node.name}: {wg_config_path}")
                except Exception as vpn_error:
                    app.logger.warning(f"Ошибка настройки VPN для {node.name}: {str(vpn_error)}")
            
            # ШАГ 3: Применяем правила безопасности из БД ПОСЛЕ установки VPN
            firewall_warning = None
            if node.role in ['Magos', 'Cognitor']:
                try:
                    # Получаем VPN IP адреса узлов (определяем ДО использования)
                    omnissiah = General.query.filter_by(role='Omnissiah').first()
                    omnissiah_vpn_ip = None
                    if omnissiah and omnissiah.ip_pool:
                        omnissiah_vpn_ip = omnissiah.ip_pool.split('/')[0]
                    
                    node_vpn_ip = node.ip_pool.split('/')[0] if node.ip_pool else None
                    
                    # Получаем правила безопасности из БД для этого узла
                    security_rules = AccessPolicyRule.query.filter(
                        ((AccessPolicyRule.destination_id == node.id) |
                         (AccessPolicyRule.source_id == node.id)),
                        AccessPolicyRule.status == 'applied'
                    ).all()
                    
                    if security_rules:
                        app.logger.info(f"Применение правил безопасности из БД для {node.name}: найдено {len(security_rules)} правил")
                        
                        # Применяем каждое правило через SSH
                        applied_rules_count = 0
                        total_rules_count = 0
                        for rule in security_rules:
                            try:
                                iptables_cmds = generate_iptables_commands_for_rule(rule)
                                total_rules_count += len(iptables_cmds)
                                for cmd_list in iptables_cmds:
                                    if isinstance(cmd_list, list):
                                        iptables_cmd = ' '.join(['sudo'] + cmd_list)
                                        if sudo_password:
                                            import shlex
                                            escaped_password = shlex.quote(sudo_password)
                                            escaped_cmd = shlex.quote(iptables_cmd)
                                            full_cmd = f"echo {escaped_password} | sudo -S {escaped_cmd}"
                                        else:
                                            full_cmd = f"sudo -n {iptables_cmd}"
                                        
                                        stdin_rule, stdout_rule, stderr_rule = ssh.exec_command(full_cmd, timeout=10)
                                        stdout_rule.read()
                                        stderr_rule.read()
                                        exit_status_rule = stdout_rule.channel.recv_exit_status()
                                        
                                        if exit_status_rule == 0:
                                            applied_rules_count += 1
                                            app.logger.info(f"Применено правило безопасности {rule.id} для {node.name}")
                                        else:
                                            app.logger.warning(f"Не удалось применить правило безопасности {rule.id} для {node.name}")
                            except Exception as rule_error:
                                app.logger.warning(f"Ошибка применения правила безопасности {rule.id}: {rule_error}")
                        
                        app.logger.info(f"Применено правил безопасности: {applied_rules_count} из {total_rules_count}")
                    
                    # ШАГ 4: Применяем дополнительные правила (ICMP, mTLS, VPN) и политику DROP
                    # Получаем РЕАЛЬНЫЕ IP адреса для правил
                    # omnissiah уже получен выше
                    omnissiah_real_ip = None
                    if omnissiah and omnissiah.endpoint:
                        omnissiah_real_ip = omnissiah.endpoint.split(':')[0]
                    
                    admin_real_ip = None
                    try:
                        admin_real_ip = request.headers.get('X-Real-IP') or \
                                      request.headers.get('X-Forwarded-For', '').split(',')[0].strip() or \
                                      request.remote_addr
                        if admin_real_ip and ':' in admin_real_ip:
                            admin_real_ip = admin_real_ip.split(':')[0]
                    except (AttributeError, TypeError) as e:
                        # Игнорируем ошибки обработки IP адреса
                        app.logger.debug(f"Ошибка обработки admin_real_ip: {e}")
                        pass
                    
                    # Применяем дополнительные правила
                    additional_rules = []
                    
                    # ICMP (ping)
                    additional_rules.append(('INPUT', '-p icmp -j ACCEPT', 'Разрешить входящий ICMP'))
                    additional_rules.append(('OUTPUT', '-p icmp -j ACCEPT', 'Разрешить исходящий ICMP'))
                    
                    # mTLS с Omnissiah (реальный IP)
                    if omnissiah_real_ip:
                        additional_rules.append(('INPUT', f'-s {omnissiah_real_ip} -p tcp --dport 5001 -j ACCEPT', f'Разрешить входящий mTLS с Omnissiah ({omnissiah_real_ip})'))
                    
                    # VPN (WireGuard) с Omnissiah (реальный IP)
                    if omnissiah_real_ip:
                        additional_rules.append(('INPUT', f'-s {omnissiah_real_ip} -p udp --dport 51820 -j ACCEPT', f'Разрешить входящий VPN с Omnissiah ({omnissiah_real_ip})'))
                    
                    # VPN трафик через интерфейс WireGuard (если VPN настроен)
                    if node_vpn_ip and node.name:
                        additional_rules.append(('INPUT', f'-i {node.name} -j ACCEPT', f'Разрешить входящий трафик через VPN интерфейс {node.name}'))
                        additional_rules.append(('OUTPUT', f'-o {node.name} -j ACCEPT', f'Разрешить исходящий трафик через VPN интерфейс {node.name}'))
                    
                    # Применяем дополнительные правила
                    for chain, rule_cmd, desc in additional_rules:
                        try:
                            iptables_cmd = f'sudo iptables -A {chain} {rule_cmd}'
                            if sudo_password:
                                import shlex
                                escaped_password = shlex.quote(sudo_password)
                                escaped_cmd = shlex.quote(iptables_cmd)
                                full_cmd = f"echo {escaped_password} | sudo -S {escaped_cmd}"
                            else:
                                full_cmd = f"sudo -n {iptables_cmd}"
                            
                            stdin_add, stdout_add, stderr_add = ssh.exec_command(full_cmd, timeout=5)
                            stdout_add.read()
                            stderr_add.read()
                            exit_status_add = stdout_add.channel.recv_exit_status()
                            if exit_status_add == 0:
                                app.logger.info(f"Применено дополнительное правило: {desc}")
                            else:
                                app.logger.warning(f"Не удалось применить дополнительное правило {desc}")
                        except Exception as e:
                            app.logger.warning(f"Ошибка применения дополнительного правила {desc}: {e}")
                    
                    # Разрешить весь исходящий трафик (ПЕРЕД политикой DROP!)
                    try:
                        iptables_cmd = 'sudo iptables -A OUTPUT -j ACCEPT'
                        if sudo_password:
                            import shlex
                            escaped_password = shlex.quote(sudo_password)
                            escaped_cmd = shlex.quote(iptables_cmd)
                            full_cmd = f"echo {escaped_password} | sudo -S {escaped_cmd}"
                        else:
                            full_cmd = f"sudo -n {iptables_cmd}"
                        
                        stdin_out, stdout_out, stderr_out = ssh.exec_command(full_cmd, timeout=5)
                        stdout_out.read()
                        stderr_out.read()
                        exit_status_out = stdout_out.channel.recv_exit_status()
                        if exit_status_out == 0:
                            app.logger.info("Применено OUTPUT ACCEPT")
                        else:
                            app.logger.warning("Не удалось применить OUTPUT ACCEPT")
                    except Exception as e:
                        app.logger.warning(f"Ошибка применения OUTPUT ACCEPT: {e}")
                    
                    # Применяем политику INPUT DROP в конце
                    try:
                        iptables_cmd = 'sudo iptables -P INPUT DROP'
                        if sudo_password:
                            import shlex
                            escaped_password = shlex.quote(sudo_password)
                            escaped_cmd = shlex.quote(iptables_cmd)
                            full_cmd = f"echo {escaped_password} | sudo -S {escaped_cmd}"
                        else:
                            full_cmd = f"sudo -n {iptables_cmd}"
                        
                        stdin_policy, stdout_policy, stderr_policy = ssh.exec_command(full_cmd, timeout=5)
                        stdout_policy.read()
                        stderr_policy.read()
                        exit_status_policy = stdout_policy.channel.recv_exit_status()
                        if exit_status_policy == 0:
                            app.logger.info("Применена политика INPUT DROP (OUTPUT остается ACCEPT)")
                        else:
                            app.logger.warning("Не удалось применить политику INPUT DROP")
                    except Exception as e:
                        app.logger.warning(f"Ошибка применения политики INPUT DROP: {e}")
                    
                    app.logger.info(f"Правила безопасности применены для {node.name}")
                    
                except Exception as firewall_error:
                    firewall_warning = f"Ошибка применения правил безопасности: {str(firewall_error)}"
                    app.logger.error(f"Ошибка при применении правил безопасности на {node.name}: {str(firewall_error)}")
                    import traceback
                    app.logger.error(traceback.format_exc())
            
            ssh.close()
            
            success_message = f'Сервис {service_name} успешно запущен'
            if firewall_warning:
                success_message += f'\n⚠️ {firewall_warning}'
            
            return jsonify({
                'success': True, 
                'message': success_message,
                'firewall_warning': firewall_warning,
                'status': service_status,
                'logs': logs_output[-500:] if logs_output else 'Логи недоступны'
            }), 200
            
        except ImportError:
            return jsonify({'success': False, 'error': 'paramiko library not installed'}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': f'Failed to start service: {str(e)}'}), 500
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ======================
# API для защищенных объектов (Политика безопасности)
# ======================

@app.route('/api/protected_objects', methods=['POST'])
@login_required
@admin_required
def api_create_protected_object():
    """
    Создание защищенного объекта
    
    Защищенный объект - это адрес, подсеть или диапазон адресов, которые находятся ЗА определенным узлом сети.
    При создании:
    1. Обновляется WireGuard allowed-ips для связанных узлов
    2. Маршрутизация происходит через WireGuard
    3. Правила iptables НЕ создаются (создаются только через политики безопасности)
    """
    try:
        data = request.get_json() or {}
        network = data.get('network')
        node_id = data.get('node_id')
        interface = data.get('interface', '')  # Интерфейс узла (опционально)
        description = data.get('description', '')
        
        if not all([network, node_id]):
            return jsonify({'success': False, 'error': 'Не заполнены обязательные поля: network, node_id'}), 400
        
        # Валидация формата сети
        try:
            ip_network(network, strict=False)
        except ValueError:
            return jsonify({'success': False, 'error': f'Неверный формат сети: {network}'}), 400
        
        # Проверяем существование узла
        node = db.session.get(General, node_id)
        if not node or node.role not in ['Omnissiah', 'Magos']:
            return jsonify({'success': False, 'error': 'Узел должен быть Omnissiah или Magos'}), 400
        
        # Создаем объект
        protected_obj = ProtectedObject(
            network=network,
            node_id=node_id,
            interface=interface if interface else None,
            description=description,
            created_by=current_user.id
        )
        
        db.session.add(protected_obj)
        db.session.commit()
        
        # Обновляем WireGuard allowed-ips для связанных узлов
        # КРИТИЧНО: Только обновление WireGuard, без системных маршрутов и правил iptables
        wg_warnings = []
        try:
            # Для Magos узлов обновляем allowed-ips на Omnissiah
            if node.role == 'Magos':
                omnissiah = General.query.filter_by(role='Omnissiah').first()
                if omnissiah and omnissiah.status == 'active':
                    # Проверяем, активен ли интерфейс WireGuard
                    result = subprocess.run(
                        ["sudo", "-n", "wg", "show", omnissiah.name],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    if result.returncode == 0:
                        # Интерфейс активен, синхронизируем пиры с обновленными allowed-ips
                        app.logger.info(f"Обновляем allowed-ips для {node.name} после добавления защищенного объекта {network}")
                        sync_wireguard_peers(omnissiah)
                    else:
                        wg_warnings.append(f"VPN интерфейс {omnissiah.name} не активен, allowed-ips не обновлен")
            elif node.role == 'Omnissiah':
                # Для Omnissiah также обновляем allowed-ips (если есть связанные узлы)
                app.logger.info(f"Обновляем allowed-ips для Omnissiah после добавления защищенного объекта {network}")
                sync_wireguard_peers(node)
        except Exception as e:
            app.logger.error(f"Ошибка обновления WireGuard allowed-ips: {str(e)}")
            import traceback
            app.logger.error(traceback.format_exc())
            wg_warnings.append(f"Не удалось обновить WireGuard allowed-ips: {str(e)}")
        
        return jsonify({
            'success': True,
            'message': 'Защищенный объект создан',
            'wg_warnings': wg_warnings,
            'object_id': protected_obj.id
        }), 200
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Create protected object error: {str(e)}")
        import traceback
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/protected_objects/<int:obj_id>', methods=['DELETE'])
@login_required
@admin_required
def api_delete_protected_object(obj_id):
    """Удаление защищенного объекта"""
    try:
        obj = db.session.get(ProtectedObject, obj_id)
        if not obj:
            return jsonify({'success': False, 'error': 'Объект не найден'}), 404
        
        # Сохраняем информацию об узле перед удалением для обновления allowed-ips
        node_id = obj.node_id
        node_role = None
        if node_id:
            node = db.session.get(General, node_id)
            if node:
                node_role = node.role
        
        db.session.delete(obj)
        db.session.commit()
        
        # Если защищенный объект принадлежал Magos узлу, обновляем allowed-ips для пира на Omnissiah
        if node_role == 'Magos':
            try:
                omnissiah = General.query.filter_by(role='Omnissiah').first()
                if omnissiah and omnissiah.status == 'active':
                    # Проверяем, активен ли интерфейс WireGuard
                    result = subprocess.run(
                        ["sudo", "-n", "wg", "show", omnissiah.name],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    if result.returncode == 0:
                        # Интерфейс активен, синхронизируем пиры с обновленными allowed-ips
                        app.logger.info(f"Обновляем allowed-ips после удаления защищенного объекта")
                        sync_wireguard_peers(omnissiah)
            except Exception as e:
                app.logger.warning(f"Не удалось обновить allowed-ips после удаления объекта: {str(e)}")
        
        return jsonify({'success': True, 'message': 'Защищенный объект удален'}), 200
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Delete protected object error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


def get_all_related_nodes(node):
    """
    Получает все узлы, связанные с данным узлом
    
    Включает:
    - Прямые связи через NodeConnection
    - Иерархические связи (родитель-потомок)
    - Omnissiah (всегда связан со всеми узлами)
    
    Args:
        node: Узел (General)
    
    Returns:
        set: Множество связанных узлов (General)
    """
    related_nodes = set()
    
    if not node:
        return related_nodes
    
    # Всегда добавляем Omnissiah (если это не сам Omnissiah)
    omnissiah = General.query.filter_by(role='Omnissiah').first()
    if omnissiah and omnissiah.id != node.id:
        related_nodes.add(omnissiah)
    
    # Добавляем прямые связи через NodeConnection
    connections = NodeConnection.query.filter(
        (NodeConnection.node1_id == node.id) | (NodeConnection.node2_id == node.id)
    ).all()
    
    for conn in connections:
        other_node_id = conn.node2_id if conn.node1_id == node.id else conn.node1_id
        other_node = db.session.get(General, other_node_id)
        if other_node:
            related_nodes.add(other_node)
    
    # Добавляем иерархические связи
    # Родитель
    if node.parent_id:
        parent = db.session.get(General, node.parent_id)
        if parent:
            related_nodes.add(parent)
    
    # Потомки
    children = General.query.filter_by(parent_id=node.id).all()
    for child in children:
        related_nodes.add(child)
    
    return related_nodes


def add_routes_for_protected_object(protected_obj):
    """
    УСТАРЕВШАЯ ФУНКЦИЯ: Маршруты теперь добавляются только через WireGuard allowed-ips
    
    Эта функция больше не используется. Маршрутизация происходит через WireGuard allowed-ips,
    которые обновляются через sync_wireguard_peers при создании защищенного объекта.
    
    Оставлена для совместимости, но не вызывается.
    
    Returns:
        list: Пустой список (функция не выполняет действий)
    """
    # Функция больше не используется - маршруты добавляются через WireGuard allowed-ips
    app.logger.debug(f"add_routes_for_protected_object вызвана для {protected_obj.network}, но маршруты теперь через WireGuard")
    return []


def add_iptables_blocking_for_protected_object(protected_obj):
    """
    УСТАРЕВШАЯ ФУНКЦИЯ: Правила iptables теперь создаются только через политики безопасности
    
    Эта функция больше не используется. Правила iptables должны создаваться только через
    политики безопасности (AccessPolicyRule), а не при создании защищенного объекта.
    
    Оставлена для совместимости, но не вызывается.
    
    Returns:
        list: Пустой список (функция не выполняет действий)
    """
    # Функция больше не используется - правила iptables создаются через политики безопасности
    app.logger.debug(f"add_iptables_blocking_for_protected_object вызвана для {protected_obj.network}, но правила теперь через политики безопасности")
    return []


def remove_routes_for_protected_object(protected_obj):
    """
    УСТАРЕВШАЯ ФУНКЦИЯ: Маршруты теперь управляются через WireGuard allowed-ips
    
    Эта функция больше не используется. Маршрутизация происходит через WireGuard allowed-ips,
    которые обновляются через sync_wireguard_peers при удалении защищенного объекта.
    
    Оставлена для совместимости, но не вызывается.
    """
    # Функция больше не используется - маршруты управляются через WireGuard allowed-ips
    app.logger.debug(f"remove_routes_for_protected_object вызвана для {protected_obj.network}, но маршруты теперь через WireGuard")
    return


def remove_iptables_blocking_for_protected_object(protected_obj):
    """
    УСТАРЕВШАЯ ФУНКЦИЯ: Правила iptables теперь управляются через политики безопасности
    
    Эта функция больше не используется. Правила iptables должны управляться только через
    политики безопасности (AccessPolicyRule), а не при удалении защищенного объекта.
    
    Оставлена для совместимости, но не вызывается.
    """
    # Функция больше не используется - правила iptables управляются через политики безопасности
    app.logger.debug(f"remove_iptables_blocking_for_protected_object вызвана для {protected_obj.network}, но правила теперь через политики безопасности")
    return


# ======================
# Вспомогательные функции для политик безопасности
# ======================

def get_rules_for_node(node):
    """
    Получает все правила политики доступа, связанные с узлом и его подчиненными узлами
    
    Логика:
    - Для Magos: правила самого Magos + правила всех его Cognitor-ов
    - Для Cognitor: только правила этого Cognitor-а
    - Для Omnissiah: все правила (так как он главный узел)
    
    Args:
        node: General объект (узел)
    
    Returns:
        list: Список AccessPolicyRule, отсортированный по priority
    """
    rules = []
    
    # Собираем список ID узлов для поиска (включая подчиненные)
    node_ids = [node.id]
    
    # Если это Magos, добавляем все его Cognitor-ы
    if node.role == 'Magos':
        cognitors = General.query.filter_by(parent_id=node.id, role='Cognitor').all()
        node_ids.extend([c.id for c in cognitors])
    
    # Если это Omnissiah, показываем все правила (будет обработано отдельно)
    if node.role == 'Omnissiah':
        # Для Omnissiah возвращаем все правила (будут отфильтрованы в основном запросе)
        all_rules = AccessPolicyRule.query.all()
        # Удаляем дубликаты и сортируем
        unique_rules = {rule.id: rule for rule in all_rules}.values()
        try:
            return sorted(unique_rules, key=lambda r: (r.priority if hasattr(r, 'priority') and r.priority is not None else 100, r.created_at))
        except Exception:
            return sorted(unique_rules, key=lambda r: r.created_at)
    
    # Правила где узел (или его подчиненные) является источником
    rules.extend(
        AccessPolicyRule.query.filter(
            (AccessPolicyRule.source_type == 'node') & 
            (AccessPolicyRule.source_id.in_(node_ids))
        ).all()
    )
    
    # Правила где узел (или его подчиненные) является назначением
    rules.extend(
        AccessPolicyRule.query.filter(
            (AccessPolicyRule.destination_type == 'node') & 
            (AccessPolicyRule.destination_id.in_(node_ids))
        ).all()
    )
    
    # Правила где узел (или его подчиненные) связан через защищенные объекты
    protected_objects = ProtectedObject.query.filter(
        ProtectedObject.node_id.in_(node_ids),
        ProtectedObject.is_active == True
    ).all()
    
    for obj in protected_objects:
        # Правила где защищенный объект является источником
        rules.extend(
            AccessPolicyRule.query.filter(
                (AccessPolicyRule.source_type == 'protected_object') & 
                (AccessPolicyRule.source_id == obj.id)
            ).all()
        )
        # Правила где защищенный объект является назначением
        rules.extend(
            AccessPolicyRule.query.filter(
                (AccessPolicyRule.destination_type == 'protected_object') & 
                (AccessPolicyRule.destination_id == obj.id)
            ).all()
        )
    
    # Удаляем дубликаты и сортируем по приоритету
    unique_rules = {rule.id: rule for rule in rules}.values()
    # Безопасная сортировка с проверкой наличия поля priority
    try:
        return sorted(unique_rules, key=lambda r: (r.priority if hasattr(r, 'priority') and r.priority is not None else 100, r.created_at))
    except Exception:
        return sorted(unique_rules, key=lambda r: r.created_at)


def get_related_node_for_rule(rule):
    """
    Получает узел, связанный с правилом (для сортировки)
    
    Args:
        rule: AccessPolicyRule объект
    
    Returns:
        General объект или None
    """
    # Сначала проверяем источник
    if rule.source_type == 'node' and rule.source_id:
        return db.session.get(General, rule.source_id)
    
    # Затем проверяем назначение
    if rule.destination_type == 'node' and rule.destination_id:
        return db.session.get(General, rule.destination_id)
    
    # Проверяем через защищенные объекты
    if rule.source_type == 'protected_object' and rule.source_id:
        obj = db.session.get(ProtectedObject, rule.source_id)
        if obj and obj.node:
            return obj.node
    
    if rule.destination_type == 'protected_object' and rule.destination_id:
        obj = db.session.get(ProtectedObject, rule.destination_id)
        if obj and obj.node:
            return obj.node
    
    return None


def group_rules_by_node(rules, nodes):
    """
    Группирует правила по узлам
    
    Args:
        rules: Список AccessPolicyRule
        nodes: Список General (узлы)
    
    Returns:
        dict: {node_name: [rules]}, отсортированный по priority
    """
    rules_by_node = {}
    
    # Инициализируем словарь для всех узлов
    for node in nodes:
        rules_by_node[node.name] = []
    
    # Группируем правила
    for rule in rules:
        # Определяем связанные узлы
        related_nodes = set()
        
        # Узел-источник
        if rule.source_type == 'node' and rule.source_id:
            source_node = db.session.get(General, rule.source_id)
            if source_node:
                related_nodes.add(source_node.name)
        
        # Узел-назначение
        if rule.destination_type == 'node' and rule.destination_id:
            dest_node = db.session.get(General, rule.destination_id)
            if dest_node:
                related_nodes.add(dest_node.name)
        
        # Узлы через защищенные объекты
        if rule.source_type == 'protected_object' and rule.source_id:
            obj = db.session.get(ProtectedObject, rule.source_id)
            if obj and obj.node:
                related_nodes.add(obj.node.name)
        
        if rule.destination_type == 'protected_object' and rule.destination_id:
            obj = db.session.get(ProtectedObject, rule.destination_id)
            if obj and obj.node:
                related_nodes.add(obj.node.name)
        
        # Добавляем правило во все связанные узлы
        for node_name in related_nodes:
            if node_name in rules_by_node:
                rules_by_node[node_name].append(rule)
    
    # Сортируем правила в каждой группе по приоритету
    for node_name in rules_by_node:
        try:
            rules_by_node[node_name] = sorted(
                rules_by_node[node_name],
                key=lambda r: (r.priority if hasattr(r, 'priority') and r.priority is not None else 100, r.created_at)
            )
        except Exception:
            rules_by_node[node_name] = sorted(
                rules_by_node[node_name],
                key=lambda r: r.created_at
            )
    
    return rules_by_node


# ======================
# API Endpoints для политики доступа
# ======================

@app.route('/api/access_policy/node/<int:node_id>/addresses', methods=['GET'])
@login_required
@admin_required
def api_get_node_addresses(node_id):
    """Получить список всех IP адресов узла (VPN + физические)"""
    try:
        node = db.session.get(General, node_id)
        if not node:
            return jsonify({'success': False, 'error': 'Узел не найден'}), 404
        
        addresses = []
        
        # Добавляем VPN IP узла
        if node.ip_pool:
            vpn_ip = node.ip_pool.split('/')[0]
            addresses.append({
                'type': 'vpn',
                'address': vpn_ip + '/32',
                'display': f'VPN: {vpn_ip}/32',
                'description': 'VPN адрес узла'
            })
        
        # Добавляем физические IP всех защищенных объектов на узле
        # КРИТИЧНО: Фильтруем только валидные защищенные объекты
        protected_objects = ProtectedObject.query.filter_by(node_id=node.id, is_active=True).all()
        for obj in protected_objects:
            # Пропускаем объекты с некорректными адресами
            if not obj.network or obj.network.strip() == '':
                continue
            # Пропускаем объекты с адресом 0.0.0.0/0 (это не конкретный адрес узла)
            if obj.network == '0.0.0.0/0':
                continue
            
            # Проверяем, что адрес действительно валидный
            # (дополнительная проверка на случай ошибок в БД)
            try:
                from ipaddress import ip_network
                # Парсим адрес для проверки валидности
                ip_network(obj.network, strict=False)
            except (ValueError, AttributeError):
                # Некорректный адрес - пропускаем
                continue
            
            addresses.append({
                'type': 'protected_object',
                'address': obj.network,
                'display': f'Защищенный объект: {obj.network}',
                'description': f'Защищенный объект за узлом {node.name}',
                'protected_object_id': obj.id
            })
        
        # Добавляем опцию "Все адреса"
        if len(addresses) > 1:
            addresses.insert(0, {
                'type': 'all',
                'address': None,
                'display': 'Все адреса узла',
                'description': 'Применить правило ко всем адресам (VPN + физические)'
            })
        
        return jsonify({
            'success': True,
            'addresses': addresses
        }), 200
        
    except Exception as e:
        app.logger.error(f"Get node addresses error: {str(e)}")
        import traceback
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/access_policy/rules', methods=['POST'])
@login_required
@admin_required
def api_create_access_policy_rule():
    """Создание правила политики доступа"""
    try:
        data = request.get_json() or {}
        
        # Валидация обязательных полей
        source_type = data.get('source_type')
        destination_type = data.get('destination_type')
        protocol = data.get('protocol', 'tcp')
        
        if not source_type or not destination_type:
            return jsonify({'success': False, 'error': 'Не указаны источник и/или назначение'}), 400
        
        # Получаем данные источника
        source_id = data.get('source_id')
        source_network = data.get('source_network')
        
        # Получаем данные назначения
        destination_id = data.get('destination_id')
        destination_network = data.get('destination_network')
        
        # Валидация: должен быть указан либо ID, либо network
        if source_type != 'network' and not source_id:
            return jsonify({'success': False, 'error': 'Для источника должен быть указан ID'}), 400
        if source_type == 'network' and not source_network:
            return jsonify({'success': False, 'error': 'Для источника-сети должен быть указан адрес'}), 400
        
        if destination_type != 'network' and not destination_id:
            return jsonify({'success': False, 'error': 'Для назначения должен быть указан ID'}), 400
        if destination_type == 'network' and not destination_network:
            return jsonify({'success': False, 'error': 'Для назначения-сети должен быть указан адрес'}), 400
        
        # Валидация формата сети (если указана)
        if source_type == 'network':
            try:
                ip_network(source_network, strict=False)
            except ValueError:
                return jsonify({'success': False, 'error': f'Неверный формат сети источника: {source_network}'}), 400
        
        if destination_type == 'network':
            try:
                ip_network(destination_network, strict=False)
            except ValueError:
                return jsonify({'success': False, 'error': f'Неверный формат сети назначения: {destination_network}'}), 400
        
        # Получаем action (ACCEPT, DROP, REJECT)
        action = data.get('action', 'ACCEPT')
        if action not in ['ACCEPT', 'DROP', 'REJECT']:
            action = 'ACCEPT'  # По умолчанию разрешаем
        
        # Получаем priority и group_id если указаны
        priority = data.get('priority', 100)
        group_id = data.get('group_id')
        
        # Валидация взаимодействия узлов (если оба узла указаны)
        source_node = None
        destination_node = None
        warnings = []
        
        if source_type == 'node' and source_id:
            source_node = db.session.get(General, source_id)
        elif source_type == 'protected_object' and source_id:
            source_obj = db.session.get(ProtectedObject, source_id)
            if source_obj and source_obj.node:
                source_node = source_obj.node
        
        if destination_type == 'node' and destination_id:
            destination_node = db.session.get(General, destination_id)
        elif destination_type == 'protected_object' and destination_id:
            dest_obj = db.session.get(ProtectedObject, destination_id)
            if dest_obj and dest_obj.node:
                destination_node = dest_obj.node
        
        # Проверяем возможность взаимодействия
        if source_node and destination_node:
            path_info = get_communication_path(source_node, destination_node)
            
            if not path_info['direct'] and not path_info['via_omnissiah']:
                return jsonify({
                    'success': False,
                    'error': f'Узлы не могут взаимодействовать: {path_info["reason"]}'
                }), 400
            
            if path_info['via_omnissiah'] and not path_info['direct']:
                warnings.append(f'Трафик будет проходить через Omnissiah (нет прямой связи между узлами)')
            
            # Проверяем Cognitor to Cognitor
            if source_node.role == 'Cognitor' and destination_node.role == 'Cognitor':
                if not (source_node.allow_cognitor_to_cognitor and destination_node.allow_cognitor_to_cognitor):
                    return jsonify({
                        'success': False,
                        'error': 'Cognitor не могут взаимодействовать напрямую друг с другом (если не разрешено явно в настройках узлов)'
                    }), 400
        
        # Создаем правило
        rule = AccessPolicyRule(
            source_type=source_type,
            source_id=source_id,
            source_network=source_network,
            destination_type=destination_type,
            destination_id=destination_id,
            destination_network=destination_network,
            protocol=protocol,
            action=action,
            ports=data.get('ports'),
            service=data.get('service'),
            description=data.get('description'),
            status='pending',
            priority=priority,
            group_id=group_id,
            created_by=current_user.id
        )
        
        db.session.add(rule)
        db.session.commit()
        
        response = {
            'success': True,
            'message': 'Правило доступа создано',
            'rule_id': rule.id
        }
        
        if warnings:
            response['warnings'] = warnings
        
        return jsonify(response), 200
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Create access policy rule error: {str(e)}")
        import traceback
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': str(e)}), 500


def remove_access_policy_rule_from_nodes(rule):
    """
    Удаляет правило политики доступа с узлов, где оно было применено
    
    Args:
        rule: AccessPolicyRule объект
        
    Returns:
        tuple: (success: bool, errors: list)
    """
    errors = []
    
    if not rule or rule.status != 'applied':
        return True, errors
    
    # Получаем список узлов, где правило было применено
    applied_nodes = []
    if rule.applied_on_nodes:
        try:
            applied_nodes = json.loads(rule.applied_on_nodes)
        except Exception as e:
            app.logger.warning(f"Ошибка парсинга applied_on_nodes для правила {rule.id}: {str(e)}")
    
    if not applied_nodes:
        app.logger.warning(f"Правило {rule.id} помечено как примененное, но список узлов пуст")
        return True, errors
    
    # Получаем снимок конфигурации
    config_snapshot = {}
    if rule.configuration_snapshot:
        try:
            config_snapshot = json.loads(rule.configuration_snapshot)
        except Exception as e:
            app.logger.warning(f"Ошибка парсинга configuration_snapshot для правила {rule.id}: {str(e)}")
    
    # Удаляем правила на каждом узле
    for node_info in applied_nodes:
        node_id = node_info.get('node_id') if isinstance(node_info, dict) else node_info
        if not node_id:
            continue
        
        node = db.session.get(General, node_id)
        if not node:
            errors.append(f"Узел с ID {node_id} не найден")
            continue
        
        try:
            # Формируем команды для удаления iptables правил
            # Берем команды из снимка конфигурации или генерируем по правилу
            iptables_rules = config_snapshot.get('iptables_rules', [])
            
            if not iptables_rules:
                # Если в снимке нет команд, генерируем их по правилу
                # (это fallback на случай, если снимок не был сохранен)
                app.logger.warning(f"Снимок конфигурации для правила {rule.id} не содержит iptables правил, пытаемся удалить по правилу")
                iptables_rules = generate_iptables_commands_for_rule(rule)
            
            # Определяем, локальный ли это узел (Omnissiah) или удаленный (Magos)
            if node.role == 'Omnissiah':
                # Локальное удаление
                for cmd_parts in iptables_rules:
                    # Преобразуем -A в -D для удаления
                    delete_cmd = ['-D'] + cmd_parts[1:] if cmd_parts[0] == '-A' else ['-D'] + cmd_parts
                    try:
                        result = subprocess.run(
                            ['sudo', '-n', 'iptables'] + delete_cmd,
                            capture_output=True,
                            text=True,
                            timeout=10,
                            check=False  # Не падаем, если правило уже удалено
                        )
                        if result.returncode == 0:
                            app.logger.info(f"Удалено iptables правило на {node.name}: {' '.join(delete_cmd)}")
                        else:
                            # Правило могло быть уже удалено или его не было
                            app.logger.debug(f"Не удалось удалить правило на {node.name} (возможно уже удалено): {result.stderr}")
                    except Exception as e:
                        errors.append(f"Ошибка удаления правила на {node.name}: {str(e)}")
            
            elif node.role in ['Magos', 'Cognitor']:
                # Удаление через VPN вместо SSH
                try:
                    from omnissiah_core.nmc_vpn_config_sender import send_iptables_rules_via_vpn
                    
                    # Отправляем правила через VPN с action='remove'
                    success, error_msg = send_iptables_rules_via_vpn(
                        node, 
                        iptables_rules, 
                        action='remove',
                        app=app,
                        check_connectivity=True  # Проверяем VPN перед отправкой
                    )
                    
                    if success:
                        app.logger.info(f"Удалены iptables правила на {node.name} через VPN")
                    else:
                        errors.append(f"Ошибка удаления правил на {node.name}: {error_msg}")
                
                except ImportError as e:
                    errors.append(f"Не удалось импортировать vpn_config_sender: {str(e)}")
                except Exception as e:
                    errors.append(f"Ошибка отправки конфигурации через VPN на {node.name}: {str(e)}")
        
        except Exception as e:
            errors.append(f"Ошибка удаления правил на узле {node.name}: {str(e)}")
    
    return len(errors) == 0, errors


def generate_iptables_commands_for_rule(rule):
    """
    Генерирует команды iptables для правила
    
    Args:
        rule: AccessPolicyRule объект
        
    Returns:
        list: Список списков команд (каждый элемент - части команды iptables)
    """
    commands = []
    
    # Получаем источник и назначение
    source = get_source_network_for_rule(rule)
    destination = get_destination_network_for_rule(rule)
    
    # КРИТИЧНО: Для узла destination может быть None (все адреса узла)
    # В этом случае нужно создать правила для всех адресов узла
    if rule.destination_type == 'node' and destination is None:
        # Получаем узел
        node = db.session.get(General, rule.destination_id) if rule.destination_id else None
        if not node:
            return commands
        
        # Создаем список всех адресов узла (VPN + физические IP защищенных объектов)
        node_addresses = []
        
        # Добавляем VPN IP узла
        if node.ip_pool:
            vpn_ip = node.ip_pool.split('/')[0] + '/32'
            node_addresses.append(vpn_ip)
        
        # Добавляем физические IP всех защищенных объектов на узле
        protected_objects = ProtectedObject.query.filter_by(node_id=node.id).all()
        for obj in protected_objects:
            if obj.network:
                node_addresses.append(obj.network)
        
        # Если нет адресов, возвращаем пустой список
        if not node_addresses:
            return commands
        
        # Создаем правила для каждого адреса узла
        for addr in node_addresses:
            # Рекурсивно вызываем для каждого адреса
            # Создаем временное правило с destination_network = адрес
            temp_rule = type('TempRule', (), {
                'source_type': rule.source_type,
                'source_id': rule.source_id,
                'source_network': rule.source_network,
                'destination_type': 'network',
                'destination_id': None,
                'destination_network': addr,
                'protocol': rule.protocol,
                'ports': rule.ports,
                'action': rule.action,
                'direction': rule.direction,
                'id': rule.id
            })()
            
            # Генерируем команды для этого адреса
            temp_commands = generate_iptables_commands_for_rule(temp_rule)
            commands.extend(temp_commands)
        
        return commands
    
    if not source or destination is None:
        return commands
    
    # Определяем протокол и порты
    protocol = rule.protocol.lower() if rule.protocol else 'tcp'
    ports = rule.ports if rule.ports else None
    
    # Определяем направление из правила (если указано)
    # КРИТИЧНО: Если direction установлен в 'FORWARD' по умолчанию, но destination - узел,
    # нужно переопределить на INPUT, так как трафик на узел идет через INPUT, а не FORWARD
    direction = rule.direction if hasattr(rule, 'direction') and rule.direction else None
    
    # Получаем узлы для определения направления
    source_node = None
    destination_node = None
    
    if rule.source_type == 'node' and rule.source_id:
        source_node = db.session.get(General, rule.source_id)
    elif rule.source_type == 'protected_object' and rule.source_id:
        source_obj = db.session.get(ProtectedObject, rule.source_id)
        if source_obj and source_obj.node:
            source_node = source_obj.node
    
    if rule.destination_type == 'node' and rule.destination_id:
        destination_node = db.session.get(General, rule.destination_id)
    elif rule.destination_type == 'protected_object' and rule.destination_id:
        dest_obj = db.session.get(ProtectedObject, rule.destination_id)
        if dest_obj and dest_obj.node:
            destination_node = dest_obj.node
    
    # КРИТИЧНО: Если destination - узел, трафик идет через INPUT, а не FORWARD
    # Переопределяем direction на INPUT, даже если оно было установлено в FORWARD
    if destination_node:
        # Если назначение - узел, это всегда INPUT (входящий трафик на узел)
        direction = 'INPUT'
    elif not direction:
        # Определяем направление автоматически на основе source и destination
        # КРИТИЧНО: Для блокировки входящего трафика на узел нужно использовать INPUT
        # Для блокировки исходящего трафика с узла нужно использовать OUTPUT
        # Для межсетевого трафика используется FORWARD
        
        # Определяем направление
        # КРИТИЧНО: Для блокировки входящего трафика на узел используем INPUT
        # Для блокировки исходящего трафика с узла используем OUTPUT
        if source_node and destination_node:
            # Если источник и назначение - узлы, это INPUT на destination узле
            # (блокируем входящий трафик на destination от source)
            direction = 'INPUT'
        elif rule.source_type == 'network' and destination_node:
            # Входящий трафик на узел из сети
            direction = 'INPUT'
        elif source_node and rule.destination_type == 'network':
            # Проверяем: если source_node - это Omnissiah, а destination - сеть, это OUTPUT
            # Но если это правило блокировки (DROP/REJECT), возможно пользователь хочет блокировать INPUT
            # Проверяем по action - если DROP/REJECT и destination выглядит как адрес администратора, это INPUT
            action_val = getattr(rule, 'action', 'ACCEPT') if hasattr(rule, 'action') and rule.action else 'ACCEPT'
            if action_val in ['DROP', 'REJECT'] and rule.destination_network:
                # Если это правило блокировки и назначение - сеть, вероятно это INPUT на source_node
                # (администратор пытается заблокировать трафик к себе)
                direction = 'INPUT'
            else:
                # Исходящий трафик с узла в сеть
                direction = 'OUTPUT'
        elif rule.source_type == 'node' and rule.destination_type == 'network':
            # Аналогичная логика: если это правило блокировки, возможно это INPUT
            action_val = getattr(rule, 'action', 'ACCEPT') if hasattr(rule, 'action') and rule.action else 'ACCEPT'
            if action_val in ['DROP', 'REJECT']:
                # Для правил блокировки: если source_node - Omnissiah, а destination - сеть админа,
                # вероятно пользователь хочет блокировать входящий трафик на Omnissiah
                # Проверяем: если source_node - Omnissiah, это INPUT на Omnissiah
                if source_node and source_node.role == 'Omnissiah':
                    direction = 'INPUT'
                else:
                    direction = 'OUTPUT'
            else:
                # Исходящий трафик с узла
                direction = 'OUTPUT'
        elif rule.source_type == 'network' and rule.destination_type == 'network':
            # Межсетевой трафик
            direction = 'FORWARD'
        else:
            # По умолчанию FORWARD для межсетевого трафика
            direction = 'FORWARD'
    
    # Генерируем команду для соответствующей цепочки
    chain = direction
    
    # Определяем действие для правила (ACCEPT, DROP, REJECT) - нужно определить ДО использования
    # По умолчанию ACCEPT, если не указано
    action = getattr(rule, 'action', 'ACCEPT') if hasattr(rule, 'action') and rule.action else 'ACCEPT'
    if action not in ['ACCEPT', 'DROP', 'REJECT']:
        action = 'ACCEPT'  # Fallback на ACCEPT если неверное значение
    
    # КРИТИЧНО: Для правил DROP/REJECT используем -I (insert) чтобы они применялись ПЕРЕД правилами ACCEPT
    # Это гарантирует, что запрещающие правила имеют приоритет над разрешающими
    if action in ['DROP', 'REJECT']:
        # Используем insert в начало цепочки (позиция 1) для правил блокировки
        cmd = ['-I', chain, '1']
    else:
        # Используем append для правил разрешения
        cmd = ['-A', chain]
    
    # Проверяем, является ли это системным правилом администратора
    is_admin_rule = (hasattr(rule, 'is_system_rule') and rule.is_system_rule and 
                    rule.description and 'администратора' in rule.description)
    
    # Проверяем, является ли это системным правилом для исходящего трафика с узла
    is_output_rule_from_node = (hasattr(rule, 'is_system_rule') and rule.is_system_rule and
                                direction == 'OUTPUT' and rule.source_type == 'node' and
                                rule.destination_type == 'network' and 
                                rule.destination_network == '0.0.0.0/0')
    
    # КРИТИЧНО: Для правил блокировки (DROP/REJECT) исключаем admin_ip из блокировки
    # чтобы администратор всегда имел доступ
    admin_ip_to_exclude = None
    if action in ['DROP', 'REJECT'] and direction == 'INPUT':
        # Получаем admin_ip из Omnissiah для исключения из блокировки
        omnissiah = General.query.filter_by(role='Omnissiah').first()
        if omnissiah and omnissiah.admin_ip:
            admin_ip_to_exclude = omnissiah.admin_ip.strip()
    
    # Добавляем источник
    # ВАЖНО: Для OUTPUT правил source НЕ указывается, потому что источник - это сам узел
    # Для OUTPUT правил указываем только destination, протокол и порты
    # Для INPUT правил указываем source (откуда приходит трафик)
    # КРИТИЧНО: Если это INPUT правило на Omnissiah, а source - узел Omnissiah,
    # то нужно использовать IP адреса администратора (из destination_network)
    
    if source != 'any' and source and direction != 'OUTPUT':
        # Для INPUT и FORWARD правил добавляем source
        if not (is_admin_rule and direction == 'INPUT' and source == '0.0.0.0/0'):
            # Если это INPUT правило блокировки на Omnissiah, и source_type == 'node' (Omnissiah),
            # а destination - сеть, то нужно использовать destination_network как source
            if direction == 'INPUT' and rule.source_type == 'node' and rule.destination_type == 'network':
                # Используем destination_network как source для INPUT правила
                if rule.destination_network and rule.destination_network != '0.0.0.0/0':
                    cmd.extend(['-s', rule.destination_network])
                else:
                    cmd.extend(['-s', source])
            else:
                cmd.extend(['-s', source])
            
            # КРИТИЧНО: Если это правило блокировки и source == '0.0.0.0/0' (любой источник),
            # исключаем admin_ip из блокировки, чтобы администратор всегда имел доступ
            if action in ['DROP', 'REJECT'] and source == '0.0.0.0/0' and admin_ip_to_exclude:
                cmd.extend(['!', '-s', admin_ip_to_exclude])
    
    # Добавляем назначение
    # Для OUTPUT правил с destination='0.0.0.0/0' не указываем -d (разрешаем на любые адреса)
    # Для INPUT правил администратора не указываем destination, чтобы правило применялось ко всем интерфейсам
    # КРИТИЧНО: Для INPUT правил на Omnissiah, когда source - Omnissiah, а destination - сеть,
    # destination должен быть IP Omnissiah (или не указываться)
    if destination != 'any' and destination:
        if not (is_admin_rule and direction == 'INPUT' and destination == '0.0.0.0/0'):
            # Для OUTPUT правил с destination='0.0.0.0/0' не указываем -d
            if not (direction == 'OUTPUT' and destination == '0.0.0.0/0'):
                # Для INPUT правил, когда source - узел, а destination - сеть,
                # destination должен быть IP адрес узла (на который приходит трафик)
                if direction == 'INPUT' and rule.source_type == 'node' and rule.destination_type == 'network':
                    # Определяем IP адрес узла назначения (на который приходит трафик)
                    destination_node = None
                    if rule.source_id:
                        source_node = db.session.get(General, rule.source_id)
                        if source_node and source_node.ip_pool:
                            # Используем IP адрес узла как destination
                            node_ip = source_node.ip_pool.split('/')[0] + '/32'
                            cmd.extend(['-d', node_ip])
                    else:
                        # Если не можем определить, используем исходный destination
                        cmd.extend(['-d', destination])
                else:
                    cmd.extend(['-d', destination])
    
    # Добавляем протокол
    if protocol != 'any':
        cmd.extend(['-p', protocol])
    
    # Определяем действие для правила (ACCEPT, DROP, REJECT)
    # По умолчанию ACCEPT, если не указано
    action = getattr(rule, 'action', 'ACCEPT') if hasattr(rule, 'action') and rule.action else 'ACCEPT'
    if action not in ['ACCEPT', 'DROP', 'REJECT']:
        action = 'ACCEPT'  # Fallback на ACCEPT если неверное значение
    
    # Генерируем точные правила в зависимости от протокола и портов
    if protocol == 'icmp':
        # Для ICMP ping нужны ДВА правила:
        # 1. --icmp-type 8 (echo-request) - для исходящих ping запросов
        # 2. --icmp-type 0 (echo-reply) - для входящих ping ответов
        # КРИТИЧНО: Без обоих правил ping не будет работать полностью
        
        rule_id = rule.id if rule.id is not None else 'system'
        
        # Правило для echo-request (тип 8) - исходящие ping запросы
        icmp_request_cmd = cmd.copy()
        icmp_request_cmd.extend(['-m', 'icmp', '--icmp-type', '8', '-j', action])
        icmp_request_cmd.extend(['-m', 'comment', '--comment', f'PolicyRule#{rule_id}: ICMP echo-request - {action}'])
        commands.append(icmp_request_cmd)
        
        # Правило для echo-reply (тип 0) - входящие ping ответы
        icmp_reply_cmd = cmd.copy()
        icmp_reply_cmd.extend(['-m', 'icmp', '--icmp-type', '0', '-j', action])
        icmp_reply_cmd.extend(['-m', 'comment', '--comment', f'PolicyRule#{rule_id}: ICMP echo-reply - {action}'])
        commands.append(icmp_reply_cmd)
    elif ports and protocol in ['tcp', 'udp']:
        # Для TCP/UDP с портами - только указанные порты
        rule_id = rule.id if rule.id is not None else 'system'
        
        # КРИТИЧНО: Для UDP протоколов часто нужны двунаправленные правила
        # (входящие и исходящие запросы), особенно для:
        # - DNS (порт 53) - запросы и ответы
        # - NTP (порт 123) - запросы и ответы
        # - DHCP (порты 67/68) - запросы и ответы
        # - Другие UDP протоколы без установления соединения
        # 
        # Для TCP обычно достаточно одного правила (--dport), так как TCP использует
        # установление соединения (ESTABLISHED), которое автоматически разрешает ответы
        
        requires_bidirectional = (protocol == 'udp')
        
        if ',' in ports:
            # Несколько портов - создаем отдельное правило для каждого
            for port in ports.split(','):
                port = port.strip()
                if port:
                    # Исходящий трафик (--dport - порт назначения)
                    port_cmd = cmd.copy()
                    port_cmd.extend(['--dport', port, '-j', action])
                    port_cmd.extend(['-m', 'comment', '--comment', f'PolicyRule#{rule_id}: {protocol}:{port} - {action}'])
                    commands.append(port_cmd)
                    
                    # Для UDP: добавляем правило для ответов
                    # КРИТИЧНО: Для OUTPUT правил ответы идут через INPUT цепочку
                    # Для INPUT/FORWARD правил ответы идут через ту же цепочку
                    if requires_bidirectional:
                        reply_cmd = cmd.copy()
                        # Для ответов используем --sport (порт источника ответа)
                        # Если это было OUTPUT правило, ответы идут через INPUT
                        if direction == 'OUTPUT':
                            # Меняем цепочку на INPUT для ответов
                            reply_cmd[reply_cmd.index(chain)] = 'INPUT'
                        reply_cmd.extend(['--sport', port, '-j', action])
                        reply_cmd.extend(['-m', 'comment', '--comment', f'PolicyRule#{rule_id}: {protocol}:{port} reply - {action}'])
                        commands.append(reply_cmd)
        elif '-' in ports:
            # Диапазон портов
            port_cmd = cmd.copy()
            port_cmd.extend(['--dport', ports, '-j', action])
            port_cmd.extend(['-m', 'comment', '--comment', f'PolicyRule#{rule_id}: {protocol}:{ports} - {action}'])
            commands.append(port_cmd)
            
            # Для UDP: добавляем правило для ответов
            if requires_bidirectional:
                reply_cmd = cmd.copy()
                # Для OUTPUT правил ответы идут через INPUT цепочку
                if direction == 'OUTPUT':
                    reply_cmd[reply_cmd.index(chain)] = 'INPUT'
                reply_cmd.extend(['--sport', ports, '-j', action])
                reply_cmd.extend(['-m', 'comment', '--comment', f'PolicyRule#{rule_id}: {protocol}:{ports} reply - {action}'])
                commands.append(reply_cmd)
        else:
            # Один порт - точное правило (например, только SSH на порту 22)
            port_cmd = cmd.copy()
            port_cmd.extend(['--dport', ports, '-j', action])
            port_cmd.extend(['-m', 'comment', '--comment', f'PolicyRule#{rule_id}: {protocol}:{ports} - {action}'])
            commands.append(port_cmd)
            
            # Для UDP: добавляем правило для ответов
            # КРИТИЧНО: Для UDP протоколов (DNS, NTP, DHCP и т.д.) нужны оба правила
            if requires_bidirectional:
                reply_cmd = cmd.copy()
                # Для OUTPUT правил ответы идут через INPUT цепочку
                if direction == 'OUTPUT':
                    reply_cmd[reply_cmd.index(chain)] = 'INPUT'
                reply_cmd.extend(['--sport', ports, '-j', action])
                reply_cmd.extend(['-m', 'comment', '--comment', f'PolicyRule#{rule_id}: {protocol}:{ports} reply - {action}'])
                commands.append(reply_cmd)
    else:
        # Без портов или протокол 'any' - применяем действие ко всему трафику
        action_cmd = cmd.copy()
        action_cmd.extend(['-j', action])
        rule_id = rule.id if rule.id is not None else 'system'
        action_cmd.extend(['-m', 'comment', '--comment', f'PolicyRule#{rule_id}: {protocol} - {action}'])
        commands.append(action_cmd)
    
    return commands


def get_source_network_for_rule(rule):
    """Получает сеть источника для правила"""
    if rule.source_type == 'protected_object':
        obj = db.session.get(ProtectedObject, rule.source_id) if rule.source_id else None
        return obj.network if obj else None
    elif rule.source_type == 'node':
        node = db.session.get(General, rule.source_id) if rule.source_id else None
        if node and node.ip_pool:
            return node.ip_pool.split('/')[0] + '/32'
        return None
    else:
        return rule.source_network


def get_destination_network_for_rule(rule):
    """
    Получает сеть назначения для правила
    
    Логика:
    - Защищенный объект: используем network защищенного объекта (физический IP)
    - Узел сети: 
      * Если указан destination_network (конкретный VPN IP) - используем его
      * Если destination_network не указан - возвращаем None (все адреса узла)
    """
    if rule.destination_type == 'protected_object':
        # Защищенный объект - используем его network (физический IP)
        obj = db.session.get(ProtectedObject, rule.destination_id) if rule.destination_id else None
        return obj.network if obj else None
    elif rule.destination_type == 'node':
        # Узел сети
        # Если указан destination_network (конкретный VPN IP), используем его
        if rule.destination_network:
            return rule.destination_network
        
        # Если destination_network не указан - возвращаем None (все адреса узла)
        # В generate_iptables_commands_for_rule будет создано правило для всех адресов
        return None
    else:
        return rule.destination_network


def can_nodes_communicate_directly(node1, node2):
    """
    Проверяет, могут ли два узла взаимодействовать напрямую (без Omnissiah)
    
    Args:
        node1: Первый узел (General)
        node2: Второй узел (General)
    
    Returns:
        tuple: (can_direct: bool, reason: str)
    """
    if not node1 or not node2:
        return False, "Узлы не найдены"
    
    # Один и тот же узел
    if node1.id == node2.id:
        return True, "Один и тот же узел"
    
    # Omnissiah всегда может взаимодействовать со всеми узлами через иерархию
    # Но для прямой связи (без промежуточного узла) нужна NodeConnection
    if node1.role == 'Omnissiah' or node2.role == 'Omnissiah':
        # Для Omnissiah проверяем прямую связь через NodeConnection
        # Если прямой связи нет, взаимодействие возможно через иерархию (родитель-потомок)
        # но это не "прямая" связь, поэтому возвращаем False для прямого взаимодействия
        pass  # Продолжаем проверку прямых связей
    
    # Проверяем прямые связи (NodeConnection)
    direct_connection = NodeConnection.query.filter(
        ((NodeConnection.node1_id == node1.id) & (NodeConnection.node2_id == node2.id)) |
        ((NodeConnection.node1_id == node2.id) & (NodeConnection.node2_id == node1.id))
    ).first()
    
    if direct_connection:
        # Если есть прямая связь, проверяем дополнительные ограничения
        
        # Cognitor не могут взаимодействовать напрямую друг с другом
        # (если не разрешено явно в allow_cognitor_to_cognitor)
        if node1.role == 'Cognitor' and node2.role == 'Cognitor':
            # Проверяем разрешение на прямую связь между Cognitor'ами
            # Разрешение должно быть на обоих узлах
            if not (node1.allow_cognitor_to_cognitor and node2.allow_cognitor_to_cognitor):
                return False, "Cognitor не могут взаимодействовать напрямую (если не разрешено явно)"
            return True, "Прямая связь между Cognitor разрешена"
        
        # Если есть прямая связь и это не два Cognitor без разрешения
        return True, "Прямая связь установлена"
    
    # Нет прямой связи - могут взаимодействовать только через Omnissiah
    return False, "Нет прямой связи, требуется маршрут через Omnissiah"


def get_communication_path(source_node, destination_node):
    """
    Определяет путь взаимодействия между узлами
    
    Args:
        source_node: Узел-источник (General)
        destination_node: Узел-назначение (General)
    
    Returns:
        dict: {
            'direct': bool,  # Прямая связь
            'via_omnissiah': bool,  # Через Omnissiah
            'path': list,  # Список узлов пути
            'reason': str  # Причина выбора пути
        }
    """
    if not source_node or not destination_node:
        return {
            'direct': False,
            'via_omnissiah': False,
            'path': [],
            'reason': 'Узлы не найдены'
        }
    
    # Один и тот же узел
    if source_node.id == destination_node.id:
        return {
            'direct': True,
            'via_omnissiah': False,
            'path': [source_node],
            'reason': 'Один и тот же узел'
        }
    
    # Проверяем прямую связь
    can_direct, reason = can_nodes_communicate_directly(source_node, destination_node)
    
    if can_direct and 'прямая связь' in reason.lower():
        return {
            'direct': True,
            'via_omnissiah': False,
            'path': [source_node, destination_node],
            'reason': reason
        }
    
    # Проверяем путь через Omnissiah
    omnissiah = General.query.filter_by(role='Omnissiah').first()
    if omnissiah:
        # Omnissiah всегда может взаимодействовать со всеми узлами через иерархию
        # Проверяем доступность узлов через родительские связи
        source_accessible = False
        dest_accessible = False
        
        # Источник доступен если:
        # - это Omnissiah
        # - имеет родителя (Magos или прямой Cognitor)
        # - имеет прямую связь с Omnissiah
        if source_node.role == 'Omnissiah':
            source_accessible = True
        elif source_node.parent_id:
            # Проверяем цепочку родительских связей до Omnissiah
            current = source_node
            while current and current.parent_id:
                if current.parent and current.parent.role == 'Omnissiah':
                    source_accessible = True
                    break
                current = current.parent
        else:
            # Проверяем прямую связь с Omnissiah
            direct_to_omnissiah = NodeConnection.query.filter(
                ((NodeConnection.node1_id == source_node.id) & (NodeConnection.node2_id == omnissiah.id)) |
                ((NodeConnection.node1_id == omnissiah.id) & (NodeConnection.node2_id == source_node.id))
            ).first()
            if direct_to_omnissiah:
                source_accessible = True
        
        # Аналогично для назначения
        if destination_node.role == 'Omnissiah':
            dest_accessible = True
        elif destination_node.parent_id:
            current = destination_node
            while current and current.parent_id:
                if current.parent and current.parent.role == 'Omnissiah':
                    dest_accessible = True
                    break
                current = current.parent
        else:
            direct_to_omnissiah = NodeConnection.query.filter(
                ((NodeConnection.node1_id == destination_node.id) & (NodeConnection.node2_id == omnissiah.id)) |
                ((NodeConnection.node1_id == omnissiah.id) & (NodeConnection.node2_id == destination_node.id))
            ).first()
            if direct_to_omnissiah:
                dest_accessible = True
        
        # Если оба узла доступны через Omnissiah, возвращаем путь через Omnissiah
        if source_accessible and dest_accessible:
            return {
                'direct': False,
                'via_omnissiah': True,
                'path': [source_node, omnissiah, destination_node],
                'reason': 'Через Omnissiah'
            }
    
    # Если путь невозможен
    return {
        'direct': False,
        'via_omnissiah': False,
        'path': [],
        'reason': 'Путь взаимодействия невозможен'
    }


@app.route('/api/access_policy/rules/<int:rule_id>', methods=['DELETE'])
@login_required
@admin_required
def api_delete_access_policy_rule(rule_id):
    """Удаление правила политики доступа"""
    try:
        rule = db.session.get(AccessPolicyRule, rule_id)
        if not rule:
            return jsonify({'success': False, 'error': 'Правило не найдено'}), 404
        
        # Запрещаем удаление системных правил
        if rule.is_system_rule:
            return jsonify({'success': False, 'error': 'Нельзя удалить системное правило'}), 403
        
        # Если правило применено, нужно удалить его с узлов
        removal_errors = []
        if rule.status == 'applied':
            app.logger.info(f"Удаляем правило {rule_id} с узлов")
            success, removal_errors = remove_access_policy_rule_from_nodes(rule)
            if not success and removal_errors:
                app.logger.warning(f"Ошибки при удалении правила {rule_id} с узлов: {removal_errors}")
        
        # Удаляем правило из БД
        db.session.delete(rule)
        db.session.commit()
        
        if removal_errors:
            return jsonify({
                'success': True,
                'message': 'Правило удалено, но были ошибки при удалении с некоторых узлов',
                'warnings': removal_errors
            }), 200
        
        return jsonify({'success': True, 'message': 'Правило удалено'}), 200
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Delete access policy rule error: {str(e)}")
        import traceback
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/access_policy/rules/<int:rule_id>/save', methods=['POST'])
@login_required
@admin_required
def api_save_access_policy_rule(rule_id):
    """
    Сохраняет конфигурацию правила БЕЗ применения
    
    Генерирует iptables команды и маршруты, сохраняет в configuration_snapshot,
    но НЕ отправляет на узлы
    """
    try:
        rule = db.session.get(AccessPolicyRule, rule_id)
        if not rule:
            return jsonify({'success': False, 'error': 'Правило не найдено'}), 404
        
        # 1. Определяем узлы для применения правила
        nodes_to_apply = determine_nodes_for_rule(rule)
        
        if not nodes_to_apply:
            return jsonify({
                'success': False,
                'error': 'Не найдено узлов для применения правила'
            }), 400
        
        # 2. Генерируем iptables команды
        iptables_rules = generate_iptables_commands_for_rule(rule)
        
        # 3. Генерируем маршруты (если нужно)
        routes = generate_routes_for_rule(rule)
        
        # 4. Сохраняем снимок конфигурации БЕЗ применения
        config_snapshot = {
            'iptables_rules': iptables_rules,
            'routes': routes,
            'target_nodes': [{'id': n.id, 'name': n.name, 'role': n.role} for n in nodes_to_apply],
            'saved_at': datetime.now(timezone.utc).isoformat(),
            'saved_by': current_user.id
        }
        
        # Обновляем статус на 'saved' (сохранено, но не применено)
        rule.status = 'saved'
        rule.configuration_snapshot = json.dumps(config_snapshot)
        rule.applied_by = None  # Еще не применено
        rule.applied_at = None
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Конфигурация сохранена',
            'target_nodes': [n['name'] for n in config_snapshot['target_nodes']],
            'config_preview': {
                'iptables_rules_count': len(iptables_rules),
                'routes_count': len(routes)
            }
        }), 200
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Save access policy rule error: {str(e)}")
        import traceback
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/access_policy/rules/<int:rule_id>/apply', methods=['POST'])
@login_required
@admin_required
def api_apply_access_policy_rule(rule_id):
    """
    Применение правила политики доступа на узлах через VPN
    
    Алгоритм:
    1. Определяем на каких узлах нужно применить правило
    2. Генерируем iptables команды и маршруты
    3. Отправляем через VPN с шифрованием
    4. Сохраняем снимок конфигурации
    5. Обновляем статус правила
    """
    try:
        rule = db.session.get(AccessPolicyRule, rule_id)
        if not rule:
            return jsonify({'success': False, 'error': 'Правило не найдено'}), 404
        
        if rule.status == 'applied':
            return jsonify({'success': False, 'error': 'Правило уже применено'}), 400
        
        # Если конфигурация уже сохранена, используем её
        use_saved_config = False
        if rule.status == 'saved' and rule.configuration_snapshot:
            try:
                saved_config = json.loads(rule.configuration_snapshot)
                if 'iptables_rules' in saved_config and 'routes' in saved_config:
                    use_saved_config = True
                    app.logger.info(f"Используем сохраненную конфигурацию для правила {rule_id}")
            except Exception as e:
                app.logger.warning(f"Ошибка чтения сохраненной конфигурации: {e}")
        
        # 1. Определяем узлы для применения правила
        nodes_to_apply = determine_nodes_for_rule(rule)
        
        if not nodes_to_apply:
            return jsonify({
                'success': False,
                'error': 'Не найдено узлов для применения правила'
            }), 400
        
        app.logger.info(f"Применение правила {rule_id} на {len(nodes_to_apply)} узлах")
        
        # 2. Генерируем маршруты ПЕРВЫМИ (если нужно)
        # КРИТИЧНО: Маршруты должны быть созданы ДО применения iptables правил
        if use_saved_config:
            routes = saved_config.get('routes', [])
        else:
            routes = generate_routes_for_rule(rule)
        
        # 3. Генерируем iptables команды (или используем сохраненные)
        if use_saved_config:
            iptables_rules = saved_config['iptables_rules']
        else:
            iptables_rules = generate_iptables_commands_for_rule(rule)
            
            if not iptables_rules:
                return jsonify({
                    'success': False,
                    'error': 'Не удалось сгенерировать iptables правила'
                }), 400
        
        # 4. Сортируем узлы по приоритету (Omnissiah первым)
        nodes_to_apply_sorted = sorted(nodes_to_apply, key=lambda n: (n.role != 'Omnissiah', n.id))
        
        # 5. Применяем на каждом узле
        applied_nodes = []
        errors = []
        
        for node in nodes_to_apply_sorted:
            node_errors = []
            
            # КРИТИЧНО: Сначала применяем маршруты, затем iptables правила
            # Маршрут должен быть создан ДО применения iptables правил
            if routes:
                try:
                    # Для Omnissiah применяем локально
                    if node.role == 'Omnissiah':
                        for route in routes:
                            if route.get('node') == 'Omnissiah':
                                cmd = ['sudo', '-n', 'ip', 'route', 'add', route['network'],
                                       'via', route['gateway'], 'dev', route['interface']]
                                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                                if result.returncode != 0 and 'File exists' not in result.stderr:
                                    node_errors.append(f"route {route['network']}: {result.stderr}")
                                else:
                                    app.logger.info(f"✅ Маршрут {route['network']} добавлен на Omnissiah")
                    else:
                        # Для других узлов отправляем через VPN
                        from omnissiah_core.nmc_vpn_config_sender import send_routes_via_vpn
                        success, error_msg = send_routes_via_vpn(
                            node,
                            routes,
                            action='add',
                            app=app,
                            check_connectivity=True  # Проверяем VPN перед отправкой
                        )
                        if not success:
                            node_errors.append(f"routes: {error_msg}")
                except Exception as e:
                    node_errors.append(f"routes: {str(e)}")
            
            # Применяем iptables правила ПОСЛЕ создания маршрутов
            if iptables_rules:
                try:
                    # Для Omnissiah применяем локально
                    if node.role == 'Omnissiah':
                        for cmd_parts in iptables_rules:
                            # КРИТИЧНО: Проверяем существование правила перед добавлением
                            # Извлекаем параметры для проверки (без -I/-A, позиции и комментария)
                            # ВАЖНО: Для -I нужно сохранить цепочку (INPUT/OUTPUT/FORWARD), но пропустить позицию
                            check_cmd_parts = []
                            i = 0
                            while i < len(cmd_parts):
                                part = cmd_parts[i]
                                
                                # Пропускаем -I/-A
                                if part in ['-I', '-A']:
                                    i += 1
                                    # Следующая часть - цепочка (INPUT/OUTPUT/FORWARD), сохраняем её
                                    if i < len(cmd_parts):
                                        check_cmd_parts.append(cmd_parts[i])
                                        i += 1
                                        # Если после цепочки идет цифра (позиция для -I), пропускаем её
                                        if i < len(cmd_parts) and cmd_parts[i].isdigit():
                                            i += 1
                                    continue
                                
                                # Пропускаем комментарий
                                if part == '--comment':
                                    i += 1  # Пропускаем значение комментария
                                    continue
                                
                                # Пропускаем -m comment
                                if part == '-m' and i + 1 < len(cmd_parts) and cmd_parts[i+1] == 'comment':
                                    i += 2  # Пропускаем -m и comment
                                    # После -m comment идет --comment и его значение
                                    if i < len(cmd_parts) and cmd_parts[i] == '--comment':
                                        i += 1  # Пропускаем --comment
                                        if i < len(cmd_parts):
                                            i += 1  # Пропускаем значение комментария
                                    continue
                                
                                # Все остальное добавляем
                                check_cmd_parts.append(part)
                                i += 1
                            
                            # Проверяем существование правила
                            check_cmd = ['sudo', '-n', 'iptables', '-C'] + check_cmd_parts
                            check_result = subprocess.run(check_cmd, capture_output=True, text=True, timeout=5)
                            
                            if check_result.returncode == 0:
                                # Правило уже существует, пропускаем
                                app.logger.debug(f"Правило уже существует, пропускаем: {' '.join(cmd_parts)}")
                                continue
                            
                            # Применяем правило
                            cmd = ['sudo', '-n', 'iptables'] + cmd_parts
                            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                            if result.returncode != 0:
                                # Игнорируем ошибку "уже существует"
                                if 'already exists' not in result.stderr.lower() and 'file exists' not in result.stderr.lower():
                                    node_errors.append(f"iptables: {result.stderr}")
                            else:
                                app.logger.info(f"✅ iptables правило применено на Omnissiah: {' '.join(cmd_parts)}")
                    else:
                        # Для других узлов отправляем через VPN
                        from omnissiah_core.nmc_vpn_config_sender import send_iptables_rules_via_vpn
                        success, error_msg = send_iptables_rules_via_vpn(
                            node,
                            iptables_rules,
                            action='add',
                            app=app,
                            check_connectivity=True  # Проверяем VPN перед отправкой
                        )
                        if not success:
                            node_errors.append(f"iptables: {error_msg}")
                except Exception as e:
                    node_errors.append(f"iptables: {str(e)}")
            
            if node_errors:
                errors.append(f"{node.name}: {', '.join(node_errors)}")
            else:
                applied_nodes.append({
                    'node_id': node.id,
                    'node_name': node.name,
                    'node_role': node.role
                })
        
        # 5. Сохраняем снимок конфигурации
        config_snapshot = {
            'iptables_rules': iptables_rules,
            'routes': routes,
            'applied_at': datetime.now(timezone.utc).isoformat()
        }
        
        # 6. Обновляем статус правила
        if applied_nodes:
            rule.status = 'applied'
            rule.applied_at = datetime.now(timezone.utc)
            rule.applied_by = current_user.id
            rule.applied_on_nodes = json.dumps(applied_nodes)
            rule.configuration_snapshot = json.dumps(config_snapshot)
        else:
            # Если не применено ни на одном узле
            app.logger.warning(f"Правило {rule_id} не применено ни на одном узле. Ошибки: {errors}")
            return jsonify({
                'success': False,
                'error': 'Не удалось применить правило ни на одном узле',
                'errors': errors
            }), 500
        
        db.session.commit()
        
        response = {
            'success': True,
            'message': f'Правило применено на {len(applied_nodes)} узлах',
            'applied_nodes': [n['node_name'] for n in applied_nodes]
        }
        
        if errors:
            response['warnings'] = errors
        
        return jsonify(response), 200
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Apply access policy rule error: {str(e)}")
        import traceback
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': str(e)}), 500


def determine_nodes_for_rule(rule):
    """
    Определяет на каких узлах нужно применить правило с учетом прямых связей
    
    Логика:
    - Если источник/назначение - защищенный объект на узле -> правило на этом узле
    - Если источник/назначение - узел -> правило на этом узле
    - Если узлы могут взаимодействовать напрямую -> правило на обоих узлах
    - Если узлы взаимодействуют через Omnissiah -> правило на обоих узлах и на Omnissiah
    - Всегда также на Omnissiah (главный сервер маршрутизирует трафик)
    
    Args:
        rule: AccessPolicyRule объект
    
    Returns:
        list: Список узлов General
    """
    nodes = set()
    
    # Получаем Omnissiah
    omnissiah = General.query.filter_by(role='Omnissiah').first()
    
    # Определяем узлы из источника
    source_node = None
    if rule.source_type == 'protected_object' and rule.source_id:
        obj = db.session.get(ProtectedObject, rule.source_id)
        if obj and obj.node:
            source_node = obj.node
            nodes.add(obj.node)
    elif rule.source_type == 'node' and rule.source_id:
        source_node = db.session.get(General, rule.source_id)
        if source_node:
            nodes.add(source_node)
    elif rule.source_type == 'network' and rule.source_network:
        # Если источник - сеть, проверяем все узлы, которые могут иметь IP в этой сети
        # Для правил с сетью как источником, правило применяется на узле назначения
        pass
    
    # Определяем узлы из назначения
    destination_node = None
    if rule.destination_type == 'protected_object' and rule.destination_id:
        obj = db.session.get(ProtectedObject, rule.destination_id)
        if obj and obj.node:
            destination_node = obj.node
            nodes.add(obj.node)
    elif rule.destination_type == 'node' and rule.destination_id:
        destination_node = db.session.get(General, rule.destination_id)
        if destination_node:
            nodes.add(destination_node)
    elif rule.destination_type == 'network' and rule.destination_network:
        # Если назначение - сеть, правило применяется на узле источника
        if source_node:
            nodes.add(source_node)
    
    # Если у нас есть оба узла (source и destination), определяем путь взаимодействия
    if source_node and destination_node:
        path_info = get_communication_path(source_node, destination_node)
        
        # Добавляем все узлы из пути
        for path_node in path_info['path']:
            nodes.add(path_node)
        
        # Если путь через Omnissiah, добавляем Omnissiah
        if path_info['via_omnissiah'] and omnissiah:
            nodes.add(omnissiah)
    
    # Если правило указывает на сеть без конкретного узла, но есть Omnissiah
    # применяем правило на Omnissiah (он маршрутизирует трафик)
    if not nodes and omnissiah:
        nodes.add(omnissiah)
    elif omnissiah and (source_node or destination_node):
        # Всегда добавляем Omnissiah если есть хотя бы один узел
        # (Omnissiah может быть промежуточным узлом)
        nodes.add(omnissiah)
    
    # Не фильтруем по статусу - применяем правила на всех найденных узлах
    # Статус может быть не установлен корректно, но правило должно применяться
    return list(nodes)


def generate_routes_for_rule(rule):
    """
    Генерирует маршруты для правила политики доступа с учетом прямых связей
    
    КРИТИЧНО: Маршрут создается ТОЛЬКО если есть защищенный объект или требуется маршрутизация.
    Маршрут позволяет трафику достичь защищенной подсети через VPN.
    iptables правила затем фильтруют трафик по протоколу/портам.
    
    Логика:
    - Если назначение - защищенный объект, создается маршрут на узле источника
    - Если путь взаимодействия через Omnissiah, маршрут создается на Omnissiah
    - Если путь прямой, маршрут создается на узле источника напрямую к узлу назначения
    - Маршрут: ip route add <network> via <gateway_vpn_ip> dev <vpn_interface>
    
    Args:
        rule: AccessPolicyRule объект
    
    Returns:
        list: Список маршрутов [{"network": "...", "gateway": "...", "interface": "...", "node": "..."}]
    """
    routes = []
    
    # Получаем узлы источника и назначения
    source_node = None
    destination_node = None
    
    if rule.source_type == 'protected_object' and rule.source_id:
        obj = db.session.get(ProtectedObject, rule.source_id)
        if obj and obj.node:
            source_node = obj.node
    elif rule.source_type == 'node' and rule.source_id:
        source_node = db.session.get(General, rule.source_id)
    
    if rule.destination_type == 'protected_object' and rule.destination_id:
        obj = db.session.get(ProtectedObject, rule.destination_id)
        if obj and obj.node:
            destination_node = obj.node
    elif rule.destination_type == 'node' and rule.destination_id:
        destination_node = db.session.get(General, rule.destination_id)
    
    # Если назначение - защищенный объект, добавляем маршрут
    if rule.destination_type == 'protected_object' and rule.destination_id:
        dest_obj = db.session.get(ProtectedObject, rule.destination_id)
        if dest_obj and dest_obj.node and dest_obj.network:
            protected_node = dest_obj.node
            
            if protected_node.ip_pool:
                protected_node_vpn_ip = protected_node.ip_pool.split('/')[0]
                
                # Определяем на каком узле создавать маршрут
                route_node = None
                route_interface = None
                
                if source_node:
                    # Определяем путь взаимодействия
                    path_info = get_communication_path(source_node, protected_node)
                    
                    if path_info['direct']:
                        # Прямой путь - маршрут на узле источника
                        route_node = source_node.name
                        route_interface = source_node.name
                        routes.append({
                            'network': dest_obj.network,
                            'gateway': protected_node_vpn_ip,
                            'interface': route_interface,
                            'node': route_node,
                            'comment': f'PolicyRule#{rule.id}: {dest_obj.network} (direct)'
                        })
                    elif path_info['via_omnissiah']:
                        # Через Omnissiah - маршрут на Omnissiah
                        omnissiah = General.query.filter_by(role='Omnissiah').first()
                        if omnissiah:
                            routes.append({
                                'network': dest_obj.network,
                                'gateway': protected_node_vpn_ip,
                                'interface': omnissiah.name,
                                'node': 'Omnissiah',
                                'comment': f'PolicyRule#{rule.id}: {dest_obj.network} (via Omnissiah)'
                            })
                else:
                    # Нет источника - маршрут на Omnissiah по умолчанию
                    omnissiah = General.query.filter_by(role='Omnissiah').first()
                    if omnissiah:
                        routes.append({
                            'network': dest_obj.network,
                            'gateway': protected_node_vpn_ip,
                            'interface': omnissiah.name,
                            'node': 'Omnissiah',
                            'comment': f'PolicyRule#{rule.id}: {dest_obj.network}'
                        })
    
    # Если источник - защищенный объект, добавляем маршрут на узле назначения
    if rule.source_type == 'protected_object' and rule.source_id:
        source_obj = db.session.get(ProtectedObject, rule.source_id)
        if source_obj and source_obj.node and source_obj.network:
            if rule.destination_type == 'node' and rule.destination_id:
                dest_node = db.session.get(General, rule.destination_id)
                if dest_node and dest_node.role in ['Magos', 'Cognitor']:
                    source_node_vpn_ip = source_obj.node.ip_pool.split('/')[0] if source_obj.node.ip_pool else None
                    if source_node_vpn_ip:
                        # Определяем путь взаимодействия
                        path_info = get_communication_path(source_obj.node, dest_node)
                        
                        if path_info['direct']:
                            # Прямой путь - маршрут на узле назначения
                            routes.append({
                                'network': source_obj.network,
                                'gateway': source_node_vpn_ip,
                                'interface': dest_node.name,
                                'node': dest_node.name,
                                'comment': f'PolicyRule#{rule.id}: {source_obj.network} (direct)'
                            })
                        elif path_info['via_omnissiah']:
                            # Через Omnissiah - маршрут на Omnissiah
                            omnissiah = General.query.filter_by(role='Omnissiah').first()
                            if omnissiah:
                                routes.append({
                                    'network': source_obj.network,
                                    'gateway': source_node_vpn_ip,
                                    'interface': omnissiah.name,
                                    'node': 'Omnissiah',
                                    'comment': f'PolicyRule#{rule.id}: {source_obj.network} (via Omnissiah)'
                                })
    
    return routes


@app.route('/api/access_policy/cleanup_orphaned', methods=['POST'])
@login_required
@admin_required
def api_cleanup_orphaned_rules():
    """
    Удаляет остатки правил политики доступа с узлов
    Позволяет указать параметры правила (источник, назначение, протокол, порт) для поиска и удаления
    """
    try:
        data = request.get_json() or {}
        node_id = data.get('node_id')  # Опционально: конкретный узел, иначе все узлы
        source = data.get('source')  # Сеть источника
        destination = data.get('destination')  # Сеть назначения
        protocol = data.get('protocol', 'tcp')  # Протокол
        ports = data.get('ports')  # Порты (через запятую или диапазон)
        
        if not all([source, destination]):
            return jsonify({
                'success': False,
                'error': 'Необходимо указать source и destination для поиска правил'
            }), 400
        
        errors = []
        removed_count = 0
        
        # Определяем список узлов для обработки
        nodes_to_process = []
        if node_id:
            node = db.session.get(General, node_id)
            if node:
                nodes_to_process = [node]
            else:
                return jsonify({'success': False, 'error': 'Узел не найден'}), 404
        else:
            # Обрабатываем все узлы (Omnissiah + активные Magos/Cognitor)
            nodes_to_process = General.query.filter(
                General.role.in_(['Omnissiah', 'Magos', 'Cognitor']),
                General.status.in_(['active', 'online'])
            ).all()
        
        for node in nodes_to_process:
            try:
                # Генерируем команды для поиска и удаления
                iptables_rules = generate_cleanup_commands(source, destination, protocol, ports)
                
                if node.role == 'Omnissiah':
                    # Локальное удаление
                    for cmd_parts in iptables_rules:
                        # Используем -D для удаления
                        delete_cmd = ['-D'] + cmd_parts[1:] if cmd_parts[0] == '-A' else ['-D'] + cmd_parts
                        
                        # Пробуем удалить правило
                        result = subprocess.run(
                            ['sudo', '-n', 'iptables'] + delete_cmd,
                            capture_output=True,
                            text=True,
                            timeout=10,
                            check=False
                        )
                        
                        if result.returncode == 0:
                            removed_count += 1
                            app.logger.info(f"Удалено правило на {node.name}: {' '.join(delete_cmd)}")
                        else:
                            # Пробуем найти правило через iptables-save и удалить по номеру
                            removed = try_remove_by_matching(node, source, destination, protocol, ports)
                            if removed:
                                removed_count += removed
                
                elif node.role in ['Magos', 'Cognitor']:
                    # Удаление через SSH
                    # Запрашиваем SSH параметры
                    ssh_ip = node.endpoint or node.heartbeat_ip
                    if not ssh_ip:
                        errors.append(f"Не указан SSH IP для узла {node.name}")
                        continue
                    
                    # Используем дефолтные параметры или из запроса
                    ssh_user = data.get('ssh_user', 'root')
                    ssh_password = data.get('ssh_password')
                    sudo_password = data.get('sudo_password')
                    
                    if not ssh_password:
                        errors.append(f"Не указан SSH пароль для узла {node.name}")
                        continue
                    
                    try:
                        import paramiko
                        ssh = paramiko.SSHClient()
                        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        ssh.connect(ssh_ip, username=ssh_user, password=ssh_password, timeout=10)
                        
                        for cmd_parts in iptables_rules:
                            delete_cmd = ['-D'] + cmd_parts[1:] if cmd_parts[0] == '-A' else ['-D'] + cmd_parts
                            
                            full_cmd = 'iptables ' + ' '.join(delete_cmd)
                            if sudo_password:
                                full_cmd = f"echo '{sudo_password}' | sudo -S {full_cmd}"
                            else:
                                full_cmd = f"sudo -n {full_cmd}"
                            
                            stdin, stdout, stderr = ssh.exec_command(full_cmd, timeout=10)
                            stdout.read()
                            exit_status = stdout.channel.recv_exit_status()
                            
                            if exit_status == 0:
                                removed_count += 1
                                app.logger.info(f"Удалено правило на {node.name}: {' '.join(delete_cmd)}")
                        
                        ssh.close()
                    except ImportError:
                        errors.append(f"Библиотека paramiko не установлена")
                    except Exception as e:
                        errors.append(f"Ошибка SSH подключения к {node.name}: {str(e)}")
            
            except Exception as e:
                errors.append(f"Ошибка обработки узла {node.name}: {str(e)}")
        
        return jsonify({
            'success': True,
            'message': f'Удалено правил: {removed_count}',
            'removed_count': removed_count,
            'errors': errors if errors else None
        }), 200
        
    except Exception as e:
        app.logger.error(f"Cleanup orphaned rules error: {str(e)}")
        import traceback
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': str(e)}), 500


def generate_cleanup_commands(source, destination, protocol, ports):
    """Генерирует команды iptables для удаления правил по параметрам"""
    commands = []
    
    # Базовая команда для FORWARD цепочки
    cmd = ['-A', 'FORWARD']
    
    if source and source != 'any':
        cmd.extend(['-s', source])
    
    if destination and destination != 'any':
        cmd.extend(['-d', destination])
    
    if protocol and protocol != 'any':
        cmd.extend(['-p', protocol])
    
    if ports and protocol in ['tcp', 'udp']:
        if ',' in ports:
            # Несколько портов
            for port in ports.split(','):
                port = port.strip()
                if port:
                    port_cmd = cmd + ['--dport', port, '-j', 'ACCEPT']
                    commands.append(port_cmd)
        else:
            # Один порт или диапазон
            cmd.extend(['--dport', ports, '-j', 'ACCEPT'])
            commands.append(cmd)
    else:
        # Без портов
        cmd.extend(['-j', 'ACCEPT'])
        commands.append(cmd)
    
    return commands


def try_remove_by_matching(node, source, destination, protocol, ports):
    """
    Пытается найти и удалить правило по совпадению параметров через iptables-save
    Возвращает количество удаленных правил
    """
    try:
        # Получаем текущие правила
        result = subprocess.run(
            ['sudo', '-n', 'iptables-save'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode != 0:
            return 0
        
        removed = 0
        lines = result.stdout.strip().splitlines()
        
        for i, line in enumerate(lines):
            if not line.startswith('-A FORWARD'):
                continue
            
            # Проверяем, соответствует ли правило нашим параметрам
            matches = True
            
            if source and source != 'any':
                if f' -s {source} ' not in line and f' -s {source}' not in line:
                    matches = False
            
            if destination and destination != 'any':
                if f' -d {destination} ' not in line and f' -d {destination}' not in line:
                    matches = False
            
            if protocol and protocol != 'any':
                if f' -p {protocol} ' not in line:
                    matches = False
            
            if ports and protocol in ['tcp', 'udp']:
                if f' --dport {ports} ' not in line and f' --dport {ports}' not in line:
                    matches = False
            
            if matches and ' -j ACCEPT' in line:
                # Извлекаем номер правила из вывода iptables -L --line-numbers
                # Для этого используем другой подход - удаляем через точное совпадение
                cmd_parts = line.replace('-A', '-D').split()
                result_del = subprocess.run(
                    ['sudo', '-n', 'iptables'] + cmd_parts,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False
                )
                
                if result_del.returncode == 0:
                    removed += 1
                    app.logger.info(f"Удалено правило на {node.name} по совпадению: {line}")
        
        return removed
    
    except Exception as e:
        app.logger.warning(f"Ошибка поиска правил по совпадению: {str(e)}")
        return 0


@app.route('/api/access_policy/rules/list', methods=['GET'])
@login_required
@admin_required
def api_list_iptables_rules():
    """
    Просмотр текущих iptables правил на узле
    Полезно для диагностики оставшихся правил
    """
    try:
        node_id = request.args.get('node_id')
        chain = request.args.get('chain', 'FORWARD')
        
        if not node_id:
            return jsonify({'success': False, 'error': 'Не указан node_id'}), 400
        
        node = db.session.get(General, node_id)
        if not node:
            return jsonify({'success': False, 'error': 'Узел не найден'}), 404
        
        rules_output = None
        
        if node.role == 'Omnissiah':
            # Локальный просмотр
            result = subprocess.run(
                ['sudo', '-n', 'iptables', '-L', chain, '-n', '-v', '--line-numbers'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                rules_output = result.stdout
            else:
                return jsonify({
                    'success': False,
                    'error': f'Ошибка выполнения iptables: {result.stderr}'
                }), 500
        
        elif node.role in ['Magos', 'Cognitor']:
            # Через SSH
            ssh_ip = request.args.get('ssh_ip') or node.endpoint or node.heartbeat_ip
            ssh_user = request.args.get('ssh_user', 'root')
            ssh_password = request.args.get('ssh_password')
            sudo_password = request.args.get('sudo_password')
            
            if not ssh_ip:
                return jsonify({'success': False, 'error': 'Не указан SSH IP'}), 400
            
            if not ssh_password:
                return jsonify({'success': False, 'error': 'Не указан SSH пароль'}), 400
            
            try:
                import paramiko
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ssh_ip, username=ssh_user, password=ssh_password, timeout=10)
                
                cmd = f'iptables -L {chain} -n -v --line-numbers'
                if sudo_password:
                    cmd = f"echo '{sudo_password}' | sudo -S {cmd}"
                else:
                    cmd = f"sudo -n {cmd}"
                
                stdin, stdout, stderr = ssh.exec_command(cmd, timeout=10)
                rules_output = stdout.read().decode()
                stderr_output = stderr.read().decode()
                exit_status = stdout.channel.recv_exit_status()
                
                ssh.close()
                
                if exit_status != 0:
                    return jsonify({
                        'success': False,
                        'error': f'Ошибка выполнения iptables: {stderr_output}'
                    }), 500
            
            except ImportError:
                return jsonify({'success': False, 'error': 'Библиотека paramiko не установлена'}), 500
            except Exception as e:
                return jsonify({'success': False, 'error': f'Ошибка SSH: {str(e)}'}), 500
        
        return jsonify({
            'success': True,
            'node': node.name,
            'chain': chain,
            'rules': rules_output
        }), 200
        
    except Exception as e:
        app.logger.error(f"List iptables rules error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/access_policy/apply_all', methods=['POST'])
@login_required
@admin_required
def api_apply_all_access_policy_rules():
    """Применение всех правил со статусом pending"""
    try:
        pending_rules = AccessPolicyRule.query.filter_by(status='pending').all()
        
        applied_count = 0
        errors = []
        
        for rule in pending_rules:
            try:
                # Используем ту же логику что и для одного правила
                # Определяем узлы
                nodes_to_apply = determine_nodes_for_rule(rule)
                if not nodes_to_apply:
                    errors.append(f"Правило {rule.id}: не найдено узлов")
                    continue
                
                # Генерируем команды
                iptables_rules = generate_iptables_commands_for_rule(rule)
                if not iptables_rules:
                    errors.append(f"Правило {rule.id}: не удалось сгенерировать команды")
                    continue
                
                routes = generate_routes_for_rule(rule)
                
                # Применяем на узлах
                applied_nodes = []
                for node in nodes_to_apply:
                    node_errors = []
                    
                    # iptables
                    try:
                        from omnissiah_core.nmc_vpn_config_sender import send_iptables_rules_via_vpn
                        success, error_msg = send_iptables_rules_via_vpn(
                            node, iptables_rules, action='add', app=app,
                            check_connectivity=True  # Проверяем VPN перед отправкой
                        )
                        if not success:
                            node_errors.append(f"iptables: {error_msg}")
                    except Exception as e:
                        node_errors.append(f"iptables: {str(e)}")
                    
                    # routes
                    if routes:
                        try:
                            from omnissiah_core.nmc_vpn_config_sender import send_routes_via_vpn
                            success, error_msg = send_routes_via_vpn(
                                node, routes, action='add', app=app,
                                check_connectivity=True  # Проверяем VPN перед отправкой
                            )
                            if not success:
                                node_errors.append(f"routes: {error_msg}")
                        except Exception as e:
                            node_errors.append(f"routes: {str(e)}")
                    
                    if not node_errors:
                        applied_nodes.append({
                            'node_id': node.id,
                            'node_name': node.name,
                            'node_role': node.role
                        })
                    else:
                        errors.append(f"Правило {rule.id} на {node.name}: {', '.join(node_errors)}")
                
                if applied_nodes:
                    # Сохраняем снимок
                    config_snapshot = {
                        'iptables_rules': iptables_rules,
                        'routes': routes,
                        'applied_at': datetime.now(timezone.utc).isoformat()
                    }
                    
                    rule.status = 'applied'
                    rule.applied_at = datetime.now(timezone.utc)
                    rule.applied_by = current_user.id
                    rule.applied_on_nodes = json.dumps(applied_nodes)
                    rule.configuration_snapshot = json.dumps(config_snapshot)
                    applied_count += 1
                else:
                    errors.append(f"Правило {rule.id}: не применено ни на одном узле")
            
            except Exception as e:
                errors.append(f"Ошибка применения правила {rule.id}: {str(e)}")
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'applied': applied_count,
            'errors': errors if errors else None,
            'message': f'Применено правил: {applied_count}'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Apply all access policy rules error: {str(e)}")
        import traceback
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/access_policy/reapply_all', methods=['POST'])
@login_required
@admin_required
def api_reapply_all_access_policy_rules():
    """
    Переприменение ВСЕХ правил безопасности, включая системные правила.
    Для Omnissiah применяет правила локально, для Magos/Cognitor - через VPN.
    """
    try:
        # Получаем ВСЕ правила, включая системные и уже примененные
        # КРИТИЧНО: Сортируем правила так, чтобы DROP/REJECT применялись ПЕРЕД ACCEPT
        # Сначала применяем правила с действием DROP/REJECT (по приоритету, меньший = выше приоритет)
        # Затем применяем правила с действием ACCEPT (по приоритету)
        all_rules = AccessPolicyRule.query.filter(
            AccessPolicyRule.status.in_(['pending', 'saved', 'applied'])
        ).all()
        
        # Сортируем: сначала DROP/REJECT (по приоритету), потом ACCEPT (по приоритету)
        def sort_key(rule):
            action = getattr(rule, 'action', 'ACCEPT') if hasattr(rule, 'action') and rule.action else 'ACCEPT'
            priority = rule.priority if rule.priority is not None else 100
            # Для DROP/REJECT: меньший приоритет = выше приоритет (применяем раньше)
            # Для ACCEPT: меньший приоритет = выше приоритет
            # DROP/REJECT должны быть в начале (0), ACCEPT в конце (1)
            action_order = 0 if action in ['DROP', 'REJECT'] else 1
            return (action_order, priority, rule.created_at)
        
        all_rules = sorted(all_rules, key=sort_key)
        
        if not all_rules:
            return jsonify({
                'success': False,
                'error': 'Нет правил для применения'
            }), 400
        
        applied_count = 0
        errors = []
        omnissiah = General.query.filter_by(role='Omnissiah').first()
        
        for rule in all_rules:
            try:
                app.logger.info(f"Переприменение правила {rule.id} ({rule.description or 'без описания'})")
                
                # Определяем узлы для применения правила
                nodes_to_apply = determine_nodes_for_rule(rule)
                if not nodes_to_apply:
                    errors.append(f"Правило {rule.id}: не найдено узлов")
                    continue
                
                # Генерируем команды
                iptables_rules = generate_iptables_commands_for_rule(rule)
                if not iptables_rules:
                    errors.append(f"Правило {rule.id}: не удалось сгенерировать команды")
                    continue
                
                routes = generate_routes_for_rule(rule)
                
                # Применяем на узлах
                applied_nodes = []
                for node in nodes_to_apply:
                    node_errors = []
                    
                    # Для Omnissiah применяем локально
                    if node.role == 'Omnissiah' and omnissiah and node.id == omnissiah.id:
                        try:
                            # Применяем iptables правила локально
                            for cmd_list in iptables_rules:
                                try:
                                    if isinstance(cmd_list, list):
                                        full_cmd = ['iptables'] + cmd_list
                                        result = subprocess.run(
                                            ['sudo', '-n'] + full_cmd,
                                            check=True,
                                            timeout=5,
                                            capture_output=True,
                                            text=True
                                        )
                                        app.logger.debug(f"Применено правило локально: {' '.join(full_cmd)}")
                                except subprocess.CalledProcessError as e:
                                    node_errors.append(f"iptables команда: {e.stderr}")
                            
                            # Применяем маршруты локально
                            if routes:
                                for route in routes:
                                    try:
                                        cmd = ['ip', 'route', 'add', route['network']]
                                        if route.get('gateway'):
                                            cmd.extend(['via', route['gateway']])
                                        cmd.extend(['dev', route['interface']])
                                        
                                        result = subprocess.run(
                                            ['sudo', '-n'] + cmd,
                                            check=False,  # Не проверяем, маршрут может уже существовать
                                            timeout=5,
                                            capture_output=True,
                                            text=True
                                        )
                                        if result.returncode != 0 and 'File exists' not in result.stderr:
                                            app.logger.warning(f"Не удалось добавить маршрут: {result.stderr}")
                                    except Exception as e:
                                        app.logger.warning(f"Ошибка добавления маршрута: {e}")
                            
                            if not node_errors:
                                applied_nodes.append({
                                    'node_id': node.id,
                                    'node_name': node.name,
                                    'node_role': node.role
                                })
                            else:
                                errors.append(f"Правило {rule.id} на {node.name} (локально): {', '.join(node_errors)}")
                        
                        except Exception as e:
                            errors.append(f"Правило {rule.id} на {node.name} (локально): {str(e)}")
                    
                    else:
                        # Для Magos/Cognitor применяем через VPN
                        try:
                            # iptables
                            try:
                                from omnissiah_core.nmc_vpn_config_sender import send_iptables_rules_via_vpn
                                success, error_msg = send_iptables_rules_via_vpn(
                                    node, iptables_rules, action='add', app=app,
                                    check_connectivity=True
                                )
                                if not success:
                                    node_errors.append(f"iptables: {error_msg}")
                            except Exception as e:
                                node_errors.append(f"iptables: {str(e)}")
                            
                            # routes
                            if routes:
                                try:
                                    from omnissiah_core.nmc_vpn_config_sender import send_routes_via_vpn
                                    success, error_msg = send_routes_via_vpn(
                                        node, routes, action='add', app=app,
                                        check_connectivity=True
                                    )
                                    if not success:
                                        node_errors.append(f"routes: {error_msg}")
                                except Exception as e:
                                    node_errors.append(f"routes: {str(e)}")
                            
                            if not node_errors:
                                applied_nodes.append({
                                    'node_id': node.id,
                                    'node_name': node.name,
                                    'node_role': node.role
                                })
                            else:
                                errors.append(f"Правило {rule.id} на {node.name}: {', '.join(node_errors)}")
                        
                        except Exception as e:
                            errors.append(f"Правило {rule.id} на {node.name}: {str(e)}")
                
                if applied_nodes:
                    # Обновляем статус правила
                    config_snapshot = {
                        'iptables_rules': iptables_rules,
                        'routes': routes,
                        'applied_at': datetime.now(timezone.utc).isoformat(),
                        'reapplied': True
                    }
                    
                    rule.status = 'applied'
                    rule.applied_at = datetime.now(timezone.utc)
                    rule.applied_by = current_user.id
                    rule.applied_on_nodes = json.dumps(applied_nodes)
                    rule.configuration_snapshot = json.dumps(config_snapshot)
                    applied_count += 1
                    app.logger.info(f"Правило {rule.id} успешно переприменено на {len(applied_nodes)} узлах")
                else:
                    errors.append(f"Правило {rule.id}: не применено ни на одном узле")
            
            except Exception as e:
                error_msg = f"Ошибка переприменения правила {rule.id}: {str(e)}"
                errors.append(error_msg)
                app.logger.error(error_msg)
                import traceback
                app.logger.error(traceback.format_exc())
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'applied': applied_count,
            'total': len(all_rules),
            'errors': errors if errors else None,
            'message': f'Переприменено правил: {applied_count} из {len(all_rules)}'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Reapply all access policy rules error: {str(e)}")
        import traceback
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/ssh/check_mtls', methods=['GET'])
@login_required
@admin_required
def api_ssh_check_mtls():
    """
    Проверка установления mTLS связи с Magos агентом
    """
    try:
        node_id = request.args.get('node_id')
        if not node_id:
            return jsonify({'success': False, 'error': 'Missing node_id'}), 400
        
        node = db.session.get(General, node_id)
        if not node or node.role not in ['Magos', 'Cognitor']:
            return jsonify({'success': False, 'error': 'Invalid node. SSH deployment only for Magos and Cognitor'}), 400
        
        # Для Magos проверяем heartbeat, для Cognitor проверяем через VPN handshake
        if node.role == 'Magos':
            # Проверяем наличие heartbeat с mTLS для Magos
            if node.last_heartbeat:
                time_since = (datetime.now(timezone.utc) - 
                             (node.last_heartbeat.replace(tzinfo=timezone.utc) if node.last_heartbeat.tzinfo is None else node.last_heartbeat))
                if time_since.total_seconds() < 90:
                    return jsonify({
                        'success': True,
                        'connected': True,
                        'message': 'mTLS connection established'
                    }), 200
        elif node.role == 'Cognitor':
            # Для Cognitor проверяем VPN handshake (подключение через Magos или Omnissiah)
            if node.last_handshake:
                time_since = (datetime.now(timezone.utc) - 
                             (node.last_handshake.replace(tzinfo=timezone.utc) if node.last_handshake.tzinfo is None else node.last_handshake))
                if time_since.total_seconds() < 180:
                    return jsonify({
                        'success': True,
                        'connected': True,
                        'message': 'VPN connection established'
                    }), 200
        
        return jsonify({
            'success': True,
            'connected': False,
            'message': 'Waiting for connection...'
        }), 200
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/add_user', methods=['POST'])
@login_required
@admin_required
def add_user():
    username = request.form.get('username') or request.form.get('email')  # Поддержка старого формата
    password = request.form.get('password')
    role = request.form.get('role', 'user')

    if not username or not password:
        flash('Заполните все обязательные поля', 'danger')
        return redirect(url_for('profile'))

    if BaseUser.query.filter_by(email=username).first():
        flash('Пользователь с таким логином уже существует', 'danger')
        return redirect(url_for('profile'))

    new_user = BaseUser(
        email=username,  # Используем поле email для хранения логина
        password_hash=generate_password_hash(password),
        role=role
    )

    try:
        db.session.add(new_user)
        db.session.commit()
        flash(f'Пользователь {username} успешно создан', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка при создании пользователя: {str(e)}', 'danger')

    return redirect(url_for('profile'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        omnissiah_config = General.query.filter_by(role='Omnissiah').first()
        if omnissiah_config:
            return redirect(url_for('dashboard'))
        else:
            return redirect(url_for('setup_wizard'))

    if request.method == 'POST':
        username = request.form.get('username').strip()
        session['email'] = username  # Сохраняем для совместимости, но используем как логин
        password = request.form.get('password')

        user = BaseUser.query.filter_by(email=username).first()

        if not user or not check_password_hash(user.password_hash, password):
            flash('Неверные учетные данные', 'danger')
            return redirect(url_for('login'))

        login_user(user, remember=True)
        flash('Успешный вход в систему', 'success')

        # 🔥 Добавляем ту же логику после логина:
        omnissiah_config = General.query.filter_by(role='Omnissiah').first()
        if omnissiah_config:
            return redirect(url_for('dashboard'))
        else:
            return redirect(url_for('setup_wizard'))

    return render_template('login.html')


@app.route('/update_config', methods=['GET', 'POST'])
@login_required
@admin_required
def update_config():
    config = General.query.first()
    if not config:
        flash('Конфигурация не найдена', 'danger')
        omnissiah_config = General.query.filter_by(role='Omnissiah').first()
        if omnissiah_config:
            return redirect(url_for('dashboard'))
        else:
            return redirect(url_for('dashboard'))

    # Создаем форму и передаем текущие значения
    form = ServerConfigForm(obj=config)

    # Убедимся, что поле ip_pool существует в форме
    if not hasattr(form, 'ip_pool'):
        form.ip_pool = StringField('IP-пул', validators=[DataRequired()])

    if form.validate_on_submit():
        try:
            old_name = config.name
            old_ip_pool = config.ip_pool
            old_port = config.listen_port

            # Вручную обновляем поля, которые не обрабатываются populate_obj
            config.name = form.name.data
            config.ip_pool = form.ip_pool.data
            config.listen_port = form.port.data
            config.dns = form.dns.data
            config.mtu = form.mtu.data
            config.endpoint = form.endpoint.data

            # Обработка общего ключа
            if 'use_preshared_key' in request.form and request.form['use_preshared_key'] == 'on':
                if not config.preshared_key:
                    config.preshared_key = subprocess.check_output(
                        ["sudo", "-n", "wg", "genpsk"], text=True).strip()
            else:
                config.preshared_key = None

            db.session.commit()

            # Обновляем конфигурационный файл
            if not update_wg_config_file(config):
                flash('Ошибка обновления файла конфигурации', 'danger')
                omnissiah_config = General.query.filter_by(role='Omnissiah').first()
                if omnissiah_config:
                    return redirect(url_for('dashboard'))
                else:
                    return redirect(url_for('dashboard'))

            # Если изменилось имя, переименовываем файл
            if old_name != config.name:
                old_path = Path(app.config['WG_CONFIG_PATH']) / f"{old_name}.conf"
                new_path = Path(app.config['WG_CONFIG_PATH']) / f"{config.name}.conf"
                try:
                    subprocess.run(['sudo', '-n', 'mv', str(old_path), str(new_path)], check=True)
                except subprocess.CalledProcessError as e:
                    flash(f'Ошибка переименования файла: {e.stderr.decode()}', 'danger')
                    omnissiah_config = General.query.filter_by(role='Omnissiah').first()
                    if omnissiah_config:
                        return redirect(url_for('dashboard'))
                    else:
                        return redirect(url_for('dashboard'))

            # Определяем, нужно ли перезапускать интерфейс
            need_restart = False
            if config.status == 'active':
                need_restart = (old_name != config.name or
                                old_ip_pool != config.ip_pool or
                                old_port != config.listen_port)

                if need_restart:
                    try:
                        subprocess.run(['sudo', '-n', 'wg-quick', 'down',
                                        old_name if old_name != config.name else config.name],
                                       check=True)
                        subprocess.run(['sudo', 'n', 'wg-quick', 'up', config.name], check=True)
                    except subprocess.CalledProcessError as e:
                        flash(f'Ошибка перезапуска интерфейса: {e.stderr.decode()}', 'warning')

            flash('Конфигурация успешно обновлена', 'success')
            omnissiah_config = General.query.filter_by(role='Omnissiah').first()
            if omnissiah_config:
                return redirect(url_for('dashboard'))
            else:
                return redirect(url_for('dashboard'))


        except subprocess.CalledProcessError as e:
            db.session.rollback()
            flash(f'Ошибка выполнения команды2: {e.stderr.decode()}', 'danger')
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка обновления: {str(e)}', 'danger')

    return render_template('update_config.html',
                           form=form,
                           config=config,
                           STATUS_CHOICES=STATUS_CHOICES)


@app.route('/verify_password', methods=['POST'])
@login_required
def verify_password():
    data = request.get_json()
    if not data or 'password' not in data:
        return jsonify({'valid': False}), 400

    if check_password_hash(current_user.password_hash, data['password']):
        return jsonify({'valid': True})
    return jsonify({'valid': False})


@app.route('/delete_config/<config_name>', methods=['POST'])
@login_required
@admin_required
def delete_config(config_name):
    try:
        config = General.query.filter_by(name=config_name).first_or_404()
        is_omnissiah_config = config.role == 'Omnissiah'

        # 1. Останавливаем активную конфигурацию
        if config.status == 'active':
            subprocess.run(
                ["sudo", "-n", "/usr/bin/wg-quick", "down", config_name],
                check=True
            )

        # 2. Получаем связанные узлы (Cognitor и Magos)
        peers = General.query.filter(
            (General.parent_id == config.id) |
            ((General.role == 'Cognitor') if is_omnissiah_config else False)
        ).all()

        for peer in peers:
            if peer.role == 'Cognitor' and peer.parent_id:
                parent = General.query.get(peer.parent_id)
                if parent:
                    # Удаляем пира из конфигурации родителя
                    subprocess.run(
                        ["sudo", "-n", "/usr/bin/wg", "set", parent.name, "peer", peer.public_key, "remove"],
                        check=True
                    )
                    subprocess.run(
                        ["sudo", "-n", "/usr/bin/wg-quick", "save", parent.name],
                        check=True
                    )
            db.session.delete(peer)

        # 3. Удаляем .conf файл
        config_path = Path(app.config['WG_CONFIG_PATH']) / f"{config_name}.conf"
        if config_path.exists():
            config_path.unlink()

        # 4. Удаляем саму конфигурацию
        db.session.delete(config)
        db.session.commit()

        # 5. Возвращаем корректный маршрут для редиректа в UI
        redirect_url = url_for('setup_wizard') if is_omnissiah_config else url_for('dashboard')
        return jsonify({'success': True, 'redirect': redirect_url})

    except subprocess.CalledProcessError as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f"Ошибка команды: {e.stderr.decode() if e.stderr else str(e)}"
        }), 500
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f"Ошибка: {str(e)}"
        }), 500


@app.route('/peer/<int:peer_id>')
@login_required
def peer_details(peer_id):
    peer = db.session.get(General, peer_id)
    if not peer:
        abort(404)

    parent = db.session.get(General, peer.parent_id) if peer.parent_id else None
    child_peers = []

    if peer.role != 'Cognitor':
        omnissiah_config = General.query.filter_by(role='Omnissiah').first()
        if omnissiah_config:
            return redirect(url_for('dashboard'))
        else:
            return redirect(url_for('dashboard'))

    # Get additional connections
    connections = peer.get_connected_nodes()

    return render_template(
        'peer_details.html',
        peer=peer,
        parent=parent,
        child_peers=child_peers,
        connections=connections,
        STATUS_CHOICES=STATUS_CHOICES
    )

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/qr_code/<config_name>')
@login_required
def qr_code(config_name):
    try:
        UserModel = dynamic_user_models.get(config_name)
        InfoModel = dynamic_info_models.get(config_name)
        base_user = db.session.execute(
            select(BaseUser).filter_by(email=session['email'])
        ).scalar_one_or_none()

        if not UserModel or not InfoModel:
            abort(404)

        config = db.session.execute(
            select(UserModel).filter_by(base_user_id=base_user.id)
        ).scalar_one_or_none()

        info = db.session.execute(
            select(InfoModel)
        ).scalar_one_or_none()

        if not config or not info:
            abort(404)

        # Генерация контента из БД
        private_key = get_cipher_suite().decrypt(config.private_key.encode()).decode()

        config_content = f"""[Interface]
PrivateKey = {private_key}
Address = {config.allowed_ip}
DNS = {config.dns or app.config['WG_DEFAULT_DNS']}

[Peer]
PublicKey = {info.public_key}
AllowedIPs = {config.endpoint_allowed_ip}
Endpoint = {info.real_endpoint}:{info.listen_port}
PersistentKeepalive = {KEEPALIVE}"""

        qr = qrcode.make(config_content)
        img_io = BytesIO()
        qr.save(img_io, 'PNG')
        img_io.seek(0)

        return send_file(img_io, mimetype='image/png')

    except Exception as e:
        app.logger.error(f"QR Error: {str(e)}")
        abort(500)


@app.route('/activate_config/<config_name>', methods=['POST'])
@login_required
def activate_config(config_name):
    try:
        base_user = BaseUser.query.filter_by(email=session['email']).first()
        UserModel = dynamic_user_models[config_name]

        # Получаем IP-пул из формы (если есть) или используем дефолтный
        ip_pool = request.form.get('ip_pool', app.config['WG_IP_POOL'])

        if db.session.execute(
                select(UserModel).filter_by(base_user_id=base_user.id)
        ).scalar_one_or_none():
            flash("Конфигурация уже активна", "warning")
            return redirect(url_for('profile'))

        private_key, public_key = generate_wg_keys()
        allowed_ip = get_next_available_ip(config_name, ip_pool)

        if not allowed_ip:
            flash("Нет свободных IP-адресов", "danger")
            return redirect(url_for('profile'))

        # Добавляем пир в интерфейс
        cmd = [
            "sudo", "-n", "wg", "set", config_name,
            "peer", public_key,
            "allowed-ips", allowed_ip.split('/')[0]
        ]

        subprocess.run(cmd, check=True)
        subprocess.run(["sudo", "-n", "wg-quick", "save", config_name], check=True)

        # Сохраняем в БД
        new_config = UserModel(
            base_user_id=base_user.id,
            user_email=base_user.email,
            public_key=public_key,
            private_key=get_cipher_suite().encrypt(private_key.encode()).decode(),
            allowed_ip=allowed_ip,
            status='active',
            dns=app.config['WG_DEFAULT_DNS'],
            endpoint_allowed_ip=app.config['WG_DEFAULT_ALLOWED_IPS']
        )

        db.session.add(new_config)
        db.session.commit()
        flash("Конфигурация успешно активирована!", "success")

    except subprocess.CalledProcessError as e:
        db.session.rollback()
        flash(f"Ошибка WireGuard: {e.stderr}", "danger")
    except Exception as e:
        db.session.rollback()
        flash(f"Ошибка активации: {str(e)}", "danger")

    return redirect(url_for('profile'))


# 4. Маршрут для удаления аккаунта
@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    if current_user.email == 'Adeptus':
        flash('Нельзя удалить системный аккаунт по умолчанию', 'danger')
        return redirect(url_for('profile'))

    if not check_password_hash(current_user.password_hash, request.form['password']):
        flash('Неверный пароль', 'danger')
        return redirect(url_for('profile'))

    try:
        # Удаление всех конфигураций пользователя
        for config_name in configurations:
            UserModel = dynamic_user_models.get(config_name)
            if UserModel:
                user_configs = UserModel.query.filter_by(base_user_id=current_user.id).all()
                for config in user_configs:
                    db.session.delete(config)

        # Удаление самого пользователя
        db.session.delete(current_user)
        db.session.commit()

        logout_user()
        flash('Ваш аккаунт успешно удален', 'success')
        return redirect(url_for('login'))

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Ошибка удаления аккаунта: {str(e)}")
        flash('Произошла ошибка при удалении аккаунта', 'danger')
        return redirect(url_for('profile'))

# проверка связи
def check_port(ip, port):
    import socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            result = s.connect_ex((ip, int(port)))
            return result == 0
    except ValueError:
        app.logger.error("Некорректный порт")
        return False
    except Exception as e:
        app.logger.error(f"Ошибка проверки порта: {str(e)}")
        return False


@app.route('/check_connection/<config_name>')
def check_connection(config_name):
    try:
        app.logger.debug(f"Checking connection for {config_name}")
        UserModel = dynamic_user_models[config_name]
        InfoModel = dynamic_info_models[config_name]
        base_user = db.session.execute(
            select(BaseUser).filter_by(email=session['email'])
        ).scalar_one_or_none()

        # Проверяем наличие конфигурации
        config = db.session.execute(
            select(UserModel).filter_by(base_user_id=base_user.id)
        ).scalar_one_or_none()
        if not config:
            return jsonify({"status": "error", "message": "Configuration not activated"})

        # Получаем информацию о сервере
        server_info = db.session.execute(
            select(InfoModel)
        ).scalar_one_or_none()
        if not server_info or not server_info.listen_port:
            return jsonify({"status": "error", "message": "Port information unavailable"})

        # Извлекаем IP из real_endpoint
        ip = config.real_endpoint.split(":")[0]  # Берем только IP
        port = server_info.listen_port

        is_open = check_port(ip, int(port))

        return jsonify({
            "status": "success",
            "available": is_open,
            "message": f"{ip}:{port} available" if is_open else f"{ip}:{port} unavailable"
        })
    except Exception as e:
        app.logger.error(f"Connection check error: {str(e)}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)})


# Удалить. избыточная функция. В Flask-login currentuser есть в шаблонах. Смотри в импортах
@app.context_processor
def inject_user():
    """Внедряет текущего пользователя и Omnissiah сервер в контекст шаблонов"""
    omnissiah_server = None
    try:
        # Проверяем, что таблица существует перед запросом
        from sqlalchemy import inspect as sqlalchemy_inspect
        inspector = sqlalchemy_inspect(db.engine)
        if 'general' in inspector.get_table_names():
            omnissiah_server = General.query.filter_by(role='Omnissiah').first()
    except Exception as e:
        # Если БД еще не готова, просто возвращаем None
        app.logger.debug(f"Ошибка получения Omnissiah в inject_user: {str(e)}")
        omnissiah_server = None
    
    def from_json(json_str):
        """Jinja2 фильтр для парсинга JSON"""
        if not json_str:
            return None
        try:
            return json.loads(json_str)
        except (json.JSONDecodeError, TypeError, ValueError) as e:
            # Игнорируем ошибки парсинга JSON, возвращаем None
            return None
    
    def tojson_filter(obj):
        """Jinja2 фильтр для сериализации в JSON"""
        return json.dumps(obj, indent=2, ensure_ascii=False)
    
    return dict(
        current_user=current_user,
        omnissiah_server=omnissiah_server,
        from_json=from_json,
        tojson=tojson_filter
    )


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == '__main__':
    # Загружаем переменные из .env
    load_dotenv(dotenv_path=env_path)

    # Проверяем обязательные переменные
    required_vars = ['SUDO_PASSWORD', 'WG_MASTER_KEY']
    missing_vars = [var for var in required_vars if not os.getenv(var)]

    if missing_vars:
        app.logger.error(f"Ошибка: Отсутствуют переменные {', '.join(missing_vars)} в .env")
        exit(1)

    # Проверка наличия обязательных переменных окружения
    if not os.getenv('SUDO_PASSWORD'):
        app.logger.error("Error: SUDO_PASSWORD environment variable required!")
        app.logger.error("Usage: SUDO_PASSWORD='your_sudo_pass' python app.py")
        exit(1)

    # Создание папки конфигурации если отсутствует
    if not Path(app.config['WG_CONFIG_PATH']).exists():
        subprocess.run(
            ["sudo", "-n", "mkdir", "-p", app.config['WG_CONFIG_PATH']],
            check=True
        )


    with app.app_context():
        # КРИТИЧНО: Защищаем SSH соединение ПЕРЕД любыми другими операциями с iptables
        # Убеждаемся что SSH правила применяются ПЕРВЫМИ, чтобы не потерять соединение
        app.logger.info("🔒 Защита SSH соединения...")
        try:
            # Устанавливаем политики ACCEPT для INPUT и OUTPUT ПЕРЕД любыми другими операциями
            subprocess.run(['sudo', '-n', 'iptables', '-P', 'INPUT', 'ACCEPT'], 
                          check=False, timeout=5, capture_output=True)
            subprocess.run(['sudo', '-n', 'iptables', '-P', 'OUTPUT', 'ACCEPT'], 
                          check=False, timeout=5, capture_output=True)
            subprocess.run(['sudo', '-n', 'iptables', '-P', 'FORWARD', 'ACCEPT'], 
                          check=False, timeout=5, capture_output=True)
            
            # Добавляем базовые правила для сохранения SSH соединения
            # Loopback
            subprocess.run(['sudo', '-n', 'iptables', '-A', 'INPUT', '-i', 'lo', '-j', 'ACCEPT'], 
                          check=False, timeout=5, capture_output=True)
            subprocess.run(['sudo', '-n', 'iptables', '-A', 'OUTPUT', '-o', 'lo', '-j', 'ACCEPT'], 
                          check=False, timeout=5, capture_output=True)
            
            # Установленные соединения (включая SSH) - КРИТИЧНО для сохранения SSH
            subprocess.run(['sudo', '-n', 'iptables', '-A', 'INPUT', 
                           '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'], 
                          check=False, timeout=5, capture_output=True)
            subprocess.run(['sudo', '-n', 'iptables', '-A', 'OUTPUT', 
                           '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'], 
                          check=False, timeout=5, capture_output=True)
            
            # Примечание: Правила для администратора будут добавлены ПОСЛЕ инициализации БД
            # (см. код после init_db())
            
            # КРИТИЧНО: Разрешаем SSH на ВСЕХ интерфейсах (включая VPN)
            # Это позволяет SSH работать и когда VPN включен
            subprocess.run(['sudo', '-n', 'iptables', '-A', 'INPUT', 
                           '-p', 'tcp', '--dport', '22', '-j', 'ACCEPT'], 
                          check=False, timeout=5, capture_output=True)
            subprocess.run(['sudo', '-n', 'iptables', '-A', 'OUTPUT', 
                           '-p', 'tcp', '--sport', '22', '-j', 'ACCEPT'], 
                          check=False, timeout=5, capture_output=True)
            
            # Разрешаем SSH через VPN интерфейс (если VPN активен)
            # Проверяем какие VPN интерфейсы есть
            try:
                wg_result = subprocess.run(['sudo', '-n', 'wg', 'show', 'interfaces'], 
                                          capture_output=True, text=True, timeout=2)
                if wg_result.returncode == 0:
                    wg_interfaces = wg_result.stdout.strip().split()
                    for wg_iface in wg_interfaces:
                        if wg_iface:
                            # Разрешаем SSH через VPN интерфейс
                            subprocess.run(['sudo', '-n', 'iptables', '-A', 'INPUT', 
                                           '-i', wg_iface, '-p', 'tcp', '--dport', '22', '-j', 'ACCEPT'], 
                                          check=False, timeout=5, capture_output=True)
                            subprocess.run(['sudo', '-n', 'iptables', '-A', 'OUTPUT', 
                                           '-o', wg_iface, '-p', 'tcp', '--sport', '22', '-j', 'ACCEPT'], 
                                          check=False, timeout=5, capture_output=True)
                            # Разрешаем весь трафик через VPN интерфейс (для SSH и других служб)
                            subprocess.run(['sudo', '-n', 'iptables', '-A', 'INPUT', 
                                           '-i', wg_iface, '-j', 'ACCEPT'], 
                                          check=False, timeout=5, capture_output=True)
                            subprocess.run(['sudo', '-n', 'iptables', '-A', 'OUTPUT', 
                                           '-o', wg_iface, '-j', 'ACCEPT'], 
                                          check=False, timeout=5, capture_output=True)
                            app.logger.info(f"✅ Добавлены правила для VPN интерфейса {wg_iface}")
            except Exception:
                pass  # Если не удалось получить список интерфейсов, продолжаем
            
            # Разрешаем весь исходящий трафик (для сохранения SSH ответов)
            subprocess.run(['sudo', '-n', 'iptables', '-A', 'OUTPUT', '-j', 'ACCEPT'], 
                          check=False, timeout=5, capture_output=True)
            
            app.logger.info("✅ SSH соединение защищено (включая VPN интерфейсы и администратора)")
        except Exception as ssh_protect_error:
            app.logger.warning(f"Предупреждение: не удалось полностью защитить SSH: {ssh_protect_error}")
            app.logger.warning(f"⚠️  Предупреждение: не удалось полностью защитить SSH: {ssh_protect_error}")
        
        # CSRF защита включена по умолчанию в Flask-WTF для форм
        # Для API endpoints (JSON запросы) CSRF не требуется, Flask-WTF автоматически пропускает их
        app.config['WTF_CSRF_ENABLED'] = True
        # Отключаем CSRF только для JSON запросов к API
        app.config['WTF_CSRF_TIME_LIMIT'] = None  # Отключаем ограничение по времени для API
        
        # Настраиваем sudo права перед инициализацией БД
        print("Проверка и настройка sudo прав...")
        if not get_sudo_status():
            print("⚠️ Sudo права не настроены. Попытка автоматической настройки...")
            print("   ⚠️  Будет запрошен пароль ОДИН РАЗ для создания файла sudoers")
            try:
                if manage_sudo_permissions('wg'):
                    print("✅ Sudo права для WireGuard и iptables настроены успешно")
                    # Проверяем, что права действительно работают
                    if get_sudo_status():
                        print("✅ Проверка: sudo права работают без пароля")
                    else:
                        print("⚠️  Внимание: sudo права настроены, но проверка не прошла")
                        print("   Возможно, нужно перезапустить терминал или войти заново")
                else:
                    print("⚠️ Не удалось автоматически настроить sudo права.")
                    print("   Выполните вручную: sudo visudo")
            except subprocess.CalledProcessError as e:
                print(f"⚠️ Ошибка при настройке sudo прав: {e}")
                print("   Возможно, нужен пароль для первоначальной настройки")
        else:
            print("✅ Sudo права уже настроены и работают")
        
        # Инициализируем БД
        try:
            init_db()  # init_db() уже вызывает db.create_all(), дубликат не нужен
        except Exception as init_error:
            app.logger.error(f"Ошибка инициализации БД: {str(init_error)}", exc_info=True)
            print(f"⚠️  Ошибка инициализации БД: {str(init_error)}")
        
        # КРИТИЧНО: Запускаем планировщик ПОСЛЕ инициализации БД
        # Это предотвращает попытки работы с неинициализированной БД
        try:
            if not scheduler.running:
                scheduler.add_job(update_omnissiah_traffic, 'interval', seconds=30, id='update_traffic')
                scheduler.add_job(collect_and_save_traffic_logs, 'interval', seconds=60, id='collect_traffic_logs')
                scheduler.start()
                app.logger.info("✅ Планировщик задач запущен")
        except Exception as scheduler_error:
            app.logger.error(f"Ошибка запуска планировщика: {str(scheduler_error)}", exc_info=True)
            print(f"⚠️  Ошибка запуска планировщика: {str(scheduler_error)}")
        
        # Обеспечиваем шифрование private_key для Omnissiah (обратная совместимость)
        ensure_omnissiah_private_key_encrypted()
        
        # Убеждаемся, что таблицы созданы перед синхронизацией
        # Автоматическая синхронизация пиров WireGuard при старте приложения
        # Это решает проблему "Требуемый ключ недоступен" после рестарта
        omnissiah = None
        try:
            # Проверяем существование таблицы general через inspector
            from sqlalchemy import inspect as sqlalchemy_inspect
            inspector = sqlalchemy_inspect(db.engine)
            tables = inspector.get_table_names()
            
            if 'general' not in tables:
                print("⚠️  Таблица general не найдена в БД, синхронизация пиров пропущена")
                app.logger.warning("Таблица general не найдена после init_db(), синхронизация пиров пропущена")
            else:
                # Пробуем получить Omnissiah узел через SQL запрос для проверки
                try:
                    result = db.session.execute(db.text("SELECT COUNT(*) FROM general WHERE role = 'Omnissiah'"))
                    count = result.scalar()
                    if count > 0:
                        omnissiah = General.query.filter_by(role='Omnissiah').first()
                        if omnissiah:
                            app.logger.info(f"Найден Omnissiah узел: {omnissiah.name}, статус: {omnissiah.status}")
                    else:
                        app.logger.info("Omnissiah узел не найден в БД")
                except Exception as query_error:
                    app.logger.error(f"Ошибка запроса к БД при старте: {str(query_error)}", exc_info=True)
                    print(f"⚠️  Ошибка запроса к БД: {str(query_error)}")
                    omnissiah = None
        except Exception as e:
            # Общая ошибка при проверке БД
            app.logger.error(f"Ошибка проверки таблиц БД при старте: {str(e)}", exc_info=True)
            print(f"⚠️  Ошибка проверки БД: {str(e)}")
            omnissiah = None
        
        if omnissiah and omnissiah.status == 'active':
            # КРИТИЧНО: Восстанавливаем конфигурацию из БД ПЕРЕД проверкой интерфейса
            # Это гарантирует что Address будет в файле
            config_path = f"/etc/wireguard/{omnissiah.name}.conf"
            temp_config_path = None
            try:
                restored_config = restore_wg_config_from_db(omnissiah)
                if restored_config:
                    try:
                        temp_config = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf')
                        temp_config.write(restored_config)
                        temp_config.close()
                        temp_config_path = temp_config.name
                        
                        subprocess.run(['sudo', '-n', 'cp', temp_config_path, config_path], 
                                     check=True, timeout=10)
                        subprocess.run(['sudo', '-n', 'chmod', '600', config_path], 
                                     check=True, timeout=5)
                        print(f"✅ Конфигурация WireGuard восстановлена из БД для {omnissiah.name} (включая Address)")
                    except Exception as restore_err:
                        print(f"⚠️  Не удалось восстановить конфигурацию: {str(restore_err)}")
                    finally:
                        if temp_config_path and os.path.exists(temp_config_path):
                            try:
                                os.unlink(temp_config_path)
                            except Exception:
                                pass
            except Exception as restore_err:
                print(f"⚠️  Ошибка восстановления конфигурации: {str(restore_err)}")
            
            # Проверяем, активен ли интерфейс WireGuard
            try:
                result = subprocess.run(
                    ["sudo", "-n", "wg", "show", omnissiah.name],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    # Интерфейс активен, синхронизируем пиры
                    print("🔄 Синхронизация пиров WireGuard при старте...")
                    sync_result = sync_wireguard_peers(omnissiah)
                    if sync_result:
                        print("✅ Пиры WireGuard синхронизированы")
                    else:
                        print("⚠️  Не удалось синхронизировать пиры WireGuard")
                else:
                    # Интерфейс не активен, но в БД статус active - запускаем
                    print(f"🔄 Интерфейс {omnissiah.name} не активен, но в БД статус active - запускаем...")
                    try:
                        up_result = subprocess.run(
                            ["sudo", "-n", "/usr/bin/wg-quick", "up", omnissiah.name],
                            capture_output=True,
                            text=True,
                            timeout=10
                        )
                        if up_result.returncode == 0:
                            print(f"✅ Интерфейс {omnissiah.name} запущен")
                            # Синхронизируем пиры после запуска
                            sync_result = sync_wireguard_peers(omnissiah)
                            if sync_result:
                                print("✅ Пиры WireGuard синхронизированы")
                        else:
                            print(f"⚠️  Не удалось запустить интерфейс: {up_result.stderr}")
                    except Exception as start_err:
                        print(f"⚠️  Ошибка запуска интерфейса: {str(start_err)}")
                    
                    # КРИТИЧНО: Обновляем правила SSH для VPN интерфейсов после включения VPN
                    # Это нужно на случай если VPN был включен после старта приложения
                    try:
                        wg_result = subprocess.run(['sudo', '-n', 'wg', 'show', 'interfaces'], 
                                                  capture_output=True, text=True, timeout=2)
                        if wg_result.returncode == 0:
                            wg_interfaces = wg_result.stdout.strip().split()
                            for wg_iface in wg_interfaces:
                                if wg_iface:
                                    # Проверяем, есть ли уже правило для этого интерфейса
                                    check_cmd = ['sudo', '-n', 'iptables', '-C', 'INPUT', 
                                                '-i', wg_iface, '-j', 'ACCEPT']
                                    check_result = subprocess.run(check_cmd, capture_output=True, timeout=2)
                                    
                                    if check_result.returncode != 0:
                                        # Правила нет, добавляем
                                        subprocess.run(['sudo', '-n', 'iptables', '-A', 'INPUT', 
                                                       '-i', wg_iface, '-p', 'tcp', '--dport', '22', '-j', 'ACCEPT'], 
                                                      check=False, timeout=5)
                                        subprocess.run(['sudo', '-n', 'iptables', '-A', 'OUTPUT', 
                                                       '-o', wg_iface, '-p', 'tcp', '--sport', '22', '-j', 'ACCEPT'], 
                                                      check=False, timeout=5)
                                        subprocess.run(['sudo', '-n', 'iptables', '-A', 'INPUT', 
                                                       '-i', wg_iface, '-j', 'ACCEPT'], 
                                                      check=False, timeout=5)
                                        subprocess.run(['sudo', '-n', 'iptables', '-A', 'OUTPUT', 
                                                       '-o', wg_iface, '-j', 'ACCEPT'], 
                                                      check=False, timeout=5)
                                        app.logger.info(f"Добавлены правила SSH для VPN интерфейса {wg_iface} после проверки")
                    except Exception:
                        pass  # Если не удалось обновить правила, продолжаем
                    
                    # КРИТИЧНО: Обновляем правила для администратора после синхронизации VPN
                    # Это гарантирует что доступ администратора всегда работает
                    try:
                        if omnissiah and omnissiah.admin_ip:
                            admin_ip = omnissiah.admin_ip.strip()
                            if admin_ip:
                                # Проверяем, есть ли уже правила для администратора
                                check_cmd = ['sudo', '-n', 'iptables', '-C', 'INPUT', '-s', admin_ip, '-j', 'ACCEPT']
                                check_result = subprocess.run(check_cmd, capture_output=True, timeout=2)
                                
                                if check_result.returncode != 0:
                                    # Правил нет, добавляем
                                    subprocess.run(['sudo', '-n', 'iptables', '-A', 'INPUT', 
                                                   '-s', admin_ip, '-j', 'ACCEPT'], 
                                                  check=False, timeout=5)
                                    subprocess.run(['sudo', '-n', 'iptables', '-A', 'OUTPUT', 
                                                   '-d', admin_ip, '-j', 'ACCEPT'], 
                                                  check=False, timeout=5)
                                    subprocess.run(['sudo', '-n', 'iptables', '-A', 'INPUT', 
                                                   '-s', admin_ip, '-p', 'tcp', '--dport', '22', '-j', 'ACCEPT'], 
                                                  check=False, timeout=5)
                                    subprocess.run(['sudo', '-n', 'iptables', '-A', 'OUTPUT', 
                                                   '-d', admin_ip, '-p', 'tcp', '--sport', '22', '-j', 'ACCEPT'], 
                                                  check=False, timeout=5)
                                    app.logger.info(f"Добавлены правила для администратора ({admin_ip}) после синхронизации VPN")
                                    print(f"✅ Правила для администратора ({admin_ip}) обновлены")
                    except Exception as admin_update_error:
                        app.logger.warning(f"Не удалось обновить правила для администратора: {admin_update_error}")
                    
                    # Восстанавливаем маршруты для защищенных объектов
                    print("🔄 Восстановление маршрутов для защищенных объектов...")
                    protected_objects = ProtectedObject.query.filter_by(is_active=True).all()
                    routes_restored = 0
                    for obj in protected_objects:
                        try:
                            # Проверяем существует ли маршрут
                            check_cmd = ['sudo', '-n', 'ip', 'route', 'show', obj.network]
                            check_result = subprocess.run(check_cmd, capture_output=True, text=True, timeout=5)
                            
                            if check_result.returncode != 0 or obj.network not in check_result.stdout:
                                # Маршрута нет, восстанавливаем через WireGuard allowed-ips
                                # Маршруты теперь управляются через WireGuard, а не системные маршруты
                                # Обновляем allowed-ips через sync_wireguard_peers
                                try:
                                    omnissiah = General.query.filter_by(role='Omnissiah').first()
                                    if omnissiah:
                                        sync_wireguard_peers(omnissiah)
                                        routes_restored += 1
                                except Exception as e:
                                    app.logger.warning(f"Не удалось восстановить маршрут через WireGuard для {obj.network}: {str(e)}")
                        except Exception as e:
                            app.logger.warning(f"Не удалось восстановить маршрут для {obj.network}: {str(e)}")
                    
                    if routes_restored > 0:
                        print(f"✅ Восстановлено маршрутов: {routes_restored}")
                    
                    # КРИТИЧНО: Восстанавливаем правила политики доступа (Access Policy Rules) из БД
                    # Это гарантирует что все правила применяются после перезапуска приложения
                    print("🔄 Восстановление правил политики доступа из БД...")
                    try:
                        applied_rules = AccessPolicyRule.query.filter_by(status='applied').all()
                        if applied_rules:
                            applied_count = 0
                            errors_count = 0
                            
                            # Сортируем правила: сначала DROP/REJECT (по приоритету), потом ACCEPT
                            def sort_key(rule):
                                action = getattr(rule, 'action', 'ACCEPT') if hasattr(rule, 'action') and rule.action else 'ACCEPT'
                                priority = rule.priority if rule.priority is not None else 100
                                action_order = 0 if action in ['DROP', 'REJECT'] else 1
                                return (action_order, priority, rule.created_at)
                            
                            sorted_rules = sorted(applied_rules, key=sort_key)
                            
                            for rule in sorted_rules:
                                try:
                                    # Проверяем, нужно ли применять правило на Omnissiah
                                    nodes_to_apply = determine_nodes_for_rule(rule)
                                    should_apply_on_omnissiah = any(
                                        node.id == omnissiah.id and node.role == 'Omnissiah' 
                                        for node in nodes_to_apply
                                    )
                                    
                                    if should_apply_on_omnissiah:
                                        # Генерируем команды iptables для правила
                                        iptables_cmds = generate_iptables_commands_for_rule(rule)
                                        
                                        if iptables_cmds:
                                            # Проверяем, есть ли уже это правило в системе
                                            # Проверяем по комментарию PolicyRule#ID
                                            rule_comment = f'PolicyRule#{rule.id}'
                                            rule_exists = False
                                            
                                            try:
                                                # Проверяем в цепочке из правила
                                                direction = rule.direction if rule.direction else 'INPUT'
                                                chain = direction
                                                
                                                check_result = subprocess.run(
                                                    ['sudo', '-n', 'iptables', '-L', chain, '-n', '--line-numbers'],
                                                    capture_output=True,
                                                    text=True,
                                                    timeout=5
                                                )
                                                
                                                if check_result.returncode == 0 and rule_comment in check_result.stdout:
                                                    rule_exists = True
                                            except Exception:
                                                pass  # Если не удалось проверить, считаем что правило нужно добавить
                                            
                                            if not rule_exists:
                                                # Применяем правило
                                                for cmd_list in iptables_cmds:
                                                    try:
                                                        if isinstance(cmd_list, list):
                                                            full_cmd = ['iptables'] + cmd_list
                                                            result = subprocess.run(
                                                                ['sudo', '-n'] + full_cmd,
                                                                check=True,
                                                                timeout=5,
                                                                capture_output=True,
                                                                text=True
                                                            )
                                                            app.logger.debug(f"Применено правило {rule.id} при старте: {' '.join(full_cmd)}")
                                                    except subprocess.CalledProcessError as e:
                                                        # Правило может уже существовать (дубликат)
                                                        if 'already exists' not in e.stderr.lower() and 'already a member' not in e.stderr.lower():
                                                            app.logger.warning(f"Ошибка применения правила {rule.id} при старте: {e.stderr}")
                                                            errors_count += 1
                                                    except Exception as e:
                                                        app.logger.warning(f"Ошибка применения правила {rule.id} при старте: {str(e)}")
                                                        errors_count += 1
                                                
                                                if not rule_exists:
                                                    applied_count += 1
                                        
                                except Exception as rule_error:
                                    app.logger.warning(f"Ошибка восстановления правила {rule.id}: {str(rule_error)}")
                                    errors_count += 1
                            
                            if applied_count > 0:
                                print(f"✅ Восстановлено правил политики доступа: {applied_count}")
                            if errors_count > 0:
                                print(f"⚠️  Ошибок при восстановлении правил: {errors_count}")
                            if applied_count == 0 and errors_count == 0:
                                print(f"ℹ️  Все правила политики доступа уже применены в системе")
                        else:
                            print("ℹ️  Нет правил политики доступа для восстановления")
                    except Exception as rules_error:
                        app.logger.warning(f"Не удалось восстановить правила политики доступа: {str(rules_error)}")
                        print(f"⚠️  Ошибка восстановления правил политики доступа: {str(rules_error)}")
                    
            except Exception as e:
                app.logger.warning(f"Не удалось проверить интерфейс WireGuard при старте: {str(e)}")
    
    debug_mode = os.getenv('DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=33787, debug=debug_mode)


