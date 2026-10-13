"""
API Blueprint для работы с узлами (nodes)
"""
from flask import Blueprint, jsonify, request, current_app
import sys
import base64
from pathlib import Path

# Добавляем путь к src для импорта
src_path = Path(__file__).parent.parent
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from nmc_models import db, General
from functools import wraps

# Импортируем функцию для получения cipher suite
# Используем относительный импорт для доступа к app.py
import importlib.util
app_py_path = Path(__file__).parent.parent / "app.py"
if app_py_path.exists():
    spec = importlib.util.spec_from_file_location("app_module", app_py_path)
    app_module = importlib.util.module_from_spec(spec)
    # Не загружаем весь модуль, только нужную функцию будет импортировать динамически

nodes_bp = Blueprint('nodes_api', __name__, url_prefix='/api/nodes')


def get_node_or_404(node_id):
    """Получает узел по ID или возвращает 404"""
    node = General.query.get_or_404(node_id)
    return node


@nodes_bp.route('', methods=['GET'])
def get_nodes():
    """Получить список всех узлов"""
    try:
        nodes = General.query.all()
        return jsonify([{
            'id': node.id,
            'name': node.name,
            'role': node.role,
            'ip_pool': node.ip_pool,
            'status': node.status,
            'parent_id': node.parent_id
        } for node in nodes]), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@nodes_bp.route('/<int:node_id>', methods=['GET'])
def get_node(node_id):
    """Получить информацию об узле"""
    try:
        node = get_node_or_404(node_id)
        return jsonify({
            'id': node.id,
            'name': node.name,
            'role': node.role,
            'ip_pool': node.ip_pool,
            'status': node.status,
            'parent_id': node.parent_id,
            'last_handshake': node.last_handshake.isoformat() if node.last_handshake else None,
            'total_receive': node.total_receive,
            'total_sent': node.total_sent
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@nodes_bp.route('/<int:node_id>', methods=['DELETE'])
def delete_node(node_id):
    """Удалить узел"""
    try:
        node = get_node_or_404(node_id)
        
        # Проверка наличия дочерних узлов
        if node.children.count() > 0:
            return jsonify({'error': 'Нельзя удалить узел с дочерними узлами'}), 400
        
        db.session.delete(node)
        db.session.commit()
        
        return jsonify({'success': True, 'message': f'Узел {node.name} удален'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@nodes_bp.route('/register_key', methods=['POST'])
def register_node_key():
    """
    Регистрация публичного ключа WireGuard от удаленного узла через mTLS
    
    В ZTN архитектуре ключи генерируются на конечных устройствах и передаются
    на Omnissiah через защищенный mTLS канал.
    
    Требует:
    - mTLS аутентификацию (проверяется через Nginx)
    - JSON payload с полями: node_name, public_key, private_key (зашифрованный)
    """
    try:
        # Проверяем наличие mTLS сертификата (через заголовки от Nginx)
        # Nginx устанавливает заголовки X-SSL-Client-Verify и X-SSL-Client-Cert
        ssl_verify = request.headers.get('X-SSL-Client-Verify', '')
        if ssl_verify != 'SUCCESS':
            return jsonify({
                'success': False,
                'error': 'mTLS аутентификация не пройдена. Требуется валидный клиентский сертификат.'
            }), 401
        
        # Получаем данные из запроса
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Отсутствует JSON payload'}), 400
        
        node_name = data.get('node_name')
        public_key = data.get('public_key')
        encrypted_private_key = data.get('private_key')  # Зашифрованный приватный ключ
        
        if not node_name or not public_key:
            return jsonify({
                'success': False,
                'error': 'Отсутствуют обязательные поля: node_name, public_key'
            }), 400
        
        # Ищем узел по имени
        node = General.query.filter_by(name=node_name).first()
        if not node:
            return jsonify({
                'success': False,
                'error': f'Узел с именем {node_name} не найден в базе данных'
            }), 404
        
        # Обновляем ключи узла
        node.public_key = public_key
        
        # Если передан приватный ключ, обрабатываем его
        # В ZTN архитектуре агент отправляет открытый ключ через mTLS (канал защищен)
        # Omnissiah шифрует ключ перед сохранением в БД
        if encrypted_private_key:
            try:
                # Декодируем base64 (агент отправляет открытый ключ в base64)
                decoded = base64.b64decode(encrypted_private_key)
                private_key_plain = decoded.decode('utf-8')
                
                # Проверяем что это валидный WireGuard ключ (длина ~44 символа)
                if len(private_key_plain) == 44:
                    # Шифруем приватный ключ перед сохранением в БД используя cipher suite
                    # Импортируем динамически чтобы избежать циклических зависимостей
                    import importlib.util
                    app_py_path = Path(__file__).parent.parent / "app.py"
                    spec = importlib.util.spec_from_file_location("app_module", app_py_path)
                    app_module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(app_module)
                    cipher = app_module.get_cipher_suite()
                    encrypted_for_db = cipher.encrypt(private_key_plain.encode('utf-8'))
                    node.private_key = base64.b64encode(encrypted_for_db).decode('utf-8')
                    current_app.logger.info(f"✅ Приватный ключ зашифрован и сохранен для узла {node_name}")
                else:
                    current_app.logger.warning(f"⚠️ Неверная длина приватного ключа для {node_name}: {len(private_key_plain)} (ожидается 44)")
                    # Сохраняем как есть (возможно уже зашифрован)
                    node.private_key = encrypted_private_key
                        
            except Exception as e:
                current_app.logger.warning(f"Ошибка обработки приватного ключа для {node_name}: {e}")
                # Сохраняем как есть (возможно уже зашифрован)
                node.private_key = encrypted_private_key
        
        db.session.commit()
        
        current_app.logger.info(f"✅ Публичный ключ зарегистрирован для узла {node_name} через mTLS")
        
        # В ZTN архитектуре: после регистрации ключей обновляем конфигурацию WireGuard на Omnissiah
        # чтобы добавить публичный ключ нового узла в конфигурацию Omnissiah
        try:
            # Импортируем функции из app.py
            import importlib.util
            import subprocess
            import tempfile
            import os as os_module
            app_py_path = Path(__file__).parent.parent / "app.py"
            spec = importlib.util.spec_from_file_location("app_module", app_py_path)
            app_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(app_module)
            
            # Получаем узел Omnissiah
            omnissiah = General.query.filter_by(role='Omnissiah').first()
            
            if omnissiah:
                # Генерируем новую конфигурацию WireGuard для Omnissiah с учетом нового узла
                wg_config = app_module.generate_wg_config_with_connections(omnissiah, include_additional_peers=True)
                
                if wg_config:
                    # Сохраняем конфигурацию в файл /etc/wireguard/{omnissiah.name}.conf
                    config_path = f"/etc/wireguard/{omnissiah.name}.conf"
                    
                    # Создаем временный файл
                    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf') as tmp:
                        tmp.write(wg_config)
                        tmp_path = tmp.name
                    
                    try:
                        # Копируем конфигурацию в /etc/wireguard/ через sudo
                        subprocess.run(
                            ['sudo', '-n', 'cp', tmp_path, config_path],
                            check=True,
                            timeout=10
                        )
                        
                        # Устанавливаем права доступа
                        subprocess.run(
                            ['sudo', '-n', 'chmod', '600', config_path],
                            check=False,
                            timeout=5
                        )
                        
                        current_app.logger.info(f"✅ Конфигурация WireGuard обновлена для Omnissiah: {config_path}")
                        
                        # Применяем конфигурацию к интерфейсу WireGuard
                        # Проверяем, активен ли интерфейс
                        check_interface = subprocess.run(
                            ['sudo', '-n', 'wg', 'show', omnissiah.name],
                            capture_output=True,
                            text=True,
                            timeout=5
                        )
                        
                        if check_interface.returncode == 0:
                            # Интерфейс активен - используем wg syncconf для обновления без перезапуска
                            current_app.logger.info(f"🔄 Обновление конфигурации WireGuard интерфейса {omnissiah.name} через wg syncconf...")
                            sync_result = subprocess.run(
                                ['sudo', '-n', 'wg', 'syncconf', omnissiah.name, config_path],
                                capture_output=True,
                                text=True,
                                timeout=10
                            )
                            
                            if sync_result.returncode == 0:
                                current_app.logger.info(f"✅ Конфигурация WireGuard успешно применена к интерфейсу {omnissiah.name}")
                            else:
                                current_app.logger.warning(f"⚠️ Ошибка применения конфигурации через wg syncconf: {sync_result.stderr}")
                                # Пробуем через wg-quick down/up
                                current_app.logger.info(f"🔄 Попытка применения через wg-quick down/up...")
                                subprocess.run(['sudo', '-n', 'wg-quick', 'down', omnissiah.name], timeout=10, check=False)
                                subprocess.run(['sudo', '-n', 'wg-quick', 'up', omnissiah.name], timeout=30, check=False)
                        else:
                            # Интерфейс не активен - просто сохраняем конфигурацию
                            current_app.logger.info(f"ℹ️ Интерфейс WireGuard {omnissiah.name} не активен, конфигурация сохранена для будущего использования")
                        
                    except subprocess.CalledProcessError as e:
                        current_app.logger.error(f"❌ Ошибка сохранения конфигурации WireGuard: {e}")
                    except Exception as e:
                        current_app.logger.error(f"❌ Ошибка применения конфигурации WireGuard: {e}")
                    finally:
                        # Удаляем временный файл
                        if os_module.path.exists(tmp_path):
                            os_module.unlink(tmp_path)
                else:
                    current_app.logger.warning(f"⚠️ Не удалось сгенерировать конфигурацию WireGuard для Omnissiah")
            else:
                current_app.logger.warning(f"⚠️ Узел Omnissiah не найден в базе данных")
                
        except Exception as config_error:
            current_app.logger.warning(f"⚠️ Ошибка обновления конфигурации WireGuard на Omnissiah: {config_error}", exc_info=True)
            # Не критично - конфигурация может быть обновлена позже
        
        return jsonify({
            'success': True,
            'message': f'Ключи успешно зарегистрированы для узла {node_name}',
            'node_id': node.id
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Ошибка регистрации ключа: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'error': f'Внутренняя ошибка сервера: {str(e)}'
        }), 500

