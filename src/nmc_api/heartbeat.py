"""
API Blueprint для heartbeat от Magos узлов
"""
from flask import Blueprint, jsonify, request, current_app
from datetime import datetime, timezone
import sys
from pathlib import Path

# Добавляем путь к src для импорта
src_path = Path(__file__).parent.parent
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from nmc_models import db, General

heartbeat_bp = Blueprint('heartbeat_api', __name__, url_prefix='/api')


@heartbeat_bp.route('/heartbeat', methods=['POST'])
@heartbeat_bp.route('/magos/heartbeat', methods=['POST'])
def api_magos_heartbeat():
    """Heartbeat endpoint для Magos агентов (поддержка mTLS)"""
    import sys
    try:
        # КРИТИЧНО: Логируем все входящие запросы
        current_app.logger.info(f"[🔥 SERVER] Heartbeat request received from {request.remote_addr}")
        current_app.logger.info(f"[🔥 SERVER] Request method: {request.method}, URL: {request.url}")
        current_app.logger.info(f"[🔥 SERVER] Headers: {dict(request.headers)}")
        
        data = request.get_json() or {}
        current_app.logger.info(f"[🔥 SERVER] Heartbeat data received: {data}")
        print(f"[🔥 SERVER] Heartbeat received from {request.remote_addr}: {data}", file=sys.stderr, flush=True)
        
        # Проверка mTLS сертификата (если используется)
        client_cert = None
        if request.environ.get('SSL_CLIENT_CERT'):
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            try:
                cert_pem = request.environ['SSL_CLIENT_CERT']
                client_cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
                current_app.logger.debug(f"[mTLS] Сертификат клиента: {client_cert.subject}")
            except Exception as e:
                current_app.logger.warning(f"Ошибка парсинга клиентского сертификата: {e}")
        
        node_name = data.get('name')
        if not node_name:
            return jsonify({'error': 'Missing name'}), 400
        
        # Находим узел (может быть Magos или другой)
        node = General.query.filter_by(name=node_name).first()
        if not node:
            return jsonify({'error': 'Node not found'}), 404
        
        # Обновляем heartbeat
        node.last_heartbeat = datetime.now(timezone.utc)
        
        # Сохраняем IP адрес из heartbeat
        local_ip = data.get('local_ip') or data.get('ip')
        if local_ip:
            node.heartbeat_ip = local_ip
        
        # Сохраняем интерфейсы из heartbeat
        interfaces = data.get('interfaces')
        if interfaces:
            try:
                import json as json_lib
                node.heartbeat_interfaces = json_lib.dumps(interfaces)
            except Exception as e:
                current_app.logger.warning(f"Ошибка сохранения интерфейсов из heartbeat: {e}")
        
        # Сохраняем статус WireGuard из heartbeat
        wireguard_enabled = data.get('wireguard_enabled', False)
        node.wireguard_enabled = wireguard_enabled
        
        # В ZTN архитектуре: сохраняем публичный ключ из heartbeat, если он пришел
        # Это важно, так как ключи генерируются на удаленных узлах и передаются через heartbeat
        public_key_from_heartbeat = data.get('public_key')
        current_app.logger.info(f"🔍 Проверка публичного ключа для {node_name}: heartbeat_key={bool(public_key_from_heartbeat)}, db_key={bool(node.public_key)}, db_key_value='{node.public_key[:20] if node.public_key else 'empty'}...'")
        
        if public_key_from_heartbeat and public_key_from_heartbeat.strip():
            # Обновляем публичный ключ в БД, если он изменился или был пустым
            if not node.public_key or not node.public_key.strip() or node.public_key.strip() != public_key_from_heartbeat.strip():
                old_key = node.public_key[:20] if node.public_key else "empty"
                node.public_key = public_key_from_heartbeat.strip()
                current_app.logger.info(f"✅ Публичный ключ обновлен для узла {node_name} из heartbeat: старый='{old_key}...', новый='{public_key_from_heartbeat[:20]}...'")
                
                # После обновления ключа обновляем конфигурацию WireGuard на Omnissiah
                try:
                    # Получаем узел Omnissiah
                    omnissiah = General.query.filter_by(role='Omnissiah').first()
                    
                    if omnissiah:
                        # Импортируем функцию генерации конфигурации
                        import importlib.util
                        app_py_path = Path(__file__).parent.parent / "app.py"
                        spec = importlib.util.spec_from_file_location("app_module", app_py_path)
                        app_module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(app_module)
                        
                        # Генерируем новую конфигурацию WireGuard для Omnissiah
                        wg_config = app_module.generate_wg_config_with_connections(omnissiah, include_additional_peers=True)
                        
                        if wg_config:
                            # Сохраняем конфигурацию в файл /etc/wireguard/{omnissiah.name}.conf
                            import subprocess
                            import tempfile
                            import os as os_module
                            
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
        
        db.session.commit()
        
        current_app.logger.info(f"💓 Heartbeat от {node_name} принят в {node.last_heartbeat}")
        
        response_data = {'success': True}
        if client_cert:
            response_data['mtls_verified'] = True
        
        return jsonify(response_data), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Ошибка heartbeat: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

