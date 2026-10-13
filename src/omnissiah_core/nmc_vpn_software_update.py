"""
Модуль для отправки обновлений ПО на узлы через VPN в зашифрованном архиве
"""
import requests
import base64
import tarfile
import tempfile
import os
import logging
import sys
from pathlib import Path
from typing import Tuple, Optional

# Добавляем путь к корню проекта для импорта
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

logger = logging.getLogger(__name__)


def create_encrypted_archive(node, archive_type: str = 'update', app=None) -> Tuple[Optional[bytes], Optional[str]]:
    """
    Создает зашифрованный архив для обновления ПО на узле
    
    Args:
        node: Объект General (узел)
        archive_type: 'update' - только код (без setup, mtls, configs), 'full' - полный архив
        app: Flask приложение
    
    Returns:
        tuple: (encrypted_archive_bytes, error_message)
    """
    try:
        from omnissiah_utils.nmc_crypto_utils import encrypt_config_for_node
        
        # Путь к исходной директории агента
        # __file__ может быть /home/nmc-admin/NMC_WG/src/omnissiah_core/nmc_vpn_software_update.py
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
                logger.error(error_msg)
                return None, error_msg
        
        # Создаем временный архив
        temp_archive = tempfile.NamedTemporaryFile(suffix='.tar.gz', delete=False)
        temp_archive.close()
        
        try:
            # Создаем архив
            exclude_patterns = ['__pycache__', '.git', 'database', 'instance']
            
            if archive_type == 'update':
                # Для обновления исключаем также setup, mtls, configs
                exclude_patterns.extend(['setup', 'mtls', '*.conf', '*.service'])
            
            with tarfile.open(temp_archive.name, 'w:gz') as tar:
                for root, dirs, files in os.walk(agent_source_dir):
                    # Фильтруем директории
                    dirs[:] = [d for d in dirs if not any(pattern in d for pattern in exclude_patterns)]
                    
                    for file in files:
                        # Исключаем .pyc, .pyo, и конфиги для update
                        if any(file.endswith(ext) for ext in ['.pyc', '.pyo']):
                            continue
                        
                        if archive_type == 'update':
                            if any(file.endswith(ext) for ext in ['.conf', '.service']):
                                continue
                        
                        file_path = Path(root) / file
                        arc_name = file_path.relative_to(agent_source_dir)
                        tar.add(file_path, arcname=str(arc_name))
            
            # Читаем архив
            with open(temp_archive.name, 'rb') as f:
                archive_data = f.read()
            
            # Шифруем архив
            try:
                # Используем тот же механизм шифрования что и для конфигураций
                from omnissiah_utils.nmc_crypto_utils import encrypt_config_for_node
                
                # Для архива создаем словарь с данными
                config_data = {
                    'archive_type': archive_type,
                    'archive_data': base64.b64encode(archive_data).decode('utf-8')
                }
                
                encrypted_data = encrypt_config_for_node(config_data, node, app)
                return encrypted_data, None
            
            except Exception as e:
                logger.error(f"Ошибка шифрования архива: {e}")
                return None, f"Ошибка шифрования: {str(e)}"
        
        finally:
            # Удаляем временный архив
            if os.path.exists(temp_archive.name):
                os.unlink(temp_archive.name)
    
    except Exception as e:
        logger.error(f"Ошибка создания зашифрованного архива: {e}", exc_info=True)
        return None, str(e)


def send_software_update_via_vpn(node, archive_type: str = 'update', app=None,
                                 check_connectivity: bool = True) -> Tuple[bool, Optional[str]]:
    """
    Отправляет обновление ПО на узел через VPN
    
    Args:
        node: Объект узла
        archive_type: 'update' или 'full'
        app: Flask приложение
        check_connectivity: Проверять ли доступность VPN перед отправкой
    
    Returns:
        tuple: (success, error_message)
    """
    try:
        # Проверяем что узел активен и имеет VPN IP
        if not node.ip_pool:
            return False, "Узел не имеет VPN IP адреса"
        
        vpn_ip = node.ip_pool.split('/')[0]
        if not vpn_ip:
            return False, "Не удалось определить VPN IP узла"
        
        # КРИТИЧНО: Проверяем доступность VPN перед отправкой большого архива
        if check_connectivity:
            from omnissiah_core.nmc_vpn_config_sender import check_vpn_connectivity
            is_reachable, error_msg = check_vpn_connectivity(vpn_ip, timeout=5)
            if not is_reachable:
                logger.warning(f"VPN недоступен для узла {node.name} ({vpn_ip}): {error_msg}")
                return False, f"VPN туннель не работает: {error_msg}. Нельзя безопасно отправить обновление через публичную сеть."
        
        # Создаем зашифрованный архив
        encrypted_archive, error = create_encrypted_archive(node, archive_type, app)
        if encrypted_archive is None:
            return False, error or "Не удалось создать архив"
        
        # Формируем URL на VPN IP узла
        # Порт агента можно указать в узле, по умолчанию 5001
        vpn_port = getattr(node, 'agent_port', None) or 5001
        vpn_url = f"http://{vpn_ip}:{vpn_port}/api/v1/software/update"
        
        logger.info(f"Отправка обновления ПО на {node.name} ({vpn_ip}:{vpn_port})")
        
        # Кодируем в base64 для передачи
        encrypted_b64 = base64.b64encode(encrypted_archive).decode('utf-8')
        
        # Формируем payload
        payload = {
            "encrypted_archive": encrypted_b64,
            "archive_type": archive_type,
            "node_name": node.name
        }
        
        logger.debug(f"Payload размер: {len(encrypted_b64)} символов, URL: {vpn_url}")
        
        # Отправляем запрос через VPN
        try:
            response = requests.post(
                vpn_url,
                json=payload,
                timeout=120,  # Больший timeout для больших архивов
                verify=False
            )
            
            logger.info(f"Ответ от {node.name}: HTTP {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    logger.info(f"Обновление ПО успешно отправлено на {node.name} ({vpn_ip})")
                    return True, None
                else:
                    error_msg = result.get('error', 'Unknown error')
                    # Если ошибка связана с отсутствием cryptography, пытаемся установить автоматически
                    if 'No module named \'cryptography\'' in error_msg or ('cryptography' in error_msg.lower() and 'module' in error_msg.lower()):
                        logger.warning(f"Обнаружено отсутствие cryptography на {node.name}, пытаемся установить...")
                        try:
                            # Пробуем вызвать endpoint для установки зависимостей
                            install_url = f"http://{vpn_ip}:{vpn_port}/api/v1/install_dependencies"
                            install_response = requests.post(
                                install_url,
                                timeout=120,
                                verify=False
                            )
                            if install_response.status_code == 200:
                                install_result = install_response.json()
                                if install_result.get('success'):
                                    logger.info(f"cryptography успешно установлен на {node.name}, повторяем отправку обновления...")
                                    # Повторяем отправку обновления
                                    retry_response = requests.post(
                                        vpn_url,
                                        json=payload,
                                        timeout=120,
                                        verify=False
                                    )
                                    if retry_response.status_code == 200:
                                        retry_result = retry_response.json()
                                        if retry_result.get('success'):
                                            logger.info(f"Обновление ПО успешно отправлено на {node.name} после установки cryptography")
                                            return True, None
                        except Exception as install_err:
                            logger.warning(f"Не удалось автоматически установить cryptography: {install_err}")
                        
                        error_msg = f"Модуль cryptography не установлен на узле {node.name}. " \
                                   f"Попытка автоматической установки не удалась. " \
                                   f"Необходимо установить вручную: pip3 install --user cryptography>=41.0.0 " \
                                   f"или переразвернуть агент через SSH."
                    logger.error(f"Ошибка установки обновления на {node.name}: {error_msg}")
                    return False, error_msg
            else:
                error_msg = f"HTTP {response.status_code}: {response.text}"
                # Проверяем текст ответа на наличие ошибки cryptography
                if 'No module named \'cryptography\'' in error_msg or ('cryptography' in error_msg.lower() and 'module' in error_msg.lower()):
                    logger.warning(f"Обнаружено отсутствие cryptography на {node.name}, пытаемся установить...")
                    try:
                        # Пробуем вызвать endpoint для установки зависимостей
                        install_url = f"http://{vpn_ip}:{vpn_port}/api/v1/install_dependencies"
                        install_response = requests.post(
                            install_url,
                            timeout=120,
                            verify=False
                        )
                        if install_response.status_code == 200:
                            install_result = install_response.json()
                            if install_result.get('success'):
                                logger.info(f"cryptography успешно установлен на {node.name}, повторяем отправку обновления...")
                                # Повторяем отправку обновления
                                retry_response = requests.post(
                                    vpn_url,
                                    json=payload,
                                    timeout=120,
                                    verify=False
                                )
                                if retry_response.status_code == 200:
                                    retry_result = retry_response.json()
                                    if retry_result.get('success'):
                                        logger.info(f"Обновление ПО успешно отправлено на {node.name} после установки cryptography")
                                        return True, None
                    except Exception as install_err:
                        logger.warning(f"Не удалось автоматически установить cryptography: {install_err}")
                    
                    error_msg = f"HTTP {response.status_code}: Модуль cryptography не установлен на узле {node.name}. " \
                               f"Попытка автоматической установки не удалась. " \
                               f"Необходимо установить вручную: pip3 install --user cryptography>=41.0.0 " \
                               f"или переразвернуть агент через SSH."
                logger.error(f"Ошибка отправки обновления на {node.name}: {error_msg}")
                return False, error_msg
        
        except requests.exceptions.Timeout:
            error_msg = f"Timeout при отправке обновления на {node.name}"
            logger.error(error_msg)
            return False, error_msg
        except requests.exceptions.ConnectionError as e:
            error_msg = f"Не удалось подключиться к {node.name} ({vpn_ip}): {str(e)}"
            logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Неожиданная ошибка при отправке обновления на {node.name}: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    except Exception as e:
        logger.error(f"Ошибка в send_software_update_via_vpn для узла {node.name}: {e}", exc_info=True)
        return False, str(e)

