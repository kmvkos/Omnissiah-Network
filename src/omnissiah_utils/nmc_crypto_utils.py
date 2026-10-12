"""
Модуль для шифрования конфигураций и данных при передаче по VPN
Использует Fernet (symmetric encryption) для шифрования данных
"""
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


class ConfigEncryptor:
    """
    Класс для шифрования/расшифровки конфигураций
    
    Использует симметричное шифрование Fernet на основе пароля.
    Пароль может быть производным от общих ключей узлов (например, preshared key).
    """
    
    def __init__(self, password: bytes = None):
        """
        Инициализация шифровальщика
        
        Args:
            password: Пароль для генерации ключа. Если None, используется системный ключ.
        """
        if password is None:
            # Используем системный ключ из переменной окружения или генерируем новый
            password = os.environ.get('NMC_ENCRYPTION_KEY', '').encode()
            if not password:
                # Генерируем ключ из системного секрета (можно использовать preshared key узла)
                # ВАЖНО: Этот ключ должен быть одинаковым на Omnissiah и Magos!
                password = self._generate_default_key()
        
        # Генерируем ключ Fernet из пароля
        self.fernet_key = self._derive_key(password)
        self.cipher = Fernet(self.fernet_key)
    
    @staticmethod
    def _generate_default_key():
        """
        Генерирует ключ по умолчанию.
        В реальной системе должен использовать preshared key или другой общий секрет узлов.
        """
        # TODO: Интегрировать с preshared key из WireGuard конфигурации
        default_key = b'nmc-default-encryption-key-change-in-production'
        return default_key
    
    @staticmethod
    def _derive_key(password: bytes, salt: bytes = None) -> bytes:
        """
        Производный ключ из пароля используя PBKDF2
        
        Args:
            password: Пароль
            salt: Соль (если None, используется фиксированная соль)
        
        Returns:
            Ключ Fernet (32 байта, base64)
        """
        if salt is None:
            # Используем фиксированную соль для консистентности
            # В продакшене лучше использовать динамическую соль
            salt = b'nmc-salt-v1-2025'  # TODO: Использовать preshared key как соль
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key
    
    def encrypt(self, data: bytes) -> bytes:
        """
        Шифрует данные
        
        Args:
            data: Исходные данные (bytes)
        
        Returns:
            Зашифрованные данные (bytes)
        """
        return self.cipher.encrypt(data)
    
    def decrypt(self, encrypted_data: bytes) -> bytes:
        """
        Расшифровывает данные
        
        Args:
            encrypted_data: Зашифрованные данные (bytes)
        
        Returns:
            Расшифрованные данные (bytes)
        """
        return self.cipher.decrypt(encrypted_data)
    
    def encrypt_json(self, data: dict) -> bytes:
        """
        Шифрует JSON данные
        
        Args:
            data: Словарь с данными
        
        Returns:
            Зашифрованные данные (bytes)
        """
        import json
        json_str = json.dumps(data, ensure_ascii=False)
        return self.encrypt(json_str.encode('utf-8'))
    
    def decrypt_json(self, encrypted_data: bytes) -> dict:
        """
        Расшифровывает JSON данные
        
        Args:
            encrypted_data: Зашифрованные данные (bytes)
        
        Returns:
            Словарь с данными
        """
        import json
        decrypted = self.decrypt(encrypted_data)
        return json.loads(decrypted.decode('utf-8'))
    
    def encrypt_file(self, file_path: str, output_path: str = None):
        """
        Шифрует файл
        
        Args:
            file_path: Путь к исходному файлу
            output_path: Путь для сохранения зашифрованного файла (если None, добавляется .enc)
        """
        if output_path is None:
            output_path = file_path + '.enc'
        
        with open(file_path, 'rb') as f:
            data = f.read()
        
        encrypted = self.encrypt(data)
        
        with open(output_path, 'wb') as f:
            f.write(encrypted)
    
    def decrypt_file(self, encrypted_path: str, output_path: str = None):
        """
        Расшифровывает файл
        
        Args:
            encrypted_path: Путь к зашифрованному файлу
            output_path: Путь для сохранения расшифрованного файла
        """
        if output_path is None:
            output_path = encrypted_path.replace('.enc', '')
        
        with open(encrypted_path, 'rb') as f:
            encrypted = f.read()
        
        decrypted = self.decrypt(encrypted)
        
        with open(output_path, 'wb') as f:
            f.write(decrypted)


def get_node_encryptor(node, app=None):
    """
    Создает шифровальщик для конкретного узла
    
    Использует preshared key узла как пароль для шифрования.
    Это гарантирует, что только узел с соответствующим ключом сможет расшифровать данные.
    
    Args:
        node: Объект General (узел)
        app: Flask приложение (для доступа к БД)
    
    Returns:
        ConfigEncryptor instance
    """
    # Используем preshared key как пароль (если есть)
    password = None
    if hasattr(node, 'preshared_key') and node.preshared_key:
        password = node.preshared_key.encode('utf-8')
    else:
        # Fallback: используем public key узла
        if hasattr(node, 'public_key') and node.public_key:
            password = node.public_key.encode('utf-8')
    
    return ConfigEncryptor(password)


def encrypt_config_for_node(config_data: dict, node, app=None) -> bytes:
    """
    Шифрует конфигурацию для конкретного узла
    
    Args:
        config_data: Словарь с конфигурацией
        node: Объект узла
        app: Flask приложение
    
    Returns:
        Зашифрованные данные (bytes)
    """
    encryptor = get_node_encryptor(node, app)
    return encryptor.encrypt_json(config_data)


def decrypt_config_from_node(encrypted_data: bytes, node, app=None) -> dict:
    """
    Расшифровывает конфигурацию от конкретного узла
    
    Args:
        encrypted_data: Зашифрованные данные
        node: Объект узла
        app: Flask приложение
    
    Returns:
        Словарь с конфигурацией
    """
    encryptor = get_node_encryptor(node, app)
    return encryptor.decrypt_json(encrypted_data)

