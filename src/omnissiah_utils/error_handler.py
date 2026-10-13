"""
Централизованная обработка ошибок
"""
import logging
import traceback
from functools import wraps
from typing import Callable, Any
from flask import jsonify, current_app

from omnissiah_core.nmc_exceptions import NMCError

logger = logging.getLogger(__name__)


def handle_errors(f: Callable) -> Callable:
    """
    Декоратор для централизованной обработки ошибок
    
    Args:
        f: Функция для обертки
        
    Returns:
        Обернутая функция с обработкой ошибок
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except NMCError as e:
            logger.error(f"{f.__name__}: {e.message}", exc_info=True)
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"{f.__name__}: {e.message}")
            return jsonify({
                'success': False,
                'error': e.message,
                'details': e.details
            }), 400
        except ValueError as e:
            logger.error(f"{f.__name__}: Validation error: {str(e)}", exc_info=True)
            return jsonify({
                'success': False,
                'error': f'Ошибка валидации: {str(e)}'
            }), 400
        except KeyError as e:
            logger.error(f"{f.__name__}: Missing key: {str(e)}", exc_info=True)
            return jsonify({
                'success': False,
                'error': f'Отсутствует обязательное поле: {str(e)}'
            }), 400
        except Exception as e:
            logger.error(
                f"{f.__name__}: Unexpected error: {str(e)}\n{traceback.format_exc()}",
                exc_info=True
            )
            if hasattr(current_app, 'logger'):
                current_app.logger.error(
                    f"{f.__name__}: Unexpected error: {str(e)}",
                    exc_info=True
                )
            return jsonify({
                'success': False,
                'error': 'Внутренняя ошибка сервера',
                'details': str(e) if current_app.config.get('DEBUG') else None
            }), 500
    
    return decorated_function


def safe_execute(func: Callable, *args, default: Any = None, **kwargs) -> Any:
    """
    Безопасное выполнение функции с обработкой ошибок
    
    Args:
        func: Функция для выполнения
        *args: Позиционные аргументы
        default: Значение по умолчанию при ошибке
        **kwargs: Именованные аргументы
        
    Returns:
        Результат функции или default при ошибке
    """
    try:
        return func(*args, **kwargs)
    except Exception as e:
        logger.warning(f"Error in {func.__name__}: {str(e)}")
        return default

