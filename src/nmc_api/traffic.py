"""
API Blueprint для работы с трафиком
"""
from flask import Blueprint, jsonify, request, current_app
from werkzeug.exceptions import BadRequest
from datetime import datetime, timezone
import sys
from pathlib import Path

# Добавляем путь к src для импорта
src_path = Path(__file__).parent.parent
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from nmc_models import db, General, TrafficLog

traffic_bp = Blueprint('traffic_api', __name__, url_prefix='/api')


@traffic_bp.route('/traffic_log/clear', methods=['POST'])
def clear_traffic_log():
    """Очистить журнал трафика"""
    try:
        # Безопасное получение JSON, если запрос пустой или без Content-Type
        try:
            data = request.get_json(force=True) or {}
        except (BadRequest, ValueError, TypeError):
            # Если JSON не может быть распарсен, используем пустой словарь
            data = {}
        
        node_id = data.get('node_id')
        
        if node_id:
            # Очищаем для конкретного узла
            deleted = TrafficLog.query.filter_by(node_id=node_id).delete()
        else:
            # Очищаем все
            deleted = TrafficLog.query.delete()
        
        db.session.commit()
        
        current_app.logger.info(f"Очищено записей трафика: {deleted}")
        return jsonify({'success': True, 'deleted': deleted}), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Ошибка очистки трафика: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@traffic_bp.route('/report_traffic', methods=['POST'])
def report_traffic():
    """
    API endpoint для приема данных трафика от удаленных узлов (Magos, Cognitor)
    """
    try:
        data = request.get_json() or {}
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
                current_app.logger.warning(f"Ошибка сохранения записи трафика: {e}")
                continue
        
        db.session.commit()
        current_app.logger.info(f"✅ Принято {saved_count} записей трафика от {node_name}")
        
        return jsonify({
            'success': True,
            'message': f'Saved {saved_count} traffic logs',
            'saved_count': saved_count
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Ошибка обработки отчета трафика: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

