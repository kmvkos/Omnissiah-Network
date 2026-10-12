"""
API Blueprint для работы с peers (клиентами)
"""
from flask import Blueprint, jsonify, request, current_app
import sys
from pathlib import Path

# Добавляем путь к src для импорта
src_path = Path(__file__).parent.parent
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from nmc_models import db, General

peers_bp = Blueprint('peers_api', __name__, url_prefix='/api')


@peers_bp.route('/ack_peer', methods=['POST'])
def ack_peer():
    """Подтверждение добавления peer от Magos"""
    try:
        data = request.get_json()
        cognitor_name = data.get('cognitor_name') or data.get('child_name')
        
        if not cognitor_name:
            return jsonify({'error': 'cognitor_name is required'}), 400
        
        cognitor = General.query.filter_by(name=cognitor_name).first()
        if not cognitor:
            return jsonify({'error': 'Cognitor not found'}), 404
        
        cognitor.ack_from_magos = 1
        db.session.commit()
        
        return jsonify({'success': True}), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Ошибка ack_peer: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@peers_bp.route('/ack_remove_peer', methods=['POST'])
def ack_remove_peer():
    """Подтверждение удаления peer от Magos"""
    try:
        data = request.json
        cognitor_name = data.get('cognitor_name') or data.get('child_name')
        
        if not cognitor_name:
            return jsonify({'error': 'cognitor_name is required'}), 400
        
        cognitor = General.query.filter_by(name=cognitor_name, role='Cognitor').first()
        if not cognitor:
            return jsonify({'error': 'Cognitor not found'}), 404
        
        # Помечаем как удаленный
        cognitor.ack_from_magos = 2
        db.session.commit()
        
        # Физически удаляем из БД
        db.session.delete(cognitor)
        db.session.commit()
        
        current_app.logger.info(f"✅ Cognitor {cognitor_name} удалён из БД после ack от Magos")
        return jsonify({'success': True}), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Ошибка ack_remove_peer: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

