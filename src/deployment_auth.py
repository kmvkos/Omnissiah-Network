"""Identity checks for backends exposed only through the managed nginx proxy."""
import os

from flask import jsonify, request
from flask_login import current_user


from proxy_identity import proxy_identity


def install_management_auth(app):
    @app.get('/health')
    def deployment_health():
        from nmc_models import db
        from sqlalchemy import text
        db.session.execute(text("SELECT 1"))
        return jsonify(status="ok", component="Omnissiah")

    @app.before_request
    def require_management_identity():
        if os.getenv("OMNISSIAH_REQUIRE_MTLS", "false").lower() != "true":
            return None
        if not request.path.startswith('/api/'):
            return None
        # Agent routes always require a certificate, even for a logged-in admin.
        agent_route = request.path in (
            '/api/heartbeat', '/api/magos/heartbeat', '/api/nodes/register_key',
            '/api/report_traffic', '/api/magos/ack', '/api/config_feedback',
        )
        identity = proxy_identity()
        if agent_route:
            if not identity:
                return jsonify(error="Client certificate required"), 401
            from nmc_models import General
            node = General.query.filter_by(name=identity, role='Magos').first()
            data = request.get_json(silent=True) or {}
            if not isinstance(data, dict):
                return jsonify(error="JSON object required"), 400
            claimed = data.get('name') or data.get('node_name')
            if node is None or claimed != identity:
                return jsonify(error="Certificate does not identify this node"), 403
            return None
        # Other API routes retain the existing authenticated web workflow.
        if not current_user.is_authenticated:
            return jsonify(error="Login required"), 401
        return None
