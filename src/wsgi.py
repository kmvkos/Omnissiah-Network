"""Systemd/Gunicorn entry point; provisioning happens in deploy/bootstrap.py.

Importing this module never runs the legacy system installation or port-killing
scripts. Exactly one Gunicorn worker is used in the supplied service unit.
"""
from app import app, create_dynamic_models, dynamic_user_models, dynamic_info_models, configurations
from nmc_models import General

with app.app_context():
    for node in General.query.all():
        users, info = create_dynamic_models(node.name)
        dynamic_user_models[node.name], dynamic_info_models[node.name] = users, info
        configurations.append(node.name)
