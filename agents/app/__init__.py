from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os
from pathlib import Path

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    
    # Определяем путь к базе данных относительно расположения файла __init__.py
    # Это гарантирует правильный путь независимо от того, откуда запускается скрипт
    base_dir = Path(__file__).parent.parent  # Директория NMC_WGr
    database_dir = Path(os.getenv('OMNISSIAH_AGENT_STATE_DIR', str(base_dir / "database")))
    database_dir.mkdir(parents=True, exist_ok=True)
    
    # Используем абсолютный путь к базе данных
    database_path = database_dir / "retra.db"
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{database_path.absolute()}'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    return app
