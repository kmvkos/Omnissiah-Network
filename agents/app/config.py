import json
from pathlib import Path

CONFIG_PATH = Path(__file__).parent.parent / "setup" / "bootstrap_config.json"

def load_config():
    with open(CONFIG_PATH, 'r') as f:
        return json.load(f)