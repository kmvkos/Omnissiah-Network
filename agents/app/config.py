import json
import os
from pathlib import Path

CONFIG_PATH = Path(__file__).parent.parent / "setup" / "bootstrap_config.json"

def load_config():
    path = Path(os.getenv('OMNISSIAH_AGENT_CONFIG', str(CONFIG_PATH)))
    with open(path, 'r') as f:
        return json.load(f)
