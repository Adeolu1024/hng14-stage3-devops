import yaml
import os

DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.yaml")

_config = None

def load_config(path=None):
    global _config
    if _config is not None:
        return _config
    path = path or DEFAULT_CONFIG_PATH
    with open(path, "r") as f:
        _config = yaml.safe_load(f)
    return _config

def get(key, default=None):
    cfg = load_config()
    keys = key.split(".")
    val = cfg
    for k in keys:
        if isinstance(val, dict):
            val = val.get(k)
        else:
            return default
    return val if val is not None else default
