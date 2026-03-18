# Developed by Galal Noaman – RedShadow_V2
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.

# RedShadow_v2/modules/utils.py

import yaml
import os
from termcolor import cprint

# ─── Internal Cache ───
_config_cache = None

def load_config(path="config.yaml", section=None, verbose=True, force_reload=False):
    """
    Loads YAML configuration file and returns the full config or a specific section.
    Uses an internal cache unless force_reload=True is set.

    Args:
        path (str): Path to YAML config file.
        section (str): Optional section to extract from the config.
        verbose (bool): Print status messages.
        force_reload (bool): Bypass cache and reload fresh.

    Returns:
        dict: Entire config or specific section (default: entire config)
    """
    global _config_cache
    default_config = {}

    # Reload if forced or never loaded
    if _config_cache is not None and not force_reload:
        return _config_cache.get(section, {}) if section else _config_cache

    # Fallback if missing file
    if not os.path.exists(path):
        if verbose:
            cprint(f"[!] Warning: Config file not found at {path}. Using default settings.", "yellow")
        _config_cache = default_config
        return default_config if section is None else default_config.get(section, {})

    try:
        with open(path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}
            if not isinstance(config, dict):
                raise ValueError("Invalid YAML format: top-level structure must be a dictionary.")

            _config_cache = config
            if verbose:
                cprint(f"[✓] Loaded config from {path}", "green")
            return config.get(section, {}) if section else config

    except yaml.YAMLError as parse_err:
        cprint(f"[!] YAML parse error in {path}: {parse_err}", "red")
    except Exception as e:
        cprint(f"[!] Failed to load config from {path}: {e}", "red")

    _config_cache = default_config
    return default_config if section is None else default_config.get(section, {})
