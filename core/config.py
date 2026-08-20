"""
Configuration loader for IPTV Checker.
Reads settings from config.json and provides defaults.
"""
import json
import os
import logging

log = logging.getLogger(__name__)

# Default configuration values
DEFAULTS = {
    "threads": 5,
    "timeout": 15,
    "retry_delay": 10,
    "max_proxy_failures": 3,
    "stats_interval": 5,
    "polite_delay": 0.3,
    "backoff_levels": [30, 60, 120],
    "notifications": {
        "enabled": False,
        "telegram_bot_token": "",
        "telegram_chat_id": ""
    }
}



class Config:
    """Centralized configuration manager."""

    def __init__(self, config_path=None):
        self.data = dict(DEFAULTS)
        if config_path is None:
            # Look for config.json in the script's directory
            config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'config.json')

        config_path = os.path.abspath(config_path)
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                self._merge(self.data, user_config)
                log.info(f"📄 Loaded config from {config_path}")
            except (json.JSONDecodeError, Exception) as e:
                log.warning(f"⚠️  Failed to load config.json: {e}. Using defaults.")
        else:
            log.info("📄 No config.json found, using defaults.")

    def _merge(self, base, override):
        """Deep merge override into base dict."""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge(base[key], value)
            else:
                base[key] = value

    @property
    def threads(self):
        return self.data["threads"]

    @threads.setter
    def threads(self, value):
        self.data["threads"] = value

    @property
    def timeout(self):
        return self.data["timeout"]

    @property
    def retry_delay(self):
        return self.data["retry_delay"]

    @property
    def max_proxy_failures(self):
        return self.data["max_proxy_failures"]

    @property
    def stats_interval(self):
        return self.data["stats_interval"]

    @property
    def polite_delay(self):
        return self.data["polite_delay"]

    @property
    def backoff_levels(self):
        return self.data["backoff_levels"]

    @property
    def notifications(self):
        return self.data["notifications"]

    @property
    def telegram_enabled(self):
        notif = self.data.get("notifications", {})
        return (notif.get("enabled", False) and
                notif.get("telegram_bot_token", "") and
                notif.get("telegram_chat_id", ""))

    @property
    def telegram_bot_token(self):
        return self.data.get("notifications", {}).get("telegram_bot_token", "")

    @property
    def telegram_chat_id(self):
        return self.data.get("notifications", {}).get("telegram_chat_id", "")
