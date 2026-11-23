from pathlib import Path
from typing import Any, Optional
import yaml


class ConfigManager:
    """
    Safely loads API keys and tool settings from config.yaml.
    Prevents crashes if a key is missing or still has a placeholder value.
    """

    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = Path(config_path)
        self.data = self._load_config()

    def _load_config(self) -> dict:
        # Check if config.yaml exists; if not, return empty default structure
        if not self.config_path.exists():
            return {"api_keys": {}, "settings": {"default_depth": 2, "ai_provider": "gemini"}}

        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f)
                return loaded if isinstance(loaded, dict) else {}
        except Exception:
            return {"api_keys": {}, "settings": {}}

    def get_api_key(self, service: str) -> Optional[str]:
        # Fetch the API key for a given service (e.g., 'virustotal', 'hunter_io', 'github', 'gemini')
        api_keys = self.data.get("api_keys", {})
        key = api_keys.get(service)

        # Ignore empty values or default placeholder strings like "YOUR_VIRUSTOTAL_API_KEY"
        if not key or not isinstance(key, str):
            return None
        key = key.strip()
        if key == "" or key.upper().startswith("YOUR_"):
            return None

        return key

    def get_setting(self, key: str, default: Any = None) -> Any:
        # Fetch a general setting from the 'settings' block
        settings = self.data.get("settings", {})
        return settings.get(key, default)