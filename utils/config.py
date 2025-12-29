"""
Configuration Management System
Loads and validates YAML configuration
"""

import yaml
import os
from typing import Any, Dict
from pathlib import Path

class Config:
    """
    Configuration manager for RansomGuard.
    Loads settings from YAML file and provides easy access.
    """
    
    def __init__(self, config_path: str = "config.yaml"):
        """
        Initialize configuration manager.
        
        Args:
            config_path: Path to YAML configuration file
        """
        self.config_path = config_path
        self.config_data: Dict[str, Any] = {}
        self.load()
    
    def load(self):
        """Load configuration from YAML file"""
        if not os.path.exists(self.config_path):
            print(f"⚠️ Config file not found: {self.config_path}")
            print("📝 Creating default configuration...")
            self._create_default_config()
        
        try:
            with open(self.config_path, 'r') as f:
                self.config_data = yaml.safe_load(f)
            print(f"✅ Configuration loaded from {self.config_path}")
        except Exception as e:
            print(f"❌ Error loading config: {e}")
            self.config_data = {}
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation.
        
        Example:
            config.get('server.port', 8000)
            config.get('killswitch.enabled', True)
        
        Args:
            key_path: Dot-separated path to config value
            default: Default value if key not found
        
        Returns:
            Configuration value or default
        """
        keys = key_path.split('.')
        value = self.config_data
        
        try:
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key_path: str, value: Any):
        """
        Set configuration value using dot notation.
        
        Args:
            key_path: Dot-separated path to config value
            value: Value to set
        """
        keys = key_path.split('.')
        data = self.config_data
        
        for key in keys[:-1]:
            if key not in data:
                data[key] = {}
            data = data[key]
        
        data[keys[-1]] = value
    
    def save(self):
        """Save current configuration to YAML file"""
        try:
            with open(self.config_path, 'w') as f:
                yaml.dump(self.config_data, f, default_flow_style=False, sort_keys=False)
            print(f"✅ Configuration saved to {self.config_path}")
        except Exception as e:
            print(f"❌ Error saving config: {e}")
    
    def reload(self):
        """Reload configuration from file"""
        self.load()
    
    def _create_default_config(self):
        """Create default configuration file if it doesn't exist"""
        # This will be created automatically when first imported
        pass
    
    # Convenience methods for common settings
    
    @property
    def server_host(self) -> str:
        return self.get('server.host', '127.0.0.1')
    
    @property
    def server_port(self) -> int:
        return self.get('server.port', 8000)
    
    @property
    def killswitch_enabled(self) -> bool:
        return self.get('killswitch.enabled', True)
    
    @property
    def killswitch_threshold(self) -> int:
        return self.get('killswitch.threat_threshold', 75)
    
    @property
    def demo_enabled(self) -> bool:
        return self.get('demo.enabled', True)
    
    @property
    def monitoring_paths(self) -> list:
        return self.get('monitoring.watch_paths', ['data/test_monitoring'])
    
    @property
    def protected_processes(self) -> list:
        return self.get('killswitch.protected_processes', [])
    
    @property
    def suspicious_extensions(self) -> list:
        return self.get('behavioral_analysis.suspicious_extensions', [])
    
    def get_all(self) -> Dict[str, Any]:
        """Get entire configuration dictionary"""
        return self.config_data.copy()
    
    def validate(self) -> bool:
        """
        Validate configuration.
        
        Returns:
            bool: True if valid, False otherwise
        """
        required_keys = [
            'system.name',
            'system.version',
            'server.host',
            'server.port'
        ]
        
        for key in required_keys:
            if self.get(key) is None:
                print(f"❌ Missing required config key: {key}")
                return False
        
        print("✅ Configuration validated successfully")
        return True


# Global config instance
config = Config()
