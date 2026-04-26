from __future__ import annotations
import os
from pathlib import Path
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator, model_validator
try:
    from pydantic_settings import BaseSettings
except ImportError:
    from pydantic.env_settings import BaseSettings


class IDAConfig(BaseModel):
    """IDA-related configuration"""
    path: str = Field(..., description="IDA executable file path")
    timeout: float = Field(default=120.0, ge=10.0, le=600.0, description="IDA startup timeout (seconds)")
    headless: bool = Field(default=True, description="Whether to run in headless mode")
    
    @field_validator('path')
    @classmethod
    def validate_ida_path(cls, v):
        path = Path(v)
        if not path.exists():
            raise ValueError(f"IDA path does not exist: {v}")
        if not path.is_file():
            raise ValueError(f"IDA path is not a file: {v}")
        if not os.access(path, os.X_OK):
            raise ValueError(f"IDA file is not executable: {v}")
        return str(path.resolve())


class NetworkConfig(BaseModel):
    """Network-related configuration"""
    host: str = Field(default="127.0.0.1", description="Service listening address")
    port: int = Field(default=20000, ge=1024, le=65535, description="Service listening port")
    worker_timeout: float = Field(default=30.0, ge=5.0, le=300.0, description="Worker timeout (seconds)")
    max_retries: int = Field(default=3, ge=0, le=10, description="Maximum retry count")
    retry_delay: float = Field(default=1.0, ge=0.1, le=10.0, description="Retry delay (seconds)")


class StorageConfig(BaseModel):
    """Storage-related configuration"""
    tmpfs_dir: Optional[str] = Field(default=None, description="Temporary filesystem directory")
    save_midfile: bool = Field(default=True, description="Whether to save intermediate files")
    artifact_patterns: List[str] = Field(
        default=["*.i64", "*.sqlite", "*.idalog"],
        description="File patterns to save"
    )
    prefer_i64: bool = Field(default=True, description="Prefer .i64 files")


class LoggingConfig(BaseModel):
    """Logging-related configuration"""
    level: str = Field(default="INFO", description="Log level")
    format: str = Field(default="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    file: Optional[str] = Field(default=None, description="Log file path")
    max_size: int = Field(default=10 * 1024 * 1024, description="Log file maximum size (bytes)")
    backup_count: int = Field(default=5, description="Log file backup count")
    
    @field_validator('level')
    @classmethod
    def validate_log_level(cls, v):
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if v.upper() not in valid_levels:
            raise ValueError(f"Invalid log level: {v}, valid values: {valid_levels}")
        return v.upper()


class ServiceConfig(BaseSettings):
    """IDA service main configuration"""
    # Sub-configurations
    ida: IDAConfig
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    
    # Environment variable prefix
    class Config:
        env_prefix = "IDA_SERVICE_"
        env_nested_delimiter = "__"
        case_sensitive = False
    
    @model_validator(mode='after')
    def validate_config(self):
        """Global configuration validation"""
        # Check if port is already in use
        import socket
        from contextlib import closing
        
        if self.network:
            with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
                try:
                    s.bind((self.network.host, self.network.port))
                except OSError as e:
                    if e.errno == 98:  # Address already in use
                        raise ValueError(f"Port {self.network.port} is already in use")
                    raise
        
        return self
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ServiceConfig":
        """Create configuration from dictionary"""
        return cls(**data)
    
    @classmethod
    def from_env(cls, **overrides) -> "ServiceConfig":
        """Create configuration from environment variables, supports overrides"""
        # Load base configuration from environment variables
        config_data = {}
        
        # IDA configuration
        ida_path = overrides.get('ida_path') or os.getenv('IDA_PATH')
        if ida_path:
            config_data['ida'] = {'path': ida_path}
        
        # Network configuration
        network_config = {}
        if 'host' in overrides:
            network_config['host'] = overrides['host']
        if 'port' in overrides:
            network_config['port'] = overrides['port']
        if network_config:
            config_data['network'] = network_config
        
        # Storage configuration
        storage_config = {}
        if 'tmpfs_dir' in overrides:
            storage_config['tmpfs_dir'] = overrides['tmpfs_dir']
        if 'save_midfile' in overrides:
            storage_config['save_midfile'] = overrides['save_midfile']
        if storage_config:
            config_data['storage'] = storage_config
        
        return cls(**config_data)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return self.model_dump()
    
    def get_worker_env(self, project_name: str, ida_input: str, log_file: str) -> Dict[str, str]:
        """Get worker environment variables"""
        return {
            "IDA_WORKER_HOST": self.network.host,
            "IDA_WORKER_PORT": str(self.network.port + 1000),  # Worker uses different port
            "IDA_WORKER_NAME": project_name,
            "IDA_WORKER_IDA_INPUT": ida_input,
            "IDA_WORKER_LOG_FILE": log_file,
            "TVHEADLESS": "1" if self.ida.headless else "0",
            "TERM": os.getenv("TERM", "xterm"),
        }
