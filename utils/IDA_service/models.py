from __future__ import annotations
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, field_validator
import uuid


class ProjectStatus(str, Enum):
    """Project status enumeration"""
    PENDING = "pending"          # Waiting to start
    STARTING = "starting"        # Starting
    READY = "ready"             # Ready
    BUSY = "busy"               # Busy
    ERROR = "error"             # Error
    CLOSING = "closing"         # Closing
    CLOSED = "closed"           # Closed


class WorkerStatus(str, Enum):
    """Worker status enumeration"""
    UNKNOWN = "unknown"         # Unknown
    STARTING = "starting"       # Starting
    READY = "ready"            # Ready
    BUSY = "busy"              # Busy
    ERROR = "error"            # Error
    CLOSED = "closed"          # Closed


class WorkerInfo(BaseModel):
    """Worker information"""
    host: str = Field(..., description="Worker host address")
    port: int = Field(..., ge=1024, le=65535, description="Worker port")
    pid: int = Field(..., ge=1, description="Worker process ID")
    url: str = Field(..., description="Worker URL")
    status: WorkerStatus = Field(default=WorkerStatus.UNKNOWN, description="Worker status")
    last_health_check: Optional[datetime] = Field(default=None, description="Last health check time")
    error_message: Optional[str] = Field(default=None, description="Error message")
    
    @field_validator('url')
    @classmethod
    def validate_url(cls, v):
        if not v.startswith(('http://', 'https://')):
            raise ValueError("URL must start with http:// or https://")
        return v
    
    @property
    def is_healthy(self) -> bool:
        """Check if worker is healthy"""
        if self.status != WorkerStatus.READY:
            return False
        if self.last_health_check is None:
            return False
        # If no health check for more than 5 minutes, consider unhealthy
        return (datetime.now() - self.last_health_check).total_seconds() < 300


class ProjectInfo(BaseModel):
    """Project information"""
    name: str = Field(..., min_length=1, max_length=100, description="Project name")
    ida_input: Path = Field(..., description="IDA input file path")
    log_file: Path = Field(..., description="Log file path")
    status: ProjectStatus = Field(default=ProjectStatus.PENDING, description="Project status")
    created_at: datetime = Field(default_factory=datetime.now, description="Creation time")
    updated_at: datetime = Field(default_factory=datetime.now, description="Update time")
    worker: Optional[WorkerInfo] = Field(default=None, description="Associated worker")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Metadata")
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        # Project name can only contain letters, numbers, underscores and hyphens
        import re
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError("Project name can only contain letters, numbers, underscores and hyphens")
        return v
    
    @field_validator('ida_input')
    @classmethod
    def validate_ida_input(cls, v):
        if not v.exists():
            raise ValueError(f"IDA input file does not exist: {v}")
        return v
    
    @property
    def is_ready(self) -> bool:
        """Check if project is ready"""
        return (self.status == ProjectStatus.READY and 
                self.worker is not None and 
                self.worker.is_healthy)
    
    def update_status(self, status: ProjectStatus, error_message: Optional[str] = None):
        """Update project status"""
        self.status = status
        self.updated_at = datetime.now()
        if error_message and self.worker:
            self.worker.error_message = error_message
            self.worker.status = WorkerStatus.ERROR


class APIResponse(BaseModel):
    """Unified API response format"""
    success: bool = Field(..., description="Whether request succeeded")
    message: str = Field(default="", description="Response message")
    data: Optional[Dict[str, Any]] = Field(default=None, description="Response data")
    error_code: Optional[str] = Field(default=None, description="Error code")
    timestamp: datetime = Field(default_factory=datetime.now, description="Response time")
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Request ID")
    
    @classmethod
    def success_response(cls, data: Optional[Dict[str, Any]] = None,         message: str = "Operation successful") -> "APIResponse":
        """Create success response"""
        return cls(success=True, message=message, data=data)
    
    @classmethod
    def error_response(cls, message: str, error_code: Optional[str] = None, data: Optional[Dict[str, Any]] = None) -> "APIResponse":
        """Create error response"""
        return cls(success=False, message=message, error_code=error_code, data=data)


class HealthCheck(BaseModel):
    """Health check response"""
    service: str = Field(..., description="Service name")
    status: str = Field(..., description="Service status")
    version: str = Field(default="1.0.0", description="Service version")
    uptime: float = Field(..., description="Uptime (seconds)")
    projects_count: int = Field(default=0, description="Project count")
    healthy_workers: int = Field(default=0, description="Healthy worker count")
    details: Dict[str, Any] = Field(default_factory=dict, description="Details")


class FunctionInfo(BaseModel):
    """Function information"""
    name: str = Field(..., description="Function name")
    ea: str = Field(..., description="Function address")
    size: Optional[int] = Field(default=None, description="Function size")
    segment: Optional[str] = Field(default=None, description="Segment")
    
    @field_validator('ea')
    @classmethod
    def validate_ea(cls, v):
        if not v.startswith('0x'):
            raise ValueError("Address must start with 0x")
        try:
            int(v, 16)
        except ValueError:
            raise ValueError("Invalid hexadecimal address")
        return v


class PseudocodeResponse(BaseModel):
    """Pseudocode response"""
    ea: str = Field(..., description="Function address")
    function_name: Optional[str] = Field(default=None, description="Function name")
    pseudocode: str = Field(..., description="Pseudocode content")
    decompiler_available: bool = Field(..., description="Whether decompiler is available")


class DisassemblyLine(BaseModel):
    """Disassembly line"""
    ea: str = Field(..., description="Instruction address")
    line: str = Field(..., description="Disassembly content")
    
    @field_validator('ea')
    @classmethod
    def validate_ea(cls, v):
        if not v.startswith('0x'):
            raise ValueError("Address must start with 0x")
        return v


class DisassemblyResponse(BaseModel):
    """Disassembly response"""
    start_ea: str = Field(..., description="Start address")
    lines: List[DisassemblyLine] = Field(..., description="Disassembly line list")


class XRefInfo(BaseModel):
    """Cross reference information"""
    from_ea: str = Field(..., description="Reference source address")
    to_ea: str = Field(..., description="Reference target address")
    type: int = Field(..., description="Reference type")
    
    @field_validator('from_ea', 'to_ea')
    @classmethod
    def validate_ea(cls, v):
        if not v.startswith('0x'):
            raise ValueError("Address must start with 0x")
        return v


class XRefResponse(BaseModel):
    """Cross reference response"""
    ea: str = Field(..., description="Target address")
    xrefs: List[XRefInfo] = Field(..., description="Cross reference list")


class ProjectCreateRequest(BaseModel):
    """Create project request"""
    name: str = Field(..., min_length=1, max_length=100, description="Project name")
    ida_input: str = Field(..., description="IDA input file path")
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        import re
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError("Project name can only contain letters, numbers, underscores and hyphens")
        return v


class ProjectListResponse(BaseModel):
    """Project list response"""
    projects: List[ProjectInfo] = Field(..., description="Project list")
    total: int = Field(..., description="Total projects")
    page: int = Field(default=1, description="Current page number")
    page_size: int = Field(default=50, description="Page size")
