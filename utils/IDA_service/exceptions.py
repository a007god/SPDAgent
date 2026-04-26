from __future__ import annotations
from typing import Optional, Dict, Any
from enum import Enum


class ErrorCode(str, Enum):
    """Error code enumeration"""
    # General errors
    UNKNOWN_ERROR = "UNKNOWN_ERROR"
    INVALID_REQUEST = "INVALID_REQUEST"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    
    # Project-related errors
    PROJECT_NOT_FOUND = "PROJECT_NOT_FOUND"
    PROJECT_ALREADY_EXISTS = "PROJECT_ALREADY_EXISTS"
    PROJECT_INVALID_STATE = "PROJECT_INVALID_STATE"
    PROJECT_CREATION_FAILED = "PROJECT_CREATION_FAILED"
    PROJECT_DELETION_FAILED = "PROJECT_DELETION_FAILED"
    
    # Worker-related errors
    WORKER_NOT_FOUND = "WORKER_NOT_FOUND"
    WORKER_NOT_READY = "WORKER_NOT_READY"
    WORKER_COMMUNICATION_ERROR = "WORKER_COMMUNICATION_ERROR"
    WORKER_LAUNCH_FAILED = "WORKER_LAUNCH_FAILED"
    WORKER_TIMEOUT = "WORKER_TIMEOUT"
    
    # IDA-related errors
    IDA_NOT_FOUND = "IDA_NOT_FOUND"
    IDA_LAUNCH_FAILED = "IDA_LAUNCH_FAILED"
    IDA_ANALYSIS_FAILED = "IDA_ANALYSIS_FAILED"
    IDA_DECOMPILER_UNAVAILABLE = "IDA_DECOMPILER_UNAVAILABLE"
    
    # File system errors
    FILE_NOT_FOUND = "FILE_NOT_FOUND"
    FILE_ACCESS_DENIED = "FILE_ACCESS_DENIED"
    FILE_INVALID_FORMAT = "FILE_INVALID_FORMAT"
    DIRECTORY_NOT_FOUND = "DIRECTORY_NOT_FOUND"
    
    # Network errors
    NETWORK_ERROR = "NETWORK_ERROR"
    CONNECTION_TIMEOUT = "CONNECTION_TIMEOUT"
    PORT_ALREADY_IN_USE = "PORT_ALREADY_IN_USE"
    
    # Configuration errors
    CONFIG_INVALID = "CONFIG_INVALID"
    CONFIG_MISSING = "CONFIG_MISSING"
    
    # Resource errors
    RESOURCE_EXHAUSTED = "RESOURCE_EXHAUSTED"
    RESOURCE_LOCKED = "RESOURCE_LOCKED"


class IDAServiceException(Exception):
    """IDA service base exception class"""
    
    def __init__(
        self,
        message: str,
        error_code: ErrorCode = ErrorCode.UNKNOWN_ERROR,
        details: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        self.cause = cause
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format"""
        return {
            "error_code": self.error_code.value,
            "message": self.message,
            "details": self.details,
            "cause": str(self.cause) if self.cause else None
        }


class ProjectException(IDAServiceException):
    """Project-related exception"""
    pass


class ProjectNotFoundError(ProjectException):
    """Project not found exception"""
    
    def __init__(self, project_name: str):
        super().__init__(
            message=f"Project does not exist: {project_name}",
            error_code=ErrorCode.PROJECT_NOT_FOUND,
            details={"project_name": project_name}
        )


class ProjectAlreadyExistsError(ProjectException):
    """Project already exists exception"""
    
    def __init__(self, project_name: str):
        super().__init__(
            message=f"Project already exists: {project_name}",
            error_code=ErrorCode.PROJECT_ALREADY_EXISTS,
            details={"project_name": project_name}
        )


class ProjectInvalidStateError(ProjectException):
    """Project invalid state exception"""
    
    def __init__(self, project_name: str, current_state: str, expected_states: list[str]):
        super().__init__(
            message=f"Project state invalid: {project_name} (current: {current_state}, expected: {expected_states})",
            error_code=ErrorCode.PROJECT_INVALID_STATE,
            details={
                "project_name": project_name,
                "current_state": current_state,
                "expected_states": expected_states
            }
        )


class WorkerException(IDAServiceException):
    """Worker-related exception"""
    pass


class WorkerNotFoundError(WorkerException):
    """Worker not found exception"""
    
    def __init__(self, project_name: str):
        super().__init__(
            message=f"Worker does not exist: {project_name}",
            error_code=ErrorCode.WORKER_NOT_FOUND,
            details={"project_name": project_name}
        )


class WorkerNotReadyError(WorkerException):
    """Worker not ready exception"""
    
    def __init__(self, project_name: str, reason: str = ""):
        super().__init__(
            message=f"Worker not ready: {project_name}" + (f" - {reason}" if reason else ""),
            error_code=ErrorCode.WORKER_NOT_READY,
            details={"project_name": project_name, "reason": reason}
        )


class WorkerCommunicationError(WorkerException):
    """Worker communication exception"""
    
    def __init__(self, project_name: str, operation: str, cause: Optional[Exception] = None):
        super().__init__(
            message=f"Worker communication failed: {project_name} - {operation}",
            error_code=ErrorCode.WORKER_COMMUNICATION_ERROR,
            details={"project_name": project_name, "operation": operation},
            cause=cause
        )


class WorkerLaunchError(WorkerException):
    """Worker launch exception"""
    
    def __init__(self, project_name: str, ida_input: str, cause: Optional[Exception] = None):
        super().__init__(
            message=f"Worker launch failed: {project_name}",
            error_code=ErrorCode.WORKER_LAUNCH_FAILED,
            details={"project_name": project_name, "ida_input": ida_input},
            cause=cause
        )


class WorkerTimeoutError(WorkerException):
    """Worker timeout exception"""
    
    def __init__(self, project_name: str, timeout: float, operation: str = ""):
        super().__init__(
            message=f"Worker timeout: {project_name} (timeout: {timeout}s)" + (f" - {operation}" if operation else ""),
            error_code=ErrorCode.WORKER_TIMEOUT,
            details={"project_name": project_name, "timeout": timeout, "operation": operation}
        )


class IDAException(IDAServiceException):
    """IDA-related exception"""
    pass


class IDANotFoundError(IDAException):
    """IDA not found exception"""
    
    def __init__(self, ida_path: str):
        super().__init__(
            message=f"IDA executable not found: {ida_path}",
            error_code=ErrorCode.IDA_NOT_FOUND,
            details={"ida_path": ida_path}
        )


class IDALaunchError(IDAException):
    """IDA launch exception"""
    
    def __init__(self, ida_input: str, cause: Optional[Exception] = None):
        super().__init__(
            message=f"IDA launch failed: {ida_input}",
            error_code=ErrorCode.IDA_LAUNCH_FAILED,
            details={"ida_input": ida_input},
            cause=cause
        )


class IDAAnalysisError(IDAException):
    """IDA analysis exception"""
    
    def __init__(self, project_name: str, operation: str, cause: Optional[Exception] = None):
        super().__init__(
            message=f"IDA analysis failed: {project_name} - {operation}",
            error_code=ErrorCode.IDA_ANALYSIS_FAILED,
            details={"project_name": project_name, "operation": operation},
            cause=cause
        )


class IDADecompilerUnavailableError(IDAException):
    """IDA decompiler unavailable exception"""
    
    def __init__(self, project_name: str):
        super().__init__(
            message=f"IDA decompiler unavailable: {project_name}",
            error_code=ErrorCode.IDA_DECOMPILER_UNAVAILABLE,
            details={"project_name": project_name}
        )


class FileSystemException(IDAServiceException):
    """File system-related exception"""
    pass


class FileNotFoundError(FileSystemException):
    """File not found exception"""
    
    def __init__(self, file_path: str):
        super().__init__(
            message=f"File does not exist: {file_path}",
            error_code=ErrorCode.FILE_NOT_FOUND,
            details={"file_path": file_path}
        )


class FileAccessDeniedError(FileSystemException):
    """File access denied exception"""
    
    def __init__(self, file_path: str, operation: str = "access"):
        super().__init__(
            message=f"File access denied: {file_path} - {operation}",
            error_code=ErrorCode.FILE_ACCESS_DENIED,
            details={"file_path": file_path, "operation": operation}
        )


class FileInvalidFormatError(FileSystemException):
    """File format invalid exception"""
    
    def __init__(self, file_path: str, expected_format: str = ""):
        super().__init__(
            message=f"File format invalid: {file_path}" + (f" (expected format: {expected_format})" if expected_format else ""),
            error_code=ErrorCode.FILE_INVALID_FORMAT,
            details={"file_path": file_path, "expected_format": expected_format}
        )


class NetworkException(IDAServiceException):
    """Network-related exception"""
    pass


class NetworkError(NetworkException):
    """Network error exception"""
    
    def __init__(self, operation: str, cause: Optional[Exception] = None):
        super().__init__(
            message=f"Network error: {operation}",
            error_code=ErrorCode.NETWORK_ERROR,
            details={"operation": operation},
            cause=cause
        )


class ConnectionTimeoutError(NetworkException):
    """Connection timeout exception"""
    
    def __init__(self, host: str, port: int, timeout: float):
        super().__init__(
            message=f"Connection timeout: {host}:{port} (timeout: {timeout}s)",
            error_code=ErrorCode.CONNECTION_TIMEOUT,
            details={"host": host, "port": port, "timeout": timeout}
        )


class PortAlreadyInUseError(NetworkException):
    """Port already in use exception"""
    
    def __init__(self, port: int):
        super().__init__(
            message=f"Port already in use: {port}",
            error_code=ErrorCode.PORT_ALREADY_IN_USE,
            details={"port": port}
        )


class ConfigException(IDAServiceException):
    """Configuration-related exception"""
    pass


class ConfigInvalidError(ConfigException):
    """Configuration invalid exception"""
    
    def __init__(self, config_key: str, value: Any, reason: str = ""):
        super().__init__(
            message=f"Configuration invalid: {config_key} = {value}" + (f" - {reason}" if reason else ""),
            error_code=ErrorCode.CONFIG_INVALID,
            details={"config_key": config_key, "value": value, "reason": reason}
        )


class ConfigMissingError(ConfigException):
    """Configuration missing exception"""
    
    def __init__(self, config_key: str):
        super().__init__(
            message=f"Configuration missing: {config_key}",
            error_code=ErrorCode.CONFIG_MISSING,
            details={"config_key": config_key}
        )


class ResourceException(IDAServiceException):
    """Resource-related exception"""
    pass


class ResourceExhaustedError(ResourceException):
    """Resource exhausted exception"""
    
    def __init__(self, resource_type: str, current: int, limit: int):
        super().__init__(
            message=f"Resource exhausted: {resource_type} (current: {current}, limit: {limit})",
            error_code=ErrorCode.RESOURCE_EXHAUSTED,
            details={"resource_type": resource_type, "current": current, "limit": limit}
        )


class ResourceLockedError(ResourceException):
    """Resource locked exception"""
    
    def __init__(self, resource_type: str, resource_id: str):
        super().__init__(
            message=f"Resource locked: {resource_type} - {resource_id}",
            error_code=ErrorCode.RESOURCE_LOCKED,
            details={"resource_type": resource_type, "resource_id": resource_id}
        )
