from __future__ import annotations
import os
import signal
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, List
import requests
from contextlib import closing
import socket

from ..models import ProjectInfo, ProjectStatus, WorkerStatus, WorkerInfo
from ..exceptions import (
    ProjectNotFoundError, ProjectAlreadyExistsError, ProjectInvalidStateError,
    WorkerLaunchError, WorkerTimeoutError, WorkerCommunicationError,
    FileNotFoundError, PortAlreadyInUseError
)
from ..config import ServiceConfig
from ...logging_helper import global_logger


class ProjectManager:
    """Project manager - responsible for project lifecycle management"""
    
    def __init__(self, config: ServiceConfig):
        self.config = config
        self._projects: Dict[str, ProjectInfo] = {}
        self._lock = {}  # Project locks to prevent concurrent operations
    
    def create_project(self, name: str, ida_input: str) -> ProjectInfo:
        """Create new project"""
        if name in self._projects:
            raise ProjectAlreadyExistsError(name)
        
        ida_input_path = Path(ida_input)
        if not ida_input_path.exists():
            raise FileNotFoundError(str(ida_input_path))
        
        # Generate log file path
        if ida_input_path.suffix.lower() == ".i64":
            stem_name = ida_input_path.stem
        else:
            stem_name = ida_input_path.name
        
        log_file = ida_input_path.parent / f"{stem_name}.agentlog"
        
        # Create project info
        project = ProjectInfo(
            name=name,
            ida_input=ida_input_path,
            log_file=log_file,
            status=ProjectStatus.PENDING
        )
        
        self._projects[name] = project
        global_logger.info(f"Project created: {name}")
        return project
    
    def get_project(self, name: str) -> ProjectInfo:
        """Get project info"""
        if name not in self._projects:
            raise ProjectNotFoundError(name)
        return self._projects[name]
    
    def list_projects(self, status_filter: Optional[ProjectStatus] = None) -> List[ProjectInfo]:
        """List projects"""
        projects = list(self._projects.values())
        if status_filter:
            projects = [p for p in projects if p.status == status_filter]
        return projects
    
    def update_project_status(self, name: str, status: ProjectStatus, error_message: Optional[str] = None):
        """Update project status"""
        project = self.get_project(name)
        project.update_status(status, error_message)
        global_logger.info(f"Project status updated: {name} -> {status}")
    
    def delete_project(self, name: str) -> bool:
        """Delete project"""
        if name not in self._projects:
            return False
        
        project = self._projects[name]
        
        # If project has associated worker, close worker first
        if project.worker:
            try:
                self._close_worker(project)
            except Exception as e:
                global_logger.warning(f"Failed to close worker: {name} - {e}")
        
        # Delete project
        del self._projects[name]
        global_logger.info(f"Project deleted: {name}")
        return True
    
    def start_worker(self, name: str) -> ProjectInfo:
        """Start project worker"""
        project = self.get_project(name)
        
        if project.status not in [ProjectStatus.PENDING, ProjectStatus.ERROR]:
            raise ProjectInvalidStateError(
                name, 
                project.status.value, 
                [ProjectStatus.PENDING.value, ProjectStatus.ERROR.value]
            )
        
        try:
            # Update status to starting
            self.update_project_status(name, ProjectStatus.STARTING)
            
            # Start worker
            worker = self._launch_worker(project)
            project.worker = worker
            
            # Wait for worker to be ready
            self._wait_for_worker_ready(project)
            
            # Update status to ready
            self.update_project_status(name, ProjectStatus.READY)
            
            global_logger.info(f"Worker started: {name}")
            return project
            
        except Exception as e:
            self.update_project_status(name, ProjectStatus.ERROR, str(e))
            raise WorkerLaunchError(name, str(project.ida_input), e)
    
    def stop_worker(self, name: str) -> bool:
        """Stop project worker"""
        project = self.get_project(name)
        
        if not project.worker:
            return True
        
        try:
            self._close_worker(project)
            project.worker = None
            self.update_project_status(name, ProjectStatus.CLOSED)
            global_logger.info(f"Worker stopped: {name}")
            return True
        except Exception as e:
            global_logger.error(f"Failed to stop worker: {name} - {e}")
            return False
    
    def check_worker_health(self, name: str) -> bool:
        """Check worker health status"""
        project = self.get_project(name)
        
        if not project.worker:
            return False
        
        try:
            response = requests.get(
                f"{project.worker.url}/health",
                timeout=self.config.network.worker_timeout
            )
            
            if response.ok:
                data = response.json()
                is_ready = data.get("ready", False)
                project.worker.status = WorkerStatus.READY if is_ready else WorkerStatus.ERROR
                project.worker.last_health_check = datetime.now()
                return is_ready
            else:
                project.worker.status = WorkerStatus.ERROR
                return False
                
        except Exception as e:
            project.worker.status = WorkerStatus.ERROR
            project.worker.error_message = str(e)
            global_logger.warning(f"Worker health check failed: {name} - {e}")
            return False
    
    def _launch_worker(self, project: ProjectInfo) -> WorkerInfo:
        """Launch worker process"""
        # Select worker port
        worker_port = self._pick_free_port()
        worker_host = self.config.network.host
        
        # Prepare environment variables
        env = os.environ.copy()
        worker_env = self.config.get_worker_env(
            project.name,
            str(project.ida_input),
            str(project.log_file)
        )
        env.update(worker_env)
        env.update({
            "IDA_WORKER_HOST": worker_host,
            "IDA_WORKER_PORT": str(worker_port),
        })
        
        # Launch IDA process
        worker_script = Path(__file__).parent.parent / "ida_worker.py"
        cmd = [
            self.config.ida.path,
            "-A",  # Auto analysis
            f"-L{project.log_file}",  # Log file
            f"-S{worker_script}",  # Script file
            str(project.ida_input),  # Input file
        ]
        
        import subprocess
        proc = subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        worker_url = f"http://{worker_host}:{worker_port}"
        
        return WorkerInfo(
            host=worker_host,
            port=worker_port,
            pid=proc.pid,
            url=worker_url,
            status=WorkerStatus.STARTING
        )
    
    def _wait_for_worker_ready(self, project: ProjectInfo):
        """Wait for worker to be ready"""
        if not project.worker:
            raise WorkerLaunchError(project.name, str(project.ida_input))
        
        deadline = time.time() + self.config.ida.timeout
        last_error = None
        
        while time.time() < deadline:
            try:
                response = requests.get(
                    f"{project.worker.url}/health",
                    timeout=1.5
                )
                
                if response.ok:
                    data = response.json()
                    if data.get("ready", False):
                        project.worker.status = WorkerStatus.READY
                        project.worker.last_health_check = datetime.now()
                        return
                
            except Exception as e:
                last_error = str(e)
            
            time.sleep(0.6)
        
        # Timeout, terminate process
        try:
            os.kill(project.worker.pid, signal.SIGTERM)
        except Exception:
            pass
        
        raise WorkerTimeoutError(
            project.name,
            self.config.ida.timeout,
            f"Worker startup timeout: {last_error}"
        )
    
    def _close_worker(self, project: ProjectInfo):
        """Close worker"""
        if not project.worker:
            return
        
        try:
            # Try graceful shutdown
            response = requests.post(
                f"{project.worker.url}/close",
                timeout=10
            )
            if not response.ok:
                raise Exception(f"HTTP {response.status_code}")
                
        except Exception as e:
            global_logger.warning(f"Graceful shutdown failed, force termination: {project.name} - {e}")
            try:
                os.kill(project.worker.pid, signal.SIGTERM)
            except Exception:
                pass
    
    def _pick_free_port(self) -> int:
        """Pick a free port"""
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.bind((self.config.network.host, 0))
            return s.getsockname()[1]
    
    def cleanup_all(self):
        """Cleanup all projects"""
        for name in list(self._projects.keys()):
            try:
                self.stop_worker(name)
                self.delete_project(name)
            except Exception as e:
                global_logger.error(f"Failed to cleanup project: {name} - {e}")
    
    def get_stats(self) -> Dict[str, int]:
        """Get project statistics"""
        total = len(self._projects)
        ready = sum(1 for p in self._projects.values() if p.status == ProjectStatus.READY)
        error = sum(1 for p in self._projects.values() if p.status == ProjectStatus.ERROR)
        healthy_workers = sum(1 for p in self._projects.values() if p.worker and p.worker.is_healthy)
        
        return {
            "total_projects": total,
            "ready_projects": ready,
            "error_projects": error,
            "healthy_workers": healthy_workers
        }
