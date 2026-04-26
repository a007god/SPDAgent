from __future__ import annotations
import time
from typing import List, Dict, Any, Optional
import requests

from ..models import ProjectInfo, FunctionInfo, PseudocodeResponse, DisassemblyResponse, XRefResponse, WorkerStatus, ProjectStatus
from ..exceptions import (
    WorkerNotReadyError, WorkerCommunicationError, IDAAnalysisError,
    IDADecompilerUnavailableError
)
from ..config import ServiceConfig
from ...logging_helper import global_logger


class WorkerService:
    """Worker service - responsible for communication with IDA workers"""
    
    def __init__(self, config: ServiceConfig):
        self.config = config
    
    def list_functions(self, project: ProjectInfo, query: str = "") -> List[FunctionInfo]:
        """List functions"""
        self._ensure_worker_ready(project)
        
        try:
            response = requests.get(
                f"{project.worker.url}/functions",
                params={"q": query},
                timeout=self.config.network.worker_timeout
            )
            response.raise_for_status()
            
            data = response.json()
            functions = data.get("functions", [])
            
            return [
                FunctionInfo(
                    name=func["name"],
                    ea=func["ea"],
                    size=func.get("size"),
                    segment=func.get("segment")
                )
                for func in functions
            ]
            
        except requests.exceptions.RequestException as e:
            raise WorkerCommunicationError(project.name, "list_functions", e)
        except Exception as e:
            raise IDAAnalysisError(project.name, "list_functions", e)
    
    def get_pseudocode(
        self, 
        project: ProjectInfo, 
        ea: Optional[str] = None, 
        func_name: Optional[str] = None
    ) -> PseudocodeResponse:
        """Get pseudocode"""
        self._ensure_worker_ready(project)
        
        if not ea and not func_name:
            raise ValueError("Either ea or func_name must be provided")
        
        try:
            params = {}
            if ea:
                params["ea"] = ea
            if func_name:
                params["func_name"] = func_name
            
            response = requests.get(
                f"{project.worker.url}/pseudocode",
                params=params,
                timeout=60  # Decompilation may take longer
            )
            
            if response.status_code == 501:
                # Decompiler unavailable
                raise IDADecompilerUnavailableError(project.name)
            
            response.raise_for_status()
            data = response.json()
            
            return PseudocodeResponse(
                ea=data["ea"],
                function_name=data.get("function_name"),
                pseudocode=data["pseudocode"],
                decompiler_available=True
            )
            
        except IDADecompilerUnavailableError:
            raise
        except requests.exceptions.RequestException as e:
            raise WorkerCommunicationError(project.name, "get_pseudocode", e)
        except Exception as e:
            raise IDAAnalysisError(project.name, "get_pseudocode", e)
    
    def get_disassembly(self, project: ProjectInfo, ea: str, lines: int = 40) -> DisassemblyResponse:
        """Get disassembly"""
        self._ensure_worker_ready(project)
        
        try:
            response = requests.get(
                f"{project.worker.url}/disasm",
                params={"ea": ea, "lines": lines},
                timeout=self.config.network.worker_timeout
            )
            response.raise_for_status()
            
            data = response.json()
            disasm_lines = data.get("lines", [])
            
            return DisassemblyResponse(
                start_ea=data["start"],
                lines=[
                    {
                        "ea": line["ea"],
                        "line": line["line"]
                    }
                    for line in disasm_lines
                ]
            )
            
        except requests.exceptions.RequestException as e:
            raise WorkerCommunicationError(project.name, "get_disassembly", e)
        except Exception as e:
            raise IDAAnalysisError(project.name, "get_disassembly", e)
    
    def get_xrefs_to(self, project: ProjectInfo, ea: str) -> XRefResponse:
        """Get cross references"""
        self._ensure_worker_ready(project)
        
        try:
            response = requests.get(
                f"{project.worker.url}/xrefs_to",
                params={"ea": ea},
                timeout=self.config.network.worker_timeout
            )
            response.raise_for_status()
            
            data = response.json()
            xrefs = data.get("xrefs", [])
            
            return XRefResponse(
                ea=data["ea"],
                xrefs=[
                    {
                        "from_ea": xref["frm"],
                        "to_ea": xref["to"],
                        "type": xref["type"]
                    }
                    for xref in xrefs
                ]
            )
            
        except requests.exceptions.RequestException as e:
            raise WorkerCommunicationError(project.name, "get_xrefs_to", e)
        except Exception as e:
            raise IDAAnalysisError(project.name, "get_xrefs_to", e)
    
    def check_health(self, project: ProjectInfo) -> Dict[str, Any]:
        """Check worker health status"""
        if not project.worker:
            return {"ready": False, "error": "No worker"}
        
        try:
            response = requests.get(
                f"{project.worker.url}/health",
                timeout=3
            )
            
            if response.ok:
                data = response.json()
                from datetime import datetime
                project.worker.status = WorkerStatus.READY if data.get("ready") else WorkerStatus.ERROR
                project.worker.last_health_check = datetime.now()
                return data
            else:
                project.worker.status = WorkerStatus.ERROR
                return {"ready": False, "error": f"HTTP {response.status_code}"}
                
        except Exception as e:
            project.worker.status = WorkerStatus.ERROR
            return {"ready": False, "error": str(e)}
    
    def _ensure_worker_ready(self, project: ProjectInfo):
        """Ensure worker is ready"""
        if not project.worker:
            raise WorkerNotReadyError(project.name, "No worker")
        
        if project.status != ProjectStatus.READY:
            raise WorkerNotReadyError(project.name, f"Project status: {project.status}")
        
        # Check worker health status
        health = self.check_health(project)
        if not health.get("ready", False):
            raise WorkerNotReadyError(project.name, health.get("error", "Unknown error"))
