from __future__ import annotations
from typing import List, Optional
from fastapi import APIRouter as FastAPIRouter, HTTPException, Query, Path as FastAPIPath
from fastapi.responses import JSONResponse

from ..models import (
    APIResponse, ProjectCreateRequest, ProjectListResponse, 
    HealthCheck, FunctionInfo, PseudocodeResponse, 
    DisassemblyResponse, XRefResponse
)
from ..exceptions import IDAServiceException
from ..services.project_manager import ProjectManager
from ..services.worker_service import WorkerService
from ..config import ServiceConfig
from ...logging_helper import global_logger


class APIRouter:
    """API route manager"""
    
    def __init__(self, project_manager: ProjectManager, worker_service: WorkerService, config: ServiceConfig):
        self.project_manager = project_manager
        self.worker_service = worker_service
        self.config = config
        self.router = FastAPIRouter()
        self._setup_routes()
    
    def _setup_routes(self):
        """Setup routes"""
        # Health check
        self.router.add_api_route("/health", self.health_check, methods=["GET"])
        
        # Project management
        self.router.add_api_route("/projects", self.create_project, methods=["POST"])
        self.router.add_api_route("/projects", self.list_projects, methods=["GET"])
        self.router.add_api_route("/projects/{name}", self.get_project, methods=["GET"])
        self.router.add_api_route("/projects/{name}", self.delete_project, methods=["DELETE"])
        self.router.add_api_route("/projects/{name}/start", self.start_project, methods=["POST"])
        self.router.add_api_route("/projects/{name}/stop", self.stop_project, methods=["POST"])
        self.router.add_api_route("/projects/{name}/health", self.project_health, methods=["GET"])
        
        # Analysis functions
        self.router.add_api_route("/projects/{name}/functions", self.list_functions, methods=["GET"])
        self.router.add_api_route("/projects/{name}/pseudocode", self.get_pseudocode, methods=["GET"])
        self.router.add_api_route("/projects/{name}/disassembly", self.get_disassembly, methods=["GET"])
        self.router.add_api_route("/projects/{name}/xrefs", self.get_xrefs, methods=["GET"])
    
    def _handle_exception(self, e: Exception) -> JSONResponse:
        """Unified exception handling"""
        if isinstance(e, IDAServiceException):
            return JSONResponse(
                status_code=400,
                content=APIResponse.error_response(
                    message=e.message,
                    error_code=e.error_code.value,
                    data=e.details
                ).model_dump(mode='json')
            )
        else:
            global_logger.error(f"Unhandled exception: {e}", exc_info=True)
            return JSONResponse(
                status_code=500,
                content=APIResponse.error_response(
                    message="Internal server error",
                    error_code="INTERNAL_ERROR"
                ).model_dump(mode='json')
            )
    
    # Health check
    async def health_check(self) -> JSONResponse:
        """Health check"""
        try:
            stats = self.project_manager.get_stats()
            
            health = HealthCheck(
                service="IDA Service",
                status="healthy",
                uptime=0,  # TODO: Implement uptime calculation
                projects_count=stats["total_projects"],
                healthy_workers=stats["healthy_workers"]
            )
            
            return JSONResponse(
                content=APIResponse.success_response(
                    data=health.model_dump(),
                    message="Service healthy"
                ).model_dump(mode='json')
            )
        except Exception as e:
            return self._handle_exception(e)
    
    # Project management
    async def create_project(self, request: ProjectCreateRequest) -> JSONResponse:
        """Create project"""
        try:
            project = self.project_manager.create_project(request.name, request.ida_input)
            
            return JSONResponse(
                status_code=201,
                content=APIResponse.success_response(
                    data=project.model_dump(),
                    message="Project created successfully"
                ).model_dump(mode='json')
            )
        except Exception as e:
            return self._handle_exception(e)
    
    async def list_projects(
        self, 
        status: Optional[str] = Query(None, description="Status filter"),
        page: int = Query(1, ge=1, description="Page number"),
        page_size: int = Query(50, ge=1, le=100, description="Page size")
    ) -> JSONResponse:
        """List projects"""
        try:
            projects = self.project_manager.list_projects()
            
            # Status filter
            if status:
                projects = [p for p in projects if p.status.value == status]
            
            # Pagination
            start = (page - 1) * page_size
            end = start + page_size
            paginated_projects = projects[start:end]
            
            response_data = ProjectListResponse(
                projects=paginated_projects,
                total=len(projects),
                page=page,
                page_size=page_size
            )
            
            return JSONResponse(
                content=APIResponse.success_response(
                    data=response_data.model_dump(),
                    message="Project list retrieved successfully"
                ).model_dump(mode='json')
            )
        except Exception as e:
            return self._handle_exception(e)
    
    async def get_project(self,         name: str = FastAPIPath(..., description="Project name")) -> JSONResponse:
        """Get project details"""
        try:
            project = self.project_manager.get_project(name)
            
            return JSONResponse(
                content=APIResponse.success_response(
                    data=project.model_dump(),
                    message="Project details retrieved successfully"
                ).model_dump(mode='json')
            )
        except Exception as e:
            return self._handle_exception(e)
    
    async def delete_project(self, name: str = FastAPIPath(..., description="Project name")) -> JSONResponse:
        """Delete project"""
        try:
            success = self.project_manager.delete_project(name)
            
            if success:
                return JSONResponse(
                    content=APIResponse.success_response(
                        message="Project deleted successfully"
                    ).model_dump(mode='json')
                )
            else:
                return JSONResponse(
                    status_code=404,
                    content=APIResponse.error_response(
                        message="Project does not exist",
                        error_code="PROJECT_NOT_FOUND"
                    ).model_dump(mode='json')
                )
        except Exception as e:
            return self._handle_exception(e)
    
    async def start_project(self, name: str = FastAPIPath(..., description="Project name")) -> JSONResponse:
        """Start project"""
        try:
            project = self.project_manager.start_worker(name)
            
            return JSONResponse(
                content=APIResponse.success_response(
                    data=project.model_dump(),
                    message="Project started successfully"
                ).model_dump(mode='json')
            )
        except Exception as e:
            return self._handle_exception(e)
    
    async def stop_project(self, name: str = FastAPIPath(..., description="Project name")) -> JSONResponse:
        """Stop project"""
        try:
            success = self.project_manager.stop_worker(name)
            
            if success:
                return JSONResponse(
                    content=APIResponse.success_response(
                        message="Project stopped successfully"
                    ).model_dump(mode='json')
                )
            else:
                return JSONResponse(
                    status_code=404,
                    content=APIResponse.error_response(
                        message="Project does not exist",
                        error_code="PROJECT_NOT_FOUND"
                    ).model_dump(mode='json')
                )
        except Exception as e:
            return self._handle_exception(e)
    
    async def project_health(self, name: str = FastAPIPath(..., description="Project name")) -> JSONResponse:
        """Project health check"""
        try:
            project = self.project_manager.get_project(name)
            health = self.worker_service.check_health(project)
            
            return JSONResponse(
                content=APIResponse.success_response(
                    data=health,
                    message="Project health check completed"
                ).model_dump(mode='json')
            )
        except Exception as e:
            return self._handle_exception(e)
    
    # Analysis functions
    async def list_functions(
        self, 
        name: str = FastAPIPath(..., description="Project name"),
        q: str = Query("", description="Search query")
    ) -> JSONResponse:
        """List functions"""
        try:
            project = self.project_manager.get_project(name)
            functions = self.worker_service.list_functions(project, q)
            
            return JSONResponse(
                content=APIResponse.success_response(
                    data={"functions": [f.model_dump() for f in functions]},
                    message="Function list retrieved successfully"
                ).model_dump(mode='json')
            )
        except Exception as e:
            return self._handle_exception(e)
    
    async def get_pseudocode(
        self,
        name: str = FastAPIPath(..., description="Project name"),
        ea: Optional[str] = Query(None, description="Function address"),
        func_name: Optional[str] = Query(None, description="Function name")
    ) -> JSONResponse:
        """Get pseudocode"""
        try:
            project = self.project_manager.get_project(name)
            pseudocode = self.worker_service.get_pseudocode(project, ea, func_name)
            
            return JSONResponse(
                content=APIResponse.success_response(
                    data=pseudocode.model_dump(),
                    message="Pseudocode retrieved successfully"
                ).model_dump(mode='json')
            )
        except Exception as e:
            return self._handle_exception(e)
    
    async def get_disassembly(
        self,
        name: str = FastAPIPath(..., description="Project name"),
        ea: str = Query(..., description="Start address"),
        lines: int = Query(40, ge=1, le=200, description="Number of lines")
    ) -> JSONResponse:
        """Get disassembly"""
        try:
            project = self.project_manager.get_project(name)
            disasm = self.worker_service.get_disassembly(project, ea, lines)
            
            return JSONResponse(
                content=APIResponse.success_response(
                    data=disasm.model_dump(),
                    message="Disassembly retrieved successfully"
                ).model_dump(mode='json')
            )
        except Exception as e:
            return self._handle_exception(e)
    
    async def get_xrefs(
        self,
        name: str = FastAPIPath(..., description="Project name"),
        ea: str = Query(..., description="Target address")
    ) -> JSONResponse:
        """Get cross references"""
        try:
            project = self.project_manager.get_project(name)
            xrefs = self.worker_service.get_xrefs_to(project, ea)
            
            return JSONResponse(
                content=APIResponse.success_response(
                    data=xrefs.model_dump(),
                    message="Cross references retrieved successfully"
                ).model_dump(mode='json')
            )
        except Exception as e:
            return self._handle_exception(e)
