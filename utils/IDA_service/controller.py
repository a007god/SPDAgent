from __future__ import annotations
import time
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import ServiceConfig
from .services.project_manager import ProjectManager
from .services.worker_service import WorkerService
from .api.routes import APIRouter
from ..logging_helper import global_logger


class IDAController:
    """IDA controller - main controller integrating all services"""
    
    def __init__(self, config: ServiceConfig):
        self.config = config
        self.project_manager = ProjectManager(config)
        self.worker_service = WorkerService(config)
        self.api_router = APIRouter(self.project_manager, self.worker_service, config)
        self.app = None
        self._start_time = None
    
    def create_app(self) -> FastAPI:
        """Create FastAPI application"""
        if self.app is not None:
            return self.app
        
        self._start_time = time.time()
        
        @asynccontextmanager
        async def lifespan(app: FastAPI):
            # On startup
            global_logger.info("IDA controller starting...")
            yield
            # On shutdown
            global_logger.info("IDA controller shutting down...")
            self.project_manager.cleanup_all()
            global_logger.info("IDA controller has been shut down")
        
        self.app = FastAPI(
            title="IDA Service Controller",
            description="IDA disassembly service controller",
            version="2.0.0",
            lifespan=lifespan
        )
        
        # Add CORS middleware
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        # Register routes
        self.app.include_router(
            self.api_router.router,
            prefix="/api/v1",
            tags=["IDA Service"]
        )
        
        # Add root path
        @self.app.get("/")
        async def root():
            return {
                "service": "IDA Service Controller",
                "version": "2.0.0",
                "status": "running",
                "uptime": time.time() - self._start_time if self._start_time else 0
            }
        
        global_logger.info("IDA controller application created")
        return self.app
    
    def get_stats(self) -> dict:
        """Get controller statistics"""
        stats = self.project_manager.get_stats()
        stats.update({
            "uptime": time.time() - self._start_time if self._start_time else 0,
            "config": {
                "ida_path": self.config.ida.path,
                "host": self.config.network.host,
                "port": self.config.network.port,
                "timeout": self.config.ida.timeout
            }
        })
        return stats


def create_app(config: ServiceConfig) -> FastAPI:
    """Create IDA controller application"""
    controller = IDAController(config)
    return controller.create_app()
