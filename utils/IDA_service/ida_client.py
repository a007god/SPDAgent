from __future__ import annotations
import json
from dataclasses import dataclass
from typing import Optional, Dict, Any
import requests
from pathlib import Path

@dataclass
class Client:
    """Control plane client: highly encapsulated, main flow friendly."""
    host: str = "127.0.0.1"
    port: int = 20000

    def _base(self) -> str:
        return f"http://{self.host}:{self.port}/api/v1"

    # ---- Service level ----
    def is_alive(self) -> bool:
        try:
            r = requests.get(self._base() + "/health", timeout=2)
            return r.ok and r.json().get("success", False)
        except Exception:
            return False

    # ---- Project lifecycle ----
    def open(
        self,
        *,
        name: str,             
        ida_input: str, 
    ) -> Dict[str, Any]:
        """Create and start project"""
        # Create project
        payload = {
            "name": name,     
            "ida_input": ida_input,
        }
        r = requests.post(self._base() + "/projects", json=payload, timeout=30)
        r.raise_for_status()
        
        # Start project
        r = requests.post(self._base() + f"/projects/{name}/start", timeout=600)
        r.raise_for_status()
        
        return r.json()

    def status(self, name: str) -> Dict[str, Any]:
        r = requests.get(self._base() + f"/projects/{name}", timeout=5)
        r.raise_for_status()
        return r.json()

    def project_ready(self, name: str) -> bool:
        try:
            r = requests.get(self._base() + f"/projects/{name}/health", timeout=3)
            if r.ok:
                data = r.json()
                return data.get("success", False) and data.get("data", {}).get("ready", False)
            return False
        except Exception:
            return False


    def close(self, name: str) -> Dict[str, Any]:
        r = requests.delete(self._base() + f"/projects/{name}", timeout=30)
        r.raise_for_status()
        return r.json()

    # ---- High-level API ----
    def list_functions(self, name: str, q: str = "") -> list[dict]:
        r = requests.get(self._base() + f"/projects/{name}/functions", params={"q": q}, timeout=10)
        r.raise_for_status()
        data = r.json()
        if data.get("success"):
            return data.get("data", {}).get("functions", [])
        return []

    def get_pseudocode(self, name: str, *, ea: Optional[str] = None, func_name: Optional[str] = None) -> str:
        params = {}
        if ea:
            params["ea"] = ea
        if func_name:
            params["func_name"] = func_name
            
        r = requests.get(self._base() + f"/projects/{name}/pseudocode", params=params, timeout=60)
        r.raise_for_status()
        data = r.json()
        if data.get("success"):
            return data.get("data", {}).get("pseudocode", "")
        raise RuntimeError(data.get("message", "Failed to get pseudocode"))

    def disasm(self, name: str, ea: str, lines: int = 40) -> list[dict]:
        r = requests.get(self._base() + f"/projects/{name}/disassembly", params={"ea": ea, "lines": lines}, timeout=10)
        r.raise_for_status()
        data = r.json()
        if data.get("success"):
            return data.get("data", {}).get("lines", [])
        return []

    def xrefs_to(self, name: str, ea: str) -> list[dict]:
        r = requests.get(self._base() + f"/projects/{name}/xrefs", params={"ea": ea}, timeout=10)
        r.raise_for_status()
        data = r.json()
        if data.get("success"):
            return data.get("data", {}).get("xrefs", [])
        return []