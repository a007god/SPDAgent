from pathlib import Path
from typing import Dict, Callable
import time
import os
import sys

from utils.logging_helper import global_logger
from utils.IDA_service.ida_client import Client

class LangTools: 
    def __init__(self, project_name: str, host: str = "127.0.0.1", port: int = 20000):
        self.project_name = project_name
        self.host = host
        self.port = port
        self.ida_client = Client(self.host, self.port)

        if not self.ida_client.is_alive():
            raise RuntimeError(f"IDA controller http://{self.host}:{self.port} not available, start first.")

        self._TOOL_MAP = {
            "ida": {
                "func_info": {
                    "fetch_func_by_name": self._fetch_func_by_name, 
                },
                "caller_info": {
                    "find_caller_for_func": self._find_caller_for_func,  # func_name
                },
                "value_info": {
                    "trace_value_by_name": self._trace_value_by_name,  # value_name
                },
            }
        }

    def _fetch_func_by_name(self, func_name: str) -> str:
        """Get function pseudocode"""
        try:
            return self.ida_client.get_pseudocode(self.project_name, func_name=func_name)
        except Exception as e:
            global_logger.error(f"Failed to fetch function {func_name}: {e}")
            return ""

    def _find_caller_for_func(self, func_name: str) -> list:
        """Find functions that call func_name (based on xrefs_to frm mapping)"""
        try:
            # 1) Get candidate list for target function (for finding target function address)
            cands = self.ida_client.list_functions(self.project_name, func_name) or []
            global_logger.debug(f"Found {len(cands)} candidate functions for '{func_name}'")
            
            if not cands:
                return []

            # Get function address - exact match preferred
            func_ea = None
            for it in cands:
                if it.get("name") == func_name:
                    func_ea = it.get("ea")
                    break
            
            # If no exact match, use the first one
            if not func_ea:
                func_ea = cands[0].get("ea")
            
            if not func_ea:
                return []
            
            global_logger.debug(f"Using func_ea: '{func_ea}' for function '{func_name}'")
            
            # 2) Get xrefs
            xrefs = self.ida_client.xrefs_to(self.project_name, func_ea) or []
            global_logger.debug(f"Found {len(xrefs)} xrefs for ea '{func_ea}'")
            
            if not xrefs:
                return []

            # 3) Cache all function list (for inferring function name from EA)
            # This cache is different from cands above, needs to include all functions
            if not hasattr(self, "_all_funcs_cache"):
                global_logger.debug("Building all functions cache for EA-to-function mapping...")
                self._all_funcs_cache = self.ida_client.list_functions(self.project_name, "") or []
                global_logger.debug(f"Cached {len(self._all_funcs_cache)} functions")

            # 4) Process each xref, find unique caller functions
            caller_funcs = {}  # {caller_name: caller_start_ea}

            for xr in xrefs:
                ea_frm = xr.get("frm") or xr.get("from_ea")  # Compatible with different return formats
                if not ea_frm:
                    continue

                # Convert to integer
                frm_int = int(ea_frm, 16) if isinstance(ea_frm, str) else int(ea_frm)

                # 5) Infer function name from EA
                # Find function with EA not greater than frm and closest
                best = None
                best_delta = None
                for f in self._all_funcs_cache:
                    fea = f.get("ea")
                    if not fea:
                        continue
                    fea_int = int(fea, 16) if isinstance(fea, str) else int(fea)
                    if fea_int <= frm_int:
                        delta = frm_int - fea_int
                        if best is None or delta < best_delta:
                            best, best_delta = f, delta
                
                if best:
                    caller_name = best.get("name") or "unknown"
                    if caller_name != "unknown" and caller_name not in caller_funcs:
                        caller_funcs[caller_name] = best.get("ea")

            # 6) Only take first 3 callers, get their pseudocode
            callers = []
            for caller_name in list(caller_funcs.keys())[:3]:
                try:
                    # Get caller function pseudocode
                    caller_code = self.ida_client.get_pseudocode(
                        self.project_name, 
                        func_name=caller_name
                    ) or ""
                    
                    if caller_code:
                        callers.append({
                            "caller_name": caller_name,
                            "caller_code": caller_code,
                        })
                    else:
                        global_logger.warning(f"Empty pseudocode for caller: {caller_name}")
                        
                except Exception as e:
                    global_logger.warning(f"Failed to get pseudocode for caller {caller_name}: {e}")
                    continue

            global_logger.info(f"Found {len(callers)} unique callers (max 3) for '{func_name}'")
            return callers

        except Exception as e:
            global_logger.error(f"Failed to find callers for {func_name}: {e}")
            return []


    def _trace_value_by_name(self, func_name: str, value_names=None, value_name: str = None) -> str:
        """
        Find variable or struct member
        
        Args:
            func_name: Function name
            value_names: List of value names (supports multiple values)
            value_name: Single value name (backward compatible)
        
        Returns:
            Function pseudocode (if at least one value exists in code)
        """
        try:
            # Handle parameters: support value_names list or single value_name
            if value_names is None:
                if value_name is None:
                    global_logger.warning("No value_name or value_names provided")
                    return ""
                # Backward compatible: single value_name
                value_names = [value_name]
            elif isinstance(value_names, str):
                # If string is passed, convert to list
                value_names = [value_names]
            
            # Get function code
            code = self.ida_client.get_pseudocode(self.project_name, func_name=func_name)
            
            if not code:
                return ""
            
            # Check if at least one value_name exists in code
            found = False
            for vname in value_names:
                if vname in code:
                    found = True
                    break
            
            if not found:
                global_logger.debug(f"None of the values {value_names} found in function {func_name}")
                return ""
            
            return code

        except Exception as e:
            global_logger.error(f"Failed to fetch function {func_name}: {e}")
            return ""

    def _get_tool(self, tool_type: str, sub_tool: str = None) -> Callable:
        """Retrieve tool with validation"""
        tool_type = tool_type.lower()
        if tool_type not in self._TOOL_MAP:
            raise ValueError(f"Unsupported tool type: {tool_type}")
        
        if sub_tool is None:
            return self._TOOL_MAP[tool_type]
        
        if sub_tool not in self._TOOL_MAP[tool_type]:
            raise ValueError(f"Invalid sub-tool: {sub_tool} for {tool_type}")
        
        return self._TOOL_MAP[tool_type][sub_tool]
    
    def get_ida_tool(self, sub_tool: str) -> Callable:
        """Retrieve IDA-specific tool"""
        return self._get_tool("ida", sub_tool)

    def supported_operations(self) -> Dict:
        return {
            lang: list(tools.keys()) 
            for lang, tools in self._TOOL_MAP.items()
        }
    
    def check_ida_project(self) -> bool:
        """Check if IDA project is ready"""
        retry_count = 0
        while True:
            res = self.ida_client.project_ready(self.project_name)
            if res:
                return True
            else:
                retry_count += 1
                time.sleep(retry_count)
                if retry_count > 20:
                    global_logger.error(f"IDA service is not running, please check the service.")
                    time.sleep(100)