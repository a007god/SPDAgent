import logging
import json
import demjson3
import re
import os
from datetime import datetime
from typing import TypedDict, Optional, List, Dict, Any, Callable, Tuple
import inspect
import unittest
from pathlib import Path
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, END
from urllib.parse import urlparse
import yaml
import sys
import time

root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from utils.logging_helper import global_logger
from .agent_selftools import LangTools

class AgentState(TypedDict):
    project_name: str  
    project_dir: Path
    patch: dict  # file_path, patch

    IDA_available: bool  # IDA state, which indicates if the project has been initialized
    ida_host: Optional[str]  # IDA controller host
    ida_port: Optional[int]  # IDA controller port

    # file_cache: List = []  # Joern file cache, help hit the file path
    # cpg_file: str = None  # Joern CPG file
    # base_url: str = None  # Joern Server URL
    prompt_version: str  # prompt version

    enriched_data: List[dict]  # more context data
    analysis: Optional[dict]  # analysis result
    root_cause: List[Dict]  # List of root cause analysis results
    confidence_score: float
    iteration: int
    need_context: bool  # flag to indicate if more context is needed
    analysis_record: List[dict]  
    tools_record: List[dict]  
    debug_trace: List[str]  # debug trace
    status: Optional[str]  # status trace
    error: Optional[str]
    
    # Pre-filter related fields
    enable_prefilter: bool  # Whether to enable pre-filter stage
    prefilter_result: Optional[dict]  # Result from pre-filter stage
    

def load_yaml(file_path: str) -> dict:
    with open(file_path, 'r', encoding='utf-8') as file:
        return yaml.safe_load(file)

# Load prompt templates

_CTRL_RE = re.compile(r"[\x00-\x1F]")
_KEY_FIX_RE = re.compile(r"([{,]\s*)([A-Za-z_][A-Za-z_0-9]*)\s*:\s*")

_CURLY_QUOTES = {
    "\u201c": '"',  # " → "
    "\u201d": '"',  # " → "
    "\u2018": "'",  # ' → '
    "\u2019": "'",  # ' → '
}

PROMPT_VERSION_MAP = {}
SLICER_PROMPT_MAP = {}

class PromptLoader:
    def __init__(self, llm_config: Optional[Dict] = None):
        self.llm_config = llm_config
        


    def load_prompts(self):
        global PROMPT_VERSION_MAP, SLICER_PROMPT_MAP
        root_cause_analysis_template = yaml.safe_load(Path(self.llm_config["prompt_path"]["root_cause_analysis_template"]).read_text(encoding="utf-8"))
        actor_prompt = yaml.safe_load(Path(self.llm_config["prompt_path"]["actor_prompt"]).read_text(encoding="utf-8"))
        early_classification_template = yaml.safe_load(Path(self.llm_config["prompt_path"]["early_classification_template"]).read_text(encoding="utf-8"))
        code_slicer_template = yaml.safe_load(Path(self.llm_config["prompt_path"]["code_slicer_template"]).read_text(encoding="utf-8"))
        
        PROMPT_VERSION_MAP = {  
            "default": (
                root_cause_analysis_template['root_cause_analysis_prompt'],
                actor_prompt['actor_tools_prompt'],
                early_classification_template['early_classification_prompt'],
            ),
            "limited": (
                root_cause_analysis_template['root_cause_analysis_prompt_limited'],
                actor_prompt['actor_tools_prompt_limited'],
                early_classification_template['early_classification_prompt'],
            ),
            "rigorous": (
                root_cause_analysis_template['root_cause_analysis_prompt_rigorous'],
                actor_prompt['actor_tools_prompt_limited'],
                early_classification_template['early_classification_prompt'],
            ),
        }
        
        SLICER_PROMPT_MAP = {
            "caller": code_slicer_template['caller_slicer_prompt'],
            "value": code_slicer_template['value_slicer_prompt'],
        }



class JsonRepairHelper:
    """
    Attempts to parse malformed JSON by repairing common issues or using an LLM fallback.
    """
    def __init__(self, api_config: Optional[Dict] = None):
        config = api_config or {}
        self.llm = ChatOpenAI(
            model=config["worker"]["helper"]["model_name"]["gpt-5-nano"],
            temperature=0.2,
            timeout=None,
            api_key=config["worker"]["helper"]["OPENAI_API_KEY"],
            base_url=config["worker"]["helper"]["OPENAI_API_BASE"]
        )

    def safe_parse_json(self, content: str, *, strict: bool = False) -> dict:
        """Return a Python object or ``None`` when every repair attempt fails."""
        # 0. Fast path – may succeed for 80‑90 % of inputs.
        try:
            return json.loads(content)
            # return json.loads(content.replace('\\','\\\\'), strict=False)
        except json.JSONDecodeError as exc:
            global_logger.debug("Initial JSON parsing failed: %s", exc)
            
        # 1. Pre‑clean: strip BOM, normalise quotes, escape ctrl chars.
        cleaned = self._preclean(content)
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError as exc:
            global_logger.debug("stage 1 – after _preclean(): %s", exc)

        # 2. Structural patch (non‑destructive).
        patched = self._structural_fix(cleaned)
        try:
            return json.loads(patched)
        except json.JSONDecodeError as exc:
            global_logger.debug("stage 2 – after _structural_fix(): %s", exc)
        # 3. demjson3 fallback, if available.
        if demjson3 is not None:
            try:
                return demjson3.decode(content)  # type: ignore[arg-type]
            except Exception as exc:  # pragma: no cover
                global_logger.debug("stage 3 – after demjson3.decode(): %s", exc)
        # 4. LLM repair.
        if self.llm is not None:
            try:
                return self._llm_fix_json(content)
            except json.JSONDecodeError as exc:  # pragma: no cover
                global_logger.debug("stage 4 – after LLM repair: %s", exc)

        if strict:
            raise json.JSONDecodeError("Unrecoverable JSON", content, 0)
        return None


    def _preclean(self, raw: str) -> str:
        if raw.startswith("\ufeff"):
            raw = raw[1:]
        raw = "".join(_CURLY_QUOTES.get(ch, ch) for ch in raw)

        def _esc(m: re.Match[str]) -> str:
            return f"\\u{ord(m.group()):04x}"

        return _CTRL_RE.sub(_esc, raw)

    def _structural_fix(self, raw: str) -> str:
        raw += "}" * (raw.count("{") - raw.count("}"))
        raw += "]" * (raw.count("[") - raw.count("]"))
        raw = _KEY_FIX_RE.sub(r'\1"\2": ', raw)
        return raw

    def _llm_fix_json(self, malformed_json: str, retry = 1) -> Optional[Any]:
        if retry > 3:
            global_logger.error(f"[JSON ERROR] LLM failed to repair JSON after 3 attempts: {malformed_json}")
            return None
        prompt = (
            f"This is Json {retry} Times:\n You are a strict JSON repair agent. Your job is to fix the given malformed JSON.\n"
            "- Return ONLY valid JSON (object `{...}` or array `[...]`).\n"
            "- Do NOT include any explanation or markdown formatting.\n"
            "- Ensure correct quotes, colons, commas, and brackets.\n\n"
            "- Only one Json object is allowed to be returned. Do not modify any key content."
            "Malformed JSON:\n"
            f"{malformed_json.strip()}\n"
        )
        try:
            response = self.llm.invoke(prompt)
            content = response.content if hasattr(response, "content") else str(response)
            content = re.sub(r"```(?:json)?\s*([\s\S]*?)\s*```", r"\1", content).strip()
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                retry += 1
                return self._llm_fix_json(content, retry)
        except Exception as e:
            global_logger.error(f"[JSON ERROR] LLM failed to repair JSON: {str(e)}\n{malformed_json}")
            return None
        
class PreFilterClassifier:
    """
    Performs early classification to filter out obvious non-security patches.
    """

    def __init__(self, api_config: Optional[Dict] = None, prompt_version: str = "default"):
        config = api_config or {}
        self.llm = ChatOpenAI(
            model=config["worker"]["analysis"]["model_name"]["gpt-5-mini"],
            temperature=0.2,
            timeout=None,
            api_key=config["worker"]["analysis"]["OPENAI_API_KEY"],
            base_url=config["worker"]["analysis"]["OPENAI_API_BASE"]
        )
        self.prompt_version = prompt_version
        self.json_helper = JsonRepairHelper(api_config)

        if self.prompt_version not in PROMPT_VERSION_MAP:
             global_logger.warning(f"Prompt version '{self.prompt_version}' not found. Falling back to 'default'.")
             self.prompt_version = "default"

        self._early_classification_prompt = PROMPT_VERSION_MAP[self.prompt_version][2]

    def classify_patch(self, state: Dict) -> Tuple[Dict, str]:
        try:
            patch = state["patch"]
            prompt = self._early_classification_prompt.format(patch=json.dumps(patch, indent=2))
            
            raw_response = self._get_llm_response(prompt)
            classification = self._validate_response(raw_response)
            
            return classification, prompt
        except Exception as e:
            global_logger.error(f"[Pre-filter ERROR] Early classification failed: {str(e)}")
            return {
                "is_security_patch": "yes",  # Default to security on error
                "analysis": f"Classification failed: {str(e)}"
            }, ""

    def _get_llm_response(self, prompt: str) -> str:
        response = self.llm.invoke(prompt)
        content = response.content if hasattr(response, 'content') else str(response)
        start_marker = '```json'
        end_marker = '```'
        start = content.find(start_marker)
        end = content.find(end_marker, start + len(start_marker))
        if start != -1 and end != -1:
            json_content = content[start + len(start_marker):end].strip()
        else:
            start_marker = '<think>'
            end_marker = '</think>'
            start = content.find(start_marker)
            end = content.find(end_marker, start + len(start_marker))
            if start != -1 and end != -1:
                json_content = content[end + len(end_marker):].strip()
            else:
                json_content = content.strip()
        return json_content

    def _validate_response(self, raw: str) -> Dict:
        try:
            data = self.json_helper.safe_parse_json(raw)
            if data is None:
                raise ValueError(f"[JSON ERROR] Failed to parse JSON response\n {raw}")

            if not isinstance(data, list):
                raise ValueError(f"[JSON ERROR] Expected JSON list but got something else\n {raw}")

            return self._prepare_function_classification(data)
        except Exception as e:
            raise ValueError(f"[JSON ERROR] Invalid JSON response format: {str(e)}\n {raw}")

    def _prepare_function_classification(self, items: List[Dict]) -> Dict:
        if not items:
            raise ValueError("[JSON ERROR] Classification list is empty")

        normalized_entries = []
        for idx, item in enumerate(items):
            if not isinstance(item, dict):
                raise ValueError(f"[JSON ERROR] Entry #{idx} is not an object: {item}")

            for field in ["func_name", "is_security_related", "analysis"]:
                if field not in item:
                    raise ValueError(f"[JSON ERROR] Missing '{field}' in entry #{idx}: {item}")
                if not isinstance(item[field], str) or not item[field].strip():
                    raise ValueError(f"[JSON ERROR] Field '{field}' in entry #{idx} must be a non-empty string")

            decision = item["is_security_related"].strip().lower()
            if decision not in {"yes", "no"}:
                raise ValueError(f"[JSON ERROR] Field 'is_security_related' must be 'yes' or 'no', got '{item['is_security_related']}'")

            normalized_entries.append({
                "func_name": item["func_name"].strip(),
                "is_security_related": decision,
                "analysis": item["analysis"].strip()
            })

        has_security_funcs = any(entry["is_security_related"] == "yes" for entry in normalized_entries)
        summary_lines = [f"{entry['func_name']}: {entry['analysis']}" for entry in normalized_entries]
        analysis_summary = "\n".join(summary_lines)

        return {
            "is_security_patch": "yes" if has_security_funcs else "no",
            "analysis": analysis_summary,
            "function_classification": normalized_entries
        }


class VulnerabilityCritic:
    """
    Performs initial and root cause analysis using LLM, backed with prompt templates and JSON validation.
    """

    def __init__(self, api_config: Optional[Dict] = None, prompt_version: str = "default"):
        config = api_config or {}
        self.llm = ChatOpenAI(
            model=config["worker"]["analysis"]["model_name"]["gpt-5-mini"],
            temperature=0.6,
            timeout=None,
            api_key=config["worker"]["analysis"]["OPENAI_API_KEY"],
            base_url=config["worker"]["analysis"]["OPENAI_API_BASE"]
        )
        self.prompt_version = prompt_version
        self.json_helper = JsonRepairHelper(api_config)

        if self.prompt_version not in PROMPT_VERSION_MAP:
             global_logger.warning(f"Prompt version '{self.prompt_version}' not found. Falling back to 'default'.")
             self.prompt_version = "default"

        self._root_cause_prompt = PROMPT_VERSION_MAP[self.prompt_version][0]

    def _build_enhanced_patch(self, state: Dict) -> str:
        """
        Integrate enriched_data into patch to generate enhanced patch
        Original patch: [{'func_name': 'OBJ_create', 'patch': ……}]
        enriched_data: [{'tool': '...', 'result': [{'type': 'function_def', 'code': '...'}]}]
        """
        patch = state.get("patch", [])
        enriched_data = state.get("enriched_data", [])
        
        # If no enriched_data, return original patch directly
        if not enriched_data:
            return json.dumps(patch, indent=2)
        
        # Build enhanced patch list
        enhanced_patch = []
        
        # First add original patch
        for patch_item in patch:
            enhanced_item = {
                'func_name': patch_item.get('func_name'),
                'patch': patch_item.get('patch')
            }
            enhanced_patch.append(enhanced_item)
        
        # Add context information from enriched_data
        for data_item in enriched_data:
            tool = data_item.get('tool', '')
            result = data_item.get('result', None)
            
            # Skip empty or error results
            if not result or isinstance(result, str):
                continue
            
            # Process different types of results
            if isinstance(result, list):
                for item in result:
                    if not isinstance(item, dict):
                        continue
                    
                    item_type = item.get('type')
                    
                    # 1. Process function_def type
                    if item_type == 'function_def':
                        func_name = self._extract_func_name_from_tool(tool)
                        enhanced_item = {
                            'func_name': func_name,
                            'context_type': 'function_def', 
                            'context': item.get('code', '')
                        }
                        enhanced_patch.append(enhanced_item)
                    
                    # 2. Process caller_info type
                    elif item_type == 'caller_info':
                        func_name = self._extract_func_name_from_tool(tool)
                        enhanced_item = {
                            'func_name': func_name,
                            'context_type': 'caller_info',
                            'caller_code': item.get('caller_code', ''),
                            'description': f"Caller context for function '{func_name}'"
                        }
                        enhanced_patch.append(enhanced_item)
                    
                    # 3. Process value_info type
                    elif item_type == 'value_info':
                        func_name = item.get('func_name', self._extract_func_name_from_tool(tool))
                        # Support value_names list
                        value_names = item.get('value_names', [])
                        if not value_names:
                            # Compatible with old format: try to extract single value_name from tool
                            value_name = self._extract_value_name_from_tool(tool)
                            value_names = [value_name] if value_name != "unknown_value" else []
                        
                        value_names_str = ", ".join(value_names) if value_names else "unknown values"
                        enhanced_item = {
                            'func_name': func_name,
                            'context_type': 'value_info',
                            'value_names': value_names,  # Save list
                            'value_code': item.get('code', ''),
                            'description': f"Data dependencies of {value_names_str} in function '{func_name}'"
                        }
                        enhanced_patch.append(enhanced_item)
        
        return json.dumps(enhanced_patch, indent=2)
    
    def _extract_func_name_from_tool(self, tool_string: str) -> str:
        """
        Extract function name from tool string
        Example: "func_info.fetch_func_by_name({'func_name': 'OBJ_txt2obj'})" -> "OBJ_txt2obj"
        """
        try:
            # Try to extract func_name from tool string
            if 'func_name' in tool_string:
                match = re.search(r"'func_name':\s*'([^']+)'", tool_string)
                if match:
                    return match.group(1)
        except Exception as e:
            global_logger.warning(f"Failed to extract func_name from tool: {tool_string}, error: {e}")
        
        return "unknown_function"
    
    def _extract_value_name_from_tool(self, tool_string: str) -> str:
        """
        Extract variable name from tool string
        Example: "value_info.trace_value_by_name({'value_name': 'v6', 'func_name': 'OBJ_obj2nid'})" -> "v6"
        """
        try:
            # Try to extract value_name from tool string
            if 'value_name' in tool_string:
                match = re.search(r"'value_name':\s*'([^']+)'", tool_string)
                if match:
                    return match.group(1)
        except Exception as e:
            global_logger.warning(f"Failed to extract value_name from tool: {tool_string}, error: {e}")
        
        return "unknown_value"
    
    def _build_simplified_tools_record(self, state: Dict) -> List[Dict]:
        """
        Extract results from all iterations' tools_record and merge into a flat list
        Only contains tool names and success status, used to pass to analysis prompt
        """
        tools_record = state.get("tools_record", [])
        all_results = []
        
        # Iterate through all iterations, extract and merge results
        for record in tools_record:
            if 'results' in record:
                for result_item in record['results']:
                    # Use new success field (if exists)
                    if 'success' in result_item:
                        success = result_item.get('success', False)
                    else:
                        # Compatible with old format: judge by result content
                        result_value = result_item.get('result')
                        success = False
                        if result_value:
                            if isinstance(result_value, str):
                                success = not any(keyword in result_value.lower() for keyword in 
                                                [None, 'None'])
                            else:
                                success = True
                    
                    # Only keep tool and success
                    all_results.append({
                        'tool': result_item.get('tool', ''),
                        'success': success
                    })
        
        return all_results


    def determine_root_cause(self, state: Dict) -> Tuple[Dict, str]:
        prompt = ""  
        try:
            analysis_record = state.get("analysis_record", [])
            # Filter out pre-filter stage records, only keep deep analysis stage records
            deep_analysis_record = [
                record for record in analysis_record 
                if record.get("stage") != "pre-filter"
            ]
            # ③ Only take result from last record
            last_analysis = deep_analysis_record[-1]['result'] if deep_analysis_record else {}
            
            # ② Build enhanced patch: integrate enriched_data into patch
            enhanced_patch = self._build_enhanced_patch(state)
            
            # ④ Build simplified tools_record: only keep request and success status
            simplified_tools_record = self._build_simplified_tools_record(state)

            prompt = self._root_cause_prompt.format(
                iteration=state.get("iteration", 0),
                patch=enhanced_patch,
                last_analysis=json.dumps(last_analysis, indent=2),
                tools_record=json.dumps(simplified_tools_record, indent=2),
                # current_context=last_context
            )
           #  print(f"prompt: {prompt}")
           #  input()
            raw_response = self._get_llm_response(prompt)

            return self._validate_response(raw_response, state), prompt
        except Exception as e:
            return self._error_response("[Analysis ERROR] Root cause analysis failed", state, e), prompt

    def _get_llm_response(self, prompt: str) -> str:
        response = self.llm.invoke(prompt)
        content = response.content if hasattr(response, 'content') else str(response)
        start_marker = '```json'
        end_marker = '```'
        start = content.find(start_marker)
        end = content.find(end_marker, start + len(start_marker))
        # \n</think>\n\n
        if start != -1 and end != -1:
            json_content = content[start + len(start_marker):end].strip()
        else:
            start_marker = '<think>'
            end_marker = '</think>'
            start = content.find(start_marker)
            end = content.find(end_marker, start + len(start_marker))
            if start != -1 and end != -1:
                json_content = content[end + len(end_marker):].strip()
            else:
                json_content = content.strip()
        return json_content

    def _validate_response(self, raw: str, state: Dict) -> Dict:
        try:
            data = self.json_helper.safe_parse_json(raw)
            if data is None:
                raise ValueError(f"[JSON ERROR] Failed to parse JSON response\n {raw}")
            if not isinstance(data, dict):
                raise ValueError(f"[JSON ERROR] Expected JSON object but got something else\n {raw}")

            if "confidence_score" in data:
                if not 0 <= data["confidence_score"] <= 1:
                    raise ValueError("Confidence score out of range")

            required_fields = (
                ["vulnerability_type", "repair_strategy", "need_context", "root_cause"]
            )
            for field in required_fields:
                if field not in data:
                    raise ValueError(f"[JSON ERROR] Missing required field: {field}\n {raw}")

            return data
        except Exception as e:
            raise ValueError(f"[JSON ERROR] Invalid JSON response format: {str(e)}\n {raw}")

    def _error_response(self, reason: str, state: Dict, error: Exception) -> Dict:
        global_logger.error(f"{reason}: {str(error)}")
        return {
            "status": "error",
            "reason": reason,
            "error_details": str(error),
            "timestamp": datetime.now().isoformat(),
            "iteration": state.get("iteration", 0),
            "debug_trace": state.get("debug_trace", []) + [f"Error in {self._current_method()}"]
        }

    def _current_method(self) -> str:
        return inspect.currentframe().f_back.f_back.f_code.co_name
    
class LLMActor:
    """
    LLM actor responsible for translating required context into tool queries
    using a language model and parsing its output as tool parameter sets.
    """
    def __init__(self, api_config: Optional[Dict] = None, prompt_version: str = "default"):
        config = api_config or {}
        self.llm = ChatOpenAI(
            # model="deepseek-ai/DeepSeek-V3",
            model=config["worker"]["helper"]["model_name"]["gpt-5-nano"],
            temperature=0.1,
            timeout=None,
            api_key=config["worker"]["helper"]["OPENAI_API_KEY"],
            base_url=config["worker"]["helper"]["OPENAI_API_BASE"]
        )
        self.prompt_version = prompt_version
        self.json_helper = JsonRepairHelper(api_config)

        if self.prompt_version not in PROMPT_VERSION_MAP:
             global_logger.warning(f"Prompt version '{self.prompt_version}' not found. Falling back to 'default'.")
             self.prompt_version = "default"
        self.tool_prompt = PROMPT_VERSION_MAP[self.prompt_version][1]

    def generate_tools_query(self, required_context: str) -> List[Dict]:
        try:
            prompt = self.tool_prompt.format(request=required_context)
            raw_output = self._get_llm_response(prompt)
            parsed = self.json_helper.safe_parse_json(raw_output)

            if isinstance(parsed, dict):
                return [parsed]
            elif isinstance(parsed, list):
                return parsed
            else:
                global_logger.error("[JSON ERROR] Unexpected JSON structure from LLM.")
                return []
        except Exception as e:
            global_logger.error(f"[Tools ERROR] Tool query generation failed: {str(e)}")
            return []

    def _get_llm_response(self, prompt: str) -> str:
        response = self.llm.invoke(prompt)
        content = response.content if hasattr(response, 'content') else str(response)
        start_marker = '```json'
        end_marker = '```'
        start = content.find(start_marker)
        end = content.find(end_marker, start + len(start_marker))
        if start != -1 and end != -1:
            json_content = content[start + len(start_marker):end].strip()
        else:
            start_marker = '<think>'
            end_marker = '</think>'
            start = content.find(start_marker)
            end = content.find(end_marker, start + len(start_marker))
            if start != -1 and end != -1:
                json_content = content[end + len(end_marker):].strip()
            else:
                json_content = content.strip()
        return json_content

class CodeSlicer:
    """
    LLM-based code slicer that extracts relevant code context based on different strategies.
    Supports caller slicing (context around call site) and value slicing (data dependencies).
    """
    def __init__(self, api_config: Optional[Dict] = None):
        config = api_config or {}
        self.llm = ChatOpenAI(
            model=config["worker"]["helper"]["model_name"]["gpt-5-nano"],
            temperature=0.1,
            timeout=None,
            api_key=config["worker"]["helper"]["OPENAI_API_KEY"],
            base_url=config["worker"]["helper"]["OPENAI_API_BASE"]
        )
        
        # Load slicer prompts
        if not SLICER_PROMPT_MAP:
            global_logger.warning("SLICER_PROMPT_MAP is empty. Ensure prompts are loaded before using CodeSlicer.")
        
        self.caller_prompt = SLICER_PROMPT_MAP.get("caller", "")
        self.value_prompt = SLICER_PROMPT_MAP.get("value", "")
    
    def slice_caller_context(self, caller_code: str, func_name: str) -> str:
        """
        Slice caller function code to extract key context around the call site.
        
        Args:
            caller_code: Full decompiled code of the caller function
            func_name: Name of the called function (callee)
            
        Returns:
            Sliced code showing context around the call site
        """
        try:
            prompt = self.caller_prompt.format(
                caller_code=caller_code,
                func_name=func_name
            )
            
            response = self.llm.invoke(prompt)
            content = response.content if hasattr(response, 'content') else str(response)
            
            # Remove any markdown code blocks if present
            content = re.sub(r"```(?:c|cpp|python)?\s*([\s\S]*?)\s*```", r"\1", content).strip()
            
            return content if content else caller_code
            
        except Exception as e:
            global_logger.error(f"Caller slicing failed: {str(e)}")
            # Return original code if slicing fails
            return caller_code
    
    def slice_value_dependencies(self, func_code: str, value_names: List[str]) -> str:
        """
        Slice function code to extract data dependencies of specific values.
        
        Args:
            func_code: Full decompiled code of the function
            value_names: List of target value/variable names to trace (supports single or multiple)
            
        Returns:
            Sliced code showing data dependencies of the target values
        """
        try:
            # Convert value_names to string form
            if isinstance(value_names, str):
                value_names = [value_names]
            
            value_name_str = ", ".join(value_names) if len(value_names) > 1 else value_names[0]
            
            prompt = self.value_prompt.format(
                func_code=func_code,
                value_name=value_name_str,
            )
            
            response = self.llm.invoke(prompt)
            content = response.content if hasattr(response, 'content') else str(response)
            
            # Remove any markdown code blocks if present
            content = re.sub(r"```(?:c|cpp|python)?\s*([\s\S]*?)\s*```", r"\1", content).strip()
            
            return content if content else func_code
            
        except Exception as e:
            global_logger.error(f"Value slicing failed: {str(e)}")
            # Return original code if slicing fails
            return func_code

class ContextActor:
    """
    Uses tool execution (IDA) to collect contextual information
    about functions or files relevant to the patch being analyzed.
    """
    def __init__(self, project_name: str, project_dir: str, api_config: Dict = None, 
                 prompt_version: str = "default", IDA_state: bool = False, 
                 ida_host: str = "127.0.0.1", ida_port: int = 20000):
        """
        Initialize the ContextActor with project directory and optional file name.
        """
        self.project_name = project_name
        self.project_dir = project_dir
        self.prompt_version = prompt_version
        self.api_config = api_config
        self.IDA_state = IDA_state

        self.Ltools = LangTools(project_name, host=ida_host, port=ida_port)
        
        # Initialize code slicer for context refinement
        self.code_slicer = CodeSlicer(api_config=api_config)
        
        # If IDA project is not initialized externally, check if project is ready
        # Note: Project opening should be done in SPD.py, here we only check status
        if not IDA_state:
            if not self.Ltools.check_ida_project():
                raise ValueError(f"IDA project {project_name} is not ready")
            global_logger.debug(f"ContextActor: IDA project ready: {project_name}")

    def collect_context(self, analysis: Dict) -> List[Dict]:
        """
        Collect context based on the provided analysis.
        """
        result = self._process_context( analysis.get('required_context', {}))
        return result

    def execute_tool(self, tool_type: str, sub_tool: str, params: Dict) -> Any:
        max_retries = 3
        retry_delay = 1 
        for attempt in range(max_retries):
            try:
                tool = self.Ltools.get_ida_tool(tool_type).get(sub_tool)
            
                if not callable(tool):
                    raise ValueError(f"{tool_type}.{sub_tool} is not callable")
                return tool(**params)
            except Exception as e:
                global_logger.warning(f"[Tools Execut Attempt {attempt + 1}/{max_retries} ERROR] {tool_type}.{sub_tool}.{params}\ndetails:\n{self.project_dir}\n{str(e)}\n")
                if attempt < max_retries - 1: 
                    time.sleep(retry_delay)
                    continue
                global_logger.error(f"[Tools Execut FINAL ERROR after {max_retries} attempts] {tool_type}.{sub_tool}.{params}\ndetails:\n{self.project_dir}\n{str(e)}\n")
                return None

    def __exit__(self):
        pass

    def _in_file_cache_fetch(self, file_path: str) -> Optional[str]:
        """
        Fetch the actual file path from the cache using fuzzy matching.
        Supports wildcard-style paths like 'core/iwasm/interpreter/*' or 'tcpdump/*.c'.
        """
        if self.file_cache is None:
            return None

        target_path = file_path.strip().lstrip('/')

        # === Case: directory + wildcard extension (e.g., tcpdump/*.c) ===
        if '*' in target_path:
            if target_path.endswith('*.c') or target_path.endswith('*.h') or '*.' in target_path:
                dir_part, _, ext_pattern = target_path.partition('*')
                ext_suffix = ext_pattern if ext_pattern.startswith('.') else f'.{ext_pattern}'
                for cached_file in self.file_cache:
                    if dir_part in cached_file and cached_file.endswith(ext_suffix):
                        return cached_file

            # Fallback: match directory patterns like core/iwasm/interpreter/*
            dir_prefix = target_path.replace('*', '')
            for cached_file in self.file_cache:
                if dir_prefix in cached_file:
                    return cached_file

            global_logger.warning(f"No wildcard match found for: {file_path}")
            return None

        # === Case: normal fuzzy match ===
        for cached_file in self.file_cache:
            if cached_file.endswith(target_path) or target_path in cached_file:
                return cached_file

        global_logger.warning(f"No matching file found in cache for: \n{self.project_dir}\n{file_path}")
        return None

    def _merge_value_requests(self, tools_query: List[Dict]) -> List[Dict]:
        """
        Merge multiple value_info requests for the same function
        
        Args:
            tools_query: Original tool query list
            
        Returns:
            Merged tool query list
        """
        # Separate value_info and other requests
        value_requests = {}  # {func_name: [value_name1, value_name2, ...]}
        other_requests = []
        
        for tool_entry in tools_query:
            tool_name = tool_entry.get("tool", "")
            params = tool_entry.get("params", {})
            
            # Check if it's a value_info request
            if "value_info" in tool_name or "trace_value" in tool_name:
                func_name = params.get("func_name", "unknown")
                value_name = params.get("value_name", "unknown")
                
                if func_name != "unknown" and value_name != "unknown":
                    if func_name not in value_requests:
                        value_requests[func_name] = []
                    value_requests[func_name].append(value_name)
                else:
                    # If parameters are incomplete, keep original request
                    other_requests.append(tool_entry)
            else:
                other_requests.append(tool_entry)
        
        # Build merged request list
        merged_requests = other_requests.copy()
        
        for func_name, value_names in value_requests.items():
            # For each function, create a merged value_info request
            merged_request = {
                "tool": "value_info.trace_value_by_name",
                "params": {
                    "func_name": func_name,
                    "value_names": value_names  # Use list
                }
            }
            merged_requests.append(merged_request)
            
            global_logger.info(
                f"Merged {len(value_names)} value requests for function '{func_name}': {value_names}"
            )
        
        return merged_requests
    
    def _process_context(self, required_context: str, retry_count: int = 0) -> List[Dict]:
        """
        Process the required context and execute tools to gather results.
        Retries up to 3 times with fallback prompts if no valid context is collected.
        """
        if retry_count >= 3:
            global_logger.error("Maximum Tools retry attempts reached.")
            return [{
                "status": "context error",
                "message": "no valid result, maybe the required_context is not true.",
            }]

        try:
            actor = LLMActor(api_config=self.api_config, prompt_version=self.prompt_version)
            tools_query = actor.generate_tools_query(required_context)
            global_logger.info(f"Tools query: {tools_query}")
            ### repair
            if (isinstance(tools_query, list) and len(tools_query) == 1 and isinstance(tools_query[0], dict) and "tools" in tools_query[0] and isinstance(tools_query[0]["tools"], list)):
                tools_query = tools_query[0]["tools"]
           
            # Preprocess: merge multiple value_info requests for the same function
            tools_query = self._merge_value_requests(tools_query)
           
            tools_result = []
            successful_tools = []
            failed_tools = []

            for tool_entry in tools_query:
                result = self._process_single_tool(tool_entry)
                tools_result.append(result)  # Record all calls, including failed ones
               
                # Distinguish success and failure based on success field
                if result.get("success", False):
                    successful_tools.append(result)
                else:
                    failed_tools.append(result)
                    global_logger.warning(
                        f"Tool call failed: {result.get('tool', 'unknown')} - "
                        f"Error: {result.get('error', 'unknown error')}"
                    )
                   
            # If there are successful tool calls, return all results (including failed ones for recording)
            if successful_tools:
                global_logger.info(
                    f"Context collection completed: {len(successful_tools)} succeeded, "
                    f"{len(failed_tools)} failed out of {len(tools_result)} total"
                )
                print('tools_result:', tools_result)
                return tools_result

            # Retry with updated context prompt
            updated_context = (
                f"{required_context}\nThe last tools query returned no valid results: {tools_query}.\n"
                "Maybe the value_name or func_name is incorrect. Please regenerate tool parameters accordingly."
            )
            return self._process_context(updated_context, retry_count + 1)

        except Exception as e:
            global_logger.error(f"Error processing context: {str(e)}")
            return [{
                "status": "context error",
                "message": str(e),
                "timestamp": datetime.now().isoformat()
            }]

    def _process_single_tool(self, tool_entry: Dict) -> Dict:
        tool_name = tool_entry.get("tool")
        tool_params = tool_entry.get("params", {})

        if tool_name == 'query':
            tool_name = 'query.query'
        if not tool_name or '.' not in tool_name:
            global_logger.warning(f"Invalid tool format: {tool_entry}")
            return {
                "tool": tool_name, 
                "result": None,
                "success": False,
                "error": "Invalid tool format"
            }

        tool_type, sub_tool = tool_name.split('.')
        parsed_params = self._prepare_tool_params(tool_type, tool_params)
        tool_result = self.execute_tool(tool_type, sub_tool, parsed_params)
        
        # Check for timeout
        if tool_result == "Query timed out":
            global_logger.warning(f"Tool execution timed out: {tool_name}({parsed_params}), retrying...")
            if self.Ltools.check_ida_project():
                tool_result = self.execute_tool(tool_type, sub_tool, parsed_params)
                if tool_result == "Query timed out":
                    global_logger.error(f"Tool execution still timed out: {tool_name}({parsed_params})")
                    return {
                        "tool": f"{tool_type}.{sub_tool}({parsed_params})",
                        "result": None,
                        "success": False,
                        "error": "Query timed out"
                    }
        
        # Check for None or empty result
        if tool_result is None:
            global_logger.error(f"Tool execution returned None: {tool_type}.{sub_tool}({parsed_params})")
            return {
                "tool": f"{tool_type}.{sub_tool}({parsed_params})",
                "result": None,
                "success": False,
                "error": "Tool returned None (execution failed)"
            }
        
        if isinstance(tool_result, str) and not tool_result.strip():
            global_logger.warning(f"Tool execution returned empty string: {tool_type}.{sub_tool}({parsed_params})")
            return {
                "tool": f"{tool_type}.{sub_tool}({parsed_params})",
                "result": None,
                "success": False,
                "error": "Tool returned empty result"
            }
        
        global_logger.debug(f"Tool result: {tool_result}")
        # Pass tool_type and parsed_params to _format_tool_result for slicing
        formatted_result = self._format_tool_result(tool_type, tool_result, parsed_params)
        global_logger.info(f"Executing tool: {tool_type}.{sub_tool}({parsed_params})")
        global_logger.info(f"Tool result: {formatted_result}")
        
        # Check if formatted result is empty
        is_empty = (
            formatted_result is None or 
            formatted_result == [] or 
            (isinstance(formatted_result, str) and not formatted_result.strip())
        )
        
        if is_empty:
            global_logger.warning(f"Formatted result is empty for: {tool_type}.{sub_tool}({parsed_params})")
            return {
                "tool": f"{tool_type}.{sub_tool}({parsed_params})",
                "result": None,
                "success": False,
                "error": "Formatted result is empty"
            }
        
        return {
            "tool": f"{tool_type}.{sub_tool}({parsed_params})",
            "result": formatted_result,
            "success": True
        }

    def _prepare_tool_params(self, tool_type: str, params: Dict) -> Dict:
        parsed = {}
        for key, val in params.items():
            parsed[key] = val
            if key == "value":
                if "struct " in val:
                    val = val.split("struct ")[-1]
                parsed["value_name"] = val
                del parsed[key]
            if key == "value_name":
                if "struct " in val:
                    val = val.split("struct ")[-1]
                parsed["value_name"] = val
            if key == "value_names":
                # Process value_names list (merged multiple values)
                if isinstance(val, list):
                    # Clean each value_name
                    cleaned_values = []
                    for v in val:
                        if "struct " in v:
                            v = v.split("struct ")[-1]
                        cleaned_values.append(v)
                    parsed["value_names"] = cleaned_values
            if key == "func_name" and isinstance(val, str) and "::" in val:
                val = val.split("::")[-1]
                parsed["func_name"] = val
                
        if "caller" in tool_type:
            tool_type = "caller_info"
        elif "func" in tool_type:
            tool_type = "func_info"
        elif "value" in tool_type:
            tool_type = "value_info"
            
            # Validate that value_info must have func_name
            if "func_name" not in parsed:
                global_logger.error(
                    f"value_info tool requires 'func_name' parameter. "
                    f"Received params: {params}"
                )
                raise ValueError(
                    f"Missing required parameter 'func_name' for value_info tool. "
                    f"To trace a value, you must specify which function it belongs to. "
                    f"Params received: {params}"
                )
            
        if tool_type in {"func_info", "caller_info", "code_info"}:
            # parsed["project_dir"] = self.project_dir
            pass
        return parsed
   


    def _format_tool_result(self, tool_type: str, tool_result: Any, tool_params: Dict = None) -> Any:
        """
        Format the result of a tool based on its type.
        Applies code slicing for caller_info and value_info types.
        
        Args:
            tool_type: Type of tool (func_info, caller_info, value_info)
            tool_result: Raw result from the tool
            tool_params: Parameters used for the tool call (needed for slicing)
        """
        tool_params = tool_params or {}
        
        try:
            if tool_type == "func_info":
                # Function info: no slicing needed, just return as-is
                if not tool_result:
                    return []
                if isinstance(tool_result, str):
                    return [
                        {
                            "type": "function_def",
                            "code": tool_result,
                        }
                    ]
               
            elif tool_type == 'caller_info':
                # Caller info: slice each caller to extract key context around call site
                if not tool_result:
                    return []

                if not isinstance(tool_result, list):
                    global_logger.warning(f"Unexpected return type for caller_info: {type(tool_result)}")
                    return []
                
                func_name = tool_params.get("func_name", "unknown")
                sliced_results = []
                
                # tool_result already contains caller_code from _find_caller_for_func
                for item in tool_result:
                    caller_name = item.get("caller_name", "unknown")
                    caller_code = item.get("caller_code", "")
                    
                    # Slice the caller code to extract context around the call
                    sliced_code = ""
                    if caller_code:
                        try:
                            sliced_code = self.code_slicer.slice_caller_context(
                                caller_code=caller_code,
                                func_name=func_name
                            )
                        except Exception as e:
                            global_logger.warning(f"Slicing failed for caller {caller_name}: {e}")
                            sliced_code = caller_code  # Fallback to original code
                    else:
                        global_logger.warning(f"Empty caller_code for caller {caller_name}")
                        sliced_code = f"// Unable to retrieve code for caller: {caller_name}"
                    
                    sliced_results.append({
                        "type": "caller_info",
                        "caller_name": caller_name,
                        "caller_code": sliced_code,  # Sliced code
                    })
                
                return sliced_results
                
            elif tool_type == 'value_info':
                # Value info: slice to extract data dependencies
                if not tool_result:
                    return []
                if isinstance(tool_result, str):
                    func_name = tool_params.get("func_name", "unknown")
                    
                    # Support single value_name or multiple value_names
                    value_names = tool_params.get("value_names")
                    if value_names is None:
                        # Compatible with old single value_name
                        value_name = tool_params.get("value_name", "unknown")
                        value_names = [value_name] if value_name != "unknown" else []
                    
                    if not value_names:
                        global_logger.warning("No value_names found in tool_params")
                        return []
                    
                    # Slice the code to extract data dependencies
                    try:
                        sliced_code = self.code_slicer.slice_value_dependencies(
                            func_code=tool_result,
                            value_names=value_names
                        )
                    except Exception as e:
                        value_names_str = ", ".join(value_names)
                        global_logger.warning(f"Slicing failed for values {value_names_str}: {e}")
                        sliced_code = tool_result
                    
                    return [
                        {
                            "type": "value_info",
                            "func_name": func_name,
                            "value_names": value_names,  # Save value_names list
                            "code": sliced_code,  # Sliced code showing data dependencies
                        }
                    ]

            else:
                return tool_result  
        except Exception as e:
            global_logger.error(f"Error formatting tool result: {str(e)} \n{tool_result}")
            return []

class VulnWorkflow:
    """Orchestrates vulnerability analysis workflow with state management

    Attributes:
        MAX_ITERATIONS: Maximum allowed analysis cycles
        CONFIDENCE_THRESHOLD: Minimum confidence score for finalization
    """

    MAX_ITERATIONS = 3
    CONFIDENCE_THRESHOLD = 0.90

    def __init__(self, api_config: Dict = None):
        self.api_config = api_config or {}
        self.graph = self._build_workflow_graph()

        # initialize prompt version map
        prompt_loader = PromptLoader(self.api_config)
        prompt_loader.load_prompts()    


    def _build_workflow_graph(self) -> StateGraph:
        """Builds the StateGraph for the vulnerability analysis workflow."""
        builder = StateGraph(AgentState)

        # Define nodes
        builder.add_node("prefilter", self._prefilter_patch)
        builder.add_node("collect", self._collect_context)
        builder.add_node("analyze", self._perform_analysis)
        builder.add_node("finalize", self._generate_report)
        builder.add_node("error_handler", self._handle_final_error) # Add an error handler node

        # Define entry point - start with prefilter
        builder.set_entry_point("prefilter")

        # prefilter transitions: if non-security, go to finalize; if security, go to analyze
        builder.add_conditional_edges(
            "prefilter",
            self._route_from_prefilter,
            {
                "analyze": "analyze",
                "finalize": "finalize",
                "error_handler": "error_handler"
            }
        )

        # analyze transitions based on need_context, confidence, iteration limit, or errors
        builder.add_conditional_edges(
            "analyze",
            self._route_from_analyze,
            {
                "collect": "collect",
                "finalize": "finalize",
                "error_handler": "error_handler" 
            }
        )

        # collect transitions always to analyze, unless there's an error during collection itself
        builder.add_conditional_edges(
            "collect",
            self._route_from_collect,
            {
                "analyze": "analyze",
                "error_handler": "error_handler" 
            }
        )

        return builder.compile()

    # --- Workflow Nodes ---

    def _prefilter_patch(self, state: AgentState) -> Dict:
        """Pre-filter patches to identify obvious non-security patches."""
        if state.get("status") == "error":
            return state

        # Skip prefilter if disabled
        if not state.get("enable_prefilter", True):
            global_logger.info("Pre-filter is disabled, skipping to deep analysis.")
            return {
                **state,
                "debug_trace": state.get("debug_trace", []) + ["Pre-filter disabled, proceeding to deep analysis."]
            }

        try:
            global_logger.info("Starting pre-filter stage...")
            classifier = PreFilterClassifier(self.api_config, prompt_version=state.get("prompt_version", "default"))
            classification, prompt = classifier.classify_patch(state)
            
            is_security = classification.get("is_security_patch", "yes").lower()
            analysis_text = classification.get("analysis", "")
            function_classifications = classification.get("function_classification", [])

            original_patch = state.get("patch", [])
            filtered_patch = original_patch
            removed_functions: List[str] = []

            if (
                isinstance(function_classifications, list)
                and function_classifications
                and original_patch
            ):
                no_functions = {
                    entry.get("func_name", "")
                    for entry in function_classifications
                    if entry.get("is_security_related", "").lower() == "no"
                }
                no_functions.discard("")

                if no_functions:
                    filtered_patch = [
                        item for item in original_patch
                        if item.get("func_name") not in no_functions
                    ]
                    removed_functions = [
                        item.get("func_name") for item in original_patch
                        if item.get("func_name") in no_functions
                    ]
            
            # Record prefilter result
            prefilter_record = {
                "stage": "pre-filter",
                "prompt": prompt,
                "result": classification,
                "timestamp": datetime.now().isoformat()
            }
            updated_analysis_record = state.get("analysis_record", []) + [prefilter_record]
            
            new_state = {
                **state,
                "prefilter_result": classification,
                "analysis_record": updated_analysis_record,
                "patch": filtered_patch,
                "debug_trace": state.get("debug_trace", []) + [
                    f"Pre-filter completed: is_security_patch={is_security}"
                ]
            }

            if removed_functions:
                removed_readable = ", ".join(sorted(set(filter(None, removed_functions))))
                new_state["debug_trace"].append(
                    f"Removed non-security functions from patch: {removed_readable}"
                )
            
            # If classified as non-security, prepare for finalization
            if is_security == "no":
                new_state["analysis"] = {
                    "is_security_patch": "no",
                    "vulnerability_type": "N/A",
                    "repair_strategy": "N/A",
                    "root_cause": analysis_text,
                    "need_context": False,
                    "confidence_score": 1.0
                }
                new_state["confidence_score"] = 1.0
                new_state["need_context"] = False
                new_state["status"] = "completed"
            
            return new_state
            
        except Exception as e:
            error_msg = f"Pre-filter failed: {str(e)}"
            global_logger.error(error_msg, exc_info=True)
            # On error, proceed to deep analysis
            return {
                **state,
                "debug_trace": state.get("debug_trace", []) + [f"Pre-filter error: {error_msg}, proceeding to deep analysis."]
            }

    def _collect_context(self, state: AgentState) -> Dict:
        """Collects additional context based on analysis requirements."""
        if state.get("status") == "error":
             return state 

        # First check required parameters before creating actor
        required_actor_keys = ["project_name","project_dir"]
        if not all(key in state for key in required_actor_keys):
             missing = [key for key in required_actor_keys if key not in state]
             error_msg = f"Missing required actor configuration in state: {', '.join(missing)}"
             global_logger.error(error_msg)
             return self._update_state_with_error(state, error_msg)

        actor = None
        try:
            ida_host = state.get('ida_host') or '127.0.0.1'
            ida_port = state.get('ida_port') or 20000
            actor = ContextActor(
                project_name=state['project_name'],
                project_dir=str(state["project_dir"]),
                api_config=self.api_config,
                prompt_version=state.get("prompt_version", "default"),
                IDA_state=state.get('IDA_available', False),
                ida_host=ida_host,
                ida_port=ida_port
            )
            required_context_info = state.get("analysis", {}).get("required_context", {})
            if not required_context_info:
                 global_logger.info("Analysis requires no additional context collection.")
                 # Even if no context is needed, close actor (handled in finally block)
                 return state

            collected = actor.collect_context(state["analysis"])

            # Distinguish successful and failed tool calls
            # Use success field to judge (new standard), also compatible with old status field
            successful_collections = []
            failed_collections = []
            
            for item in collected:
                # Check if it's old context error format
                if item.get("status") == "context error":
                    failed_collections.append(item)
                # Check new success field
                elif "success" in item:
                    if item.get("success", False):
                        successful_collections.append(item)
                    else:
                        failed_collections.append(item)
                # Default handling: if result exists and is non-empty, consider it successful
                elif item.get("result"):
                    successful_collections.append(item)
                else:
                    failed_collections.append(item)
            
            if failed_collections:
                global_logger.warning(
                    f"Encountered {len(failed_collections)} failed tool calls. "
                    f"Failed tools: {[item.get('tool', 'unknown') for item in failed_collections]}"
                )

            # Update tools_record, record tool call results (including failed ones)
            current_tools_record = {
                "iteration": state.get("iteration", 0),
                "stage": "collection",
                "required_context": required_context_info,
                "tools_executed": len(collected),
                "successful_tools": len(successful_collections),
                "failed_tools": len(failed_collections),
                "results": collected,  # Contains all results, successful and failed
                "timestamp": datetime.now().isoformat()
            }
            updated_tools_record = state.get("tools_record", []) + [current_tools_record]

            # Only add successful results to enriched_data
            updated_enriched_data = state.get("enriched_data", []) + successful_collections

            new_state = {
                **state,
                "enriched_data": updated_enriched_data,
                "tools_record": updated_tools_record,
                "debug_trace": state.get("debug_trace", []) + [
                    f"Collected {len(successful_collections)} context items. ({len(failed_collections)} failed)"
                ]
            }

            return new_state

        except KeyError as e:
            error_msg = f"Missing required state key for context collection: {str(e)}"
            global_logger.error(error_msg, exc_info=True)
            return self._update_state_with_error(state, error_msg)
        except Exception as e:
            error_msg = f"Context collection failed: {str(e)}"
            global_logger.error(error_msg, exc_info=True)
            return self._update_state_with_error(state, error_msg)
        finally:
            # Ensure IDA process is closed regardless of what happens
            if actor is not None:
                try:
                    global_logger.debug(f"Successfully closed IDA actor for project: {state.get('project_name', 'unknown')}")
                except Exception as e:
                    global_logger.error(f"Failed to close IDA actor: {str(e)}", exc_info=True)


    def _perform_analysis(self, state: AgentState) -> Dict:
        """Performs root cause analysis using collected context."""
        if state.get("status") == "error":
             return state 

        # Input validation
        required_keys = ["patch"]
        if not all(key in state for key in required_keys):
            missing = [key for key in required_keys if key not in state]
            error_msg = f"Missing required state keys: {', '.join(missing)}"
            global_logger.error(error_msg)
            return self._update_state_with_error(state, error_msg)

        current_iteration = state.get("iteration", 0)
        new_iteration = current_iteration + 1 

        try:
            critic = VulnerabilityCritic(self.api_config, prompt_version=state.get("prompt_version", "default"))
            report, prompt = critic.determine_root_cause(state)
            if report.get("status") == "error":
                error_msg = f"Analysis failed: {report.get('reason', 'Unknown error')}"
                global_logger.error(error_msg, exc_info=True)
                return self._update_state_with_error(state, error_msg)
            need_context = report.get("need_context", False)
            if isinstance(need_context, str):
                 need_context = need_context.lower() == 'true'

            confidence_score = report.get("confidence_score", 0.0)

            # Update analysis_record, add current analysis result
            current_analysis_record = {
                "stage": "analysis",
                "iteration": new_iteration,
                "prompt": prompt,
                "result": report,
                "timestamp": datetime.now().isoformat()
            }
            updated_analysis_record = state.get("analysis_record", []) + [current_analysis_record]

            new_state = {
                **state, #
                "iteration": new_iteration,  # Update iteration count
                "analysis": {**state.get("analysis", {}), **report}, 
                "analysis_record": updated_analysis_record,  # Update analysis record
                "need_context": need_context, 
                "confidence_score": confidence_score, 
                "root_cause": report.get("root_cause", state.get("root_cause", [])), # Update root cause
                 "debug_trace": state.get("debug_trace", []) + [
                    f"Performed analysis iteration {new_iteration}. Needs more context: {need_context}. Confidence: {confidence_score:.2f}"
                 ]
            }

            return new_state

        except Exception as e:
            error_msg = f"Analysis failed: {str(e)}"
            global_logger.error(error_msg, exc_info=True)
            return self._update_state_with_error(state, error_msg)


    def _generate_report(self, state: AgentState) -> Dict:
        """Generates the final vulnerability report."""
        if state.get("status") == "error":
             global_logger.warning("Attempted to generate report while in error state.")
             return {
                    **state,
                    "status": "error",
                    "final_report": "Error state reached before report generation.",
                    "debug_trace": state.get("debug_trace", []) + ["Report generation failed due to error state."]
             }

        global_logger.info("Finalizing report.")
        
        # Determine classification stage based on prefilter_result
        prefilter_result = state.get("prefilter_result", {})
        is_security = prefilter_result.get("is_security_patch", "yes").lower() if prefilter_result else "yes"
        classification_stage = "Pre-filter" if is_security == "no" else "Deep analysis"
        
        # Check if maximum iteration count is reached
        current_iteration = state.get("iteration", 0)
        need_context = state.get("need_context", False)
        reached_max_iter = current_iteration >= self.MAX_ITERATIONS and need_context
        
        status_note = ""
        if reached_max_iter:
            status_note = f" (reached max iterations: {self.MAX_ITERATIONS})"
            global_logger.warning(f"Analysis reached maximum iterations ({self.MAX_ITERATIONS}) with incomplete context.")
        
        final_report_content = f"""
Vulnerability Report
====================

Classification Stage: {classification_stage}
Status: Completed{status_note}
Iterations: {current_iteration}/{self.MAX_ITERATIONS}
Root Cause: {json.dumps(state.get('root_cause', []), indent=2) if state.get('root_cause') else state.get('analysis', {}).get('root_cause', 'N/A')}
Confidence Score: {state.get('confidence_score', 0.0):.2f}
Vulnerability Type: {state.get('analysis', {}).get('vulnerability_type', 'N/A')}
Repair Strategy: {state.get('analysis', {}).get('repair_strategy', 'N/A')}
"""
        
        if reached_max_iter:
            final_report_content += f"""
Note: Analysis stopped at maximum iterations ({self.MAX_ITERATIONS}).
The root cause chain may be incomplete. Consider increasing MAX_ITERATIONS if more context is needed.
Required Context (unfulfilled): {json.dumps(state.get('analysis', {}).get('required_context', []), indent=2)}
"""
        # Generate report from analysis_record
        for entry in state.get("analysis_record", []):
             final_report_content += f"- Stage: {entry['stage']}, Timestamp: {entry['timestamp']}\n"
             if entry['stage'] == 'analysis':
                  final_report_content += f"  Iteration: {entry.get('iteration', 'N/A')}, Needs Context: {entry['result'].get('need_context', 'N/A')}, Confidence: {entry['result'].get('confidence_score', 'N/A'):.2f}\n"
             elif entry['stage'] == 'pre-filter':
                  final_report_content += f"  Result: is_security_patch={entry['result'].get('is_security_patch', 'N/A')}\n"
             # Add more details from analysis entries as needed
        
        # Generate tool call report from tools_record
        for entry in state.get("tools_record", []):
             final_report_content += f"- Tools: {entry['stage']}, Iteration: {entry.get('iteration', 'N/A')}, Success: {entry.get('successful_tools', 0)}/{entry.get('tools_executed', 0)}\n"

        return {
            **state,
            "status": "completed",
            "final_report": final_report_content,
            "debug_trace": state.get("debug_trace", []) + ["Report generation completed."]
        }

    def _handle_final_error(self, state: AgentState) -> Dict:
        """Handles the workflow reaching a final error state."""
        error_message = state.get("error", "An unknown error occurred.")
        global_logger.error(f"Workflow ended in error state: {error_message}")

        return {
            **state,
            "status": "error",
            "final_report": f"Workflow failed: {error_message}\nDebug Trace:\n" + "\n".join(state.get("debug_trace", []))
        }

    # --- Conditional Routing Functions ---
    
    def _route_from_prefilter(self, state: AgentState) -> str:
        """Routes from prefilter based on classification result."""
        if state.get("status") == "error":
            global_logger.debug("_route_from_prefilter: Routing to error_handler due to error status.")
            return "error_handler"
        
        # If prefilter is disabled or not applicable, go to analyze
        if not state.get("enable_prefilter", True):
            global_logger.debug("_route_from_prefilter: Pre-filter disabled, routing to analyze.")
            return "analyze"
        
        # Check prefilter result
        prefilter_result = state.get("prefilter_result", {})
        is_security = prefilter_result.get("is_security_patch", "yes").lower()
        
        # Check if it's a non-security patch
        if is_security == "no":
            global_logger.debug(f"_route_from_prefilter: Non-security patch detected, routing to finalize.")
            return "finalize"
        else:
            global_logger.debug(f"_route_from_prefilter: Potential security patch detected, routing to analyze for deep analysis.")
            return "analyze"

    def _route_from_collect(self, state: AgentState) -> str:
        """Routes from collect based on collection success/failure."""
        # Check for error state first. Collection errors set status="error".
        if state.get("status") == "error":
            global_logger.debug("_route_from_collect: Routing to error_handler due to error status.")
            return "error_handler"

        global_logger.debug("_route_from_collect: Routing to analyze.")
        return "analyze"


    def _route_from_analyze(self, state: AgentState) -> str:
        """Routes from analyze based on analysis results, iteration limit, and errors."""
        if state.get("status") == "error":
            global_logger.debug("_route_from_analyze: Routing to error_handler due to error status.")
            return "error_handler"

        current_iteration = state.get("iteration", 0) # Should be >= 1 after analysis
        need_context = state.get("need_context", False) 
        if isinstance(need_context, str):
            need_context = need_context.lower() == 'true'
        confidence_score = state.get("confidence_score", 0.0)

        global_logger.debug(f"_route_from_analyze: Iteration: {current_iteration}, Need context: {need_context}, Confidence: {confidence_score:.2f}")

        # Check iteration limit
        if current_iteration >= self.MAX_ITERATIONS:
            global_logger.warning(f"_route_from_analyze: Maximum iterations ({self.MAX_ITERATIONS}) reached.")
            global_logger.debug("_route_from_analyze: Routing to finalize (max iterations reached).")
            return "finalize"

        if need_context:
            # global_logger.debug("_route_from_analyze: Routing to collect (needs more context).")
            return "collect"
        else:
            if confidence_score >= self.CONFIDENCE_THRESHOLD:
                global_logger.debug("_route_from_analyze: Routing to finalize (confident enough).")
                return "finalize"
            else:
                error_msg = f"Analysis finished (no context needed) but confidence ({confidence_score:.2f}) below threshold ({self.CONFIDENCE_THRESHOLD})."
                global_logger.error(error_msg)
                state = self._update_state_with_error(state, error_msg)
                return "error_handler"


    # --- Helper Method for Error State Update ---
    def _update_state_with_error(self, state: AgentState, message: str) -> Dict:
        """Helper to consistently update state when an error occurs."""
        if state is None:
            state = {}

        debug_trace = state.get("debug_trace", [])
        if not debug_trace or debug_trace[-1] != message: 
             debug_trace.append(message)

        return {
            **state,
            "status": "error",
            "error": message,
            "debug_trace": debug_trace
        }


    # --- Utility Method ---
    def visualize_workflow(self) -> str:
        """Provides a visual representation of the workflow."""
        return """
        My Vulnerability Analysis Workflow (Revised)
        ===========================================
        Nodes:
        - analyze: Root cause analysis (iterative, entry point)
        - collect: Context data collection
        - finalize: Report generation (success state)
        - error_handler: Handles workflow errors (failure state)

        State Transitions:
        [analyze] --(needs more context)--> [collect]
        [analyze] --(no more context, confident)--> [finalize]
        [analyze] --(no more context, not confident OR max iterations reached)--> [finalize]
        [analyze] --(analysis error OR stuck)--> [error_handler]
        [analyze] --(max iterations, still needs context)--> [finalize]

        [collect] --(successful)--> [analyze]
        [collect] --(collection error)--> [error_handler]

        Error Flow: Any node can potentially lead to [error_handler] if a critical exception or defined error condition occurs.
        Final States: [finalize], [error_handler]
        """

def load_diff_list(json_path: str) -> List[Dict[str, Any]]:
    text = Path(json_path).read_text(encoding='utf-8')
    data = json.loads(text)
    return data
