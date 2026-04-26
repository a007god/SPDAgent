import os
import json
import logging
import queue
import threading
import time
from pydantic.type_adapter import P
import yaml
from pathlib import Path
from typing import Dict, List, Set, Union, Tuple, Optional
from functools import lru_cache


from .agent_worker import VulnWorkflow, AgentState
from utils.logging_helper import global_logger
logger = global_logger

# Result and deduplication files
SUCCESS_FILE = Path("./final_check_success.txt")
FAILED_FILE = Path("./final_check_error.txt")


# ===================== Utility Functions =====================
def append_to_success(project_id: str, project_path: Path, context_count: int, iteration: int, confidence_score: float) -> None:
    with open(SUCCESS_FILE, 'a') as f:
        f.write(f"{project_id},{project_path},{context_count},{iteration},{confidence_score}\n")

def append_to_failed(project_id: str, project_path: Path, reason: str) -> None:
    with open(FAILED_FILE, 'a') as f:
        f.write(f"{project_id},{project_path},{reason}\n")

def load_success_ids() -> Set[str]:
    """Read success list to avoid duplicate processing."""
    success_ids: Set[str] = set()
    if SUCCESS_FILE.exists():
        with open(SUCCESS_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                project_id = line.split(',')[0]
                # Robustness for compatibility with old format
                try:
                    parts = line.split(',')
                    iteration = int(parts[3])
                    context_count = int(parts[2])
                    confidence_score = float(parts[4])
                    if context_count == 0 and iteration > 0:
                        global_logger.warning(f"[suspicious success] {line}")
                except Exception:
                    pass
                success_ids.add(project_id)
    return success_ids

def discover_projects(base_dir: Path) -> List[Tuple[str, Path]]:
    """
    Recursively find "project directories" containing diff.json (i.e., firmware_version/firmware_version_bin_name).
    Returns [(project_id, project_dir)]:
      - project_id uses relative path string for identification, convenient for deduplication and logging
      - project_dir is the directory containing diff.json
    """
    projects: List[Tuple[str, Path]] = []
    for diff_path in base_dir.rglob("diff.json"):
        project_dir = diff_path.parent
        # Use relative path from base_dir as ID (stable and readable)
        project_id = str(project_dir.relative_to(base_dir))
        projects.append((project_id, project_dir))
    return projects

def count_valid_contexts(enriched_data: List[Dict]) -> int:
    count = 0
    for item in enriched_data:
        result = item.get("result")
        if isinstance(result, str):
            if "no valid" not in result:
                count += 1
        elif isinstance(result, list) and result:
            count += 1
        else:
            count += 1
    return count


# ===================== Token & Chunking Utilities =====================
_tiktoken_encoder_cache: Dict[str, any] = {}
def _get_encoder(model_name: Optional[str]) -> Optional[any]:
    try:
        import tiktoken  # type: ignore
    except Exception:
        return None
    if not model_name:
        model_name = "cl100k_base"
    # Cache encoders by model/encoding name
    enc = _tiktoken_encoder_cache.get(model_name)
    if enc is not None:
        return enc
    try:
        # Try mapping model to encoding
        enc = tiktoken.encoding_for_model(model_name)
    except Exception:
        try:
            enc = tiktoken.get_encoding("cl100k_base")
        except Exception:
            enc = None
    if enc is not None:
        _tiktoken_encoder_cache[model_name] = enc
    return enc

def estimate_tokens(text: str, model_name: Optional[str] = None) -> int:
    """More precise token estimation: prioritize tiktoken; otherwise fallback to len/4 approximation."""
    if not text:
        return 0
    enc = _get_encoder(model_name)
    if enc is not None:
        try:
            return len(enc.encode(text))
        except Exception:
            pass
    # Fallback heuristic
    return max(1, int(len(text) / 4))

def make_patch_items(all_diffs: List[Dict]) -> List[Dict]:
    items: List[Dict] = []
    for p in all_diffs:
        old_func = p.get("old_func", "")
        new_func = p.get("new_func", "")
        
        # Determine function name based on whether it's added, deleted, or modified
        if old_func == "":
            # Function only in new version (added) - mark with <N:...>
            func_name = f"<N:{new_func}>"
        else:
            # Normal matched function (modified) or deleted function
            func_name = new_func or old_func or ""
        
        patch_text = p.get("diff") or ""
        items.append({
            "func_name": func_name,
            "patch": patch_text,
        })
    return items


def _item_token_cost(item: Dict, model_name: Optional[str] = None) -> int:
    # Unified "how to estimate token" approach, consistent with your original
    token_body = estimate_tokens(
        f"Function: {item.get('func_name','')}\nDiff:\n{item.get('patch','')}",
        model_name=model_name
    )
    # Fixed overhead per item (you previously used +48)
    return token_body + 48

def pack_batches_by_token(
    patches: List[Dict],
    max_tokens_per_query: int,
    *,
    model_name: Optional[str] = None
) -> List[List[Dict]]:
    """First fit descending, compute token count here on demand, don't write back to data."""
    if max_tokens_per_query <= 0:
        return [patches]

    # Add a simple cache layer for token calculation to avoid repeated computation
    @lru_cache(maxsize=None)
    def cost_of(index: int) -> int:
        return _item_token_cost(patches[index], model_name=model_name)

    # Sort by cost first (use index to avoid modifying original object)
    indices = list(range(len(patches)))
    indices.sort(key=lambda i: cost_of(i), reverse=True)

    batches: List[List[Dict]] = []
    batch_costs: List[int] = []

    batch_overhead = 256
    effective_limit = max(0, int(max_tokens_per_query * 0.9) - batch_overhead)

    for i in indices:
        c = cost_of(i)
        placed = False
        for bi in range(len(batches)):
            if batch_costs[bi] + c <= effective_limit:
                batches[bi].append(patches[i])
                batch_costs[bi] += c
                placed = True
                break
        if not placed:
            batches.append([patches[i]])
            batch_costs.append(c)
    return batches

def save_result_to_json(result, save_path, file_name):
    save_path = Path(save_path)
    save_path.mkdir(parents=True, exist_ok=True)

    file_path = save_path / file_name

    def convert_posixpath(obj):
        if isinstance(obj, Path):
            return str(obj)
        return obj

    for key in ['file_cache', 'cpg_file', 'base_url', 'joern', 'need_context', 'project_dir', 'prompt_version']:
        result.pop(key, None)

    json_data = json.dumps(
        result,
        default=convert_posixpath,
        indent=4,
        ensure_ascii=False
    )

    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(json_data)
    print(f"Result saved to {file_path}")

# ===================== Main Processing Flow (Two Modes) =====================
def run_workflow(project_name: str, project_dir: Path, llm_config: Dict, patch_batch: List[Dict], 
                 IDA_available: bool, enable_prefilter: bool = True, 
                 ida_host: str = "127.0.0.1", ida_port: int = 20000) -> Dict:
    initial_state = AgentState(
        project_name=project_name,
        project_dir=project_dir,
        patch=patch_batch,
        IDA_available=IDA_available,
        ida_host=ida_host,
        ida_port=ida_port,
        prompt_version="limited",
        enriched_data=[],
        analysis={},
        root_cause=[],
        confidence_score=0.0,
        iteration=0,
        need_context=True,
        analysis_record=[],
        tools_record=[],
        debug_trace=[],
        status=None,
        error=None,
        enable_prefilter=enable_prefilter,
        prefilter_result=None
    )
    workflow = VulnWorkflow(llm_config)
    result = workflow.graph.invoke(initial_state)
    return result

def aggregate_and_save(project_name: str, project_dir: Path, mode: str, batch_results: List[Dict]) -> None:
    out = {
        "project": project_name,
        "mode": mode,
        "batches": [],
        "summary": {
            "completed": 0,
            "errors": 0
        }
    }
    for idx, r in enumerate(batch_results):
        status = r.get("status")
        if status == "completed":
            out["summary"]["completed"] += 1
        else:
            out["summary"]["errors"] += 1
        out["batches"].append({
            "index": idx,
            "status": status,
            "analysis": r.get("analysis"),
            "need_context": r.get("analysis", {}).get("need_context") if isinstance(r.get("analysis"), dict) else None,
            # "confidence_score": r.get("confidence_score"),
            "error": r.get("error"),
            "debug_trace": r.get("debug_trace"),
        })

    out_path = Path(project_dir) / "Analysis_result" / "aggregated_report.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    logger.info(f"Aggregated report saved: {out_path}")


def process_project(project_name: str, project_dir: Path, llm_cfg: Dict, all_diffs: List[Dict], 
                    IDA_available: bool, *, mode: str = "binary", max_tokens_per_query: int = 0, 
                    enable_prefilter: bool = True, ida_host: str = "127.0.0.1", ida_port: int = 20000) -> None:
    patches = make_patch_items(all_diffs)
    
    batch_results: List[Dict] = []
    try:
        if mode == "function":
            for item in patches:
                result = run_workflow(project_name, project_dir, llm_cfg, [item], IDA_available, 
                                    enable_prefilter, ida_host, ida_port)
                batch_results.append(result)
                enriched_data = result.get("enriched_data", [])
                context_count = count_valid_contexts(enriched_data)
                iteration = result.get("iteration", 0)
                confidence_score = result.get("confidence_score", 0.0)
                classification_stage = result.get("classification_stage", "Deep analysis")
                
                # Check if successfully completed (including cases where iteration limit is reached)
                is_completed = result.get("status") == "completed"
                need_context = (result.get("analysis", {}) or {}).get("need_context") in (True, "true", "True")
                reached_max_iter = iteration >= VulnWorkflow.MAX_ITERATIONS and need_context
                
                if is_completed:
                    # Generate normal analysis report regardless of whether iteration limit is reached
                    filename = f"Root_cause_analysis_{item.get('func_name','unknown')}.json"
                    if reached_max_iter:
                        # Add marker in result indicating iteration limit was reached
                        result["max_iteration_reached"] = True
                        result["analysis"]["note"] = f"Analysis stopped at maximum iterations ({iteration}). The root cause chain may be incomplete."
                    save_result_to_json(result, project_dir, filename)
                    append_to_success(project_name, project_dir, context_count, iteration, confidence_score)
                else:
                    save_result_to_json(result, project_dir, f"error_analysis_{item.get('func_name','unknown')}.json")
                    append_to_failed(project_name, project_dir, result.get("error", "Unknown error"))
        else:
            # binary/file level, perform token batching
            batches = pack_batches_by_token(patches, max_tokens_per_query)
            for bi, batch in enumerate(batches):
                result = run_workflow(project_name, project_dir, llm_cfg, batch, IDA_available, 
                                    enable_prefilter, ida_host, ida_port)
                batch_results.append(result)
                enriched_data = result.get("enriched_data", [])
                context_count = count_valid_contexts(enriched_data)
                iteration = result.get("iteration", 0)
                confidence_score = result.get("confidence_score", 0.0)
                classification_stage = result.get("classification_stage", "Deep analysis")
                
                # Check if successfully completed (including cases where iteration limit is reached)
                is_completed = result.get("status") == "completed"
                need_context = (result.get("analysis", {}) or {}).get("need_context") in (True, "true", "True")
                reached_max_iter = iteration >= VulnWorkflow.MAX_ITERATIONS and need_context
                
                if is_completed:
                    # Generate normal analysis report regardless of whether iteration limit is reached
                    filename = f"Root_cause_analysis_part{bi+1}.json"
                    if reached_max_iter:
                        # Add marker in result indicating iteration limit was reached
                        result["max_iteration_reached"] = True
                        result["analysis"]["note"] = f"Analysis stopped at maximum iterations ({iteration}). The root cause chain may be incomplete."
                    save_result_to_json(result, project_dir, filename)
                    append_to_success(project_name, project_dir, context_count, iteration, confidence_score)
                else:
                    save_result_to_json(result, project_dir, f"error_analysis_part{bi+1}.json")
                    append_to_failed(project_name, project_dir, result.get("error", "Unknown error"))

        # Aggregate
        aggregate_and_save(project_name, project_dir, mode, batch_results)
    except Exception as e:
        append_to_failed(project_name, project_dir, str(e))
        logger.error(f"Processing exception [{project_name}]: {e}")





