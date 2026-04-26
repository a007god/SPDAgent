# -*- coding: utf-8 -*-
"""
IDA Script Part 2: Export pseudocode and pseudotree ONLY for specified functions
This is the second stage of a two-stage process to optimize performance.

The script reads a JSON file containing the list of function names to process.
This significantly improves efficiency when only a small subset of functions have diffs.

Usage: IDA -S ida_script_part2.py <binary>
Environment:
  - IDA_INPUT_PATH: path to binary/i64 file
  - IDA_FUNCTION_LIST: path to JSON file with function names
"""
import re
import sys
from pathlib import Path
import json
import os
import time
from collections import defaultdict

import idaapi
import ida_bytes
import ida_hexrays
import ida_kernwin
import ida_lines
import idautils
import idc
import ida_auto
import ida_funcs
import ida_nalt
import ida_segment
from idaapi import XREF_FAR, fl_CF

# Ensure project root is importable inside IDA embedded Python.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utils.logging_helper import global_logger

_MAX_BASE_LEN = 240
LABEL_RE = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:')


def safe_name(func_name: str) -> str:
    """Truncate function name to safe length"""
    return func_name[:_MAX_BASE_LEN]




# Resolve environment parameters
env_path = os.environ.get('IDA_INPUT_PATH')
if not env_path:
    print("[-] IDA_INPUT_PATH environment variable not set")
    idaapi.qexit(1)
in_path = Path(env_path).resolve()

func_list_path_str = os.environ.get('IDA_FUNCTION_LIST')
if not func_list_path_str:
    global_logger.error("[-] IDA_FUNCTION_LIST environment variable not set")
    idaapi.qexit(1)

func_list_path = Path(func_list_path_str).resolve()


def resolve_output_dirs(in_path: Path) -> tuple[Path, Path]:
    """
    Prepare output directories: decompile folder and pseudotree folder under base_dir.
    """
    base_dir = in_path.parent
    decompile_dir = base_dir / "decompile"
    pseudotree_dir = base_dir / "pseudotree"

    decompile_dir.mkdir(parents=True, exist_ok=True)
    pseudotree_dir.mkdir(parents=True, exist_ok=True)

    return decompile_dir, pseudotree_dir


def load_function_list(json_path: Path) -> set[str]:
    """
    Load the list of function names from JSON file.
    Returns a set of cleaned function names.
    """
    if not json_path.exists():
        global_logger.error(f"[-] Function list file not found: {json_path}")
        return set()
    
    with json_path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    
    # data should be a list of function names
    if isinstance(data, list):
        func_set = {name for name in data}
    else:
        global_logger.error(f"[-] Invalid function list format, expected list")
        return set()
    
    global_logger.info(f"[•] Loaded {len(func_set)} functions to process")
    return func_set


def export_function_catalog(base_dir: Path) -> Path:
    """
    Export a JSON list of all function names detected in current IDA database.
    """
    func_names: list[str] = []
    for func_ea in idautils.Functions():
        name = idc.get_func_name(func_ea)
        if not name:
            continue
        func_names.append(name)

    func_names = sorted(set(func_names))
    out_path = base_dir / "functions.json"

    try:
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(func_names, f, ensure_ascii=False, indent=2)
        global_logger.info(f"[•] Exported {len(func_names)} functions to {out_path}")
    except Exception as exc:
        global_logger.error(f"[!] Failed to export function list: {exc}")
    return out_path


def find_function_by_name(func_name: str):
    """
    Find function entry address by name.
    Returns function EA or None if not found.
    """    
    # Try exact match first
    for func_ea in idautils.Functions():
        name = idc.get_func_name(func_ea)
        if name == func_name:
            return func_ea
    
    return None


def export_pseudocode_selective(out_dir: Path, func_names: set[str]) -> dict:
    """
    Decompile only specified functions to C pseudocode files.
    Returns dict mapping function names to success status.
    """
    start = time.time()
    global_logger.info(f"[•] Writing pseudocode for {len(func_names)} functions → {out_dir}")
    
    results = {"success": [], "failed": [], "not_found": []}
    
    for func_name in func_names:
        func_ea = find_function_by_name(func_name)
        
        if func_ea is None:
            global_logger.warning(f"[!] Function not found: {func_name}")
            results["not_found"].append(func_name)
            continue
        
        seg = idaapi.getseg(func_ea)
        if not seg or not (seg.perm & ida_segment.SEGPERM_EXEC):
            global_logger.warning(f"[!] Function not in executable segment: {func_name}")
            results["not_found"].append(func_name)
            continue
        
        try:
            cfunc = ida_hexrays.decompile(func_ea)
        except ida_hexrays.DecompilationFailure:
            global_logger.warning(f"[!] Decompilation failed: {func_name}")
            results["failed"].append(func_name)
            continue

        filename = safe_name(func_name) + ".c"
        out_file = out_dir / filename
        with out_file.open("w", encoding="utf-8") as f:
            for line in str(cfunc).splitlines():
                f.write(f"{line}\n")
        
        results["success"].append(func_name)
    
    cost = time.time() - start
    global_logger.info(
        f"[✓] Pseudocode export completed: "
        f"success={len(results['success'])}, "
        f"failed={len(results['failed'])}, "
        f"not_found={len(results['not_found'])}, "
        f"cost={cost:.2f}s"
    )
    return results


# ======================================================================
# AST / Pseudotree Functions
# ======================================================================

def safe_decompile(ea):
    """
    Return (cfunc or None, reason string).
    Filters out lib/thunk quickly, and catches hex-rays failures.
    """
    f = ida_funcs.get_func(ea)
    if not f:
        return None, "not a function"

    if f.flags & (ida_funcs.FUNC_LIB | ida_funcs.FUNC_THUNK):
        return None, "lib/thunk"

    try:
        cf = ida_hexrays.decompile(ea)
    except ida_hexrays.DecompilationFailure as ex:
        return None, f"DecompileFailure: {ex}"

    if not cf:
        return None, "None from decompile()"
    if getattr(cf, "body", None) is None:
        return None, "no body"

    return cf, "OK"


def collect_obj_line_map(cfunc) -> dict[int, int]:
    """
    return {obj_id: first_pseudocode_line_no (1‑based)}.
    """
    pc = cfunc.get_pseudocode()
    rst: dict[int, int] = {}
    for ln_idx, _ in enumerate(pc):  # ln_idx 0‑based
        for oid in get_line_obj_ids(cfunc, ln_idx):
            rst.setdefault(oid, ln_idx + 1)  # Store 1-based line_no
    return rst


def get_line_obj_ids(cfunc, ln):
    """
    Parse color tags in pseudocode line `ln` of `cfunc` and return all
    ctree object IDs (obj_id) referenced on that line.
    """
    obj_ids = []
    pc = cfunc.get_pseudocode()
    if ln < 0 or ln >= len(pc):
        return obj_ids

    line = pc[ln].line
    tag = ida_lines.COLOR_ON + chr(ida_lines.COLOR_ADDR)
    pos = line.find(tag)
    while pos != -1:
        start = pos + len(tag)
        end = start + ida_lines.COLOR_ADDR_SIZE
        if end > len(line):
            break
        addr_str = line[start:end]
        try:
            idx = int(addr_str, 16)
            anch = ida_hexrays.ctree_anchor_t()
            anch.value = idx
            if anch.is_valid_anchor() and anch.is_citem_anchor():
                ci = cfunc.treeitems.at(anch.get_index())
                obj_ids.append(ci.obj_id)
        except Exception:
            pass
        pos = line.find(tag, end)
    return obj_ids


def export_pseudotree_selective(out_dir: Path, func_names: set[str]) -> dict:
    """
    Dump pseudo-tree JSON for specified functions only.
    Returns dict mapping function names to success status.
    """
    if not ida_hexrays.init_hexrays_plugin():
        global_logger.warning("[!] Hex-Rays not available, skip pseudotree export")
        return {"success": [], "failed": [], "not_found": []}

    start = time.time()
    out_dir.mkdir(parents=True, exist_ok=True)
    global_logger.info(f"[•] Writing pseudotrees for {len(func_names)} functions → {out_dir}")

    results = {"success": [], "failed": [], "not_found": []}

    for func_name in func_names:
        func_ea = find_function_by_name(func_name)
        
        if func_ea is None:
            results["not_found"].append(func_name)
            continue
        
        seg = idaapi.getseg(func_ea)
        if not seg or not (seg.perm & ida_segment.SEGPERM_EXEC):
            results["not_found"].append(func_name)
            continue

        cfunc, why = safe_decompile(func_ea)
        if not cfunc:
            global_logger.debug(f"[-] skip {func_name} @ {func_ea:x}: {why}")
            results["failed"].append(func_name)
            continue

        line_map = collect_obj_line_map(cfunc)
        builder = _PTBuilder(cfunc, line_map)
        data = builder.build()

        out_file = out_dir / f"{safe_name(func_name)}.json"
        with out_file.open("w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        results["success"].append(func_name)

    cost = time.time() - start
    global_logger.info(
        f"[✓] Pseudotree export done: "
        f"success={len(results['success'])}, "
        f"failed={len(results['failed'])}, "
        f"not_found={len(results['not_found'])}, "
        f"cost={cost:.2f}s"
    )
    return results


# ----------------------------------------------------------------------
# Pseudo-tree builder
# ----------------------------------------------------------------------

class _PTBuilder(ida_hexrays.ctree_parentee_t):
    """
    Traverse ctree, classify nodes (block/stmt/attr), save nodes & edges.
    """
    def __init__(self, cfunc, line_map: dict[int, int]):
        super().__init__()
        self.cfunc = cfunc
        self.line_map = line_map
        self.nodes = {}          # obj_id(str) -> node dict
        self.edges = []          # [ [parent_id, child_id], ... ]
        self._edge_set = set()   # to avoid duplicates
        self._kinds = {}         # cache obj_id -> kind

    def build(self):
        self.apply_to(self.cfunc.body, self.cfunc.body)
        return {"nodes": self.nodes, "edges": self.edges}

    # ------------ helpers ------------
    @staticmethod
    def _is_insn(ci): return isinstance(ci, ida_hexrays.cinsn_t)
    @staticmethod
    def _is_expr(ci): return isinstance(ci, ida_hexrays.cexpr_t)

    def _is_string_ci(self, ci) -> bool:
        if not isinstance(ci, ida_hexrays.cexpr_t):
            return False
        if ci.op == ida_hexrays.cot_str:
            return True
        if ci.op == ida_hexrays.cot_obj:
            ea = ci.obj_ea
            if ea != idaapi.BADADDR:
                return ida_bytes.get_strlit_contents(ea, -1, ida_nalt.STRTYPE_C) is not None
        return False

    def _get_string_val(self, ci) -> str | None:
        if not self._is_string_ci(ci):
            return None
        try:
            if ci.op == ida_hexrays.cot_str:
                return ida_hexrays.cstr_value(ci).decode("utf-8", "replace")
            if ci.op == ida_hexrays.cot_obj:
                s = ida_bytes.get_strlit_contents(
                    ci.obj_ea, -1, ida_nalt.STRTYPE_C)
                if s is not None:
                    return s.decode("utf-8", "replace")
        except Exception:
            pass
        return None

    def _kind(self, ci):
        if self._is_insn(ci):
            return "block" if ci.op == ida_hexrays.cit_block else "stmt"
        return "attr"

    def _expr_str(self, e):
        return ida_lines.tag_remove(e.print1(None)) if e else ""

    def _text_for_stmt(self, ci):
        op = ci.op
        try:
            if op == ida_hexrays.cit_block:
                return ""
            if op == ida_hexrays.cit_if:
                return f"if ({self._expr_str(ci.cif.expr)})"
            elif op == ida_hexrays.cit_while:
                return f"while ({self._expr_str(ci.cwhile.expr)})"
            elif op == ida_hexrays.cit_do:
                cond_e = None
                if hasattr(ci, "cdo") and ci.cdo:
                    cond_e = ci.cdo.expr
                elif hasattr(ci, "cwhile") and ci.cwhile:
                    cond_e = ci.cwhile.expr
                return f"do ... while ({self._expr_str(cond_e)})"
            elif op == ida_hexrays.cit_for:
                init = self._expr_str(ci.cfor.init) if ci.cfor.init else ""
                cond = self._expr_str(ci.cfor.expr) if ci.cfor.expr else ""
                step = self._expr_str(ci.cfor.step) if ci.cfor.step else ""
                return f"for ({init}; {cond}; {step})"
            elif op == ida_hexrays.cit_switch:
                return f"switch ({self._expr_str(ci.cswitch.expr)})"
            elif op == ida_hexrays.cit_return:
                e = ci.creturn.expr if hasattr(ci, "creturn") else None
                return "return %s" % self._expr_str(e) if e else "return;"
            else:
                return ida_lines.tag_remove(ci.print1(None))
        except Exception:
            return ida_lines.tag_remove(ci.print1(None))

    def _text(self, ci):
        if self._is_insn(ci):
            return self._text_for_stmt(ci)
        try:
            return ida_lines.tag_remove(ci.print1(None))
        except Exception as e:
            return f"<print_err:{e}>"

    def _add_edge(self, p, c):
        key = (p, c)
        if key not in self._edge_set:
            self._edge_set.add(key)
            self.edges.append([p, c])

    # ------------ traversal ------------
    def _save(self, ci):
        oid = int(ci.obj_id)
        kind = self._kinds.get(oid)
        if not kind:
            kind = self._kind(ci)
            self._kinds[oid] = kind

        tinfo_str = ""
        if self._is_expr(ci) and not ci.type.empty():
            tinfo_str = ci.type.dstr()

        # ensure node exists
        k = str(oid)
        if k not in self.nodes:
            text = "" if kind == "block" else self._text(ci)
            label_name = None
            if kind == "stmt":
                m = LABEL_RE.match(text)
                if m:
                    label_name = m.group(1)
                    text = text[m.end():].lstrip()

            self.nodes[k] = {
                "id": oid,
                "kind": kind,
                "op": ida_hexrays.get_ctype_name(ci.op),
                "ea": int(ci.ea),
                "text": text,
                "label": label_name,
                "ctype": tinfo_str,
                "line_no": self.line_map.get(oid, -1)
            }

            if self._is_string_ci(ci):
                self.nodes[k]["is_string"] = True
                sval = self._get_string_val(ci)
                if sval is not None:
                    self.nodes[k]["str_val"] = sval

        # connect edge to nearest main-line ancestor
        if len(self.parents) > 1:
            if kind in ("block", "stmt"):
                parent_ci = self.parents.back()
                pid = int(parent_ci.obj_id)
                pkind = self._kinds.get(pid) or self._kind(parent_ci)
                if pkind in ("block", "stmt"):
                    self._add_edge(pid, oid)
            else:
                parent_ci = self.parents.back()
                pid = int(parent_ci.obj_id)
                pkind = self._kinds.get(pid) or self._kind(parent_ci)

                if pkind == "attr":
                    self._add_edge(pid, oid)
                else:
                    for anc in reversed(self.parents):
                        aid = int(anc.obj_id)
                        ak = self._kinds.get(aid) or self._kind(anc)
                        if ak in ("block", "stmt"):
                            self._add_edge(aid, oid)
                            break

        return 0

    def visit_insn(self, i):  return self._save(i)
    def visit_expr(self, e):  return self._save(e)


# ======================================================================
# Main entry
# ======================================================================

def main() -> None:
    """Main entry point for Part 2: selective pseudocode and pseudotree export"""
    # Wait for IDA auto analysis and hide progress box
    ida_auto.auto_wait()
    ida_kernwin.hide_wait_box()

    global_logger.info(f"[Stage 2] Processing {in_path.name}")
    
    # Load function list
    func_names = load_function_list(func_list_path)
    if not func_names:
        global_logger.warning("[!] No functions to process, exiting")
        idaapi.qexit(0)
    
    # Prepare output directories
    decompile_dir, pseudotree_dir = resolve_output_dirs(in_path)
    export_function_catalog(in_path.parent)
    
    # Export pseudocode and pseudotree for specified functions only
    pseudo_results = export_pseudocode_selective(decompile_dir, func_names)
    tree_results = export_pseudotree_selective(pseudotree_dir, func_names)
    
    global_logger.info("[Stage 2] Completed")
    
    # Exit IDA
    idaapi.qexit(0)


if __name__ == "__main__":
    main()

