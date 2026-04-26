from __future__ import annotations
import re
from pathlib import Path
import xxhash
from collections import defaultdict, Counter, OrderedDict
from bisect import bisect_left
from typing import Dict, List, Tuple, Optional, Set
from utils.logging_helper import global_logger
import csv
import json
import os

from difflib import SequenceMatcher

_MAX_BASE_LEN = 240

_LINE_RE = re.compile(r"^\s*(\d+):\s*(.*)$")  # capture line-no and code part
_BRACE_ONLY = {"{", "}"}
_PROTO_RE = re.compile(r"^.+\)\s*(?:\{)?$")
_CALL_RE = re.compile(r'^\s*([A-Za-z_][\w$]*)\s*\(')
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

_KEYWORDS: Set[str] = {
    "if","else","switch","case","default","for","while","do","continue","break","return","goto",
    "void","char","short","int","long","float","double","signed","unsigned","struct","union","enum",
    "static","const","volatile","extern","inline","register","typedef","sizeof","true","false","NULL",
}

# IDA built-in macro set (these macros should be preserved, no variable substitution or function mapping)
_IDA_MACROS: Set[str] = {
    # 64-bit related macros
    "_PAIR64_", "SHIDWORD", "HIDWORD", "LODWORD", "WORD1", "BYTE4",
    # High/low byte/word related
    "HIWORD", "LOWORD", "HIBYTE", "LOBYTE",
    # Sign extension related
    "__PAIR__", "__PAIR64__", "__SPAIR64__",
    "__ROL__", "__ROR__", "__ROL8__", "__ROR8__", 
    "__ROL4__", "__ROR4__", "__ROL2__", "__ROR2__", "__ROL1__", "__ROR1__",
    # Register concatenation macros
    "__PAIR32__",
    # Bit operation helper macros
    "__CFSHL__", "__CFSHR__", "__OFADD__", "__OFSUB__",
    # Other built-in pseudo functions
    "__readfsdword", "__readgsqword", "__readfsqword", "__readgsdword",
    "__int64", "__int32", "__int16", "__int8",
    "__debugbreak", "__emit",
    # Register value macros
    "BYTE0", "BYTE1", "BYTE2", "BYTE3", "BYTE5", "BYTE6", "BYTE7",
    "WORD0", "WORD2", "WORD3",
    # Other common macros
    "SLOBYTE", "SHIBYTE", "SLOWORD", "SHIWORD",
    "__CFADD__", "__CFSUB__",
}

OLD_TAG = "<O:{name}>"
NEW_TAG = "<N:{name}>"

_LOCAL_FUNC_RE = re.compile(r"^(sub_|FUN_|loc_|unk_)", re.IGNORECASE)

# === helper ===
class FuncMapper:
    """old func name -> new func name  for normalization"""
    def __init__(self, mapping: Optional[Dict[str, str]] = None):
        self._m = mapping or {}

    def map_name(self, name: str) -> str:
        return self._m.get(name, name)

_DEFAULT_MAPPER = FuncMapper()

def set_default_mapper(mapping: Dict[str, str]):
    global _DEFAULT_MAPPER
    _DEFAULT_MAPPER = FuncMapper(mapping)

def safe_name(func_name: str) -> str:
    cleaned = re.sub(r'[^0-9A-Za-z_]', '_', func_name)
    truncated = cleaned[:_MAX_BASE_LEN]
    return truncated 

# === diff core ===

class Statement:
    """A single pseudo-code statement."""

    def __init__(self,
                 version: str,
                 line_no: int,
                 op : str ,
                 text: str,
                 category: str,
                 node_id: int | None = None,
                 label: str | None = None
                 ):
        """
        Args:
            line_no : original line number in the txt file (or -1 if from ctree).
            text    : code text stripped of leading/trailing spaces.
            category: 'prototype' | 'var_decl' | 'logic' | 'block' | 'stmt'
            node_id : obj_id in pseudotree json (None for lines from txt).
        """
        self.version = version
        self.line_no  = line_no
        self.op = op
        self.text     = text
        self.category = category
        self.node_id  = node_id
        self.label    = label

        # normalize and hash
        self.norm = ""
        self.fp = ""

        # children = Statement sub-nodes (block/stmt)
        self.children: List["Statement"] = []

        # attr info collected from pseudotree (direct attrs of this stmt/block)
        self.attr_info: Dict[str, set] = {
            "vars": set(),
            "calls": set(),
            "nums": set(),
            "strs": set(),
            "locals":  set(),   
            "globals": set(),   
            "raw_ids": set(),      # all attr node ids
            "raw_texts": set(),    # raw text of attr nodes
            "ops": set()           # attr ops 
        }

    def normalize_statement(self, mapping:  Dict[str, str] | None = None ):
        """return `(normalized_text, 64‑bit_hash)`."""

        mapping   = mapping or {}
        resolved  = set(mapping.values())

        def repl(m: re.Match[str]) -> str:
            name = m.group(0)
            # First check if it's an IDA macro, if so keep it as is
            if name in _IDA_MACROS:
                return name
            if name in _KEYWORDS or name[0].isupper() or name.endswith("_t"):
                return name
            if name in self.attr_info["vars"]:
                if self.version == 'new':
                    return mapping.get(name, "VAR")
                else: 
                    return name if name in resolved else "VAR"
            end = m.end()
            if name in self.attr_info["calls"] or self._peek_next_nonspace(self.text, end) == '(':
                # print(self.version, name, _DEFAULT_MAPPER.map_name(name))
                return _DEFAULT_MAPPER.map_name(name) if self.version == 'new' else name
            prev_ch = self._peek_prev_nonspace(self.text, m.start())
            if prev_ch in {'.', '>'}:
                return name
            return name
        # print(self.version,self.norm)
        self.norm = _IDENT_RE.sub(repl, self.text)
        self.norm = re.sub(
         r'(\bgoto\s+)[A-Za-z_][A-Za-z0-9_]*',
         r'\1LABEL',
         self.norm
         )
        # print(self.version,self.norm)
        self.fp = xxhash.xxh64(self.norm).hexdigest()
    
    @staticmethod
    def _peek_next_nonspace(src: str, pos: int) -> str | None:
        i = pos
        while i < len(src) and src[i].isspace():
            i += 1
        return src[i] if i < len(src) else None

    @staticmethod
    def _peek_prev_nonspace(src: str, pos: int) -> str | None:
        i = pos - 1
        while i >= 0 and src[i].isspace():
            i -= 1
        return src[i] if i >= 0 else None

    def remap_text(self,
                   mapping: Dict[str, str],
                   side: str,
                   stable_calls: set | None = None,
                   known_funcs: set[str] | None = None) -> str:
        """
        side: 'old' or 'new', determines the suffix to add to unmapped variables.
        """
        
        fn_has_map = getattr(_DEFAULT_MAPPER, "_m", {}).__contains__

        def _repl(m: re.Match[str]) -> str:
            name = m.group(0)

            # ------------ Skip IDA macros ------------
            if name in _IDA_MACROS:
                return name

            # ------------ Skip keywords / type names ------------
            if (name in _KEYWORDS or name[0].isupper() or name.endswith('_t')):
                return name

            # ------------ Determine if it's a function call ------------
            end = m.end()
            is_call = (
                name in self.attr_info["calls"] or
                Statement._peek_next_nonspace(self.text, end) == '('
            )

            # ==========================================================
            # Old side processing
            # ==========================================================
            if side == 'old':

                return name                   

            # ==========================================================
            # New side processing (keep original name)
            # ==========================================================
            else:  # side == 'new'
                if is_call:
                    if fn_has_map(name):
                        return _DEFAULT_MAPPER.map_name(name)
                    if stable_calls and (name in stable_calls):
                        return name
                    if known_funcs is not None and name not in known_funcs:
                        return name
                    if _LOCAL_FUNC_RE.match(name):
                        return NEW_TAG.format(name=name)
                    # For unmapped function calls, mark as new function
                    return NEW_TAG.format(name=name)

                if name in self.attr_info["vars"]:
                    if name in mapping:
                        return mapping[name]
                    return NEW_TAG.format(name=name)
                
                return name

        return _IDENT_RE.sub(_repl, self.text)

    def __repr__(self) -> str:  # for quick debugging
        return f"<{self.category}@{self.line_no}: {self.text!r}>"


class FunctionPseudoCode:
    """Hold every useful line of one decompiled function."""

    def __init__(self,
                 func_name: str,
                 mid_file_dir: Path,
                 version: str):
        self.func_name = func_name
        self.mid_file_dir = mid_file_dir
        self.version = version

        self.return_type = ""
        self.params = []
        self.vars_dict = {}
        self.local_var_set: set[str] = set()
        

        self.stmt_root: Statement | None = None
        self.id2stmt: Dict[int, Statement] = {}
        self.label_map: Dict[str, Statement] = {}
        self.all_vars: set[str] = set()
        self.all_calls: set[str] = set()

        # classified views
        self.prototype_lines = []
        self.var_decls = []
        self.logic_lines = []


    def parse(self):
        return self._load_pseudotree()
 
    

    def _build_stmt_tree(self,
                         nid: int,
                         nodes: Dict[int, dict],
                         children_map: Dict[int, List[int]],
                         parent_map: Dict[int, int]) -> Statement:
        """Recursively build Statement tree from a main-line node."""
        n = nodes[nid]
        category = n["kind"]            # 'block' or 'stmt'
        text = n["text"]
        line_no = n.get("line_no", -1)
        op = n.get("op", "")
        stmt = Statement(self.version, line_no, op, text, category, node_id=nid, label=n.get("label"))

        if stmt.label:
            self.label_map[stmt.label] = stmt

        for cid in children_map.get(nid, []):
            cn = nodes[cid]
            if cn["kind"] == "attr":
                self._collect_attr(stmt, cid, nodes, children_map, parent_map)

        for cid in children_map.get(nid, []):
            cn = nodes[cid]
            if cn["kind"] in ("block", "stmt"):
                child_stmt = self._build_stmt_tree(cid, nodes, children_map, parent_map)
                stmt.children.append(child_stmt)
        
        if category == "stmt":
            stmt.normalize_statement()
            # print(stmt.norm)
        
        return stmt

    def _collect_attr(self,
                  stmt: Statement,
                  aid: int,
                  nodes: Dict[int, dict],
                  children_map: Dict[int, List[int]],
                  parent_map: Dict[int, int]) -> None:
        """
        Traverse attr subtree rooted at aid; fill stmt.attr_info:
        vars / calls / nums / strs.
        """
        stack = [aid]
        while stack:
            cur = stack.pop()
            an   = nodes[cur]
            op   = an["op"].lower()          # call / obj / var / num ...
            txt  = an.get("text", "") or ""

            info = stmt.attr_info
            info["raw_ids"].add(cur)
            info["raw_texts"].add(txt)
            info["ops"].add(op)

            # -------- num --------
            if op == "num":
                info["nums"].add(txt)

            # -------- str --------
            if op in {"str", "string"} or (op == "obj" and txt.startswith('"') and txt.endswith('"')):
                info["strs"].add(txt.strip('"'))
                continue


            # -------- call --------
            elif op == "call":
                # 1) fn in own text
                if (m := _CALL_RE.match(txt)):
                    fn = m.group(1)
                    # Skip IDA macros, don't add them to calls set
                    if fn not in _IDA_MACROS:
                        info["calls"].add(fn)
                        info["vars"].discard(fn)
                # 2) first child may be obj/var (function name)
                kids = children_map.get(cur, [])
                if kids:
                    fn_node = nodes[kids[0]]
                    if fn_node["op"].lower() in {"obj", "var"}:
                        fn = fn_node.get("text", "")
                        # Skip IDA macros, don't add them to calls set
                        if fn and fn not in _IDA_MACROS:
                            info["calls"].add(fn)
                            info["vars"].discard(fn)

            # -------- var --------
            elif op == "var":
                self.local_var_set.add(txt)
                info["locals"].add(txt)
                info["vars"].add(txt)

            # -------- obj --------
            elif op == "obj":
                
                is_func = False
                par = parent_map.get(cur)
                if par is not None and nodes[par]["op"].lower() == "call":
                    # is first child of that call?
                    if children_map.get(par, [None])[0] == cur:
                        is_func = True

                if is_func:
                    info["calls"].add(txt)
                    info["vars"].discard(txt)
                else:
                    bucket = "locals" if txt in self.local_var_set else "globals"
                    info[bucket].add(txt)
                    info["vars"].add(txt)

            

            # push deeper attr‑children
            for ch in children_map.get(cur, []):
                if nodes[ch]["kind"] == "attr":
                    stack.append(ch)

    def _index_stmt_nodes(self, node: Statement, out: Dict[int, Statement]):
        out[node.node_id] = node
        for ch in node.children:
            self._index_stmt_nodes(ch, out)

    def _load_pseudotree(self):
        """
        Read pseudotree JSON (nodes/edges), build a tree whose nodes are
        Statement objects (category 'block'/'stmt'), and attach attr info.
        """
        pseudotree_dir = self.mid_file_dir / "pseudotree"
        json_path = None
        for p in pseudotree_dir.glob(f"{safe_name(self.func_name)}*.json"):
            json_path = p
            break
        if json_path is None:
            global_logger.warning(f"Can't find pseudotree json for {self.func_name}")
            return False

        with json_path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        nodes: Dict[int, dict] = {int(k): v for k, v in data["nodes"].items()}
        edges: List[Tuple[int, int]] = [(int(p), int(c)) for p, c in data["edges"]]

        # --- build parent/children map
        children_map: Dict[int, List[int]] = {}
        parent_map: Dict[int, int] = {}
        for p, c in edges:
            children_map.setdefault(p, []).append(c)
            parent_map[c] = p

        roots = [nid for nid, n in nodes.items()
                 if n["kind"] in ("block", "stmt") and nid not in parent_map]
        if not roots:
            global_logger.warning(f"No root for {self.func_name}")
            return False
        root_id = roots[0]  # only one root

        # DFS
        self.stmt_root = self._build_stmt_tree(root_id, nodes, children_map, parent_map)

        # (optional) id->Statement 
        self.id2stmt: Dict[int, Statement] = {}
        self._index_stmt_nodes(self.stmt_root, self.id2stmt)

        # collect attr info
        self.all_vars    = set()
        self.all_calls   = set()
        self.all_locals  = set()
        self.all_globals = set()
        for st in self.id2stmt.values():
            self.all_vars    |= st.attr_info["vars"]
            self.all_calls   |= st.attr_info["calls"]
            self.all_locals  |= st.attr_info["locals"]
            self.all_globals |= st.attr_info["globals"]

        return True

         
    @staticmethod
    # show stmt_tree via graphviz
    def export_stmt_tree_graph(root: "Statement",
                           out_path,
                           fmt: str = "png",
                           show_attr: bool = False,
                           show_label: bool = True) -> None:
        """
        Export stmt_tree to an image via graphviz.
        - out_path: Path/str, without extension (we will add .png/.pdf etc.)
        - fmt: 'png'/'pdf'/'svg'...
        - show_attr: show vars/calls on node label
        - show_label: include label=... if stmt has a label
        All imports are local, so commenting this call out is harmless.
        """
        # lazy imports
        from pathlib import Path
        try:
            from graphviz import Digraph
        except ImportError as e:
            raise RuntimeError("graphviz not installed. pip install graphviz") from e

        if root is None:
            raise ValueError("root is None")

        out_path = Path(out_path)
        dot = Digraph(comment="stmt_tree")
        dot.format = fmt

        # collect all nodes
        def iter_nodes(node: "Statement"):
            stack = [node]
            while stack:
                n = stack.pop()
                yield n
                stack.extend(reversed(n.children))

        # id -> stmt
        id2stmt = {}
        for n in iter_nodes(root):
            if n.node_id is None:
                nid = id(n)
            else:
                nid = n.node_id
            id2stmt[nid] = n

        for nid, stmt in id2stmt.items():
            # label text
            parts = []
            if show_label and getattr(stmt, "label", None):
                parts.append(f"<<{stmt.label}>>")
            parts.append(f"line_no:{stmt.line_no}")
            parts.append(stmt.category)
            if stmt.category == 'stmt':
                txt = stmt.text.replace("\n", "\\n")
                if len(txt) > 60:
                    txt = txt[:57] + "..."
                
                parts.append(txt)
                parts.append(stmt.norm)

                if show_attr:
                    avars  = ", ".join(sorted(stmt.attr_info.get("vars", [])))
                    alocals = ", ".join(sorted(stmt.attr_info.get("locals", [])))
                    aglobals = ", ".join(sorted(stmt.attr_info.get("globals", [])))
                    acalls = ", ".join(sorted(stmt.attr_info.get("calls", [])))
                    anums = ", ".join(sorted(stmt.attr_info.get("nums", [])))
                    astrs = ", ".join(sorted(stmt.attr_info.get("strs", [])))
                    
                    parts.append(f"vars:[{avars}]")
                    parts.append(f"locals:[{alocals}]")
                    parts.append(f"globals:[{aglobals}]")
                    parts.append(f"calls:[{acalls}]")
                    parts.append(f"nums:[{anums}]")
                    parts.append(f"strs:[{astrs}]")

            label = "\\n".join(parts)
            color = "lightgray" if stmt.category == "block" else "white"

            dot.node(str(nid), label=label, shape="box", style="filled", fillcolor=color)

        for pid, p in id2stmt.items():
            for ch in p.children:
                cid = ch.node_id if ch.node_id is not None else id(ch)
                dot.edge(str(pid), str(cid))

        out_file = dot.render(out_path.as_posix(), cleanup=True)
        print(f"[export_stmt_tree_graph] saved to {out_file}")


class PseudoCodeDiff:
    """Wrap two versions (before/after) of a function for diff usage."""

    def __init__(self, mid_file_dir: Path):
        self.mid_file_dir = mid_file_dir
        self.before: FunctionPseudoCode | None = None
        self.after: FunctionPseudoCode | None = None

        self.mums = []
        self.unmatched_old: List[Statement] = []
        self.unmatched_new: List[Statement] = []
        self.pair_counts: Dict[str, Counter] = {}
        self.M_new2old: Dict[str, str] = {}
        self.func_catalog = {
            "old": self._load_function_names(self.mid_file_dir / "patch_before"),
            "new": self._load_function_names(self.mid_file_dir / "patch_after"),
        }
        self.stable_calls: set[str] = set()

    def process(self, old_func: str, new_func: str):
        # Load and parse old version
        old_fp = FunctionPseudoCode(old_func, self.mid_file_dir / "patch_before", "old")
        if not(old_fp.parse()):
            global_logger.warning(f"fail to parse {old_fp}")
            return None
        # Load and parse new version
        new_fp = FunctionPseudoCode(new_func, self.mid_file_dir / "patch_after", "new")
        if not(new_fp.parse()):
            global_logger.warning(f"fail to parse {new_fp}")
            return None


        self.before = old_fp
        self.after = new_fp

        seqA = self.flatten_statements(self.before.stmt_root)
        seqB = self.flatten_statements(self.after.stmt_root)


        prev_map: Dict[str, str] = {}
        while(1):
            # a. Match MUM blocks
            self.mums = self.find_stmt_mums(seqA, seqB)
            # for a_block, b_block, sa, ea, sb, eb in self.mums:
            #     print(f"Match A[{sa}:{ea}] vs B[{sb}:{eb}]:")
            #     for stmt in a_block:
            #         print("before:  ", stmt.norm)
            #     for stmt in b_block:
            #         print("after:  ", stmt.norm)
            #     print()
        
            
            # b. Count mapping frequency
            counts = self._collect_varmap(self.mums)
            
            curr_map: Dict[str, str] = {}
            for new_var, counter in counts.items():
                commons = counter.most_common()
                if not commons:
                    continue
                old_name, cnt1 = commons[0]
                cnt2 = commons[1][1] if len(commons) > 1 else 0
                if cnt1 - cnt2 >= 2:
                    curr_map[new_var] = old_name
            # c. Convergence detection
            if curr_map == prev_map:
                for new_var, counter in counts.items():
                    if new_var not in curr_map:
                        commons = counter.most_common()
                        if commons:
                            # Take the one with highest frequency as default mapping
                           curr_map[new_var] = commons[0][0]
                prev_map = curr_map.copy()
                break
            prev_map = curr_map.copy()
            self.M_new2old = curr_map
            # d. Normalize all statements
            for stmt in seqA + seqB:
                stmt.normalize_statement(mapping=self.M_new2old)

        # print(len(prev_map))
        self.unmatched_old, self.unmatched_new = self._collect_unmatched(seqA, seqB)
        self.pair_counts = counts
        self.M_new2old = prev_map

        self.stable_calls = set(self.before.all_calls) & set(self.after.all_calls)
        # ————— Variable substitution + pseudocode + diff —————
        old_lines = self.generate_pseudocode_lines(side="old")
        new_lines = self.generate_pseudocode_lines(side="new")
        # for i in old_lines:
        #     print("old: ",i)
        # for j in new_lines:
        #     print("new: ",j)

        self.diff_text = self._make_unified_diff(old_lines, new_lines)

        # —— New: pack result into dict and return ——————————————
        diff_dict = {
            "old_func": old_func,
            "new_func": new_func,
            "old_code": "\n".join(old_lines),
            "new_code": "\n".join(new_lines),
            "diff":     self.diff_text
        }

        # for i in diff_dict['diff'].splitlines():
        #     print(i)

        # show results of MUMs
        # for a_block, b_block, sa, ea, sb, eb in self.mums:
        #     print(f"Match A[{sa}:{ea}] vs B[{sb}:{eb}]:")
        #     for stmt in a_block:
        #         print("before:  ", stmt.norm)
        #     for stmt in b_block:
        #         print("after:  ", stmt.norm)
        #     print()

        # v_keys = []
        # other_keys = []

        # for k in self.M_old2new:
        #     match = re.fullmatch(r"v(\d+)", k)
        #     if match:
        #         v_keys.append((int(match.group(1)), k))
        #     else:
        #         other_keys.append(k)

        # # Sort by number v1 ~ v30
        # for _, k in sorted(v_keys):
        #     print(k, self.M_old2new[k])

        # # Other keys sorted alphabetically (or not sorted)
        # for k in sorted(other_keys):
        #     print(k, self.M_old2new[k])

        return diff_dict
    

    # —— Flatten to pseudocode text ———————————————————————————
    def generate_pseudocode_lines(self, side: str) -> List[str]:
        root = self.before.stmt_root if side == "old" else self.after.stmt_root
        lines: List[str] = []
        known_funcs = self._get_function_catalog(side)
        self._emit_pseudocode(root, side, 0, lines, known_funcs)
        return lines

    def _emit_pseudocode(self,
                         node: "Statement" | None,
                         side: str,
                         indent: int,
                         out: List[str],
                         known_funcs: set[str]) -> int:
        if node is None:
            return indent

        # ==============================================================
        # A) Special handling for do ... while (cond)
        # ==============================================================
        if node.category == "stmt" and node.op.lower() == "do":
            # 1. Extract while condition (find in remapped text)
            remapped = node.remap_text(
                self.M_new2old,
                side,
                stable_calls=self.stable_calls,
                known_funcs=known_funcs,
            )
            m = re.search(r'while\s*\((.*)\)', remapped)
            cond = m.group(1).strip() if m else ""

            # 2. Output "do {" line
            out.append("    " * indent + "do {")
            indent += 1

            # 3. Output loop body block (if any)
            for ch in node.children:
                indent = self._emit_pseudocode(ch, side, indent, out, known_funcs)

            # 4. Output "} while (cond);" line
            indent -= 1
            trailer = f"}} while ({cond});" if cond else "}"
            out.append("    " * indent + trailer)
            return indent

        # ==============================================================
        # B) Normal stmt: directly output remapped text
        # ==============================================================
        if node.category == "stmt":
            out.append(
                "    " * indent
                + node.remap_text(
                    self.M_new2old,
                    side,
                    stable_calls=self.stable_calls,
                    known_funcs=known_funcs,
                ).rstrip()
            )

            # If this stmt has block child nodes (like if/for/while body), explicitly add { }
            for ch in node.children:
                if ch.category == "block":
                    out.append("    " * indent + "{")
                    indent += 1
                    indent = self._emit_pseudocode(ch, side, indent, out, known_funcs)
                    indent -= 1
                    out.append("    " * indent + "}")
                else:
                    indent = self._emit_pseudocode(ch, side, indent, out, known_funcs)
            return indent

        # ==============================================================
        # C) Normal block: traverse child nodes, indent unchanged
        # ==============================================================
        if node.category == "block":
            for ch in node.children:
                indent = self._emit_pseudocode(ch, side, indent, out, known_funcs)
            return indent

        return indent
        

        

    def _get_function_catalog(self, side: str) -> set[str]:
        return self.func_catalog.get(side, set())

    @staticmethod
    def _load_function_names(root_dir: Path) -> set[str]:
        func_file = root_dir / "functions.json"
        if not func_file.exists():
            global_logger.debug(f"[diff] Function catalog not found: {func_file}")
            return set()
        try:
            with func_file.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as exc:
            global_logger.warning(f"[diff] Failed to load function catalog {func_file}: {exc}")
            return set()

        if isinstance(data, list):
            return {str(name) for name in data if name}

        global_logger.warning(f"[diff] Unexpected function catalog format: {func_file}")
        return set()


    # —— Generate unified diff ————————————————————————
    @staticmethod
    def _make_unified_diff(a_lines: List[str], b_lines: List[str]) -> str:
        import difflib
        diff_iter = difflib.unified_diff(
            a_lines, b_lines,
            fromfile="old_version", tofile="new_version",
            lineterm=""
        )
        numbered = []
        for idx, line in enumerate(diff_iter, start=1):
            numbered.append(f"{idx:4d}: {line}")
        return "\n".join(numbered)
    
    def flatten_statements(self, root: Statement) -> list[Statement]:
        """
        Pre-order traversal of stmt_root, collect all nodes with category=='stmt'
        into a list in order of appearance and return.
        """
        stmts: list[Statement] = []
        def dfs(node: Statement):
            # If it's a "statement", collect it
            if node.category == "stmt":
                stmts.append(node)
                # print(node.version,node.text,int(node.fp,16))
            # Recursively process its child nodes (block / stmt)
            for ch in node.children:
                dfs(ch)
        dfs(root)
        return stmts

    def build_suffix_array(self, seq):
        """
        Construct suffix array for integer sequence seq, return sa (list of suffix start indices).
        Based on doubling algorithm, time complexity O(n log n)
        """
        n = len(seq)
        k = 1
        sa = list(range(n))
        rank = list(seq)
        tmp = [0] * n
        while True:
            sa.sort(key=lambda i: (rank[i], rank[i+k] if i+k<n else -1))
            tmp[sa[0]] = 0
            for i in range(1, n):
                prev, curr = sa[i-1], sa[i]
                prev_key = (rank[prev], rank[prev+k] if prev+k<n else -1)
                curr_key = (rank[curr], rank[curr+k] if curr+k<n else -1)
                tmp[curr] = tmp[prev] + (prev_key < curr_key)
            rank, tmp = tmp, rank
            if rank[sa[-1]] == n-1:
                break
            k <<= 1
        return sa


    def build_lcp_array(self, seq, sa):
        """
        Given sequence seq and its suffix array sa, construct LCP array.
        LCP[i] = length of longest common prefix between suffix SA[i] and suffix SA[i-1].
        Time complexity O(n)
        """
        n = len(seq)
        rank = [0]*n
        for i, p in enumerate(sa):
            rank[p] = i
        lcp = [0]*n
        h = 0
        for i in range(n):
            if rank[i] == 0:
                continue
            j = sa[rank[i]-1]
            while i+h<n and j+h<n and seq[i+h] == seq[j+h]:
                h += 1
            lcp[rank[i]] = h
            if h > 0:
                h -= 1
        return lcp


    def find_stmt_mums(self,seqA, seqB):
        """
        Input: two Statement object lists seqA, seqB
        Comparison uses stmt.fp (hash) as token, can also use stmt.norm.
        Returns list:
        [(stmtsA, stmtsB, startA, endA, startB, endB), ...]
        where stmtsA/B are matching Statement object sublists.
        Filter subsets, duplicates and overlaps, keep true maximum blocks.
        """
        # 1. Extract token list
        toksA = [int(stmt.fp, 16) for stmt in seqA]
        toksB = [int(stmt.fp, 16) for stmt in seqB]

        # 2. Merge and add sentinels
        sep1 = max(max(toksA, default=0), max(toksB, default=0)) + 1
        sep2 = sep1 + 1
        merged = toksA + [sep1] + toksB + [sep2]
        nA = len(toksA)

        # 3. Construct SA and LCP
        sa = self.build_suffix_array(merged)
        lcp = self.build_lcp_array(merged, sa)
        N = len(merged)

        # 4. Scan to find local maximum matches
        raw = []
        for i in range(1, N):
            p1, p2 = sa[i], sa[i-1]
            inA1, inA2 = (p1 < nA), (p2 < nA)
            if inA1 != inA2:
                L = lcp[i]
                left = lcp[i-1] if i-1>=0 else 0
                right = lcp[i+1] if i+1<N else 0
                if L > left and L > right and L > 0:
                    if inA1:
                        sa0, sb0 = p1, p2 - (nA+1)
                    else:
                        sa0, sb0 = p2, p1 - (nA+1)
                    raw.append((sa0, sa0+L-1, sb0, sb0+L-1))

        # 5. Filter subsets by descending length
        cand = sorted(raw, key=lambda x: x[1]-x[0], reverse=True)
        subset_filtered = []
        for a0,a1,b0,b1 in cand:
            if not any(aa0<=a0 and a1<=aa1 and bb0<=b0 and b1<=bb1 for aa0,aa1,bb0,bb1 in subset_filtered):
                subset_filtered.append((a0,a1,b0,b1))

        # 6. Global uniqueness filtering
        unique_filtered = []
        for a0,a1,b0,b1 in subset_filtered:
            L = a1 - a0 + 1
            blockA = tuple(toksA[a0:a1+1])
            # Count sliding window
            cntA = sum(1 for i in range(len(toksA)-L+1) if tuple(toksA[i:i+L]) == blockA)
            blockB = tuple(toksB[b0:b1+1])
            cntB = sum(1 for i in range(len(toksB)-L+1) if tuple(toksB[i:i+L]) == blockB)
            if cntA == 1 and cntB == 1:
                unique_filtered.append((a0,a1,b0,b1))

        # 7. Non-overlapping filtering: select by descending length
        final = []
        coveredA = set()
        coveredB = set()
        for a0,a1,b0,b1 in sorted(unique_filtered, key=lambda x: x[1]-x[0], reverse=True):
            if not any(idx in coveredA for idx in range(a0, a1+1)) \
            and not any(idx in coveredB for idx in range(b0, b1+1)):
                final.append((a0,a1,b0,b1))
                coveredA.update(range(a0, a1+1))
                coveredB.update(range(b0, b1+1))

        # 8. Construct final result
        results = []
        for a0,a1,b0,b1 in final:
            stmtsA = seqA[a0:a1+1]
            stmtsB = seqB[b0:b1+1]
            results.append((stmtsA, stmtsB, a0, a1, b0, b1))

        return results

    def _collect_unmatched(self, seqA: List[Statement], seqB: List[Statement]) -> Tuple[List[Statement], List[Statement]]:
        matched_old = set(st for block, _, *rest in self.mums for st in block) if self.mums else set()
        matched_new = set(st for _, block, *rest in self.mums for st in block) if self.mums else set()
        return ([s for s in seqA if s not in matched_old],
                [s for s in seqB if s not in matched_new])

    def _collect_varmap(self, mums) -> Dict[str, Counter]:
        pair_counts = defaultdict(Counter)
        for a_block, b_block, *_ in mums:
            for stmt_old, stmt_new in zip(a_block, b_block):
                old_vars = self._ordered_vars(stmt_old)
                new_vars = self._ordered_vars(stmt_new)
                if len(old_vars) == len(new_vars):
                    for o, n in zip(old_vars, new_vars):
                        pair_counts[n][o] += 1
        return pair_counts

    def _build_varmap(self, pair_counts: Dict[str, Counter]) -> Dict[str, str]:
        mapping = {}
        for old_var, counter in pair_counts.items():
            new_var, _ = counter.most_common(1)[0]
            mapping[old_var] = new_var
        return mapping

    @staticmethod
    def _ordered_vars(stmt: Statement) -> List[str]:
        """Collect stmt.attr_info['vars'] with deduplication in order of appearance in text."""
        seen = set()
        ordered = []
        for m in _IDENT_RE.finditer(stmt.text):
            name = m.group(0)
            if name in stmt.attr_info["vars"] and name not in seen:
                ordered.append(name)
                seen.add(name)
        return ordered
       

class PseudoDiffManager:
    def __init__(self,
                 match_funcs: Dict,
                 mid_file_dir: Path,
                 unmatched_funcs: Optional[Dict] = None,
                 ):
        self.match_funcs = match_funcs or {}
        self.mid_file_dir = mid_file_dir
        self.unmatched_funcs = unmatched_funcs or {}
        self.all_match = [] # partial + best
        self.partial_match = []

    

    def generate_diff(self):
        import time
        start = time.time()
        # load match list first

        has_partial = self._load_match_list()
        all_diffs = []

        if has_partial:
            # process diff
            # Create new->old mapping: {new_func: old_func}
            new_to_old_mapping = {new_func: old_func for old_func, new_func in self.all_match}
            set_default_mapper(new_to_old_mapping)

            pcd = PseudoCodeDiff(self.mid_file_dir)
            
            # Process matched functions
            for old_func, new_func in self.partial_match:
                diff_dict = pcd.process(old_func, new_func)
                if diff_dict:
                    all_diffs.append(diff_dict)
        else:
            global_logger.info("No partial match, skip matched diff generation.")
        
        # Process unmatched functions (only in one version)
        if self.unmatched_funcs:
            unmatched_diffs = self._generate_unmatched_diffs()
            if unmatched_diffs:
                all_diffs.extend(unmatched_diffs)
                global_logger.info(f"Added {len(unmatched_diffs)} unmatched function diffs")
        elif not has_partial:
            global_logger.info("No unmatched functions to diff.")
        
        global_logger.info(f"Diff costs {time.time()-start} seconds.")

        return all_diffs

    def _generate_unmatched_diffs(self) -> List[Dict]:
        """Generate diffs for unmatched functions (added or deleted)"""
        unmatched_diffs = []
        
        # Process secondary (new version only - added functions)
        primary_funcs = self.unmatched_funcs.get("primary", [])
        for func_name in primary_funcs:
            diff_dict = self._generate_single_version_diff(func_name, version="new")
            if diff_dict:
                unmatched_diffs.append(diff_dict)
        
        # Process primary (old version only - deleted functions)
        secondary_funcs = self.unmatched_funcs.get("secondary", [])
        for func_name in secondary_funcs:
            diff_dict = self._generate_single_version_diff(func_name, version="old")
            if diff_dict:
                unmatched_diffs.append(diff_dict)
        
        return unmatched_diffs
    
    def _generate_single_version_diff(self, func_name: str, version: str) -> Optional[Dict]:
        """
        Generate diff for a function that only exists in one version.
        version: 'old' (deleted) or 'new' (added)
        """
        try:
            if version == "old":
                # Function only in old version (deleted)
                old_fp = FunctionPseudoCode(func_name, self.mid_file_dir / "patch_before", "old")
                if not old_fp.parse():
                    global_logger.warning(f"Failed to parse old function {func_name}")
                    return None
                
                # Generate pseudocode lines
                old_lines = self._generate_simple_pseudocode(old_fp.stmt_root)
                
                # Create diff with all lines prefixed with '-'
                diff_lines = [
                    "   1: --- old_version",
                    "   2: +++ new_version",
                ]
                for idx, line in enumerate(old_lines, start=3):
                    diff_lines.append(f"{idx:4d}: -{line}")
                
                return {
                    "old_func": func_name,
                    "new_func": "",
                    "old_code": "\n".join(old_lines),
                    "new_code": "",
                    "diff": "\n".join(diff_lines)
                }
                
            else:  # version == "new"
                # Function only in new version (added)
                new_fp = FunctionPseudoCode(func_name, self.mid_file_dir / "patch_after", "new")
                if not new_fp.parse():
                    global_logger.warning(f"Failed to parse new function {func_name}")
                    return None
                
                # Generate pseudocode lines
                new_lines = self._generate_simple_pseudocode(new_fp.stmt_root)
                
                # Create diff with all lines prefixed with '+'
                diff_lines = [
                    "   1: --- old_version",
                    "   2: +++ new_version",
                ]
                for idx, line in enumerate(new_lines, start=3):
                    diff_lines.append(f"{idx:4d}: +{line}")
                
                return {
                    "old_func": "",
                    "new_func": func_name,
                    "old_code": "",
                    "new_code": "\n".join(new_lines),
                    "diff": "\n".join(diff_lines)
                }
        except Exception as e:
            global_logger.error(f"Error generating diff for unmatched function {func_name}: {e}")
            return None
    
    def _generate_simple_pseudocode(self, root: Statement) -> List[str]:
        """Generate simple pseudocode lines from statement tree without variable remapping"""
        lines: List[str] = []
        self._emit_simple_pseudocode(root, 0, lines)
        return lines
    
    def _emit_simple_pseudocode(self, node: Statement, indent: int, out: List[str]) -> int:
        """Emit pseudocode without variable remapping (for single-version functions)"""
        if node is None:
            return indent
        
        # Handle do...while specially
        if node.category == "stmt" and node.op.lower() == "do":
            m = re.search(r'while\s*\((.*)\)', node.text)
            cond = m.group(1).strip() if m else ""
            
            out.append("    " * indent + "do {")
            indent += 1
            for ch in node.children:
                indent = self._emit_simple_pseudocode(ch, indent, out)
            indent -= 1
            trailer = f"}} while ({cond});" if cond else "}"
            out.append("    " * indent + trailer)
            return indent
        
        # Regular statement
        if node.category == "stmt":
            out.append("    " * indent + node.text.rstrip())
            
            for ch in node.children:
                if ch.category == "block":
                    out.append("    " * indent + "{")
                    indent += 1
                    indent = self._emit_simple_pseudocode(ch, indent, out)
                    indent -= 1
                    out.append("    " * indent + "}")
                else:
                    indent = self._emit_simple_pseudocode(ch, indent, out)
            return indent
        
        # Block
        if node.category == "block":
            for ch in node.children:
                indent = self._emit_simple_pseudocode(ch, indent, out)
            return indent
        
        return indent

    def _load_match_list(self):
        if "partial" not in self.match_funcs or not self.match_funcs["partial"]:
            return False
        self.partial_match = self.match_funcs["partial"]
        # all_match = best + partial
        self.all_match = self.match_funcs.get("best", []) + self.partial_match
        return True
        
