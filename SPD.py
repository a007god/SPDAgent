#!/usr/bin/env python3
from __future__ import annotations
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import yaml
import multiprocessing as mp
import uvicorn
import threading
import time
import uuid
import random

from utils.logging_helper import global_logger
from utils.storage_helper import StorageLocation
from utils.IDA_service.ida_client import Client
from utils.IDA_service.config import ServiceConfig
from utils.IDA_service.controller import create_app
from pseudo_diff_gen.diff_gen import process_pair
from LLM_query.agent_pipeline import process_project, AgentState


def is_binary_file(filepath: Path, blocksize: int = 1024) -> bool:
    forbidden_suffixes = {".i64", ".sqlite", ".difflog", ".agentlog"}
    try:
        if filepath.suffix.lower() in forbidden_suffixes:
            return False
        with filepath.open("rb") as f:
            chunk = f.read(blocksize)
        return b"\0" in chunk
    except Exception:
        return False

# input: binary

def _pick_old_new_dirs(subdirs: List[Path]) -> tuple[Path, Path]:
    mapping = {d.name.lower(): d for d in subdirs}
    if "patch_before" in mapping and "patch_after" in mapping:
        return mapping["patch_before"], mapping["patch_after"]
    
    a, b = sorted(subdirs, key=lambda d: d.name)
    return a, b

def get_binary_pairs(datasets: Dict[str, Path]) -> List[Dict]:
    """
    Dir MUST BE:
    └── dataset_root/
        ├── patch_before/   ← old version
        └── patch_after/    ← new version
    """
    pairs: List[Dict] = []

    def walk_with_root(root: Path): # consider root and its subdirs
        yield root
        yield from root.rglob("*")

    for label, root in datasets.items():
        root = Path(root)

        for cand in walk_with_root(root):
            # print(cand,root)
            if not cand.is_dir():
                continue
            subdirs = [d for d in cand.iterdir() if d.is_dir()]
            if len(subdirs) != 2:
                continue
            
            old_dir, new_dir = _pick_old_new_dirs(subdirs)

            # at least one binary
            if not any(is_binary_file(p) for p in old_dir.rglob("*") if p.is_file()):
                continue
            if not any(is_binary_file(p) for p in new_dir.rglob("*") if p.is_file()):
                continue

            for old_file in old_dir.rglob("*"):
                if (not old_file.is_file()
                        or not is_binary_file(old_file)):
                    continue
                rel = old_file.relative_to(old_dir)
                new_file = new_dir / rel
                if not (new_file.exists() and new_file.is_file()
                        and is_binary_file(new_file)):
                    continue

                safe_rel = rel.as_posix().replace("/", "_")
                bin_tag = f"{safe_rel}"
                

                pairs.append({
                    "label":      label,
                    "old_bin":    str(old_file),
                    "new_bin":    str(new_file),
                    'group_name': cand.name,
                    "bin_tag":    bin_tag,
                })


    return pairs

def collect_bin_pairs(old: Optional[Path], new: Optional[Path],
                           bin_dir: Optional[Path],
                           Default_dataset: Optional[Dict]) -> List[Dict]:

    # single bin pair
    if old and new:
        if not old.exists() or not new.exists():
            raise FileNotFoundError(" Wrong path: --new / --old ")
        if not (old.is_file() and new.is_file()):
            raise ValueError("--old / --new must be file")
        if not is_binary_file(old):
            raise ValueError(f"--old not binary: {old}")
        if not is_binary_file(new):
            raise ValueError(f"--new not binary: {new}")

        group_name = f"{old.stem}_VS_{new.stem}"
        return [{
            "label":      "user",
            "old_bin":    str(old.resolve()),
            "new_bin":    str(new.resolve()),
            'group_name': group_name,
            "bin_tag":    old.name,
        }]
    
    if bin_dir:
        if not bin_dir.exists() or not bin_dir.is_dir():
            raise NotADirectoryError(f"--bin-dir not dir / not exist: {bin_dir}")
        return get_binary_pairs({"user": bin_dir.resolve()})
    elif Default_dataset: # cfg
        datasets = {k: Path(v) for k, v in Default_dataset.items()}

        if not datasets:
            raise RuntimeError("No valid path in config.yaml")

        return get_binary_pairs(datasets)
    else:
        return []



def spd_worker(pair: Dict, general_cfg: Dict, llm_cfg: Dict, host: str, port: int, llm_mode: str, max_tokens_per_query: int, enable_prefilter: bool) -> Tuple[str, bool, str]:
    """
    Return (bin_tag, ok, msg)

    """
    project_name = None
    cli = None
    
    try:
        #config
        old_bin = pair["old_bin"]
        new_bin = pair["new_bin"]
        bin_tag = pair["bin_tag"]
        label = pair["label"]
        group_dir = pair['group_name']

        #diff text gen
        all_diffs = process_pair(pair, general_cfg)

        
        if not all_diffs:
            global_logger.info(f"No diff for {old_bin} vs {new_bin}")
            return (group_dir, True, f"OK: ")
        
    
        uniq = f"{uuid.uuid4().hex[:6]}"

        project_name = f"{group_dir}-{uniq}"
        project_dir = StorageLocation.result_dir() / label / group_dir / bin_tag

        i64_path = Path(old_bin+".i64")

        # print(IDA_input, project_name)
        
        IDA_available = False

        cli = Client(host=host, port=port)
        cli.open(name=project_name, ida_input=str(i64_path))

        retry_deadline = time.time() + 300
        while time.time() < retry_deadline:
            try:
                if cli.project_ready(project_name):
                    IDA_available = True
                    break
            except Exception:
                pass
            time.sleep(1.0)
        

        process_project(project_name, project_dir, llm_cfg, all_diffs, IDA_available, mode=llm_mode, 
                       max_tokens_per_query=max_tokens_per_query, enable_prefilter=enable_prefilter,
                       ida_host=host, ida_port=port)

        return (group_dir, True, f"OK: ")
        
    except Exception as e:
        global_logger.error(f"Worker error for {pair.get('bin_tag', '?')}: {str(e)}", exc_info=True)
        return (pair.get("bin_tag", "?"), False, f"ERR: {e}")
    finally:
        # 确保无论发生什么情况，都会关闭 IDA 项目
        if cli is not None and project_name is not None:
            try:
                cli.close(name=project_name)
                global_logger.debug(f"Successfully closed IDA project: {project_name}")
            except Exception as e:
                global_logger.error(f"Failed to close IDA project {project_name}: {str(e)}")
    


def wait_controller_ready(host: str, port: int, timeout_s: float = 30.0):
    cli = Client(host=host, port=port)
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if cli.is_alive():
            return
        time.sleep(0.2)
    raise RuntimeError("controller not ready")


def main(argv: Optional[List[str]] = None):
    #Step 1: get all binaries to be test
    # Get the root directory (where SPD.py is located)
    root_dir = Path(__file__).parent.resolve()
    
    p = argparse.ArgumentParser(description="Run SPD process with bin input mode")

    # bin input (default mode)
    p.add_argument("--old", type=Path, help="old bin path")
    p.add_argument("--new", type=Path, help="new bin path")
    p.add_argument("--bin_dir", type=Path, help="process batch of bin pairs, the dir must contain <patch_after> and <patch_before>")

    # config and other options
    p.add_argument("--general_cfg", type=Path, default=root_dir / "config" / "general_config.yaml", help="load bin-dir from config.yaml")
    p.add_argument("--llm_cfg", type=Path, default=root_dir / "config" / "llm_config.yaml", help="load bin-dir from config.yaml")
    p.add_argument("--workers", type=int, default=1, help="number of workers")
    p.add_argument("--llm_mode", type=str, choices=["binary", "function"], default="binary", help="LLM processing mode for diffs")
    p.add_argument("--max_tokens_per_query", type=int, default=25000, help="Max tokens per query (binary mode chunking)")
    p.add_argument("--enable-prefilter", dest="enable_prefilter", action="store_true", default=True, help="Enable pre-filter stage for early classification (default: True)")
    p.add_argument("--disable-prefilter", dest="enable_prefilter", action="store_false", help="Disable pre-filter stage")

    args = p.parse_args(argv)
    general_cfg = yaml.safe_load(args.general_cfg.read_text(encoding="utf-8"))
    llm_cfg = yaml.safe_load(args.llm_cfg.read_text(encoding="utf-8"))

    try:
        pairs = collect_bin_pairs(args.old, args.new, args.bin_dir, general_cfg.get("datasets"))
    except Exception as e:
        global_logger.error(f"[ERROR] {e}")
        return
    if not pairs:
        global_logger.error("No binary pairs found.")
        return 
    
    #Step 2: Start the controller
    
    ida_path = general_cfg['ida']
    tmpfs_dir = general_cfg.get('tmpfs_dir', None)
    ida_service_cfg = ServiceConfig.from_env(ida_path=ida_path, tmpfs_dir=tmpfs_dir)

    app = create_app(ida_service_cfg)
    controller = None

    t = threading.Thread(
        target=lambda: uvicorn.run(app, host=ida_service_cfg.network.host, port=ida_service_cfg.network.port),
        daemon=True
    )
    t.start()
    wait_controller_ready(ida_service_cfg.network.host, ida_service_cfg.network.port, timeout_s=30.0)

    #Step 3: Process bin pairs
    try:
        random.shuffle(pairs)
        with mp.Pool(processes=args.workers) as pool:
            results = pool.starmap(
                spd_worker,
                [
                    (pair, general_cfg, llm_cfg, ida_service_cfg.network.host, ida_service_cfg.network.port, args.llm_mode, args.max_tokens_per_query, args.enable_prefilter)
                    for pair in pairs
                ],
                chunksize=1
            )

        ok = sum(1 for _, s, _ in results if s)
        fail = len(results) - ok
        for tag, s, msg in results:
            global_logger.info(f"[{tag}] {'OK' if s else 'FAIL'} - {msg}")

        global_logger.info(f"Done. Success: {ok}, Failed: {fail}, Total: {len(results)}")
    finally:
        global_logger.info("Waiting for all IDA projects to close...")
        time.sleep(2)
        global_logger.info("All workers finished. IDA projects should be closed.")
    
    
    return 0


if __name__ == '__main__':
    main()
    