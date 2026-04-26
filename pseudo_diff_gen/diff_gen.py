# -*- coding: utf-8 -*-
"""
diff_gen.py — Main workflow interface that integrates IDA analysis, Diaphora diff, and Partial-Match extraction
Supports concurrent processing with multiple processes
"""
import sys
import yaml
import json
from pathlib import Path
from typing import List, Dict
import os
import multiprocessing
import subprocess
import shutil
import hashlib

root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)
from logging.handlers import QueueHandler, QueueListener

from utils.logging_helper import global_logger, get_child_logger
from utils.storage_helper import StorageLocation
from .ida_runner import run_ida
from .diaphora_script import run_diaphora, extract_partial_diffs, extract_function_match, extract_unmatched_functions
from .diff_core import PseudoDiffManager


IGNORE_EXTS = {
    ".i64", ".id0", ".id1", ".id2", ".nam", ".til", ".sig",
    ".idb", ".d64", ".db64", ".lst", ".asm", ".c", ".cpp",
    ".h", ".txt", ".log", ".sqlite", ".diff", ".json"
}

# These globals will be initialized in each worker process by init_worker
LOG_QUEUE: multiprocessing.Queue
CFG: dict


def run_simple_ida_analysis(binary: Path, cfg: dict) -> None:
    """
    Run simple IDA analysis, only generate .i64 file, don't execute other scripts
    """
    ida_exe = Path(cfg["ida"])
    i64_file = binary.with_suffix(".i64")
    
    # Create simple IDA command, only perform analysis and save database
    cmd = [
        str(ida_exe),
        "-A",  # Automatic mode
        "-B",
        str(binary)
    ]
    
    global_logger.info(f"[•] Running simple IDA analysis on {binary.name}")
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        global_logger.info(f"[✓] Generated database: {i64_file}")
    except subprocess.CalledProcessError as e:
        global_logger.error(f"IDA analysis failed: {e}")
        raise


def _cleanup_binary_directories(old_bin: Path, new_bin: Path) -> None:
    """
    Clean up binary file directories, keeping only:
    - Original binary files
    - .i64 files
    - .sqlite files  
    - .log files
    Remove all other files and directories
    """
    global_logger.info("Cleaning up binary file directories...")
    
    # Define file extensions to keep
    keep_extensions = {'.i64', '.sqlite', '.difflog'}
    
    # Get original binary file names (without path)
    old_bin_name = old_bin.name
    new_bin_name = new_bin.name
    
    # Get directories containing the binary files
    old_bin_dir = old_bin.parent
    new_bin_dir = new_bin.parent
    
    # Process both directories
    for bin_dir in [old_bin_dir, new_bin_dir]:
        if not bin_dir.exists():
            continue
            
        global_logger.info(f"Cleaning directory: {bin_dir}")
        removed_count = 0
        kept_count = 0
        
        # Walk through all files and directories in binary directory
        for item in bin_dir.rglob('*'):
            if not item.exists():
                continue
                
            # Skip if it's the binary directory itself
            if item == bin_dir:
                continue
                
            should_keep = False
            
            if item.is_file():
                # Check if it's an original binary file
                if item.name == old_bin_name or item.name == new_bin_name:
                    should_keep = True
                    kept_count += 1
                # Check if it has a keepable extension
                elif item.suffix.lower() in keep_extensions:
                    should_keep = True
                    kept_count += 1
            elif item.is_dir():
                # Check if directory contains only files we want to keep
                has_keepable_files = False
                for sub_item in item.rglob('*'):
                    if sub_item.is_file():
                        if (sub_item.name == old_bin_name or 
                            sub_item.name == new_bin_name or 
                            sub_item.suffix.lower() in keep_extensions):
                            has_keepable_files = True
                            break
                
                if has_keepable_files:
                    should_keep = True
                    kept_count += 1
            
            # Remove item if it shouldn't be kept
            if not should_keep:
                try:
                    if item.is_dir():
                        shutil.rmtree(item, ignore_errors=True)
                        global_logger.debug(f"Removed directory: {item.relative_to(bin_dir)}")
                    else:
                        item.unlink(missing_ok=True)
                        global_logger.debug(f"Removed file: {item.relative_to(bin_dir)}")
                    removed_count += 1
                except Exception as e:
                    global_logger.warning(f"Failed to remove {item.relative_to(bin_dir)}: {e}")
        
        global_logger.info(f"Directory {bin_dir} cleanup completed: kept {kept_count} items, removed {removed_count} items")


def is_binary_file(filepath: Path, blocksize: int = 1024) -> bool:
    """
    Simple check whether a file is binary:
    Read the first `blocksize` bytes; if it contains '\0', treat it as binary.
    """
    try:
        with filepath.open('rb') as f:
            chunk = f.read(blocksize)
        return b'\0' in chunk
    except Exception:
        return False


def get_binary_pairs(datasets: Dict[str, Path]) -> List[Dict]:
    """
    General binary pairing:

    Dataset layout:
    └── xxx/
        ├── patch_before/   ← old version
        └── patch_after/    ← new version

    Steps:
      1. Recursively find any candidate directory with exactly two subdirectories.
      2. If the subdirectory names include 'patch_before' / 'patch_after',
         assign old_dir / new_dir accordingly; otherwise fall back to alphabetical order.
      3. Enumerate files under old_dir; if the same relative path exists in new_dir
         and both are real binaries, count them as a pair.

    Returns:
      A list of dicts with keys 'label', 'group_name', 'old_bin', 'new_bin', 'bin_tag'.
    """
    pairs: List[Dict] = []

    for label, root in datasets.items():
        root = Path(root)

        # 1) Find candidate directories with exactly two subdirectories
        for cand in root.rglob('*'):
            if not cand.is_dir():
                continue
            subdirs = [d for d in cand.iterdir() if d.is_dir()]
            if len(subdirs) != 2:
                continue

            
            # 2) Determine before / after
            mapping = {d.name.lower(): d for d in subdirs}
            if 'patch_before' in mapping and 'patch_after' in mapping:
                old_dir = mapping['patch_before']
                new_dir = mapping['patch_after']
            else:
                # Fallback: alphabetical order (preserve old logic)
                old_dir, new_dir = sorted(subdirs, key=lambda d: d.name)

            # 3) Must have at least one binary file in each
            if not any(is_binary_file(p) for p in old_dir.rglob('*') if p.is_file()):
                continue
            if not any(is_binary_file(p) for p in new_dir.rglob('*') if p.is_file()):
                continue

            # 4) Pair up files by relative path
            for old_file in old_dir.rglob('*'):
                if (not old_file.is_file()
                        or old_file.suffix.lower() in IGNORE_EXTS
                        or not is_binary_file(old_file)):
                    continue

                rel = old_file.relative_to(old_dir)
                new_file = new_dir / rel
                if not (new_file.exists() and new_file.is_file()
                        and is_binary_file(new_file)):
                    continue

                # 5) Generate a unique tag
                safe_rel = rel.as_posix().replace('/', '_')
                bin_tag = f"{cand.name}_{safe_rel}"

                pairs.append({
                    'label':      label,
                    'group_name': cand.relative_to(root).as_posix(),
                    'old_bin':    old_file,
                    'new_bin':    new_file,
                    'bin_tag':    bin_tag,
                })

    return pairs


def init_worker(log_queue: multiprocessing.Queue, cfg_dict: dict):
    """
    Worker process initialization: set global log queue and config,
    replace global_logger with a QueueHandler
    """
    global LOG_QUEUE, CFG
    LOG_QUEUE = log_queue
    CFG = cfg_dict

    # Replace handlers on the base logger with a single QueueHandler
    base_logger = global_logger
    for h in list(base_logger.handlers):
        base_logger.removeHandler(h)
        try:
            h.close()
        except Exception:
            pass

    qh = QueueHandler(LOG_QUEUE)
    qh.setLevel(base_logger.level)
    base_logger.addHandler(qh)
    base_logger.propagate = False  # Prevent double logging

    # Optionally rename logger to the process name for clarity
    base_logger.name = multiprocessing.current_process().name


def process_pair(pair: Dict, cfg :dict, overide = False) -> list:
    """
    Worker function: uses the replaced global_logger and CFG
    Implements memory disk optimization strategy:
    - If tmpfs_dir is enabled, copy binaries to memory disk for analysis
    - Generate .i64 files on memory disk, then copy back to local disk
    - Run subsequent analysis on local disk
    - Generate sqlite files on memory disk if enabled
    - Clean up temporary files at the end
    """
    
    
    label = pair['label']
    old_bin = Path(pair['old_bin'])
    new_bin = Path(pair['new_bin'])
    bin_tag = pair['bin_tag']
    group_dir = pair['group_name'].replace('/', '_')

    out_root = StorageLocation.result_dir() / label / group_dir / bin_tag
    tmpfs_dir = cfg.get("tmpfs_dir", "")
    tmpfs = Path(tmpfs_dir) if tmpfs_dir else None
    use_ramdisk = tmpfs is not None and tmpfs.exists()

    global_logger.info(f"=== [{label}] Processing {bin_tag} ===")

    # Temporary files to clean up at the end - moved to function level
    temp_files = []
    final_cleanup_files = []

    local_old_i64 = old_bin.parent / f"{old_bin.name}.i64"
    local_new_i64 = new_bin.parent / f"{new_bin.name}.i64"

    old_sqlite_path: Path | None = None
    new_sqlite_path: Path | None = None
    diff_db: Path | None = None
    match_funcs = None
    unmatched_funcs = None

    try:
        # Check if .i64 files already exist locally - check at the outermost level
        if local_old_i64.exists() and local_new_i64.exists() and not overide:
            global_logger.info(f"Database files already exist locally, skipping IDA analysis: {local_old_i64.name}")
        else:
            if use_ramdisk and tmpfs:
                global_logger.info(f"Using memory disk: {tmpfs}")
                
                # Create temporary directories for this pair
                temp_old_dir = tmpfs / f"temp_old_{hashlib.md5(str(old_bin).encode()).hexdigest()}"
                temp_new_dir = tmpfs / f"temp_new_{hashlib.md5(str(new_bin).encode()).hexdigest()}"
                temp_old_dir.mkdir(parents=True, exist_ok=True)
                temp_new_dir.mkdir(parents=True, exist_ok=True)
                temp_files.extend([temp_old_dir, temp_new_dir])
                
                # Copy binaries to memory disk
                temp_old_bin = temp_old_dir / old_bin.name
                temp_new_bin = temp_new_dir / new_bin.name
                shutil.copy2(old_bin, temp_old_bin)
                shutil.copy2(new_bin, temp_new_bin)
                temp_files.extend([temp_old_bin, temp_new_bin])
                
                global_logger.info(f"Copied binaries to memory disk: {temp_old_bin.name}, {temp_new_bin.name}")
                
                # Run simple IDA analysis on memory disk (only generate .i64 files)
                run_simple_ida_analysis(temp_old_bin, cfg)
                run_simple_ida_analysis(temp_new_bin, cfg)
                
                # Copy generated .i64 files back to local disk
                temp_old_i64 = temp_old_bin.parent / f"{temp_old_bin.name}.i64"
                temp_new_i64 = temp_new_bin.parent / f"{temp_new_bin.name}.i64"
                
                if temp_old_i64.exists():
                    shutil.copy2(temp_old_i64, local_old_i64)
                    global_logger.info(f"Copied {temp_old_i64.name} back to local disk")
                if temp_new_i64.exists():
                    shutil.copy2(temp_new_i64, local_new_i64)
                    global_logger.info(f"Copied {temp_new_i64.name} back to local disk")
            else:
                global_logger.info("Using local disk for analysis")
                
                # Run simple IDA analysis on local disk (only generate .i64 files)
                run_simple_ida_analysis(old_bin, cfg)
                run_simple_ida_analysis(new_bin, cfg)

        diff_path = out_root / "diff.json"
        if diff_path.exists() and not overide:
            global_logger.info("Function level diff already generated")
            with diff_path.open("r", encoding="utf-8") as f:
                all_diffs = json.load(f)

            global_logger.info(f"Loaded {len(all_diffs)} diffs from {diff_path}")
            return all_diffs
        

        # ========== STAGE 1: Generate .sqlite only ==========
        global_logger.info("=== Stage 1: Generating .sqlite databases ===")
        
        # Get script directory path
        script_dir = Path(__file__).parent
        
        # Run Part 1 script to generate .sqlite files only
        if use_ramdisk and tmpfs:
            global_logger.info("Running Stage 1 on memory disk")

            stage1_old_dir = tmpfs / f"temp_stage1_old_{hashlib.md5(str(local_old_i64).encode()).hexdigest()}"
            stage1_new_dir = tmpfs / f"temp_stage1_new_{hashlib.md5(str(local_new_i64).encode()).hexdigest()}"
            stage1_old_dir.mkdir(parents=True, exist_ok=True)
            stage1_new_dir.mkdir(parents=True, exist_ok=True)
            temp_files.extend([stage1_old_dir, stage1_new_dir])

            temp_old_i64 = stage1_old_dir / local_old_i64.name
            temp_new_i64 = stage1_new_dir / local_new_i64.name
            shutil.copy2(local_old_i64, temp_old_i64)
            shutil.copy2(local_new_i64, temp_new_i64)
            temp_files.extend([temp_old_i64, temp_new_i64])

            run_ida(temp_old_i64, cfg, script_name=str(script_dir / "ida_script_part1.py"))
            run_ida(temp_new_i64, cfg, script_name=str(script_dir / "ida_script_part1.py"))

            # Copy generated log files back to local disk
            copies = [
                (temp_old_i64.with_suffix(".difflog"), local_old_i64.with_suffix(".difflog")),
                (temp_new_i64.with_suffix(".difflog"), local_new_i64.with_suffix(".difflog")),
            ]
            for src, dst in copies:
                if src.exists():
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src, dst)
            old_sqlite_path = temp_old_i64.with_suffix(".sqlite")
            new_sqlite_path = temp_new_i64.with_suffix(".sqlite")
        else:
            run_ida(local_old_i64, cfg, script_name=str(script_dir / "ida_script_part1.py"))
            run_ida(local_new_i64, cfg, script_name=str(script_dir / "ida_script_part1.py"))
            final_cleanup_files.extend([
                local_old_i64.with_suffix(".sqlite"),
                local_new_i64.with_suffix(".sqlite"),
            ])
            old_sqlite_path = local_old_i64.with_suffix(".sqlite")
            new_sqlite_path = local_new_i64.with_suffix(".sqlite")

        # ========== Generate Diaphora diff and function matching ==========
        global_logger.info("=== Running Diaphora diff and function matching ===")
        
        if use_ramdisk and tmpfs:
            # Use memory disk for sqlite generation
            temp_sqlite_dir = tmpfs / f"temp_sqlite_{hashlib.md5(str(old_bin).encode()).hexdigest()}"
            temp_sqlite_dir.mkdir(parents=True, exist_ok=True)
            temp_files.append(temp_sqlite_dir)  # Add to cleanup list
            
            temp_diff_sqlite = temp_sqlite_dir / f"{new_bin.stem}.diff.sqlite"
            
            # Run Diaphora on memory disk
            run_diaphora(
                db_old=old_sqlite_path,
                db_new=new_sqlite_path,
                diff_db=temp_diff_sqlite,
                cfg=cfg
            )
            
            diff_db = temp_diff_sqlite

            # Extract function match results
            match_funcs = extract_function_match(
                diff_db=diff_db,
                out_dir=out_root
            )
            
            # Extract unmatched functions
            unmatched_funcs = extract_unmatched_functions(
                diff_db=diff_db,
                out_dir=out_root
            )
            
        else:
            # Use local disk for sqlite generation
            diff_db = new_bin.with_suffix(".diff.sqlite")
            run_diaphora(
                db_old=old_sqlite_path,
                db_new=new_sqlite_path,
                diff_db=diff_db,
                cfg=cfg
            )
            final_cleanup_files.append(diff_db)

            # Extract function match results
            match_funcs = extract_function_match(
                diff_db=diff_db,
                out_dir=out_root
            )
            
            # Extract unmatched functions
            unmatched_funcs = extract_unmatched_functions(
                diff_db=diff_db,
                out_dir=out_root
            )
        
        # ========== STAGE 2: Generate pseudocode and pseudotree for matched and unmatched functions ==========
        global_logger.info("=== Stage 2: Generating pseudocode and pseudotree for matched and unmatched functions ===")
        
        # Collect all unique function names from all match types (partial, best, unreliable, etc.)
        partial_match_old_funcs = set()
        partial_match_new_funcs = set()
        
        if match_funcs:
            for match_type, func_pairs in match_funcs.items():
                if match_type == "partial":
                    for old_func, new_func in func_pairs:
                        partial_match_old_funcs.add(old_func)
                        partial_match_new_funcs.add(new_func)
        
        # Add unmatched functions
        if unmatched_funcs:
            #NOTE: here Diaphora diffs from GUI plugin. When I use Diaphora on IDA GUI, primary means the old version;
            # But in script, primary means new version;
            if unmatched_funcs.get("primary"):
                partial_match_new_funcs.update(unmatched_funcs["primary"])
                global_logger.info(f"Added {len(unmatched_funcs['primary'])} unmatched primary (new) functions")
            if unmatched_funcs.get("secondary"):
                partial_match_old_funcs.update(unmatched_funcs["secondary"])
                global_logger.info(f"Added {len(unmatched_funcs['secondary'])} unmatched secondary (old) functions")
        
        global_logger.info(f"Found {len(partial_match_old_funcs)} old functions and {len(partial_match_new_funcs)} new functions with matches or unmatched")
        
        if partial_match_old_funcs or partial_match_new_funcs:
            # Create temporary JSON files with function lists
            old_func_list_path = out_root / "old_functions.json"
            new_func_list_path = out_root / "new_functions.json"
            
            try:
                with old_func_list_path.open("w", encoding="utf-8") as f:
                    json.dump(list(partial_match_old_funcs), f, ensure_ascii=False, indent=2)
                
                with new_func_list_path.open("w", encoding="utf-8") as f:
                    json.dump(list(partial_match_new_funcs), f, ensure_ascii=False, indent=2)
                
                global_logger.info(f"Generated function lists: {old_func_list_path.name}, {new_func_list_path.name}")
                
                # Run Part 2 script to generate pseudocode and pseudotree for matched functions only
                run_ida(
                    local_old_i64, 
                    cfg, 
                    script_name=str(script_dir / "ida_script_part2.py"),
                    extra_env={"IDA_FUNCTION_LIST": str(old_func_list_path.resolve())}
                )
                
                run_ida(
                    local_new_i64, 
                    cfg, 
                    script_name=str(script_dir / "ida_script_part2.py"),
                    extra_env={"IDA_FUNCTION_LIST": str(new_func_list_path.resolve())}
                )
                
            finally:
                # Clean up temporary function list JSON files after IDA processing
                for func_list_file in [old_func_list_path, new_func_list_path]:
                    if func_list_file.exists():
                        try:
                            func_list_file.unlink()
                            global_logger.debug(f"Cleaned up temporary file: {func_list_file.name}")
                        except Exception as e:
                            global_logger.warning(f"Failed to clean up {func_list_file.name}: {e}")
                
                global_logger.info("Cleaned up temporary function list files")
        else:
            global_logger.warning("No matched functions found, skipping Stage 2")

        # Generate Partial-Match diff texts
        if not match_funcs:
            global_logger.warning("No function matches found, generating unmatched diffs only if available")
            
        pdm = PseudoDiffManager(match_funcs or {}, old_bin.parent.parent, unmatched_funcs=unmatched_funcs)
        all_diffs = pdm.generate_diff()
        if not all_diffs:
            return []


        
        with diff_path.open("w", encoding="utf-8") as f:
            json.dump(all_diffs, f, ensure_ascii=False, indent=2)
        global_logger.info(f"Saved diff to {diff_path}")
    

        # (Optional) Extract Partial-Match diffs using Diaphora
        # for ablation study
        extract_partial_diffs(
            old_db=old_sqlite_path,
            new_db=new_sqlite_path,
            diff_db=diff_db,
            out_dir=out_root
        )

        return all_diffs
    finally:
        # Remove intermediate sqlite databases if requested
        if final_cleanup_files:
            global_logger.info("Removing intermediate sqlite databases")
            for cleanup_file in final_cleanup_files:
                try:
                    if cleanup_file.exists():
                        cleanup_file.unlink()
                        global_logger.debug(f"Removed intermediate sqlite: {cleanup_file}")
                except Exception as e:
                    global_logger.warning(f"Failed to remove {cleanup_file}: {e}")

        # Clean up all temporary files at the end
        if temp_files:
            global_logger.info("Cleaning up temporary files...")
            for temp_file in temp_files:
                try:
                    if temp_file.is_dir():
                        shutil.rmtree(temp_file, ignore_errors=True)
                    elif temp_file.is_file():
                        temp_file.unlink(missing_ok=True)
                except Exception as e:
                    global_logger.warning(f"Failed to clean up {temp_file}: {e}")
            global_logger.info("Temporary file cleanup completed")

        # Clean up binary file directories, keeping only specified file types
        _cleanup_binary_directories(old_bin, new_bin)

