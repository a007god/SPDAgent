# -*- coding: utf-8 -*-
import subprocess
import shutil
import hashlib
from pathlib import Path
import time
import os
from typing import Optional

from utils.logging_helper import global_logger

def _normalize_logical_path(p: Path) -> Path:
    # If passed *.i64, remove .i64, treat as "logical input"
    return p.with_suffix("") if p.suffix == ".i64" else p

def stable_work_dir(tmpfs: Path, input_path: Path, *, clean_if_exists: bool = False) -> Path:
    """
    Generate stable and unique working directory for the same "target program".
    - Normalization: treat *.i64 as its corresponding original filename (remove .i64)
    - Uniqueness: do sha1 on normalized absolute path, take first 8 characters
    Directory name: ida_<logical_filename>.<short_hash>
    Example: ida_xattr.o.02eb04e5
    """
    logical_path = _normalize_logical_path(input_path).resolve()
    digest = hashlib.sha1(str(logical_path).encode("utf-8")).hexdigest()[:8]
    dirname = f"ida_{logical_path.name}.{digest}"
    work_dir = tmpfs / dirname

    if work_dir.exists():
        if clean_if_exists:
            for p in work_dir.iterdir():
                if p.is_dir():
                    shutil.rmtree(p, ignore_errors=True)
                else:
                    try:
                        p.unlink()
                    except Exception:
                        pass
    else:
        work_dir.mkdir(parents=True, exist_ok=True)

    return work_dir

def run_ida(ida_input: Path, cfg: dict, script_name: Optional[str] = None, extra_env: Optional[dict] = None) -> None:
    """
    Run IDA analysis with specified script.
    
    Args:
        ida_input: Path to input binary or i64 file
        cfg: Configuration dictionary
        script_name: Name of the IDA script to run (default: uses cfg["ida_script"])
        extra_env: Additional environment variables to pass to IDA script
    """
    start = time.time()

    ida_exe = Path(cfg["ida"])
    
    # Use specified script or default from config
    if script_name:
        ida_script = Path(cfg.get("scripts_dir", ".")) / script_name
    else:
        ida_script = Path(cfg["ida_script"])
    print(ida_script)
    
    diaphora_dir = Path(cfg["diaphora"])

    log_file = ida_input.with_suffix(".difflog")

    # Set up environment variables
    env = os.environ.copy()
    env['IDA_INPUT_PATH'] = str(Path(ida_input).resolve())
    env['DIAPHORA_DIR'] = str(Path(diaphora_dir).resolve())
    
    # Add extra environment variables if provided
    if extra_env:
        env.update(extra_env)
    
    cmd = [
        str(ida_exe),
        "-A",
        f"-L{log_file}",
        f"-S{ida_script}",
        str(ida_input)
    ]
    
    global_logger.info(f"[•] Running IDA with script: {ida_script.name}")
    subprocess.run(cmd, check=True, env=env)
    
