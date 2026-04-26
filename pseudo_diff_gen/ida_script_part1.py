# -*- coding: utf-8 -*-
"""
IDA Script Part 1: Only export Diaphora .sqlite database
This is the first stage of a two-stage process to optimize performance.

Usage: IDA -S ida_script_part1.py <binary>
"""
import sys
import os
from pathlib import Path
import time

import idaapi
import ida_auto
import ida_kernwin

# Ensure project root is importable inside IDA embedded Python.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utils.logging_helper import global_logger


# Resolve environment parameters
env_path = os.environ.get('IDA_INPUT_PATH')
in_path = Path(env_path).resolve()

DIAPHORA_DIR = os.environ.get('DIAPHORA_DIR')
if DIAPHORA_DIR not in sys.path:
    sys.path.insert(0, DIAPHORA_DIR)

try:
    import diaphora_ida
except ImportError:
    global_logger.error("[-] Failed to import diaphora_ida, please check DIAPHORA_DIR path")
    idaapi.qexit(1)


def export_sqlite(in_path: Path) -> Path:
    """
    Export Diaphora comparison database (.sqlite). If already exists, skip.
    """
    start = time.time()
    if in_path.suffix == ".i64":
        out_path = in_path.with_suffix(".sqlite")
    else:
        out_path = in_path.with_suffix(in_path.suffix + ".sqlite")
    
    if out_path.exists():
        global_logger.info(f"[=] {out_path.name} exists, skipping export")
        return out_path

    global_logger.info(f"[•] Exporting Diaphora sqlite → {out_path.name}")
    diaphora_ida.CIDABinDiff(str(out_path)).export()
    cost = time.time() - start
    global_logger.info(f"[✓] sqlite export completed, cost {cost:.2f} seconds.")
    return out_path


def main() -> None:
    """Main entry point for Part 1: only export sqlite"""
    # Wait for IDA auto analysis and hide progress box
    ida_auto.auto_wait()
    ida_kernwin.hide_wait_box()

    global_logger.info(f"[Stage 1] Processing {in_path.name}")
    
    # Only export Diaphora sqlite
    export_sqlite(in_path)

    global_logger.info("[Stage 1] Completed")
    # Exit IDA
    idaapi.qexit(0)


if __name__ == "__main__":
    main()

