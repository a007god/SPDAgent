# -*- coding: utf-8 -*-
"""
diaphora_script.py
"""
import subprocess
import sys
import sqlite3
import difflib
import re
from pathlib import Path
import time, random
import csv
from typing import Dict, Optional

from utils.logging_helper import global_logger

def clean_func_name(name: str) -> str:
    if not name:                     
        return name
    return name[1:] if name.startswith('_') else name


def run_diaphora(db_old: Path, db_new: Path, diff_db: Path, cfg: dict) -> None:
    """
    Use the Diaphora script to diff the old/new databases and generate diff_db
    """
    diaphora_py = Path(cfg["diaphora_py"])
    if diff_db.exists():
        global_logger.info(f"[+] {diff_db.name} already exists, skipping diff")
        return

    cmd = [
        sys.executable,
        str(diaphora_py),
        str(db_old),
        str(db_new),
        "-o", str(diff_db)
    ]
    global_logger.info("[•] Running Diaphora diff …")
    subprocess.run(cmd, check=True)
    global_logger.info(f"[✓] Generated diff database {diff_db.name}")


def _find_pseudo_column(cur) -> str | None:
    """Find the column name containing 'pseudo' in the functions table"""
    cur.execute("PRAGMA table_info(functions)")
    for _, name, *_ in cur.fetchall():
        if re.search(r"pseudo", name, re.I):
            return name
    return None


def _to_int(val):
    """Convert an address field to an integer (hex string or numeric string)"""
    if isinstance(val, (bytes, bytearray)):
        val = val.decode()
    if isinstance(val, str):
        return int(val.strip(), 16)
    return int(val)


def extract_unmatched_functions(diff_db: Path, out_dir: Path) -> Optional[Dict]:
    """
    Read unmatched functions from diff_db's unmatched table.
    NOTE: In Diaphora script mode, primary means new version, secondary means old version.
    Returns dict with 'primary' (new version) and 'secondary' (old version) function lists.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    
    conn = sqlite3.connect(diff_db)
    cur = conn.cursor()
    
    # Check if unmatched table exists
    tables = [r[0] for r in cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    )]
    if "unmatched" not in tables:
        global_logger.warning("[!] No 'unmatched' table found in diff database")
        conn.close()
        return None
    
    # Read unmatched functions
    cur.execute("SELECT type, name FROM unmatched")
    rows = cur.fetchall()
    
    if not rows:
        global_logger.info("[*] No unmatched functions found")
        conn.close()
        return {"primary": [], "secondary": []}
    
    unmatched_funcs = {"primary": [], "secondary": []}
    for func_type, func_name in rows:
        if func_type in ("primary", "secondary"):
            cleaned_name = clean_func_name(func_name)
            unmatched_funcs[func_type].append(cleaned_name)
    
    # Write to CSV files
    for func_type in ["primary", "secondary"]:
        if unmatched_funcs[func_type]:
            out_file = out_dir / f"{func_type}_unmatched.csv"
            with out_file.open("w", newline='', encoding="utf-8") as fp:
                writer = csv.writer(fp)
                writer.writerow(["name"])
                for name in unmatched_funcs[func_type]:
                    writer.writerow([name])
            global_logger.info(f"[✓] Exported {len(unmatched_funcs[func_type])} unmatched {func_type} functions to {out_file.name}")
    
    conn.close()
    time.sleep(random.uniform(0.3, 1.5))
    return unmatched_funcs


def extract_function_match(diff_db: Path, out_dir: Path) -> Optional[Dict]:
    """
    Read all match records from diff_db, group by type,
    and export the three columns (name1, name2) for each type to out_dir/<type>_match.csv
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(diff_db)
    cur  = conn.cursor()

    # Auto-find table name (prefer matches, diff, results)
    tables = [r[0] for r in cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    )]
    tbl='results'

    # Read table schema to locate column indices
    cur.execute(f"PRAGMA table_info({tbl})")
    cols = [c[1] for c in cur.fetchall()]

    # Ensure required columns exist
    for col in ("type", "name", "name2"):
        if col not in cols:
            global_logger.warning(f"[!] Required column `{col}` missing in table {tbl}, skipping")
            conn.close()
            return

    # Read all records
    cur.execute(f"SELECT type, name, name2 FROM {tbl}")
    rows = cur.fetchall()
    if not rows:
        global_logger.info(f"[*] No records found in table {tbl}")
        conn.close()
        return

    # Group by type
    groups = {}
    for t, n1, n2 in rows:
        groups.setdefault(t, []).append((n1, n2))

    # Write CSV files
    match_funcs={}
    for t, recs in groups.items():
        if t not in ("partial", "best"):
            continue
        out_file = out_dir / f"{t}_match.csv"
        with out_file.open("w", newline='', encoding="utf-8") as fp:
            writer = csv.writer(fp)
            # Write header
            writer.writerow(["name1", "name2"])
            # Write each record
            pairs = []
            for n1, n2 in recs:
                writer.writerow([clean_func_name(n1), clean_func_name(n2)])
                pairs.append((clean_func_name(n1), clean_func_name(n2)))
        match_funcs[t] = pairs
        global_logger.info(f"[✓] Exported {len(recs)} records of type='{t}' to {out_file.name}")

    conn.close()
    time.sleep(random.uniform(0.3, 1.5))
    return match_funcs


# Diaphora Diff using difflib.unified_diff()
def extract_partial_diffs(old_db: Path,
                          new_db: Path,
                          diff_db: Path,
                          out_dir: Path) -> None:
    """
    Filter Partial-Match records from diff_db and export unified diffs
    of old/new pseudocode to out_dir in JSON format matching PseudoDiffManager
    Also extracts unmatched functions (only in old or new version)
    """
    import json
    
    out_dir.mkdir(parents=True, exist_ok=True)

    # Open database connections
    c_diff = sqlite3.connect(diff_db)
    c_old  = sqlite3.connect(old_db)
    c_new  = sqlite3.connect(new_db)
    d_cur = c_diff.cursor()

    # Select appropriate table
    tables = [r[0] for r in d_cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    )]
    pref = ["results", "diff", "matches"]
    tbl = next((t for t in pref if t in tables), tables[0] if tables else None)
    if not tbl:
        global_logger.warning("[!] No tables found in diff database, skipping Partial-Match extraction")
        return

    # Find address and type columns
    d_cur.execute(f"PRAGMA table_info({tbl})")
    cols = [c[1] for c in d_cur.fetchall()]

    a1 = 'address'
    a2 = 'address2'
    st = 'type'
    n = 'name'

    if not (a1 and a2 and st):
        global_logger.warning("[!] Unable to identify necessary fields for Partial-Match, skipping")
        return

    # Retrieve Partial-Match rows
    rows = d_cur.execute(
        f"SELECT {a1}, {a2} FROM {tbl} WHERE lower({st}) LIKE '%partial%' ORDER BY {a1}"
    ).fetchall()
    if not rows:
        global_logger.info("[*] No Partial-Match records found")
    else:
        global_logger.info(f"[＊] Found {len(rows)} Partial-Match records")

    # Prepare cursors for old/new pseudocode
    o_cur = c_old.cursor()
    n_cur = c_new.cursor()
    col_old = _find_pseudo_column(o_cur) or "pseudo"
    col_new = _find_pseudo_column(n_cur) or "pseudo"

    # Collect all diffs in a list to match PseudoDiffManager format
    all_diffs = []
    count = 0
    
    for addr_old, addr_new in rows:
        try:
            oa = _to_int(addr_old)
            na = _to_int(addr_new)
        except Exception as e:
            global_logger.error(f"[!] Address conversion failed: {e}")
            continue

        # Read pseudocode
        o_cur.execute(f"SELECT {col_old} FROM functions WHERE address=?", (oa,))
        old_code = (o_cur.fetchone() or [None])[0]
        n_cur.execute(f"SELECT {col_new} FROM functions WHERE address=?", (na,))
        new_code = (n_cur.fetchone() or [None])[0]

        # Extract function names
        o_cur.execute(f"SELECT {n} FROM functions WHERE address=?", (oa,))
        fn1 = (o_cur.fetchone() or [None])[0] or f"{oa:08X}"
        n_cur.execute(f"SELECT {n} FROM functions WHERE address=?", (na,))
        fn2 = (n_cur.fetchone() or [None])[0] or f"{na:08X}"

        # Only process if both codes exist
        if old_code and new_code:
            # Generate unified diff
            diff_lines = list(difflib.unified_diff(
                old_code.splitlines(), 
                new_code.splitlines(),
                fromfile="old", 
                tofile="new", 
                lineterm=""
            ))
            
            numbered_diff = []
            for idx, line in enumerate(diff_lines, start=1):
                numbered_diff.append(f"{idx:4d}: {line}")
            # Create diff dict matching PseudoDiffManager format
            diff_dict = {
                "old_func": fn1,
                "new_func": fn2,
                "old_code": old_code,
                "new_code": new_code,
                "diff": "\n".join(numbered_diff)
            }
            
            all_diffs.append(diff_dict)
            count += 1

    # Process unmatched functions
    # NOTE: In Diaphora script mode, primary means new version, secondary means old version
    if "unmatched" in tables:
        global_logger.info("[•] Processing unmatched functions")
        d_cur.execute("SELECT type, name, address FROM unmatched")
        unmatched_rows = d_cur.fetchall()
        
        unmatched_count = 0
        for func_type, func_name, func_addr in unmatched_rows:
            if func_type == "primary":
                # Function only in new version (added)
                try:
                    addr = _to_int(func_addr)
                    n_cur.execute(f"SELECT {col_new} FROM functions WHERE address=?", (addr,))
                    new_code = (n_cur.fetchone() or [None])[0]
                    
                    if new_code:
                        # Add '+' prefix to each line
                        new_lines = new_code.splitlines()
                        diff_lines = [f"--- old_version", f"+++ new_version"]
                        diff_lines.extend([f"+{line}" for line in new_lines])
                        
                        numbered_diff = []
                        for idx, line in enumerate(diff_lines, start=1):
                            numbered_diff.append(f"{idx:4d}: {line}")
                        
                        diff_dict = {
                            "old_func": "",
                            "new_func": clean_func_name(func_name),
                            "old_code": "",
                            "new_code": new_code,
                            "diff": "\n".join(numbered_diff)
                        }
                        all_diffs.append(diff_dict)
                        unmatched_count += 1
                except Exception as e:
                    global_logger.warning(f"[!] Failed to process primary unmatched function {func_name}: {e}")
                    
            elif func_type == "secondary":
                # Function only in old version (deleted)
                try:
                    addr = _to_int(func_addr)
                    o_cur.execute(f"SELECT {col_old} FROM functions WHERE address=?", (addr,))
                    old_code = (o_cur.fetchone() or [None])[0]
                    
                    if old_code:
                        # Add '-' prefix to each line
                        old_lines = old_code.splitlines()
                        diff_lines = [f"--- old_version", f"+++ new_version"]
                        diff_lines.extend([f"-{line}" for line in old_lines])
                        
                        numbered_diff = []
                        for idx, line in enumerate(diff_lines, start=1):
                            numbered_diff.append(f"{idx:4d}: {line}")
                        
                        diff_dict = {
                            "old_func": clean_func_name(func_name),
                            "new_func": "",
                            "old_code": old_code,
                            "new_code": "",
                            "diff": "\n".join(numbered_diff)
                        }
                        all_diffs.append(diff_dict)
                        unmatched_count += 1
                except Exception as e:
                    global_logger.warning(f"[!] Failed to process secondary unmatched function {func_name}: {e}")
        
        if unmatched_count > 0:
            global_logger.info(f"[✓] Processed {unmatched_count} unmatched functions")

    # Close database connections
    c_diff.close()
    c_old.close()
    c_new.close()

    # Save all diffs to JSON file matching PseudoDiffManager format
    diff_path = out_dir / "diaphora_diff.json"
    with diff_path.open("w", encoding="utf-8") as f:
        json.dump(all_diffs, f, ensure_ascii=False, indent=2)
    
    global_logger.info(f"[✓] Output {count} Partial-Match diffs + unmatched functions to {diff_path}")

    time.sleep(random.uniform(0.3, 1.5))
