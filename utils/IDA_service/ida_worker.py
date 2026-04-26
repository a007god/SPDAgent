from __future__ import annotations
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from pathlib import Path

READY_FLAG = {"ready": False}


import idaapi
import ida_auto
import idc
import idautils
import ida_name
import ida_lines
import ida_kernwin
import ida_segment
try:
    import ida_hexrays
    HAS_DECOMP = True
except Exception:
    ida_hexrays = None
    HAS_DECOMP = False

def _auto_wait_and_mark_ready():
    try:
        if idaapi:
            idaapi.auto_wait()
    except Exception:
        pass
    READY_FLAG["ready"] = True


def _parse_ea(s: str):
    s = s.strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    return int(s)


class Handler(BaseHTTPRequestHandler):
    server_version = "ida-worker/1.0"

    def _json(self, code=200, obj=None):
        data = json.dumps(obj or {}).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        # Avoid polluting IDA console with stdout
        return

    # ---- Routes ----
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path == "/health":
            return self._json(200, {"ready": READY_FLAG["ready"], "has_decompiler": HAS_DECOMP})

        if path == "/functions":
            try:
                q = (qs.get("q", [""])[0] or "").lower()
                out = []

                if not READY_FLAG.get("ready"):
                    return self._json(503, {"error": "IDA not ready"})

                for func_ea in idautils.Functions():
                    # Only keep functions in executable segments (consistent with your reference)
                    seg = idaapi.getseg(func_ea)
                    if not seg or not (seg.perm & ida_segment.SEGPERM_EXEC):
                        continue

                    name = idc.get_func_name(func_ea) or f"sub_{func_ea:X}"

                    # Case-insensitive keyword matching
                    if q and q not in name.lower():
                        continue

                    out.append({"name": name, "ea": f"0x{func_ea:x}"})

                return self._json(200, {"functions": out})
            except Exception as e:
                return self._json(500, {"error": repr(e)})

        if path == "/pseudocode":
            ea_s = qs.get("ea", [None])[0]
            func_name = qs.get("func_name", [None])[0]
            body = ""
            if not HAS_DECOMP:
                return self._json(501, {"error": "No Hex-Rays decompiler"})
            try:
                if func_name and ida_name:
                    ea = ida_name.get_name_ea(idaapi.BADADDR, func_name)
                elif ea_s:
                    ea = _parse_ea(ea_s)
                else:
                    return self._json(400, {"error": "ea or func_name required"})
                cfunc = ida_hexrays.decompile(ea)
                body = str(cfunc)
                return self._json(200, {"ea": hex(ea), "pseudocode": body})
            except Exception as e:
                return self._json(500, {"error": repr(e)})

        if path == "/disasm":
            ea_s = qs.get("ea", [None])[0]
            lines = int(qs.get("lines", ["40"])[0])
            if not ea_s:
                return self._json(400, {"error": "ea required"})
            try:
                ea = _parse_ea(ea_s)
                out = []
                cur = ea
                for _ in range(max(1, lines)):
                    # Use new IDA API: generate_disasm_line and next_head
                    disasm_line = idc.generate_disasm_line(cur, 0) if idc else ""
                    out.append({"ea": hex(cur), "line": disasm_line})
                    cur = idc.next_head(cur) if idc else cur + 1
                return self._json(200, {"start": hex(ea), "lines": out})
            except Exception as e:
                return self._json(500, {"error": repr(e)})

        if path == "/xrefs_to":
            ea_s = qs.get("ea", [None])[0]
            if not ea_s:
                return self._json(400, {"error": "ea required"})
            try:
                ea = _parse_ea(ea_s)
                out = []
                for xr in idautils.XrefsTo(ea):
                    out.append({"frm": hex(xr.frm), "to": hex(xr.to), "type": int(xr.type)})
                return self._json(200, {"ea": hex(ea), "xrefs": out})
            except Exception as e:
                return self._json(500, {"error": repr(e)})

        return self._json(404, {"error": "not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/close":
            input_path = Path(os.getenv("IDA_WORKER_IDA_INPUT") or "")
            print(input_path)
            if not input_path:
                return self._json(500, {"ok": False, "error": "IDA_WORKER_IDA_INPUT not set"})

            try:
                ida_auto.auto_wait()
                ida_kernwin.hide_wait_box()
            except Exception:
                pass

            self._json(200, {"ok": True})

            def _do_quit():
                idaapi.qexit(0)
            ida_kernwin.execute_sync(_do_quit, ida_kernwin.MFF_FAST)
            return

        return self._json(404, {"error": "not found"})


def main():
    host = os.getenv("IDA_WORKER_HOST", "127.0.0.1")
    port = int(os.getenv("IDA_WORKER_PORT", "0"))

    # Start background thread to wait for auto analysis to finish
    t = threading.Thread(target=_auto_wait_and_mark_ready, daemon=True)
    t.start()

    httpd = HTTPServer((host, port), Handler)
    httpd.serve_forever()


if __name__ == "__main__":
    main()