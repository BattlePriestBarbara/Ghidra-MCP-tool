"""Smoke test: exercise every MCP tool directly, without the MCP transport.

It reuses the 'probe' project (notepad.exe) created by probe_pyghidra.py so it runs
in seconds. Run:

    .\\.venv\\Scripts\\python.exe tests\\smoke_tools.py [project] [program] [binary]
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ghidra_mcp import tools  # noqa: E402

PROJECT = sys.argv[1] if len(sys.argv) > 1 else "probe"
PROGRAM = sys.argv[2] if len(sys.argv) > 2 else "notepad.exe"
BINARY = sys.argv[3] if len(sys.argv) > 3 else r"C:\Windows\System32\notepad.exe"

RESULTS: list[dict] = []


def digest(payload: dict) -> str:
    """Short human-readable summary of a tool result."""
    parts: list[str] = []
    for key, value in payload.items():
        if key == "ok":
            continue
        if isinstance(value, bool):
            parts.append(f"{key}={value}")
        elif isinstance(value, int):
            parts.append(f"{key}={value}")
        elif isinstance(value, str) and len(value) <= 60:
            parts.append(f"{key}={value!r}")
        elif isinstance(value, list):
            parts.append(f"{key}[{len(value)}]")
        elif isinstance(value, dict):
            parts.append(f"{key}{{{len(value)}}}")
    return ", ".join(parts[:6])


def run(label: str, func, *args, **kwargs) -> dict:
    started = time.time()
    try:
        payload = json.loads(func(*args, **kwargs))
    except Exception as exc:  # noqa: BLE001
        payload = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    entry = {
        "check": label,
        "ok": bool(payload.get("ok")),
        "seconds": round(time.time() - started, 2),
        "detail": digest(payload) if payload.get("ok") else payload.get("error"),
        "payload": payload,
    }
    RESULTS.append(entry)
    return payload


def main() -> int:
    print(f"[smoke] project={PROJECT} program={PROGRAM} binary={BINARY}", file=sys.stderr)
    run("ghidra_environment", tools.ghidra_environment)
    run("ghidra_list_projects", tools.ghidra_list_projects)
    run("ghidra_import_and_analyze (cached open)", tools.ghidra_import_and_analyze,
        binary_path=BINARY, project_name=PROJECT, program_name=PROGRAM)
    run("ghidra_list_programs", tools.ghidra_list_programs, PROJECT)
    run("ghidra_current_program", tools.ghidra_current_program)
    run("ghidra_list_functions", tools.ghidra_list_functions, name_filter="entry", limit=5)
    run("ghidra_search_symbols", tools.ghidra_search_symbols, query="entry", limit=5)
    run("ghidra_function_details", tools.ghidra_function_details, "entry", max_xrefs=5)
    run("ghidra_decompile_function", tools.ghidra_decompile_function, "entry", max_chars=1200)
    run("ghidra_call_graph", tools.ghidra_call_graph, "entry", limit=5)
    run("ghidra_xrefs (to)", tools.ghidra_xrefs, "entry", direction="to", limit=5)
    run("ghidra_xrefs (from)", tools.ghidra_xrefs, "entry", direction="from", limit=5)
    run("ghidra_disassemble", tools.ghidra_disassemble, "entry", count=5)
    run("ghidra_read_bytes", tools.ghidra_read_bytes, "0x140000000", 32)
    run("ghidra_search_bytes (MZ)", tools.ghidra_search_bytes, "4D 5A", limit=3)
    run("ghidra_list_strings", tools.ghidra_list_strings, min_length=8, limit=5)
    run("ghidra_list_imports", tools.ghidra_list_imports, limit=5)
    run("ghidra_list_entry_points", tools.ghidra_list_entry_points, limit=5)
    run("ghidra_list_data_types", tools.ghidra_list_data_types, limit=5)
    run("ghidra_list_memory_blocks", tools.ghidra_list_memory_blocks)
    run("ghidra_session_status", tools.ghidra_session_status)
    run("ghidra_close_program", tools.ghidra_close_program)

    # A few semantic assertions so the test fails loudly if a query silently empties.
    by_check = {entry["check"]: entry["payload"] for entry in RESULTS}
    assertions = [
        ("import/open created a program", bool(by_check["ghidra_import_and_analyze (cached open)"].get("program"))),
        ("functions listed", by_check["ghidra_list_functions"].get("total_functions", 0) > 0),
        ("symbols found", by_check["ghidra_search_symbols"].get("returned", 0) > 0),
        ("decompiler produced code", len(str(by_check["ghidra_decompile_function"].get("code", ""))) > 10),
        ("disassembly returned instructions",
         by_check["ghidra_disassemble"].get("returned", 0) > 0),
        ("strings found", by_check["ghidra_list_strings"].get("returned", 0) > 0),
        ("imports found", by_check["ghidra_list_imports"].get("returned", 0) > 0),
        ("memory blocks found", by_check["ghidra_list_memory_blocks"].get("returned", 0) > 0),
        ("byte pattern matched", by_check["ghidra_search_bytes (MZ)"].get("returned", 0) > 0),
    ]

    print("\n=== tool smoke test ===")
    failures = 0
    for entry in RESULTS:
        status = "PASS" if entry["ok"] else "FAIL"
        if not entry["ok"]:
            failures += 1
        print(f"{status} {entry['seconds']:>6.2f}s  {entry['check']:<45} {entry['detail']}")

    print("\n=== semantic assertions ===")
    for label, passed in assertions:
        print(f"{'PASS' if passed else 'FAIL'} {label}")
        if not passed:
            failures += 1

    summary = {"checks": len(RESULTS), "failures": failures}
    print("\n" + json.dumps(summary, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
