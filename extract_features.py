"""Feature extraction for one binary, using the same tool functions the MCP server exposes.

    .\\.venv\\Scripts\\python.exe extract_features.py <binary> [-o out.json] [--project NAME]
                                                     [--top N] [--timeout SECONDS] [--analyze]

It imports + auto-analyses the binary into the Ghidra project store, then extracts:
  * total function count
  * imported API count (plus imported libraries and an API name sample)
  * total string count
  * the N most "core" functions (highest caller count, ties broken by size; the program
    entry point is always included) with their decompiled pseudo-code
and writes everything to JSON.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ghidra_mcp import tools  # noqa: E402
from ghidra_mcp.session import SESSION  # noqa: E402

#: How many candidates (by size) get a caller-count pass for the "core function" ranking.
CANDIDATE_POOL = 30


def call(label: str, func, *args, **kwargs) -> dict:
    """Calls a tool function and returns its JSON payload, aborting on failure."""
    payload = json.loads(func(*args, **kwargs))
    if not payload.get("ok"):
        raise SystemExit(f"[extract] {label} failed: {payload.get('error')}")
    print(f"[extract] {label}: ok", file=sys.stderr)
    return payload


def file_hashes(path: Path) -> dict:
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            md5.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest(),
            "size_bytes": path.stat().st_size}


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract Ghidra features for one binary.")
    parser.add_argument("binary", help="path to the binary to analyse")
    parser.add_argument("-o", "--output", default=None, help="output JSON path")
    parser.add_argument("--project", default="weka", help="Ghidra project name")
    parser.add_argument("--top", type=int, default=5, help="number of core functions")
    parser.add_argument("--timeout", type=int, default=900, help="import/analysis timeout (s)")
    parser.add_argument("--decompile-chars", type=int, default=8000,
                        help="max characters of pseudo-code per function")
    parser.add_argument("--force", action="store_true", help="force re-import/re-analysis")
    parser.add_argument("--no-analyze", action="store_true", help="import only")
    args = parser.parse_args()

    binary = Path(args.binary)
    if not binary.is_file():
        raise SystemExit(f"[extract] binary not found: {binary}")
    output = Path(args.output) if args.output else binary.with_name("calc_features.json")

    print(f"[extract] binary={binary}", file=sys.stderr)
    imported = call("ghidra_import_and_analyze", tools.ghidra_import_and_analyze,
                    binary_path=str(binary), project_name=args.project,
                    analyze=not args.no_analyze, timeout=args.timeout,
                    force_reimport=args.force)
    summary = call("ghidra_current_program", tools.ghidra_current_program)["program"]

    functions = call("ghidra_list_functions", tools.ghidra_list_functions,
                     limit=100000, include_external=True, include_thunks=True)
    imports = call("ghidra_list_imports", tools.ghidra_list_imports, limit=100000)
    strings = call("ghidra_list_strings", tools.ghidra_list_strings,
                   min_length=4, limit=100000)
    entry_points = call("ghidra_list_entry_points", tools.ghidra_list_entry_points, limit=1000)
    blocks = call("ghidra_list_memory_blocks", tools.ghidra_list_memory_blocks)

    core = rank_core_functions(functions["functions"], args.top)
    for func in core:
        payload = json.loads(tools.ghidra_decompile_function(
            func["entry"], max_chars=args.decompile_chars))
        func["decompile_completed"] = bool(payload.get("decompile_completed"))
        func["decompile_full_length"] = payload.get("length")
        func["pseudo_code_truncated"] = bool(payload.get("truncated"))
        func["pseudo_code"] = payload.get("code", "")
        if not payload.get("ok") or not payload.get("decompile_completed"):
            func["decompile_error"] = payload.get("error", "decompilation incomplete")

    features = {
        "total_functions": functions["total_functions"],
        "imported_api_count": len(imports["imports"]),
        "imported_library_count": len(imports.get("libraries", [])),
        "total_strings": strings["matched"],
        "symbol_count": summary["symbol_count"],
        "entry_point_count": entry_points["returned"],
        "memory_blocks": blocks["returned"],
        "memory_bytes": summary["memory_bytes"],
    }

    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "generated_by": {
            "server": "ghidra-mcp via Cline MCP tools (PyGhidra, headless)",
            "ghidra": SESSION.environment().get("ghidra_version"),
            "project": args.project,
        },
        "binary": {
            "path": str(binary),
            "name": binary.name,
            **file_hashes(binary),
            "executable_format": summary["executable_format"],
            "language": summary["language"],
            "compiler": summary["compiler"],
            "image_base": summary["image_base"],
        },
        "analysis": {
            "imported": imported.get("imported"),
            "analyzed": imported.get("analyzed"),
            "elapsed_seconds": imported.get("elapsed_seconds"),
            "program": imported.get("program"),
        },
        "features": features,
        "core_functions": [
            {
                "rank": func["rank"],
                "name": func["full_name"],
                "entry": func["entry"],
                "signature": func["signature"],
                "size_bytes": func["size_bytes"],
                "callers": func["callers"],
                "callees": func["callees"],
                "decompile_completed": func["decompile_completed"],
                "pseudo_code_length": func["decompile_full_length"],
                "pseudo_code_truncated": func["pseudo_code_truncated"],
                "pseudo_code": func["pseudo_code"],
                **({"decompile_error": func["decompile_error"]} if "decompile_error" in func else {}),
            }
            for func in core
        ],
        "ranking_method": (
            f"Non-import, non-thunk functions sorted by caller count (in-degree from "
            f"ghidra_call_graph), ties broken by body size; caller counts computed for the "
            f"{CANDIDATE_POOL} largest functions; the program entry point is always included."
        ),
        "imported_apis": [entry["name"] for entry in imports["imports"]],
        "imported_libraries": imports.get("libraries", []),
        "strings_sample": strings["strings"],
        "entry_points": entry_points["entry_points"],
        "memory_blocks": blocks["blocks"],
    }

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[extract] wrote {output}", file=sys.stderr)

    SESSION.close()
    print(json.dumps({"output": str(output), "features": features,
                      "core_functions": [f"{f['name']} @ {f['entry']}" for f in result["core_functions"]]},
                     indent=2, ensure_ascii=False))
    return 0


def rank_core_functions(all_functions: list[dict], top_n: int) -> list[dict]:
    """Ranks functions for the "core function" list.

    Only non-import, non-thunk functions with a body are considered. Caller counts
    (in-degree via ghidra_call_graph) are computed for the CANDIDATE_POOL largest
    functions; everything is then sorted by caller count and finally by body size.
    The program entry point is always kept so the analysis entry is never missing.
    """
    pool = [
        func for func in all_functions
        if not func["is_external"] and not func["is_thunk"] and func.get("size_bytes")
    ]
    pool.sort(key=lambda func: func["size_bytes"], reverse=True)
    candidates = {func["entry"]: func for func in pool[:CANDIDATE_POOL]}

    entry_func = next((func for func in pool if func["name"] == "entry"), None)
    if entry_func is not None:
        candidates.setdefault(entry_func["entry"], entry_func)

    ranked = []
    for func in candidates.values():
        graph = json.loads(tools.ghidra_call_graph(func["entry"], limit=500))
        callers = len(graph.get("calling_functions", [])) if graph.get("ok") else 0
        callees = len(graph.get("called_functions", [])) if graph.get("ok") else 0
        ranked.append({**func, "callers": callers, "callees": callees,
                       "score": callers * 1000 + func["size_bytes"]})
    ranked.sort(key=lambda func: (func["score"], func["size_bytes"]), reverse=True)

    chosen = ranked[:top_n]
    if entry_func is not None and entry_func["entry"] not in {f["entry"] for f in chosen}:
        chosen = chosen[: max(top_n - 1, 0)] + [
            next(func for func in ranked if func["entry"] == entry_func["entry"])
        ]

    for index, func in enumerate(chosen, start=1):
        func["rank"] = index
    return chosen


if __name__ == "__main__":
    raise SystemExit(main())
