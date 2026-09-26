"""Smoke test for the analyzeHeadless fallback and its interop with PyGhidra.

    .\\.venv\\Scripts\\python.exe tests\\smoke_headless.py [binary]

Imports a binary with analyzeHeadless (-noanalysis to keep it quick), then reopens
the very same project with PyGhidra to prove both engines share the project store.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ghidra_mcp import tools  # noqa: E402

BINARY = sys.argv[1] if len(sys.argv) > 1 else r"C:\Windows\System32\notepad.exe"
PROJECT = "headless_smoke"
PROGRAM = Path(BINARY).name


def call(label: str, func, *args, **kwargs) -> dict:
    payload = json.loads(func(*args, **kwargs))
    ok = bool(payload.get("ok"))
    print(f"{'PASS' if ok else 'FAIL'} {label}: {json.dumps(payload, ensure_ascii=False)[:300]}")
    return payload


def main() -> int:
    problems = 0

    headless = call("ghidra_headless_import", tools.ghidra_headless_import,
                    binary_paths=[BINARY], project_name=PROJECT, no_analysis=True,
                    timeout=900)
    if not headless.get("ok") or not headless.get("headless", {}).get("success"):
        problems += 1
        print(f"  exit_code={headless.get('headless', {}).get('exit_code')}")

    listing = call("ghidra_list_programs (from headless project)", tools.ghidra_list_programs,
                   PROJECT)
    names = [entry["name"] for entry in listing.get("programs", [])]
    if PROGRAM not in names:
        problems += 1
        print(f"  expected {PROGRAM} in {names}")

    opened = call("ghidra_open_program (PyGhidra reads headless project)",
                  tools.ghidra_open_program, project_name=PROJECT, program_name=PROGRAM,
                  analyze_if_needed=False)
    if not opened.get("ok"):
        problems += 1

    call("ghidra_close_program", tools.ghidra_close_program)

    print(json.dumps({"problems": problems}))
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
