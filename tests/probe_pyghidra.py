"""Standalone probe: does PyGhidra import/analyze/decompile work on this machine?

Run with the project venv (from an ASCII install directory, see README):
    .\.venv\Scripts\python.exe tests\probe_pyghidra.py [binary]

Progress goes to stderr, the JSON result to stdout, so this also verifies that
nothing leaks into the MCP stdout stream before the transport claims fd 1.
"""
from __future__ import annotations

import json
import os
import sys
import time

GHIDRA_INSTALL_DIR = os.environ.get("GHIDRA_INSTALL_DIR", r"D:\ghidra_12.1.3_PUBLIC")
JAVA_HOME = os.environ.get("JAVA_HOME", r"D:\nd")
PROJECT_DIR = os.environ.get("PROBE_PROJECT_DIR", r"D:\ghidra-mcp\projects")
BINARY = sys.argv[1] if len(sys.argv) > 1 else r"C:\Windows\System32\notepad.exe"

os.environ["GHIDRA_INSTALL_DIR"] = GHIDRA_INSTALL_DIR
os.environ["JAVA_HOME"] = JAVA_HOME


def log(msg: str) -> None:
    print(f"[probe] {msg}", file=sys.stderr, flush=True)


def main() -> int:
    result: dict = {"ghidra_install_dir": GHIDRA_INSTALL_DIR, "java_home": JAVA_HOME, "binary": BINARY}
    t0 = time.time()
    import pyghidra

    log(f"pyghidra {pyghidra.__version__} imported")
    pyghidra.start()
    result["jvm_start_seconds"] = round(time.time() - t0, 1)
    log(f"JVM up in {result['jvm_start_seconds']}s")

    # Route Java's System.out to stderr: keep stdout clean for the MCP transport.
    from java.io import FileDescriptor, FileOutputStream, PrintStream
    from java.lang import System as JSystem

    JSystem.setOut(PrintStream(FileOutputStream(FileDescriptor.err)))

    os.makedirs(PROJECT_DIR, exist_ok=True)
    project = pyghidra.open_project(PROJECT_DIR, "probe", create=True)

    program_path = "/" + os.path.basename(BINARY)
    if project.getProjectData().getFile(program_path) is None:
        t1 = time.time()
        loader = (
            pyghidra.program_loader()
            .project(project)
            .source(BINARY)
            .name(os.path.basename(BINARY))
        )
        with loader.load() as load_results:
            load_results.save(pyghidra.task_monitor(300))
        result["import_seconds"] = round(time.time() - t1, 1)
        log(f"imported in {result['import_seconds']}s")

    program, consumer = pyghidra.consume_program(project, program_path)
    try:
        from ghidra.program.util import GhidraProgramUtilities

        if GhidraProgramUtilities.shouldAskToAnalyze(program):
            t2 = time.time()
            pyghidra.analyze(program, pyghidra.task_monitor(900))
            program.save("Analyzed", pyghidra.task_monitor(300))
            result["analyze_seconds"] = round(time.time() - t2, 1)
            log(f"analyzed in {result['analyze_seconds']}s")

        result["program_name"] = program.getName()
        result["language"] = program.getLanguageID().toString()
        result["compiler"] = program.getCompilerSpec().getCompilerSpecID().toString()
        result["md5"] = program.getExecutableMD5()
        result["image_base"] = program.getImageBase().toString()
        result["function_count"] = program.getFunctionManager().getFunctionCount()
        result["symbol_count"] = program.getSymbolTable().getNumSymbols()
        log(f"functions={result['function_count']} symbols={result['symbol_count']}")

        # Decompile one function (prefer "entry")
        from ghidra.app.decompiler import DecompInterface

        funcs = list(program.getFunctionManager().getFunctions(True))
        target = next((f for f in funcs if f.getName() == "entry"), funcs[0] if funcs else None)
        if target is not None:
            ifc = DecompInterface()
            ifc.openProgram(program)
            try:
                res = ifc.decompileFunction(target, 60, pyghidra.task_monitor(120))
                result["decompiled_function"] = target.getName()
                result["decompile_ok"] = bool(res.decompileCompleted())
                text = res.getDecompiledFunction().getC() if res.decompileCompleted() else res.getErrorMessage()
                result["decompile_chars"] = len(text or "")
                result["decompile_head"] = (text or "")[:200]
            finally:
                ifc.dispose()
    finally:
        program.release(consumer)

    project.close()
    result["ok"] = True
    log("done")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001 - probe reports the raw failure
        import traceback

        traceback.print_exc(file=sys.stderr)
        print(json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"}, indent=2))
        raise SystemExit(1)
