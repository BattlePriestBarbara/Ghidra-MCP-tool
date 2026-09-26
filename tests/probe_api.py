"""Probe every Ghidra Java API used by the MCP server against an analyzed program.

Every API call is exercised in isolation so a wrong signature shows up as a
single FAIL entry instead of breaking the server. Run:

    .\.venv\Scripts\python.exe tests\probe_api.py
"""
from __future__ import annotations

import json
import os
import sys

GHIDRA_INSTALL_DIR = os.environ.get("GHIDRA_INSTALL_DIR", r"D:\ghidra_12.1.3_PUBLIC")
PROJECT_DIR = os.environ.get("PROBE_PROJECT_DIR", r"D:\ghidra-mcp\projects")
PROJECT_NAME = os.environ.get("PROBE_PROJECT_NAME", "probe")
PROGRAM_PATH = os.environ.get("PROBE_PROGRAM", "/notepad.exe")

os.environ["GHIDRA_INSTALL_DIR"] = GHIDRA_INSTALL_DIR

results: list[dict] = []


def check(name: str, fn) -> object:
    try:
        value = fn()
        results.append({"api": name, "ok": True, "sample": repr(value)[:160]})
        return value
    except Exception as exc:  # noqa: BLE001
        results.append({"api": name, "ok": False, "error": f"{type(exc).__name__}: {exc}"})
        return None


def _signed(values):
    """Java bytes are signed; 0xFF must be passed as -1."""
    return [v - 256 if v > 127 else v for v in values]


def main() -> int:
    import pyghidra

    pyghidra.start()
    from java.io import FileDescriptor, FileOutputStream, PrintStream
    from java.lang import System as JSystem

    JSystem.setOut(PrintStream(FileOutputStream(FileDescriptor.err)))

    project = pyghidra.open_project(PROJECT_DIR, PROJECT_NAME, create=False)
    program, consumer = pyghidra.consume_program(project, PROGRAM_PATH)
    monitor = pyghidra.task_monitor(120)

    try:
        # --- program metadata -------------------------------------------------
        check("program.getName", lambda: program.getName())
        check("program.getExecutableMD5", lambda: program.getExecutableMD5())
        check("program.getExecutableSHA256", lambda: program.getExecutableSHA256())
        check("program.getLanguageID().toString", lambda: program.getLanguageID().toString())
        check("program.getCompilerSpec().getCompilerSpecID().toString",
              lambda: program.getCompilerSpec().getCompilerSpecID().toString())
        check("program.getImageBase", lambda: program.getImageBase().toString())
        check("program.getMinAddress", lambda: program.getMinAddress().toString())
        check("program.getMaxAddress", lambda: program.getMaxAddress().toString())
        check("program.getExecutablePath", lambda: program.getExecutablePath())
        check("SymbolTable external entry points",
              lambda: len(list(program.getSymbolTable().getExternalEntryPointIterator())))
        check("program.getExecutableFormat", lambda: str(program.getExecutableFormat()))

        # --- functions --------------------------------------------------------
        fm = program.getFunctionManager()
        check("FunctionManager.getFunctionCount", lambda: fm.getFunctionCount())
        check("FunctionManager.getFunctions(True) first 3",
              lambda: [f.getName() for f in list(fm.getFunctions(True))[:3]])
        check("FunctionManager.getFunctions(False) count",
              lambda: len(list(fm.getFunctions(False))))
        first = None
        for f in fm.getFunctions(True):
            first = f
            break
        check("func.getEntryPoint", lambda: first.getEntryPoint().toString())
        check("func.getName", lambda: first.getName())
        check("func.getName(True)", lambda: first.getName(True))
        check("func.getPrototypeString(True,False)", lambda: first.getPrototypeString(True, False))
        check("func.getSignature(True)", lambda: str(first.getSignature(True)))
        check("func.getReturnType().getName", lambda: first.getReturnType().getName())
        check("func.getParentNamespace().getName(True)",
              lambda: first.getParentNamespace().getName(True))
        check("func.getParameters", lambda: [
            f"{p.getDataType().getName()} {p.getName()}" for p in first.getParameters()])
        check("func.getLocalVariables", lambda: [
            f"{v.getDataType().getName()} {v.getName()}" for v in first.getLocalVariables()])
        check("func.getBody().getNumAddresses", lambda: first.getBody().getNumAddresses())
        check("func.getCallingConventionName", lambda: first.getCallingConventionName())
        check("func.isThunk", lambda: first.isThunk())
        check("func.isExternal", lambda: first.isExternal())
        check("func.getComment()", lambda: first.getComment())
        check("func.getRepeatableComment()", lambda: first.getRepeatableComment())
        check("fm.getFunctionAt(first.entry)", lambda: fm.getFunctionAt(first.getEntryPoint()).getName())
        check("fm.getFunctionContaining(first.entry)",
              lambda: fm.getFunctionContaining(first.getEntryPoint()).getName())
        check("func.getCalledFunctions(monitor)",
              lambda: [f.getName() for f in list(first.getCalledFunctions(monitor))[:3]])
        check("func.getCallingFunctions(monitor)",
              lambda: [f.getName() for f in list(first.getCallingFunctions(monitor))[:3]])
    finally:
        pass

    return _rest(program, consumer, project, monitor, first)


def _rest(program, consumer, project, monitor, first):
    """Symbols, strings, memory, references and instructions."""
    try:
        # --- symbols ----------------------------------------------------------
        symtab = program.getSymbolTable()
        check("SymbolTable.getNumSymbols", lambda: symtab.getNumSymbols())
        check("SymbolTable.getAllSymbols(True)",
              lambda: [s.getName(True) for s in list(symtab.getAllSymbols(True))[:3]])
        check("SymbolTable.getSymbols(name)",
              lambda: [s.getAddress().toString() for s in list(symtab.getSymbols("entry"))])
        check("SymbolTable.getExternalSymbols",
              lambda: [s.getName(True) for s in list(symtab.getExternalSymbols())[:3]])
        check("SymbolTable.getExternalEntryPointIterator",
              lambda: [a.toString() for a in list(symtab.getExternalEntryPointIterator())[:3]])
        check("SymbolTable.getGlobalSymbols",
              lambda: [s.getName() for s in list(symtab.getGlobalSymbols("entry"))[:2]])
        check("ExternalManager.getExternalLibraryNames",
              lambda: [str(n) for n in list(program.getExternalManager().getExternalLibraryNames())[:3]])
        check("Symbol.isExternalEntryPoint",
              lambda: bool(list(symtab.getSymbols("entry"))[0].isExternalEntryPoint()))

        # --- strings / data ---------------------------------------------------
        listing = program.getListing()
        check("Listing.getNumDefinedData", lambda: listing.getNumDefinedData())

        def first_strings():
            out = []
            for d in listing.getDefinedData(True):
                if d.hasStringValue():
                    out.append((d.getAddress().toString(), str(d.getValue())[:40]))
                if len(out) >= 3:
                    break
            return out

        check("Data.hasStringValue", first_strings)
        check("DataTypeManager.getAllDataTypes count",
              lambda: len(list(program.getDataTypeManager().getAllDataTypes())))
        check("DataTypeManager.getAllDataTypes",
              lambda: [dt.getName() for dt in list(program.getDataTypeManager().getAllDataTypes())[:3]])

        # --- memory -----------------------------------------------------------
        mem = program.getMemory()
        check("Memory.getBlocks", lambda: [
            (b.getName(), b.getStart().toString(), b.getEnd().toString(), str(b.getSize()),
             b.isInitialized(), b.isRead(), b.isWrite(), b.isExecute())
            for b in list(mem.getBlocks())[:2]])
        check("Memory.getNumAddresses", lambda: mem.getNumAddresses())

        def read_bytes():
            from jpype import JArray, JByte

            buf = JArray(JByte)(16)
            mem.getBytes(program.getMinAddress(), buf)
            return bytes(bytearray(buf)).hex()

        check("Memory.getBytes(JArray(JByte))", read_bytes)

        def find_bytes():
            from jpype import JArray, JByte

            pattern = JArray(JByte)(_signed([0x4C, 0x8B, 0xDC]))
            mask = JArray(JByte)(_signed([0xFF, 0xFF, 0xFF]))
            hit = mem.findBytes(program.getMinAddress(), pattern, mask, True, monitor)
            return None if hit is None else hit.toString()

        check("Memory.findBytes(addr,byte[],byte[],bool,monitor)", find_bytes)

        # --- references -------------------------------------------------------
        refmgr = program.getReferenceManager()
        entry = first.getEntryPoint()
        check("ReferenceManager.getReferencesTo",
              lambda: [(r.getFromAddress().toString(), str(r.getReferenceType()))
                       for r in list(refmgr.getReferencesTo(entry))[:2]])
        check("ReferenceManager.getReferenceIterator",
              lambda: [(r.getToAddress().toString(), str(r.getReferenceType()))
                       for r in list(refmgr.getReferenceIterator(entry))[:2]])
        check("ReferenceManager.getReferenceCountTo",
              lambda: refmgr.getReferenceCountTo(entry))
        check("ReferenceManager.getReferenceCountFrom",
              lambda: refmgr.getReferenceCountFrom(entry))

        # --- instructions -----------------------------------------------------
        check("Listing.getInstructions(addr,True)",
              lambda: [i.toString() for i in list(listing.getInstructions(entry, True))[:3]])
        check("Listing.getInstructionAt",
              lambda: listing.getInstructionAt(entry).getMnemonicString())
        return _decompiler(program, consumer, project, monitor, first)
    except Exception as exc:  # noqa: BLE001
        check("_rest raised", lambda: (_ for _ in ()).throw(exc))
        return _report(program, consumer, project)


def _decompiler(program, consumer, project, monitor, first):
    """Decompiler interface checks."""
    from ghidra.app.decompiler import DecompileOptions, DecompInterface

    ifc = DecompInterface()
    check("DecompInterface.setOptions", lambda: ifc.setOptions(DecompileOptions()) or "ok")
    check("DecompInterface.openProgram", lambda: ifc.openProgram(program) or "ok")
    res = check("DecompInterface.decompileFunction",
                lambda: ifc.decompileFunction(first, 60, monitor))
    if res is not None:
        check("DecompileResults.decompileCompleted", lambda: res.decompileCompleted())
        check("DecompileResults.getErrorMessage", lambda: res.getErrorMessage())
        df = check("DecompileResults.getDecompiledFunction", lambda: res.getDecompiledFunction())
        if df is not None:
            check("DecompiledFunction.getC", lambda: df.getC()[:120])
            check("DecompiledFunction.getSignature", lambda: df.getSignature())
        check("DecompileResults.getHighFunction",
              lambda: str(res.getHighFunction().getFunctionPrototype()))
    check("DecompInterface.dispose", lambda: ifc.dispose() or "ok")
    return _report(program, consumer, project)


def _report(program, consumer, project):
    """Release Ghidra resources and print the results."""
    try:
        program.release(consumer)
    finally:
        project.close()

    failures = [r for r in results if not r["ok"]]
    print(json.dumps({"total": len(results), "failure_count": len(failures),
                      "failures": failures}, indent=2, ensure_ascii=False))
    for r in results:
        status = "OK  " if r["ok"] else "FAIL"
        detail = r.get("sample") if r["ok"] else r.get("error")
        print(f"{status} {r['api']} -> {detail}", file=sys.stderr)
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
