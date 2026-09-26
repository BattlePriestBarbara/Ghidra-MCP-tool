"""Probe: can the ORIGINAL file (and therefore its hash) be recovered from the Ghidra project?

Note: the file name deliberately does NOT start with "ghidra" - PyGhidra's import hook
intercepts modules whose name begins with "ghidra", which makes such a script recurse
inside find_spec ("maximum recursion depth exceeded").

    .\\.venv\\Scripts\\python.exe tests\\probe_original_export.py
"""
from __future__ import annotations

import hashlib
import os
import sys

os.environ.setdefault("GHIDRA_INSTALL_DIR", r"D:\ghidra_12.1.3_PUBLIC")
PROJECT_DIR = r"D:\ghidra-mcp\projects"
PROJECT_NAME = sys.argv[1] if len(sys.argv) > 1 else "weka"
PROGRAM = sys.argv[2] if len(sys.argv) > 2 else "/uninstall.exe"


def main() -> int:
    import pyghidra

    pyghidra.start()

    from java.io import File, FileDescriptor, FileOutputStream, PrintStream
    from java.lang import System as JSystem

    JSystem.setOut(PrintStream(FileOutputStream(FileDescriptor.err)))

    project = pyghidra.open_project(PROJECT_DIR, PROJECT_NAME, create=False)
    program, consumer = pyghidra.consume_program(project, PROGRAM)
    try:
        # ghidra.* imports must happen inside a function, after the JVM is up.
        from ghidra.app.util.exporter import OriginalFileExporter
        from ghidra.program.model.address import AddressSet
        from ghidra.util.task import TaskMonitor

        print(f"stored MD5 in program DB : {program.getExecutableMD5()}", file=sys.stderr)
        print(f"stored sha256 in DB      : {program.getExecutableSHA256()}", file=sys.stderr)
        print(f"original import path     : {program.getExecutablePath()}", file=sys.stderr)
        print(f"executable format        : {program.getExecutableFormat()}", file=sys.stderr)

        out_path = os.path.join(os.environ.get("TEMP", "."), "uninstall_from_ghidra.exe")
        exporter = OriginalFileExporter()
        address_set = AddressSet(program.getMinAddress(), program.getMaxAddress())
        ok = bool(exporter.export(File(out_path), program, address_set, TaskMonitor.DUMMY))
        print(f"OriginalFileExporter.export -> {ok} : {out_path}", file=sys.stderr)

        if ok and os.path.isfile(out_path):
            data = open(out_path, "rb").read()
            print(f"exported size   : {len(data)}", file=sys.stderr)
            print(f"exported md5    : {hashlib.md5(data).hexdigest()}", file=sys.stderr)
            print(f"exported sha256 : {hashlib.sha256(data).hexdigest()}", file=sys.stderr)
            print(f"md5 matches JSON: "
                  f"{hashlib.md5(data).hexdigest() == '59d3469678498a4ece87c7789cd0c74f'}",
                  file=sys.stderr)
        else:
            print("no original bytes were stored in this project", file=sys.stderr)
    finally:
        program.release(consumer)
        project.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
