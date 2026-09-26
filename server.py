"""MCP server entry point for Cline.

Run:  .\\.venv\\Scripts\\python.exe server.py            (stdio transport, used by Cline)
      .\\.venv\\Scripts\\python.exe server.py --check     (print the environment report)
      .\\.venv\\Scripts\\python.exe server.py --tools     (list the exposed tools)
"""
from __future__ import annotations

import json
import sys

from mcp.server.mcpserver import MCPServer

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))

from ghidra_mcp import __version__, tools  # noqa: E402
from ghidra_mcp.session import SESSION  # noqa: E402

INSTRUCTIONS = """\
Ghidra reverse-engineering tools (PyGhidra, headless). Typical workflow:

1. ghidra_environment - verify the Ghidra install, JDK (>= 21) and project store.
2. ghidra_import_and_analyze(binary_path=...) - import + auto-analyse + open a binary.
   Analysis can take minutes on large binaries; results are cached in the Ghidra
   project, so later calls are instant.
3. Query the open program:
   ghidra_current_program, ghidra_list_functions, ghidra_search_symbols,
   ghidra_function_details, ghidra_decompile_function, ghidra_xrefs, ghidra_call_graph,
   ghidra_disassemble, ghidra_list_strings, ghidra_list_imports, ghidra_read_bytes,
   ghidra_search_bytes, ghidra_list_data_types, ghidra_list_memory_blocks.
4. ghidra_open_program(project_name, program_name) - reopen an already analysed program.
   ghidra_list_projects / ghidra_list_programs - see what is stored.

Notes:
- Function arguments accept a name (FUN_140001008, "kernel32.dll::CreateFileW") or an
  address like 0x140001008; addresses are printed as 0x-prefixed hex.
- The JVM is started lazily on the first Ghidra call (~10 s) and stays warm while the
  server runs; one program is kept open at a time.
- ghidra_headless_import runs Ghidra's analyzeHeadless CLI for batch imports or when a
  separate process is preferable; its project can be opened with ghidra_open_program.
"""

#: Tools registered with Cline, in the order they are shown.
TOOL_FUNCTIONS = (
    tools.ghidra_environment,
    tools.ghidra_session_status,
    tools.ghidra_import_and_analyze,
    tools.ghidra_open_program,
    tools.ghidra_current_program,
    tools.ghidra_close_program,
    tools.ghidra_list_projects,
    tools.ghidra_list_programs,
    tools.ghidra_list_functions,
    tools.ghidra_function_details,
    tools.ghidra_decompile_function,
    tools.ghidra_search_symbols,
    tools.ghidra_call_graph,
    tools.ghidra_disassemble,
    tools.ghidra_xrefs,
    tools.ghidra_list_strings,
    tools.ghidra_list_imports,
    tools.ghidra_list_entry_points,
    tools.ghidra_read_bytes,
    tools.ghidra_search_bytes,
    tools.ghidra_list_data_types,
    tools.ghidra_list_memory_blocks,
    tools.ghidra_headless_import,
)


def build_server() -> MCPServer:
    """Creates the MCPServer with every Ghidra tool registered."""
    server = MCPServer(
        name="ghidra",
        title="Ghidra reverse engineering",
        version=__version__,
        instructions=INSTRUCTIONS,
    )
    for function in TOOL_FUNCTIONS:
        server.add_tool(function)
    return server


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    if "--check" in argv:
        print(json.dumps(SESSION.environment(), indent=2, ensure_ascii=False, default=str))
        problems = SESSION.environment().get("non_ascii_path_problems") or []
        return 1 if problems else 0

    if "--tools" in argv:
        for function in TOOL_FUNCTIONS:
            print(f"{function.__name__}: {(function.__doc__ or '').strip().splitlines()[0]}")
        return 0

    server = build_server()
    try:
        server.run(transport="stdio")
    finally:
        try:
            SESSION.close()
        except Exception:  # noqa: BLE001 - shutting down anyway
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
