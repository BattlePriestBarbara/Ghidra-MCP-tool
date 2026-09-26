"""End-to-end test: talk to the MCP server exactly like Cline does (stdio transport).

    .\\.venv\\Scripts\\python.exe tests\\smoke_mcp_client.py [project] [program]

It spawns server.py, performs the MCP handshake, lists the tools and calls a few of
them, so it verifies the JSON-RPC stream is clean (no JVM/Java output leaking into it).
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parent.parent
SERVER = ROOT / "server.py"
PYTHON = ROOT / ".venv" / "Scripts" / "python.exe"
PROJECT = sys.argv[1] if len(sys.argv) > 1 else "probe"
PROGRAM = sys.argv[2] if len(sys.argv) > 2 else "notepad.exe"


def text_of(result) -> str:
    chunks = []
    for block in getattr(result, "content", []) or []:
        text = getattr(block, "text", None)
        if text:
            chunks.append(text)
    return "".join(chunks)


async def main() -> int:
    python = str(PYTHON if PYTHON.is_file() else Path(sys.executable))
    parameters = StdioServerParameters(command=python, args=[str(SERVER)], cwd=str(ROOT))
    problems = 0

    async with stdio_client(parameters) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            info = await session.initialize()
            print(f"server: {info.server_info.name} {info.server_info.version}")
            print(f"protocol: {info.protocol_version}")

            listing = await session.list_tools()
            names = [tool.name for tool in listing.tools]
            print(f"tools ({len(names)}): {', '.join(names)}")
            expected = {
                "ghidra_environment", "ghidra_import_and_analyze", "ghidra_open_program",
                "ghidra_list_functions", "ghidra_decompile_function", "ghidra_search_symbols",
                "ghidra_function_details", "ghidra_list_strings", "ghidra_list_imports",
                "ghidra_xrefs", "ghidra_disassemble", "ghidra_read_bytes",
                "ghidra_search_bytes", "ghidra_list_data_types", "ghidra_list_memory_blocks",
                "ghidra_headless_import", "ghidra_call_graph", "ghidra_list_programs",
                "ghidra_list_projects", "ghidra_current_program", "ghidra_close_program",
                "ghidra_session_status", "ghidra_list_entry_points",
            }
            missing = expected - set(names)
            if missing:
                problems += 1
                print(f"FAIL missing tools: {sorted(missing)}")

            calls = [
                ("ghidra_environment", {}),
                ("ghidra_open_program", {"project_name": PROJECT, "program_name": PROGRAM}),
                ("ghidra_list_functions", {"name_filter": "entry", "limit": 3}),
                ("ghidra_decompile_function", {"name_or_address": "entry", "max_chars": 400}),
                ("ghidra_list_memory_blocks", {}),
                ("ghidra_close_program", {}),
            ]
            for name, arguments in calls:
                result = await session.call_tool(name, arguments)
                payload_text = text_of(result)
                try:
                    payload = json.loads(payload_text)
                    ok = bool(payload.get("ok"))
                except json.JSONDecodeError:
                    ok, payload = False, {"raw": payload_text[:200]}
                if not ok:
                    problems += 1
                detail = json.dumps(payload, ensure_ascii=False)[:160]
                print(f"{'PASS' if ok else 'FAIL'} {name}: {detail}")

    print(json.dumps({"problems": problems}))
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
