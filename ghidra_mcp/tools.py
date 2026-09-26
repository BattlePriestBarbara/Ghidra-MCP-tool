"""MCP tool implementations.

Each function is registered as a Cline tool by server.py. Tools never raise: they
return a JSON string, and failures come back as {"ok": false, "error": ...} so the
model can read the reason and adapt.
"""
from __future__ import annotations

import json
from typing import Any

from . import config, headless, queries
from .session import GhidraError, SESSION


def _json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2, default=str)


def _error(exc: Exception) -> str:
    payload: dict[str, Any] = {
        "ok": False,
        "error": str(exc),
        "error_type": type(exc).__name__,
    }
    if not isinstance(exc, GhidraError):
        payload["hint"] = (
            "Unexpected failure. Run ghidra_environment to check the Ghidra/JDK setup."
        )
    return _json(payload)


def _ok(**payload: Any) -> str:
    return _json({"ok": True, **payload})


# --------------------------------------------------------------- environment
def ghidra_environment() -> str:
    """Report the Ghidra/JDK/Python setup, project store location and JVM state.

    Use this first to diagnose configuration problems (missing Ghidra, JDK < 21,
    non-ASCII paths, JVM not started yet).
    """
    try:
        return _ok(environment=SESSION.environment(), session=SESSION.status())
    except Exception as exc:  # noqa: BLE001
        return _error(exc)


def ghidra_session_status() -> str:
    """Show whether the JVM is running and which project/program is currently open."""
    try:
        return _ok(session=SESSION.status())
    except Exception as exc:  # noqa: BLE001
        return _error(exc)


# ------------------------------------------------------------ import / open
def ghidra_import_and_analyze(binary_path: str, project_name: str = "default",
                              program_name: str | None = None, analyze: bool = True,
                              timeout: int = 900, force_reimport: bool = False,
                              language: str | None = None) -> str:
    """Import a binary into a Ghidra project, auto-analyse it and open it for queries.

    Analysis of a large binary can take minutes; the result is cached in the Ghidra
    project (see ghidra_environment -> projects_dir), so later calls are instant.
    Re-importing is skipped unless force_reimport=True.

    Args:
        binary_path: Absolute path to the executable/dll/object to analyse.
        project_name: Ghidra project to store it in (created on demand).
        program_name: Name inside the project (defaults to the file name).
        analyze: Run Ghidra's auto-analysis after importing.
        timeout: Per-step timeout in seconds (import and analysis).
        force_reimport: Re-import even if the program already exists in the project.
        language: Optional Ghidra LanguageID (e.g. "x86:LE:64:default").
    """
    try:
        with SESSION.lock:
            summary = SESSION.ensure_program(
                binary_path=binary_path, project_name=project_name,
                program_name=program_name, analyze=analyze, timeout=timeout,
                force_reimport=force_reimport, language=language,
            )
            return _ok(**summary, project_location=str(config.projects_dir()))
    except Exception as exc:  # noqa: BLE001
        return _error(exc)


def ghidra_open_program(project_name: str = "default", program_name: str | None = None,
                        binary_path: str | None = None, analyze_if_needed: bool = True,
                        timeout: int = 900) -> str:
    """Open an already-imported program (fast path; no re-import, analysis only if needed).

    Args:
        project_name: Project that holds the program.
        program_name: Program name inside the project, e.g. "notepad.exe".
        binary_path: Optional path used only if the program still has to be imported.
        analyze_if_needed: Run auto-analysis if the program was never analysed.
        timeout: Analysis timeout in seconds.
    """
    try:
        with SESSION.lock:
            summary = SESSION.ensure_program(
                binary_path=binary_path, project_name=project_name,
                program_name=program_name, analyze=analyze_if_needed, timeout=timeout,
            )
            return _ok(**summary, summary=queries.program_summary(SESSION.require_program()))
    except Exception as exc:  # noqa: BLE001
        return _error(exc)


def ghidra_close_program() -> str:
    """Save and close the open program/project (the JVM stays warm for the next call)."""
    try:
        with SESSION.lock:
            return _ok(closed=SESSION.close())
    except Exception as exc:  # noqa: BLE001
        return _error(exc)


def ghidra_current_program() -> str:
    """Metadata of the currently open program (hashes, language, sizes, counts)."""
    try:
        with SESSION.lock:
            return _ok(program=queries.program_summary(SESSION.require_program()))
    except Exception as exc:  # noqa: BLE001
        return _error(exc)


def ghidra_list_projects() -> str:
    """List Ghidra projects in the server's project store."""
    try:
        return _ok(projects=SESSION.list_projects(),
                   project_location=str(config.projects_dir()))
    except Exception as exc:  # noqa: BLE001
        return _error(exc)


def ghidra_list_programs(project_name: str) -> str:
    """List the programs (imported binaries) inside a Ghidra project."""
    try:
        with SESSION.lock:
            return _ok(project=project_name, programs=SESSION.list_programs(project_name))
    except Exception as exc:  # noqa: BLE001
        return _error(exc)


# -------------------------------------------------------------- functions
def ghidra_list_functions(name_filter: str | None = None, limit: int = 100, offset: int = 0,
                          include_external: bool = False, include_thunks: bool = True) -> str:
    """List functions of the open program, optionally filtered by a name substring.

    Args:
        name_filter: Case-insensitive substring filter on the full function name.
        limit: Maximum number of functions to return.
        offset: Skip this many matches (paging).
        include_external: Include imported (external) functions.
        include_thunks: Include thunk functions.
    """
    try:
        with SESSION.lock:
            return _ok(**queries.list_functions(SESSION.require_program(), name_filter,
                                                limit, offset, include_external, include_thunks))
    except Exception as exc:  # noqa: BLE001
        return _error(exc)


def ghidra_function_details(name_or_address: str, include_xrefs: bool = True,
                            max_xrefs: int = 25, include_decompiled: bool = False,
                            decompile_timeout: int = 120) -> str:
    """Describe one function: signature, parameters, locals, callers/callees and xrefs.

    Args:
        name_or_address: Function name (e.g. "FUN_140001008"), "namespace::name" or an
            address such as "0x140001008".
        include_xrefs: Include references to the function entry point.
        max_xrefs: Cap for callers/callees/reference lists.
        include_decompiled: Also include the decompiled C code.
        decompile_timeout: Decompiler timeout in seconds.
    """
    try:
        with SESSION.lock:
            return _ok(function=queries.function_details(
                SESSION.require_program(), name_or_address, include_xrefs, max_xrefs,
                include_decompiled, decompile_timeout))
    except Exception as exc:  # noqa: BLE001
        return _error(exc)


def ghidra_decompile_function(name_or_address: str, timeout: int = 120,
                              max_chars: int = 20000) -> str:
    """Decompile one function to C-like pseudocode.

    Args:
        name_or_address: Function name or address (see ghidra_list_functions /
            ghidra_search_symbols).
        timeout: Decompiler timeout in seconds.
        max_chars: Truncate the pseudocode at this many characters.
    """
    try:
        with SESSION.lock:
            return _ok(**queries.decompile_function(SESSION.require_program(), name_or_address,
                                                    timeout, max_chars))
    except Exception as exc:  # noqa: BLE001
        return _error(exc)


def ghidra_search_symbols(query: str, limit: int = 50, case_sensitive: bool = False,
                          include_external: bool = True) -> str:
    """Search all symbols (functions, data, imports) for a substring."""
    try:
        with SESSION.lock:
            return _ok(**queries.search_symbols(SESSION.require_program(), query, limit,
                                                case_sensitive, include_external))
    except Exception as exc:  # noqa: BLE001
        return _error(exc)


def ghidra_disassemble(name_or_address: str, count: int = 32, offset: int = 0) -> str:
    """Disassemble instructions from an address or a function entry point.

    Args:
        name_or_address: Address ("0x140001008") or function name (starts at its entry).
        count: Number of instructions to return.
        offset: Skip this many instructions first.
    """
    try:
        with SESSION.lock:
            return _ok(**queries.disassemble(SESSION.require_program(), name_or_address,
                                             count, offset))
    except Exception as exc:  # noqa: BLE001
        return _error(exc)


def ghidra_xrefs(name_or_address: str, direction: str = "to", limit: int = 50) -> str:
    """Cross references of a function/address.

    Args:
        name_or_address: Function name or address.
        direction: "to" for incoming references (who calls/uses it), "from" for
            outgoing references (what this address references).
        limit: Maximum number of references to return.
    """
    try:
        with SESSION.lock:
            return _ok(**queries.xrefs(SESSION.require_program(), name_or_address,
                                       direction, limit))
    except Exception as exc:  # noqa: BLE001
        return _error(exc)


def ghidra_list_strings(min_length: int = 5, filter_text: str | None = None,
                        limit: int = 200, offset: int = 0) -> str:
    """List strings defined in the program (optionally filtered by substring)."""
    try:
        with SESSION.lock:
            return _ok(**queries.list_strings(SESSION.require_program(), min_length,
                                              filter_text, limit, offset))
    except Exception as exc:  # noqa: BLE001
        return _error(exc)


def ghidra_list_imports(filter_text: str | None = None, limit: int = 500) -> str:
    """List imported symbols (external functions) and the imported libraries."""
    try:
        with SESSION.lock:
            return _ok(**queries.list_imports(SESSION.require_program(), filter_text, limit))
    except Exception as exc:  # noqa: BLE001
        return _error(exc)


def ghidra_list_entry_points(limit: int = 200) -> str:
    """List the program's entry points (exports plus the executable entry)."""
    try:
        with SESSION.lock:
            return _ok(**queries.list_entry_points(SESSION.require_program(), limit))
    except Exception as exc:  # noqa: BLE001
        return _error(exc)


def ghidra_call_graph(name_or_address: str, limit: int = 50) -> str:
    """Show the callers and callees of one function."""
    try:
        with SESSION.lock:
            return _ok(**queries.call_graph(SESSION.require_program(), name_or_address, limit))
    except Exception as exc:  # noqa: BLE001
        return _error(exc)


def ghidra_read_bytes(address: str, length: int = 64) -> str:
    """Read raw bytes from program memory (hex plus ASCII dump)."""
    try:
        with SESSION.lock:
            return _ok(**queries.read_bytes(SESSION.require_program(), address, length))
    except Exception as exc:  # noqa: BLE001
        return _error(exc)


def ghidra_search_bytes(pattern: str, limit: int = 20, max_scan_mb: int = 8) -> str:
    """Search loaded memory for a byte pattern, e.g. "4C 8B DC" ("??" wildcards allowed)."""
    try:
        with SESSION.lock:
            return _ok(**queries.search_bytes(SESSION.require_program(), pattern, limit,
                                              max_scan_mb))
    except Exception as exc:  # noqa: BLE001
        return _error(exc)


def ghidra_list_data_types(query: str | None = None, limit: int = 200) -> str:
    """List data types (structs, enums, typedefs) known to the program."""
    try:
        with SESSION.lock:
            return _ok(**queries.list_data_types(SESSION.require_program(), query, limit))
    except Exception as exc:  # noqa: BLE001
        return _error(exc)


def ghidra_list_memory_blocks() -> str:
    """List memory blocks/segments with address ranges and permissions."""
    try:
        with SESSION.lock:
            return _ok(**queries.list_memory_blocks(SESSION.require_program()))
    except Exception as exc:  # noqa: BLE001
        return _error(exc)


# ---------------------------------------------------------------- headless
def ghidra_headless_import(binary_paths: list[str], project_name: str = "headless",
                           timeout: int = 1800, analysis_timeout_per_file: int | None = None,
                           post_scripts: list[str] | None = None,
                           pre_scripts: list[str] | None = None,
                           script_paths: list[str] | None = None,
                           processor: str | None = None, no_analysis: bool = False,
                           recursive: bool = False) -> str:
    """Import/analyse binaries with Ghidra's analyzeHeadless CLI (batch, separate process).

    Use this for batch imports or to reproduce Ghidra's own headless pipeline. The
    resulting project lands in the same project store, so ghidra_open_program can
    query it afterwards.

    Args:
        binary_paths: Files or directories to import.
        project_name: Project to create/fill.
        timeout: Hard timeout for the whole headless run (seconds).
        analysis_timeout_per_file: Passed as -analysisTimeoutPerFile.
        post_scripts / pre_scripts: Ghidra scripts to run after/before analysis.
        script_paths: Extra directories to search for those scripts.
        processor: Optional -processor language id.
        no_analysis: Pass -noanalysis (import only, no auto-analysis).
        recursive: Pass -recursive (import directories recursively).
    """
    try:
        return _ok(headless=headless.headless_import(
            binary_paths=binary_paths, project_name=project_name, timeout=timeout,
            analysis_timeout_per_file=analysis_timeout_per_file, post_scripts=post_scripts,
            pre_scripts=pre_scripts, script_paths=script_paths, processor=processor,
            no_analysis=no_analysis, recursive=recursive,
        ))
    except Exception as exc:  # noqa: BLE001
        return _error(exc)
