"""Program introspection helpers built on the Ghidra Java API.

Every Java call used here was verified against Ghidra 12.1.3 by tests/probe_api.py.
Functions take an open Ghidra `Program` and return plain JSON-serialisable data.
"""
from __future__ import annotations

from typing import Any, Iterable

from .session import GhidraError, SESSION

#: Reused decompiler interface; Ghidra decompiler setup is expensive.
_DECOMPILER: dict[str, Any] = {"program": None, "interface": None}


def _hex(address) -> str:
    return f"0x{address.toString()}" if address is not None else ""


def _function_prototype(func) -> str:
    """Function signature; getPrototypeString(bool, bool) is the supported overload."""
    try:
        return str(func.getPrototypeString(True, False))
    except Exception:  # noqa: BLE001
        try:
            return str(func.getSignature(True))
        except Exception:  # noqa: BLE001
            return str(func.getName(True))


def _symbol_name_at(program, address) -> str | None:
    """Best-effort symbol name at an address (primary symbol first)."""
    try:
        symbol = program.getSymbolTable().getPrimarySymbol(address)
        if symbol is not None:
            return str(symbol.getName(True))
    except Exception:  # noqa: BLE001
        pass
    try:
        func = program.getFunctionManager().getFunctionAt(address)
        if func is not None:
            return str(func.getName(True))
    except Exception:  # noqa: BLE001
        pass
    return None


def resolve_address(program, text: str):
    """Parses '0x140001008', '140001008' or a symbol name into a Ghidra address."""
    if text is None:
        return None
    candidate = str(text).strip()
    if not candidate:
        return None
    factory = program.getAddressFactory()
    variants = [candidate] if candidate.lower().startswith("0x") else [candidate, "0x" + candidate]
    for variant in variants:
        try:
            address = factory.getAddress(variant)
        except Exception:  # noqa: BLE001 - AddressFormatException on bad input
            address = None
        if address is not None:
            return address
    for name in (candidate, candidate.split("::")[-1]):
        try:
            for symbol in program.getSymbolTable().getSymbols(name):
                return symbol.getAddress()
        except Exception:  # noqa: BLE001
            continue
    return None


def resolve_function(program, text: str, allow_fuzzy: bool = True):
    """Finds a Ghidra Function by address, symbol name or (optionally) substring."""
    if text is None:
        raise GhidraError("a function name or address is required")
    candidate = str(text).strip().rstrip("()")
    manager = program.getFunctionManager()

    address = resolve_address(program, candidate)
    if address is not None:
        for lookup in (manager.getFunctionAt, manager.getFunctionContaining):
            try:
                func = lookup(address)
            except Exception:  # noqa: BLE001
                func = None
            if func is not None:
                return func

    for name in (candidate, candidate.split("::")[-1]):
        try:
            symbols = program.getSymbolTable().getSymbols(name)
        except Exception:  # noqa: BLE001
            symbols = []
        for entry in symbols:
            func = manager.getFunctionAt(entry.getAddress())
            if func is not None:
                return func

    if allow_fuzzy:
        lowered = candidate.lower()
        fallback = None
        for func in manager.getFunctions(True):
            full = str(func.getName(True))
            if full.lower() == lowered or str(func.getName()).lower() == lowered:
                return func
            if fallback is None and lowered in full.lower():
                fallback = func
        if fallback is not None:
            return fallback
        for func in manager.getFunctions(False):
            if lowered in str(func.getName(True)).lower():
                return func

    raise GhidraError(
        f"function '{text}' not found. Use ghidra_list_functions or ghidra_search_symbols "
        f"to find candidate names, or pass an address such as 0x140001008."
    )


def _function_brief(func) -> dict[str, Any]:
    try:
        size = int(func.getBody().getNumAddresses())
    except Exception:  # noqa: BLE001
        size = None
    return {
        "name": str(func.getName()),
        "full_name": str(func.getName(True)),
        "namespace": str(func.getParentNamespace().getName(True)),
        "entry": _hex(func.getEntryPoint()),
        "size_bytes": size,
        "signature": _function_prototype(func),
        "is_external": bool(func.isExternal()),
        "is_thunk": bool(func.isThunk()),
    }


def _function_page(functions: Iterable, offset: int, limit: int, name_filter: str | None,
                   include_external: bool, include_thunks: bool) -> list[dict[str, Any]]:
    lowered = name_filter.lower() if name_filter else None
    page: list[dict[str, Any]] = []
    seen = 0
    for func in functions:
        if not include_external and bool(func.isExternal()):
            continue
        if not include_thunks and bool(func.isThunk()):
            continue
        full_name = str(func.getName(True))
        if lowered and lowered not in full_name.lower():
            continue
        if seen < offset:
            seen += 1
            continue
        if len(page) >= limit:
            break
        page.append(_function_brief(func))
    return page


def list_functions(program, name_filter: str | None = None, limit: int = 100, offset: int = 0,
                   include_external: bool = False, include_thunks: bool = True,
                   include_undefined: bool = False) -> dict[str, Any]:
    """Lists functions in the program (paged, optional name substring filter)."""
    manager = program.getFunctionManager()
    entries = _function_page(manager.getFunctions(True), offset, limit, name_filter,
                             include_external, include_thunks)
    if not include_undefined:
        entries = [entry for entry in entries if entry["name"] != "undefined"]
    return {
        "total_functions": int(manager.getFunctionCount()),
        "returned": len(entries),
        "offset": offset,
        "name_filter": name_filter,
        "functions": entries,
    }


def _decompiler_for(program):
    """Returns a DecompInterface bound to the given program (cached)."""
    if _DECOMPILER["program"] is program and _DECOMPILER["interface"] is not None:
        return _DECOMPILER["interface"]

    from ghidra.app.decompiler import DecompInterface, DecompileOptions

    if _DECOMPILER["interface"] is not None:
        try:
            _DECOMPILER["interface"].dispose()
        except Exception:  # noqa: BLE001
            pass
    interface = DecompInterface()
    interface.setOptions(DecompileOptions())
    interface.openProgram(program)
    _DECOMPILER["program"] = program
    _DECOMPILER["interface"] = interface
    return interface


def decompile_function(program, name_or_address: str, timeout: int = 120,
                       max_chars: int = 20000) -> dict[str, Any]:
    """Decompiles a single function to C-like pseudocode."""
    func = resolve_function(program, name_or_address)
    monitor = SESSION.task_monitor(timeout)
    decompiler = _decompiler_for(program)
    results = decompiler.decompileFunction(func, timeout, monitor)
    completed = bool(results.decompileCompleted())
    if not completed:
        return {
            "function": str(func.getName(True)),
            "entry": _hex(func.getEntryPoint()),
            "signature": _function_prototype(func),
            "decompile_completed": False,
            "error": str(results.getErrorMessage()),
        }
    high_function = results.getDecompiledFunction()
    text = str(high_function.getC())
    truncated = len(text) > max_chars
    return {
        "function": str(func.getName(True)),
        "entry": _hex(func.getEntryPoint()),
        "signature": str(high_function.getSignature()),
        "decompile_completed": True,
        "truncated": truncated,
        "length": len(text),
        "code": text[:max_chars],
    }


def function_details(program, name_or_address: str, include_xrefs: bool = True,
                     max_xrefs: int = 25, include_decompiled: bool = False,
                     decompile_timeout: int = 120) -> dict[str, Any]:
    """Full description of one function: signature, variables, callers/callees, xrefs."""
    func = resolve_function(program, name_or_address)
    detail = _function_brief(func)
    detail["calling_convention"] = str(func.getCallingConventionName())
    try:
        detail["return_type"] = str(func.getReturnType().getName())
    except Exception:  # noqa: BLE001
        detail["return_type"] = None
    detail["parameters"] = []
    try:
        for parameter in func.getParameters():
            detail["parameters"].append({
                "name": str(parameter.getName()),
                "type": str(parameter.getDataType().getName()),
            })
    except Exception:  # noqa: BLE001
        pass
    detail["local_variables"] = []
    try:
        for variable in func.getLocalVariables():
            detail["local_variables"].append({
                "name": str(variable.getName()),
                "type": str(variable.getDataType().getName()),
            })
    except Exception:  # noqa: BLE001
        pass
    detail["comment"] = str(func.getComment()) if func.getComment() else None
    detail["repeatable_comment"] = (
        str(func.getRepeatableComment()) if func.getRepeatableComment() else None
    )

    monitor = SESSION.task_monitor(120)
    try:
        detail["called_functions"] = [
            str(callee.getName(True)) for callee in list(func.getCalledFunctions(monitor))[:max_xrefs]
        ]
    except Exception:  # noqa: BLE001
        detail["called_functions"] = []
    try:
        detail["calling_functions"] = [
            str(caller.getName(True)) for caller in list(func.getCallingFunctions(monitor))[:max_xrefs]
        ]
    except Exception:  # noqa: BLE001
        detail["calling_functions"] = []

    if include_xrefs:
        detail["xrefs"] = xrefs(program, detail["entry"], direction="to", limit=max_xrefs)
    if include_decompiled:
        detail["decompiled"] = decompile_function(program, detail["entry"],
                                                  timeout=decompile_timeout)
    return detail


def search_symbols(program, query: str, limit: int = 50, case_sensitive: bool = False,
                   include_external: bool = True) -> dict[str, Any]:
    """Substring search over every symbol in the program."""
    needle = query if case_sensitive else query.lower()
    matches: list[dict[str, Any]] = []
    for symbol in program.getSymbolTable().getAllSymbols(True):
        is_external = bool(symbol.isExternal())
        if is_external and not include_external:
            continue
        name = str(symbol.getName(True))
        haystack = name if case_sensitive else name.lower()
        if needle not in haystack:
            continue
        matches.append({
            "name": name,
            "address": _hex(symbol.getAddress()),
            "type": str(symbol.getSymbolType()),
            "external": is_external,
        })
        if len(matches) >= limit:
            break
    return {"query": query, "returned": len(matches), "symbols": matches}


def list_strings(program, min_length: int = 5, filter_text: str | None = None, limit: int = 200,
                 offset: int = 0) -> dict[str, Any]:
    """Defined string data in the program."""
    needle = filter_text.lower() if filter_text else None
    strings: list[dict[str, Any]] = []
    seen = 0
    matched = 0
    for data in program.getListing().getDefinedData(True):
        try:
            if not data.hasStringValue():
                continue
            value = str(data.getValue())
        except Exception:  # noqa: BLE001
            continue
        if len(value) < min_length:
            continue
        if needle and needle not in value.lower():
            continue
        matched += 1
        if seen < offset:
            seen += 1
            continue
        if len(strings) >= limit:
            break
        strings.append({"address": _hex(data.getAddress()), "length": len(value),
                        "value": value[:500]})
    return {"min_length": min_length, "filter": filter_text, "matched": matched,
            "returned": len(strings), "strings": strings}


def list_imports(program, filter_text: str | None = None, limit: int = 500) -> dict[str, Any]:
    """External symbols (functions/libraries the binary references)."""
    needle = filter_text.lower() if filter_text else None
    imports: list[dict[str, Any]] = []
    for symbol in program.getSymbolTable().getExternalSymbols():
        name = str(symbol.getName(True))
        if needle and needle not in name.lower():
            continue
        imports.append({"name": name, "address": _hex(symbol.getAddress())})
        if len(imports) >= limit:
            break
    libraries: list[str] = []
    try:
        libraries = [str(name) for name in program.getExternalManager().getExternalLibraryNames()]
    except Exception:  # noqa: BLE001
        pass
    return {"returned": len(imports), "filter": filter_text, "libraries": libraries,
            "imports": imports}


def list_entry_points(program, limit: int = 200) -> dict[str, Any]:
    """Binary entry points / exported functions."""
    entries: list[dict[str, Any]] = []
    memory = program.getMemory()
    for address in program.getSymbolTable().getExternalEntryPointIterator():
        entries.append({
            "address": _hex(address),
            "name": _symbol_name_at(program, address),
            "in_memory": bool(memory.contains(address)),
        })
        if len(entries) >= limit:
            break
    return {"returned": len(entries), "entry_points": entries}


def xrefs(program, name_or_address: str, direction: str = "to", limit: int = 50) -> dict[str, Any]:
    """Cross references to (callers/users) or from (callees/reads) an address."""
    address = resolve_address(program, name_or_address)
    if address is None:
        address = resolve_function(program, name_or_address).getEntryPoint()

    manager = program.getReferenceManager()
    outgoing = str(direction).lower() in ("from", "out", "outgoing")
    iterator = manager.getReferenceIterator(address) if outgoing else manager.getReferencesTo(address)

    references: list[dict[str, Any]] = []
    for reference in iterator:
        if len(references) >= limit:
            break
        try:
            from_address = reference.getFromAddress()
            to_address = reference.getToAddress()
            probe = to_address if outgoing else from_address
            references.append({
                "from": _hex(from_address),
                "to": _hex(to_address),
                "type": str(reference.getReferenceType()),
                "function": _symbol_name_at(program, probe),
            })
        except Exception:  # noqa: BLE001
            continue

    return {"target": _hex(address), "direction": "from" if outgoing else "to",
            "returned": len(references), "references": references}


def disassemble(program, name_or_address: str, count: int = 32, offset: int = 0) -> dict[str, Any]:
    """Disassembles instructions starting at an address or a function entry point."""
    address = resolve_address(program, name_or_address)
    if address is None:
        address = resolve_function(program, name_or_address).getEntryPoint()

    instructions: list[dict[str, Any]] = []
    skipped = 0
    for instruction in program.getListing().getInstructions(address, True):
        if skipped < offset:
            skipped += 1
            continue
        if len(instructions) >= count:
            break
        instructions.append({
            "address": _hex(instruction.getAddress()),
            "mnemonic": str(instruction.getMnemonicString()),
            "text": str(instruction.toString()),
        })
    return {"start": _hex(address), "offset": offset, "returned": len(instructions),
            "instructions": instructions}


def read_bytes(program, address: str, length: int = 64) -> dict[str, Any]:
    """Reads raw bytes from program memory."""
    from jpype import JArray, JByte

    resolved = resolve_address(program, address)
    if resolved is None:
        raise GhidraError(f"cannot parse address '{address}'")

    memory = program.getMemory()
    if not memory.contains(resolved):
        raise GhidraError(f"address {_hex(resolved)} is not inside mapped memory")

    buffer = JArray(JByte)(length)
    read = int(memory.getBytes(resolved, buffer))
    raw = bytes(bytearray(buffer))[:read]
    return {
        "address": _hex(resolved),
        "requested": length,
        "read": read,
        "hex": raw.hex(" "),
        "ascii": "".join(chr(byte) if 32 <= byte < 127 else "." for byte in raw),
    }


def _parse_hex_pattern(pattern: str) -> tuple[list[int], list[int]]:
    """Turns '4C 8B ??' into byte values and masks ('??' matches any byte)."""
    tokens = pattern.replace(",", " ").split()
    values: list[int] = []
    masks: list[int] = []
    for token in tokens:
        if token in ("?", "??", "**"):
            values.append(0)
            masks.append(0)
            continue
        if len(token) == 1 and token.lower() in "0123456789abcdef":
            token = "0" + token
        if len(token) != 2:
            raise GhidraError(f"invalid byte '{token}' in pattern '{pattern}'")
        try:
            values.append(int(token, 16))
        except ValueError as exc:
            raise GhidraError(f"invalid byte '{token}' in pattern '{pattern}'") from exc
        masks.append(0xFF)
    if not values:
        raise GhidraError("pattern must contain at least one byte, e.g. '4C 8B DC'")
    return values, masks


def _signed(values: list[int]) -> list[int]:
    """Java bytes are signed: 0xFF must be passed as -1."""
    return [value - 256 if value > 127 else value for value in values]


def search_bytes(program, pattern: str, limit: int = 20, max_scan_mb: int = 8) -> dict[str, Any]:
    """Searches loaded memory for a byte pattern ('4C 8B DC', '??' wildcards allowed)."""
    from jpype import JArray, JByte

    values, masks = _parse_hex_pattern(pattern)
    blob = JArray(JByte)(_signed(values))
    mask_blob = JArray(JByte)(_signed(masks))

    memory = program.getMemory()
    start = memory.getMinAddress()
    monitor = SESSION.task_monitor(300)
    scan_limit = int(max_scan_mb) * 1024 * 1024

    hits: list[dict[str, Any]] = []
    cursor = start
    scanned = 0
    while cursor is not None and len(hits) < limit:
        found = memory.findBytes(cursor, blob, mask_blob, True, monitor)
        if found is None:
            break
        hits.append({"address": _hex(found), "in_function": _symbol_name_at(program, found)})
        scanned = int(found.getOffset() - start.getOffset())
        if scanned > scan_limit:
            break
        try:
            cursor = found.add(1)
        except Exception:  # noqa: BLE001
            break

    return {"pattern": pattern, "returned": len(hits), "scanned_bytes": scanned,
            "scan_limit_bytes": scan_limit, "matches": hits}


def list_data_types(program, query: str | None = None, limit: int = 200) -> dict[str, Any]:
    """Data types known to the program (filters on name or path)."""
    needle = query.lower() if query else None
    types: list[dict[str, Any]] = []
    for data_type in program.getDataTypeManager().getAllDataTypes():
        try:
            name = str(data_type.getName())
            path = str(data_type.getPathName())
        except Exception:  # noqa: BLE001
            continue
        if needle and needle not in name.lower() and needle not in path.lower():
            continue
        entry = {"name": name, "path": path}
        try:
            entry["length"] = int(data_type.getLength())
        except Exception:  # noqa: BLE001
            entry["length"] = None
        types.append(entry)
        if len(types) >= limit:
            break
    return {"query": query, "returned": len(types), "data_types": types}


def list_memory_blocks(program) -> dict[str, Any]:
    """Memory segments/blocks with permissions."""
    blocks: list[dict[str, Any]] = []
    for block in program.getMemory().getBlocks():
        blocks.append({
            "name": str(block.getName()),
            "start": _hex(block.getStart()),
            "end": _hex(block.getEnd()),
            "size": int(block.getSize()),
            "initialized": bool(block.isInitialized()),
            "read": bool(block.isRead()),
            "write": bool(block.isWrite()),
            "execute": bool(block.isExecute()),
        })
    return {"returned": len(blocks), "blocks": blocks}


def program_summary(program) -> dict[str, Any]:
    """High level metadata of the open program."""
    summary: dict[str, Any] = {
        "name": str(program.getName()),
        "executable_path": str(program.getExecutablePath()),
        "executable_format": str(program.getExecutableFormat()),
        "md5": str(program.getExecutableMD5()),
        "sha256": str(program.getExecutableSHA256()),
        "language": str(program.getLanguageID().toString()),
        "compiler": str(program.getCompilerSpec().getCompilerSpecID().toString()),
        "image_base": _hex(program.getImageBase()),
        "min_address": _hex(program.getMinAddress()),
        "max_address": _hex(program.getMaxAddress()),
        "memory_bytes": int(program.getMemory().getNumAddresses()),
        "function_count": int(program.getFunctionManager().getFunctionCount()),
        "symbol_count": int(program.getSymbolTable().getNumSymbols()),
        "defined_data_count": int(program.getListing().getNumDefinedData()),
    }
    try:
        summary["entry_points"] = len(
            list(program.getSymbolTable().getExternalEntryPointIterator())
        )
    except Exception:  # noqa: BLE001
        summary["entry_points"] = None
    try:
        summary["import_libraries"] = [
            str(name) for name in program.getExternalManager().getExternalLibraryNames()
        ]
    except Exception:  # noqa: BLE001
        summary["import_libraries"] = []
    return summary


def call_graph(program, name_or_address: str, limit: int = 50) -> dict[str, Any]:
    """Call-graph view for a single function (callees and callers)."""
    func = resolve_function(program, name_or_address)
    monitor = SESSION.task_monitor(120)
    called = [str(callee.getName(True)) for callee in list(func.getCalledFunctions(monitor))[:limit]]
    calling = [str(caller.getName(True)) for caller in list(func.getCallingFunctions(monitor))[:limit]]
    return {"function": str(func.getName(True)), "entry": _hex(func.getEntryPoint()),
            "called_functions": called, "calling_functions": calling}
