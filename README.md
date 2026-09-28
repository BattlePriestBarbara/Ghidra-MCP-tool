[![M8ven Score](https://m8ven.ai/badge/mcp/battlepriestbarbara/ghidra-mcp-tool)](https://m8ven.ai/mcp/battlepriestbarbara/ghidra-mcp-tool)
[![M8ven Score](https://m8ven.ai/badge/mcp/battlepriestbarbara-ghidra-mcp-tool-jfi1kg?v=c3358808675b58c499889889eca676ad)](https://m8ven.ai/mcp/battlepriestbarbara-ghidra-mcp-tool-jfi1kg)
[![M8ven Score](https://m8ven.ai/badge/mcp/battlepriestbarbara-ghidra-mcp-tool-jfi1kg)](https://m8ven.ai/mcp/battlepriestbarbara-ghidra-mcp-tool-jfi1kg)
# Ghidra MCP server for Cline

Exposes Ghidra (headless, via **PyGhidra**) to Cline as MCP tools, so the assistant can
import binaries, trigger auto-analysis, browse functions/symbols/strings/imports, and read
decompiled C code and disassembly inside a normal chat.

Verified on this machine against:

| Component | Version / path |
| --- | --- |
| Ghidra | 12.1.3 PUBLIC — `D:\ghidra_12.1.3_PUBLIC` (requires JDK >= 21) |
| JDK used | Temurin 25.0.4.1 — `D:\nd` (the machine's `JAVA_HOME`/`PATH` java is JDK 8/16, i.e. too old) |
| Python | 3.12.10 (`C:\Users\...\AppData\Local\Programs\Python\Python312`) |
| pyghidra | 3.1.0 (+ jpype1 1.5.2, shipped inside the Ghidra install) |
| MCP SDK | 2.2.0 (`mcp.server.mcpserver.MCPServer`) |

## Why this design

* **MCP is the integration layer.** Cline cannot drive Ghidra's GUI or Java API directly;
  the MCP protocol turns Ghidra operations into typed tools the model can call.
* **PyGhidra is the primary engine.** One JVM is started lazily inside the MCP server and
  kept warm; the analysed program stays open, so repeated questions (decompile this, list
  those xrefs) cost milliseconds instead of a JVM restart.
* **`analyzeHeadless` is the fallback/batch engine.** `ghidra_headless_import` shells out to
  Ghidra's own CLI (separate process, good for batch or long jobs). Both engines use the
  **same project store**, so a program imported by headless can be queried through PyGhidra
  and vice versa (covered by `tests/smoke_headless.py`).

## Layout

```
D:\ghidra-mcp\
├── server.py                  # MCP entry point (stdio). Flags: --check, --tools
├── ghidra_mcp\
│   ├── config.py              # locates Ghidra + a JDK >= 21, project store, timeouts
│   ├── session.py             # JVM/project/program lifecycle, caching, locking
│   ├── queries.py             # program introspection (Ghidra Java API wrappers)
│   ├── headless.py            # analyzeHeadless subprocess wrapper
│   └── tools.py               # 23 MCP tools (JSON in/out, never raise)
├── tests\
│   ├── probe_pyghidra.py      # JVM + import + analyse + decompile smoke test
│   ├── probe_api.py           # checks every Ghidra Java API the server relies on
│   ├── smoke_tools.py         # calls all 23 tools directly (fast)
│   ├── smoke_mcp_client.py    # real MCP stdio handshake + tool calls (like Cline)
│   └── smoke_headless.py      # analyzeHeadless -> PyGhidra interop
├── projects\                  # Ghidra project store (created at runtime; git-ignored)
├── requirements.txt
├── LICENSE                    # MIT
├── .gitignore                 # excludes .venv\, projects\, __pycache__\
└── cline_mcp_config.json      # snippet to paste into Cline's MCP settings
```

## Setup (already done on this machine)

```powershell
# 1. venv on an ASCII path (see the non-ASCII caveat below!)
& "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe" -m venv D:\ghidra-mcp\.venv

# 2. pyghidra + jpype from the wheels bundled with Ghidra (works offline)
& D:\ghidra-mcp\.venv\Scripts\python.exe -m pip install --no-index `
    --find-links "D:\ghidra_12.1.3_PUBLIC\Ghidra\Features\PyGhidra\pypkg\dist" pyghidra

# 3. MCP SDK
& D:\ghidra-mcp\.venv\Scripts\python.exe -m pip install mcp
```

Sanity check before wiring anything up:

```powershell
& D:\ghidra-mcp\.venv\Scripts\python.exe D:\ghidra-mcp\server.py --check   # environment JSON
& D:\ghidra-mcp\.venv\Scripts\python.exe D:\ghidra-mcp\server.py --tools   # tool list
```

## Cline configuration

Cline keeps MCP servers in
`%APPDATA%\Code\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json`.
Merge the `ghidra` entry from `cline_mcp_config.json` into `mcpServers` (a backup of the
previous file is written next to it as `cline_mcp_settings.json.bak`):

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "D:\\ghidra-mcp\\.venv\\Scripts\\python.exe",
      "args": ["D:\\ghidra-mcp\\server.py"],
      "env": {
        "GHIDRA_MCP_INSTALL_DIR": "D:\\ghidra_12.1.3_PUBLIC",
        "GHIDRA_MCP_JAVA_HOME": "D:\\nd",
        "GHIDRA_MCP_PROJECTS": "D:\\ghidra-mcp\\projects"
      },
      "disabled": false,
      "autoApprove": ["ghidra_environment", "ghidra_list_functions", "..."],
      "timeout": 900
    }
  }
}
```

* `timeout: 900` matters — auto-analysis of a large binary takes minutes.
* Read-only tools are auto-approved in the provided snippet; the mutating ones
  (`ghidra_import_and_analyze`, `ghidra_open_program`, `ghidra_close_program`,
  `ghidra_headless_import`) still ask for approval.
* Use `"disabled": true` to unload it without deleting the entry.
* Restart the MCP server from Cline's MCP panel after editing the file.


## Tools

| Tool | What it does |
| --- | --- |
| `ghidra_environment` | Ghidra/JDK/Python report, project store, JVM state (run this first) |
| `ghidra_session_status` | Is the JVM up, which project/program is open |
| `ghidra_import_and_analyze` | Import + auto-analyse + open a binary (result cached in the project) |
| `ghidra_open_program` | Reopen an analysed program (fast path) |
| `ghidra_current_program` | Hashes, language/compiler, image base, counts |
| `ghidra_close_program` | Save + release the program/project (JVM stays warm) |
| `ghidra_list_projects` / `ghidra_list_programs` | Browse the project store |
| `ghidra_list_functions` | Function list, paged, substring filter |
| `ghidra_function_details` | Signature, params, locals, callers/callees, xrefs (+optional decompile) |
| `ghidra_decompile_function` | C-like pseudocode for one function |
| `ghidra_search_symbols` | Symbol search (functions, data, imports) |
| `ghidra_call_graph` | Callers/callees of a function |
| `ghidra_disassemble` | Instructions from an address or function entry |
| `ghidra_xrefs` | Incoming (`to`) or outgoing (`from`) cross references |
| `ghidra_list_strings` | Defined strings (min length + substring filter) |
| `ghidra_list_imports` | Imported symbols and libraries |
| `ghidra_list_entry_points` | Entry points/exports |
| `ghidra_read_bytes` | Raw memory dump (hex + ASCII) |
| `ghidra_search_bytes` | Byte-pattern search with `??` wildcards |
| `ghidra_list_data_types` | Structs/enums/typedefs known to the program |
| `ghidra_list_memory_blocks` | Segments with ranges and permissions |
| `ghidra_headless_import` | Batch import via `analyzeHeadless` (separate process) |

Arguments that take `name_or_address` accept a function name (`FUN_140001008`),
`namespace::name` (`KERNEL32.DLL::CreateFileW`) or an address (`0x140001008`); a unique
substring also matches. Addresses are always reported as `0x`-prefixed hex.

### Example workflow in chat

1. `ghidra_environment` -> confirms Ghidra 12.1.3 + JDK 25 + project store.
2. `ghidra_import_and_analyze(binary_path="C:\\Windows\\System32\\notepad.exe")`
   -> 853 functions, analysis cached in `D:\ghidra-mcp\projects\default`.
3. `ghidra_search_symbols(query="CreateFileW")` -> address of the import thunk.
4. `ghidra_xrefs(name_or_address="0x1400019c0", direction="to")` -> who calls it.
5. `ghidra_decompile_function(name_or_address="entry")` -> pseudocode to explain.
6. `ghidra_open_program(project_name="default", program_name="notepad.exe")` in a later
   session -> instant, because the analysis is already on disk.

## Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `GHIDRA_MCP_INSTALL_DIR` (or `GHIDRA_INSTALL_DIR`) | auto-detected (`ghidra_*` on C:/D:/E:, Ghidra's `lastrun` file) | Ghidra installation |
| `GHIDRA_MCP_JAVA_HOME` (or `JAVA_HOME`) | newest JDK >= 21 found (`D:\nd`, Program Files JDKs, `java` on PATH) | JDK used by PyGhidra |
| `GHIDRA_MCP_PROJECTS` | `<server dir>\projects` | Ghidra project store |
| `GHIDRA_MCP_TIMEOUT` | `900` | Default per-task timeout (seconds) |
| `GHIDRA_MCP_JAVA_STDOUT_TO_STDERR` | `1` | Route Java's `System.out` to stderr (keeps MCP's JSON-RPC stream clean) |

## Design notes and gotchas

* **The server must live on an ASCII path.** JPype refuses to apply Ghidra's system class
  loader when any classpath entry contains non-ASCII characters (`ValueError: system
  classloader cannot be specified with non ascii characters in the classpath`), and the
  venv/interpreter path is always on that classpath. That is why the server sits in
  `D:\ghidra-mcp` and not under `D:\调用`. `config.non_ascii_classpath_problems()` re-checks
  this and `ghidra_environment` reports it.
* **JDK >= 21 is mandatory** (Ghidra 12.1.3 `application.java.min=21`). This machine's
  `JAVA_HOME` points at JDK 8 and `java` on PATH is JDK 16, so the server resolves a suitable
  JDK itself (`D:\nd`, Temurin 25) and exports it via `JAVA_HOME` before starting the JVM.
* **stdout discipline.** MCP speaks JSON-RPC over stdout and Ghidra/Java logs would corrupt
  it. The MCP SDK diverts fd 1 to stderr while serving, and the server additionally redirects
  Java's `System.out` to stderr. `tests/smoke_mcp_client.py` proves the stream stays clean.
* **Analysis is cached.** `ghidra_import_and_analyze` re-imports/re-analyses only when the
  program is missing or `force_reimport=True`; `GhidraProgramUtilities.shouldAskToAnalyze`
  decides whether analysis is still required.
* **One program open at a time.** Ghidra program objects are not thread-safe, so every tool
  call runs under a single re-entrant lock; opening another program releases the previous one.
* **Bounded output.** Large listings are paged/limited (`limit`, `offset`, `max_chars`,
  `max_scan_mb`) so a chat turn does not drown in data.
* **API details verified, not guessed.** `tests/probe_api.py` records 66 Ghidra API checks;
  e.g. `Function.getPrototypeString(bool, bool)` exists while the no-arg overload and
  `getSignature(bool, bool)` do not in Ghidra 12.1.3, and `DomainFile.getContentType()`
  returns a String (`"Program"`) rather than a Class.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `pyghidra is not installed in this interpreter` | Install it into this venv (see Setup); do not point Cline at the system Python |
| `system classloader cannot be specified with non ascii characters` | Move the server + venv to an ASCII path |
| `Ghidra version ... is not supported` or JVM start failure | Provide a JDK >= 21 via `GHIDRA_MCP_JAVA_HOME` |
| `Ghidra installation not found` | Set `GHIDRA_MCP_INSTALL_DIR` to the folder containing `support\analyzeHeadless.bat` |
| Tool times out on a big binary | Raise the MCP `timeout`, pass a larger `timeout` argument, or pre-analyse with `ghidra_headless_import` |
| `no program is open` | Call `ghidra_import_and_analyze` or `ghidra_open_program` first |
| `project 'x' does not exist` | `ghidra_list_projects` to see what is stored, or import with that project name |
| Decompiler returns an error string | Retry with a larger `timeout`; some functions legitimately fail (`decompile_completed: false`) |

## Tests (all green on this machine)

```powershell
$py = "D:\ghidra-mcp\.venv\Scripts\python.exe"
& $py D:\ghidra-mcp\tests\probe_api.py            # 66 Ghidra API checks            (~35 s)
& $py D:\ghidra-mcp\tests\smoke_tools.py          # 23 tools + 9 assertions         (~15 s)
& $py D:\ghidra-mcp\tests\smoke_mcp_client.py     # real MCP handshake + calls      (~15 s)
& $py D:\ghidra-mcp\tests\smoke_headless.py       # analyzeHeadless <-> PyGhidra    (~40 s)
& $py D:\ghidra-mcp\tests\probe_pyghidra.py <bin> # fresh import + analyse + decompile (minutes)
```

The two `probe`/`headless_smoke` projects the tests use are created on demand in
`D:\ghidra-mcp\projects`; analysing `notepad.exe` there takes ~3 minutes the first time.

## Extending

Add a function to `ghidra_mcp/queries.py` (plain Python, returns JSON-serialisable data),
wrap it in `ghidra_mcp/tools.py` (take `SESSION.lock`, call `SESSION.require_program()`,
return `_ok(...)` / `_error(...)`), then list it in `TOOL_FUNCTIONS` in `server.py`. Keep the
docstring accurate - Cline shows it to the model as the tool description.

## Recovering the original bytes (and the stored hashes)

Ghidra keeps the **original imported file bytes** in the program database, so the hashes in
`calc_features.json` are reproducible even if the source file is lost. `tests/probe_original_export.py`
demonstrates it:

```powershell
& D:\ghidra-mcp\.venv\Scripts\python.exe D:\ghidra-mcp\tests\probe_original_export.py weka /uninstall.exe
# stored MD5 in program DB : 59d3469678498a4ece87c7789cd0c74f
# stored sha256 in DB      : 24b839a1e96a590b23f650dc26a35c052d28c2a641c6eb6ee376d8c9af48d024
# OriginalFileExporter.export -> True : %TEMP%\uninstall_from_ghidra.exe
# exported size   : 56722
# exported md5    : 59d3469678498a4ece87c7789cd0c74f
# exported sha256 : 24b839a1e96a590b23f650dc26a35c052d28c2a641c6eb6ee376d8c9af48d024
```

The exported copy is byte-identical to `D:\weka\Weka-3-6\uninstall.exe` (same size, MD5 and
SHA-256). A hash value itself is a one-way function and cannot be inverted, but a Ghidra program
*is* sufficient to rebuild the file it was imported from (`ghidra.app.util.exporter.OriginalFileExporter`,
or "Export Original File" in the GUI).

**Gotcha:** do not name your own Python files `ghidra*.py`. PyGhidra's import hook claims modules
whose name starts with `ghidra`, and a script called `ghidra_export_probe.py` fails with
`RecursionError: maximum recursion depth exceeded` inside `find_spec`. The probe above is named
`probe_original_export.py` for that reason.

## Feature-extraction CLI

`extract_features.py` drives the same tool functions as the MCP server without a chat, which is
handy for batch/repeatable runs or when the MCP server has not been reloaded yet:

```powershell
$py = "D:\ghidra-mcp\.venv\Scripts\python.exe"
& $py D:\ghidra-mcp\extract_features.py <binary> [-o out.json] [--project NAME] [--top 5]
                                     [--timeout 900] [--decompile-chars 8000] [--force] [--no-analyze]
```

It imports + analyses the binary, then writes a JSON document containing the binary hashes and
format, the analysis result, `features` (function count, imported API count, string count,
symbols, entry points, memory), the N "core" functions with decompiled pseudo-code,
`imported_apis`, `imported_libraries`, a string sample, entry points and memory blocks.

"Core" ranking: non-import, non-thunk functions with a body, sorted by caller count (in-degree
from `ghidra_call_graph`) with ties broken by body size; caller counts are computed for the 30
largest functions, and the program entry point is always included. The exact rule is echoed in
the JSON as `ranking_method`.

Example (Weka uninstaller, 2026-09-22):

```
[extract] ghidra_import_and_analyze: ok        # 31.5 s, imported=True, analyzed=True
[extract] ghidra_list_functions: ok            # 240 functions
[extract] ghidra_list_imports: ok              # 155 APIs from 8 DLLs
[extract] ghidra_list_strings: ok              # 212 strings
[extract] wrote D:\weka\Weka-3-6\calc_features.json
```

### Tool-name mapping

The MCP tools are named after the queries they run; older/other Ghidra MCP servers use
different names:

| Name used elsewhere | Tool in this server |
| --- | --- |
| `ghidra_get_functions` | `ghidra_list_functions` |
| `ghidra_get_symbols` | `ghidra_search_symbols` |
| `ghidra_get_imports` | `ghidra_list_imports` |
| `ghidra_get_strings` | `ghidra_list_strings` |
| `ghidra_decompile` | `ghidra_decompile_function` |

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 Xinhang Yu.

## Not committed to git

`.gitignore` keeps machine-local and regenerable state out of the repository:
`.venv/` (the virtual environment), `projects/` (Ghidra's `.gpr`/`.rep` project store, created at
runtime by `ghidra_mcp/config.py:projects_dir()`), `__pycache__/`, and `calc_features.json`
(`extract_features.py`'s default output). Recreate them with the setup steps above; the `.venv`
must be rebuilt per machine because it contains absolute paths and is wired to the local Ghidra
and JDK installs.
