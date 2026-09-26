"""analyzeHeadless fallback path.

PyGhidra is the primary engine (in-process, warm JVM), but Ghidra's headless
analyzer is handy for batch imports where a fresh process is preferable, or to
reproduce exactly what the Ghidra GUI/CLI would do. Projects created here live in
the same project store and can be opened later with ghidra_open_program.
"""
from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from typing import Any

from . import config
from .session import GhidraError


def headless_launcher() -> Path:
    install_dir = config.resolve_ghidra_install_dir()
    for name in ("analyzeHeadless.bat", "analyzeHeadless"):
        candidate = install_dir / "support" / name
        if candidate.is_file():
            return candidate
    raise GhidraError(f"analyzeHeadless not found under {install_dir / 'support'}")


def headless_import(
    binary_paths: list[str],
    project_name: str = "headless",
    timeout: int = 1800,
    analysis_timeout_per_file: int | None = None,
    post_scripts: list[str] | None = None,
    pre_scripts: list[str] | None = None,
    script_paths: list[str] | None = None,
    processor: str | None = None,
    no_analysis: bool = False,
    recursive: bool = False,
) -> dict[str, Any]:
    """Runs analyzeHeadless to import (and analyse) binaries into the project store."""
    if not binary_paths:
        raise GhidraError("at least one binary path is required")

    for binary in binary_paths:
        if not Path(binary).exists():
            raise GhidraError(f"file or directory not found: {binary}")

    launcher = headless_launcher()
    location = str(config.projects_dir())

    arguments: list[str] = [location, project_name, "-import", *[str(p) for p in binary_paths]]
    for script in pre_scripts or []:
        arguments += ["-preScript", str(script)]
    for script in post_scripts or []:
        arguments += ["-postScript", str(script)]
    if script_paths:
        arguments += ["-scriptPath", ";".join(str(p) for p in script_paths)]
    if processor:
        arguments += ["-processor", str(processor)]
    if analysis_timeout_per_file:
        arguments += ["-analysisTimeoutPerFile", str(int(analysis_timeout_per_file))]
    if no_analysis:
        arguments.append("-noanalysis")
    if recursive:
        arguments.append("-recursive")

    env = os.environ.copy()
    java_home, _ = config.resolve_java_home()
    if java_home is not None:
        env["JAVA_HOME"] = str(java_home)
    env["GHIDRA_INSTALL_DIR"] = str(config.resolve_ghidra_install_dir())

    command = ["cmd.exe", "/c", str(launcher), *arguments] if os.name == "nt" else [
        str(launcher), *arguments
    ]

    started = time.time()
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            timeout=timeout,
            env=env,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.TimeoutExpired as exc:
        raise GhidraError(
            f"headless analysis timed out after {timeout}s. Increase the timeout or analyse "
            f"with ghidra_import_and_analyze instead."
        ) from exc

    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    errors = [
        line.strip()
        for line in (stdout + "\n" + stderr).splitlines()
        if " ERROR " in line or line.strip().startswith("ERROR")
    ]

    return {
        "exit_code": completed.returncode,
        "success": completed.returncode == 0,
        "elapsed_seconds": round(time.time() - started, 1),
        "project": {"name": project_name, "location": location},
        "command": " ".join(str(part) for part in command),
        "errors": errors[:20],
        "stdout_tail": stdout[-4000:],
        "stderr_tail": stderr[-2000:],
        "next_step": (
            f"Open the imported program with ghidra_open_program "
            f"(project_name='{project_name}') or list it with ghidra_list_programs."
        ),
    }
