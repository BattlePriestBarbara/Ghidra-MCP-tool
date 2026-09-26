"""Configuration and environment resolution for the Ghidra MCP server.

Everything here is pure Python (no Ghidra/JVM import), so the environment tool can
answer questions even when the JVM is not up yet.
"""
from __future__ import annotations

import glob
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_DIR.parent

#: Ghidra requires a JDK of this major version or newer (see application.properties).
MIN_JAVA_MAJOR = 21


class ConfigError(RuntimeError):
    """Raised when the Ghidra installation or JDK cannot be located."""


def _env_path(name: str) -> Path | None:
    value = os.environ.get(name)
    return Path(value) if value else None


def _is_ghidra_install(path: Path) -> bool:
    return (path / "support" / "analyzeHeadless.bat").is_file() or (
        path / "support" / "analyzeHeadless"
    ).is_file()


def _lastrun_install_dir() -> Path | None:
    """Ghidra >= 11.4 records its install dir in a 'lastrun' file."""
    appdata = os.environ.get("APPDATA")
    candidates = [Path(appdata) / "ghidra" / "lastrun"] if appdata else []
    candidates.append(Path.home() / ".config" / "ghidra" / "lastrun")
    for candidate in candidates:
        try:
            if candidate.is_file():
                text = candidate.read_text(encoding="utf-8", errors="replace").strip()
                if text:
                    path = Path(text)
                    if _is_ghidra_install(path):
                        return path
        except OSError:
            continue
    return None


def resolve_ghidra_install_dir(required: bool = True) -> Path | None:
    """Finds the Ghidra installation directory.

    Order: $GHIDRA_MCP_INSTALL_DIR, $GHIDRA_INSTALL_DIR, Ghidra's 'lastrun' file,
    then a filesystem scan of the usual drive roots.
    """
    for name in ("GHIDRA_MCP_INSTALL_DIR", "GHIDRA_INSTALL_DIR"):
        candidate = _env_path(name)
        if candidate is not None and _is_ghidra_install(candidate):
            return candidate

    lastrun = _lastrun_install_dir()
    if lastrun is not None:
        return lastrun

    patterns: list[str] = []
    for root in ("D:\\", "C:\\", "E:\\"):
        patterns.append(f"{root}ghidra_*")
        patterns.append(f"{root}tools\\ghidra_*")
    patterns.append(str(Path.home() / "ghidra_*"))
    patterns.append("C:\\Program Files\\ghidra_*")

    found: list[Path] = []
    for pattern in patterns:
        for match in glob.glob(pattern):
            path = Path(match)
            if _is_ghidra_install(path):
                found.append(path)
    if found:
        # Newest release wins (ghidra_12.1.3_PUBLIC > ghidra_11.0_PUBLIC).
        def _version_key(path: Path) -> tuple:
            numbers = re.findall(r"\d+", path.name)
            return tuple(int(n) for n in numbers) if numbers else (0,)

        return sorted(found, key=_version_key)[-1]

    if required:
        raise ConfigError(
            "Ghidra installation not found. Set GHIDRA_MCP_INSTALL_DIR (or GHIDRA_INSTALL_DIR) "
            "to a directory containing support/analyzeHeadless."
        )
    return None

def java_major_version(java_home: Path, timeout: int = 20) -> int | None:
    """Returns the JDK major version for a JAVA_HOME directory, or None if unusable."""
    java_exe = java_home / "bin" / "java.exe"
    if not java_exe.is_file():
        java_exe = java_home / "bin" / "java"
    if not java_exe.is_file():
        return None

    release_file = java_home / "release"
    if release_file.is_file():
        try:
            match = re.search(r'JAVA_VERSION="([^"]+)"',
                              release_file.read_text(encoding="utf-8", errors="replace"))
            if match:
                raw = match.group(1)
                if raw.startswith("1."):
                    return int(raw.split(".")[1])
                numbers = re.match(r"(\d+)", raw)
                if numbers:
                    return int(numbers.group(1))
        except (OSError, ValueError):
            pass

    try:
        proc = subprocess.run([str(java_exe), "-version"], capture_output=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    text = (proc.stderr or b"").decode("utf-8", errors="replace") or (
        proc.stdout or b""
    ).decode("utf-8", errors="replace")
    match = re.search(r'version "(\d+)(?:\.(\d+))?', text)
    if not match:
        return None
    if match.group(1) == "1" and match.group(2):
        return int(match.group(2))
    return int(match.group(1))


def candidate_java_homes() -> list[Path]:
    """Common JDK locations, plus anything pointed at by environment variables."""
    candidates: list[Path] = []
    for name in ("GHIDRA_MCP_JAVA_HOME", "JAVA_HOME"):
        value = _env_path(name)
        if value is not None:
            candidates.append(value)

    jdk_patterns = [
        "D:\\nd",
        "D:\\jdk*",
        "D:\\Java\\jdk*",
        "C:\\Java\\jdk*",
        "C:\\jdk*",
        "C:\\Program Files\\Java\\jdk*",
        "C:\\Program Files\\Eclipse Adoptium\\jdk*",
        "C:\\Program Files\\Zulu\\zulu*",
        "C:\\Program Files\\Microsoft\\jdk*",
        "C:\\Program Files\\Amazon Corretto\\jdk*",
        str(Path.home() / ".jdks" / "*"),
    ]
    for pattern in jdk_patterns:
        candidates.extend(Path(match) for match in glob.glob(pattern))

    on_path = shutil.which("java")
    if on_path:
        candidates.append(Path(on_path).resolve().parent.parent)

    unique: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate).lower()
        if key not in seen and candidate.is_dir():
            seen.add(key)
            unique.append(candidate)
    return unique


def resolve_java_home(min_major: int = MIN_JAVA_MAJOR) -> tuple[Path | None, list[dict]]:
    """Picks the newest usable JDK for Ghidra.

    Ghidra's launch scripts ignore unsupported JAVA_HOME values, but JPype is happier
    when we hand it the right one, so we validate versions ourselves.
    Returns (chosen_java_home or None, report of every candidate considered).
    """
    report: list[dict] = []
    usable: list[tuple[int, Path]] = []
    for candidate in candidate_java_homes():
        major = java_major_version(candidate)
        report.append({"path": str(candidate), "major_version": major,
                       "usable": bool(major and major >= min_major)})
        if major and major >= min_major:
            usable.append((major, candidate))
    if not usable:
        return None, report
    usable.sort(key=lambda item: (item[0], str(item[1])))
    return usable[-1][1], report


def projects_dir() -> Path:
    """Ghidra project store used by the server."""
    override = _env_path("GHIDRA_MCP_PROJECTS")
    path = override if override is not None else PROJECT_ROOT / "projects"
    path.mkdir(parents=True, exist_ok=True)
    return path


def resolve_config(require_ghidra: bool = True) -> dict:
    """Resolves everything the server needs to boot Ghidra."""
    install_dir = resolve_ghidra_install_dir(required=require_ghidra)
    java_home, java_report = resolve_java_home()
    return {
        "ghidra_install_dir": install_dir,
        "java_home": java_home,
        "java_candidates": java_report,
        "projects_dir": projects_dir(),
    }


def non_ascii_classpath_problems() -> list[str]:
    """Paths that must stay ASCII for JPype to start the JVM.

    JPype refuses to use a custom system class loader when any classpath entry has
    non-ASCII characters ("system classloader cannot be specified with non ascii
    characters in the classpath"), and the interpreter/venv path is always on that
    classpath. This is why the server must live under an ASCII path.
    """
    problems: list[str] = []
    for label, value in (
        ("python executable", sys.executable),
        ("python prefix (venv)", sys.prefix),
        ("server package", str(PACKAGE_DIR)),
    ):
        try:
            value.encode("ascii")
        except UnicodeEncodeError:
            problems.append(f"{label} contains non-ASCII characters: {value}")
    return problems


def default_timeout() -> int:
    """Default per-request Ghidra task timeout (seconds)."""
    try:
        return int(os.environ.get("GHIDRA_MCP_TIMEOUT", "900"))
    except ValueError:
        return 900
