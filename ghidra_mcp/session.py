"""Ghidra JVM, project and program lifecycle.

The MCP server keeps one JVM and one open program per (project, program) pair so
repeated queries are fast: importing and analysing a binary happens once, the
result lives in the Ghidra project on disk, and later opens reuse it.
"""
from __future__ import annotations

import os
import platform
import sys
import threading
import time
from pathlib import Path
from typing import Any

from . import config


class GhidraError(RuntimeError):
    """Raised for Ghidra-level failures (bad program name, analysis error, ...)."""


def _read_ghidra_version(install_dir: Path | None) -> str | None:
    if install_dir is None:
        return None
    props = install_dir / "Ghidra" / "application.properties"
    try:
        for line in props.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("application.version="):
                return line.split("=", 1)[1].strip()
    except OSError:
        return None
    return None


def _redirect_java_stdout_to_stderr() -> bool:
    """Send Java's System.out to stderr so Groovy/Java logs cannot corrupt MCP stdio.

    The MCP stdio transport already diverts fd 1 to stderr while serving, but doing
    this too keeps stray output harmless if the process is used interactively.
    """
    if os.environ.get("GHIDRA_MCP_JAVA_STDOUT_TO_STDERR", "1") == "0":
        return False
    try:
        from java.io import FileDescriptor, FileOutputStream, PrintStream
        from java.lang import System as JSystem

        JSystem.setOut(PrintStream(FileOutputStream(FileDescriptor.err)))
        return True
    except Exception:  # noqa: BLE001 - best effort only
        return False



class GhidraSession:
    """Owns the JVM, the open Ghidra project and the currently open program."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._pyghidra = None
        self._launcher = None
        self._project = None
        self._program = None
        self._consumer = None
        self._key: tuple[str, str] | None = None
        self._started_at: float | None = None
        self._java_home: str | None = None
        self._install_dir: str | None = None
        self._analysis_log: str = ""

    # ------------------------------------------------------------------ info
    def environment(self) -> dict[str, Any]:
        """Environment report that does not require the JVM."""
        install_dir, install_error = None, None
        try:
            install_dir = config.resolve_ghidra_install_dir(required=False)
        except config.ConfigError as exc:  # pragma: no cover - defensive
            install_error = str(exc)

        java_home, java_report = config.resolve_java_home()
        info: dict[str, Any] = {
            "python": {
                "version": platform.python_version(),
                "executable": sys.executable,
                "prefix": sys.prefix,
            },
            "ghidra_install_dir": str(install_dir) if install_dir else None,
            "ghidra_install_error": install_error,
            "ghidra_version": _read_ghidra_version(install_dir),
            "java_home_selected": str(java_home) if java_home else None,
            "java_candidates": java_report,
            "projects_dir": str(config.projects_dir()),
            "non_ascii_path_problems": config.non_ascii_classpath_problems(),
            "java_stdout_to_stderr": os.environ.get("GHIDRA_MCP_JAVA_STDOUT_TO_STDERR", "1") != "0",
            "jvm_started": self.jvm_started(),
        }
        if self._launcher is not None:
            info["jvm"] = {
                "startup_seconds": self._started_at,
                "java_home_in_use": self._java_home,
                "ghidra_install_dir_in_use": self._install_dir,
            }
        return info

    def jvm_started(self) -> bool:
        try:
            import pyghidra  # noqa: PLC0415 - optional dependency probe

            return bool(pyghidra.started())
        except Exception:  # noqa: BLE001
            return False

    def status(self) -> dict[str, Any]:
        return {
            "jvm_started": self.jvm_started(),
            "project": self._project_name(),
            "program": self._program_name(),
            "analysis_log_tail": self._analysis_log[-2000:] if self._analysis_log else "",
        }

    def _project_name(self) -> str | None:
        return self._key[0] if self._key else None

    def _program_name(self) -> str | None:
        return self._key[1] if self._key else None

    # ------------------------------------------------------------- lifecycle
    def start(self) -> None:
        """Starts the JVM and initialises Ghidra headless (idempotent)."""
        with self._lock:
            if self._launcher is not None and self.jvm_started():
                return

            problems = config.non_ascii_classpath_problems()
            if problems:
                raise GhidraError(
                    "JPype cannot start the JVM because a path on the Java classpath "
                    "contains non-ASCII characters. Move this server (and its venv) to an "
                    "ASCII path. " + "; ".join(problems)
                )

            try:
                import pyghidra  # noqa: PLC0415
            except ImportError as exc:  # pragma: no cover - deployed env check
                raise GhidraError(
                    "pyghidra is not installed in this interpreter. Install it with "
                    "'pip install pyghidra' (see README)."
                ) from exc

            self._pyghidra = pyghidra
            cfg = config.resolve_config()
            install_dir: Path = cfg["ghidra_install_dir"]
            java_home: Path | None = cfg["java_home"]

            os.environ["GHIDRA_INSTALL_DIR"] = str(install_dir)
            if java_home is not None:
                os.environ["JAVA_HOME"] = str(java_home)

            started = time.time()
            self._launcher = pyghidra.start(install_dir=install_dir)
            self._started_at = round(time.time() - started, 1)
            self._install_dir = str(install_dir)
            try:
                self._java_home = str(self._launcher.java_home)
            except Exception:  # noqa: BLE001 - attribute is optional
                self._java_home = str(java_home) if java_home else None

            _redirect_java_stdout_to_stderr()

    def close(self) -> dict[str, Any]:
        """Releases the open program/project (the JVM stays up for later calls)."""
        with self._lock:
            closed = {"program": self._program_name(), "project": self._project_name()}
            if self._program is not None and self._consumer is not None:
                try:
                    self._program.release(self._consumer)
                except Exception:  # noqa: BLE001
                    pass
            if self._project is not None:
                try:
                    self._project.close()
                except Exception:  # noqa: BLE001
                    pass
            self._program = None
            self._consumer = None
            self._project = None
            self._key = None
            self._analysis_log = ""
            return closed

    # ------------------------------------------------------- project/program
    def open_project(self, project_name: str, create: bool = False):
        """Opens (and caches) a Ghidra project from the server's project store."""
        with self._lock:
            if self._project is not None and self._key and self._key[0] == project_name:
                return self._project
            self.close()
            self.start()
            try:
                self._project = self._pyghidra.open_project(
                    str(config.projects_dir()), project_name, create=create
                )
            except FileNotFoundError as exc:
                raise GhidraError(
                    f"Ghidra project '{project_name}' does not exist in "
                    f"{config.projects_dir()}. Import a binary first with "
                    f"ghidra_import_and_analyze, or list existing projects with "
                    f"ghidra_list_projects."
                ) from exc
            self._key = (project_name, "")
            return self._project

    def list_projects(self) -> list[dict[str, Any]]:
        """Lists Ghidra projects found in the project store (no JVM needed)."""
        root = config.projects_dir()
        projects: list[dict[str, Any]] = []
        for child in sorted(root.iterdir()):
            if child.is_dir() and (child / f"{child.name}.gpr").is_file():
                projects.append({"name": child.name, "location": str(root)})
            elif child.suffix == ".gpr":
                projects.append({"name": child.stem, "location": str(root)})
        return projects

    def list_programs(self, project_name: str) -> list[dict[str, Any]]:
        """Lists the programs (imported binaries) inside a project."""
        with self._lock:
            self.start()
            own_project = (
                self._project is not None and self._key is not None
                and self._key[0] == project_name
            )
            if own_project:
                project = self._project
            else:
                try:
                    project = self._pyghidra.open_project(
                        str(config.projects_dir()), project_name, create=False
                    )
                except FileNotFoundError as exc:
                    raise GhidraError(
                        f"Ghidra project '{project_name}' does not exist in "
                        f"{config.projects_dir()}."
                    ) from exc

            programs: list[dict[str, Any]] = []
            current = self._program_name()

            def collect(domain_file) -> None:
                try:
                    # Ghidra 12 returns a String here (older versions returned a Class).
                    content_type = str(domain_file.getContentType())
                    if "Program" not in content_type:
                        return
                    entry: dict[str, Any] = {
                        "name": str(domain_file.getName()),
                        "path": str(domain_file.getPathname()),
                        "content_type": content_type,
                        "open": str(domain_file.getName()) == current,
                    }
                    for label, getter in (("file_id", domain_file.getFileID),
                                          ("version", domain_file.getVersion)):
                        try:
                            entry[label] = str(getter())
                        except Exception:  # noqa: BLE001
                            entry[label] = None
                    programs.append(entry)
                except Exception:  # noqa: BLE001 - skip unreadable entries
                    return

            try:
                self._pyghidra.walk_project(project, collect)
            finally:
                if not own_project:
                    project.close()
            return programs

    def ensure_program(
        self,
        binary_path: str | None = None,
        project_name: str = "default",
        program_name: str | None = None,
        analyze: bool = True,
        timeout: int | None = None,
        force_reimport: bool = False,
        language: str | None = None,
    ) -> dict[str, Any]:
        """Imports (if needed), analyses (if needed) and opens a program.

        Returns a summary of what happened. Re-opening the same program is a no-op.
        """
        with self._lock:
            self.start()
            if program_name is None:
                if not binary_path:
                    raise GhidraError("program_name is required when binary_path is not given.")
                program_name = Path(binary_path).name
            program_name = program_name.lstrip("/").strip()
            if not program_name:
                raise GhidraError("program_name must not be empty.")

            key = (project_name, program_name)
            if self._key == key and self._program is not None:
                return {"program": program_name, "project": project_name,
                        "cached": True, "imported": False, "analyzed": False}

            timeout = timeout or config.default_timeout()
            summary: dict[str, Any] = {"program": program_name, "project": project_name,
                                       "cached": False, "imported": False, "analyzed": False}
            started = time.time()
            try:
                self.close()
                project = self.open_project(project_name, create=binary_path is not None)
                program_path = "/" + program_name
                domain_file = project.getProjectData().getFile(program_path)

                if binary_path is not None and (domain_file is None or force_reimport):
                    binary = Path(binary_path)
                    if not binary.is_file():
                        raise GhidraError(f"binary not found: {binary}")
                    loader = (
                        self._pyghidra.program_loader()
                        .project(project)
                        .source(str(binary))
                        .name(program_name)
                    )
                    if language:
                        loader = loader.language(language)
                    with loader.load() as load_results:
                        load_results.save(self._pyghidra.task_monitor(timeout))
                    domain_file = project.getProjectData().getFile(program_path)
                    summary["imported"] = True

                if domain_file is None:
                    raise GhidraError(
                        f"program '{program_name}' was not found in project '{project_name}'. "
                        f"Use ghidra_list_programs to see what is available, or pass "
                        f"binary_path to import it."
                    )

                program, consumer = self._pyghidra.consume_program(project, program_path)
                self._program, self._consumer = program, consumer
                self._key = key

                if analyze:
                    from ghidra.program.util import GhidraProgramUtilities

                    if (summary["imported"] or force_reimport
                            or GhidraProgramUtilities.shouldAskToAnalyze(program)):
                        self._analysis_log = self._pyghidra.analyze(
                            program, self._pyghidra.task_monitor(timeout)
                        )
                        program.save("Analyzed", self._pyghidra.task_monitor(timeout))
                        summary["analyzed"] = True

                summary.update({
                    "language": program.getLanguageID().toString(),
                    "compiler": program.getCompilerSpec().getCompilerSpecID().toString(),
                    "md5": program.getExecutableMD5(),
                    "image_base": program.getImageBase().toString(),
                    "function_count": program.getFunctionManager().getFunctionCount(),
                    "elapsed_seconds": round(time.time() - started, 1),
                })
                if summary["analyzed"] and self._analysis_log:
                    summary["analysis_log_tail"] = self._analysis_log[-1000:]
                return summary
            except GhidraError:
                self.close()
                raise
            except Exception as exc:  # noqa: BLE001 - normalise Ghidra/Java errors
                self.close()
                raise GhidraError(
                    f"failed to open/import program '{program_name}' in project "
                    f"'{project_name}': {type(exc).__name__}: {exc}"
                ) from exc

    def require_program(self):
        """Returns the currently open Ghidra program or raises a helpful error."""
        with self._lock:
            if self._program is None:
                raise GhidraError(
                    "no program is open. Call ghidra_import_and_analyze (to import a binary) "
                    "or ghidra_open_program (to reuse an analysed one) first."
                )
            return self._program

    def task_monitor(self, timeout: int | None = None):
        return self._pyghidra.task_monitor(timeout or config.default_timeout())

    @property
    def lock(self) -> threading.RLock:
        """Re-entrant lock guarding the JVM/project/program (Ghidra is not thread safe)."""
        return self._lock


#: Shared session for the MCP server (one JVM per server process).
SESSION = GhidraSession()
