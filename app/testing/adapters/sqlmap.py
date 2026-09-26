"""Thin sqlmap adapter: fixed argv, bounded execution, structured parse.

Escalation only: invoked with a single flagged URL + parameter, never free-form.
"""
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

SQLMAP_TIMEOUT_SECONDS = 300
MAX_OUTPUT_BYTES = 5_000_000
_INJECTABLE_RE = re.compile(r"parameter\s+'([^']+)'\s+is\s+([^\n]+?injectable[^\n]*)", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class SqlmapCommand:
    url: str
    parameter: str
    output_dir: Path

    @property
    def argv(self) -> tuple[str, ...]:
        return (
            "sqlmap",
            "--batch",
            "--level=2",
            "--risk=1",
            "-u",
            self.url,
            "-p",
            self.parameter,
            "--output-dir",
            str(self.output_dir),
        )


@dataclass(frozen=True, slots=True)
class SqlmapFinding:
    parameter: str
    detail: str


@dataclass(frozen=True, slots=True)
class SqlmapResult:
    findings: tuple[SqlmapFinding, ...]
    raw: bytes


class SqlmapError(RuntimeError):
    pass


def build_command(url: str, parameter: str, output_dir: Path) -> SqlmapCommand:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("sqlmap requires an absolute HTTP(S) URL.")
    if not parameter or any(char.isspace() for char in parameter):
        raise ValueError("sqlmap requires a single parameter name.")
    return SqlmapCommand(url=url, parameter=parameter, output_dir=output_dir)


def parse_output(payload: bytes) -> tuple[SqlmapFinding, ...]:
    text = payload.decode("utf-8", errors="replace")
    return tuple(SqlmapFinding(parameter=match.group(1), detail=match.group(2).strip()) for match in _INJECTABLE_RE.finditer(text))


def execute(command: SqlmapCommand) -> SqlmapResult:
    try:
        completed = subprocess.run(
            command.argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=SQLMAP_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError as error:
        raise SqlmapError("Required tool is unavailable: sqlmap") from error
    except subprocess.TimeoutExpired as error:
        raise SqlmapError(f"sqlmap exceeded its {SQLMAP_TIMEOUT_SECONDS}s timeout") from error
    if len(completed.stdout) > MAX_OUTPUT_BYTES or len(completed.stderr) > MAX_OUTPUT_BYTES:
        raise SqlmapError("sqlmap exceeded the output-size limit")
    return SqlmapResult(findings=parse_output(completed.stdout), raw=completed.stdout)
