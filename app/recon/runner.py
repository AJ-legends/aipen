"""Bounded subprocess runner; it has no target knowledge and must be called through ReconService."""
import subprocess
from dataclasses import dataclass

from app.recon.adapters import ToolCommand

MAX_OUTPUT_BYTES = 5_000_000


@dataclass(frozen=True, slots=True)
class ToolExecution:
    stdout: bytes
    stderr: bytes
    return_code: int


class ToolExecutionError(RuntimeError):
    pass


def execute(command: ToolCommand) -> ToolExecution:
    try:
        completed = subprocess.run(command.argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=command.timeout_seconds, check=False)
    except FileNotFoundError as error:
        raise ToolExecutionError(f"Required tool is unavailable: {command.executable}") from error
    except subprocess.TimeoutExpired as error:
        raise ToolExecutionError(f"{command.executable} exceeded its {command.timeout_seconds}s timeout") from error
    if len(completed.stdout) > MAX_OUTPUT_BYTES or len(completed.stderr) > MAX_OUTPUT_BYTES:
        raise ToolExecutionError(f"{command.executable} exceeded the output-size limit")
    return ToolExecution(stdout=completed.stdout, stderr=completed.stderr, return_code=completed.returncode)
