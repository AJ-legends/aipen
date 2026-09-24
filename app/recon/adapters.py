"""Recon tool command builders. Execution is delegated to the bounded runner."""
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True, slots=True)
class ToolCommand:
    executable: str
    arguments: tuple[str, ...]
    timeout_seconds: int

    @property
    def argv(self) -> tuple[str, ...]:
        return (self.executable, *self.arguments)


class NmapAdapter:
    name = "nmap"

    def build_command(self, hostname: str, ports: list[int]) -> ToolCommand:
        safe_ports = ",".join(str(port) for port in sorted(set(ports)))
        return ToolCommand("nmap", ("-Pn", "-sV", "--version-light", "--open", "-p", safe_ports, "-oX", "-", hostname), 300)


class HttpxAdapter:
    name = "httpx"

    def build_command(self, target_url: str) -> ToolCommand:
        parsed = urlparse(target_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("httpx requires an absolute HTTP(S) URL.")
        return ToolCommand("httpx", ("-u", target_url, "-json", "-silent", "-status-code", "-title", "-tech-detect", "-web-server"), 120)
