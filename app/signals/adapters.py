"""Fixed, scope-safe command construction for signal tools."""
from urllib.parse import urlparse

from app.recon.adapters import ToolCommand


class NucleiAdapter:
    name = "nuclei"

    def build_command(self, base_url: str) -> ToolCommand:
        parsed = urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Nuclei requires an absolute HTTP(S) URL.")
        return ToolCommand(
            "nuclei",
            ("-u", base_url, "-jsonl", "-silent", "-severity", "low,medium,high,critical", "-rate-limit", "10", "-c", "5"),
            600,
        )
