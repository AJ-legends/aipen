"""Fixed, scope-safe command construction for discovery tools."""
from urllib.parse import urlparse

from app.recon.adapters import ToolCommand


def _http_url(value: str) -> None:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Discovery requires an absolute HTTP(S) URL.")


class KatanaAdapter:
    name = "katana"

    def build_command(self, base_url: str) -> ToolCommand:
        _http_url(base_url)
        return ToolCommand("katana", ("-u", base_url, "-jsonl", "-silent", "-depth", "3", "-c", "5", "-rl", "10"), 300)


class FfufAdapter:
    name = "ffuf"

    def build_command(self, base_url: str, wordlist_path: str) -> ToolCommand:
        _http_url(base_url)
        if not wordlist_path:
            raise ValueError("ffuf requires an explicitly configured wordlist.")
        target = base_url.rstrip("/") + "/FUZZ"
        return ToolCommand("ffuf", ("-u", target, "-w", wordlist_path, "-mc", "200,204,301,302,307,401,403", "-rate", "10", "-of", "json", "-o", "-"), 300)
