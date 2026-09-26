"""Fixed, scope-safe command construction for discovery tools."""
from pathlib import Path
from urllib.parse import urlparse

from app.recon.adapters import ToolCommand


def _http_url(value: str) -> None:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Discovery requires an absolute HTTP(S) URL.")


def resolve_wordlist(wordlist_path: str, allowed_dirs: tuple[Path, ...]) -> Path:
    """Resolve a wordlist path inside one of the allowed directories.

    Raises ValueError for missing/unreadable files and PermissionError for
    paths escaping the allow-list (traversal guard).
    """
    if not wordlist_path or "\x00" in wordlist_path:
        raise ValueError("ffuf requires an explicitly configured wordlist.")
    candidate = Path(wordlist_path).expanduser()
    if not candidate.is_absolute():
        candidate = (allowed_dirs[0] / candidate) if allowed_dirs else candidate.absolute()
    resolved = candidate.resolve()
    for base in allowed_dirs:
        try:
            resolved.relative_to(base.resolve())
            break
        except ValueError:
            continue
    else:
        raise PermissionError(f"Wordlist is outside allowed directories: {wordlist_path}")
    if not resolved.is_file():
        raise ValueError(f"Wordlist does not exist: {wordlist_path}")
    return resolved


class KatanaAdapter:
    name = "katana"

    def build_command(self, base_url: str) -> ToolCommand:
        _http_url(base_url)
        return ToolCommand("katana", ("-u", base_url, "-jsonl", "-silent", "-depth", "3", "-c", "5", "-rl", "10"), 300)


class FfufAdapter:
    name = "ffuf"

    def build_command(
        self, base_url: str, wordlist_path: str, allowed_dirs: tuple[Path, ...] = (Path("data/wordlists"),)
    ) -> ToolCommand:
        _http_url(base_url)
        resolved = resolve_wordlist(wordlist_path, allowed_dirs)
        target = base_url.rstrip("/") + "/FUZZ"
        return ToolCommand("ffuf", ("-u", target, "-w", str(resolved), "-mc", "200,204,301,302,307,401,403", "-rate", "10", "-of", "json", "-o", "-"), 300)
