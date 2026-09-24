from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class DiscoveredEndpoint:
    url: str
    method: str = "GET"
    parameters: tuple[str, ...] = ()
    form_fields: tuple[str, ...] = ()
    is_api: bool = False
    source: str = ""


@dataclass(frozen=True, slots=True)
class DiscoveryResult:
    endpoints: tuple[DiscoveredEndpoint, ...] = ()
    warnings: tuple[str, ...] = field(default_factory=tuple)
