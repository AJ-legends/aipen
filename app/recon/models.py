from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class ServiceRecord:
    port: int
    protocol: str
    name: str | None = None
    product: str | None = None
    version: str | None = None
    banner: str | None = None


@dataclass(frozen=True, slots=True)
class HostRecord:
    ip: str
    hostname: str | None
    services: tuple[ServiceRecord, ...] = ()


@dataclass(frozen=True, slots=True)
class HttpProbeRecord:
    url: str
    status_code: int | None = None
    title: str | None = None
    webserver: str | None = None
    technologies: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ReconResult:
    hosts: tuple[HostRecord, ...] = ()
    probes: tuple[HttpProbeRecord, ...] = ()
    warnings: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class ApplicationProfile:
    tech_stack: tuple[str, ...] = ()
    entry_points: tuple[str, ...] = ()
    auth_surfaces: tuple[str, ...] = ()
    api_indicators: tuple[str, ...] = ()
    notes: str = ""
