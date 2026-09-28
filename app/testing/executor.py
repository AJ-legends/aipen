"""Async differential HTTP executor with per-host token-bucket rate limiting.

The executor has no policy knowledge: the caller (TestingService) must run
``check_action`` and record the ``test_actions`` row before invoking it.
"""
import asyncio
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse
from uuid import UUID, uuid4

import httpx

from app.core.db import connection, json_value
from app.testing.models import CapturedResponse, Probe, ProbeOutcome, ResponseDiff

MAX_BODY_BYTES = 2_000_000
REQUEST_TIMEOUT_SECONDS = 15.0
TIMING_ANOMALY_FLOOR_MS = 1500.0
TIMING_ANOMALY_RATIO = 3.0


@dataclass(slots=True)
class _Bucket:
    tokens: float
    updated: float


@dataclass(slots=True)
class RateLimiter:
    """Token-bucket limiter, one bucket per host. Async; sleeps only as long as needed."""

    rate_per_second: float = 10.0
    _buckets: dict[str, _Bucket] = field(default_factory=dict)

    @property
    def burst(self) -> int:
        return max(1, int(self.rate_per_second))

    async def acquire(self, host: str) -> None:
        now = time.monotonic()
        bucket = self._buckets.get(host)
        if bucket is None:
            bucket = _Bucket(tokens=float(self.burst - 1), updated=now)
            self._buckets[host] = bucket
            return
        elapsed = now - bucket.updated
        bucket.tokens = min(float(self.burst), bucket.tokens + elapsed * self.rate_per_second)
        bucket.updated = now
        if bucket.tokens >= 1.0:
            bucket.tokens -= 1.0
            return
        deficit = 1.0 - bucket.tokens
        await asyncio.sleep(deficit / self.rate_per_second)
        bucket.tokens = 0.0
        bucket.updated = time.monotonic()


class TestExecutor:
    __test__ = False  # not a pytest test class despite the name

    def __init__(
        self,
        database_path: Path,
        artifacts_dir: Path,
        rate_per_second: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.database_path = database_path
        self.artifacts_dir = artifacts_dir
        self.limiter = RateLimiter(rate_per_second=rate_per_second)
        self._transport = transport

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=self._transport,
            timeout=REQUEST_TIMEOUT_SECONDS,
            follow_redirects=False,
            headers={"User-Agent": "AIPEN-test-executor/0.1"},
        )

    async def fetch(self, url: str, params: dict[str, str] | None = None, headers: dict[str, str] | None = None) -> CapturedResponse:
        host = urlparse(url).hostname or ""
        await self.limiter.acquire(host)
        started = time.perf_counter()
        async with self._client() as client:
            response = await client.get(url, params=params, headers=headers)
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        body = response.content[:MAX_BODY_BYTES]
        return CapturedResponse(
            url=str(response.url),
            status_code=response.status_code,
            length=len(response.content),
            headers=dict(response.headers),
            body=body,
            elapsed_ms=elapsed_ms,
        )

    @staticmethod
    def diff(baseline: CapturedResponse, mutated: CapturedResponse, markers: tuple[str, ...] = ()) -> ResponseDiff:
        body_text = mutated.body.decode("utf-8", errors="replace")
        lowered = body_text.lower()
        hits = tuple(marker for marker in markers if marker.lower() in lowered)
        timing_delta = mutated.elapsed_ms - baseline.elapsed_ms
        # Adaptive: absolute floor for fast hosts, ratio-based for slow ones,
        # so sluggish targets don't false-positive every time-based probe.
        threshold = max(TIMING_ANOMALY_FLOOR_MS, TIMING_ANOMALY_RATIO * baseline.elapsed_ms)
        return ResponseDiff(
            status_changed=mutated.status_code != baseline.status_code,
            length_delta=mutated.length - baseline.length,
            markers=hits,
            timing_ms=timing_delta,
            timing_anomaly=timing_delta >= threshold,
        )

    async def run_probe(
        self,
        action_id: UUID,
        run_id: UUID | None,
        url: str,
        param: str,
        baseline_value: str,
        probe: Probe,
        markers: tuple[str, ...] = (),
        baseline_headers: dict[str, str] | None = None,
        mutated_headers: dict[str, str] | None = None,
    ) -> ProbeOutcome:
        baseline = await self.fetch(url, params={param: baseline_value} if param else None, headers=baseline_headers)
        mutated = await self.fetch(url, params={param: probe.payload} if param else None, headers=mutated_headers)
        outcome_diff = self.diff(baseline, mutated, markers)
        signals: list[str] = []
        if outcome_diff.markers:
            signals.append(f"markers:{','.join(outcome_diff.markers)}")
        if outcome_diff.status_changed:
            signals.append(f"status:{baseline.status_code}->{mutated.status_code}")
        if outcome_diff.timing_anomaly:
            signals.append(f"timing:+{outcome_diff.timing_ms:.0f}ms")
        outcome = ProbeOutcome(probe=probe, baseline=baseline, mutated=mutated, diff=outcome_diff, signals=tuple(signals))
        self._record(action_id, run_id, outcome)
        return outcome

    def _record(self, action_id: UUID, run_id: UUID | None, outcome: ProbeOutcome) -> None:
        del run_id  # linkage lives on the test_actions row; artifacts key off the action.
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        baseline_ref = self._write_artifact(action_id, "baseline", outcome.baseline.body)
        mutated_ref = self._write_artifact(action_id, f"mutated-{outcome.probe.kind}", outcome.mutated.body)
        analysis = {
            "module": outcome.probe.module,
            "kind": outcome.probe.kind,
            "param": outcome.probe.param,
            "payload": outcome.probe.payload,
            "baseline": {"url": outcome.baseline.url, "status": outcome.baseline.status_code, "length": outcome.baseline.length},
            "mutated": {"url": outcome.mutated.url, "status": outcome.mutated.status_code, "length": outcome.mutated.length},
            "diff": {
                "status_changed": outcome.diff.status_changed,
                "length_delta": outcome.diff.length_delta,
                "markers": list(outcome.diff.markers),
                "timing_ms": outcome.diff.timing_ms,
                "timing_anomaly": outcome.diff.timing_anomaly,
            },
            "signals": list(outcome.signals),
        }
        with connection(self.database_path) as db:
            db.execute(
                "INSERT INTO evidence (id, test_action_id, kind, artifact_ref, analysis, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    str(uuid4()),
                    str(action_id),
                    "diff",
                    f"{baseline_ref}|{mutated_ref}",
                    json_value(analysis),
                    datetime.now(UTC).isoformat(),
                ),
            )

    def _write_artifact(self, action_id: UUID, name: str, body: bytes) -> str:
        safe = "".join(char if char.isalnum() or char in "-_" else "_" for char in name)[:40]
        path = self.artifacts_dir / f"{action_id}-{safe}.raw"
        path.write_bytes(body)
        return str(path)


def hosts_of(url: str) -> str:
    return urlparse(url).hostname or ""


__all__ = ["MAX_BODY_BYTES", "REQUEST_TIMEOUT_SECONDS", "RateLimiter", "TestExecutor", "hosts_of"]
