"""In-process structured metrics for mcp-witness operations."""

import threading
from typing import Dict

__all__ = [
    "Counter",
    "Histogram",
    "get_metrics",
    "chain_breaks",
    "signature_failures",
    "anchor_verification_failures",
    "rate_limit_hits",
    "idempotency_duplicates",
    "records_written",
    "records_read",
    "lock_contention",
]


class Counter:
    """Thread-safe monotonic counter."""

    def __init__(self) -> None:
        self._value = 0
        self._lock = threading.Lock()

    def inc(self, delta: int = 1) -> None:
        """Increment the counter by delta."""
        with self._lock:
            self._value += delta

    def get(self) -> int:
        """Get the current counter value."""
        with self._lock:
            return self._value


class Histogram:
    """Thread-safe histogram collecting observation values."""

    def __init__(self) -> None:
        self._values: list[float] = []
        self._lock = threading.Lock()

    def observe(self, value: float) -> None:
        """Record a single observation."""
        with self._lock:
            self._values.append(value)

    def summary(self) -> dict:
        """Return a summary dict with count, sum, avg, p95."""
        with self._lock:
            if not self._values:
                return {"count": 0, "sum": 0, "avg": 0, "p95": 0}
            sorted_vals = sorted(self._values)
            return {
                "count": len(sorted_vals),
                "sum": sum(sorted_vals),
                "avg": sum(sorted_vals) / len(sorted_vals),
                "p95": sorted_vals[int(len(sorted_vals) * 0.95)],
            }


# Metric counters
chain_breaks = Counter()
signature_failures = Counter()
anchor_verification_failures = Counter()
rate_limit_hits = Counter()
idempotency_duplicates = Counter()
records_written = Counter()
records_read = Counter()
lock_contention = Histogram()


def get_metrics() -> Dict:
    """Return all metrics as a dict."""
    return {
        "chain_breaks_total": chain_breaks.get(),
        "signature_failures_total": signature_failures.get(),
        "anchor_verification_failures_total": anchor_verification_failures.get(),
        "rate_limit_hits_total": rate_limit_hits.get(),
        "idempotency_duplicates_total": idempotency_duplicates.get(),
        "records_written_total": records_written.get(),
        "records_read_total": records_read.get(),
        "lock_contention": lock_contention.summary(),
    }
