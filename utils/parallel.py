"""
Parallel execution engine — runs per-host operations concurrently
using a thread pool with progress tracking and error isolation.

Each host's work is isolated: if one host's enumeration fails,
the others continue unaffected.
"""

import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from typing import Callable, Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class ParallelResult:
    """Aggregated results from parallel execution."""

    total: int = 0
    succeeded: int = 0
    failed: int = 0
    results: Dict[str, Any] = field(default_factory=dict)
    errors: Dict[str, str] = field(default_factory=dict)
    duration: float = 0.0


class ParallelRunner:
    """
    Execute per-host operations in parallel with controlled concurrency.

    Features:
        - Configurable thread pool size
        - Per-host error isolation (one failure doesn't stop others)
        - Progress logging with completion percentage
        - Thread-safe result aggregation
        - Graceful shutdown on interrupt

    Usage:
        runner = ParallelRunner(max_workers=10)
        results = runner.run_per_host(
            hosts=["192.168.1.1", "192.168.1.2", ...],
            func=my_scan_function,    # func(host_ip) -> dict
            description="Scanning",
        )
    """

    def __init__(self, max_workers: int = 10):
        self.max_workers = max(1, min(max_workers, 50))
        self._lock = threading.Lock()
        self._completed = 0
        self._total = 0

    def run_per_host(
        self,
        hosts: List[str],
        func: Callable[[str], Any],
        description: str = "Processing",
        timeout_per_host: Optional[int] = None,
    ) -> ParallelResult:
        """
        Execute a function against each host in parallel.

        Args:
            hosts:             List of host IPs/hostnames
            func:              Function taking a single host string, returning a dict
            description:       Label for progress logging
            timeout_per_host:  Optional per-host timeout in seconds

        Returns:
            ParallelResult with aggregated results and errors
        """
        result = ParallelResult(total=len(hosts))
        self._completed = 0
        self._total = len(hosts)

        if not hosts:
            return result

        # Use min of configured workers and host count
        workers = min(self.max_workers, len(hosts))

        if workers == 1:
            # Single-threaded fast path (no overhead)
            return self._run_sequential(hosts, func, description)

        logger.info(f"[PARALLEL] {description}: {len(hosts)} hosts, {workers} threads")

        start = datetime.now()

        try:
            with ThreadPoolExecutor(
                max_workers=workers,
                thread_name_prefix="pentestfw",
            ) as executor:
                # Submit all tasks
                future_to_host: Dict[Future, str] = {}
                for host in hosts:
                    future = executor.submit(self._safe_execute, func, host)
                    future_to_host[future] = host

                # Collect results as they complete
                for future in as_completed(
                    future_to_host,
                    timeout=timeout_per_host * len(hosts) if timeout_per_host else None,
                ):
                    host = future_to_host[future]
                    try:
                        host_result, error = future.result(timeout=5)
                        if error:
                            result.errors[host] = error
                            result.failed += 1
                        else:
                            result.results[host] = host_result
                            result.succeeded += 1
                    except Exception as e:
                        result.errors[host] = str(e)
                        result.failed += 1
                        logger.error(f"[PARALLEL] {host} failed: {e}")

                    # Progress logging
                    with self._lock:
                        self._completed += 1
                        pct = (self._completed / self._total) * 100
                        logger.info(
                            f"[PARALLEL] {description}: "
                            f"{self._completed}/{self._total} "
                            f"({pct:.0f}%) — {host} done"
                        )

        except KeyboardInterrupt:
            logger.warning("[PARALLEL] Interrupted — returning partial results")

        result.duration = (datetime.now() - start).total_seconds()

        logger.info(
            f"[PARALLEL] {description} complete: "
            f"{result.succeeded} succeeded, {result.failed} failed "
            f"in {result.duration:.1f}s"
        )

        return result

    def _safe_execute(self, func: Callable, host: str) -> Tuple[Any, Optional[str]]:
        """Execute function with error isolation per host."""
        try:
            data = func(host)
            return data, None
        except Exception as e:
            logger.error(f"[PARALLEL] Exception on {host}: {type(e).__name__}: {e}")
            return None, f"{type(e).__name__}: {e}"

    def _run_sequential(
        self,
        hosts: List[str],
        func: Callable,
        description: str,
    ) -> ParallelResult:
        """Sequential fallback for single-host or single-thread scenarios."""
        result = ParallelResult(total=len(hosts))
        start = datetime.now()

        for i, host in enumerate(hosts, 1):
            try:
                host_result = func(host)
                result.results[host] = host_result
                result.succeeded += 1
            except Exception as e:
                result.errors[host] = str(e)
                result.failed += 1
                logger.error(f"[{description}] {host} failed: {e}")

            logger.info(f"[{description}] {i}/{len(hosts)} — {host} done")

        result.duration = (datetime.now() - start).total_seconds()
        return result


def run_parallel(
    items: List[Any],
    func: Callable[[Any], Any],
    max_workers: int = 10,
    description: str = "Processing",
) -> ParallelResult:
    """
    Convenience function — run a callable against a list of items in parallel.

    Args:
        items:        List of inputs to process
        func:         Function taking one item, returning a result
        max_workers:  Thread pool size
        description:  Label for logging

    Returns:
        ParallelResult
    """
    runner = ParallelRunner(max_workers=max_workers)
    return runner.run_per_host(
        hosts=[str(i) for i in items],
        func=lambda key: func(next(it for it in items if str(it) == key)),
        description=description,
    )
