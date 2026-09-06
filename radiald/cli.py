from __future__ import annotations

import argparse
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from .core import RadialExecutor


def _demo(jobs: int, delay: float) -> int:
    engine = RadialExecutor()
    barrier = threading.Barrier(jobs)
    calls = 0
    lock = threading.Lock()

    def compute() -> dict[str, int]:
        nonlocal calls
        with lock:
            calls += 1
        time.sleep(delay)
        return {"answer": 42}

    def one(_: int) -> str:
        barrier.wait()
        return engine.run(
            authority="demo",
            work_key="same-deterministic-input",
            compute=compute,
            verifier=lambda value: value.get("answer") == 42,
        ).digest

    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        digests = list(pool.map(one, range(jobs)))
    elapsed = time.perf_counter() - start
    stats = engine.stats()

    print("RadialD v0.1 demo")
    print(f"logical requests:       {stats.logical_requests}")
    print(f"physical executions:    {stats.physical_executions}")
    print(f"shared requests:        {stats.shared_requests}")
    print(f"work avoided:           {stats.work_avoided_ratio:.1%}")
    print(f"compute function calls: {calls}")
    print(f"output equivalence:     {len(set(digests)) == 1}")
    print(f"elapsed:                {elapsed:.3f}s")
    return 0 if calls == 1 and len(set(digests)) == 1 else 1


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="radiald",
        description="Authority-safe concurrent compute deduplication.",
    )
    sub = parser.add_subparsers(dest="command")
    demo = sub.add_parser("demo", help="run the deterministic sharing demo")
    demo.add_argument("--jobs", type=int, default=32)
    demo.add_argument("--delay", type=float, default=0.05)
    args = parser.parse_args()

    if args.command in (None, "demo"):
        jobs = getattr(args, "jobs", 32)
        delay = getattr(args, "delay", 0.05)
        if jobs < 2:
            parser.error("--jobs must be at least 2")
        return _demo(jobs, delay)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
