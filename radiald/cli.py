from __future__ import annotations

import argparse
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from .core import RadialExecutor
from .graph import RadialGraphExecutor, Stage


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

    print("RadialD v0.2 single-node demo")
    print(f"logical requests:       {stats.logical_requests}")
    print(f"physical executions:    {stats.physical_executions}")
    print(f"shared requests:        {stats.shared_requests}")
    print(f"work avoided:           {stats.work_avoided_ratio:.1%}")
    print(f"compute function calls: {calls}")
    print(f"output equivalence:     {len(set(digests)) == 1}")
    print(f"elapsed:                {elapsed:.3f}s")
    return 0 if calls == 1 and len(set(digests)) == 1 else 1


def _graph_demo(delay: float) -> int:
    graph = RadialGraphExecutor()
    barrier = threading.Barrier(2)
    calls = {"A": 0, "B": 0, "X": 0, "Y": 0}
    lock = threading.Lock()

    def step(name: str):
        def transform(value: str) -> str:
            with lock:
                calls[name] += 1
            time.sleep(delay)
            return value + name
        return transform

    prefix = [Stage("A:v1", step("A")), Stage("B:v1", step("B"))]
    left = prefix + [Stage("X:v1", step("X"))]
    right = prefix + [Stage("Y:v1", step("Y"))]

    def one(stages):
        barrier.wait()
        return graph.run(authority="demo", initial="", stages=stages)

    with ThreadPoolExecutor(max_workers=2) as pool:
        left_result, right_result = list(pool.map(one, [left, right]))

    stats = graph.stats()
    expected_calls = {"A": 1, "B": 1, "X": 1, "Y": 1}
    passed = (
        calls == expected_calls
        and left_result.value == "ABX"
        and right_result.value == "ABY"
        and stats.physical_executions == 4
        and stats.logical_requests == 6
    )

    print("RadialD v0.2 graph demo")
    print("logical pipelines:      2")
    print("logical node requests:  6")
    print(f"physical executions:    {stats.physical_executions}")
    print("shared prefix:          A -> B")
    print("fracture:               X / Y")
    print(f"left result:            {left_result.value}")
    print(f"right result:           {right_result.value}")
    print(f"stage calls:            {calls}")
    print(f"gate:                   {'PASS' if passed else 'FAIL'}")
    return 0 if passed else 1


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="radiald",
        description="Authority-safe concurrent compute deduplication.",
    )
    sub = parser.add_subparsers(dest="command")

    demo = sub.add_parser("demo", help="run the single-node sharing demo")
    demo.add_argument("--jobs", type=int, default=32)
    demo.add_argument("--delay", type=float, default=0.05)

    graph_demo = sub.add_parser(
        "graph-demo", help="run the shared-prefix / divergent-suffix demo"
    )
    graph_demo.add_argument("--delay", type=float, default=0.05)

    args = parser.parse_args()

    if args.command in (None, "demo"):
        jobs = getattr(args, "jobs", 32)
        delay = getattr(args, "delay", 0.05)
        if jobs < 2:
            parser.error("--jobs must be at least 2")
        return _demo(jobs, delay)
    if args.command == "graph-demo":
        return _graph_demo(args.delay)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
