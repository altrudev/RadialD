import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

from radiald import RadialGraphExecutor, Stage


class RadialGraphTests(unittest.TestCase):
    def test_identical_concurrent_pipelines_share_every_node(self):
        graph = RadialGraphExecutor()
        workers = 8
        barrier = threading.Barrier(workers)
        calls = {"a": 0, "b": 0, "c": 0}
        lock = threading.Lock()

        def step(name, delta):
            def transform(value):
                with lock:
                    calls[name] += 1
                time.sleep(0.03)
                return value + delta
            return transform

        stages = [
            Stage("a:v1", step("a", 1)),
            Stage("b:v1", step("b", 2)),
            Stage("c:v1", step("c", 3)),
        ]

        def job(_):
            barrier.wait()
            return graph.run(authority="A", initial=10, stages=stages)

        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(job, range(workers)))

        self.assertEqual(calls, {"a": 1, "b": 1, "c": 1})
        self.assertEqual({result.value for result in results}, {16})
        self.assertEqual({result.digest for result in results}, {results[0].digest})
        self.assertEqual(graph.stats().physical_executions, 3)
        self.assertEqual(graph.stats().logical_requests, workers * 3)

    def test_shared_prefix_fractures_at_first_divergent_stage(self):
        graph = RadialGraphExecutor()
        barrier = threading.Barrier(2)
        calls = {"a": 0, "b": 0, "x": 0, "y": 0}
        lock = threading.Lock()

        def step(name, suffix):
            def transform(value):
                with lock:
                    calls[name] += 1
                time.sleep(0.04 if name in {"a", "b"} else 0.02)
                return f"{value}{suffix}"
            return transform

        prefix = [Stage("a:v1", step("a", "A")), Stage("b:v1", step("b", "B"))]
        left = prefix + [Stage("x:v1", step("x", "X"))]
        right = prefix + [Stage("y:v1", step("y", "Y"))]

        def job(stages):
            barrier.wait()
            return graph.run(authority="A", initial="", stages=stages)

        with ThreadPoolExecutor(max_workers=2) as pool:
            left_result, right_result = list(pool.map(job, [left, right]))

        self.assertEqual(calls, {"a": 1, "b": 1, "x": 1, "y": 1})
        self.assertEqual(left_result.value, "ABX")
        self.assertEqual(right_result.value, "ABY")
        self.assertEqual(graph.stats().physical_executions, 4)
        self.assertEqual(graph.stats().logical_requests, 6)

    def test_diverged_lineages_do_not_rejoin_on_equal_value(self):
        graph = RadialGraphExecutor()
        barrier = threading.Barrier(2)
        calls = {"root": 0, "left": 0, "right": 0, "tail": 0}
        lock = threading.Lock()

        def counted(name, fn, delay=0.03):
            def transform(value):
                with lock:
                    calls[name] += 1
                time.sleep(delay)
                return fn(value)
            return transform

        root = Stage("root:v1", counted("root", lambda v: v + 1))
        left = Stage("left:v1", counted("left", lambda v: 100))
        right = Stage("right:v1", counted("right", lambda v: 100))
        tail = Stage("tail:v1", counted("tail", lambda v: v * 2, delay=0.05))

        def job(stages):
            barrier.wait()
            return graph.run(authority="A", initial=0, stages=stages)

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(job, [[root, left, tail], [root, right, tail]]))

        self.assertEqual([r.value for r in results], [200, 200])
        self.assertEqual(calls["root"], 1)
        self.assertEqual(calls["left"], 1)
        self.assertEqual(calls["right"], 1)
        self.assertEqual(calls["tail"], 2)

    def test_same_graph_different_authorities_never_share(self):
        graph = RadialGraphExecutor()
        barrier = threading.Barrier(2)
        calls = 0
        lock = threading.Lock()

        def transform(value):
            nonlocal calls
            with lock:
                calls += 1
            time.sleep(0.04)
            return value + 1

        stages = [Stage("step:v1", transform)]

        def job(authority):
            barrier.wait()
            return graph.run(authority=authority, initial=1, stages=stages)

        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(job, ["tenant-A", "tenant-B"]))

        self.assertEqual(calls, 2)
        self.assertEqual(graph.stats().physical_executions, 2)
        self.assertGreaterEqual(graph.stats().refused_cross_authority, 1)

    def test_different_initial_state_prevents_prefix_sharing(self):
        graph = RadialGraphExecutor()
        barrier = threading.Barrier(2)
        calls = 0
        lock = threading.Lock()

        def transform(value):
            nonlocal calls
            with lock:
                calls += 1
            time.sleep(0.04)
            return value + 1

        stages = [Stage("step:v1", transform)]

        def job(value):
            barrier.wait()
            return graph.run(authority="A", initial=value, stages=stages)

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(job, [1, 2]))

        self.assertEqual(calls, 2)
        self.assertCountEqual([r.value for r in results], [2, 3])

    def test_stage_verifier_failure_reaches_prefix_joiners(self):
        graph = RadialGraphExecutor()
        workers = 4
        barrier = threading.Barrier(workers)
        stages = [
            Stage(
                "reject:v1",
                lambda value: (time.sleep(0.04), value + 1)[1],
                verifier=lambda value: value < 0,
            )
        ]

        def job(_):
            barrier.wait()
            return graph.run(authority="A", initial=0, stages=stages)

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(job, i) for i in range(workers)]
            for future in futures:
                with self.assertRaises(ValueError):
                    future.result()

        self.assertEqual(graph.stats().physical_executions, 1)

    def test_graph_matches_isolated_execution(self):
        graph = RadialGraphExecutor()
        stages = [
            Stage("inc:v1", lambda v: v + 1),
            Stage("square:v1", lambda v: v * v),
            Stage("format:v1", lambda v: {"answer": v}),
        ]
        result = graph.run(authority="A", initial=4, stages=stages)

        isolated = 4
        for stage in stages:
            isolated = stage.transform(isolated)

        self.assertEqual(result.value, isolated)
        self.assertEqual(result.value, {"answer": 25})
        self.assertEqual(len(result.trace), 3)


if __name__ == "__main__":
    unittest.main()
