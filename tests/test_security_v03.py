import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

from radiald import (
    CanonicalizationError,
    RadialExecutor,
    RadialGraphExecutor,
    Stage,
    stable_digest,
)


class SecurityHardeningTests(unittest.TestCase):
    def test_bool_and_int_authorities_do_not_coalesce(self):
        engine = RadialExecutor()
        barrier = threading.Barrier(2)
        calls = 0
        lock = threading.Lock()

        def job(authority):
            def compute():
                nonlocal calls
                with lock:
                    calls += 1
                time.sleep(0.03)
                return type(authority).__name__

            barrier.wait()
            return engine.run(
                authority=authority, work_key="same", compute=compute
            ).value

        with ThreadPoolExecutor(max_workers=2) as pool:
            values = list(pool.map(job, [True, 1]))

        self.assertCountEqual(values, ["bool", "int"])
        self.assertEqual(calls, 2)

    def test_list_and_tuple_initial_states_do_not_share(self):
        graph = RadialGraphExecutor()
        barrier = threading.Barrier(2)
        calls = 0
        lock = threading.Lock()

        def transform(value):
            nonlocal calls
            with lock:
                calls += 1
            time.sleep(0.03)
            return type(value).__name__

        stages = [Stage("type:v1", transform)]

        def job(value):
            barrier.wait()
            return graph.run(authority="A", initial=value, stages=stages).value

        with ThreadPoolExecutor(max_workers=2) as pool:
            values = list(pool.map(job, [[1], (1,)]))

        self.assertCountEqual(values, ["list", "tuple"])
        self.assertEqual(calls, 2)

    def test_dict_key_types_have_distinct_fingerprints(self):
        self.assertNotEqual(stable_digest({1: "x"}), stable_digest({"1": "x"}))

    def test_builtin_subclass_fails_closed(self):
        class Tenant(str):
            pass

        with self.assertRaises(CanonicalizationError):
            stable_digest(Tenant("tenant-A"))

    def test_joiner_verifier_is_not_bypassed(self):
        engine = RadialExecutor()
        started = threading.Event()

        def owner():
            def compute():
                started.set()
                time.sleep(0.05)
                return 7

            return engine.run(authority="A", work_key="K", compute=compute)

        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(owner)
            self.assertTrue(started.wait(timeout=1))
            second = pool.submit(
                lambda: engine.run(
                    authority="A",
                    work_key="K",
                    compute=lambda: 999,
                    verifier=lambda value: value == 999,
                )
            )
            first.result()
            with self.assertRaises(ValueError):
                second.result()

        stats = engine.stats()
        self.assertEqual(stats.join_attempts, 1)
        self.assertEqual(stats.shared_requests, 0)
        self.assertEqual(stats.rejected_shared_outputs, 1)

    def test_join_timeout_bounds_wait(self):
        engine = RadialExecutor()
        started = threading.Event()

        def owner():
            def compute():
                started.set()
                time.sleep(0.2)
                return 1

            return engine.run(authority="A", work_key="K", compute=compute)

        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(owner)
            self.assertTrue(started.wait(timeout=1))
            second = pool.submit(
                lambda: engine.run(
                    authority="A",
                    work_key="K",
                    compute=lambda: 2,
                    join_timeout=0.01,
                )
            )
            with self.assertRaises(TimeoutError):
                second.result()
            first.result()

        stats = engine.stats()
        self.assertEqual(stats.join_attempts, 1)
        self.assertEqual(stats.shared_requests, 0)
        self.assertEqual(stats.timed_out_joins, 1)

    def test_unsupported_value_fails_closed(self):
        class Opaque:
            pass

        with self.assertRaises(CanonicalizationError):
            stable_digest(Opaque())


if __name__ == "__main__":
    unittest.main()
