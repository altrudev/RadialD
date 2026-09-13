import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

from radiald import RadialExecutor
from radiald.core import stable_digest


class RadialExecutorTests(unittest.TestCase):
    def test_identical_concurrent_work_executes_once(self):
        engine = RadialExecutor()
        workers = 16
        barrier = threading.Barrier(workers)
        calls = 0
        calls_lock = threading.Lock()

        def compute():
            nonlocal calls
            with calls_lock:
                calls += 1
            time.sleep(0.04)
            return {"value": 7}

        def job(_):
            barrier.wait()
            return engine.run(authority="A", work_key="K", compute=compute)

        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(job, range(workers)))

        self.assertEqual(calls, 1)
        self.assertEqual({r.digest for r in results}, {results[0].digest})
        self.assertEqual(engine.stats().physical_executions, 1)
        self.assertEqual(engine.stats().shared_requests, workers - 1)

    def test_different_keys_fracture(self):
        engine = RadialExecutor()
        calls = 0
        lock = threading.Lock()
        barrier = threading.Barrier(2)

        def compute(value):
            nonlocal calls
            with lock:
                calls += 1
            time.sleep(0.03)
            return value

        def job(key):
            barrier.wait()
            return engine.run(
                authority="A", work_key=key, compute=lambda: compute(key)
            ).value

        with ThreadPoolExecutor(max_workers=2) as pool:
            values = list(pool.map(job, ["left", "right"]))

        self.assertCountEqual(values, ["left", "right"])
        self.assertEqual(calls, 2)

    def test_authority_boundary_refuses_sharing(self):
        engine = RadialExecutor()
        calls = 0
        lock = threading.Lock()
        barrier = threading.Barrier(2)

        def compute(authority):
            nonlocal calls
            with lock:
                calls += 1
            time.sleep(0.04)
            return authority

        def job(authority):
            barrier.wait()
            return engine.run(
                authority=authority,
                work_key="same-key",
                compute=lambda: compute(authority),
            ).value

        with ThreadPoolExecutor(max_workers=2) as pool:
            values = list(pool.map(job, ["tenant-A", "tenant-B"]))

        self.assertCountEqual(values, ["tenant-A", "tenant-B"])
        self.assertEqual(calls, 2)
        self.assertGreaterEqual(engine.stats().refused_cross_authority, 1)

    def test_verifier_failure_propagates_to_joiners(self):
        engine = RadialExecutor()
        workers = 4
        barrier = threading.Barrier(workers)

        def job(_):
            barrier.wait()
            return engine.run(
                authority="A",
                work_key="bad",
                compute=lambda: (time.sleep(0.03), 3)[1],
                verifier=lambda value: value == 4,
                verifier_key="equals-4-v1",
            )

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(job, i) for i in range(workers)]
            for future in futures:
                with self.assertRaises(ValueError):
                    future.result()

        self.assertEqual(engine.stats().physical_executions, 1)

    def test_sequential_requests_are_not_cached(self):
        engine = RadialExecutor()
        calls = 0

        def compute():
            nonlocal calls
            calls += 1
            return calls

        first = engine.run(authority="A", work_key="K", compute=compute)
        second = engine.run(authority="A", work_key="K", compute=compute)
        self.assertEqual((first.value, second.value), (1, 2))
        self.assertEqual(calls, 2)


    def test_different_verifier_contracts_do_not_share(self):
        engine = RadialExecutor()
        barrier = threading.Barrier(2)
        calls = 0
        lock = threading.Lock()

        def compute():
            nonlocal calls
            with lock:
                calls += 1
            time.sleep(0.04)
            return 5

        def job(verifier_key, expected):
            barrier.wait()
            return engine.run(
                authority="A",
                work_key="K",
                compute=compute,
                verifier=lambda value: value == expected,
                verifier_key=verifier_key,
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            good = pool.submit(job, "equals-5", 5)
            bad = pool.submit(job, "equals-6", 6)
            self.assertEqual(good.result().value, 5)
            with self.assertRaises(ValueError):
                bad.result()

        self.assertEqual(calls, 2)
        self.assertEqual(engine.stats().physical_executions, 2)

    def test_type_preserving_digest_distinguishes_python_values(self):
        self.assertNotEqual(stable_digest([1, 2]), stable_digest((1, 2)))
        self.assertNotEqual(stable_digest({1: "x"}), stable_digest({"1": "x"}))
        self.assertNotEqual(stable_digest(True), stable_digest(1))

    def test_unsupported_object_fingerprint_fails_closed(self):
        class Hidden:
            def __init__(self, value):
                self.value = value

            def __repr__(self):
                return "same"

        with self.assertRaises(TypeError):
            stable_digest(Hidden(1))


    def test_cyclic_container_fingerprint_fails_closed(self):
        value = []
        value.append(value)
        with self.assertRaises(TypeError):
            stable_digest(value)

    def test_binary_fingerprint_is_stable_and_type_distinct(self):
        self.assertEqual(stable_digest(b"abc"), stable_digest(b"abc"))
        self.assertNotEqual(stable_digest(b"abc"), stable_digest("abc"))



if __name__ == "__main__":
    unittest.main()
