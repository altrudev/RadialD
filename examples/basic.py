import threading
import time
from concurrent.futures import ThreadPoolExecutor

from radiald import RadialExecutor

engine = RadialExecutor()
barrier = threading.Barrier(8)


def request(_):
    barrier.wait()
    result = engine.run(
        authority="tenant-17",
        work_key=("thumbnail", "sha256:abc", 256),
        compute=lambda: (time.sleep(0.05), b"thumbnail-bytes")[1],
    )
    return result.digest


with ThreadPoolExecutor(max_workers=8) as pool:
    digests = list(pool.map(request, range(8)))

print(engine.stats())
print("all outputs equivalent:", len(set(digests)) == 1)
