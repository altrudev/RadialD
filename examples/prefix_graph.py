import threading
import time
from concurrent.futures import ThreadPoolExecutor

from radiald import RadialGraphExecutor, Stage


graph = RadialGraphExecutor()
barrier = threading.Barrier(2)


def stage(name):
    def transform(value):
        time.sleep(0.02)
        return value + name
    return transform


prefix = [
    Stage("decode:v1", stage("D")),
    Stage("normalize:v1", stage("N")),
]

left = prefix + [Stage("preview:v1", stage("P"))]
right = prefix + [Stage("thumbnail:v1", stage("T"))]


def run(stages):
    barrier.wait()
    return graph.run(authority="example", initial="", stages=stages)


with ThreadPoolExecutor(max_workers=2) as pool:
    preview, thumbnail = list(pool.map(run, [left, right]))

print("preview:", preview.value)
print("thumbnail:", thumbnail.value)
print("physical executions:", graph.stats().physical_executions)
print("logical node requests:", graph.stats().logical_requests)
