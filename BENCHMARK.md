# Benchmark protocol

RadialD reports **physical executions avoided**, not an assumed CPU-speedup percentage.

Wall-clock improvement depends on overlap, stage cost, scheduler overhead, contention, and the shape of the workload.

## v0.1 single-node demo

```bash
radiald demo --jobs 32 --delay 0.05
```

For 32 concurrent identical requests, the expected execution shape is 32 logical requests and 1 physical execution while that work remains in flight.

## v0.2 graph demo

```bash
radiald graph-demo --delay 0.05
```

The demo constructs two concurrent pipelines:

```text
A -> B -> X
A -> B -> Y
```

Expected execution shape:

```text
logical pipelines:      2
logical node requests:  6
physical executions:    4
shared prefix:          A -> B
fracture:               X / Y
gate:                   PASS
```

The meaningful measurement is that 6 logical node requests require 4 physical node executions because the two-node prefix overlaps in flight.

## Required comparisons for real adapters

A benchmark for a real workload should report at least:

1. isolated baseline wall time;
2. RadialD wall time;
3. logical node requests;
4. physical executions;
5. shared requests;
6. peak memory when relevant;
7. output-equivalence result;
8. authority-domain configuration;
9. stage-key/version scheme.

Do not claim a performance win if outputs differ or if the test removes capability from the baseline.

## Development validation

During v0.2 development, the graph suite passed 7/7 targeted tests and a separate randomized harness matched isolated execution in 500/500 deterministic arithmetic pipelines.

Those numbers validate the bounded implementation tested; they are not a universal performance or correctness proof for arbitrary caller-defined stages.
