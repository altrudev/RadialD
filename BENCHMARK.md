# Benchmark protocol

RadialD reports **physical executions avoided**, not an assumed CPU-speedup percentage.

Wall-clock improvement depends on overlap, stage cost, fingerprinting overhead,
scheduler overhead, contention, and workload shape.

## Execution demos

```bash
radiald demo --jobs 32 --delay 0.05
radiald graph-demo --delay 0.05
radiald weaklink-demo
```

For shared execution, the meaningful comparison is logical node requests versus
physical node executions while preserving output equivalence and authority
boundaries.

## Required comparisons for real adapters

A benchmark for a real workload should report at least:

1. isolated baseline wall time;
2. RadialD wall time;
3. logical node requests;
4. physical executions;
5. shared requests;
6. canonical fingerprinting cost when material;
7. peak memory when relevant;
8. output-equivalence result;
9. authority-domain configuration;
10. stage-key/version scheme;
11. verifier configuration.

Do not claim a performance win if outputs differ, if security boundaries differ,
or if the test removes capability from the baseline.

## Assurance benchmark rule

Weak-link scores are not performance metrics. Do not mix reduced residual risk
with throughput or wall-clock speed into one synthetic number.

## Development validation

The v0.3 regression run preserved the original concurrency and graph behavior
while adding representation, verifier, timeout, and weak-link tests.

Those tests validate the bounded implementation tested; they are not a universal
performance, determinism, or safety proof for arbitrary caller-defined stages.
