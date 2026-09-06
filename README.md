# RadialD

**Stop computing the same deterministic work twice.**

RadialD is a small, local-first execution primitive that coalesces identical **concurrent** work. If multiple callers request the same deterministic work inside the same authority domain, one caller performs the physical computation and the others join it. When the work key or authority differs, execution fractures automatically.

RadialD is **not a persistent cache** and does not guess whether arbitrary programs are equivalent.

## Why

Many systems duplicate expensive work while requests are simultaneously in flight: image transforms, compilation stages, metadata extraction, model preprocessing, builds, tests, and data transforms. RadialD provides a conservative primitive for eliminating that duplication without reducing logical capability.

```text
logical requests
 A ─┐
 A ─┼──── same authority + same deterministic key ──── compute once ──┬─ result A
 A ─┘                                                                  ├─ result A
 B ───── different key ─────────────────────────────── compute ────────┴─ result B
```

## Safety rule

RadialD shares work **only** when:

1. `authority` is identical, and
2. `work_key` is identical.

The caller owns the contract that `work_key` completely identifies all inputs that can affect deterministic output. Different authority domains never share work.

## Quick start

Requires Python 3.10+ and no runtime dependencies.

```bash
python -m pip install -e .
radiald demo --jobs 32
```

Typical result:

```text
RadialD v0.1 demo
logical requests:       32
physical executions:    1
shared requests:        31
work avoided:           96.9%
compute function calls: 1
output equivalence:     True
```

Run the test suite:

```bash
python -m unittest discover -s tests -v
```

## Library API

```python
from radiald import RadialExecutor

engine = RadialExecutor()
result = engine.run(
    authority="tenant-17",
    work_key=("thumbnail", source_sha256, 256),
    compute=lambda: make_thumbnail(source, 256),
    verifier=lambda output: len(output) > 0,
)

print(result.value)
print(result.digest)
print(result.shared)
```

`run()` is thread-safe. Joiners receive the same computed value and digest. Exceptions and verifier failures are propagated to all joiners.

## What v0.1 proves

- concurrent identical deterministic requests can collapse to one physical execution;
- different work keys fracture rather than share;
- equal work keys across different authorities still fracture;
- output fingerprints are stable for equivalent serializable results;
- verifier rejection reaches every joined caller;
- completed results are not retained as a cache.

## What v0.1 does **not** claim

RadialD does not automatically prove arbitrary programs are deterministic, deduplicate work across processes or machines, infer hidden inputs, sandbox user code, or promise a speedup when requests do not overlap. Those are future layers and require stronger evidence boundaries.

## Design direction

The public project intentionally exposes a small execution contract rather than any private decision methodology. Future adapters can use RadialD underneath build systems, renderers, data pipelines, or local compute services while keeping authority and verification explicit.

## License

Apache-2.0. See [LICENSE](LICENSE).
