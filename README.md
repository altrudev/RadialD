# RadialD

**Stop computing the same deterministic work twice — and stop recomputing identical prefixes across concurrent pipelines.**

RadialD is a small, local-first execution primitive for authority-safe concurrent work sharing.

- v0.1 coalesces identical in-flight work.
- v0.2 adds **lineage-safe prefix sharing**: concurrent pipelines can share an identical prefix and fracture automatically at the first divergence.
- v0.3 candidate hardens fingerprints, verifier identity, lineage evidence, and memory usage without adding persistent storage.

RadialD is **not a persistent cache** and does not guess whether arbitrary programs are equivalent.

## The v0.3 execution model

Two concurrent pipelines:

```text
A -> B -> X
A -> B -> Y
```

can execute as:

```text
A -> B -+-> X
        +-> Y
```

`A` and `B` are physically executed once when their authority, initial state, stage identity, and prefix lineage are identical. `X` and `Y` fracture because their stage keys differ.

Once a lineage fractures, RadialD does **not** silently rejoin it later merely because two branches happen to produce the same value. Provenance remains part of node identity.

## Safety rules

RadialD shares a graph node only when all public conditions agree:

1. `authority` is identical;
2. initial-state fingerprint is identical;
3. complete prefix lineage is identical;
4. stage `key` is identical;
5. verifier contract is identical when a verifier is used;
6. the node is concurrently in flight.

Graph-stage verifiers require an explicit `verifier_key`, and that key is included in both node identity and lineage. A different verification rule is therefore a different execution path.

Fingerprints are type-preserving and versioned. Unsupported objects, cyclic containers, non-finite floats, and excessive nesting fail closed instead of falling back to `repr()`.

The caller owns the stage-key contract: **change the key whenever transform code, configuration, hidden inputs, or semantics change.**

Different authority domains never share work.

## Quick start

Requires Python 3.10+ and no runtime dependencies.

```bash
python -m pip install -e .
radiald graph-demo
```

Expected graph-demo shape:

```text
RadialD v0.3 graph demo
logical pipelines:      2
logical node requests:  6
physical executions:    4
shared prefix:          A -> B
fracture:               X / Y
left result:            ABX
right result:           ABY
gate:                   PASS
```

The original single-node demo remains available:

```bash
radiald demo --jobs 32
```

Run the test suite:

```bash
python -m unittest discover -s tests -v
```

## Graph API

```python
from radiald import RadialGraphExecutor, Stage

graph = RadialGraphExecutor()

prefix = [
    Stage("decode:v3", decode),
    Stage("normalize:v2", normalize),
]

preview = graph.run(
    authority="tenant-17",
    initial=source_bytes,
    stages=prefix + [Stage("resize:256:v1", resize_256)],
)

thumbnail = graph.run(
    authority="tenant-17",
    initial=source_bytes,
    stages=prefix + [Stage("resize:64:v1", resize_64)],
)
```

When these pipelines overlap in time, `decode` and `normalize` are eligible to share. The resize stages fracture.

By default every graph result includes a node trace with input, output, verifier, and lineage fingerprints plus whether each node was shared. For memory-sensitive workloads, `record_trace=False` omits per-node trace records while preserving the final lineage digest and shared-node count. Use compact mode only when equivalent evidence is retained elsewhere.

## Single-node API

```python
from radiald import RadialExecutor

engine = RadialExecutor()
result = engine.run(
    authority="tenant-17",
    work_key=("thumbnail", source_sha256, 256),
    compute=lambda: make_thumbnail(source, 256),
    verifier=lambda output: len(output) > 0,
    verifier_key="nonempty-v1",
)
```

## DDC-governed release gates

RadialD is developed under bounded behavioral gates derived from DDC work, while private DDC decision methodology is not published in this repository.

Public release invariants are documented in [DDC_GATES.md](DDC_GATES.md).

The v0.3 candidate gate adds:

- shared prefixes execute once under concurrency;
- divergent stages fracture;
- divergent lineages cannot silently rejoin;
- authority boundaries prevent sharing at every node;
- different initial states prevent sharing;
- verifier rejection reaches all joiners;
- graph output matches isolated execution;
- completed results are not retained as a cache;
- verifier contracts are part of coalescing identity and lineage;
- fingerprints preserve Python value type and fail closed on unsupported representations;
- compact trace mode reduces per-result memory without changing execution identity.

## What v0.3 does not claim

RadialD does not automatically prove arbitrary programs are deterministic, infer complete stage keys, deduplicate work across processes or machines, sandbox user code, or promise a speedup when workloads do not overlap.

It currently shares **declared deterministic work**, not arbitrary shell commands.

## Why lineage is sticky

A value fingerprint alone is not enough to establish safe equivalence. Two different computation paths can accidentally or intentionally produce the same value while carrying different provenance or authority implications.

RadialD therefore includes the complete prefix lineage in node identity. Once two graphs fracture, later equal values do not make them eligible to rejoin.

## License

MIT. See [LICENSE](LICENSE).
