# RadialD

**Share deterministic concurrent work without erasing authority, representation, or lineage — and identify the weak link that bounds safe autonomy.**

RadialD is a small, local-first execution and assurance primitive.

- v0.1: identical in-flight work coalescing.
- v0.2: lineage-safe shared-prefix execution.
- v0.3: type-preserving canonical identity, joiner-side verifier enforcement, bounded shared waits, and first-class weak-link analysis.

RadialD is **not a persistent cache**, sandbox, policy engine, or proof that arbitrary programs are deterministic.

## Execution model

Two concurrent pipelines:

```text
A -> B -> X
A -> B -> Y
```

may execute as:

```text
A -> B -+-> X
        +-> Y
```

A node is eligible to share only when authority, initial-state representation,
complete prefix lineage, stage identity, and in-flight timing agree.

Once a lineage fractures, it does not silently rejoin merely because later
values happen to be equal.

## v0.3 security hardening

v0.3 closes representation-equivalence gaps present in earlier releases.

Identity and lineage fingerprints are now generated from a deterministic,
type-preserving canonical representation. For example, these are distinct:

- `True` and `1`;
- `[1]` and `(1,)`;
- `{1: "x"}` and `{"1": "x"}`.

Unsupported custom objects and ambiguous representations fail closed instead
of falling back to `repr()`.

A caller that joins existing work also runs its own verifier before receiving
the shared output. `join_timeout` can bound how long a joiner waits for the
owner computation.

These changes are intentionally conservative and can reject values that v0.2
would fingerprint via `repr()`.

## Weak-link analysis

Weak-link analysis ranks **explicit evidence supplied by the caller**. It does
not infer safety from arbitrary program behavior.

```python
from radiald import (
    WeakLinkAnalyzer,
    WeakLinkSignal,
    WeakLinkStatus,
)

report = WeakLinkAnalyzer().analyze([
    WeakLinkSignal(
        "representation_equivalence",
        severity=0.95,
        confidence=1.0,
        status=WeakLinkStatus.CLOSED,
    ),
    WeakLinkSignal(
        "external_state_freshness",
        severity=0.90,
        confidence=0.95,
        status=WeakLinkStatus.UNRESOLVED,
        propagation_depth=2,
        reversible=False,
    ),
])

print(report.bounding_link.name)
print(report.system_assurance)
print(report.maximum_safe_autonomy.value)
```

Statuses are `DETECTED`, `CONTAINED`, `CLOSED`, and `UNRESOLVED`.

The report identifies the residual-risk bottleneck and maps it to a configurable
autonomy ceiling. The numeric score is a bounded policy aid, not a proof of
system safety.

## Quick start

Requires Python 3.10+ and no runtime dependencies.

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
radiald graph-demo
radiald weaklink-demo
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
    join_timeout=1.0,
)
```

The stage key is part of the execution contract. Change it whenever transform
code, configuration, hidden inputs, verifier semantics, resource identity, or
other execution semantics change.

## Single-node API

```python
from radiald import RadialExecutor

engine = RadialExecutor()
result = engine.run(
    authority="tenant-17",
    work_key=("thumbnail", "sha256:abc", 256),
    compute=lambda: make_thumbnail(source, 256),
    verifier=lambda output: len(output) > 0,
    join_timeout=1.0,
)
```

## DDC-governed release gates

Public release invariants are documented in [DDC_GATES.md](DDC_GATES.md).
Security assumptions and trust boundaries are documented in
[SECURITY.md](SECURITY.md).

## What v0.3 does not claim

RadialD does not automatically prove determinism, infer complete stage keys,
deduplicate across processes or machines, sandbox untrusted code, establish
freshness of external state, or guarantee performance improvements when work
does not overlap.

Weak-link analysis does not discover evidence by itself. Callers must supply
signals grounded in their own observations, policy checks, receipts, state
validation, or other assurance mechanisms.

## License

MIT. See [LICENSE](LICENSE).
