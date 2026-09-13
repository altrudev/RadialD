# DDC-governed public release gates

This repository publishes **behavioral release gates**, not private DDC decision methodology.

A RadialD release is acceptable only when the public implementation preserves these invariants.

## G1 — Exact logical equivalence

For declared deterministic stages, graph execution must produce the same logical result as isolated execution.

## G2 — Authority isolation

Work from different authority domains must never coalesce, even when stage keys and visible inputs are identical.

## G3 — Prefix-only sharing

Concurrent graph nodes may share only when initial state, complete prefix lineage, stage key, verifier contract, and authority agree.

## G4 — Sticky fracture

After two pipelines diverge, they remain distinct. Equal later values are insufficient to erase lineage divergence.

## G5 — Conservative ambiguity

If the caller cannot provide complete deterministic identity, that stage is not safe for shared execution. The correct fallback is isolated execution with a distinct key.

## G6 — Verifier integrity

A verifier rejection or computation exception must propagate to every caller joined to that node. Different verifier contracts must not share or silently converge downstream.

## G7 — No hidden persistence

Completed node results are removed from the in-flight table. RadialD is not a persistent cache.

## G8 — Evidence surface

Full graph results expose input, output, verifier, and lineage fingerprints for every stage plus whether the node was shared.

## G9 — Representation integrity

Fingerprints must preserve relevant value type and must fail closed on unsupported or cyclic representations rather than using ambiguous fallback serialization.

## G10 — Bounded resource behavior

The fingerprint path must reject pathological recursion. Runtime result structures should minimize avoidable object overhead and should not duplicate persistent state.

## G11 — Evidence-aware compaction

Compact trace mode may omit per-node trace objects only when execution identity and final lineage remain unchanged. It must not be presented as equivalent to a retained full trace.

## Candidate validation scope

The v0.3 candidate test surface now includes cases for:

- identical concurrent pipelines;
- shared prefixes with divergent suffixes;
- non-rejoin after divergence even when values become equal;
- cross-authority refusal;
- different initial-state refusal;
- verifier-failure propagation;
- different verifier-contract fracture;
- type-distinct initial-state fracture;
- strict unsupported-object and cyclic-container fingerprint rejection;
- compact trace lineage retention;
- isolated-output equivalence.

These are candidate gates until the v0.3 branch is executed through the normal validation path.

A previous randomized v0.2 development harness matched isolated execution in 500/500 deterministic arithmetic pipelines. That remains historical evidence for v0.2 only and is not reused as proof for v0.3.
