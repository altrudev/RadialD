# Changelog

## 0.3.0 — candidate

Status: **implementation complete; validation intentionally deferred**.

### Security and governance

- bind verifier identity into in-flight work identity;
- require stable verifier identity for graph-stage verification;
- bind verifier identity into downstream graph lineage;
- replace permissive `repr()` fingerprint fallback with fail-closed, type-preserving fingerprints;
- reject cyclic containers, non-finite floats, unsupported objects, and excessive nesting;
- version the fingerprint and graph-lineage domains so v0.2/v0.3 evidence is not silently mixed;
- document authority freshness, mutable shared-value, and trust-boundary responsibilities explicitly.

### Performance and memory

- slot-back immutable result, trace, stage, and statistics objects;
- add `record_trace=False` for evidence-aware low-memory graph execution;
- preserve final lineage and shared-node counts when compact tracing is selected;
- encode binary values with base64 instead of hexadecimal inside canonical fingerprint material;
- retain no completed result cache or new persistent state.

### Evidence

- full trace remains the default;
- compact trace mode is explicitly not represented as equivalent to full per-node evidence;
- new candidate tests cover verifier fracture, type-distinct values, cyclic representations, and compact tracing.

No PASS claim is made for v0.3 until the deferred validation run is executed.
