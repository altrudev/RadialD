# Security model

RadialD is a concurrency primitive. It does **not** sandbox code, authenticate callers, or infer whether arbitrary programs are safe to share.

## Authority boundary

Every request carries an explicit `authority`. Authority participates in in-flight identity, so different authority domains never coalesce.

RadialD treats the authority value as a caller-supplied execution boundary. The surrounding system remains responsible for authentication, delegation scope, expiry/revocation, and execution-time authority freshness. If any of those change, use a different authority identity and do not reuse the old one.

## Deterministic-work boundary

The caller is responsible for choosing a `work_key` or graph-stage `key` that completely identifies every input capable of changing deterministic output.

Change the key whenever transform implementation, configuration, model/version/resource identity, environment, hidden dependency, or semantics change. If completeness cannot be established, execute in isolation with a distinct key.

## Representation boundary

Graph fingerprints use a versioned, type-preserving representation. RadialD deliberately does not fall back to `repr()`.

Supported built-in values are fingerprinted recursively. Unsupported objects, cyclic containers, non-finite floats, or nesting beyond the configured hard bound fail closed.

Graph stage keys and verifier keys become part of lineage and therefore should use supported stable built-in values.

## Verifier boundary

A verifier changes the acceptance semantics of a node and therefore changes node identity.

Graph stages with a verifier require an explicit `verifier_key`. The verifier key is bound into both the in-flight work identity and downstream lineage, so paths with different verification contracts cannot silently rejoin.

The lower-level `RadialExecutor` remains backward compatible: if a verifier is supplied without a key it uses that callable instance as a conservative process-local identity, preventing unrelated verifier functions from coalescing.

## Lineage boundary

Graph nodes include complete prefix lineage in their identity. Once two pipelines diverge, equal later values are insufficient to erase provenance differences.

## Shared-value boundary

Joined callers receive the same computed Python value object. Within one authority domain, callers should prefer immutable results or copy mutable values before mutation. RadialD does not deep-copy shared values by default because doing so would add hidden CPU and memory cost.

## Evidence and compact tracing

Full tracing is the default and records per-node input, output, verifier, lineage, and sharing metadata.

`record_trace=False` is an optimization for callers that preserve equivalent evidence externally. It omits per-node trace objects but retains the final lineage digest and shared-node count. Compact mode must not be represented as full per-stage evidence.

## Persistence and storage

Completed results are removed from the in-flight table. RadialD does not persist computed values or maintain a hidden cache.

Slot-backed result structures and optional compact tracing reduce per-request memory overhead without weakening execution identity.

## Trust boundary

Do not use RadialD to coalesce untrusted multi-tenant work unless the surrounding application supplies correct authority domains, complete deterministic keys, appropriate isolation, resource controls, and execution-time revalidation.

Output digests are evidence fingerprints, not proof that caller-supplied work is deterministic or authorized.

Report suspected security issues privately to the repository owner rather than publishing exploit details in a public issue.
