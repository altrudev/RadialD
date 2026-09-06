# Security model

RadialD is a concurrency primitive. It does **not** sandbox code and it does not infer whether arbitrary programs are safe to share.

## Authority boundary

Every request carries an explicit `authority`. RadialD includes authority in the in-flight identity, so equal work from different authorities executes separately.

## Deterministic-key boundary

The caller is responsible for choosing a `work_key` or graph-stage `key` that completely identifies every input capable of changing deterministic output.

A stage key must change when any of these change:

- transform implementation;
- configuration;
- model/version/resource identity;
- environment value that affects output;
- hidden dependency or input;
- semantics of the stage.

If that cannot be established, use a unique key and execute in isolation.

## Lineage boundary

Graph nodes include complete prefix lineage in their identity. Two pipelines that diverge cannot silently rejoin in v0.2 merely because a later value fingerprint matches.

This is intentional: equal values are weaker evidence than equal execution lineage.

## Verification

Optional node verifiers can reject a computed value before it is released to joined callers. Computation errors and verifier failures propagate to all joiners.

Output digests are evidence fingerprints, not cryptographic proofs that caller-supplied work is deterministic.

## Persistence

Completed results are removed from the in-flight table. RadialD v0.2 does not provide persistent caching.

## Trust boundary

Do not use RadialD to coalesce untrusted multi-tenant work unless the surrounding application supplies correct authority domains, complete deterministic keys, appropriate isolation, and resource controls.

Report suspected security issues privately to the repository owner rather than publishing exploit details in a public issue.
