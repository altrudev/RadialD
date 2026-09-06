# DDC-governed public release gates

This repository publishes **behavioral release gates**, not private DDC decision methodology.

A RadialD release is acceptable only when the public implementation preserves these invariants.

## G1 — Exact logical equivalence

For declared deterministic stages, graph execution must produce the same logical result as isolated execution.

## G2 — Authority isolation

Work from different authority domains must never coalesce, even when stage keys and visible inputs are identical.

## G3 — Prefix-only sharing

Concurrent graph nodes may share only when initial state, complete prefix lineage, stage key, and authority agree.

## G4 — Sticky fracture

After two pipelines diverge, they remain distinct in v0.2. Equal later values are insufficient to erase lineage divergence.

## G5 — Conservative ambiguity

If the caller cannot provide a complete deterministic stage key, that stage is not safe for shared execution. The correct fallback is isolated execution with a distinct key.

## G6 — Verifier propagation

A node verifier rejection or computation exception must propagate to every caller joined to that in-flight node.

## G7 — No hidden persistence

Completed node results are removed from the in-flight table. RadialD v0.2 is not a persistent cache.

## G8 — Evidence surface

Graph results expose input, output, and lineage fingerprints for every stage plus whether the node was shared.

## Current validation

The v0.2 graph suite covers:

- identical concurrent pipelines;
- shared prefix with divergent suffixes;
- non-rejoin after divergence even when values become equal;
- cross-authority refusal;
- different initial-state refusal;
- verifier-failure propagation;
- isolated-output equivalence.

A separate randomized harness was also run over 500 deterministic arithmetic pipelines during v0.2 development and matched isolated execution in all 500 trials.

That development harness is evidence for the release process, not a proof that arbitrary user-supplied programs are deterministic.
