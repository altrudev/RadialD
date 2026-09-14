# DDC-governed public release gates

This repository publishes behavioral release gates, not private DDC decision methodology.

A RadialD release is acceptable only when the public implementation preserves these invariants.

## G1 — Exact logical equivalence

For declared deterministic stages, graph execution must produce the same logical result as isolated execution.

## G2 — Authority isolation

Work from different authority domains must never coalesce when their type-preserving authority identities differ.

## G3 — Prefix-only sharing

Concurrent graph nodes may share only when initial-state fingerprint, complete prefix lineage, stage identity, authority identity, and in-flight timing agree.

## G4 — Sticky fracture

After two pipelines diverge, equal later values are insufficient to erase lineage divergence.

## G5 — Conservative ambiguity

Values used for authority, work identity, lineage, or output evidence must have an unambiguous supported canonical representation. Unsupported representations fail closed.

## G6 — Verifier propagation and local enforcement

Computation errors and owner-side verifier rejection propagate to every joined caller. A joiner-supplied verifier must also be evaluated before that caller receives shared output.

## G7 — No hidden persistence

Completed node results are removed from the in-flight table. RadialD is not a persistent cache.

## G8 — Evidence surface

Graph results expose input, output, and lineage fingerprints for every stage plus whether the node was shared.

## G9 — Representation distinction

Semantically or operationally distinct built-in representations must not collapse merely because Python equality or JSON coercion treats them as equivalent.

Regression examples include:

- `True` versus `1`;
- list versus tuple;
- integer dictionary keys versus string dictionary keys.

## G10 — Bounded join availability

A caller may bound its wait on already-running shared work. A timeout must fail that joiner without corrupting or cancelling the owner computation.

## G11 — Weak-link evidence honesty

Weak-link analysis must rank explicit caller-supplied evidence. It must not claim to have discovered, proven, or closed a condition for which no evidence was supplied.

Closed links contribute zero residual risk. The report identifies the highest residual-risk link as the current bound.

## Current validation

The v0.3 suite covers the original v0.2 graph and concurrency gates plus:

- authority type-confusion regression;
- representation-distinct initial states;
- dictionary-key representation distinction;
- joiner-verifier bypass regression;
- bounded shared-work waits;
- fail-closed unsupported values;
- weak-link bounding, closure, and containment behavior.

The implementation remains bounded to declared deterministic work and explicit assurance signals.


## G12 — External evidence trust

An evidence envelope must not become trusted solely because its own disposition
claims VERIFIED. A caller-supplied external verifier must accept the attestation
before the envelope can close required evidence or participate in trusted
cross-artifact binding.

## G13 — Cross-artifact coherence

Individually valid artifacts must not compose into one safe assurance result
when required action, resource, policy, revision, state, or execution bindings
disagree.

## G14 — Per-source freshness

A fresh artifact from one producer must not make another producer's stale or
historical evidence current. Required preflight freshness is evaluated per
declared source.

## G15 — Missing evidence fails closed

Missing mandatory producers, missing required bindings, future-dated evidence,
and evidence outside the configured freshness window remain UNRESOLVED.

## G16 — Contradictions remain visible

Conflicting CLOSED and non-CLOSED states for the same assurance signal create a
first-class evidence_contradiction weak link.

## G17 — Assurance receipt integrity

The assurance receipt binds the evidence fingerprints, policy digest, binding
result, bounding link, autonomy ceiling, and report digest. Signing and
signature verification remain external trust operations.

## v0.4 validation targets

The v0.4 assurance suite includes mixed-action composition rejection,
self-declared trust rejection, missing-source failure, per-source stale evidence,
contradiction creation, RenderDiff missing-evidence handling, receipt tamper
detection, and external seal verification.
