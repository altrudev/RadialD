# Security model

RadialD is a concurrency and assurance primitive. It does **not** sandbox code,
establish authorization by itself, or infer whether arbitrary programs are safe
to share.

## Authority boundary

Every request carries an explicit authority identity. v0.3 canonicalizes
supported values with type preservation before using them in the in-flight
identity.

Python-equal but representation-distinct values such as `True` and `1` do
not share.

Applications must still choose authority values that correspond to their real
security domains.

## Deterministic-key boundary

The caller is responsible for choosing a work key or stage key that completely
identifies every input and semantic condition capable of changing the result.

A key must change when any of these change:

- transform implementation;
- configuration;
- model/version/resource identity;
- environment or hidden dependency;
- external state assumed by the transform;
- verifier semantics;
- any other execution semantics.

If that cannot be established, execute in isolation with a distinct key.

## Canonical representation boundary

Fingerprints are generated only for exact supported built-in representations:
`None`, booleans, integers, finite floats, strings, bytes, lists, tuples,
dictionaries, sets, and frozensets composed recursively from supported values.

Unsupported custom objects, cyclic structures, non-finite floats, and ambiguous
representations fail closed. This prevents `repr()` fallback and JSON
type-coercion from becoming an equivalence oracle.

This is a compatibility tightening from v0.2.

## Lineage boundary

Graph nodes include complete prefix lineage in their identity. Two pipelines
that diverge cannot silently rejoin merely because a later value fingerprint
matches.

## Verification

Optional node verifiers can reject a computed value before it is released.

In v0.3, a joiner also evaluates its own verifier before receiving a shared
value. This prevents the verifier selected by the owner request from implicitly
becoming the verifier for all callers.

A caller that deliberately reuses the same work/stage key for different compute
semantics still violates the deterministic-key contract; RadialD cannot infer
function equivalence.

## Availability

`join_timeout` can bound the wait of callers joining existing work. Timing out
a joiner does not cancel the owner computation.

Owner computations themselves are not preempted or sandboxed. Applications
must provide execution timeouts, memory limits, process isolation, and resource
controls appropriate to the workload.

## Weak-link analysis

Weak-link analysis consumes explicit signals. Severity, confidence, status,
propagation depth, reversibility, affected dimensions, and evidence are supplied
by the caller.

The resulting score and autonomy ceiling are policy outputs, not cryptographic
proofs or independent observations. Untrusted callers must not be allowed to
self-attest closure without an external trust mechanism.

## Persistence

Completed results are removed from the in-flight table. RadialD does not provide
persistent caching.

## Trust boundary

Do not use RadialD to coalesce untrusted multi-tenant work unless the surrounding
application supplies correct authority domains, complete deterministic keys,
appropriate process isolation, resource controls, trusted evidence sources, and
fresh-state validation.

Report suspected security issues privately to the repository owner rather than
publishing exploit details in a public issue.


## Assurance-fabric trust boundary

v0.4 evidence envelopes are metadata containers, not trust roots. A self-declared
VERIFIED disposition cannot close evidence. Assurance-fabric analysis requires
an externally supplied verifier callback that validates the envelope's
attestation against the application's own trust anchors.

Policies may require producer presence, specific cross-artifact bindings,
per-source preflight freshness, and evidence-count budgets. Missing, stale,
future-dated, over-budget, or conflicting evidence fails closed.

Trusted artifacts from different actions must not compose: required action,
resource, policy, revision, predecessor/successor, and execution bindings must
agree where the policy requires them.

Assurance receipt sealing and seal verification are delegated to external
signer/verifier functions. RadialD does not generate trust anchors or infer that
a signature is trustworthy merely because it is syntactically valid.


## Attestation self-binding

v0.4.1 recomputes the attestation digest from the envelope's source schema,
artifact digest, verifier identity, trust-anchor fingerprint, verification time,
freshness scope, disposition, and immutable bindings.

An envelope whose attestation digest does not match those fields is never
eligible for trust, even if the external verifier callback returns true.
Use EvidenceEnvelope.create() to construct a self-bound envelope.
