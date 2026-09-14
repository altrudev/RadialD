# RadialD Assurance Fabric v0.4

RadialD v0.4 adds evidence-bound assurance above the v0.3 weak-link engine.

## Trust model

An EvidenceEnvelope records producer schema, artifact digest, verifier identity,
trust-anchor fingerprint, verification time, freshness scope, attestation
digest, and cross-artifact bindings.

An envelope cannot establish its own trust. Even when its disposition says
VERIFIED, RadialD requires an externally supplied verifier callback before that
envelope may close evidence requirements or participate in trusted bindings.

## Cross-evidence binding

Policies can require bindings such as:

- action_digest
- resource_id
- policy_digest
- revision
- predecessor_digest
- successor_digest
- execution_digest

Trusted artifacts must agree on every required field. Missing fields or
conflicting values leave cross_evidence_binding UNRESOLVED.

This prevents valid artifacts from unrelated actions from composing into one
apparently safe decision.

## Required evidence and freshness

EvidencePolicy declares mandatory producers and per-source preflight
requirements. A fresh artifact from one producer cannot make another producer's
historical evidence fresh.

Future timestamps, missing preflight evidence, and evidence older than the
configured age limit fail closed.

## Contradictions

If the same assurance signal is CLOSED in one evidence path and non-CLOSED in
another, RadialD emits an evidence_contradiction signal. Contradictions become
first-class weak links rather than being averaged away.

## Resource bounds

Policies bound the number of evidence envelopes. Evidence envelopes also bound
the number and size of binding values. Exceeding these limits creates an
UNRESOLVED evidence_budget condition or rejects the envelope.

## Assurance receipts

make_assurance_receipt() produces a deterministic receipt containing:

- evidence fingerprints
- policy digest
- resolved, missing, and conflicting bindings
- system assurance
- maximum safe autonomy
- bounding weak link
- signal count
- receipt digest

seal_assurance_receipt() delegates signing to an external signer.
verify_assurance_seal() delegates cryptographic verification to an externally
supplied verifier. RadialD does not create or infer trust anchors.

## Non-claims

RadialD does not authenticate producer artifacts by itself, prove arbitrary
semantic correctness, establish physical safety without trusted producer
evidence, or make stale evidence current.

The assurance score remains a policy result, not a mathematical proof of whole
system safety.


## v0.4.1 attestation integrity

EvidenceEnvelope.create() computes an attestation digest over the envelope's
attested fields. During trust evaluation RadialD recomputes that digest before
calling the external verifier.

A syntactically valid envelope with an arbitrary or stale attestation digest
therefore remains untrusted even if a permissive verifier callback would
otherwise accept it.
