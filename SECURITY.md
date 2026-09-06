# Security model

RadialD v0.1 is deliberately conservative.

## Trust boundary

A caller supplies two values:

- `authority`: an isolation/trust domain;
- `work_key`: a complete identity for all deterministic inputs affecting a unit of work.

RadialD permits in-flight sharing only when both values are exactly equal.

## Caller responsibility

Never reuse a work key when output can differ because of undeclared state such as credentials, environment variables, filesystem state, time, randomness, locale, mutable services, or hidden configuration. Include hashes or version identifiers for every relevant input in the key, or do not share that work.

## Non-goals

v0.1 does not sandbox `compute`, inspect arbitrary code for determinism, protect secrets inside caller-provided values, or provide cross-process tenant isolation. Do not expose it as an arbitrary remote-code-execution service.

## Reporting

Please report security issues privately to the repository owner rather than publishing exploit details first.
