# RadialD v0.1 benchmark protocol

RadialD's meaningful metric is **physical executions avoided during overlap**, not a synthetic claim that CPUs become faster.

## Reproduce

```bash
python -m pip install -e .
radiald demo --jobs 32 --delay 0.05
python -m unittest discover -s tests -v
```

The demo synchronizes 32 callers so they request exactly the same declared deterministic unit while it is in flight. Correct v0.1 behavior is:

- 32 logical requests;
- 1 physical execution;
- 31 joiners;
- one output digest;
- verifier acceptance;
- no retained result after completion.

`work avoided` is calculated as `1 - physical_executions / logical_requests`. It describes coalesced execution count for the demo workload. It is **not** a general application speedup claim.

## Negative controls

The test suite also verifies cases where sharing must not occur:

- same authority + different work key -> two executions;
- same work key + different authority -> two executions;
- sequential same-key requests -> two executions (no cache);
- verifier failure -> failure propagates to every joiner.

## Current boundary

v0.1 is an in-process threaded primitive. Cross-process, distributed, sandboxed, and automatically inferred equivalence are explicitly out of scope.
