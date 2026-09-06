from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Callable, Generic, Hashable, Iterable, TypeVar

from .core import RadialExecutor, WorkResult, WorkStats

T = TypeVar("T")


def _stable_digest(value: object) -> str:
    try:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    except (TypeError, ValueError):
        encoded = repr(value).encode("utf-8")
    return sha256(encoded).hexdigest()


def _lineage_digest(*parts: object) -> str:
    return _stable_digest(parts)


@dataclass(frozen=True)
class Stage(Generic[T]):
    """One deterministic graph stage.

    `key` is a public execution contract: callers MUST change it whenever the
    transform implementation, configuration, hidden inputs, or semantics change.
    """

    key: Hashable
    transform: Callable[[object], T]
    verifier: Callable[[T], bool] | None = None


@dataclass(frozen=True)
class NodeTrace:
    stage_key: Hashable
    input_digest: str
    output_digest: str
    lineage_digest: str
    shared: bool


@dataclass(frozen=True)
class GraphResult(Generic[T]):
    value: T
    digest: str
    lineage_digest: str
    trace: tuple[NodeTrace, ...]

    @property
    def shared_nodes(self) -> int:
        return sum(node.shared for node in self.trace)


class RadialGraphExecutor:
    """Share only identical in-flight deterministic prefixes.

    Node identity includes authority (enforced by RadialExecutor), the complete
    prefix lineage, and the stage key. Once two pipelines diverge, their lineage
    differs and they cannot silently rejoin later, even if an intermediate value
    happens to hash identically.
    """

    def __init__(self, executor: RadialExecutor | None = None) -> None:
        self._executor = executor or RadialExecutor()

    def run(
        self,
        *,
        authority: Hashable,
        initial: object,
        stages: Iterable[Stage[object]],
    ) -> GraphResult[object]:
        value: object = initial
        input_digest = _stable_digest(value)
        lineage = _lineage_digest("radiald-root-v1", input_digest)
        trace: list[NodeTrace] = []

        for stage in stages:
            node_key = ("radiald-node-v1", lineage, stage.key)
            node_input = value
            node_input_digest = input_digest

            result: WorkResult[object] = self._executor.run(
                authority=authority,
                work_key=node_key,
                compute=lambda s=stage, v=node_input: s.transform(v),
                verifier=stage.verifier,
            )

            value = result.value
            input_digest = result.digest
            lineage = _lineage_digest(
                "radiald-lineage-v1", lineage, stage.key, result.digest
            )
            trace.append(
                NodeTrace(
                    stage_key=stage.key,
                    input_digest=node_input_digest,
                    output_digest=result.digest,
                    lineage_digest=lineage,
                    shared=result.shared,
                )
            )

        return GraphResult(
            value=value,
            digest=input_digest,
            lineage_digest=lineage,
            trace=tuple(trace),
        )

    def stats(self) -> WorkStats:
        return self._executor.stats()
