from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Generic, Hashable, Iterable, TypeVar

from .canonical import stable_digest, typed_identity
from .core import RadialExecutor, WorkResult, WorkStats

T = TypeVar("T")


def _stable_digest(value: object) -> str:
    return stable_digest(value)


def _lineage_digest(*parts: object) -> str:
    return _stable_digest(parts)


@dataclass(frozen=True)
class Stage(Generic[T]):
    """One deterministic graph stage.

    The key is a public execution contract: callers MUST change it whenever the
    transform implementation, configuration, hidden inputs, verifier semantics,
    or other execution semantics change.
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

    Node identity includes authority (enforced by RadialExecutor), complete
    prefix lineage, and a type-preserving stage identity. Once two pipelines
    diverge, their lineage differs and they cannot silently rejoin later.
    """

    def __init__(self, executor: RadialExecutor | None = None) -> None:
        self._executor = executor or RadialExecutor()

    def run(
        self,
        *,
        authority: Hashable,
        initial: object,
        stages: Iterable[Stage[object]],
        join_timeout: float | None = None,
    ) -> GraphResult[object]:
        value: object = initial
        input_digest = _stable_digest(value)
        lineage = _lineage_digest("radiald-root-v2", input_digest)
        trace: list[NodeTrace] = []

        for stage in stages:
            stage_id = typed_identity(stage.key)
            node_key = ("radiald-node-v2", lineage, stage_id)
            node_input = value
            node_input_digest = input_digest

            result: WorkResult[object] = self._executor.run(
                authority=authority,
                work_key=node_key,
                compute=lambda s=stage, v=node_input: s.transform(v),
                verifier=stage.verifier,
                join_timeout=join_timeout,
            )

            value = result.value
            input_digest = result.digest
            lineage = _lineage_digest(
                "radiald-lineage-v2", lineage, stage_id, result.digest
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
