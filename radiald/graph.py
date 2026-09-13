from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Generic, Hashable, Iterable, TypeVar

from .core import RadialExecutor, WorkResult, WorkStats, stable_digest

T = TypeVar("T")


def _stable_digest(value: object) -> str:
    return stable_digest(value)


def _lineage_digest(*parts: object) -> str:
    return stable_digest(parts)


@dataclass(frozen=True, slots=True)
class Stage(Generic[T]):
    """One deterministic graph stage.

    `key` is a public execution contract: callers MUST change it whenever the
    transform implementation, configuration, hidden inputs, or semantics change.
    """

    key: Hashable
    transform: Callable[[object], T]
    verifier: Callable[[T], bool] | None = None
    verifier_key: Hashable | None = None


@dataclass(frozen=True, slots=True)
class NodeTrace:
    stage_key: Hashable
    verifier_key: Hashable | None
    input_digest: str
    output_digest: str
    lineage_digest: str
    shared: bool


@dataclass(frozen=True, slots=True)
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

    __slots__ = ("_executor",)

    def __init__(self, executor: RadialExecutor | None = None) -> None:
        self._executor = executor or RadialExecutor()

    def run(
        self,
        *,
        authority: Hashable,
        initial: object,
        stages: Iterable[Stage[object]],
        record_trace: bool = True,
    ) -> GraphResult[object]:
        value: object = initial
        input_digest = _stable_digest(value)
        lineage = _lineage_digest("radiald-root-v1", input_digest)
        trace: list[NodeTrace] | None = [] if record_trace else None

        for stage in stages:
            if stage.verifier is not None and stage.verifier_key is None:
                raise ValueError("graph stages with a verifier require verifier_key")
            verifier_contract = (
                ("none",)
                if stage.verifier is None
                else ("key", stage.verifier_key)
            )
            node_key = ("radiald-node-v1", lineage, stage.key, verifier_contract)
            node_input = value
            node_input_digest = input_digest

            result: WorkResult[object] = self._executor.run(
                authority=authority,
                work_key=node_key,
                compute=lambda s=stage, v=node_input: s.transform(v),
                verifier=stage.verifier,
                verifier_key=stage.verifier_key,
            )

            value = result.value
            input_digest = result.digest
            lineage = _lineage_digest(
                "radiald-lineage-v1",
                lineage,
                stage.key,
                verifier_contract,
                result.digest,
            )
            if trace is not None:
                trace.append(
                    NodeTrace(
                        stage_key=stage.key,
                        verifier_key=stage.verifier_key,
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
            trace=tuple(trace) if trace is not None else (),
        )

    def stats(self) -> WorkStats:
        return self._executor.stats()
